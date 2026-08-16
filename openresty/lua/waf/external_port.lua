-- Resolve the *external* port a client connected to, after sk_lookup steered
-- the SYN to a fixed internal listen socket.
--
-- Why the previous implementation had to change:
--
-- The old `resolve()` tried `/proc/self/net/tcp` FIRST and only fell back to
-- `getsockname()`. That was wrong on three counts, and the ordering made all
-- three unavoidable rather than merely possible:
--
--  1. Correctness. It matched rows on the *remote* 4-tuple half only
--     (`remote_ip:remote_port`) and returned the first hit. Behind NAT or a
--     load balancer the same client tuple legitimately appears more than once
--     (including TIME_WAIT remnants), so the scan could return another
--     connection's local port. That port then feeds ACL decisions and rate
--     limiting, i.e. a wrong answer is a security-relevant mis-attribution,
--     not a cosmetic bug.
--  2. Cost. It was O(number of sockets on the host) per request, with blocking
--     `io.open`/`io.lines` inside the request path. On a busy WAF node
--     /proc/self/net/tcp is tens of thousands of lines; the repo's own
--     docs/repro-g2-http-p99.md measured the resulting p99 damage.
--  3. Blocking I/O. Reading /proc from a light thread stalls the whole nginx
--     worker's event loop, so the damage is not confined to the request that
--     paid for it.
--
-- `getsockname()` on the request's own socket is the authoritative answer: it
-- reads the local half of *this* connection's 4-tuple from the kernel, which is
-- exactly the client's destination port after `bpf_sk_assign`. It is O(1), does
-- not block, and cannot be confused by another connection.
--
-- The /proc scan is kept only as a last-resort diagnostic path (some builds
-- expose no FD to Lua), is now matched on the *full* 4-tuple so it cannot
-- mis-attribute, and is rate-limited so a persistent failure cannot turn every
-- request into a /proc walk.

local ffi = require "ffi"

ffi.cdef [[
    unsigned short ntohs(unsigned short netshort);
    struct in_addr { unsigned int s_addr; };
    struct in6_addr { unsigned char s6_addr[16]; };
    struct sockaddr { unsigned short sa_family; char sa_data[14]; };
    struct sockaddr_in {
        unsigned short sin_family;
        unsigned short sin_port;
        struct in_addr sin_addr;
        unsigned char sin_zero[8];
    };
    struct sockaddr_in6 {
        unsigned short sin6_family;
        unsigned short sin6_port;
        unsigned int sin6_flowinfo;
        struct in6_addr sin6_addr;
        unsigned int sin6_scope_id;
    };
    struct sockaddr_storage {
        unsigned short ss_family;
        char __pad[126];
    };
    typedef unsigned int socklen_t;
    int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
]]

local C = ffi.C
local ngx = ngx
local AF_INET = 2
local AF_INET6 = 10

-- Reused across requests: allocating an FFI buffer per request would add
-- garbage to the hot path for no benefit.
local addr_buf = ffi.new("struct sockaddr_storage[1]")
local addr_len = ffi.new("socklen_t[1]")
local storage_size = ffi.sizeof("struct sockaddr_storage")

local _M = {}

-- Diagnostics, exposed so tests and `status` can assert which path served the
-- request instead of inferring it from logs.
local stats = {
    getsockname_ok = 0,
    getsockname_fail = 0,
    proc_ok = 0,
    proc_fail = 0,
    proc_skipped_ratelimit = 0,
    unresolved = 0,
}

function _M.stats()
    return {
        getsockname_ok = stats.getsockname_ok,
        getsockname_fail = stats.getsockname_fail,
        proc_ok = stats.proc_ok,
        proc_fail = stats.proc_fail,
        proc_skipped_ratelimit = stats.proc_skipped_ratelimit,
        unresolved = stats.unresolved,
    }
end

--- Primary path: ask the kernel for the local half of this connection.
-- Handles both address families, because an IPv6 listen socket reports
-- `sockaddr_in6` and reading it as `sockaddr_in` would yield a garbage port.
local function port_from_fd(fd)
    addr_len[0] = storage_size
    if C.getsockname(fd, ffi.cast("struct sockaddr *", addr_buf), addr_len) ~= 0 then
        return nil, "getsockname failed"
    end
    local family = addr_buf[0].ss_family
    if family == AF_INET then
        local sin = ffi.cast("struct sockaddr_in *", addr_buf)
        return tonumber(C.ntohs(sin.sin_port))
    elseif family == AF_INET6 then
        local sin6 = ffi.cast("struct sockaddr_in6 *", addr_buf)
        return tonumber(C.ntohs(sin6.sin6_port))
    end
    return nil, "unsupported sockaddr family " .. tostring(family)
end

local function port_from_req_socket()
    local ok, reader = pcall(ngx.req.socket, true)
    if not ok or not reader then
        return nil, "ngx.req.socket unavailable"
    end
    if not reader.getfd then
        return nil, "req socket has no getfd()"
    end
    local fd, err = reader:getfd()
    if not fd or fd < 0 then
        return nil, err or "getfd failed"
    end
    return port_from_fd(fd)
end

local function ip4_to_proc_hex(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then
        return nil
    end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    return string.format("%08X", a + b * 256 + c * 65536 + d * 16777216)
end

-- Fallback scan, rate limited: at most one /proc walk per window per worker.
local PROC_SCAN_MIN_INTERVAL = 1
local last_proc_scan = 0

--- Last-resort path. Matches the FULL 4-tuple, unlike the previous version.
--
-- Matching only the remote half meant that behind NAT (or with a TIME_WAIT
-- remnant) two rows could match and the first one won, silently returning
-- another connection's port. Requiring the local address to match as well makes
-- a wrong answer impossible: if the row is ambiguous we return nil and the
-- caller records `unresolved` rather than guessing.
local function port_from_proc_net(local_ip, remote_ip, remote_port)
    local rem_hex = ip4_to_proc_hex(remote_ip)
    local loc_hex = local_ip and ip4_to_proc_hex(local_ip)
    if not rem_hex or not remote_port then
        return nil, "missing remote addr"
    end
    local want_rem = rem_hex .. ":" .. string.format("%04X", tonumber(remote_port))

    local f, err = io.open("/proc/self/net/tcp", "r")
    if not f then
        return nil, "open /proc/self/net/tcp: " .. tostring(err)
    end
    f:read("*l") -- header

    local found, matches = nil, 0
    for line in f:lines() do
        local local_addr, rem_addr, st =
            line:match("%s*%d+:%s*(%x+:%x+)%s+(%x+:%x+)%s+(%x+)")
        -- 01 = ESTABLISHED. Anything else (notably 06 TIME_WAIT) is a stale
        -- row that must never be attributed to a live request.
        if local_addr and st == "01" and rem_addr:upper() == want_rem then
            local this_loc_hex = local_addr:match("^(%x+):")
            if (not loc_hex) or (this_loc_hex and this_loc_hex:upper() == loc_hex) then
                matches = matches + 1
                found = local_addr:match(":(%x+)$")
            end
        end
    end
    f:close()

    if matches > 1 then
        -- Ambiguous: refuse rather than pick one and mis-attribute the port to
        -- an ACL or rate-limit decision.
        return nil, "ambiguous: " .. matches .. " ESTABLISHED rows for " .. want_rem
    end
    if not found then
        return nil, "no ESTABLISHED row for " .. want_rem
    end
    return tonumber(found, 16)
end

--- Resolve the external port for the current request.
-- Returns a string (nginx variables are strings) or "" when unresolvable.
-- Never falls back to $server_port: that is the *internal* listen port and
-- would silently look plausible while being wrong for every steered request.
function _M.resolve()
    local port, err = port_from_req_socket()
    if port then
        stats.getsockname_ok = stats.getsockname_ok + 1
        return tostring(port)
    end
    stats.getsockname_fail = stats.getsockname_fail + 1

    local now = ngx.now()
    if now - last_proc_scan < PROC_SCAN_MIN_INTERVAL then
        stats.proc_skipped_ratelimit = stats.proc_skipped_ratelimit + 1
        stats.unresolved = stats.unresolved + 1
        ngx.log(ngx.ERR, "waf.external_port: getsockname=", tostring(err),
                " and /proc fallback suppressed by rate limit")
        return ""
    end
    last_proc_scan = now

    local port2, err2 = port_from_proc_net(ngx.var.server_addr, ngx.var.remote_addr,
                                           ngx.var.remote_port)
    if port2 then
        stats.proc_ok = stats.proc_ok + 1
        ngx.log(ngx.WARN, "waf.external_port: served from /proc fallback (getsockname=",
                tostring(err), "); investigate, this path is O(sockets)")
        return tostring(port2)
    end
    stats.proc_fail = stats.proc_fail + 1
    stats.unresolved = stats.unresolved + 1

    ngx.log(ngx.ERR, "waf.external_port: unresolved getsockname=", tostring(err),
            " proc=", tostring(err2), " (not falling back to $server_port)")
    return ""
end

-- Exposed for tests.
_M._port_from_fd = port_from_fd
_M._port_from_proc_net = port_from_proc_net
_M._ip4_to_proc_hex = ip4_to_proc_hex

return _M
