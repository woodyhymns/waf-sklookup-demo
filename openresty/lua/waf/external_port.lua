-- Resolve the *external* port a client connected to, after sk_lookup steered
-- the SYN to a fixed internal listen socket.
--
-- Do NOT call ngx.req.socket(true) on the request path. That takes over the
-- downstream socket (same as reverted PR #10) and HAH OpenResty 1.19.3.2 +
-- https_allow_http then returns 0-byte HTTP and HTTPS bodies (curl 52/56).
-- See #32 / #37: /proc stays until a body-safe source exists.
--
-- Never fall back to $server_port: that is the internal listen port.

local ngx = ngx

local _M = {}

local stats = {
    proc_ok = 0,
    proc_fail = 0,
    unresolved = 0,
}

function _M.stats()
    return {
        proc_ok = stats.proc_ok,
        proc_fail = stats.proc_fail,
        unresolved = stats.unresolved,
    }
end

local function ip4_to_proc_hex(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then
        return nil
    end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    return string.format("%08X", a + b * 256 + c * 65536 + d * 16777216)
end

-- Fallback-until-replaced path. Matches the FULL 4-tuple.
-- Matching only the remote half meant that behind NAT (or with a TIME_WAIT
-- remnant) two rows could match and the first one won, silently returning
-- another connection's port. Requiring the local address to match as well
-- makes a wrong answer impossible: if the row is ambiguous we return nil
-- and the caller records `unresolved` rather than guessing.
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
        return nil, "ambiguous: " .. matches .. " ESTABLISHED rows for " .. want_rem
    end
    if not found then
        return nil, "no ESTABLISHED row for " .. want_rem
    end
    return tonumber(found, 16)
end

--- Resolve the external port for the current request.
-- Returns a string (nginx variables are strings) or "" when unresolvable.
function _M.resolve()
    local port, err = port_from_proc_net(ngx.var.server_addr, ngx.var.remote_addr,
                                         ngx.var.remote_port)
    if port then
        stats.proc_ok = stats.proc_ok + 1
        return tostring(port)
    end
    stats.proc_fail = stats.proc_fail + 1
    stats.unresolved = stats.unresolved + 1
    ngx.log(ngx.ERR, "waf.external_port: proc=", tostring(err),
            " (not falling back to $server_port or ngx.req.socket)")
    return ""
end

_M._port_from_proc_net = port_from_proc_net
_M._ip4_to_proc_hex = ip4_to_proc_hex

return _M
