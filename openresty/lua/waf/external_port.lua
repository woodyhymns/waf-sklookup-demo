local ffi = require "ffi"

ffi.cdef[[
    unsigned short ntohs(unsigned short netshort);
    struct in_addr { unsigned int s_addr; };
    struct sockaddr { unsigned short sa_family; char sa_data[14]; };
    struct sockaddr_in {
        unsigned short sin_family;
        unsigned short sin_port;
        struct in_addr sin_addr;
        unsigned char sin_zero[8];
    };
    typedef unsigned int socklen_t;
    int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
]]

local C = ffi.C

local function ip4_to_proc_hex(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then
        return nil
    end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    return string.format("%08X", a + b * 256 + c * 65536 + d * 16777216)
end

-- After sk_lookup, the ESTABLISHED 4-tuple local port is the client destination
-- (external port), not the OpenResty listen port. $server_port must not be used.
local function port_from_proc_net(remote_ip, remote_port)
    local rem_hex = ip4_to_proc_hex(remote_ip)
    if not rem_hex or not remote_port then
        return nil, "missing remote addr"
    end
    local want_rem = rem_hex .. ":" .. string.format("%04X", tonumber(remote_port))
    local f, err = io.open("/proc/self/net/tcp", "r")
    if not f then
        return nil, "open /proc/self/net/tcp: " .. tostring(err)
    end
    f:read("*l") -- header
    for line in f:lines() do
        local local_addr, rem_addr, st = line:match("%s*%d+:%s*(%x+:%x+)%s+(%x+:%x+)%s+(%x+)")
        if local_addr and st == "01" and rem_addr:upper() == want_rem then
            local port_hex = local_addr:match(":(%x+)$")
            f:close()
            return tostring(tonumber(port_hex, 16))
        end
    end
    f:close()
    return nil, "no ESTABLISHED row for " .. want_rem
end

local function port_from_fd(fd)
    local addr = ffi.new("struct sockaddr_in[1]")
    local addrlen = ffi.new("socklen_t[1]", ffi.sizeof("struct sockaddr_in"))
    if C.getsockname(fd, ffi.cast("struct sockaddr *", addr), addrlen) ~= 0 then
        return nil, "getsockname failed"
    end
    return tostring(C.ntohs(addr[0].sin_port))
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
    if not fd then
        return nil, err or "getfd failed"
    end
    return port_from_fd(fd)
end

local _M = {}

function _M.resolve()
    local port, err = port_from_proc_net(ngx.var.remote_addr, ngx.var.remote_port)
    if port then
        return port
    end
    local port2, err2 = port_from_req_socket()
    if port2 then
        return port2
    end
    ngx.log(ngx.ERR, "waf.external_port: proc_net=", err, " getsockname=", err2,
            " (not falling back to $server_port)")
    return ""
end

return _M
