-- Deprecated diagnostic compatibility stub.
--
-- Production external-port resolution is provided by the version-pinned native
-- ngx_http_waf_external_port_module as $waf_external_port. Do not restore a
-- /proc/self/net/tcp scan or take over the downstream Lua request socket here:
-- either approach is unsafe on a hot WAF request path.
--
-- This stub returns an empty value so an accidental legacy configuration fails
-- closed rather than substituting $server_port (the internal listener port).

local ngx = ngx
local _M = {}

local stats = {
    native_required = 0,
}

function _M.stats()
    return {
        native_required = stats.native_required,
    }
end

function _M.resolve()
    stats.native_required = stats.native_required + 1
    ngx.log(ngx.ERR, "waf.external_port legacy Lua resolver invoked; ",
            "load ngx_http_waf_external_port_module and use $waf_external_port")
    return ""
end

return _M
