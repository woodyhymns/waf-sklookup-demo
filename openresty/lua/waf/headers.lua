-- Debug response headers. Default: do not expose X-Waf-External-Port.
-- Enable with WAF_EXPOSE_EXTERNAL_PORT=1 (process env; requires nginx `env`)
-- or set $waf_expose_external_port to 1 in nginx.conf.
-- $waf_external_port is still filled for access_log / body / Lua regardless.

local _M = {}

local function truthy(v)
    return v == "1" or v == "true" or v == "TRUE" or v == "yes"
end

function _M.expose_debug_headers()
    local var = ngx.var.waf_expose_external_port
    if truthy(var) then
        return true
    end
    return truthy(os.getenv("WAF_EXPOSE_EXTERNAL_PORT"))
end

function _M.apply_debug_headers(port)
    if not _M.expose_debug_headers() then
        ngx.header["X-Waf-External-Port"] = nil
        return
    end
    ngx.header["X-Waf-External-Port"] = port or ""
    ngx.header["X-Waf-Internal-Port"] = ngx.var.server_port
end

return _M
