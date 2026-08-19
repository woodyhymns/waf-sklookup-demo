# External-Port Resolution Research Notes

## Purpose

These notes support the production decision to remove per-request `/proc/self/net/tcp` scanning from `openresty/lua/waf/external_port.lua`. They preserve only externally sourced findings; repository-specific conclusions belong in SDD/ADR documents.

## Findings

| Source | Finding relevant to the design |
|---|---|
| Nginx HTTP Core documentation | HTTP embedded variables describe configured server/listener state. They are not a documented contract for preserving the original destination of a connection whose lookup was redirected by `BPF_PROG_TYPE_SK_LOOKUP`; `$server_port` therefore must not be treated as evidence of the external dynamic port. |
| OpenResty `ngx_http_lua_module` documentation | The module runs inside the Nginx HTTP subsystem and supports HTTP-family downstream protocols. The existing project evidence already shows that taking over the downstream request socket in the request path is unsafe for this workload; a production external-port source must not consume or mutate request-body/socket ownership. |
| Nginx core `ngx_connection.c` | Nginx core owns a connection object and socket-address utility path. A tightly version-pinned native Nginx/OpenResty module can read connection-local socket information without walking procfs or taking over the Lua downstream request socket. This must be validated against the exact OpenResty/Tengine build because Nginx internal C APIs are not a stable cross-version ABI. |

## Design consequence

The selected production direction is a version-pinned native HTTP variable module that reads the accepted connection's local sockaddr at request-variable evaluation time and exposes only the numeric port as `$waf_external_port`. The module must fail closed (empty variable plus bounded metric) if the local sockaddr cannot be resolved. It must be compiled and tested against the exact OpenResty/Tengine image used in staging; there is no generic binary compatibility claim.

The Lua `/proc` implementation remains only as a deprecated diagnostic fallback during migration and must not be enabled for production WAF policy/ACL/rate-limit decisions.

## References

[1]: https://nginx.org/en/docs/http/ngx_http_core_module.html "Nginx ngx_http_core_module"
[2]: https://github.com/openresty/lua-nginx-module "OpenResty ngx_http_lua_module documentation"
[3]: https://github.com/nginx/nginx/blob/master/src/core/ngx_connection.c "Nginx core connection implementation"
