# SDD-004 Native External-Port Module Build Acceptance

**Date:** 2026-08-19
**Result:** **Source contract and reference Nginx dynamic-module build passed. Exact WAF image staging remains mandatory.**

## Passed repository gates

| Gate | Result | Evidence |
|---|---|---|
| No Lua request-path `/proc` implementation | Pass | `openresty/lua/waf/external_port.lua` is an empty-value diagnostic stub; it has no `io.open`, proc parser, or downstream socket use. |
| Native variable contract | Pass | `ngx_http_waf_external_port_module.c` exports `$waf_external_port`, invokes `ngx_connection_local_sockaddr`, handles `AF_INET`/`AF_INET6`, uses `ntohs`, and returns `not_found` rather than `$server_port` on failure. |
| Production config contract | Pass | Native example loads the module before `http`, never writes `$waf_external_port`, removes legacy resolver use, and returns 503 when a port-scoped WAF decision receives an empty value. |
| Static regression test | Pass | `tests/openresty/test_native_external_port_module.py` passed. |
| Native C module compile | Pass | `tests/staging/build-native-external-port-module.sh` built `ngx_http_waf_external_port_module.so` against Ubuntu Nginx development source (1.24.0) with `--with-compat`; the resulting module checksum was recorded by the script. |

## What this evidence means

The C module is source-coupled by design. Its reference build proves that the module config and Nginx C API use compile successfully against the tested Nginx source. It does **not** prove binary compatibility with the target OpenResty/Tengine image, which may contain a different Nginx revision, patches, compiler ABI, modules, or configure options.

The production evidence must use the exact deployed image/source and `nginx -V` configure arguments. The staging harness is intentionally committed rather than simulated: [build-native-external-port-module.sh](../tests/staging/build-native-external-port-module.sh) creates the version-specific module, and [waf-external-port-contract.sh](../tests/staging/waf-external-port-contract.sh) validates HTTP, keep-alive, TLS, HTTP/2, loader metrics and reservation state. WebSocket, actual WAF policy, graceful reload and traffic load are explicit product-specific cases in [the staging README](../tests/staging/README.md).

## External API basis

The implementation relies on Nginx connection-local socket handling rather than HTTP configuration variables or Lua request socket ownership. Nginx HTTP variables describe configured HTTP-server state, while the Nginx core owns connection/socket address paths; OpenResty Lua runs in the HTTP subsystem and must not be used here to take over a downstream request socket.[1] [2] [3]

## References

[1]: https://nginx.org/en/docs/http/ngx_http_core_module.html "Nginx HTTP Core Module"
[2]: https://github.com/openresty/lua-nginx-module "OpenResty ngx_http_lua_module"
[3]: https://github.com/nginx/nginx/blob/master/src/core/ngx_connection.c "Nginx connection implementation"
