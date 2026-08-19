# SDD-004: Native External-Port Variable for WAF Policy

**Status:** Implementing

## Context

The dynamic-port data plane steers an inbound SYN to a fixed internal listener. WAF policy, ACL, quota, rate-limit, logging, and tenant attribution must nevertheless see the external port selected by the client. The existing Lua resolver scans `/proc/self/net/tcp` on every request. That approach is not acceptable as a production policy dependency: it has request-path file I/O, only models IPv4, and can only fail safely by returning an empty value after work has already been done.

`$server_port` is a configured-server/listener concept and is not accepted as evidence of the original dynamic destination. Taking ownership of the downstream Lua request socket is prohibited because it can change body/socket behavior. The production source is therefore a version-pinned native HTTP variable module that obtains the accepted connection's local sockaddr through Nginx core APIs.

## Scope

The module exports a read-only `$waf_external_port` variable. It returns an ASCII decimal port from the current accepted TCP connection local sockaddr. It supports `AF_INET` and `AF_INET6`; it emits an empty not-found value for unknown families, non-INET local sockets, unavailable connections, or sockaddr resolution failure.

The module does not determine tenant identity, map port to configuration, alter connection ownership, take a Lua cosocket, perform `/proc` I/O, query BPF maps, or make authorization decisions itself. Existing WAF policy is responsible for treating an empty external port as a closed/error condition when a port-bound rule applies.

## Requirements

| ID | Requirement | Acceptance evidence |
|---|---|---|
| EP-1 | Variable evaluation performs no `/proc` I/O, Lua socket takeover, map lookup, or allocation proportional to connection count. | Source contract test plus exact-image staging trace. |
| EP-2 | IPv4 and IPv6 local sockaddrs return the numeric port in network byte order. | Unit harness and exact OpenResty/Tengine integration test. |
| EP-3 | Unknown/unavailable local sockaddr produces an empty, `not_found` variable rather than `$server_port` or a guessed port. | Unit test. |
| EP-4 | Variable is cacheable for the request, has no writable setter, and returns an immutable value allocated from the request pool only. | Source review and module test. |
| EP-5 | The module builds only against the exact deployed Nginx/OpenResty/Tengine source/configuration; module `.so` files are never reused across releases without compatibility validation. | Staging build manifest captures `nginx -V`, source revision, compiler and module checksum. |
| EP-6 | Lua `/proc` resolver is disabled by default in production configuration. A temporary diagnostic fallback requires an explicit environment/config switch and cannot feed ACL/rate-limit decisions. | Staging config test. |
| EP-7 | HTTP/1.1 keep-alive, HTTP/2, TLS/SNI, WebSocket upgrade and a new connection after graceful reload preserve a correct external port. | Staging matrix. |

## API contract

```nginx
load_module modules/ngx_http_waf_external_port_module.so;

http {
    # The module registers this variable; no `set` or Lua write is permitted.
    log_format waf '$waf_external_port $request';
}
```

The variable value has exactly two states: a decimal `1..65535` port or empty. It must not use `0`, an internal listener port, a stale cached value from another request, or a synthetic fallback.

## Migration

The OpenResty `access_by_lua` assignment is removed from the production configuration. The existing Lua file is retained only as explicitly marked diagnostic legacy code until the first real-image staging release completes. A deployment must fail its config gate if both the native module and the legacy policy resolver are active.

## Release blockers

This implementation cannot be signed for broad production until it passes on the exact WAF image against the exact Nginx/OpenResty/Tengine build flags. The native module is intentionally source-coupled, so source-level test success in this repository is not binary compatibility evidence.

## References

[1]: https://nginx.org/en/docs/http/ngx_http_core_module.html "Nginx HTTP Core Module"
[2]: https://github.com/openresty/lua-nginx-module "OpenResty ngx_http_lua_module"
[3]: https://github.com/nginx/nginx/blob/master/src/core/ngx_connection.c "Nginx connection implementation"
