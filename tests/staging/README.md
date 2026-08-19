# Real WAF Staging Harness

This directory is intentionally a **staging harness**, not a claim that the repository can emulate a customer's WAF image. It builds the native external-port module against an exact Nginx/OpenResty/Tengine source tree and executes a port-semantics contract against a deployed staging endpoint.

## Required inputs

| Input | Why it is required |
|---|---|
| Exact WAF image or exact source tree | Native Nginx modules are source/ABI coupled. A module built for another Nginx/OpenResty/Tengine build is invalid evidence. |
| `nginx -V` output and build manifest | Captures core version, configure flags, compiler, OpenSSL/LuaJIT/Tengine patches, module checksum, and image digest. |
| Isolated staging ingress VIP(s) | Multi-VIP `sk_lookup` semantics must be tested without exposing wildcard dynamic ports over the management plane. |
| Test certificate and SNI names | Required for TLS, SNI, ALPN/HTTP2, and certificate reload paths. |
| Representative WAF policy/rule set | Port-scoped ACL, rate-limit, tenant lookup, logging and reject semantics must execute as production would. |
| Approved service-manager commands | Only the platform's service manager may reload/restart the WAF during the test. The harness never evaluates a shell reload string. |

## Execution sequence

First, unpack or check out the exact Nginx/OpenResty/Tengine source corresponding to the staging image. Run the module build script with the production configure arguments copied from `nginx -V`.

```bash
./tests/staging/build-native-external-port-module.sh \
  /srv/src/openresty-nginx-exact \
  --with-http_ssl_module --with-http_v2_module
```

Install only that generated `.so` into the matching image/module directory. Record the SHA-256 printed by the script alongside the image digest and `nginx -V` output. Use `openresty/nginx.native-external-port.conf.example` as the integration pattern: it loads the module before `http`, does not define `set $waf_external_port`, and has no `access_by_lua` call to the legacy resolver.

After the loader and WAF are started, export the endpoint variables and run the contract. It validates config syntax, HTTP, keep-alive, TLS, HTTP/2, loader metrics, runtime reservation state, and native external-port output.

```bash
export WAF_NGINX_BIN=/opt/waf/openresty/nginx/sbin/nginx
export WAF_NGINX_PREFIX=/etc/waf/openresty
export WAF_HTTP_URL=http://198.51.100.10:18081/waf-port-contract
export WAF_HTTPS_URL=https://198.51.100.10:18443/waf-port-contract
export WAF_EXPECT_HTTP_PORT=18081
export WAF_EXPECT_HTTPS_PORT=18443
export WAF_METRICS_URL=http://127.0.0.1:9101/metrics
./tests/staging/waf-external-port-contract.sh
```

## Mandatory manual/product-specific cases

The WAF product team must capture request/response transcripts and observability evidence for the following cases. These are deliberately not faked by a generic harness.

| Case | Required assertion |
|---|---|
| HTTP/1.1 keep-alive | Multiple requests on one TCP connection keep the original external port; ACL/rate-limit sees the same value. |
| TLS with SNI and ALPN | TLS handshake, SNI route, certificate selection, and HTTP/2 request see the external destination port, not the internal listener. |
| WebSocket | Upgrade succeeds; the WAF logs/ACL see the correct port before upgrade; long-lived session survives the stated observation window. |
| HTTP/2 multiplexing | Independent streams on one connection have the connection's external port and no Lua downstream socket errors. |
| Graceful WAF reload | Existing connection behavior meets product contract; new connection after reload resolves the correct port. |
| Port-scoped policy | Allow, deny, rate-limit and tenant configuration each use correct port input; native lookup failure is fail-closed. |
| Worker loss/rescan | Kill one reuseport worker; watch shard metrics, no-slot/assign errors, recovery and existing WAF behavior. |
| BPF upgrade/rollback | Execute SDD-003 success and forced health-failure rollback while canary HTTP/TLS traffic is running. |

## Evidence and sign-off

Archive the contract artifacts, native module SHA, exact image digest, `nginx -V`, loader `status`, Prometheus scrape, WAF access/error log extracts, TLS/HTTP2/WebSocket transcripts, load-test raw output, and rollback journal. A staging result is valid only if all mandatory cases pass on the exact target image and target kernel family.
