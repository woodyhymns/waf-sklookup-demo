# https_allow_http for OpenResty 1.19.3.2

Port of Tengine's `https_allow_http` listen flag onto nginx 1.19.3 (bundled by
OpenResty 1.19.3.2). One `listen ... ssl https_allow_http;` accepts both
plaintext HTTP and TLS on the same TCP port.

## Upstream source

- Feature PR/commit: [alibaba/tengine#1866](https://github.com/alibaba/tengine/pull/1866) /
  [`573a423`](https://github.com/alibaba/tengine/commit/573a423e26b2dc84ea86c9b883617cbd3bae4a75)
- Issue/docs: [alibaba/tengine#1751](https://github.com/alibaba/tengine/issues/1751)
- Gate macro: `T_NGX_HTTPS_ALLOW_HTTP` (enabled via `auto/modules` → `auto/have`)

Touched files (same as Tengine, adapted to stock nginx 1.19.3 context):

| File | Change |
|------|--------|
| `auto/modules` | `have=T_NGX_HTTPS_ALLOW_HTTP` |
| `src/http/ngx_http_core_module.h` | `https_allow_http` bits on listen opt + addr conf |
| `src/http/ngx_http_core_module.c` | parse `https_allow_http` listen parameter |
| `src/http/ngx_http.c` | merge/copy flag across addr lists |
| `src/http/ngx_http_request.c` | on plain-HTTP peek, clear `hc->ssl` so 497 is skipped |

Runtime effect: nginx already peeks the first byte to distinguish TLS (`0x16`)
from HTTP. Without this flag, plain HTTP on an `ssl` listen ends as
`NGX_HTTP_TO_HTTPS` (497). With the flag, `hc->ssl = 0` and the request is
served as HTTP (`$scheme=http`).

## Build

```bash
# From repo root (or anywhere):
./third_party/https_allow_http/build-openresty-hah.sh
```

Defaults:

- `OPENRESTY_PREFIX=/usr/local/openresty-hah` (does **not** overwrite stock `/usr/local/openresty`)
- OpenResty 1.19.3.2 + bundled PCRE 8.45 (avoids Debian 13 missing `libpcre3-dev`)
- System OpenSSL + zlib

Rebuild after editing the patch: re-run the script (it re-extracts / re-applies).

## Verify

```bash
export OPENRESTY_PREFIX=/usr/local/openresty-hah
$OPENRESTY_PREFIX/bin/openresty -V
$OPENRESTY_PREFIX/bin/openresty -p /tmp/hah-smoke -c conf/nginx.conf -t
# (build script also runs a smoke nginx -t with listen 8443 ssl https_allow_http;)
```

Syntax for product configs:

```nginx
listen 127.0.0.1:8080 ssl https_allow_http;
```

See also `openresty/nginx.tengine-https-allow-http.conf.example`.
