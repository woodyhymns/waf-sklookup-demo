# Production Go/No-Go P0 last run

- tip: `04127bf`
- when: 2026-08-13 08:27:53 CST (utc 2026-08-13T00:27:53Z)
- env: OPENRESTY_PREFIX=/usr/local/openresty-hah · conf=openresty/nginx.tengine-https-allow-http.conf.example · LOADER_TLS_PORTS="" · DURATION=5s · HOT_COUNT=10000
- engine: nginx version: openresty/1.19.3.2
- bench: tools/httpbench + openssl s_time (no wrk/ab)
- log: [acceptance-prod-gng-p0-last.log](acceptance-prod-gng-p0-last.log)

| 项 | 测了什么 | 结果 |
|----|----------|------|
| P0-1 | 短连接 CPS + TLS 握手风暴 / 同口双协议 | 通过 (rc=0) |
| P0-2 | 长连接吞吐+P99 直连 vs sk_lookup | 通过 (rc=0) |
| P0-3 | Loader kill/unload/restart + map rebuild | 通过 (rc=0) |
| P0-4 | 热加删 ~10k 端口 + P99 采样 | 通过 (rc=0) |

## Go/No-Go

**推荐: Go（P0 全通过）** — 仍待 Alex / Json 书面门槛确认后再上线。

overall=通过
