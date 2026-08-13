# Production Go/No-Go P1 last run

- tip: `5844c7b`
- when: 2026-08-13 08:37:23 CST (utc 2026-08-13T00:37:23Z)
- env: OPENRESTY_PREFIX=/usr/local/openresty-hah · conf=openresty/nginx.tengine-https-allow-http.conf.example · LOADER_TLS_PORTS="" · DURATION=5s
- engine: nginx version: openresty/1.19.3.2
- bench: tools/httpbench + curl + bpftool + openssl (no wrk/ab)
- log: [acceptance-prod-gng-p1-last.log](acceptance-prod-gng-p1-last.log)

| 项 | 测了什么 | 结果 |
|----|----------|------|
| P1-a | BPF map bytes curve (memlock vs RSS) | 通过 (rc=0) |
| P1-b | multi-worker / SO_REUSEPORT skew | 通过 (rc=0) |
| P1-c | $waf_external_port ACL/log/limit true path | 通过 (rc=0) |
| P1-d | rollback drill unload/restore (+ PROXY N/A) | 通过 (rc=0) |

## Notes

- P1-a: map **memlock ≠ process RSS** (kernel-charged open_ports).
- P1-b: temp conf `worker_processes 4` + `reuseport`; restored to 1 after.
- P1-c: ACL deny + per-`$waf_external_port` rate limit (not Host).
- P1-d: PROXY path documented N/A if unimplemented; direct :8080 is observation path.

## Overall

overall=通过
