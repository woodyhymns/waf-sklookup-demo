# M3 full Go ladder run（30K + 60K）

- tip: `a01b5b2` (`pr-7-m2`)
- env: `OPENRESTY_PREFIX=/usr/local/openresty-hah` · openresty/1.19.3.2 · conf `nginx.tengine-https-allow-http.conf.example`
- artifacts: [acceptance-m3-ladder-last.csv](acceptance-m3-ladder-last.csv) · [acceptance-m3-full-run.log](acceptance-m3-full-run.log)

| 项 | 测了什么 | 结果 |
|----|----------|------|
| env | openresty-hah + tip | openresty/1.19.3.2 · tip `a01b5b2` · PASS |
| map max_entries | bpftool `open_ports` | **131072** (memlock 10487488B); stale 1024 map also visible |
| 30K | bulk fill + RSS/QPS/CPU | have=30000 · loader/OR **7024/10780** kB · QPS≈100 · CPU≈0 · fill 8ms · PASS |
| 60K | bulk fill + RSS/QPS/CPU | have=60000 · loader/OR **7024/10784** kB · QPS≈85 · CPU≈0 · fill 16ms · PASS |
| functional probe | curl high port 34999 | HTTP 200 · PASS |
| Rust | — | DEFER |
| overall | M3 Go ladder 30K+60K | **PASS** |
