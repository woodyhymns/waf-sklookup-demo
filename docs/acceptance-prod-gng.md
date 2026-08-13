# Production Go/No-Go 验收包（Acceptance）

- **分支**: `test/prod-gng-acceptance`（基于 `main@09d138b`）
- **Tip SHA**: `04127bf`
- **Scope**: HAH OpenResty `/usr/local/openresty-hah`（1.19.3.2 + `https_allow_http`）+ **Go loader**；Rust **DEFER**
- **产品路径**: 同口 HTTP+HTTPS；`LOADER_TLS_PORTS=""`；conf `openresty/nginx.tengine-https-allow-http.conf.example`
- **前置**: M3 30K/60K 内存阶梯已 PASS（见 [acceptance-m3-full-run.md](acceptance-m3-full-run.md)）
- **执行人**: Test QA · 勿 merge · 勿 push（Repo 稍后推）
- **Bench 约束**: **不依赖 wrk/ab**（镜像 apt 502）。使用 `tools/httpbench`（net/http CPS/P99）+ `openssl s_time`（TLS 握手风暴）+ curl 兜底

## 环境默认值

| 变量 | 默认 |
|------|------|
| `OPENRESTY_PREFIX` | `/usr/local/openresty-hah` |
| `OPENRESTY_NGINX_CONF` | `openresty/nginx.tengine-https-allow-http.conf.example` |
| `LOADER_TLS_PORTS` | `""`（空 = 产品单听，跳过 stock TLS fallback） |
| `PORT` | `18081` |
| `DURATION` | `8s`（P0 bench 窗口，5–10s） |
| `CONCURRENCY` | `50` |
| `HOT_COUNT` | `10000`（非 60K） |
| `CGO_ENABLED` | `0` |

## 一键跑 P0

```bash
export OPENRESTY_PREFIX=/usr/local/openresty-hah
export OPENRESTY_NGINX_CONF=openresty/nginx.tengine-https-allow-http.conf.example
export LOADER_TLS_PORTS=""
make accept-prod-p0
# 或: ./scripts/accept-prod-p0.sh
```

产出：

- [acceptance-prod-gng-p0-last.md](acceptance-prod-gng-p0-last.md) — 短表
- [acceptance-prod-gng-p0-last.log](acceptance-prod-gng-p0-last.log) — 全文 log

个别脚本：

```bash
./scripts/accept-prod-p0-cps-tls.sh
./scripts/accept-prod-p0-long-p99.sh
./scripts/accept-prod-p0-loader-lifecycle.sh
./scripts/accept-prod-p0-hot-ports.sh
```

Makefile: `accept-prod-p0` / `accept-prod-p0-cps-tls` / `accept-prod-p0-long-p99` / `accept-prod-p0-loader-lifecycle` / `accept-prod-p0-hot-ports`

---

## P0（门禁必须跑）

### P0-1 短连接 CPS + TLS 握手风暴 / 同口双协议

- **脚本**: `scripts/accept-prod-p0-cps-tls.sh`
- **测什么**:
  1. 同口 dual: `curl http://127.0.0.1:$PORT/` + `curl -k https://127.0.0.1:$PORT/`
  2. HTTP 短连接 CPS: `tools/httpbench`（DisableKeepAlives）
  3. TLS 握手风暴: `openssl s_time -connect HOST:PORT -new -time N -www /`
- **缺工具**: 标 **阻塞**（不编造数字）

| 项 | 测了什么 | 结果 |
|----|----------|------|
| dual-proto | 同口 :18081 HTTP+HTTPS scheme ok | 通过 |
| http-cps | short rps=625.3 p99_us=155444 ok=3234 fail=0 (5s c=50) | 通过 |
| tls-hs-storm | openssl s_time -new 1195 conn / 6s real (~199 CPS) | 通过 |

### P0-2 长连接吞吐 + P99（直连 vs sk_lookup）

- **脚本**: `scripts/accept-prod-p0-long-p99.sh`
- **腿 A**: 直连内听 `127.0.0.1:8080`（HAH 上 HTTPS 亦同口 `https_allow_http`）
- **腿 B**: sk_lookup 导向外口 `$PORT`
- **模式**: httpbench `-keepalive`，HTTP + HTTPS 各跑

| leg | protocol | target | rps | p99_us | 结果 |
|-----|----------|--------|-----|--------|------|
| A direct | HTTP | 127.0.0.1:8080 | 311.1 | 1655852 | 通过 |
| A direct | HTTPS | 127.0.0.1:8080 | 275.4 | 227819 | 通过 |
| B sk_lookup | HTTP | 127.0.0.1:18081 | 346.2 | 1668891 | 通过 |
| B sk_lookup | HTTPS | 127.0.0.1:18081 | 276.2 | 211831 | 通过 |

注：HTTP keepalive p99 偏高（A/B 同量级，单 worker + 短窗尖刺）；sk_lookup 未显著劣于直连。

### P0-3 Loader kill / unload / restart

- **脚本**: `scripts/accept-prod-p0-loader-lifecycle.sh`
- **步骤**: demo 运行中 kill loader → 观察失败形态 → `run-openresty-demo.sh start` 恢复 → `bpftool`/pin 确认 map rebuild → curl 恢复
- **可观测性**: `$TMPDIR/waf-sklookup-m1/loader.log`、`sudo bpftool map show name open_ports`、`ss -lntp`、curl

| 项 | 测了什么 | 结果 |
|----|----------|------|
| kill-fail-mode | kill 后 curl rc=7 / http_code=000 | 通过 |
| map-repin | pin+open_ports max_entries=131072 重建 | 通过 |
| curl-recover | HTTP+HTTPS :18081 恢复 200 | 通过 |
| observability | loader.log + bpftool + ss | 通过 |

### P0-4 热加删端口 ~10k + P99

- **脚本**: `scripts/accept-prod-p0-hot-ports.sh`
- **步骤**: 背景轻流量 → `bulk open -range` ~10000 → 采样 → `bulk close` 一半 → 再采样
- **CLI**: `sudo ./waf-sklookup-demo bulk open/close -range START-END`

| phase | rps | p99_us | ok | 结果 |
|-------|-----|--------|----|------|
| before | 371.8 | 807566 | 1905 | 通过 |
| during (10k open, 15ms) | 370.3 | 917110 | 1913 | 通过 |
| after (close half, 14ms) | 401.4 | 889239 | 2057 | 通过 |

热口探测 `:20100` → 200 / waf_external_port=20100 · 通过

---

## P1（文档项；脚本可选 stub）

| # | 项 | 说明 | 结果 |
|---|----|------|------|
| P1-a | BPF map bytes curve | 随端口规模的 map/memlock 曲线（可复用 M3 ladder + `bpftool map show`） | 文档 / M3 已有 30K/60K 点 |
| P1-b | reuseport skew | 多 worker / reuseport 倾斜观察（本 demo `worker_processes 1`，记 N/A 或后续） | ☐ stub |
| P1-c | `$waf_external_port` true path | 导向口 body/access_log 真值（P1/M1 已验；生产抽检） | 参见 acceptance-p1 |
| P1-d | rollback drill | 卸 sk_lookup / 停 loader → 业务回退路径演练记录 | ☐ stub |

可选 stub（不作为 P0 门禁）:

```bash
# P1-a quick map bytes
sudo bpftool map show name open_ports
# P1-d rollback sketch
./run-openresty-demo.sh stop   # detach loader; document client impact + recovery
```

---

## Go / No-Go 判决（占位 → 跑完填写）

> **Go/No-Go:** **推荐 Go（P0 全通过 @ HAH, DURATION=5s, HOT_COUNT=10000, tip 04127bf）** — 仍待 Alex / Json 书面门槛确认后再上线。
>
> 规则：P0 全 **通过** → 推荐 **Go**（仍待书面门槛确认）；任一 **失败** → **No-Go**；缺工具/环境不明 → **阻塞**。

最近一次自动跑：见 [acceptance-prod-gng-p0-last.md](acceptance-prod-gng-p0-last.md)。

---

## 产物清单

| 路径 | 用途 |
|------|------|
| `docs/acceptance-prod-gng.md` | 本清单 |
| `docs/acceptance-prod-gng-p0-last.md` | 最近 P0 短表 |
| `docs/acceptance-prod-gng-p0-last.log` | 最近 P0 全文 |
| `tools/httpbench/` | Go CPS/P99 bench（替代 wrk/ab） |
| `scripts/lib-prod-gng.sh` | 共享 env/helpers |
| `scripts/accept-prod-p0*.sh` | P0 脚本 + umbrella |
| `Makefile` targets `accept-prod-p0*` | make 入口 |

---
*Test QA · branch test/prod-gng-acceptance · do not merge · do not push*
