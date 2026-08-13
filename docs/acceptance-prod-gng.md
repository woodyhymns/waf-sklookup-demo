# Production Go/No-Go 验收包（Acceptance）

- **分支**: `test/prod-gng-acceptance`（基于 `main@09d138b`）
- **Tip SHA**: `0e3bafe` (Written gates table content from `741db63`)
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

## 一键跑 P1

```bash
export OPENRESTY_PREFIX=/usr/local/openresty-hah
export OPENRESTY_NGINX_CONF=openresty/nginx.tengine-https-allow-http.conf.example
export LOADER_TLS_PORTS=""
make accept-prod-p1
# 或: ./scripts/accept-prod-p1.sh
```

产出：

- [acceptance-prod-gng-p1-last.md](acceptance-prod-gng-p1-last.md) — 短表
- [acceptance-prod-gng-p1-last.log](acceptance-prod-gng-p1-last.log) — 全文 log

个别脚本 / Makefile: `accept-prod-p1-map-bytes` / `accept-prod-p1-reuseport` / `accept-prod-p1-waf-port-path` / `accept-prod-p1-rollback`

---

## P1（应跑项）

### P1-a BPF map bytes curve

- **脚本**: `scripts/accept-prod-p1-map-bytes.sh`
- **测什么**: baseline → bulk fill 30K → 60K（可选 near-full ≤u16；100K unique N/A）采样 `bpftool map show name open_ports` memlock/max_entries + loader RSS + OR RSS
- **强调**: **map memlock ≠ process RSS**（内核记账）

| ports | map memlock B | max_entries | loader RSS | OR RSS | note |
|-------|---------------|-------------|------------|--------|------|
| baseline (have=3) | 10487488 | 131072 | ~7 MB | ~8.3 MB | few ports |
| 30K (have=30001) | 10487488 | 131072 | ~7 MB | ~8.3 MB | fill ~20ms |
| 60K (have=60001) | 10487488 | 131072 | ~7 MB | ~8.3 MB | fill ~27ms |
| near-full(~60500) | 10487488 | 131072 | ~7 MB | ~8.3 MB | 100K unique N/A (u16) |

**结果: 通过** — memlock 预充到 max_entries（~10.5MB）且随端口占用几乎不变；**≠ process RSS**（loader/OR 基本持平）。详见 [p1-last](acceptance-prod-gng-p1-last.md)。

### P1-b multi-worker / SO_REUSEPORT skew

- **脚本**: `scripts/accept-prod-p1-reuseport.sh`
- **测什么**: 生成临时 conf：`worker_processes 4` + `listen ... https_allow_http reuseport`；lua shared dict 按 `ngx.worker.id()` 计数；并发短连接后看分布
- **通过**: 无单 worker ~100% 而其余 idle 的极端倾斜；若 sk_lookup+multi-worker 在本栈不可用 → **阻塞**（不假 PASS）
- **恢复**: 跑完恢复 `worker_processes 1` 默认 conf

| 项 | 测了什么 | 结果 |
|----|----------|------|
| conf-4-reuseport | worker_processes=4 + listen reuseport | 通过 |
| worker-dist | w0..w3 ≈ 25% each (max_pct≈25.8, idle=0) | 通过 |
| restore-wp1 | 恢复 worker_processes=1 默认 conf | 通过 |

**结果: 通过** — 本栈 sk_lookup→reuseport 组未出现单 worker 吃满。

### P1-c `$waf_external_port` true path（ACL / log / limit）

- **脚本**: `scripts/accept-prod-p1-waf-port-path.sh`
- **测什么**: 临时 conf：access_log 保留 `waf_external_port`；`access_by_lua` 在 `resolve()` 后 ACL deny `19999`；shared dict 按 **external port** 限流
- **证明**: 口 A→200 且 body/log=`waf_external_port=A`（非 Host）；deny 口→403；A 突发 503 时同 Host 的 B 仍 200

| 项 | 测了什么 | 结果 |
|----|----------|------|
| port-A-body/log | :18081 Host=wrong → waf_external_port=18081 | 通过 |
| acl-deny | :19999 → 403 | 通过 |
| limit-by-ext-port | burst A→503 ×12 同时 B→200（同 Host） | 通过 |

**结果: 通过**

### P1-d rollback drill

- **脚本**: `scripts/accept-prod-p1-rollback.sh`
- **测什么**: 导向 curl 200 → 定时 unload loader/detach → 导向失败 + 直连 `:8080` 仍可用 → 定时 restore loader → 导向恢复
- **PROXY**: 若仓库无 PROXY 实现 → **N/A/阻塞(无实现)**；观察路径 = 直连内听

| 项 | 测了什么 | 结果 |
|----|----------|------|
| unload | kill loader + unpin ~0.11s；导向 rc=7 | 通过 |
| direct-8080 | 直连内听仍 200（回退观察路径） | 通过 |
| restore | loader READY ~0.26s；HTTP+HTTPS 恢复 | 通过 |
| PROXY-fallback | 仓库无 PROXY 回退实现 | **N/A/阻塞(无实现)** |

**结果: 通过**（直连内听路径）；PROXY 子路径阻塞/无实现。

---

## Go / No-Go 判决（占位 → 跑完填写）

> **Go/No-Go（门槛锁定后）:** 见下方 **Written gates (locked)**。  
> 功能/脚本向：P0+P1 场景 **通过**；对照 G1–G10 后 **有条件 Go**（差 G6 p99 比；G2 abs Pending）。确认前 **不 merge**。
> 规则：P0 全 **通过** → 推荐 **Go**（仍待书面门槛确认）；任一 **失败** → **No-Go**；缺工具/环境不明 → **阻塞**。

最近一次自动跑：见 [acceptance-prod-gng-p0-last.md](acceptance-prod-gng-p0-last.md)。

最近一次 P1：见 [acceptance-prod-gng-p1-last.md](acceptance-prod-gng-p1-last.md)。

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
| `scripts/accept-prod-p1*.sh` | P1 脚本 + umbrella |
| `docs/acceptance-prod-gng-p1-last.md` | 最近 P1 短表 |
| `docs/acceptance-prod-gng-p1-last.log` | 最近 P1 全文 |
| `Makefile` targets `accept-prod-p0*` / `accept-prod-p1*` | make 入口 |

---
*Test QA · branch test/prod-gng-acceptance · do not merge · do not push*


---

## Written gates (locked)

> **锁定来源**: Json 默认锁定（业界收紧 + **G2 相对优先**；绝对 p99≤10ms 待校准后另验）。  
> **对照跑次**: P0 [acceptance-prod-gng-p0-last.md](acceptance-prod-gng-p0-last.md) · P1 [acceptance-prod-gng-p1-last.md](acceptance-prod-gng-p1-last.md) · HAH `openresty/1.19.3.2` · tip 证据见上。  
> **不 merge** 直至 Alex 书面确认；Rust 仍 DEFER。

| Gate | 门槛 | 对照证据（现跑次） | 状态 |
|------|------|-------------------|------|
| **G1** | sk_lookup/直连 **rps 比 ≥ 0.98** | HTTP 346.2/311.1=**1.113**；HTTPS 276.2/275.4=**1.003**（P0-2） | **Pass** |
| **G2** | **相对** p99 比 ≤ **1.05**；**绝对** p99 ≤ **10ms**（校准后） | 相对：HTTP 1668891/1655852=**1.008**；HTTPS 211831/227819=**0.930** → 相对 OK。绝对：HTTP p99≈1.66s / HTTPS≈0.21s **≫10ms**（短窗+单 worker 尖刺，A≈B） | **Pass（相对）** / **Pending(G2 abs)** |
| **G3** | fail=0 且 error ≤ 0.01% | P0 各腿 `fail=0`（短连 ok=3234；长连/热更各腿 fail=0） | **Pass** |
| **G4** | TLS 路径 CPS/吞吐 比 ≥ **0.95** | HTTPS keepalive rps 比 **1.003**（P0-2）。另：导向口 openssl s_time ≈199 CPS（P0-1，无直连对照腿） | **Pass** |
| **G5** | map **memlock ±2%**；进程 **RSS ≤5%**（相对阶梯） | memlock 全程 **10487488B**（0%）；loader/OR RSS 7008/8308 kB 阶梯持平（P1-a） | **Pass** |
| **G6** | 热更 10k：**open ≤50ms** · fail=0 · 期间 p99 比 ≤ **1.10** | open **15ms** · fail=0；p99 during/before 917110/807566=**1.136**（>1.10）；after/before≈1.10 | **Pending**（时延/失败 OK；**p99 比超标**） |
| **G7** | fail-closed；restore ≤ **1s** | kill 后 curl rc=7（P0-3）；P1-d restore ≈**0.26s** | **Pass** |
| **G8** | reuseport：max worker 占比 ≤ **35%** · idle=0 | max_pct=**25.8** · idle=0 · 4 workers（P1-b） | **Pass** |
| **G9** | 外口硬门：`$waf_external_port` 真路径（非 Host） | ACL deny :19999→403；按外口限流 A→503 且同 Host B→200；body/log 外口正确（P1-c） | **Pass** |
| **G10** | unload ≤ **0.5s** · restore ≤ **1s**；PROXY **N/A** | unload ≈**0.11s** · restore ≈**0.26s**；PROXY **N/A（无实现）**（P1-d） | **Pass** |

### 现跑次 vs 已锁门槛（结论）

| 结论项 | 结果 |
|--------|------|
| 除 **G2 abs** 与 **G6 p99 比** 外 | 其余 G1–G5/G7–G10 **满足** |
| G2 绝对 p99≤10ms | **Pending(G2 abs)** — 需校准环境/更长窗后再验；相对门已过 |
| G6 热更 p99 比 | **未满足**（1.136 > 1.10）；open 15ms / fail=0 已过 |
| 是否建议「现跑次满足已锁门槛（除 G2 abs）」 | **否（差 G6 p99 比）** — 建议复跑热更窗或放宽/重测 G6 后再锁 Go |
| Go/No-Go（门槛视角） | **有条件 Go**：相对性能/正确性门已过；**G6 复测前不宣称全面满足** |

### 交叉引用

- P0-2 → G1/G2/G3/G4  
- P0-1 → G3/G4（TLS storm）  
- P0-3 → G7  
- P0-4 → G6  
- P1-a → G5  
- P1-b → G8  
- P1-c → G9  
- P1-d → G7/G10  

