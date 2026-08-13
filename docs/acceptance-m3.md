# M3 验收清单：压测 · 内存阶梯 · 回退（Go loader）

- **基线**: `main@ab66cf5` + harness 分支；引擎优先 **`/usr/local/openresty-hah`**（1.19.3.2 + `https_allow_http`）
- **状态**: **harness ready**（`scripts/accept-m3-ladder.sh`；smoke `LADDER=10,100` OK on HAH）· 满档 **30K/60K 等 M2 bulk** + **`open_ports` map 扩容**（当前 `max_entries=1024`）
- **实现**: **仅 Go loader 列** — **Defer Rust**（不占本表列；Go 基线通过后再开 Rust 同指标复测）
- **产品 listen**: `OPENRESTY_NGINX_CONF=openresty/nginx.tengine-https-allow-http.conf.example`，`LOADER_TLS_PORTS=""`（main 已支持）
- **不 merge / 不 push**（draft harness 本地分支）

## 怎么跑

```bash
export OPENRESTY_PREFIX=/usr/local/openresty-hah
# 小阶梯（默认 10,100,1000 — 现在可跑；1K 接近 map 上限 1024）
./scripts/accept-m3-ladder.sh
# 或
make accept-m3-ladder

# 更快冒烟
LADDER=10,100 DURATION=3 ./scripts/accept-m3-ladder.sh

# 满档（无 M2 bulk 会 WARN；map 未扩容会 BLOCKED）
LADDER=10,100,1000,30000,60000 ./scripts/accept-m3-ladder.sh
```

常用环境变量：`LADDER` · `BASE_PORT`（默认 20000；满 60K 需更低如 2048）· `BATCH`（默认 1000）· `DURATION` / `QPS_TOOL=auto|wrk|curl|none` · `PIN_DIR` · `TARGET` · `BULK_CMD`（可选）。

产出：`docs/acceptance-m3-ladder-last.csv`（gitignore）+ 终端 markdown 简表（项/测了什么/结果）。

## 表 A — Go 端口阶梯（RSS / BPF / QPS / CPU）

| 端口档 | Go loader RSS | OpenResty RSS | BPF map (`open_ports`) | QPS | CPU% | P99 | notes |
|--------|---------------|---------------|------------------------|-----|------|-----|-------|
| 10 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | 小阶梯 / harness 冒烟 |
| 100 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| 1K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | 接近 `max_entries=1024` |
| 10K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | 需 map 扩容 |
| **30K** | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | Alex 必测 · 空着等 M2 bulk + map resize |
| **60K** | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | Alex 必测 · 空着等 M2 bulk + map resize |

> **Defer Rust**：上表**无** Rust loader 列。

采样命令（harness 已包；手工复核时）：

```bash
ps -o pid,rss,comm -p <loader_pid>,<openresty_pids>
sudo bpftool map show name open_ports   # memlock / max_entries
sudo ./waf-sklookup-demo -mode dump-ports -pin-dir /sys/fs/bpf/waf-sklookup | wc -l
```

## 表 B — 架构对照（占位）

| 路径 | 端口档 | QPS | CPU% | P99 | Go loader RSS | OpenResty RSS | BPF map | notes |
|------|--------|-----|------|-----|---------------|---------------|---------|-------|
| 直连 OpenResty | ≤10 | ☐ | ☐ | ☐ | — | ☐ | — | |
| sk_lookup (Go) | 30K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| sk_lookup (Go) | 60K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| PROXY（若有） | 30K/60K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |

## Defer Rust

**不**在本轮跑 Rust loader，**不**占上表列。M3 Go 基线通过后再开 Rust 同指标复测。

## 勾选

| # | 项 | 结果 |
|---|----|------|
| M3-harness | `scripts/accept-m3-ladder.sh` 可跑小阶梯 | ☐ |
| M3-mem | 30K/60K RSS + BPF map 填表 | ☐ SKIP(wait M2 bulk + map resize) / ☐ |
| M3-cpu-qps | QPS/CPU/P99 列填齐 | ☐ |
| M3-perf | vs 直连/PROXY | ☐ |
| M3-rollback | 卸 sk_lookup 回退 | ☐ |
| M3-gate | 门槛书面结论 | ☐ |
| M3-rust | Rust 复测 | ☑ **DEFER** |

## 阻塞（满档 30K/60K）

| 阻塞 | 影响 | 缓解 |
|------|------|------|
| **M2 bulk `load-ports` / `-ports-file` 未就绪** | 无高效批量开通；只能分批 `open-port`（慢） | Repo 出 bulk；harness 已支持 `BULK_CMD` / 探测 `load-ports`，否则 `BATCH` 分批 + 进度 |
| **`open_ports` `max_entries=1024`**（`dispatch.bpf.c`） | **无法**容纳 30K/60K（1K 已近顶） | Repo 扩容 map 后重跑 |
| 机器内存/CPU | 满档采样失真 | 专用压测机 |
| PROXY 对照未实现 | 表 B PROXY 行空 | Repo 最小 PROXY 或 N/A |

---
*Test · M3 harness draft · Go only · defer Rust · 不 merge*
