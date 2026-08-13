# M3 验收清单：压测 · 内存阶梯 · 回退（Go loader）

- **基线**: `main` @ P1 合入后；引擎优先 **`/usr/local/openresty-hah`**（`https_allow_http`）
- **状态**: **harness 可执行** · 满档 30K/60K **等 M2 bulk** 或接受慢速分批 `open-port`
- **实现**: **仅 Go loader** — **Defer Rust**（复测另开，不占本表列）
- **不 merge**（draft harness 另开 PR）

## 怎么跑

```bash
export OPENRESTY_PREFIX=/usr/local/openresty-hah
# 小阶梯（默认可现在跑）
./scripts/accept-m3-ladder.sh
# 满档（无 bulk 会 WARN/慢）
LADDER=10,100,1000,30000,60000 ./scripts/accept-m3-ladder.sh
# 或: make accept-m3-ladder
```

产出：`docs/acceptance-m3-ladder-last.csv` + 终端简表。

## 表 A — Go 端口阶梯（RSS / BPF / QPS / CPU）

| 端口档 | Go loader RSS | OpenResty RSS | BPF map (`open_ports`) | QPS | CPU% | P99 | notes |
|--------|---------------|---------------|------------------------|-----|------|-----|-------|
| ≤10 / 10 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| 100 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| 1K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| 10K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| **30K** | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | Alex 必测 · 待 M2 bulk 或分批 |
| **60K** | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | Alex 必测 · 待 M2 bulk 或分批 |

## 表 B — 架构对照（Go sk_lookup；PROXY/直连后续）

| 路径 | 端口档 | QPS | CPU% | P99 | loader RSS | OpenResty RSS | BPF map | notes |
|------|--------|-----|------|-----|------------|---------------|---------|-------|
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
| M3-mem | 30K/60K RSS + BPF map 填表 | ☐ SKIP(wait M2 bulk) / ☐ |
| M3-cpu-qps | QPS/CPU 列填齐 | ☐ |
| M3-perf | vs 直连/PROXY | ☐ |
| M3-rollback | 卸 sk_lookup 回退 | ☐ |
| M3-gate | 门槛书面结论 | ☐ |
| M3-rust | Rust 复测 | ☑ **DEFER** |

## 阻塞

| 阻塞 | 影响 | 缓解 |
|------|------|------|
| **M2 bulk `load-ports` / ports-file 未就绪** | 30K/60K 只能分批 `open-port`（慢、易超时） | Repo 出 bulk；或 `BATCH`+长时跑 |
| 机器内存/CPU | 满档采样失真 | 专用压测机 |
| PROXY 对照未实现 | 表 B PROXY 行空 | Repo 最小 PROXY 或 N/A |

---
*Test · Json M3 开工：可执行阶梯 + Go only · defer Rust*
