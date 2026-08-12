# M3 验收清单：压测 · 对照 · 回退（含内存 / QPS / CPU）

- **里程碑**: [可执行里程碑：sk_lookup → OpenResty WAF](https://app.notion.com/p/3ba6e599de1981b292abfec7ccd84417) §M3
- **状态**: **充实草稿 / harness 准备** — **先不跑满量**（30K/60K 待 Repo P1 后或 M3 开工）
- **约束**: OpenResty **1.19.3.2** 路径；`$waf_external_port`；sk_lookup → 固定内听；同口双协议见 `docs/acceptance-p1-tls.md`（Tengine `https_allow_http`）

## 硬性：端口阶梯 × 内存 × QPS × CPU

压测与内存、QPS、CPU **同级**。至少填满 **30K / 60K**。

### 表 A — sk_lookup 端口阶梯

| 端口档 | loader RSS | OpenResty RSS | BPF map 内存 (`open_ports` 等) | QPS | CPU% | P99 | 备注 |
|--------|------------|---------------|--------------------------------|-----|------|-----|------|
| 基线 ≤10 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| 10 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| 100 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| 1K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| 10K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| **30K** | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | **Alex 必测** |
| **60K** | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | **Alex 必测** |

### 表 B — 对照（同档端口规模并排；含内存列）

| 路径 | 端口档 | QPS | CPU% | P99 | loader/accept RSS | OpenResty RSS | BPF/其它 map | 备注 |
|------|--------|-----|------|-----|-------------------|---------------|--------------|------|
| 直连 OpenResty 基线 | ≤10 | ☐ | ☐ | ☐ | — | ☐ | — | |
| sk_lookup | 30K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| sk_lookup | 60K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| PROXY+thin-accept | 30K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| PROXY+thin-accept | 60K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |

### 采集提示（harness 预留，未执行）

```bash
# RSS
ps -o pid,rss,comm -p <loader_pid>,<openresty_pids>

# BPF map
sudo bpftool map show name open_ports
# bytes / memlock / entries 一并抄录

# QPS / CPU / P99：以 Repo 压测工具为准（wrk/h2load/内部炮）——记录命令行与时长
```

产出：填满表 A/B + 增量曲线结论（是否近似线性、有无异常尖刺/泄漏）。

## 勾选总表

| # | 项 | 结果 |
|---|----|------|
| M3-perf | 长连接吞吐 + 短连接 CPS/QPS/P99；直连 vs sk_lookup vs PROXY | ☐ |
| M3-scale-conn | 10 / 100 / 1K 建连 P99 摸底（可衔接表 A） | ☐ |
| M3-mem | **30K/60K** RSS + BPF map + 增量；对照表含**内存列** | ☐ 预留 |
| M3-cpu-qps | 表 A/B 的 **QPS、CPU%** 列填齐 | ☐ 预留 |
| M3-hot | 加删端口 P99 尖刺（定性→定量） | ☐ |
| M3-rollback | 卸 sk_lookup → PROXY/旧架构演练有记录 | ☐ |
| M3-gate | 书面门槛：额外 CPU &lt; 3%～5%；30K/60K 内存可接受；无事故级抖动 | ☐ |

## Harness 准备（给 Repo · 并行）

Test 侧先不跑满量；Repo 若可并行暴露：

1. **批量写 `open_ports`**（30K/60K）CLI/API，避免人工循环
2. 稳定 **loader / worker PID** 或 metrics 端点（RSS、map entries）
3. 压测入口：同口 HTTP 或 HTTPS（与 P1 `https_allow_http` 语义对齐）
4. PROXY 对照最小可跑路径（便于表 B）

脚本占位（未来）：`scripts/accept-m3-mem-ladder.sh` — 按档灌端口 → 采 RSS/map → 可选打一发 QPS → 填表；**现在不实现满量**。

## 结论栏（开工后填）

- **总体**: ☐ PASS · ☐ FAIL · ☐ BLOCKED
- **是否默认 sk_lookup / PROXY 回退**:
- **时间 (Asia/Shanghai)**:

---
*Test · Json P1 分工充实；满量待 Repo P1/M3 就绪*
