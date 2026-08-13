# M3 验收清单（草稿 / 预留）：压测 · 对照 · 回退

- **里程碑**: [可执行里程碑：sk_lookup → OpenResty WAF](https://app.notion.com/p/3ba6e599de1981b292abfec7ccd84417) §M3
- **状态**: **预留草稿** — 不在 M1 执行；大规模压测待 M3 开工
- **约束回响**: OpenResty **1.19.3.2**；外口走 `$waf_external_port`；sk_lookup → 固定内听

## 预留：内存 vs 端口规模（Alex）

压测矩阵**必须**含内存随端口规模变化，不只是吞吐/P99。

**M2 seed (do this first):** `open_ports` is sized **131072** (was 1024 — that blocked this ladder). With the loader already running (`./run-openresty-demo.sh start`), flood the map without an OpenResty reload:

```bash
./scripts/m3-fill-ports.sh 30000
./scripts/m3-fill-ports.sh 60000
# equivalent: sudo ./waf-sklookup-demo bulk fill -count 30000 -start 5000
```

See [docs/openresty-m2.md](openresty-m2.md). CLI bulk is the contract; HTTP API is not required for these fills.

| 端口阶梯 | RSS（loader / OpenResty，分开记） | BPF map 内存（`open_ports` 等，bpftool/统计） | 备注 |
|---------|-----------------------------------|-----------------------------------------------|------|
| 基线（少端口，如 ≤10） | ☐ | ☐ | |
| **30K** | ☐ | ☐ | Alex 要求 |
| **60K** | ☐ | ☐ | Alex 要求 |
| （可选）10 / 100 / 1K / 10K 中间点 | ☐ | ☐ | 对齐 perf-deep-compare 建连阶梯时可兼用 |

记录方式建议（执行时填实）：

```bash
# 进程 RSS（示例）
ps -o pid,rss,comm -p <loader_pid>,<openresty_worker_pids>

# BPF map 侧（以实际 map 名为准）
sudo bpftool map show name open_ports
# 若有 memlock / bytes 字段一并抄录；不足则补 /proc/<pid>/status VmRSS + bpftool prog/map 汇总
```

产出物：**端口阶梯内存表**（上表填满）+ 简短结论（是否随端口近似线性、有无异常尖刺）。

## 其它 M3 项（占位，开工时展开）

| # | 项 | 结果 |
|---|----|------|
| M3-perf | 长连接吞吐 / 短连接 CPS / P99；对照直连基线 vs sk_lookup vs PROXY | ☐ |
| M3-scale-conn | 开通 10 / 100 / 1000 端口时建连 P99（可与上表阶梯衔接） | ☐ |
| M3-hot | 加删端口时 P99 尖刺（定性→定量） | ☐ |
| M3-mem | **内存 vs 端口规模（30K / 60K）+ RSS + BPF map 表** | ☐ 预留 |
| M3-rollback | 回退演练（卸 sk_lookup → PROXY/旧架构）有记录 | ☐ |
| M3-gate | 书面上线门槛（例：相对直连额外 CPU &lt; 3%～5%） | ☐ |

---
*预留原因: Json 预告（Alex）— M1 照旧；写 M3 清单时预留 RSS + BPF map、30K/60K 端口阶梯内存表。*
