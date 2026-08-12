# M3 验收清单（草稿 / 预留）：压测 · 对照 · 回退

- **里程碑**: [可执行里程碑：sk_lookup → OpenResty WAF](https://app.notion.com/p/3ba6e599de1981b292abfec7ccd84417) §M3
- **状态**: **DRAFT / 预留** — **不要**在本草稿上跑完整 30K/60K 压测；等 Repo **P1 / M3 readiness**
- **约束回响**: OpenResty **1.19.3.2**；外口走 `$waf_external_port`；sk_lookup → 固定内听；业务口 ≠ `$server_port`
- **执行人**: Test（QA）— harness 可先准备；全量规模待 Repo 暴露批量开端口 / 指标刮取点

> Explicit: **full scale waits for Repo P1/M3 readiness.** Tables below are scaffolds for evidence, not a run log.

## 目标（验收时证明什么）

1. **M3-perf**: 吞吐 / CPS / P99 相对直连与 PROXY 可接受
2. **M3-mem**: 内存随端口规模近似可控（含 **30K / 60K**）
3. **M3-rollback**: 卸 sk_lookup 可回到 PROXY/旧架构并有记录
4. **M3-gate**: 书面上线门槛（例：相对直连额外 CPU &lt; 3%～5%）达成或明确豁免

## 端口阶梯矩阵（内存 + QPS + CPU + P99）

压测矩阵**必须**含内存随端口规模变化，不只是吞吐/P99。  
**全量 30K/60K：暂不执行** — 仅在 Repo 提供批量开端口 API / 工具后由 Test 填实。

| 端口阶梯 | loader RSS | OpenResty RSS | BPF map 内存 | QPS | CPU%（或 cores busy） | P99 latency | notes |
|---------|------------|---------------|--------------|-----|----------------------|-------------|-------|
| baseline（≤10） | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | 少端口对照；可先用默认 `18081,18082,65500` |
| 10 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| 100 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| 1K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| 10K | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | |
| **30K** | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | **Alex 要求 · 待 Repo ready** |
| **60K** | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | **Alex 要求 · 待 Repo ready** |

### 记录方式建议（执行时填实 — 现在只准备）

```bash
# 进程 RSS（示例）
ps -o pid,rss,comm -p <loader_pid>,<openresty_master>,<openresty_workers>
# 或:
grep -E 'VmRSS|VmHWM' /proc/<pid>/status

# CPU%（示例，采样窗口与压测对齐）
pidstat -p <pids> 1 <N>
# 或 mpstat /perf stat；记 cores busy 亦可

# BPF map 侧（以实际 map 名为准）
sudo bpftool map show name open_ports
sudo bpftool map show pinned /sys/fs/bpf/waf-sklookup/open_ports
# 抄 memlock / bytes；不足则补 prog/map 汇总

# QPS / P99（工具以 harness 为准：wrk / h2load / vegeta / 自研）
# 固定：OpenResty 1.19.3.2、同机、同 payload、同并发阶梯
```

产出物：**上表填满** + 简短结论（是否随端口近似线性、有无 RSS/BPF/CPU 尖刺）。

## 架构对照表（sk_lookup vs PROXY vs direct）

同一负载模型下比较（填内存 + QPS + CPU；P99 可附注）。

| 架构 | 说明 | 内存（loader+OR+BPF / 或总量） | QPS | CPU% / cores | P99 | notes |
|------|------|--------------------------------|-----|--------------|-----|-------|
| **direct** baseline | 直连 OpenResty 内听或旧架构直连（无 sk_lookup / 无 PROXY） | ☐ | ☐ | ☐ | ☐ | 性能基线 |
| **sk_lookup** | BPF sk_lookup → 固定内听；外口在 map | ☐ | ☐ | ☐ | ☐ | 本方案 |
| **PROXY** | 旧 PROXY/转发路径（若环境仍有） | ☐ | ☐ | ☐ | ☐ | 回退对照 |

相对直连的额外开销（gate 用）：

| 指标 | sk_lookup vs direct | PROXY vs direct | 门槛（草案） |
|------|---------------------|-----------------|--------------|
| 额外 CPU | ☐ | ☐ | 例：&lt; 3%～5% |
| QPS 回退 | ☐ | ☐ | 书面约定 |
| P99 增量 | ☐ | ☐ | 书面约定 |
| 内存增量 @30K / @60K | ☐ | ☐ | 无异常尖刺 |

## Checklist

| # | 项 | 结果 | 证据槽 |
|---|----|------|--------|
| **M3-perf** | 长连接吞吐 / 短连接 CPS / P99；对照 direct vs sk_lookup vs PROXY | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ SKIP(wait Repo) | 对照表 + 原始压测日志路径 |
| **M3-mem** | 端口阶梯 RSS + BPF map；必含 **30K / 60K** | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ SKIP(wait Repo) | 阶梯表填满 |
| **M3-scale-conn** | 开通 10 / 100 / 1K（及更高）时建连 P99 | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ SKIP | 可与阶梯表衔接 |
| **M3-hot** | 加删端口时 P99 尖刺（定性→定量） | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ SKIP | 热加删时间线 |
| **M3-rollback** | 卸 sk_lookup → PROXY/旧架构演练有记录 | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ SKIP | 步骤 + 恢复时间 |
| **M3-gate** | 书面上线门槛达成或豁免签字 | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ SKIP | 门槛文档链接/摘录 |

## Harness 准备（给 Repo — 并行准备，不在此执行全量）

Test 可先准备并行 harness 脚本骨架；下列由 **Repo** 暴露后才能跑满阶梯：

| 需求 | 为什么 | 建议形态 |
|------|--------|----------|
| **Port bulk load API / CLI** | 一次写入 10…60K `open_ports`（或等价） | `loader -mode load-ports -ports-file ports.txt` / HTTP admin（若 P1 有） |
| **Port bulk delete / replace** | 热加删与 rollback | CLI + 幂等 |
| **Metrics scrape points** | QPS、延迟直方图、RSS 旁路 | `/metrics`（Prometheus）或文档化 `pidstat`+access_log 方案 |
| **Stable pin path** | CI/本地一致 | 现有 `PIN_DIR=/sys/fs/bpf/waf-sklookup` |
| **TLS/HTTP 负载开关** | P1 TLS 后分别压 HTTP/HTTPS | 配置或 env |
| **单 worker / 多 worker 说明** | 1.19.3.2 reuseport 行为 | README / openresty-m1 续写 |

本地烟雾（**非** M3 全量；仅确认工具链）可继续用：

```bash
OPENRESTY_PREFIX=/usr/local/openresty ./scripts/accept-m1.sh
```

## 明确不在本草稿执行

- ❌ 完整 **30K / 60K** 端口装载与压测
- ❌ 上线门槛签字
- ❌ 与生产流量对打

待 **Repo P1（TLS/产品头策略）** 与 **M3 readiness（批量端口 + 指标）** 后再开 Test 执行轮。

## 结论栏（执行后填写）

- **总体**: ☐ PASS · ☐ FAIL · ☐ BLOCKED · ☑ DRAFT (not run at full scale)
- **OpenResty 版本字符串**: _must remain 1.19.3.2_
- **最大端口阶梯已跑**: _TBD_
- **Gate 结论**: _TBD_
- **报告时间 (Asia/Shanghai)**: _TBD_
- **阻塞 / 交还 Repo**: 批量开端口 API、metrics 刮取点、P1/M3 readiness 声明

---
*预留原因: Json / Alex — M1 照旧；M3 清单预留 RSS + BPF map、30K/60K，并补 QPS/CPU 与架构对照。*
*Test 风格: checklist · evidence-first · 全量规模等待 Repo。*
