# 测试矩阵与 TDD 执行规则

本矩阵把 [SDD-001](../specs/SDD-001-management-plane-and-capacity-safety.md) 的需求映射到自动化测试和真实流量证据。测试顺序固定为 **Red → Green → Real Kernel → Artifact**：先提交或保留能失败的测试，再实现最小正确代码，最后以隔离真实内核证明控制面约束没有绕过 BPF 数据面。

| ID | 层级 | 场景 | 触发 | 通过条件 | 现状 |
|---|---|---|---|---|---|
| T-001 | L1 | `reserve=` policy 解析、合并、非法值 | 每次 policy 改动 | parse result 稳定，未知字段/非法端口拒绝 | 本迭代实现。 |
| T-002 | L1 | wildcard binding 与 runtime metrics/target reservation 冲突 | 每次 admission 改动 | map 与 desired state 均未写入 | 本迭代实现。 |
| T-003 | L1 | exact VIP 与不同地址 reservation 的隔离 | 每次 key/admission 改动 | 不同 address 可共用端口 | 本迭代实现。 |
| T-004 | L1/L2 | add/bulk/reconcile/central 共用 admission | 每次 control-plane 改动 | 任一路径不可绕过 reservation | 本迭代先覆盖 shared policy helper。 |
| T-005 | L1 | capacity metric snapshot | 每次 metrics 改动 | entries/max/pressure/headroom 同时出现且数值一致 | 本迭代实现。 |
| T-006 | L1/L2 | map capacity/threshold 拒绝 | 每次 quota/admission 改动 | 不变性：失败前后 map 相同 | 本迭代单测；真机后续。 |
| T-007 | L2 | wildcard large fill 保留 metrics/control endpoint | release candidate | scrape 保持有效，外部端口转发保持有效 | 30K/60K namespace evidence 已有；新 reservation 逻辑待复验。 |
| T-008 | L2 | program/link/map pin、tag mismatch、worker kill | BPF 或 lifecycle 改动 | fail-closed mutation、bounded recovery | 已有 baseline，持续回归。 |
| T-009 | L3 | OpenResty/Tengine HTTP、TLS、Lua external port、HAH body | release candidate | WAF 语义与普通 listen 一致 | 需要 staging。 |
| T-010 | L4 | direct vs steered CPS、keep-alive、map mutation、pressure | 灰度前 | 明确 p99/RPS/CPU budget，满足 SDD | 需要 target host。 |
| T-011 | L4 | crash/restart/rollback/management endpoint chaos | 灰度前 | alert、runbook、rollback 时限满足 SLO | 需要 target host。 |

## TDD 判定规则

1. 每个 P0 bug 或能力必须新增一个最小可复现测试，测试名称含 SDD/T 编号或表达可读业务不变量。
2. 单元测试不 mock BPF admission 语义；map 写入和真实 `sk_lookup` 行为至少由一个 L2 test 覆盖。
3. 真实内核 tests 必须运行在管理面隔离的 network namespace、独立 host 或精确 ingress VIP 上。禁止在承载自动化控制通道的 host namespace 对 wildcard range 做大规模 fill。
4. 基准数据必须存原始产物：命令、内核、CPU/内存、map info、metrics、成功/失败数、清理结果；摘要不能替代原始证据。
5. 任何 flaky 结果不准通过调整阈值“刷绿”；应记录样本顺序、环境干扰、置信结论与复测条件。
