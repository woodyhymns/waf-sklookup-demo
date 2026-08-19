# SDD-003：BPF Program/Link 原子升级与可验证回滚

**状态：** Proposed / P0 backlog。
**前置：** SDD-001、SDD-002。
**目标：** 让数据面升级从“reload 后观察”变成有 identity、有兼容性检查、有回滚证明的受控变更。

## 1. 问题

当前 loader 能 pin maps、program 和 netns link，也会校验 program tag 与 map layout；但尚未定义完整的双代升级事务。当 BPF object、map ABI、link attach 或 listener registration 在升级中任一步失败时，必须能明确回答旧 dataplane 是否仍处理流量、控制面是否仍写入正确 generation、以及怎样在秒级回滚。

## 2. 设计合同

升级以 `generation` 为最小一致性单位。每个 generation 包含 object identity（program tag、BTF/build identity）、map ABI manifest、netns link、listener shard registration、runtime reservation manifest 和 desired-state revision。新 generation 在 shadow pin path 完整 load、verifier 通过、ABI compatibility 通过、listener 注册和 desired reconcile 成功后，才允许激活；旧 generation 必须保留至新 generation 健康窗口结束。

| 状态 | 允许的数据面 | 控制面行为 |
|---|---|---|
| `prepare` | 仅旧 generation | 拒绝 mutation，返回 `upgrade_in_progress`。 |
| `shadow-ready` | 仅旧 generation | 可读状态，不写 map。 |
| `activate` | 新 generation；旧 generation 保留 | 仅接受带 expected generation 的 mutation。 |
| `health-window` | 新 generation | 监视 dataplane fault、worker shard、reservation、drift。 |
| `commit` | 新 generation | 删除旧 pin，更新 durable generation。 |
| `rollback` | 旧 generation | 恢复旧 link/map 指针并记录失败原因。 |

## 3. 不变量与测试

| ID | 不变量 | 验收 |
|---|---|---|
| SDD-003-R1 | ABI 不兼容（key/value size、map type、max entries、stat slots）在 attach 前失败。 | object compatibility unit/integration。 |
| SDD-003-R2 | prepare/attach/register/reconcile 任一步失败时，旧 generation 仍保留且新 connection 可达。 | fault injection matrix。 |
| SDD-003-R3 | mutation 必须携带或服务端解析 expected generation；stale client 不得覆盖新 desired state。 | concurrent ctl test。 |
| SDD-003-R4 | activation 后 health window 内 fault ratio、`no_slot`、shard health、reservation state、drift 任一越界则自动 rollback。 | real-kernel canary drill。 |
| SDD-003-R5 | status/audit 明确显示 active、previous、rollback reason、elapsed 和 compatibility result。 | DFX contract test。 |

## 4. 非目标

本规格不等同集群发布编排，不处理跨机任播/VIP cutover。多机控制面在单机 generation 语义稳定后，由独立规格定义。
