# SDD 规格与需求追踪

本目录是动态端口生产能力的规格来源。实现、测试、验收和发布必须引用一个 SDD 编号；不以口头需求或单次 demo 结果替代规格。

| SDD | 主题 | 风险等级 | 当前状态 | TDD 覆盖 | 发布条件 |
|---|---|---|---|---|---|
| [SDD-001](SDD-001-management-plane-and-capacity-safety.md) | 管理面 reservation、精确 VIP 默认、map capacity/pressure | P0 | Accepted / implementation pending | T-001 至 T-007 | Rust 单测、isolated real kernel、OpenResty/Tengine integration、target-host load。 |
| SDD-002（计划） | BPF program/link 原子升级、ABI manifest、rollback | P0 | Backlog | 待定义 | canary + fault injection。 |
| SDD-003（计划） | 控制面版本化事务、generation、审计与多租户权限 | P0 | Backlog | 待定义 | concurrency + recovery drill。 |
| SDD-004（计划） | TLS/WAF/Lua 端到端流量与性能 SLO | P0 | Backlog | 待定义 | target-host traffic/chaos matrix。 |

## 关联规则

| 工件 | 角色 |
|---|---|
| `docs/architecture/` | 行业横评、ADR、跨组件设计与不可逆决策。 |
| `docs/specs/` | 可测试需求、范围、非目标、TDD 编号与 Done 标准。 |
| `docs/dfx/` | 发布门禁、SLO、可观测性、可靠性、安全性和服务性要求。 |
| `tests/` | L0-L4 自动/半自动验证实现。 |
| `artifacts/` | 真实执行的原始输出；不能用人工摘要替代。 |

每次 Pull Request 或 release candidate 应在描述中列出 SDD、ADR、TDD、DFX gate 和 artifact 路径。任何未通过 gate 的豁免必须有 owner、到期日、风险说明和回滚路径。
