# SDD 规格与需求追踪

本目录是动态端口生产能力的规格来源。实现、测试、验收和发布必须引用一个 SDD 编号；不以口头需求或单次 demo 结果替代规格。

| SDD | 主题 | 风险等级 | 当前状态 | TDD 覆盖 | 发布条件 |
|---|---|---|---|---|---|
| [SDD-001](SDD-001-management-plane-and-capacity-safety.md) | 管理面 reservation、精确 VIP 默认、map capacity/pressure | P0 | Partially implemented | T-001 至 T-007 | SDD-002 完成后更新 R3/R4/R8；继续执行 OpenResty/Tengine integration 与 target-host load。 |
| [SDD-002](SDD-002-endpoint-aware-runtime-reservation.md) | endpoint-aware reservation、runtime manifest、多 VIP 管理面隔离 | P0 | Implemented / real-kernel verified | T-020 至 T-026 | isolated real kernel 已通过；继续执行真实 OpenResty/Tengine integration。 |
| [SDD-003](SDD-003-atomic-upgrade-and-rollback.md) | BPF program/link 单机原子升级、ABI preflight、health window、rollback、revision/CAS 与 pressure freeze | P0 | Implemented / real-kernel verified | SDD-003-R1 至 R5 | exact WAF image、node/process crash recovery、target-host canary/fault injection。 |
| [SDD-004](SDD-004-native-external-port-variable.md) | native external-port variable；移除 Lua `/proc` request-path 依赖 | P0 | Reference build passed; staging pending | EP-1 至 EP-7 | exact OpenResty/Tengine image 的 HTTP/TLS/HTTP2/WebSocket/reload matrix。 |
| SDD-005（计划） | TLS/WAF/Lua 端到端流量与性能 SLO | P0 | Backlog | 待定义 | target-host traffic/chaos matrix。 |

## 本轮验收入口

| 规格 | 验收/工具 |
|---|---|
| SDD-003 | [真实内核 upgrade/control-plane 验收](../acceptance-sdd003-real-kernel-2026-08-19.md) · [`tests/e2e/sdd003-real-kernel-upgrade.sh`](../../tests/e2e/sdd003-real-kernel-upgrade.sh) · [`tests/e2e/sdd003-control-plane-real-kernel.sh`](../../tests/e2e/sdd003-control-plane-real-kernel.sh) |
| SDD-004 | [native module build 验收](../acceptance-sdd004-native-module-build-2026-08-19.md) · [staging harness](../../tests/staging/README.md) |

## 关联规则

| 工件 | 角色 |
|---|---|
| `docs/architecture/` | 行业横评、ADR、跨组件设计与不可逆决策。 |
| `docs/specs/` | 可测试需求、范围、非目标、TDD 编号与 Done 标准。 |
| `docs/dfx/` | 发布门禁、SLO、可观测性、可靠性、安全性和服务性要求。 |
| `tests/` | L0-L4 自动/半自动验证实现。 |
| `artifacts/` | 真实执行的原始输出；不能用人工摘要替代。 |

每次 Pull Request 或 release candidate 应在描述中列出 SDD、ADR、TDD、DFX gate 和 artifact 路径。任何未通过 gate 的豁免必须有 owner、到期日、风险说明和回滚路径。
