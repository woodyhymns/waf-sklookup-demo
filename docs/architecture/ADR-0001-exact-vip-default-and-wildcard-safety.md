# ADR-0001：精确 ingress VIP 默认，wildcard binding 必须具备管理面隔离

**状态：** Accepted
**日期：** 2026-08-16
**上下文：** [SDD-001](../specs/SDD-001-management-plane-and-capacity-safety.md)

## 决策

生产 WAF 动态端口 binding 默认使用精确的 `(AF, ingress VIP, port)` key。address 为全零的 wildcard binding 只能在以下任一条件满足时启用：其一，数据面和管理面位于不同 network namespace/interface/address；其二，所有管理 listener 都已通过 reservation policy 明确声明，且部署预检证明生成范围不相交。

## 原因

Linux `sk_lookup` 在 socket lookup 时依据 BPF 程序选择接收 socket。[1] 因此 wildcard key 对同一 address family 中匹配端口的本地流量具有效果，不存在“仅公网流量”的隐式范围。真实容量探索曾将管理端口落入 range；隔离 namespace 后 30K/60K 验收通过，证明风险可被工程约束消除，但不能依赖人为记忆。

精确 VIP 与当前数据面 `exact → wildcard` 查找顺序一致，不增加 BPF hot-path lookup 数量。它还允许同一主机的不同 VIP 使用相同端口而不互相影响。Cloudflare Tubular 亦将地址/prefix 和端口作为 binding 匹配语义的一部分，并定义重叠优先级。[2]

## 后果

| 正向后果 | 代价与缓解 |
|---|---|
| 管理端口不会因不同 VIP 的业务 binding 被端口级误拦截。 | 用户必须在接入时提供 ingress VIP；控制面应提供清晰错误和 migration 工具。 |
| 多 VIP / 多租户隔离可直接映射到 BPF key。 | wildcard 仍保留给单 VIP 或受隔离环境，不能作为默认便利选项。 |
| 运行时 metrics/ctl/health 可以放在独立地址或 namespace，故障域更清晰。 | 部署模板必须记录管理 endpoint 与 reservation source。 |

## 不采纳的方案

**端口全局 deny。** 它会阻止不同 VIP 在相同端口提供业务，破坏动态端口方案的租户隔离价值。

**让 BPF 程序识别“管理流量”。** 数据面不应解析用户态管理协议或维护高基数规则；reservation/admission 在低频控制面更可靠、可审计。

**仅通过文档提醒 operator。** 真实 30K 探索已证明人为 skip 容易漏掉 management endpoint，因此必须由 admission 自动执行。

## 验证

SDD-001 的 T-002、T-003、T-004、T-007 是本 ADR 的完成证据。任何未来引入 CIDR/LPM binding 的设计须新增 ADR 并定义 longest-prefix 与 reservation 的优先级。

## 参考资料

[1] [Linux Kernel — BPF `sk_lookup`](https://docs.kernel.org/bpf/prog_sk_lookup.html)
[2] [Cloudflare — Tubular bindings and precedence](https://blog.cloudflare.com/tubular-fixing-the-socket-api-with-ebpf/)
