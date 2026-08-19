# ADR-0002：以 Runtime Reservation Manifest 统一管理端点保护

**状态：** Accepted.
**日期：** 2026-08-19.
**关联规格：** [SDD-002](../specs/SDD-002-endpoint-aware-runtime-reservation.md)。

## 背景

dynamic-port loader 的实际管理端点并不完全存在于 `policy.conf`：metrics endpoint、primary/TLS internal target 来自启动参数，而独立 CLI 或 Unix control client 在运行时需要执行 map mutation。如果这些 mutation 仅依赖静态 policy，就会遗漏当前实例的 endpoint；若静态 `reserve=` 以全局 port 保护，又会破坏 multi-VIP 同端口隔离。

## 决策

每个成功 pin 的 long-running loader instance 将写入一份 runtime reservation manifest。manifest 使用 pin directory 的稳定 hash 命名，位于 `/run/waf-sklookup/reservations/`；不能位于 bpffs，因为 bpffs 不允许普通 JSON 文件。其写入通过同目录临时文件和原子 `rename` 完成。

manifest 记录 schema version、canonical pin directory、endpoint 列表和确定性 generation。所有 detached control-plane mutation 必须将 manifest 与 policy.conf 合并为 effective policy；manifest 已存在但不可读取、版本不匹配、pin identity 不匹配或 endpoint 非法时拒绝 mutation。缺失 manifest 保持 legacy 兼容，但只有没有活动 pin 的场景可安全使用该兼容路径。

Reservation 使用 endpoint-aware 交集算法。legacy `reserve=` 是跨 family 的 global-port reservation；`reserve_endpoint=` 与 runtime endpoint 使用 family/address-aware 规则。这样 wildcard binding 无法覆盖管理端点，而 exact ingress VIP 可以与不同地址上的 loopback management endpoint 共存。

## 后果

该设计让分离的 CLI、bulk、central apply、Unix socket control 和 loader reconcile 共享同一 reservation 合同。代价是 loader 生命周期多一个 runtime sidecar，并需要在 status/DFX 中显示 generation 与 endpoint count。任何手工删除 manifest 都会使后续 detached mutation fail closed，必须通过 loader restart/reconcile 恢复，而不是绕开保护。

## 被拒绝方案

| 方案 | 拒绝原因 |
|---|---|
| 仅靠 `reserve=` 全局 port | 安全但破坏 exact multi-VIP 场景，无法表达 endpoint source。 |
| 将 runtime JSON 写入 bpffs | bpffs 只接受 BPF 对象；private bpffs 已实证普通 JSON 会 `EPERM`。 |
| 每次 CLI 扫描 `/proc/net/tcp*` 推断管理端点 | 管理 endpoint 未必是 TCP listener，race 高、无 source、无法表示 intent，且控制面语义不可审计。 |
| 让每个 ctl 命令重复接收 target/metrics 参数 | 容易遗漏 mutation path，与实际 attached dataplane 的配置产生漂移。 |
