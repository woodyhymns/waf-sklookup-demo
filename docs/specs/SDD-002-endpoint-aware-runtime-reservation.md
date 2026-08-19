# SDD-002：Endpoint-aware Reservation 与 Runtime Manifest

**状态：** Implemented — isolated real-kernel verified; real OpenResty/Tengine staging pending.
**Owner：** WAF dynamic-port architecture.
**目标版本：** Production hardening iteration 2.
**关联：** [SDD-001](SDD-001-management-plane-and-capacity-safety.md)、[ADR-0001](../architecture/ADR-0001-exact-vip-default-and-wildcard-safety.md)。

## 1. 问题

`reserve=9101` 能避免 wildcard 动态端口抢占管理端口，但它以全局端口拒绝实现，会错误阻断合法的多 VIP 情形：例如 `10.0.0.10:9101` 是 WAF ingress，而 `127.0.0.1:9101` 是 exporter。更重要的是，`metrics-listen`、primary target、TLS target 来自 long-running loader 的运行参数；独立 `ctl` 进程若只读取静态 `policy.conf`，无法知道这些真实运行时端点。

本规格将 reservation 升级为 `(family, destination address mode, port, source)`，并将 loader 运行时端点写入与 pinned dataplane 生命周期绑定的 manifest。该 manifest 是所有控制面 mutation 的共同输入，而不是 operator 的口头约定。

## 2. 范围与非范围

本迭代覆盖 TCP `sk_lookup`、IPv4/IPv6 exact/wildcard endpoint、静态 policy reservation、runtime endpoint manifest 和控制面 admission。它不实现 CIDR/LPM、跨机器全局冲突、UDP、自动 program hot upgrade 或自动 capacity freeze；这些需求继续受 DFX release gate 约束。

## 3. 数据模型

```text
ReservedEndpoint {
  port: u16,
  destination: AnyFamily | AnyV4 | AnyV6 | ExactV4(ip) | ExactV6(ip),
  source: "policy.conf" | "metrics-listen" | "primary-target" | "tls-target"
}
RuntimeReservationManifest {
  schema_version: 1,
  pin_dir: canonical path string,
  endpoints: [ReservedEndpoint],
  generation: deterministic content hash
}
```

静态 `reserve=` 保持向后兼容，等价于 `AnyFamily` 的保守 reservation。新增可重复的 `reserve_endpoint=`，格式为 `IP:PORT` 或 `[IPv6]:PORT`，例如 `reserve_endpoint=127.0.0.1:9101`、`reserve_endpoint=10.0.0.10:443`。静态 endpoint source 固定为 `policy.conf`。

manifest 存放于普通运行时文件系统的 `/run/waf-sklookup/reservations/`，文件名由 `pin_dir` 的稳定 hash 生成；它绝不写入 bpffs。写入使用临时文件 + `rename`，读取失败、schema 不匹配、pin_dir 不匹配或 endpoint 无效时，独立控制面 mutation 必须 fail closed。

## 4. 冲突算法

所有待写 `PortKey` 与每个 effective reservation 比较，先比较 port，再应用下表。

| Dynamic binding | Reservation | 相同 family/port 时的结果 |
|---|---|---|
| 任意 destination | `AnyFamily`（legacy `reserve=`） | 拒绝。 |
| IPv4/IPv6 wildcard | 同 family 的 exact 或 wildcard endpoint | 拒绝；wildcard 会覆盖该 endpoint。 |
| exact destination | 同 family、同 exact address | 拒绝。 |
| exact destination | 同 family、不同 exact address | 允许。 |
| IPv4 binding | IPv6 endpoint，或反之 | 允许。 |

错误必须包含 port、binding key、reservation source 和 remediation。示例：`10.0.0.10:9101 conflicts with 127.0.0.1:9101 (metrics-listen); use another VIP or change the management endpoint`。

## 5. 生命周期与一致性

long-running loader 在 attach 成功、pin 成功且 listener 注册完成后，计算 effective runtime endpoints 并原子写入 manifest。至少包含：enabled `metrics-listen` 的 TCP endpoint、primary target、TLS target；Unix ctl socket 不进入 TCP reservation 集合。

loader 在 seed、SIGHUP reconcile 和本地 desired-state mutation 使用内存中的 runtime reservations。独立 CLI、Unix socket control、bulk/fill、central apply、apply/reconcile 则读取 static policy 与 pinned runtime manifest 合并后的 effective policy。loader 正常退出或 pin cleanup 时删除对应 manifest；任何无 pin 的 stale manifest 不能被用于 mutation。

## 6. 不变量

| ID | 不变量 | 优先级 |
|---|---|---|
| SDD-002-R1 | exact VIP binding 与不同 exact-address reservation 必须共存。 | P0 |
| SDD-002-R2 | wildcard binding 与同 family reservation 必须在 map/desired 写入前拒绝。 | P0 |
| SDD-002-R3 | `metrics-listen`、primary target、TLS target 必须由 loader 自动进入 runtime manifest。 | P0 |
| SDD-002-R4 | 所有 mutation surface 使用同一 effective policy；任何 manifest parse/identity failure fail closed。 | P0 |
| SDD-002-R5 | 旧 policy 仅含 `reserve=` 时行为保持保守兼容。 | P0 |
| SDD-002-R6 | status/exporter 可报告 manifest generation、endpoint count 和最近拒绝原因，但不暴露 tenant/IP 等高基数标签。 | P1 |
| SDD-002-R7 | manifest cleanup 不能删除仍被活动 BPF pin 使用的其他 instance manifest。 | P0 |

## 7. TDD 与验收

| 测试 | Red 条件 | Green 证据 |
|---|---|---|
| T-020 | exact `10.0.0.10:9101` 被 `127.0.0.1:9101` 错误拒绝 | policy unit test 允许。 |
| T-021 | wildcard `*:9101` 未拒绝 exact loopback exporter reservation | policy unit test 拒绝且含 source。 |
| T-022 | IPv4 binding 被 IPv6-only reservation 错误拒绝 | policy unit test 允许。 |
| T-023 | manifest round-trip、corrupt/mismatched pin path | unit test；异常 mutation fail closed。 |
| T-024 | long-running args 没有进入 manifest | startup integration test。 |
| T-025 | direct CLI/bulk/central 与 SIGHUP 使用不同 reservation | parameterized integration test。 |
| T-026 | 2 VIP + loopback exporter + wildcard negative case | isolated real-kernel namespace。 |

## 8. 发布边界

SDD-002 完成后才能将 SDD-001 的 R3/R4/R8 从“未完成”转为“已验证”。完成本规格仍不等于生产签字；capacity freeze、program/link upgrade rollback、真实 OpenResty/Tengine TLS/WAF 和目标硬件流量门禁继续阻断上线。
