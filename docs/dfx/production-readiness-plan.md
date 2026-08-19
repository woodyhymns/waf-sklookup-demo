# Production Readiness Plan / 现网发布补齐计划

**Status / 状态：** Active engineering plan.
**Goal / 目标：** Move the dynamic-port WAF from isolated real-kernel evidence to a release candidate that may enter a customer-facing staging and canary process.
**Decision / 决策：** **No broad-production approval** until every P0 gate below has code, test evidence, an owner, a rollback action, and target-environment evidence.

> `sk_lookup` is appropriate for the problem: it can program socket selection for wide port or address ranges without binding every port in userspace. It is attached to a network namespace, and a selected socket is used only when the program returns `SK_PASS`.[1]
>
> `BPF_LINK_UPDATE` can replace the program behind one BPF link without a detach/re-attach gap, but this alone does not make the whole stateful application transaction atomic.[2] [3]

## 1. Release posture / 发布姿态

The project is **Conditional Go for staging; No-Go for broad production**. Existing evidence covers real `sk_lookup` attachment, four-worker steering, IPv4/IPv6, 30K/60K map occupancy, runtime endpoint reservation, private-bpffs identity, multi-VIP same-port isolation, serialized Unix-socket mutations, revision/CAS, pressure freeze, map-first ordinary-error compensation, and a single-node link commit/forced-health-failure rollback drill. It does not yet cover process/node-crash recovery across every control-plane journal window, WAF request semantics on the target OpenResty/Tengine image, target-hardware performance, or a canary rollback drill.

项目当前状态为**可进入受控 staging，禁止全量现网**。已有真实内核证据覆盖 `sk_lookup` attach、四 worker、IPv4/IPv6、30K/60K、运行时端点保护、private bpffs identity、多 VIP 同端口隔离、Unix socket 串行 mutation、revision/CAS、pressure freeze、普通错误下的 map-first 补偿以及单机 link commit/强制健康失败 rollback；但尚无控制进程/节点在每个 journal 窗口崩溃后的恢复、真实 WAF 请求路径、目标硬件性能和 canary 回滚演练证据。

## 2. P0 gates / P0 发布阻断项

| ID | Gate / 门禁 | Required implementation / 必需实现 | Required evidence / 必需证据 | Exit decision / 退出条件 |
|---|---|---|---|---|
| P0-1 | Upgrade transaction / 升级事务 | SDD-003 generation journal, ABI manifest, prepare/activate/health/commit/rollback states | **Partial pass:** single-link commit and forced health-failure rollback pass under traffic; remaining: kill controller/node after every externally visible phase and prove recovery converges | One-node rollback drill plus crash-recovery matrix pass under traffic |
| P0-2 | Control consistency / 控制面一致性 | Desired-state revision, expected-generation mutation, bounded lock/freeze, pressure admission | **Partial pass:** parallel writers, stale client, pressure freeze, and desired-file failure compensation pass; remaining: HUP/restart and partial-map batch failure recovery | No lost desired state; no mutation bypass across restart/crash |
| P0-3 | Dataplane safety / 数据面安全 | Exact VIP default, reservation manifest lifecycle, worker-health guard, failure counters | IPv4/IPv6, same port/different VIP, worker kill, loader restart, no-slot and assign-error injection | No management capture, no unknown assignment error |
| P0-4 | WAF semantic integration / WAF 语义集成 | Real OpenResty/Tengine image, Lua external-port path, policy binding | HTTP, HTTPS/SNI, HTTP/2, WebSocket, long connection, ACL, rate limit, audit/access logs | External port remains correct across all policy decisions |
| P0-5 | Performance and capacity / 性能与容量 | Target-node benchmark harness and dashboards | CPS/new-SYN, keep-alive RPS, p50/p99/p999, CPU, BPF runtime, RSS, map pressure, 60K tenant/VIP distribution | All values within agreed SLO budget for repeated runs |
| P0-6 | Operability and canary / 可运营与灰度 | Alert rules, dashboards, stop rule, rollback command, on-call runbook | Simulated alert, failed upgrade, TLS failure, map-pressure freeze, node rollback | Operator completes drill within agreed RTO |

## 3. P1 gates / P1 强化项

| ID | Scope / 范围 | Rationale / 理由 |
|---|---|---|
| P1-1 | Durable external manifest authority, RBAC, retention and tamper-evident audit | `/run` sidecars are node-local; central intent and audit durability need an explicit owner. |
| P1-2 | Multi-node rollout controller and per-node generation inventory | A node-local safe upgrade does not establish cluster-level consistency. |
| P1-3 | Compatibility corpus for map/schema evolution | Structural map checks cannot prove semantic state migration safety.[3] |
| P1-4 | Kernel and image qualification matrix | `sk_lookup`, BTF, libbpf, LSM and security capabilities must be tracked per production image. |

## 4. Engineering order / 实施顺序

The next implementation order is deliberately safety-first: (1) restart/crash recovery for mutation and upgrade journals, (2) exact-image native external-port and WAF semantics staging, (3) target-hardware performance/chaos, and (4) multi-node canary evidence. Cilium’s guidance similarly emphasizes preflight, preserving deployment configuration, constrained supported upgrade/rollback paths, and checking incompatible features before rollback.[4]

下一步严格按安全优先顺序执行：**mutation/upgrade journal 的 restart/crash recovery → exact-image native external-port 与 WAF 语义 staging → 目标硬件性能/chaos → 多节点 canary 证据**。禁止将容量 fill 或单机 curl 成功替代 WAF 语义、性能或回滚签字。

## 5. Non-substitutable customer inputs / 必须由真实环境提供的输入

The following cannot be truthfully manufactured in a sandbox and are mandatory before final release approval: target WAF image/build flags; exact Tengine/OpenResty version; TLS certificates and SNI matrix; production-equivalent rules; representative encrypted/plain traffic and concurrency distribution; target kernel/CPU/memory/NIC; management/ingress IP topology; alerting route; and an authorized rollback owner.

以下输入不能由沙箱伪造，且是最终发布签字的前提：目标 WAF image/build flag、准确 Tengine/OpenResty 版本、TLS/SNI 矩阵、生产等价规则、代表性明文/加密流量与并发分布、目标 kernel/CPU/memory/NIC、管理面/ingress IP 拓扑、告警路由和授权回滚 owner。

## References / 参考资料

[1] [Linux kernel: BPF `sk_lookup` program](https://docs.kernel.org/bpf/prog_sk_lookup.html)
[2] [libbpf: `bpf_link__update_program`](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_link__update_program/)
[3] [Eunomia: Stateful eBPF transactional upgrade analysis](https://eunomia.dev/research/stateful-ebpf-transactional-upgrade/)
[4] [Cilium Upgrade Guide](https://docs.cilium.io/en/stable/operations/upgrade/)
