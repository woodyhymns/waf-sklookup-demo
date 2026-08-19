# SDD-001：管理面隔离与 dataplane 容量安全

**状态：** Partially implemented — production completion pending.
**Owner：** WAF dynamic-port architecture.
**目标版本：** Production hardening iteration 1.
**关联：** [行业差距评估](../architecture/industry-production-gap.md)、[真实 30K/60K 验收](../acceptance-m3-real-kernel-2026-08-16.md)。

## 1. 问题与范围

`sk_lookup` wildcard binding 可以将任意本地 IPv4/IPv6 地址上匹配端口的新连接转入 WAF worker。它解决了“无 Nginx reload 的动态端口”问题，也会在管理面端口落入 range 时改变 metrics、host agent 或调试服务的连接语义。真实容量探索已经验证该风险；隔离 network namespace 和显式 skip set 可以规避测试环境问题，但生产系统需要把这种隔离做成**控制面不变量**，而不是 operator 的记忆。

同时，BPF hash map 到达上限时写入会失败。entry count 不是足够的运维接口；生产需要 current/max/pressure/headroom、admission 决策和一致的告警阈值。Cilium 将 map upper bound 和 pressure 作为 datapath 可扩展性的显式对象，本规格采纳同一工程原则，而不复制其 Kubernetes 功能范围。[1]

本规格只覆盖 TCP WAF 动态端口、管理面 reservation、map capacity/pressure 和关联 DFX。UDP、CIDR/LPM binding、多机一致性和自动 BPF program upgrade 不在本迭代实现范围，但必须被架构文档列为后续 SDD。

## 2. 术语

| 术语 | 定义 |
|---|---|
| **binding** | 一个 `(family, destination address, port) → redir group` 动态端口规则。 |
| **wildcard binding** | address 为全零的 binding；匹配同 family 的所有本地目的地址。 |
| **reserved endpoint** | 不能被动态 binding 接管的管理或固定监听 endpoint；至少包含 exporter、WAF internal target、stock TLS fallback、operator 显式声明端口。 |
| **map pressure** | `open_ports_entries / open_ports_max_entries`；它描述配置容量，不等同于内核内存可用量。 |
| **admission** | 对 add/bulk/reconcile/central desired state 的写入前验证；拒绝必须在 map mutation 前发生。 |

## 3. 产品不变量

| ID | 不变量 | 优先级 | 可验证性 |
|---|---|---|---|
| SDD-001-R1 | 所有 mutation 路径在写 pinned map 前都必须验证 reservation：`add/open`、bulk、fill、load-ports、reconcile、central desired state 和启动 seed。 | P0 | 单元、CLI、真实内核。 |
| SDD-001-R2 | wildcard binding 与任一同 family reserved endpoint 的端口冲突必须拒绝，错误应给出 port、reservation source 与 remediation。 | P0 | 单元、真实 namespace。 |
| SDD-001-R3 | exact-address binding 仅在其 exact address 与 reserved endpoint address 相交时拒绝；不能用端口全局拒绝破坏多 VIP 隔离。 | P0 | 单元。 |
| SDD-001-R4 | 内置 reservation 必须包含已配置的 exporter endpoint、primary internal target 和 TLS fallback target；operator 可通过 policy 增加保留 endpoint。 | P0 | 启动与解析单元测试。 |
| SDD-001-R5 | exporter 必须公开 `open_ports_entries`、`open_ports_max_entries`、`open_ports_pressure_ratio` 与 `open_ports_headroom_entries`；四者来自同一采样。 | P0 | exporter 快照测试。 |
| SDD-001-R6 | 任何 admission 超过 hard capacity 必须失败且 map 保持不变；soft pressure 预警不自动拒绝，hard policy threshold 可配置。 | P0 | 单元、60K/over-capacity 真实内核。 |
| SDD-001-R7 | status、audit log 与 Prometheus 必须暴露 active reservation generation/summary，便于将“端口不可用”区分为 policy rejection、map full、socket unavailable 或 traffic miss。 | P1 | snapshot/CLI 测试。 |
| SDD-001-R8 | 现有 policy 文件未声明 reservation 时保持兼容；默认 runtime reservation 仍必须由 long-running loader 注入。 | P0 | 回归测试。 |

## 4. 设计

### 4.1 Reservation 数据模型

新增 `ReservedEndpoint`：`{ family, address mode, port, source }`。address mode 为 `Exact` 或 `Wildcard`。`source` 取值至少包括 `metrics-listen`、`primary-target`、`tls-target`、`policy.conf`。该对象不进入 `open_ports` map；它是 loader/runtime manifest 的一部分，并在所有控制面 mutation 前读取。

`policy.conf` 增加可重复的 `reserve=` 行。格式复用端口列表解析，作为跨 IP 的保守 reservation。后续可扩展为 `reserve_endpoint=` 表达精确 endpoint，但本迭代不将复杂的 CIDR 语法塞进已有轻量配置文件。

### 4.2 冲突算法

对任一待写 binding，先计算 effective reservation：静态 policy reserve 加运行时 endpoint reserve。随后按下面规则处理。

| Binding | Reservation | 结果 |
|---|---|---|
| wildcard address，family 和 port 相同 | exact 或 wildcard | 拒绝。 |
| exact address，family/port/address 均相同 | exact | 拒绝。 |
| exact address，family/port 相同，地址不同 | exact | 允许。 |
| family 不同 | 任意 | 允许。 |
| policy `deny` 命中 | 任意 | 拒绝，保持既有 deny 语义。 |

该算法使 production 默认能够以 exact ingress VIP 接入动态端口，同时防止 wildcard map 抢占 loopback metrics/control endpoint。

### 4.3 Capacity/pressure 合同

`OPEN_PORTS_MAX_ENTRIES` 是唯一 capacity 常量来源。loader 在读取 map 或 exporter 抓取时以同一 snapshot 计算：

```text
entries  = current open_ports map element count
capacity = OPEN_PORTS_MAX_ENTRIES
headroom = capacity - entries
pressure = entries / capacity
```

`pressure` 仅用于容量可见性和软告警；不因整数舍入误拒绝。admission 的 hard check 使用 `desired.len() <= capacity`。阈值由运行配置提供，默认建议 warn=0.70、critical=0.85、freeze=0.95，但只在 operator 明确启用 `capacity_freeze_threshold` 后自动拒绝新写入。这样不会将一个未经演练的自动化策略突然带入现网。

### 4.4 DFX 行为

拒绝必须：不修改 desired file、不修改 pinned map、增加控制面 rejection counter、写入 audit event，并在错误文本内说明 source。metrics 不允许以 port、tenant、remote IP 等高基数标签标记；详细定位走受限 audit/status 或 rate-limited ringbuf。

## 5. 非功能性验收

| 维度 | 门禁 |
|---|---|
| 正确性 | 所有 R1–R8 TDD 测试通过；失败 mutation 前后 map snapshot 相同。 |
| 性能 | reservation check 仅在 control-plane mutation 执行，零入侵 BPF hot path。 |
| 可用性 | exporter、ctl socket、target listen 被保留后，大 range fill 不应改变其连通性。 |
| 可观测性 | capacity 四指标、reject total、last rejection reason 和 reservation summary 可读取。 |
| 安全性 | exporter 默认 loopback；无权限调用不可通过管理端口创建 binding。 |
| 可恢复性 | policy/reservation 更新失败不影响现有 map；close/reconcile 后可恢复基线。 |

## 6. TDD 测试编号

| 测试 | 先写失败测试 | 实现后证据 |
|---|---|---|
| T-001 | policy 解析 `reserve=`，重复行合并，非法端口拒绝 | Rust 单元测试。 |
| T-002 | wildcard 与 runtime metrics target 冲突拒绝且 map 未写入 | Rust 单元测试与 isolated netns。 |
| T-003 | exact VIP 与不同-address reservation 可共存 | Rust 单元测试。 |
| T-004 | add、bulk、reconcile、central 路径共享同一 admission | 参数化/集成测试。 |
| T-005 | exporter 对空、60K 和 near-capacity map 输出 current/max/ratio/headroom | snapshot 测试。 |
| T-006 | capacity overflow/threshold rejection 不改变 map/desired state | 单元和真实内核。 |
| T-007 | 30K/60K fill 显式保留 metrics 后 scrape 与 port sample 均通过 | 真实内核证据。 |

## 7. 首轮实现状态（2026-08-19）

| 需求 | 状态 | 已验证证据 | 剩余工作 |
|---|---|---|---|
| `reserve=` 解析与所有 shared-policy admission | **已实现** | Red→Green 单元测试；默认 policy 保留 `8080,8443,9101`。 | 将 reservation source/generation 暴露到 `status` 与 audit。 |
| wildcard 管理端口拒绝且 map 不变 | **已实现（保守的 port-global 语义）** | `tests/e2e/sdd001-real-kernel.sh`：`add 9101` 拒绝，entry count 保持 1，metrics 可继续 scrape。 | 实现 family/address-aware `reserve_endpoint=` 以满足 R3。 |
| current/max/pressure/headroom 指标 | **已实现** | 纯函数 TDD；真实 60K map 输出四项一致 gauges。 | 增加 map pressure 告警规则与 dashboard。 |
| 私有 bpffs identity | **已实现** | 初次 60K 演练发现路径前缀 bug；以 `statfs(BPF_FS_MAGIC)` 修复；私有 bpffs 下 bulk mutation/60K 复验通过。 | 在 CI 中添加具有 CAP_BPF 的 integration runner。 |
| R3 exact VIP reservation | **未实现** | 无。 | 新增 `reserve_endpoint=`、address/family 交集算法及 T-003。 |
| R4 runtime endpoint 注入 | **未实现** | 无。 | 将 `metrics-listen`、primary/TLS target 写入 runtime reservation manifest，供所有 ctl process 读取。 |
| R6 pressure threshold/freeze | **部分实现** | hard map capacity 校验存在；60K metrics 通过。 | 实现 warn/critical/freeze config、无 map mutation overflow test。 |
| R7 DFX reservation/rejection summary | **未实现** | 现有 policy 错误文本与 audit。 | 增加 bounded reason counter、last reject、generation/status。 |

> **发布结论：** 本轮成果证明“reservation 基础语义、private bpffs identity 和容量 metrics”可在真实内核运行，但 **SDD-001 仍不是生产签字完成**。准确 multi-VIP reservation、runtime reservation manifest、pressure admission 和 DFX status 是继续上线前的 P0 阻断项。

## 8. 参考资料

[1] [Cilium — eBPF Maps](https://docs.cilium.io/en/latest/network/ebpf/maps/)
[2] [Linux Kernel — BPF `sk_lookup`](https://docs.kernel.org/bpf/prog_sk_lookup.html)
[3] [Cloudflare — Tubular production architecture](https://blog.cloudflare.com/tubular-fixing-the-socket-api-with-ebpf/)
