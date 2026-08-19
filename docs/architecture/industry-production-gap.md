# 业界横向比较与生产差距评估

**状态：** 首轮架构基线。
**范围：** WAF 动态非标端口接入的数据面、控制面、可观测性、可靠性与测试工程。
**决策原则：** 以真实流量下的正确性、可诊断性与可回滚性优先于 demo 指标；任何未被可重复证据证明的能力不得标记为生产就绪。

## 1. 结论

`sk_lookup` 是与需求高度匹配的内核能力：它可在 TCP 新建连接的本地监听 socket 查找阶段选择目标 socket，而已建立的 TCP 连接不重新经过该 hook。[1] 因而它能消除为每个客户端口修改 OpenResty/Nginx 配置、创建监听 socket 和 reload 的要求。Cloudflare 的 Tubular 已将该模型用于大规模地址/端口接入，并明确把安全在线发布、内核持久状态、冲突解析、最小权限观测与并发修改保护作为生产实现的组成部分。[2]

当前项目已经具备可运行的核心：精确 `(family, address, port)` 后回落 wildcard 的查找、IPv4/IPv6、worker shard、程序/link pin、program tag 校验、异常分类指标、真实内核 30K/60K map 容量证据与基本故障恢复。它不应再被视为简单 demo，但距离“可承载现网 WAF 流量”仍有四项 **P0 架构缺口**：管理面端口隔离、原子发布/回滚、map 压力 SLO、生产流量下的端到端演练。

| 维度 | 当前实现 | 行业参考 | 架构判断 |
|---|---|---|---|
| 新连接转发 | TCP `sk_lookup`、socket map、worker sharding | Linux 明确支持 TCP/UDP lookup 与 `bpf_sk_assign()`；Tubular 以 binding→destination→socket 分层建模。[1] [2] | **方向正确**；WAF 首轮仅支持 TCP 是合理范围边界。 |
| 地址匹配 | 精确 IP 优先、同 family wildcard 回落 | Tubular 支持前缀匹配，并用最长前缀规则解决重叠 binding。[2] | **可用但需收紧**；生产 WAF 默认应精确 ingress VIP，wildcard 必须显式批准并隔离管理面。 |
| worker 可靠性 | 64 shard、pidfd owner 健康检测、500ms 默认重扫 | Tubular 依赖稳定 socket 生命周期与可安全的注册方式；内核引用实现强调未选 socket 时正常 lookup 继续。[1] [2] | **已有基础**；仍需定义 restart、drain、缺 shard、连续失败的服务 SLO 与自动处置。 |
| 控制面持久化 | bpffs pin、desired state、tag 校验、reconcile | Tubular 让内核 map 持久化状态，以短生命周期命令降低 daemon crash 影响；并以目录锁避免并发损坏。[2] | **部分达到**；需要版本化事务、预检、原子切换和一键回滚证明。 |
| 发布安全 | pin program/link 和 tag fail-closed | Tubular 使用新 program pin、link 原子更新、再原子替换 program 引用的升级路径。[2] | **P0 缺口**；当前必须补 BPF ABI 兼容性、canary、atomic upgrade/rollback 规格与测试。 |
| 容量管理 | map 固定 131,072 entries；60K 真实验收；当前有 entry gauge | Cilium 将 BPF map 上限、map pressure 与扩容/重建风险作为显式运维对象。[3] | **P0 缺口**；需要 capacity、pressure、headroom、拒绝次数、预警/冻结策略和容量预算。 |
| 可观测性 | Prometheus counters、异常 ringbuf、list/status | Tubular 提供 bindings 视图以补足 `ss` 不可见；Cilium 以 health、drop reason、map pressure 和连通性测试支撑运维。[2] [3] [4] | **P1 缺口**；需要 readiness、config generation、last reconcile、ringbuf loss、按原因告警与 operator runbook。 |
| 验证方法 | 单测、真实内核 IPv4/IPv6、worker kill、100 port hot update、30K/60K isolated run | Cilium 用隔离 namespace 的 connectivity matrix；生产 map 规模还必须结合主机内存、流量、协议与故障路径。[3] [4] | **P0 缺口**；缺生产规格 host 上的 sustained load、TLS/WAF、rollback、内核版本矩阵与 chaos 测试。 |

## 2. 必须保留的架构约束

### 2.1 连接语义

数据面只影响**新建 TCP 连接**。任何 SLO、压测和故障演练必须把“每连接 SYN 路径”与“keep-alive 已建立连接请求路径”分开计量；把二者混成单一 QPS 会掩盖或误判 `sk_lookup` 成本。[1] TCP 之外的协议要以独立 SDD 规格进入，不得把当前 `SK_PASS` 行为误称为 UDP 支持。

### 2.2 管理面与数据面隔离

动态端口 key 的 wildcard 形式会匹配同一 network namespace 中该端口的所有本地 IPv4 或 IPv6 目的地址。真实 30K 探索已证明，这能把 metrics 或自动化控制连接误导入 WAF worker。因此生产拓扑必须满足以下任一条件：第一，使用精确 ingress VIP key；第二，管理面（metrics、ctl、SSH、agent、health check、orchestrator）使用独立 address/interface/network namespace；第三，对 wildcard range 施行版本化的 reservation policy 并在任何 map mutation 前校验。

### 2.3 安全失败边界

“fail closed”只适用于已确认应由本系统接管、却没有安全目标 socket 的 binding。对于未命中 binding、未知协议或未知 address family，必须 `SK_PASS` 给正常内核 socket lookup，避免把无关业务流量变成 WAF 故障。每一种 `SK_DROP` 都必须对应稳定的 reason code、指标、采样事件与 runbook。

## 3. 首轮优先级

| 优先级 | SDD 工作项 | 完成定义（Definition of Done） |
|---|---|---|
| P0-1 | 管理端口 reservation policy 与 exact-VIP 默认策略 | 启动、单端口、bulk、reconcile、central desired state 均拒绝冲突；错误不触碰 map；单测和隔离真机测试通过。 |
| P0-2 | Dataplane capacity/pressure contract | exporter 给出 current/max/ratio/headroom；阈值、admission policy 与告警文档明确；60K/预阈值/拒绝路径有证据。 |
| P0-3 | 版本化 BPF 发布与回滚 | ABI manifest、program/link version、preflight、atomic cutover、fail-safe rollback、旧 map 兼容/拒绝规则与故障演练完成。 |
| P0-4 | 生产流量验证矩阵 | 目标内核/CPU/内存下，HTTP、TLS、WAF policy、keep-alive、new CPS、bulk mutation、worker restart 和 rollback 均有门禁。 |
| P1-1 | DFX status/readiness/runbook | `/metrics`、`status`、ringbuf、audit、readiness 与告警/处置手册可关联同一 generation。 |
| P1-2 | 多租户隔离与审计 | Binding 有 tenant/site/VIP/port/reservation 来源；配额与 mutation 均可审计、可查询、可回放。 |

## 4. 本项目与业界的明确差异，不做模糊承诺

Tubular 支持按 IP 前缀与端口优先级的通用 binding 模型；当前项目只需要精确 VIP 加同 family wildcard，这是刻意收窄的 WAF 需求，而不是功能缺失。如果未来需要 CIDR 或 all-port binding，必须新增 LPM trie、冲突优先级、性能测试和 operator UX；不能通过在现有 HASH map 上叠加线性规则临时实现。[2]

Cilium 的规模经验说明 BPF map 满时会直接影响 datapath 的可扩展性，且重建 map 可能造成连接扰动；因此本项目不会在生产通过盲目提高 `max_entries` 解决容量问题，而要先以 map 压力与 host memlock 预算定义容量，之后才进行带 drain/canary 的容量变更。[3]

## 5. 参考资料

[1] [Linux Kernel Documentation — BPF `sk_lookup` program](https://docs.kernel.org/bpf/prog_sk_lookup.html)
[2] [Cloudflare — Production ready eBPF, or how we fixed the BSD socket API](https://blog.cloudflare.com/tubular-fixing-the-socket-api-with-ebpf/)
[3] [Cilium Documentation — eBPF Maps](https://docs.cilium.io/en/latest/network/ebpf/maps/)
[4] [Cilium Documentation — Troubleshooting](https://docs.cilium.io/en/stable/operations/troubleshooting/)
[5] [Cilium Documentation — Monitoring & Metrics](https://docs.cilium.io/en/stable/observability/metrics/)
