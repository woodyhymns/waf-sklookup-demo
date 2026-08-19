# SDD-001 首轮真实内核验收记录

**日期：** 2026-08-19
**状态：** 功能性子集通过；不构成完整生产发布签字。
**规格：** [SDD-001](specs/SDD-001-management-plane-and-capacity-safety.md)
**执行环境：** Linux 6.1.102，root 创建的 private network + mount namespace，私有 bpffs，C `dispatch.bpf.c` + Rust loader，4 个 `SO_REUSEPORT` HTTP worker。

## 1. 目的

本轮验证两个直接来源于真实容量探索的生产风险。第一，wildcard dynamic-port binding 不得接管 metrics 管理端口。第二，capacity 指标必须从真实 pinned `open_ports` map 的同一 entry snapshot 推导 current、max、pressure 和 headroom。测试在私有 network namespace 中运行，从而不会让合法的 wildcard `sk_lookup` 流量规则影响执行环境的自动化控制面。

## 2. TDD 证据

| TDD 阶段 | 测试/实现 | 结果 |
|---|---|---|
| Red | `reserve_lines_merge_and_reject_before_mutation`、`reserve_is_distinct_from_deny` | 在 `Policy.reserve` 实现前编译失败。 |
| Green | policy `reserve=`、默认 `policy.conf` reservation | 通过；全量 Rust 测试 110+。 |
| Red | `capacity_snapshot_reports_consistent_pressure_and_headroom`、exporter capacity extras 测试 | 在 `CapacitySnapshot`/exporter 实现前编译失败。 |
| Green | entries/max/pressure/headroom snapshot | 通过；`60,000 / 131,072 = 0.457763671875`。 |
| Red | `private_bpffs_mount_uses_runtime_sidecar` | 发现 identity path 仅检查 `/sys/fs/bpf` 前缀。 |
| Green | 以 `statfs(BPF_FS_MAGIC)` 判断实际文件系统类型 | 通过；private bpffs 下 second-process `bulk` mutation 成功。 |

## 3. 真实内核结果

| 场景 | 断言 | 结果 |
|---|---|---|
| baseline | BPF attach、4 worker listener 注册、1 个 `18181` binding、metrics scrape | 通过。 |
| reservation rejection | `add 9101` 命中 `reserve=9101`，CLI 非零退出 | 通过。 |
| reservation 不变性 | 拒绝后 `waf_sklookup_open_ports_entries` 仍为 `1`，metrics endpoint 仍可 scrape | 通过。 |
| 动态转发 | `127.0.0.1:18181` 通过 `sk_lookup` 到 internal listener，响应 local port 保持 `18181` | 通过。 |
| capacity gauges（baseline） | entries=`1`，max=`131072`，pressure=`0.00000762939453125`，headroom=`131071` | 通过。 |
| 60K bulk fill | 真实 map count=`60000`；wall time=`59.230ms` | 通过。 |
| capacity gauges（60K） | entries=`60000`，max=`131072`，pressure=`0.457763671875`，headroom=`71072` | 通过。 |
| 60K data plane | external port `5000` HTTP 转发成功，accepted local port 保持 `5000` | 通过。 |
| cleanup | `close-all` 后 map count=`0` | 通过。 |

## 4. private bpffs defect 与修复

在第一次 private bpffs 的 60K 演练中，loader 成功 attach 和 pin maps，但 second-process `bulk fill` 读取 `<private-bpffs>/pin/identity.json` 返回 `EPERM`。bpffs 只允许 BPF object pin，不允许普通 JSON；旧实现仅当 pin path 以 `/sys/fs/bpf` 开头时才把 identity 放到 `/run`，因此私有 bpffs mount 被错误分类。

修复后，identity sidecar 基于实际 filesystem `statfs` 的 `BPF_FS_MAGIC` 判断，而不依赖路径前缀。任何 bpffs mount 上的 identity 均写入确定性的 `/run/waf-sklookup/identities/<hash>.json`。完整 60K fill 使用 private bpffs 和另一个 control process 重新验证成功。

## 5. 可复现入口与原始证据

| 工件 | 用途 |
|---|---|
| `tests/e2e/sdd001-real-kernel.sh` | reservation、map 不变性、动态转发和 capacity gauge baseline 验收。 |
| `tests/e2e/sdd001-capacity-60k.sh` | private bpffs、60K fill、capacity gauges、端口抽样和 cleanup 验收。 |
| `artifacts/sdd001-real-kernel/` | 基础真实内核运行的 loader/workers/metrics/rejection 原始输出。 |
| `artifacts/sdd001-capacity-60k/` | 60K fill、metrics、count、HTTP sample、close 和 loader 原始输出。 |

## 6. 发布边界

本记录证明本轮功能可以在真实内核运行，并且补上了管理端口 reservation、capacity 观测和 private bpffs sidecar 的关键缺口。但它**不证明** WAF 已准备好承载现网流量。仍然阻断生产签字的 P0 工作是：address/family-aware `reserve_endpoint=`（multi-VIP）、runtime endpoint reservation manifest、map pressure admission/freeze、OpenResty/Tengine TLS/WAF 端到端、目标规格机器上的持续 CPS/keep-alive 性能、program/link atomic upgrade 与 rollback、以及灰度 chaos 演练。

下一轮必须按 [DFX 生产发布门禁](dfx/production-release-gates.md) 和 [测试矩阵](dfx/test-matrix.md) 继续，而不是把本轮 60K 成绩泛化为整体上线结论。
