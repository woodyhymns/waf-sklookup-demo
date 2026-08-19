# SDD-003：单机 BPF Generation 升级、健康窗口与回滚

**状态：** Proposed / P0 implementation.
**前置：** SDD-001、SDD-002。
**Owner：** WAF dynamic-port architecture.
**目标：** 将单节点 `sk_lookup` 数据面升级从“停止旧 loader、重新 attach、观察结果”转化为有 preflight、持久状态、受控切换、健康窗口和确定性回滚的 generation transaction。

> Linux `sk_lookup` 可挂载到 network namespace，多个同 attach point 的 program 的最终 socket selection 依赖其执行及返回规则；因此升级不能只假设“新对象 load 成功”就等于运行语义正确。[1]
>
> libbpf 的 `Link::update_prog()` 能在不 destroy/re-attach link 的情况下替换单个 link 背后的 program；它是本规格的单 link cutover primitive，而不是多对象应用事务。[2] [3]

## 1. 范围与明确边界

**v1 scope** 为同一个 netns、一个 `sk_lookup` link、固定 map ABI、一个 attached loader 的单机升级。当前 dataplane 只有一个 dispatch link，因此在 `prepare` 后可使用 link update 避免 detach/re-attach 空窗。`open_ports`、`redir_socket`、stats、anomaly maps 必须满足已声明的 ABI compatible contract 后才可以 reuse。

| Capability | v1 disposition | Reason |
|---|---|---|
| Same map ABI / same semantics | Supported: reuse pinned maps | 保留 dynamic port、listener shard 和 metric state。 |
| Structural ABI mismatch | Rejected before activate | 不隐式 delete/recreate map，不接受无证据 state loss。 |
| Semantic schema migration | Not supported in v1 | 等尺寸 value 仍可能有不兼容语义，必须单独规格化 converter/invariant。 |
| Multiple `sk_lookup` links | Not supported in v1 transaction | 单 link atomic update 不能直接承诺跨 link atomicity。 |
| Cross-node rollout | Not supported in v1 | 单机 transaction 成熟后由 cluster rollout specification 定义。 |
| Detached direct CLI during transaction | Rejected | product mutations 通过 Unix socket；escape CLI 不得穿透 upgrade freeze。 |

## 2. Generation journal

journal 位于 `/run/waf-sklookup/upgrades/<pin-hash>.json`，与 reservation/identity sidecar 同属运行时控制面，**不写入 bpffs**。每次写入采用 write-temp + fsync + rename；journal 只保存 low-cardinality identity、generation 和 phase，不包含 tenant、domain、cookie 或 raw request data。

```text
UpgradeJournal {
  schema_version: 1,
  active_generation: UUID-like deterministic id,
  previous_generation: optional id,
  phase: stable | prepare | shadow_ready | activate | health_window | commit | rollback | failed,
  active_program: { id, tag },
  candidate_program: optional { id, tag },
  map_abi_digest: SHA-256-like canonical layout digest,
  expected_desired_revision: u64,
  started_at_unix: u64,
  health_deadline_unix: u64,
  failure_code: optional bounded enum
}
```

`active_generation` 是 status、mutation expected-generation、audit 和 rollback 的唯一权威代际。controller restart 后依据 journal、pinned link identity 和 map ABI 三方交叉校验；无法证明哪一代 active 时 fail closed，保留对象并要求人工诊断，而不是删除“看似旧”的 map。

## 3. State machine

| Phase | Dataplane | Control-plane mutation | Required invariants | Failure action |
|---|---|---|---|---|
| `stable` | active generation | Allowed with matching generation | identity, map ABI, desired/map agreement, reservation active | normal operation |
| `prepare` | old generation only | Freeze | load candidate, verifier pass, ABI compatible, candidate identity recorded | remove candidate; return `stable` |
| `shadow_ready` | old generation only | Freeze | candidate loaded, map reuse bound, journal durable | return `stable` |
| `activate` | link update in progress | Freeze | expected old program tag still active | if update fails, retain old link/object |
| `health_window` | candidate generation | Freeze | fault ratio, `no_slot`, worker shards, map drift, manifest state, exporter all within budget | rollback candidate to previous link |
| `commit` | candidate generation | Freeze until journal durable | current link identity equals candidate; prior generation retained until commit record | recovery resolves to candidate |
| `rollback` | previous generation | Freeze | link identity equals previous; desired/map state preserved | if rollback fails: `failed`, preserve all pins |
| `failed` | unknown or preserved active generation | Reject | no automatic destructive cleanup | operator runbook only |

## 4. Preflight compatibility contract

Before loading/attaching candidate code, the upgrader reads active pinned maps and candidate map definitions. For every named persistent map, it requires exact match of map type, key size, value size, max entries, flags where stable, and project-specific layout constants (`OPEN_PORTS_KEY_SIZE=20`, port value size, sockmap capacity, stats slot count). It also requires an explicit `state_semantics="reuse-v1"` marker in the candidate manifest.

This restriction is deliberate. Production experience distinguishes safe state reuse, explicit transformation and deliberate replacement; structural checking alone cannot prove semantic migration correctness.[3] An ABI mismatch therefore produces bounded `upgrade_abi_incompatible` and must not alter live link/maps.

## 5. Health-window contract

The default health window is **60 seconds** in staging and configurable by a bounded CLI/config value in production. It observes:

| Signal | Expected healthy state | Automatic rollback trigger |
|---|---|---|
| Program identity | link tag equals candidate tag | tag mismatch / unreadable identity |
| Reservation | `state=active` | missing or invalid |
| Desired/map | `file_map_agree=true`, `drift.put=0`, `drift.delete=0` | any drift |
| Listener | live shard count equals preflight count | zero, unexpected drop, or non-convergence |
| BPF dataplane | no unknown assign error; `no_slot=0` for populated groups | non-zero unexpected error / threshold breach |
| Metrics | exporter scrape succeeds | scrape missing during window |
| Control plane | no mutation allowed while frozen | any mutation bypass |

Thresholds must be target-environment configured, not invented by this repository. The only safe default for unknown assignment errors or `no_slot` on a populated target is rollback/stop expansion.

## 6. TDD and real-kernel acceptance

| ID | Test | Required evidence |
|---|---|---|
| T-030 | journal serialize/parse/atomic-write/recovery classification | unit tests, tamper cases |
| T-031 | ABI comparison accepts exact reuse and rejects every size/type/slot mismatch | unit tests and candidate fixture matrix |
| T-032 | preflight failure leaves old program/link/maps unchanged | real kernel: original port remains reachable |
| T-033 | successful single-link update preserves steering, original external port and map contents | real kernel with private netns/bpffs |
| T-034 | fault injected during health window rolls back to old program tag with no map loss | real kernel and journal artifacts |
| T-035 | SIGKILL at each phase recovers deterministically to old/new committed generation | fault-injection matrix |
| T-036 | stale expected-generation and concurrent socket mutations are rejected during freeze | socket integration test |

## 7. Operations

The release command must emit a transaction ID, prior/candidate program tag, map ABI digest, preflight result, phase transitions, health observations, final decision and bounded failure code. `status` must display active/previous generation and phase. A successful transaction preserves the previous generation only until the post-commit retention interval ends; a failed transaction retains both sets of pins/journal for forensic inspection.

Cilium’s documented preflight, constrained upgrade/rollback path and configuration compatibility checks reinforce this conservative approach: incompatible or skipped preconditions must be resolved before progressing, not discovered after broad rollout.[4]

## References / 参考资料

[1] [Linux kernel: BPF `sk_lookup` program](https://docs.kernel.org/bpf/prog_sk_lookup.html)
[2] [libbpf-rs `Link::update_prog`](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_link__update_program/)
[3] [Stateful eBPF transactional upgrade analysis](https://eunomia.dev/research/stateful-ebpf-transactional-upgrade/)
[4] [Cilium Upgrade Guide](https://docs.cilium.io/en/stable/operations/upgrade/)
