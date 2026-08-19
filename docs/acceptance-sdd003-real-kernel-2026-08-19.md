# SDD-003 Real-Kernel Upgrade and Control-Plane Acceptance

**Date:** 2026-08-19
**Scope:** single-node `sk_lookup` data plane, runtime control plane, and DFX behavior.
**Result:** **PASS for the bounded real-kernel scope. Not a broad production-release signature.**

## Environment

All executable cases ran in a private Linux network namespace with loopback enabled, a private bpffs mount, a pinned `BPF_PROG_TYPE_SK_LOOKUP` program/link, four Python `SO_REUSEPORT` worker sockets, and the release loader. The isolation is essential: wildcard dynamic-port keys are network-namespace scoped and must not capture the sandbox management plane.

| Gate | Result | Evidence |
|---|---|---|
| Candidate map ABI preflight and map reuse | Pass | `upgrade-commit.json` records `open_ports` key/value size `20/4` for old and candidate programs. |
| Atomic single-link candidate activation | Pass | Committed journal changed program tag from `54d365048953e520` to `471cb9aea8882c6c` with a 25ms health window. |
| Health failure rollback | Pass | Forced fault generated `rolled_back`; previous tag `471cb9aea8882c6c` was restored after candidate tag `591fd3cf7f3eb924` failed health. |
| Commit/rollback traffic continuity | Pass | HTTP response after both paths reported `local=127.0.0.1:18181`. |
| DFX health state | Pass | `/healthz` was `ready` before/after commit and after explicit unfreeze; it returned `503` with `frozen` while the forced rollback freeze was set. |
| Upgrade Prometheus state | Pass | Artifacts assert `upgrade_phase=committed`, then `upgrade_phase=rolledback`, plus frozen state transitions. |
| Pressure admission | Pass | At 1% policy threshold, 1,310 entries were accepted below the exact boundary; projected entry 1,311 was rejected before map/file mutation and wrote freeze. |
| Stale writer control | Pass | Two Unix socket clients used one revision; one add succeeded and the other received a bounded `revision` rejection. Final `desired_count=map_count=2` with zero drift. |
| Single worker loss | Pass | Killing one of four workers converged `listen_shards` to 3; 300 subsequent external-port HTTP requests passed with `no_slot=0` and `-ESOCKTNOSUPPORT=0`. |
| Desired-file commit compensation | Pass | A real read-only desired-state filesystem caused file commit failure after a candidate map update; snapshot/restore returned `map_count=1`, `file_map_agree=true`, and the attempted external port remained unreachable. |

## Key journal evidence

```json
{"phase":"committed","old":{"tag":"54d365048953e520"},"candidate":{"tag":"471cb9aea8882c6c"},"health_window_ms":25}
{"phase":"rolled_back","old":{"tag":"471cb9aea8882c6c"},"candidate":{"tag":"591fd3cf7f3eb924"},"health_window_ms":25}
```

The journal is a local single-link control record. It proves the implemented machine can preflight ABI, switch the netns link without a detach gap, preserve old program identity through a health window, and return to the old link target after a detected failure. It does not prove a multi-node or fleet-wide atomic release.

## Raw evidence

| Case | Repository artifact directory |
|---|---|
| Program/link upgrade, forced rollback, readiness | [`artifacts/sdd003-real-kernel-upgrade/`](../artifacts/sdd003-real-kernel-upgrade/) |
| Pressure freeze and revision CAS | [`artifacts/sdd003-control-plane-real-kernel/`](../artifacts/sdd003-control-plane-real-kernel/) |
| Worker loss/rescan | [`artifacts/worker-fault-recovery-real-kernel/`](../artifacts/worker-fault-recovery-real-kernel/) |
| Desired-file failure rollback | [`artifacts/control-plane-file-rollback-real-kernel/`](../artifacts/control-plane-file-rollback-real-kernel/) |
| Reproducible scripts | [`tests/e2e/`](../tests/e2e/) |

## Release boundaries still open

The map-first compensation covers ordinary map or desired-file errors returned to the control process. A process or host crash between map mutation and desired-file commit still requires journal replay/reconcile evidence, and remains a P0 staging gate. The checks above are deliberately not substitutes for the following release evidence: exact OpenResty/Tengine image module build and native external-port behavior; actual WAF TLS/SNI/HTTP2/WebSocket/policy traffic; target-host CPU/CPS/p99/p999 and memory tests; upgrade recovery after process/node crash at every persisted journal phase; multi-node canary/stop rules; and human on-call rollback drill. Those gates are listed in [the production readiness plan](dfx/production-readiness-plan.md) and [the OpenResty/Tengine staging admission matrix](dfx/openresty-tengine-staging-admission.md).
