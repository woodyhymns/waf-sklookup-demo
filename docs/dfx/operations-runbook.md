# WAF Dynamic-Port Operations Runbook

This runbook is the operator contract for the `sk_lookup` dynamic-port plane. It deliberately uses bounded status and metric fields. Do not scrape, alert on, or paste full tenant, port, IP, desired-state, or manifest contents into a shared dashboard. Those details belong in access-controlled host investigation.

## First-response invariant

When a P1 or P0 alert fires, **stop expansion before diagnosis**. The safe control command is `freeze`; it rejects new add, bulk, fill, central apply, and upgrade mutations. Existing BPF map entries are not removed by `freeze` and established connections are not interrupted.

```bash
sudo waf-sklookup-loader freeze -freeze-file /run/waf-sklookup/frozen
sudo waf-sklookup-loader status -pin-dir /sys/fs/bpf/waf-sklookup
curl -fsS http://127.0.0.1:9101/metrics
```

The operator must record the `desired_revision`, `runtime_reservation` summary, `last_rejection_reason`, map pressure, live shard count, and upgrade journal phase before changing anything. The default unfreeze action is prohibited until the corresponding section below closes the incident.

| Alert or symptom | Immediate containment | Evidence to preserve | Safe recovery authority |
|---|---|---|---|
| `WafSklookupSteeringFailure` | Freeze mutations; do **not** reload OpenResty blindly. | Five-minute counter deltas, `status`, worker process list, current journal. | On-call WAF owner after shard and target-family checks. |
| `WafSklookupMapPressureCritical` | Freeze automatically/manual; reject new customer port allocations. | `open_ports_entries`, `headroom`, policy threshold, desired revision. | Capacity owner after planned delete or capacity migration. |
| `WafSklookupReservationNotActive` | Freeze and stop detached CLI/central changes. | Manifest summary and sidecar read error from local protected logs. | Loader owner after restarting attached loader or repairing sidecar. |
| `WafSklookupUpgradeStuck` | Keep freeze set; inspect journal. | Journal phase, old/candidate tags, link/program pins, health-window result. | Release owner through documented rollback path. |
| `WafSklookupFrozen` | Treat as intentional until the triggering alert is resolved. | Freeze creator/change ticket and last rejection code. | Incident commander only. |
| `WafSklookupRevisionConflictBurst` | Pause competing clients; route writes through Unix socket with `expected-revision`. | Current revision and caller audit IDs; no raw endpoint export. | Control-plane owner. |

## Dataplane steering failure

A nonzero terminal counter (`no_slot`, family/protocol error, or other assignment error) is a traffic-impacting signal. First validate that all workers are still present and that the dynamic endpoint family matches the internal listener family.

```bash
sudo waf-sklookup-loader status -pin-dir /sys/fs/bpf/waf-sklookup
sudo waf-sklookup-loader rescan-listen -target 127.0.0.1:8080
```

If a worker is gone, allow the configured rescan to converge or send `SIGUSR1` to the attached loader. If the target is not listening or the family is wrong, restore the known-good OpenResty/Tengine worker configuration; do not add fallback map entries. If terminal counters continue after rescan, keep freeze set and revert the release/canary according to the deployment rollback plan.

## Map pressure or capacity freeze

`pressure_freeze_pct` is an admission boundary, not a capacity-planning target. At warning level, stop bulk migrations and reserve a change window. At critical level, keep freeze set, identify the approved deprovision set from the authoritative desired state, and delete only through the Unix socket using the latest `desired_revision`.

```bash
# Obtain the current token from the JSON field desired_revision.
sudo waf-sklookup-loader status -pin-dir /sys/fs/bpf/waf-sklookup
# Use the production Unix socket, not concurrent root escape-hatch CLIs.
CTL_SOCK=/run/waf-sklookup/ctl.sock waf-sklookup-loader ctl close PORT \
  -addr INGRESS_VIP -expected-revision REVISION
```

Never solve pressure by increasing map capacity in place. A map ABI/capacity change is an SDD-003 upgrade with a compatibility review and rollback plan.

## Runtime reservation not active

A missing or invalid manifest means detached control paths cannot prove protection for metrics, internal target, TLS fallback, and other runtime endpoints. Keep freeze set. Verify the attached loader is alive, the pin directory still contains a matching program/link, and the sidecar filesystem is writable. Restart the attached loader only through the approved service manager; its startup writes a new manifest atomically. Confirm `runtime_reservation.state="active"` before unfreezing.

## Upgrade stuck or rolled back

Use the persisted journal before any change.

```bash
sudo waf-sklookup-loader upgrade status -pin-dir /sys/fs/bpf/waf-sklookup
sudo waf-sklookup-loader status -pin-dir /sys/fs/bpf/waf-sklookup
```

A `rolled_back` journal proves the local link was restored to the recorded previous program after a failed health window. Keep freeze set, preserve the candidate object and journal for release investigation, and run an explicit HTTP/TLS smoke test against the canary VIP. A `failed`, `prepared`, `activating`, `healthy`, or `rolling_back` phase is not release-safe: do not unfreeze until the release owner has verified the actual pinned link/program and completed the documented recovery path. A successful `committed` state alone is insufficient for broad rollout; it must also pass the staging health window and SLO checks.

## Frozen control plane

Freeze is a stop rule, not an error to clear automatically. Check the last bounded rejection reason and the corresponding alert. If it was raised by the pressure boundary, delete approved stale bindings or scale the platform. If it was raised during upgrade, follow the journal procedure. Only the incident commander can issue:

```bash
sudo waf-sklookup-loader unfreeze -freeze-file /run/waf-sklookup/frozen
```

After unfreezing, submit one exact-VIP canary mutation with the current `expected-revision`, confirm `map_count` and `desired_count` converge, and watch terminal dataplane counters before allowing bulk work.

## Revision conflict burst

Clients must read `status.desired_revision` immediately before mutation and send it as `-expected-revision`. Multiple automation workers must use the loader Unix socket, which serializes mutations. Root pinned-map CLI is an emergency escape hatch only; it cannot be used as a concurrent production writer. Repeated conflict means a controller is retrying stale state and must be paused or changed to re-read/retry with bounded backoff.

## Exporter or bpffs unreadable

If `/metrics` returns `waf_sklookup_exporter_up 0` or `/healthz` is non-200, freeze new changes. Check bpffs mount, pinned map/link paths, identity sidecar, manifest state, and exporter process privilege (`CAP_BPF`/required capabilities). Do not restart the exporter by itself as a cure for a missing pin; determine whether the loader exited, unpinned objects, or an upgrade failed.

## Exit criteria

An incident is closed only after the affected alert is clear for the configured observation window, `/healthz` reports `ready`, runtime reservation is active, no non-terminal upgrade journal remains, map pressure is below warning threshold, `desired_count == map_count`, and the canary HTTP/TLS request path passes.
