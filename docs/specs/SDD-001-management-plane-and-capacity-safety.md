# SDD-001: reserved ports and map capacity (main ABI slice)

**Status:** Partial — small slice on current main ABI.
**Not from #37:** rewrite against `dispatch.bpf.c` and the Rust loader on main.
Do not copy 64-shard, 20-byte dest key, IPv6 map keys, or `reserve_endpoint=`.

## Product bar

Control-plane mutation must not steal management or inner-listen ports, and
operators must see how full `open_ports` is. Established TCP is not in scope:
only new SYNs are steered.

## Main ABI (do not invent)

| Object | Type | Key | Value | max_entries |
|---|---|---|---|---:|
| `open_ports` | HASH | host-order `u16` local port | `u8` sockmap slot | 131072 |
| `redir_socket` | SOCKMAP | `u32` slot | `u64` | 2 |

Reservation is **port-global** because the key is only a port. Exact-VIP /
family intersection is SDD-002 and stays out of this slice.

## This slice

| ID | Requirement | Where |
|---|---|---|
| SDD-001-R1 | `add` / bulk / reconcile / central / desired-file load share `policy::validate` before map write | already on main; reserve joins that path |
| SDD-001-R4′ | `policy.conf` `reserve=` plus runtime `-target` / `-tls-target` ports | `policy.rs`, long-running loader |
| SDD-001-R5 | `status`/`metrics` expose entries, max, pressure, headroom from one snapshot | `metrics::capacity_snapshot` |
| SDD-001-R6 | `desired.len() > OPEN_PORTS_MAX_ENTRIES` refuses; no map write | `policy::validate` + `desired` |
| SDD-001-R8 | missing `reserve=` stays compatible (empty set); repo `policy.conf` declares 80/443/8080/8443 | defaults + file |

Out of this PR: HTTP exporter, `reserve_endpoint=`, pressure freeze, IPv6.

## Policy

```text
reserve=80,443,8080,8443
```

Repeated `reserve=` lines merge. A reserved port is refused with a remediation
hint. Deny / privileged / quota keep their existing messages.

Host/SNI remains product identity. 80/443 stay real binds.

## Test

- Unit: `reserve=` parse/merge, compat empty default, capacity snapshot, status JSON.
- HAH / kernel (optional): `sudo ./scripts/accept-pidfd-listen-reinsert.sh`
  also exercises reserved-port `add` refuse when the demo policy is loaded.
