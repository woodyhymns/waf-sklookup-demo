# SDD-003: atomic BPF upgrade / rollback (main ABI)

**Status:** Implemented on current main ABI.
**Parent:** leftover of [#34](https://github.com/woodyhymns/waf-sklookup-demo/issues/34) after pin-link [#38](https://github.com/woodyhymns/waf-sklookup-demo/pull/38).
**Not from #37:** this is a rewrite against `dispatch.bpf.c` and the Rust loader
on main. Do not copy 64-shard, 20-byte dest key, IPv6 key, stats/anomaly maps,
or any other #37 ABI fork.

## Product bar

When BPF/`sk_lookup` is upgraded or partially fails, traffic must not break:

- **Established TCP stays** on the accepting listen. `sk_lookup` never rehashes
  or migrates live flows. Only new SYNs are in scope.
- **Upgrade** replaces the primary program with `bpf_link_update` (no
  detach / “no program” window).
- **Rollback** if the candidate fails verify, attach, pin, or the health window.
- **Second line:** a separately pinned backup `sk_lookup` stays attached when
  the primary link is detached, and still steers new SYNs for ports in
  `open_ports` to the existing listen. nftables is **not** this second
  line; see [SDD-005](SDD-005-nft-dnat-last-resort.md) (last-resort, default OFF).

Pin-link + `bpf_link_update` on loader restart already landed in #38. This SDD
adds a transactional upgrade CLI and the backup link.

## Main ABI (do not invent)

| Object | Type | Key | Value | max_entries |
|---|---|---|---|---:|
| `open_ports` | HASH | host-order `u16` local port | `u8` sockmap slot | 131072 |
| `redir_socket` | SOCKMAP | `u32` slot | `u64` | 2 |

Program name: `dispatch` (section `sk_lookup`). C hot path stays
`dispatch.bpf.c`. Optional Rust twin must match this ABI. 80/443 stay real
listens and stay out of `open_ports` unless already present as a documented
exception.

A candidate object that adds maps, changes key/value size, or uses a 20-byte
dest key is **rejected** in preflight. Live maps are reused, never deleted.

## Pins

Under `${PIN_DIR:-/sys/fs/bpf/waf-sklookup}`:

| Pin | Role |
|---|---|
| `open_ports`, `redir_socket` | Persistent maps (#38) |
| `sk_lookup` | Primary netns link (updated on upgrade) |
| `sk_lookup_backup` | Backup netns link (attached once; never `bpf_link_update` during upgrade) |
| `prog` | Currently promoted `dispatch` (FD for rollback) |
| `prog_previous` | Last committed generation (explicit rollback) |
| `prog_candidate` | Transient during activate |

Journal (not bpffs): `/run/waf-sklookup/upgrades/<pin-hash>.json`.
Write-temp + fsync + rename. Low-cardinality phase/identity only.

## State machine

| Phase | Dataplane | On failure |
|---|---|---|
| `prepared` | Old primary only | Drop candidate pin; stay on old link |
| `activating` | `bpf_link_update` in progress | Old program remains if update fails (kernel primitive) |
| `healthy` | Candidate on primary | Health fail → `bpf_link_update` back to `prog` / previous FD |
| `committed` | Candidate promoted | Keep `prog_previous` for operator rollback |
| `rolled_back` | Previous generation | Terminal |
| `failed` | Preserved active generation | No automatic destructive cleanup |

`upgrade` refuses to start if a journal exists in a non-terminal phase.
`upgrade-rollback` restores `prog_previous` when present; if the transaction
never reached activate, it only clears the candidate pin.

## Health window

Default **1s** for this demo (`-health-window`; max 300s). Checks: primary
link pin exists, map ABI still matches main, `prog` pin readable. Fault
injection: `WAF_UPGRADE_FAIL_HEALTH=1` (test-only; never set by the loader).

This is deliberately smaller than a 60s staging window. Production can pass
`-health-window 60s`.

## Backup sk_lookup

On first attach the loader pins a **second** netns link at `sk_lookup_backup`
and disconnects it. Loader restart reuses that pin and does not update it.
Upgrade / `bpf_link_update` touch **only** `sk_lookup`.

`detach-primary` detaches the primary link only. New SYNs for `open_ports`
keys still hit the backup program and `bpf_sk_assign` the live SOCKMAP listen.
`unpin` / `teardown` remains the install teardown (both links + maps).

Backup is not a second ABI and not a 64-shard. It is the same `dispatch`
logic bound to the same pinned maps.

## CLI

```text
sudo waf-sklookup-loader upgrade -obj PATH [-pin-dir DIR] [-health-window 1s]
sudo waf-sklookup-loader upgrade-status [-pin-dir DIR]
sudo waf-sklookup-loader upgrade-rollback [-pin-dir DIR]
sudo waf-sklookup-loader detach-primary [-pin-dir DIR]
```

## Tests

| ID | What | How |
|---|---|---|
| T-030 | Journal serialize / atomic write / terminal phases | `cargo test` in `upgrade` |
| T-031 | ABI accept u16/u8 + 2-slot; reject 20-byte key / extra maps | `cargo test` |
| T-032 | Missing/unreadable candidate leaves link untouched | unit + accept script |
| T-033 | `bpf_link_update` upgrade, steered SYN still 200 | `scripts/accept-sdd003-upgrade-rollback.sh` |
| T-034 | Health-fail rolls back; SYN still 200 | same script, `WAF_UPGRADE_FAIL_HEALTH=1` |
| T-034a | Accept script exit 0 on criteria PASS (no ERR/hygiene false fail) | `tests/hygiene-trap-status.sh` |
| T-040 | Kill loader, new SYN still 200 (#38 pin-link) | `scripts/accept-issue-34-kill-loader.sh` |
| T-041 | Detach primary, new SYN still 200; established TCP stays | `scripts/accept-issue-34-detach-primary.sh` |

## Non-goals

- Cherry-pick or merge #37
- Change product identity to `$waf_external_port` (Host/SNI stays policy)
- Revive `ngx.req.socket(true)` / getfd body-stripping
- nftables as a second line (that is SDD-005, last line only, default OFF)
- Cross-node rollout
- Semantic map migration
