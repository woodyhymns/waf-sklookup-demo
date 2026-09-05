# Specs (main ABI)

This directory is the source of product requirements that land on **main**.
Implementations must cite an SDD number. Do **not** import ABI-breaking
shapes from the #37 experiment bay (64-shard, 20-byte dest key, IPv6 key).

| SDD | Topic | Status |
|---|---|---|
| [SDD-001](SDD-001-management-plane-and-capacity-safety.md) | Reserved ports (`reserve=`) and `open_ports` capacity/pressure gauges | Main-ABI slice (port-global only; no dest key / VIP) |
| [SDD-003](SDD-003-atomic-upgrade-and-rollback.md) | Single-node `sk_lookup` program replace via `bpf_link_update`, ABI preflight, health window, rollback; backup link for primary detach | Implemented on main ABI (u16 `open_ports`, 2-slot SOCKMAP) |
| [SDD-005](SDD-005-nft-dnat-last-resort.md) | Optional last-resort nftables DNAT when **both** `sk_lookup` links are gone | Scripts + docs; default OFF; no production auto-enable |

Related product notes: [issue-34-fallback.md](../issue-34-fallback.md), [nft-dnat-fallback.md](../nft-dnat-fallback.md), [recovery.md](../recovery.md).
