# #34 leftover: upgrade + backup sk_lookup (main ABI)

Pin-link already landed in [#38](https://github.com/woodyhymns/waf-sklookup-demo/pull/38).
This note is the remaining product bar: **atomic program replace** and a
**second-line sk_lookup** when the primary link is gone.

Not from [#37](https://github.com/woodyhymns/waf-sklookup-demo/pull/37): no
64-shard, no 20-byte dest key, no IPv6 key rewrite. Spec:
[SDD-003](specs/SDD-003-atomic-upgrade-and-rollback.md).

## What stays true

- Established TCP is pinned to the accepting listen. Only **new SYNs** reselect.
- Host/SNI stays policy identity. Do not switch the product to `$waf_external_port`.
- C BPF hot path is `dispatch.bpf.c` (`open_ports` u16→u8, `redir_socket` 2 slots).
- 80/443 stay real binds and stay out of `open_ports`.
- Loader kill does **not** detach pins (#38). `unpin` is install teardown only.

## Layers

| Layer | When it matters | What happens to a new virtual SYN |
|---|---|---|
| Pinned primary `sk_lookup` | Loader crash / `kill -9` | Still steered (maps + link survive) |
| `bpf_link_update` | Loader restart or `upgrade -obj` | No detach window; old program stays if update fails |
| Backup `sk_lookup_backup` | Primary link detached | Same maps, still `bpf_sk_assign` the listen |
| Empty SOCKMAP | OpenResty listen gone | `SK_DROP` (inner `:8080` still direct) |

nftables is optional later, not required here.

## Operator commands

```bash
# Transactional replace (reuses pinned maps; rolls back on verify/attach/health fail)
sudo ./rust/loader/target/release/waf-sklookup-loader upgrade \
  -obj /path/to/dispatch.bpf.o -health-window 1s
sudo ./rust/loader/target/release/waf-sklookup-loader upgrade-status
sudo ./rust/loader/target/release/waf-sklookup-loader upgrade-rollback

# Detach primary only (backup must keep steering)
sudo ./rust/loader/target/release/waf-sklookup-loader detach-primary

# Full teardown (both links + maps)
sudo ./rust/loader/target/release/waf-sklookup-loader unpin
```

Health-window fault injection (tests only): `WAF_UPGRADE_FAIL_HEALTH=1`.

## How Test re-runs the scenarios

Needs root/CAP_BPF, `sk_lookup`, and the OpenResty demo stack. Hygiene traps
unload maps and stop the loader; do not leave BPF occupied.

```bash
# #38: kill loader; new SYN still 200 while the primary link is pinned
sudo ./scripts/accept-issue-34-kill-loader.sh

# Backup: detach primary; new SYN still 200; held TCP stays
sudo ./scripts/accept-issue-34-detach-primary.sh

# SDD-003: same-object upgrade commit + health-fail rollback; steered SYN stays 200
sudo ./scripts/accept-sdd003-upgrade-rollback.sh
```

Compile a candidate ELF (same main ABI) if you want a local object:

```bash
clang -O2 -g -target bpf -I bpf/headers -I /usr/include/$(uname -m)-linux-gnu -I /usr/include \
  -c dispatch.bpf.c -o /tmp/dispatch.bpf.o
```

`cargo test --manifest-path rust/loader/Cargo.toml` covers journal + ABI
preflight (including rejecting a 20-byte dest key) without attaching.
