# SDD-004: optional last-resort nftables DNAT

**Status:** Implemented as scripts + docs. Default **OFF**.
**Parent:** leftover of [#34](https://github.com/woodyhymns/waf-sklookup-demo/issues/34) after pin-link [#38](https://github.com/woodyhymns/waf-sklookup-demo/pull/38) and backup `sk_lookup` [#40](https://github.com/woodyhymns/waf-sklookup-demo/pull/40).
**Not from #37:** main ABI only. Do not copy 64-shard, 20-byte dest key, or IPv6 key.

## Product bar

When **both** `sk_lookup` links are gone (primary and backup detached/unpinned),
new SYNs to dynamic non-standard ports have no listener. This SDD is an
**optional last line**: nftables DNAT those **NEW SYNs** to the existing main
listen. Established TCP is not migrated.

This is the bake-off **E** path that was skipped when `nft` was missing.

## Layering (do not invert)

| Line | Mechanism | When |
|---|---|---|
| 1 | Pinned primary `sk_lookup` (#38) | Loader crash / `kill -9` |
| 2 | Backup `sk_lookup_backup` (#40) | Primary detached |
| 3 | This SDD: nft DNAT | **Both** links gone; **explicit** enable only |

nft is not a substitute for pin-link or backup. While either link is pinned,
`enable` refuses (override: `--force`, experiments only).

`unpin` / systemd / `upgrade` **never** install this table.

## Behaviour

- Source of ports: `ports.conf` or `--ports`. **80/443** never enter the set.
  Inner real listens `8080`/`8443` and the DNAT target port are also omitted
  (project convention: they are real binds, not virtual ports).
- Match: IPv4 TCP, exact SYN, `ct state new` → `dnat to TARGET`.
- Hooks: `prerouting` (forwarded/ingress) and `output` (local `curl` to 127.0.0.1).
- Established / non-SYN packets are not rewritten. `sk_lookup`-accepted sockets
  stay on the accepting listen after unpin.
- Host/SNI remains policy identity. After DNAT, `$waf_external_port` / the
  socket dest port is the **inner listen**, not the virtual port. That is
  expected for last-resort continuity, not a product identity switch.

## Enable / disable

```bash
# required: --enable or WAF_NFT_FALLBACK=1
sudo ./scripts/nft-dnat-fallback.sh enable --enable
sudo ./scripts/nft-dnat-fallback.sh disable
sudo ./scripts/nft-dnat-fallback.sh status
sudo ./scripts/nft-dnat-fallback.sh render
```

Table: `inet waf_sklookup_dnat`. Rollback is `disable` (delete the table).
Conntrack entries for already-DNATed flows may continue until those sockets
close; that is not a migrate of pre-nft established TCP.

## Failure modes

| Mode | What happens | Operator action |
|---|---|---|
| `nft` absent | Feature unavailable (accept exits 77) | Install nftables or stay on lines 1–2 |
| Enable without flag | Refused (default OFF) | Pass `--enable` or `WAF_NFT_FALLBACK=1` |
| Either sk_lookup pin present | Refused | `unpin` both, or `--force` only in a lab |
| Enable while BPF still attached (`--force`) | Dest port rewritten before `sk_lookup`; virtual-port identity lost | Disable nft; prefer BPF |
| Both BPF gone, nft OFF | New virtual SYN refuse (fail-closed) | Restore loader **or** explicit nft enable |
| Empty SOCKMAP / inner listen down | DNAT lands on a dead port | Restore OpenResty / toy listen |
| VIP:virt → `127.0.0.1:listen` | May need `route_localnet` | Keep dest IP (`dnat to :PORT`) or enable the sysctl |
| Stock TLS slot DNATed to HTTP listen | Handshake fails on stock dual-listen | `--skip-tls` or HAH single listen |
| Stale table after test | Leftover NAT | `disable`; hygiene deletes the table |
| `nft -f` / nat module missing | Enable fails | Load `nf_tables` + nat; CAP_NET_ADMIN |

## Non-goals

- Production auto-enable (systemd, `unpin`, `recover.sh`, loader start)
- Cherry-pick or merge #37
- Change C BPF / 2-slot ABI
- PROXY wrap, TPROXY, or migrating established TCP
- IPv6 dest key / UDP / QUIC

## Tests

| ID | What | How |
|---|---|---|
| T-050 | Reserved filter, default-OFF, render SYN+new | `tests/nft-dnat-fallback-unit.sh` (no nft) |
| T-051 | Skip if `nft` absent (exit 77) | `scripts/accept-nft-dnat-fallback.sh` |
| T-052 | Standalone DNAT PASS when nft present | same; python listen |
| T-053 | Unpin both links; NEW SYN via nft; established stays | same; optional toy attach |
