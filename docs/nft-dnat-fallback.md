# Last-resort nftables DNAT (default OFF)

Optional **third line** after pin-link ([#38](https://github.com/woodyhymns/waf-sklookup-demo/pull/38))
and backup `sk_lookup` ([#40](https://github.com/woodyhymns/waf-sklookup-demo/pull/40)).
Spec: [SDD-004](specs/SDD-004-nft-dnat-last-resort.md).

When **both** BPF/`sk_lookup` links are gone, new SYNs to virtual ports have
no listener. This helper DNATs **NEW TCP SYNs** on those dynamic ports to the
existing main listen (`TARGET`, default `127.0.0.1:8080`). Established TCP is
not rewritten.

This is bake-off **E** (skipped in sandbox when `nft` was missing). It is
**not** on by default and is **never** started by the loader, `unpin`,
upgrade, `recover.sh`, or systemd.

## Enable / disable

```bash
# Preview (no privileges, no apply)
./scripts/nft-dnat-fallback.sh render
./scripts/nft-dnat-fallback.sh ports
./scripts/nft-dnat-fallback.sh status

# Apply — explicit flag required (or WAF_NFT_FALLBACK=1)
sudo ./scripts/nft-dnat-fallback.sh enable --enable
sudo ./scripts/nft-dnat-fallback.sh disable
```

`enable` refuses if `sk_lookup` or `sk_lookup_backup` is still pinned
(last line only). `--force` is a lab escape hatch and rewrites the dest
port before `sk_lookup`.

80/443 stay out of the set, as do inner real listens 8080/8443 and the
DNAT target port.

## Interaction with #34 / #40

| Event | Who steers a new virtual SYN |
|---|---|
| Loader `kill -9` | Pinned primary (#38) |
| `detach-primary` | Backup `sk_lookup_backup` (#40) |
| `unpin` / both links gone, nft OFF | Refuse (fail-closed) |
| Both links gone, nft **explicitly** ON | DNAT → main listen (this doc) |

Do not enable nft “just in case” while BPF is healthy. Host/SNI stays
policy identity; after DNAT the socket dest port is the inner listen, so
`$waf_external_port` is not the virtual port.

## Rollback

```bash
sudo ./scripts/nft-dnat-fallback.sh disable
# equivalent: sudo nft delete table inet waf_sklookup_dnat
```

Already-DNATed flows may continue via conntrack until they close. That
does not migrate sockets that were accepted before nft existed.

## Failure modes (short)

- No `nft` → unavailable. Accept script exits **77**.
- Enable without `--enable` / `WAF_NFT_FALLBACK=1` → refused.
- Pins still present → refused (unless `--force`).
- Inner listen down → DNAT hits a dead port.
- Stock TLS slot → HTTP listen: use `--skip-tls` or HAH one listen.
- Leftover table: hygiene and `disable` delete `inet waf_sklookup_dnat`.

## How Test verifies on a host with nft

```bash
# No nft: SKIP (exit 77)
./scripts/accept-nft-dnat-fallback.sh

# nft present: standalone DNAT must PASS
sudo ./scripts/accept-nft-dnat-fallback.sh

# Offline unit (no nft, no BPF)
./tests/nft-dnat-fallback-unit.sh
```

On a host with `nft` + CAP_NET_ADMIN the accept script:

1. Refuses `enable` without the flag.
2. Filters 80/443/8080/8443 out of the set.
3. Renders `ct state new` + exact SYN.
4. Listens on a main port; virtual port fails; after `enable --enable` a
   NEW SYN to the virtual port returns 200; a held TCP on the main listen
   still completes; `disable` returns the virtual port to fail.
5. If toy `sk_lookup` can attach: unpin **both** links, then enable
   without `--force`; NEW SYN is 200 via DNAT; the held virtual-port TCP
   still completes.

Do not enable systemd or run 30K on the shared box.
