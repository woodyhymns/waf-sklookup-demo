# M2: port control plane (hot add/remove, bulk seed)

Hot-edit the pinned BPF `open_ports` map **without reloading OpenResty** and without
re-attaching `sk_lookup`. The long-running Go loader (`-mode openresty` or `toy`)
must already be up so maps stay pinned under `/sys/fs/bpf/waf-sklookup` (default).

**Go is the reference userspace loader.** A Rust rewrite is only after M3 / perf is OK.

## Test: 30K / 60K seed (copy-paste)

Loader must already be running (`./run-openresty-demo.sh start`). Then fill the map.
No nginx reload. `open_ports` is sized **131072** (was 1024).

```bash
export CGO_ENABLED=0
# stock: OPENRESTY_PREFIX=/usr/local/openresty
# HAH:   OPENRESTY_PREFIX=/usr/local/openresty-hah
./run-openresty-demo.sh start    # skip if already up

# preferred M3 seed (bulk open)
./scripts/m3-fill-ports.sh 30000
./scripts/m3-fill-ports.sh 60000

# bulk open / close — range or file, no OpenResty reload
sudo ./waf-sklookup-demo bulk open  -range 5000-34999
sudo ./waf-sklookup-demo bulk close -range 5000-34999
sudo ./waf-sklookup-demo load-ports -file ports.txt
sudo ./waf-sklookup-demo close-ports -file ports.txt
sudo ./waf-sklookup-demo load-ports -stdin < ports.txt
sudo ./waf-sklookup-demo bulk fill -count 30000 -start 5000
sudo ./waf-sklookup-demo list -count
sudo bpftool map show name open_ports   # expect max_entries 131072
```

Default fill start is **5000** so 60K fits in `uint16`. HTTP API is not required for this.

## Run with the OpenResty demo

Same helper as M1/P1. Stock prefix or HAH both work:

```bash
export CGO_ENABLED=0
# stock 1.19.3.2:
#   OPENRESTY_PREFIX=/usr/local/openresty
# Tengine https_allow_http (HAH):
#   OPENRESTY_PREFIX=/usr/local/openresty-hah
./run-openresty-demo.sh start
./run-openresty-demo.sh verify
```

Leave the loader running. Control-plane commands are a **second process** talking to
the pinned map (same binary, subcommands). OpenResty is not restarted.

## CLI

Preferred entrypoint: subcommands on `./waf-sklookup-demo`. Legacy `-mode open-port` /
`close-port` / `dump-ports` still work.

```bash
# add / remove / list (no OpenResty reload)
sudo ./waf-sklookup-demo add 18083
sudo ./waf-sklookup-demo add 18084,18085
sudo ./waf-sklookup-demo add 20000-20010
sudo ./waf-sklookup-demo remove 18083
sudo ./waf-sklookup-demo list
sudo ./waf-sklookup-demo list -count

# stock TLS fallback slot only (not the Tengine product path)
sudo ./waf-sklookup-demo add -tls 18444

# via the demo helper
./run-openresty-demo.sh add 18083
./run-openresty-demo.sh remove 18083
./run-openresty-demo.sh list
```

Aliases: `open`=`add`, `close`=`remove`, `dump`=`list`, `load-ports`=`bulk open`, `close-ports`=`bulk close`.

## Bulk (M3 seed)

Range, file, or stdin. Puts are chunked (default 4096) with BPF `BatchUpdate` when
the kernel supports it, otherwise per-key `Put` — still **O(n)**, not a map walk per
port. Progress and elapsed time go to stderr; a one-line summary goes to stdout.

```bash
# 30K / 60K fills Test will use for M3
sudo ./waf-sklookup-demo bulk fill -count 30000 -start 5000
sudo ./waf-sklookup-demo bulk fill -count 60000 -start 5000
# or:
./scripts/m3-fill-ports.sh 30000
./scripts/m3-fill-ports.sh 60000
./run-openresty-demo.sh fill 30000

# explicit range / file / stdin
sudo ./waf-sklookup-demo bulk open  -range 10000-39999
sudo ./waf-sklookup-demo bulk close -range 10000-39999
sudo ./waf-sklookup-demo load-ports -file ports.txt
sudo ./waf-sklookup-demo close-ports -file ports.txt
sudo ./waf-sklookup-demo load-ports -stdin < ports.txt
sudo ./waf-sklookup-demo list -count
```

`bulk fill` default `-start 5000` so a **60K** fill fits in `uint16` (10000+60000 would overflow). It skips internal listens `8080,8443` (`-skip`). Do **not** pass tens of thousands of ports on loader **startup** (`-ports`); start the demo with the usual few ports, then fill.

File format (also stdin): blank lines and `#` comments ignored; tokens may be single
ports, comma lists, or `START-END` ranges.

`open_ports` **`max_entries` is 131072** (was 1024 — that ceiling made 30K/60K
impossible). M3’s full ladder depends on this size.

| | old | M2 |
|--|-----|-----|
| `max_entries` | 1024 | **131072** |
| Why not 65536 | 60K / 65536 ≈ 92% hash occupancy; 2×64K leaves headroom | |
| Payload | `u16` key + `u8` slot | unchanged |
| Kernel memlock | ~64–128 KB | **~8–16 MB** (hash buckets + precharged elems; not 60K × userspace structs) |
| Userspace RSS | pin FD only | still pin FD; bulk fill does not keep a 60K slice after the syscall |

Confirm after loader start:

```bash
sudo bpftool map show name open_ports
# expect max_entries 131072 and memlock on the order of 10 MB, not 100+ MB
```

Restart the **loader** once after pulling this change so the new map is pinned.
Do not reload OpenResty.

## What does not happen

- No OpenResty / nginx reload
- No BPF program re-attach
- No userspace `bind()` on the extra ports
- Toy (`-mode toy`) and OpenResty (`-mode openresty`) long-running modes are unchanged

HTTP API is deferred; CLI bulk is the M3 contract.
