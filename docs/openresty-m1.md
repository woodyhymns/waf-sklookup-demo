# M1: sk_lookup → OpenResty (HTTP-first)

This milestone wires the existing BPF `sk_lookup` loader to **OpenResty 1.19.3.2** on a fixed internal listen (`127.0.0.1:8080`). External steered ports (for example `18081`, `18082`, `65500`) reach OpenResty **without** userspace `bind()` on those ports.

Aligns with [docs/acceptance-m1.md](acceptance-m1.md) core items **M1-1 … M1-5**. TLS handshake (M1-6) is documented as follow-up; this PR is HTTP-first.

## Architecture

```
Client :18081 / :18082 / :65500
        |
        v  sk_lookup (open_ports map + redir_socket sockmap)
OpenResty listen 127.0.0.1:8080  (single worker for M1)
        |
        access_by_lua → $waf_external_port
```

### Listen FD → sockmap

1. OpenResty binds only `127.0.0.1:8080` (`worker_processes 1`; no reuseport).
2. The loader (`-mode openresty`) attaches `sk_lookup` to the current network namespace.
3. It discovers OpenResty’s listen socket **inode** from `/proc/net/tcp`, finds the matching `/proc/<pid>/fd/<n>` link, and copies that FD into the loader with **`pidfd_getfd(2)`** (Linux ≥ 5.6; `open(/proc/pid/fd/N)` returns `ENXIO` for sockets on some kernels). The FD is `Put` into the `redir_socket` BPF sockmap.
4. Steered ports are inserted into the `open_ports` hash map (no userspace bind).
5. Maps are pinned at `/sys/fs/bpf/waf-sklookup/` so a second process can delete keys (M1-4) without restarting OpenResty.

### `$waf_external_port`

OpenResty declares `$waf_external_port` with the stock rewrite-module `set` directive and fills it in `access_by_lua` via `openresty/lua/waf/external_port.lua`:

1. **Primary:** parse `/proc/self/net/tcp` for this connection’s ESTABLISHED 4-tuple (`$remote_addr`:`$remote_port`) and read the **local** port. After `sk_lookup` assign, that local port is the client’s original destination (e.g. `18081`).
2. **Fallback:** `ngx.req.socket(true):getfd()` + LuaJIT FFI `getsockname(2)` (same kernel fact: connection local port ≠ listen port).
3. **Not used:** `$server_port` — after sk_lookup it is often the internal listen (`8080`). An empty `$waf_external_port` is a hard failure, not a silent fallback to `$server_port`.

The response sets `X-Waf-External-Port` and the access log records `waf_external_port=...` next to `internal_port=$server_port` so the two can be compared.

The toy Go demo already showed `http_local_addr=127.0.0.1:18081` on steered connections; M1 reuses that kernel behavior inside OpenResty.

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Linux ≥ 5.9 with `sk_lookup` | `sudo bpftool feature \| rg sk_lookup` |
| root / CAP_BPF | Loader attaches BPF and updates maps |
| Go 1.22+ | `CGO_ENABLED=0` |
| clang | BPF object generation via `go generate` |
| OpenResty **1.19.3.2** | Docker image `openresty/openresty:1.19.3.2-bionic` or local install |
| curl | Verification |

Optional: `ss` (`iproute2`), `bpftool` (alternative to `-mode close-port`).

## Reproduce locally

```bash
export CGO_ENABLED=0
make build
make test

# OpenResty 1.19.3.2 — pick one:
docker compose -f openresty/docker-compose.yml up -d
# or local: OPENRESTY_PREFIX=/usr/local/openresty

./run-openresty-demo.sh start
./run-openresty-demo.sh verify
```

Manual equivalent:

```bash
# Terminal A — OpenResty (only 127.0.0.1:8080)
openresty -p ... -c openresty/nginx.conf   # see docker-compose / helper

# Terminal B — loader
sudo ./waf-sklookup-demo -mode openresty \
  -target 127.0.0.1:8080 \
  -ports 18081,18082,65500
```

## Verification (M1-1 … M1-5)

### M1-1 — only internal listen is bound

```bash
ss -lntp | grep -E ':(8080|18081|18082|65500)\b'
# Expect LISTEN on 127.0.0.1:8080 only (OpenResty). No userspace bind on steered ports.
```

Without `ss`, `/proc/net/tcp` LISTEN (`state 0A`) must not list `18081` / `18082` / `65500`.

### M1-2 — steered ports hit OpenResty, not the toy server

```bash
curl -sS -D - http://127.0.0.1:18081/
# Body starts with "OpenResty M1 OK"
# Must NOT contain "sk_lookup demo OK"
```

### M1-3 — `$waf_external_port` equals the client destination

```bash
curl -sS -D - http://127.0.0.1:18081/   # X-Waf-External-Port: 18081
curl -sS -D - http://127.0.0.1:18082/   # X-Waf-External-Port: 18082
curl -sS -D - http://127.0.0.1:65500/   # X-Waf-External-Port: 65500
# Body: waf_external_port=<that port>
# Must NOT report 8080 for a steered request
```

Access log (`/tmp/waf-sklookup-m1/logs/access.log` when using the helper):

```
... internal_port=8080 waf_external_port=18081 status=200
```

(`internal_port` may show the listen port; that is why rules must use `$waf_external_port`.)

### M1-4 — delete map entry, that port fails, neighbors still work

Maps are pinned at `/sys/fs/bpf/waf-sklookup/open_ports` while the loader runs.

```bash
sudo ./waf-sklookup-demo -mode dump-ports
sudo ./waf-sklookup-demo -mode close-port -ports 18081
# or: ./run-openresty-demo.sh close-port 18081
# or bpftool (matches docs/acceptance-m1.md; u16 LE key; 18081 = 0x46A9 → a9 46):
#   sudo bpftool map dump name open_ports
#   sudo bpftool map delete name open_ports key hex a9 46
#   sudo bpftool map delete pinned /sys/fs/bpf/waf-sklookup/open_ports key hex a9 46

curl -sS --max-time 3 http://127.0.0.1:18081/   # expect fail
curl -sS http://127.0.0.1:18082/                # still 200 OpenResty M1 OK
```

Unopened ports (never written to the map) also fail (M1-9).

### M1-5 — OpenResty version

```bash
openresty -v 2>&1
# Reference: nginx version: openresty/1.19.3.2
# Docker image: openresty/openresty:1.19.3.2-bionic
```

Config uses stock nginx variables + standard OpenResty Lua (`set`, `access_by_lua`, LuaJIT FFI). No private/custom nginx C modules.

## Toy demo (still the default)

```bash
make run-toy
# or: sudo ./waf-sklookup-demo -mode toy -listen 127.0.0.1:18080
```

See [docs/repro.md](repro.md) for the original kernel-steering pack.

## OpenResty baseline choices

- **Version:** 1.19.3.2 (`openresty/openresty:1.19.3.2-bionic`)
- **Workers:** `worker_processes 1` — reuseport / multi-worker sockmap is left for later (assign-to-group behavior is easy to get wrong)
- **TLS:** not required for this HTTP PR. Same steering would apply to `listen 127.0.0.1:8443 ssl` as a follow-up (M1-6). Do not treat this PR as TLS-parity complete.

| Path | Purpose |
|------|---------|
| `openresty/nginx.conf` | Single internal listen, log format, Lua hook |
| `openresty/lua/waf/external_port.lua` | 4-tuple / getsockname → port string |
| `openresty/docker-compose.yml` | Reference 1.19.3.2 runtime, host network |

## Loader flags

| Flag | Default | Description |
|------|---------|-------------|
| `-mode` | `toy` | `toy`, `openresty`, `close-port`, `dump-ports` |
| `-listen` | `127.0.0.1:18080` | Toy mode bind address |
| `-target` | `127.0.0.1:8080` | OpenResty internal listen to register |
| `-ports` | `18081,18082,65500` | Steered ports; `close-port` deletes these keys |
| `-wait` | `60s` | Wait for OpenResty listen before failing |
| `-pin-dir` | `/sys/fs/bpf/waf-sklookup` | Pinned maps for bpftool / close-port |

## Out of scope (this PR)

- M2 hot-add API / control plane push
- M3 performance / memory-vs-port-scale matrix ([docs/acceptance-m3.md](acceptance-m3.md))
- OpenResty reload sockmap re-registration automation
- Full TLS parity (8443 steered HTTPS)
- Custom nginx C modules
- Multi-worker reuseport sockmap

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `target listen ... not found` | OpenResty not started or wrong `-target` |
| Steered curl connection refused | Loader not running or port not in `-ports` |
| `waf_external_port` empty | Check `error.log`; `/proc/self/net/tcp` not readable in the worker |
| `load BPF` fails | Missing caps / kernel without sk_lookup |
| `close-port` cannot load pinned map | Loader not running, or bpffs not mounted at `/sys/fs/bpf` |

See also: [docs/repro.md](repro.md) (toy demo), [docs/design-thin-accept-openresty.md](design-thin-accept-openresty.md) (long-term design).
