# waf-sklookup-demo

Minimal demo: **one** userspace `listen()`, many extra TCP ports opened only via Linux BPF **`sk_lookup`** (no `bind`/`listen` on those ports).

Useful as a building block for WAF / OpenResty-style **runtime dynamic non-standard listen ports** on kernels that support `sk_lookup` (Linux ≥ 5.9; HCE 2.0 / kernel 5.10 qualifies).

**M1 (this branch):** steer those ports into **OpenResty 1.19.3.2** on a fixed internal listen (`127.0.0.1:8080`) and expose the client destination as **`$waf_external_port`**. The original toy HTTP server remains the default (`-mode toy`).

## 10-minute quick start (toy HTTP)

```bash
# 0) Host check (must be a real Linux with sk_lookup — not macOS / most CI sandboxes)
uname -r                                          # need ≥ 5.9 (5.10+ preferred)
bpftool feature 2>/dev/null | grep -i sk_lookup   # optional; expect sk_lookup support

# 1) Deps (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-libc-dev golang-go
# optional: linux-tools-common / linux-tools-$(uname -r) for bpftool

# 2) Build & run (needs root for BPF attach)
git clone https://github.com/woodyhymns/waf-sklookup-demo.git
cd waf-sklookup-demo
go mod download
./run.sh
# same as: make run
# default: listen 127.0.0.1:18080 ; steered ports 18081,18082,65500
```

In **another** terminal:

```bash
curl -sS http://127.0.0.1:18080/    # real bind
curl -sS http://127.0.0.1:18081/    # steered — no userspace listen
curl -sS http://127.0.0.1:18082/
curl -sS http://127.0.0.1:65500/

# proof: nothing bound on steered ports in userspace
ss -lntp | grep -E '18081|18082|65500' || echo "no userspace listeners (expected)"
```

Without the BPF program attached, steered-port curls should fail.

## M1: sk_lookup → OpenResty

**Acceptance source of truth:** [docs/acceptance-m1.md](docs/acceptance-m1.md) (Test / QA). This wiring exists to pass **M1-1 … M1-5**. Design notes: [docs/openresty-m1.md](docs/openresty-m1.md).

HTTP-first. OpenResty binds **only** `127.0.0.1:8080`; the loader registers that listen FD into the sockmap and opens extra ports in BPF. Do **not** use `$server_port` as the business/external port (after `sk_lookup` it is often `8080`). Use **`$waf_external_port`**.

| Must-pass | What to prove | This PR |
|-----------|---------------|---------|
| **M1-1** | `ss -lntp` shows only the fixed OpenResty internal listen; steered ports have no userspace bind | Internal `127.0.0.1:8080`; extras `18081,18082,65500` |
| **M1-2** | External ports hit **OpenResty**, not toy `sk_lookup demo OK` | Body `OpenResty M1 OK`; `Server: openresty/1.19.3.2`; **http://** (TLS = M1-6, not required here) |
| **M1-3** | `$waf_external_port` = client destination; two ports distinguishable; **not** the internal listen | Header `X-Waf-External-Port` + access_log; `$server_port` may stay `8080` |
| **M1-4** | Delete one `open_ports` key → that port fails; neighbors still work | `./run-openresty-demo.sh close-port 18081` or `bpftool map delete` |
| **M1-5** | Run against OpenResty **1.19.3.2** (or same-generation, write the version string) | Image `openresty/openresty:1.19.3.2-bionic` |

```bash
export CGO_ENABLED=0
# OpenResty 1.19.3.2 via docker (host network) or local prefix:
#   docker compose -f openresty/docker-compose.yml up -d
#   # or: OPENRESTY_PREFIX=/usr/local/openresty
./run-openresty-demo.sh start
./run-openresty-demo.sh verify          # M1-1, M1-2, M1-3 (+ prints version for M1-5)
./run-openresty-demo.sh close-port 18081  # M1-4
curl -sS --max-time 3 http://127.0.0.1:18081/   # expect fail
curl -sS http://127.0.0.1:18082/                # still OpenResty
./run-openresty-demo.sh stop
```

QA fills the checkboxes in **[docs/acceptance-m1.md](docs/acceptance-m1.md)** after running the PR; do not treat toy HTTP (`make run-toy`) as M1.

## Idea

```
Client → :18081 / :18082 / :65500  ──sk_lookup──►  same listening socket
         toy: Go HTTP on :18080
         M1:  OpenResty on 127.0.0.1:8080
```

- Real bind: toy `:18080` or OpenResty `:8080`
- Steered ports (default): `18081`, `18082`, `65500` — present only in a BPF hash map
- Removing a map entry closes that external port without touching nginx/OpenResty config

## Requirements

| Need | Notes |
|------|--------|
| Linux + `sk_lookup` | Kernel ≥ 5.9; HCE 2.0 / 5.10 OK. Confirm with `uname -r` / `bpftool feature` |
| Privileges | Root, or `CAP_BPF` + `CAP_NET_ADMIN` (and usually ability to attach to current netns) |
| Build tools | Go **1.22+**, clang, linux headers (`linux-libc-dev`). `CGO_ENABLED=0` |
| OpenResty (M1) | **1.19.3.2** — `openresty/openresty:1.19.3.2-bionic` or a local prefix |
| Network | Demo listens on **loopback**; run on a host/VM where BPF attach is allowed |

```bash
# Debian/Ubuntu example
sudo apt-get install -y clang llvm libbpf-dev linux-libc-dev golang-go
```

`./run.sh` runs `go generate` (cilium/ebpf `bpf2go`) then `go build`, then `sudo` to start the toy binary.

## Flags

```bash
# Toy (default)
sudo ./waf-sklookup-demo -mode toy -listen 127.0.0.1:18080 -ports 18081,18082,65500

# OpenResty M1 (OpenResty must already listen on -target)
sudo ./waf-sklookup-demo -mode openresty -target 127.0.0.1:8080 -ports 18081,18082,65500

# Drop a steered port (loader must still be running; maps pinned)
sudo ./waf-sklookup-demo -mode close-port -ports 18081
```

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `load BPF` / `attach sk_lookup` fails | Not root / missing caps; kernel too old; sk_lookup disabled; restricted container |
| `go generate` / `bpf2go` fails | Missing clang or kernel headers (`linux-libc-dev`); `asm/types.h` via `-I/usr/include/$(uname -m)-linux-gnu` |
| Steered `curl` fails while internal port works | BPF not attached, or port not in `-ports` map |
| Works on bare metal, fails in Docker | Many containers block BPF / netns attach — use a privileged VM or real node |
| `$waf_external_port` empty | See error.log; do not substitute `$server_port` |

## Layout

| Path | Role |
|------|------|
| `dispatch.bpf.c` | `sk_lookup` program + `open_ports` / `redir_socket` maps |
| `loader.go` | load/attach, register listener FD, toy HTTP or OpenResty sockmap mode |
| `openresty/` | OpenResty 1.19.3.2 config + Lua for `$waf_external_port` |
| `run-openresty-demo.sh` | Start/verify/stop M1 demo |
| `docs/openresty-m1.md` | M1 design, reproduce, out of scope |
| `docs/acceptance-m1.md` | QA checklist (M1-1…M1-5 required) |
| `docs/acceptance-m3.md` | M3 stub only (30K/60K memory ladder); not executed in this PR |
| `docs/design-thin-accept-openresty.md` | Transition design: PROXY v2 + thin-accept + OpenResty TLS |
| `docs/perf-deep-compare.md` | Reload / PROXY / TPROXY / sk_lookup performance comparison |

## Relation to the WAF plan

- **End state:** BPF sk_lookup → OpenResty (TLS + Lua WAF). Toy mode is the kernel steering proof; M1 is the first OpenResty wiring.
- **Transition:** PROXY + thin-accept (see `docs/`). Product semantics first; switch data plane when perf gates pass.
- Design notes live in `docs/`; the Notion summary page links this repo as the runnable demo.

## Not production

This is a **kernel steering proof + M1 wiring**, not a full WAF integration. Still out of scope here:

- M2 hot-add API / control plane
- M3 performance matrix ([docs/acceptance-m3.md](docs/acceptance-m3.md) stub is in this PR, not run)
- full TLS parity on steered ports (documented as follow-up)
- multi-worker reuseport sockmap

## License

Demo code: GPL-2.0 for the BPF program (required by helpers); userspace Go code Apache-2.0 / MIT as you prefer for derivatives — adjust before shipping product code.
