# waf-sklookup-demo

Minimal demo: **one** userspace `listen()`, many extra TCP ports opened only via Linux BPF **`sk_lookup`** (no `bind`/`listen` on those ports).

Useful as a building block for WAF / OpenResty-style **runtime dynamic non-standard listen ports** on kernels that support `sk_lookup` (Linux ≥ 5.9; HCE 2.0 / kernel 5.10 qualifies).

**M1:** steer those ports into **OpenResty 1.19.3.2** on a fixed internal listen (`127.0.0.1:8080`) and record the client destination as **`$waf_external_port`**. **P1:** TLS is terminated only in OpenResty; production uses Tengine **`https_allow_http`** so **one listen accepts both HTTP and TLS**. Stock 1.19.3.2 cannot do that — the demo’s second listen (`:8443 ssl`) is a labeled fallback. Default responses **omit** `X-Waf-External-Port` (enable with `WAF_EXPOSE_EXTERNAL_PORT=1`). Toy HTTP remains `-mode toy`.

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

## M1 + P1: sk_lookup → OpenResty (HTTP + TLS)

**M1 acceptance:** [docs/acceptance-m1.md](docs/acceptance-m1.md). Design: [docs/openresty-m1.md](docs/openresty-m1.md). **P1 (this branch):** [docs/openresty-p1.md](docs/openresty-p1.md).

OpenResty binds **fixed internal listens** only. The loader registers those listen FDs into the sockmap and opens extra ports in BPF. Do **not** use `$server_port` as the business/external port (after `sk_lookup` it is often `8080` / `8443`). Use **`$waf_external_port`**.

**Product (Tengine):** one listen, both protocols — `listen 127.0.0.1:8080 ssl https_allow_http;` — sk_lookup does not classify HTTP vs TLS. Snippet: [`openresty/nginx.tengine-https-allow-http.conf.example`](openresty/nginx.tengine-https-allow-http.conf.example).

**Stock demo (`openresty/openresty:1.19.3.2-bionic`):** that listen flag is **invalid**. Fallback (not the product model): `127.0.0.1:8080` HTTP + `127.0.0.1:8443 ssl`, with `-tls-ports` steered to 8443.

| Must-pass | What to prove | This PR |
|-----------|---------------|---------|
| **M1-1** | `ss -lntp` shows only the fixed OpenResty internal listen; steered ports have no userspace bind | Internal `127.0.0.1:8080`; extras `18081,18082,65500` |
| **M1-2** | External ports hit **OpenResty**, not toy `sk_lookup demo OK` | Body `OpenResty M1 OK`; `Server: openresty/1.19.3.2` |
| **M1-3** | `$waf_external_port` = client destination; two ports distinguishable; **not** the internal listen | Body + access_log (header `X-Waf-External-Port` is **off** by default; see P1) |
| **M1-4** | Delete one `open_ports` key → that port fails; neighbors still work | `./run-openresty-demo.sh close-port 18081` or `bpftool map delete` |
| **M1-5** | Run against OpenResty **1.19.3.2** (or same-generation, write the version string) | Image `openresty/openresty:1.19.3.2-bionic` |

```bash
export CGO_ENABLED=0
make certs   # demo-only self-signed cert (required for :8443 ssl on stock 1.19.3.2)
# OpenResty 1.19.3.2 via docker (host network) or local prefix:
#   docker compose -f openresty/docker-compose.yml up -d
#   # or: OPENRESTY_PREFIX=/usr/local/openresty
./run-openresty-demo.sh start
./run-openresty-demo.sh verify          # HTTP + stock HTTPS fallback; header hidden
curl -sS -D- http://127.0.0.1:18081/   # no X-Waf-External-Port by default
curl -sk -D- https://127.0.0.1:18443/  # steered TLS (stock fallback; -k = self-signed)
./run-openresty-demo.sh close-port 18081
./run-openresty-demo.sh open-port 18081
./run-openresty-demo.sh stop

# Debug header (restart OpenResty so nginx env is picked up):
WAF_EXPOSE_EXTERNAL_PORT=1 ./run-openresty-demo.sh start
```

QA fills the checkboxes in **[docs/acceptance-m1.md](docs/acceptance-m1.md)** after running the PR; do not treat toy HTTP (`make run-toy`) as M1.

## Idea

```
Client → :18081 / :18082 / :65500  ──sk_lookup──►  fixed internal listen(s)
         toy: Go HTTP on :18080
         product (Tengine): OpenResty 127.0.0.1:8080 ssl https_allow_http  (HTTP+TLS)
         stock 1.19.3.2 fallback: 127.0.0.1:8080 HTTP + 127.0.0.1:8443 ssl
```

- Real bind: toy `:18080`, or OpenResty `:8080` (and stock fallback `:8443`)
- Steered ports (default): `18081`, `18082`, `65500` → primary listen; stock TLS demo also steers `18443` → `:8443`
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

# OpenResty — product-shaped (all ports → one listen; Tengine https_allow_http)
sudo ./waf-sklookup-demo -mode openresty -target 127.0.0.1:8080 -ports 18081,18082,65500

# OpenResty — stock 1.19.3.2 TLS fallback (NOT the product model)
sudo ./waf-sklookup-demo -mode openresty \
  -target 127.0.0.1:8080 -ports 18081,18082,65500 \
  -tls-target 127.0.0.1:8443 -tls-ports 18443

# Drop / re-open a steered port (loader must still be running; maps pinned)
sudo ./waf-sklookup-demo -mode close-port -ports 18081
sudo ./waf-sklookup-demo -mode open-port -ports 18081
```

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `load BPF` / `attach sk_lookup` fails | Not root / missing caps; kernel too old; sk_lookup disabled; restricted container |
| `go generate` / `bpf2go` fails | Missing clang or kernel headers (`linux-libc-dev`); `asm/types.h` via `-I/usr/include/$(uname -m)-linux-gnu` |
| Steered `curl` fails while internal port works | BPF not attached, or port not in `-ports` map |
| Works on bare metal, fails in Docker | Many containers block BPF / netns attach — use a privileged VM or real node |
| `$waf_external_port` empty | See error.log; do not substitute `$server_port` |
| `https_allow_http` invalid parameter | Stock 1.19.3.2 — use the fallback conf, not the Tengine example |
| `X-Waf-External-Port` missing | Default. Set `WAF_EXPOSE_EXTERNAL_PORT=1` and restart OpenResty |
| HTTPS curl fails with certificate error | Use `curl -k` (demo self-signed); run `make certs` first |

## Layout

| Path | Role |
|------|------|
| `dispatch.bpf.c` | `sk_lookup` program + `open_ports` / `redir_socket` maps |
| `loader.go` | load/attach, register listener FD, toy HTTP or OpenResty sockmap mode |
| `openresty/` | OpenResty 1.19.3.2 config + Lua for `$waf_external_port`; Tengine example listen |
| `openresty/certs/` | `make certs` demo-only self-signed material (keys gitignored) |
| `run-openresty-demo.sh` | Start/verify/stop OpenResty demo (HTTP + stock TLS fallback) |
| `docs/openresty-m1.md` | M1 HTTP wiring |
| `docs/openresty-p1.md` | P1 TLS product model, stock vs Tengine, header flag |
| `docs/acceptance-m1.md` | QA checklist (M1-1…M1-5 required) |
| `docs/acceptance-m3.md` | M3 stub only (30K/60K memory ladder); not executed in this PR |
| `docs/design-thin-accept-openresty.md` | Transition design: PROXY v2 + thin-accept + OpenResty TLS |
| `docs/perf-deep-compare.md` | Reload / PROXY / TPROXY / sk_lookup performance comparison |

## Relation to the WAF plan

- **End state:** BPF sk_lookup → OpenResty (TLS + Lua WAF), with Tengine `https_allow_http` so one listen takes HTTP and TLS. Toy mode is the kernel steering proof; M1 is HTTP wiring; P1 adds TLS + header policy.
- **Transition:** PROXY + thin-accept (see `docs/`). Product semantics first; switch data plane when perf gates pass.
- Design notes live in `docs/`; the Notion summary page links this repo as the runnable demo.

## Not production

This is a **kernel steering proof + M1 wiring**, not a full WAF integration. Still out of scope here:

- M2 hot-add API / control plane
- M3 performance matrix ([docs/acceptance-m3.md](docs/acceptance-m3.md) stub is in this PR, not run)
- Tengine runtime in the default helper (example conf + test plan only)
- multi-worker reuseport sockmap

## License

Demo code: GPL-2.0 for the BPF program (required by helpers); userspace Go code Apache-2.0 / MIT as you prefer for derivatives — adjust before shipping product code.
