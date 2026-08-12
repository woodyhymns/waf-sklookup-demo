# waf-sklookup-demo

Minimal demo: **one** userspace `listen()`, many extra TCP ports opened only via Linux BPF **`sk_lookup`** (no `bind`/`listen` on those ports).

Useful as a building block for WAF / OpenResty-style **runtime dynamic non-standard listen ports** on kernels that support `sk_lookup` (Linux ≥ 5.9; HCE 2.0 / kernel 5.10 qualifies).

**Goal of this repo:** prove sk_lookup can steer traffic to a single listening socket without binding the extra ports. It is **not** a full OpenResty/WAF integration.

## 10-minute quick start

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

## Idea

```
Client → :18081 / :18082 / :65500  ──sk_lookup──►  same listening socket on :18080
```

- Real bind: `127.0.0.1:18080`
- Steered ports (default): `18081`, `18082`, `65500` — present only in a BPF hash map
- Removing a map entry closes that external port without touching nginx/OpenResty config

## Requirements

| Need | Notes |
|------|--------|
| Linux + `sk_lookup` | Kernel ≥ 5.9; HCE 2.0 / 5.10 OK. Confirm with `uname -r` / `bpftool feature` |
| Privileges | Root, or `CAP_BPF` + `CAP_NET_ADMIN` (and usually ability to attach to current netns) |
| Build tools | Go **1.22+**, clang, llvm, libbpf headers (`libbpf-dev`, `linux-libc-dev`) |
| Network | Demo listens on **loopback**; run on a host/VM where BPF attach is allowed |

```bash
# Debian/Ubuntu example
sudo apt-get install -y clang llvm libbpf-dev linux-libc-dev golang-go
```

`./run.sh` runs `go generate` (cilium/ebpf `bpf2go`) then `go build`, then `sudo` to start the binary.

## Flags

```bash
sudo ./waf-sklookup-demo -listen 127.0.0.1:18080 -ports 18081,18082,65500
```

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `load BPF` / `attach sk_lookup` fails | Not root / missing caps; kernel too old; sk_lookup disabled; restricted container |
| `go generate` / `bpf2go` fails | Missing clang/llvm or libbpf headers |
| Steered `curl` fails while `:18080` works | BPF not attached, or port not in `-ports` map |
| Works on bare metal, fails in Docker | Many containers block BPF / netns attach — use a privileged VM or real node |

## Layout

| Path | Role |
|------|------|
| `dispatch.bpf.c` | `sk_lookup` program + `open_ports` / `redir_socket` maps |
| `loader.go` | load/attach, register listener FD, open ports, tiny HTTP server |
| `docs/design-thin-accept-openresty.md` | Transition design: PROXY v2 + thin-accept + OpenResty TLS |
| `docs/perf-deep-compare.md` | Reload / PROXY / TPROXY / sk_lookup performance comparison |

## Relation to the WAF plan

- **End state:** BPF sk_lookup → OpenResty (TLS + Lua WAF). This demo is the kernel steering proof.
- **Transition:** PROXY + thin-accept (see `docs/`). Product semantics first; switch data plane when perf gates pass.
- Design notes live in `docs/`; the Notion summary page links this repo as the runnable demo.

## Not production

This is a **kernel steering proof**, not a full WAF integration. Production path typically still needs:

- preserve original dest port for logging / ACL (`$waf_external_port` or equivalent)
- OpenResty / nginx worker model + TLS termination
- safe map update API (add/remove port under load)
- long-term: tubular-style sk_lookup vs short-term PROXY v2 thin-accept (see `docs/`)

## License

Demo code: GPL-2.0 for the BPF program (required by helpers); userspace Go code Apache-2.0 / MIT as you prefer for derivatives — adjust before shipping product code.
