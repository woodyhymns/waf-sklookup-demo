# waf-sklookup-demo

Minimal demo: **one** userspace `listen()`, many extra TCP ports opened only via Linux BPF **`sk_lookup`** (no `bind`/`listen` on those ports).

Useful as a building block for WAF / OpenResty-style **runtime dynamic non-standard listen ports** on kernels that support `sk_lookup` (Linux ≥ 5.9; HCE 2.0 / kernel 5.10 qualifies).

## Idea

```
Client → :18081 / :18082 / :65500  ──sk_lookup──►  same listening socket on :18080
```

- Real bind: `127.0.0.1:18080`
- Steered ports (default): `18081`, `18082`, `65500` — present only in a BPF hash map
- Removing a map entry closes that external port without touching nginx/OpenResty config

## Requirements

- Linux with `sk_lookup` (check: `bpftool feature | grep -i sk_lookup` or kernel ≥ 5.9)
- Root (or `CAP_BPF` + `CAP_NET_ADMIN` as appropriate)
- Go 1.22+, clang, llvm, libbpf headers (`linux-libc-dev`), `bpftool` helpful

```bash
# Debian/Ubuntu example
sudo apt-get install -y clang llvm libbpf-dev linux-libc-dev golang-go
```

## Build & run

```bash
git clone https://github.com/woodyhymns/waf-sklookup-demo.git
cd waf-sklookup-demo
./run.sh
# or: make run
```

Flags:

```bash
sudo ./waf-sklookup-demo -listen 127.0.0.1:18080 -ports 18081,18082,65500
```

## Verify

In another terminal:

```bash
# real bind
curl -sS http://127.0.0.1:18080/

# steered ports (no userspace listen on these)
curl -sS http://127.0.0.1:18081/
curl -sS http://127.0.0.1:18082/
curl -sS http://127.0.0.1:65500/

# proof: nothing bound on steered port in userspace
ss -lntp | grep -E '18081|18082|65500' || echo "no userspace listeners (expected)"
```

Without the BPF program attached, steered-port curls should fail.

## Layout

| Path | Role |
|------|------|
| `dispatch.bpf.c` | `sk_lookup` program + `open_ports` / `redir_socket` maps |
| `loader.go` | load/attach, register listener FD, open ports, tiny HTTP server |
| `docs/` | design notes (thin-accept transition, perf compare) |

## Not production

This is a **kernel steering proof**, not a full WAF integration. Production path typically still needs:

- preserve original dest port for logging / ACL (`$waf_external_port` or equivalent)
- OpenResty / nginx worker model + TLS termination
- safe map update API (add/remove port under load)
- long-term: tubular-style sk_lookup vs short-term PROXY v2 thin-accept (see `docs/`)

## License

Demo code: GPL-2.0 for the BPF program (required by helpers); userspace Go code Apache-2.0 / MIT as you prefer for derivatives — adjust before shipping product code.
