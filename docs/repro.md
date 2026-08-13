# Reproduction pack: waf-sklookup-demo

Goal: prove that **one** userspace `listen()` on `:18080` can serve extra TCP ports (`18081`, `18082`, `65500`) via Linux BPF **`sk_lookup`**, with **no** `bind`/`listen` on those steered ports.

Someone else following this file should see the same success/failure contrast.

---

## 1. Environment prerequisites

| Item | Requirement | How to check |
|------|-------------|--------------|
| OS | Linux | `uname -s` → `Linux` |
| Kernel | ≥ 5.9 (HCE 2.0 / 5.10 OK) | `uname -r` |
| `sk_lookup` | Present in BPF features | See below |
| Privileges | root, or `CAP_BPF` + `CAP_NET_ADMIN` (and usually `CAP_PERFMON` / `CAP_SYS_ADMIN` depending on distro) | `id -u` → `0`, or run under `sudo` |
| Go | 1.22+ | `go version` |
| Toolchain | `clang`, `llvm`, libbpf headers (`linux-libc-dev` / `libbpf-dev`) | `clang --version` |
| Optional | `bpftool`, `curl`, `ss` (`iproute2`) | for feature check + verify |

### Confirm `sk_lookup`

```bash
# Preferred
sudo bpftool feature 2>/dev/null | grep -i sk_lookup

# Fallback: kernel version
uname -r
# Expect 5.9+ (and a distro that actually built sk_lookup in).
```

If `bpftool` shows no `sk_lookup` / `BPF_PROG_TYPE_SK_LOOKUP`, **stop** — this demo cannot work on that kernel.

### Install deps (Debian/Ubuntu example)

```bash
sudo apt-get update
sudo apt-get install -y rustc cargo clang llvm libbpf-dev libelf-dev linux-libc-dev iproute2 curl
# Optional but useful:
sudo apt-get install -y linux-tools-common linux-tools-$(uname -r) || true
```

### Ports that must be free

Defaults used below:

- Real bind: `127.0.0.1:18080`
- Steered (no userspace bind): `18081`, `18082`, `65500`

```bash
ss -lntp | grep -E '18080|18081|18082|65500' || echo "ports free (good)"
```

---

## 2. Step-by-step: build → run → curl contrast → ss proof

Work from the shared tree (or a clone):

```bash
cd /workspace/waf-sklookup-demo
# or: git clone https://github.com/woodyhymns/waf-sklookup-demo.git && cd waf-sklookup-demo
```

### 2.1 Build

```bash
# Generates dispatch_bpfel.go / .o via bpf2go, then builds the binary
make build
# equivalent:
#   cargo build --release --manifest-path rust/loader/Cargo.toml
```

Expect: binary `./rust/loader/target/release/waf-sklookup-loader` appears; no clang/libbpf errors.

### 2.2 Run (terminal A — keep it open)

```bash
sudo ./rust/loader/target/release/waf-sklookup-loader -listen 127.0.0.1:18080 -ports 18081,18082,65500
# or: ./run.sh
# or: make run
```

Leave this process running until verify is done. Ctrl+C stops it and detaches the program.

### 2.3 Curl contrast (terminal B)

**A. Real bind (always works while demo is up):**

```bash
curl -sS http://127.0.0.1:18080/
```

**B. Steered ports (must work *with* BPF attached):**

```bash
curl -sS http://127.0.0.1:18081/
curl -sS http://127.0.0.1:18082/
curl -sS http://127.0.0.1:65500/
```

**C. Negative control — stop the demo (Ctrl+C in terminal A), then:**

```bash
curl -sS --connect-timeout 2 http://127.0.0.1:18081/ || echo "steered port failed without BPF (expected)"
```

Without the process / BPF attach, steered-port curls must fail. `:18080` also fails once the process is gone (that one really was bound).

Optional sharper negative: if you can load a build that listens but skips attach (not in-tree), steered ports fail while `:18080` still works. Stock demo attaches before serving, so process-down is the practical negative.

### 2.4 Prove no userspace bind on steered ports (while demo is running)

```bash
ss -lntp | grep -E '18080|18081|18082|65500'
```

Expect:

- One listener on `127.0.0.1:18080` (the Go process).
- **No** lines for `18081`, `18082`, or `65500`.

```bash
ss -lntp | grep -E '18081|18082|65500' || echo "no userspace listeners (expected)"
```

That is the core proof: curls to steered ports succeed, but `ss` shows no bind there.

---

## 3. Expected output samples

### 3.1 Success — process startup (terminal A)

```text
2026/08/13 00:00:00 sk_lookup attached to current netns
2026/08/13 00:00:00 registered listening socket fd=7 for 127.0.0.1:18080
2026/08/13 00:00:00 opened steered port 18081 (no userspace bind on that port)
2026/08/13 00:00:00 opened steered port 18082 (no userspace bind on that port)
2026/08/13 00:00:00 opened steered port 65500 (no userspace bind on that port)
2026/08/13 00:00:00 HTTP server serving on 127.0.0.1:18080 (and steered ports)
======== DEMO READY ========
Real bind:   curl -sS http://127.0.0.1:18080/
Steered:     curl -sS http://127.0.0.1:18081/
Steered:     curl -sS http://127.0.0.1:18082/
Steered:     curl -sS http://127.0.0.1:65500/
Without BPF those steered ports would fail to connect.
Ctrl+C to stop.
============================
```

(Timestamps / fd numbers vary.)

### 3.2 Success — curl on real + steered ports (terminal B)

Each of `18080` / `18081` / `18082` / `65500` should return something like:

```text
sk_lookup demo OK
server_listen=127.0.0.1:18080
http_local_addr=127.0.0.1:18080
remote=127.0.0.1:54321
host=127.0.0.1:18081
path=/
```

Notes:

- Body always says `server_listen=127.0.0.1:18080` (single real listen).
- `host=` reflects the port the client used in the URL (e.g. `18081`).
- `http_local_addr` often still shows the *listening* socket address (`:18080`) even when the client hit a steered port — that is normal for this demosock assignment path; do not treat it as a fail.

### 3.3 Success — `ss` proof

```text
LISTEN 0  4096  127.0.0.1:18080  0.0.0.0:*  users:(("waf-sklookup-d",pid=1234,fd=6))
```

And:

```text
no userspace listeners (expected)
```

when grepping only steered ports.

### 3.4 Failure samples

**No root / missing caps:**

```text
load BPF: ... permission denied
(hint: need root/CAP_BPF and kernel sk_lookup)
```

or attach fails:

```text
attach sk_lookup: ... operation not permitted
```

**Kernel without `sk_lookup`:**

```text
load BPF: ... 
```

or

```text
attach sk_lookup: ... invalid argument / not supported
```

**Port already in use on real listen:**

```text
listen 127.0.0.1:18080: bind: address already in use
```

**Steered curl without demo / without BPF (expected fail):**

```text
curl: (7) Failed to connect to 127.0.0.1 port 18081: Connection refused
steered port failed without BPF (expected)
```

**bpf2go / clang failure at generate:**

```text
Error: ... clang ... not found
```

or missing headers:

```text
fatal error: 'linux/bpf.h' file not found
```

---

## 4. Common pitfalls

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Attach/load fails with “not supported” / weird errno | Kernel has no `sk_lookup` (&lt; 5.9 or feature stripped) | Use a ≥5.9 kernel with sk_lookup; verify with `bpftool feature` |
| Permission denied on load/attach | Not root / missing caps | `sudo ./rust/loader/target/release/waf-sklookup-loader ...` |
| `address already in use` on `:18080` | Another process holds the real listen port | `ss -lntp \| grep 18080`, stop the other listener or change `-listen` |
| Steered curls fail but `:18080` works | BPF not attached, wrong netns, or ports not in `-ports` | Check startup logs for “sk_lookup attached” and “opened steered port”; same netns as the client |
| Cargo/libbpf build fails | No `clang`, or missing `libbpf` / `libelf` / kernel UAPI headers | Install `clang llvm libbpf-dev libelf-dev linux-libc-dev` |
| `go: ... go.mod requires go >= 1.22` | Old Go toolchain | Install Go 1.22+ |
| Demo works on host, fails in container | Container runtime blocks BPF / netns attach | Privileged (or suitable caps) + host kernel that supports sk_lookup; attach is to *current* netns |
| Expect `ss` to show steered ports | Misunderstanding the demo | Steered ports must **not** appear in `ss -lntp`; that is the point |
| IPv6-only curl / wrong host | Listening on `127.0.0.1` only | Use `http://127.0.0.1:...` as documented, not `localhost` if that resolves to `::1` |

---

## 5. Minimal pass/fail checklist

Copy this when filing or handing off:

- [ ] `uname -r` ≥ 5.9 and/or `bpftool feature` shows sk_lookup  
- [ ] `make build` succeeds  
- [ ] `sudo ./rust/loader/target/release/waf-sklookup-loader ...` prints `DEMO READY`
- [ ] `curl` to `:18080`, `:18081`, `:18082`, `:65500` all return `sk_lookup demo OK`  
- [ ] `ss -lntp` shows listener **only** on `:18080`, not on steered ports  
- [ ] After Ctrl+C, steered `curl` fails  

If all six are true, reproduction succeeded.

---

## 6. Scope / non-goals

- This pack is a **kernel steering proof**, not a full WAF/OpenResty integration.
- No production customer data, no production deploys, no GitHub push from this pack.
- Design context (thin-accept vs sk_lookup, perf notes): see sibling docs under `docs/`.

## 7. OpenResty M1 wiring

The toy HTTP path above remains valid. For **sk_lookup → OpenResty** (fixed internal listen + `$waf_external_port`), follow **[docs/openresty-m1.md](openresty-m1.md)** (M1 HTTP) and **[docs/openresty-p1.md](openresty-p1.md)** (P1 TLS + header policy). Helper: `./run-openresty-demo.sh start && ./run-openresty-demo.sh verify`. HTTPS on the stock image uses `curl -k` against the fallback TLS port.
