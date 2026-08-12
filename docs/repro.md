# Reproduction pack: waf-sklookup-demo

**Aligned to:** `main@3487db5` — *feat: M1 sk_lookup → OpenResty 1.19.3.2（$waf_external_port） (#1)*

Someone else following this file should see the same success/failure contrast.

| Path | What it proves | Status on main@3487db5 |
|------|----------------|------------------------|
| **A. M1 OpenResty (HTTP)** | sk_lookup → OpenResty `127.0.0.1:8080` + `$waf_external_port` | **Primary — run this** |
| **B. Toy Go HTTP** | Kernel steering only (no OpenResty) | Still default binary mode; secondary |
| **C. P1 dual-protocol listen** | Same internal listen accepts **HTTP + HTTPS** (prod: Tengine `https_allow_http`) | **Skeleton only** — fill when Repo P1 branch lands |

QA checklist: [acceptance-m1.md](acceptance-m1.md). Design notes: [openresty-m1.md](openresty-m1.md). Evidence from Test: [acceptance-m1-run.log](acceptance-m1-run.log).

---

## A. M1 OpenResty (HTTP) — primary on main@3487db5

### A.1 Goal

```
Client :18081 / :18082 / :65500
        │  sk_lookup (open_ports + redir_socket)
        ▼
OpenResty listen 127.0.0.1:8080  (worker_processes 1)
        │  access_by_lua → $waf_external_port
        ▼
Body "OpenResty M1 OK" + header X-Waf-External-Port
```

Prove:

1. Only the **internal** listen is bound in userspace (`:8080`).
2. Steered ports hit **OpenResty**, not the toy string `sk_lookup demo OK`.
3. `$waf_external_port` / `X-Waf-External-Port` equals the client destination (not `8080`).
4. Deleting one `open_ports` key fails that port; neighbors still work.
5. OpenResty version string is **1.19.3.2**.

### A.2 Environment prerequisites

| Item | Requirement | How to check |
|------|-------------|--------------|
| OS / kernel | Linux ≥ 5.9 with `sk_lookup` | `uname -r`; `sudo bpftool feature list_builtins prog_types \| rg sk_lookup` |
| Privileges | root / `CAP_BPF` (+ net caps as needed) | loader via `sudo` |
| Go | 1.22+, `CGO_ENABLED=0` | `go version` |
| Toolchain | clang, llvm, libbpf / linux UAPI headers | `clang --version` |
| OpenResty | **1.19.3.2** | `openresty -v` → `nginx version: openresty/1.19.3.2` |
| Helpers | curl; `ss` (iproute2) optional; bpftool optional | |

#### OpenResty 1.19.3.2 install (what Test actually used)

Debian/Ubuntu apt often ships **newer** OpenResty only. Preferred baseline:

```bash
# Image: openresty/openresty:1.19.3.2-bionic
# Option 1 — docker (host network), used by helper when no local binary:
docker compose -f openresty/docker-compose.yml up -d

# Option 2 — extract layers to a local prefix (Test path on Debian 13):
# pull/extract amd64 image layers → OPENRESTY_PREFIX=/usr/local/openresty
export OPENRESTY_PREFIX=/usr/local/openresty
"$OPENRESTY_PREFIX/bin/openresty" -v 2>&1
# Expect: nginx version: openresty/1.19.3.2
```

#### Ports that must be free

| Role | Address |
|------|---------|
| OpenResty internal listen | `127.0.0.1:8080` |
| Steered (no userspace bind) | `18081`, `18082`, `65500` |

```bash
ss -lntp | grep -E ':(8080|18081|18082|65500)\b' || echo "ports free (good)"
```

#### Deps (Debian/Ubuntu example)

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-libc-dev golang-go iproute2 curl
# optional: bpftool via linux-tools-*; docker if using compose path
```

### A.3 Step-by-step (helper — preferred)

```bash
cd /workspace/waf-sklookup-demo
# or: git clone https://github.com/woodyhymns/waf-sklookup-demo.git && cd waf-sklookup-demo
# pin: git checkout 3487db5   # or current main after that merge

export CGO_ENABLED=0
# if local OpenResty extracted:
# export OPENRESTY_PREFIX=/usr/local/openresty

make build
make test

./run-openresty-demo.sh start
./run-openresty-demo.sh verify          # M1-1, M1-2, M1-3 (+ version for M1-5)

# M1-4 negative
./run-openresty-demo.sh dump-ports
./run-openresty-demo.sh close-port 18081
curl -sS --max-time 3 http://127.0.0.1:18081/ || echo "18081 failed (expected)"
curl -sS -D- http://127.0.0.1:18082/ | head -20   # still OpenResty M1 OK
curl -sS -D- http://127.0.0.1:65500/ | head -20

./run-openresty-demo.sh stop
```

Make aliases: `make run-openresty` / `make verify-openresty` / `make stop-openresty`.

### A.4 Manual equivalent (no helper)

```bash
export CGO_ENABLED=0
make build

# Terminal A — OpenResty only binds 127.0.0.1:8080
docker compose -f openresty/docker-compose.yml up -d
# or local openresty -p … -c openresty/nginx.conf (see helper for conf rewrite)

# Terminal B — loader
sudo ./waf-sklookup-demo -mode openresty \
  -target 127.0.0.1:8080 \
  -ports 18081,18082,65500 \
  -wait 60s \
  -pin-dir /sys/fs/bpf/waf-sklookup
```

Then curl / ss / close-port as in A.3 / A.5.

### A.5 Expected output samples

#### Success — start

```text
OpenResty started (local) nginx version: openresty/1.19.3.2 ...
Loader: sk_lookup attached; pinned /sys/fs/bpf/waf-sklookup; registered listen fd for 127.0.0.1:8080
opened steered ports 18081,18082,65500 (no userspace bind)
======== OPENRESTY M1 READY ========
```

#### Success — bind proof (M1-1)

```text
LISTEN 0 511 127.0.0.1:8080 0.0.0.0:* users:(("openresty",...))
PASS: no userspace LISTEN on steered ports
```

`ss` / `/proc/net/tcp` must **not** show LISTEN on `18081` / `18082` / `65500`.

#### Success — steered curl (M1-2 / M1-3)

```text
HTTP/1.1 200 OK
Server: openresty/1.19.3.2
X-Waf-External-Port: 18081
X-Waf-Internal-Port: 8080
...
OpenResty M1 OK
waf_external_port=18081
server_port=8080
remote_addr=127.0.0.1
```

Same pattern for `:18082` and `:65500` with matching external port. Body must **not** contain `sk_lookup demo OK`.

Access log (helper path `/tmp/waf-sklookup-m1/logs/access.log`):

```text
127.0.0.1:… internal_port=8080 waf_external_port=18081 status=200
```

#### Success — close-port (M1-4)

```text
$ ./run-openresty-demo.sh close-port 18081
closed steered port 18081
$ curl -sS --max-time 3 http://127.0.0.1:18081/
curl: (7) Failed to connect to 127.0.0.1 port 18081 ...
$ curl -sS http://127.0.0.1:18082/
... OpenResty M1 OK ... X-Waf-External-Port: 18082
```

bpftool alternative (u16 LE; `18081` = `0x46A9` → `a9 46`):

```bash
sudo bpftool map delete pinned /sys/fs/bpf/waf-sklookup/open_ports key hex a9 46
# or: sudo bpftool map delete name open_ports key hex a9 46
```

#### Failure samples

| Situation | Typical output |
|-----------|----------------|
| No OpenResty yet | `target listen 127.0.0.1:8080 not found` (loader wait expires) |
| No root / caps | `load BPF: ... permission denied` / attach not permitted |
| No sk_lookup | load/attach unsupported / invalid argument |
| Hit toy instead of OpenResty | body contains `sk_lookup demo OK` — **FAIL M1-2** |
| Wrong business port var | `waf_external_port=8080` on a steered request — **FAIL M1-3** (do not use `$server_port`) |
| Port busy on `:8080` | OpenResty fail to bind / helper start fails |
| clang / bpf2go | `clang: not found` or `linux/bpf.h: No such file` |

### A.6 Common pitfalls (M1)

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| apt OpenResty is 1.25+ | Distro package too new | Use `1.19.3.2-bionic` image or extracted prefix |
| `waf_external_port` empty | Lua cannot read `/proc/self/net/tcp` / getsockname | Check `error.log`; never fall back to `$server_port` |
| Steered curl → toy body | Toy loader still running on same ports, or wrong mode | Stop toy; use `-mode openresty` / helper |
| `close-port` cannot open pin | Loader not running / bpffs missing | Keep loader up; ensure `/sys/fs/bpf` mounted |
| Docker without host network | Different netns than curl | Use compose as shipped (`network_mode: host`) or local binary |
| Multi-worker / reuseport | Sockmap assign ambiguity | M1 requires `worker_processes 1` |

### A.7 Minimal pass/fail checklist (M1-1…5)

- [ ] `openresty -v` (or Server header) = **openresty/1.19.3.2**
- [ ] `make build && make test` OK
- [ ] `./run-openresty-demo.sh start` → `OPENRESTY M1 READY`
- [ ] `ss` / proc: LISTEN only on `127.0.0.1:8080` (not steered ports)
- [ ] curl steered ports → `OpenResty M1 OK` + matching `X-Waf-External-Port`
- [ ] `close-port 18081` → that port fails; `18082`/`65500` still 200
- [ ] `./run-openresty-demo.sh stop` cleans up

---

## B. Toy Go HTTP (secondary — kernel steering only)

Default binary mode when you are **not** proving OpenResty wiring.

### B.1 Ports

- Real bind: `127.0.0.1:18080`
- Steered: `18081`, `18082`, `65500`

### B.2 Commands

```bash
export CGO_ENABLED=0
make build
sudo ./waf-sklookup-demo -mode toy -listen 127.0.0.1:18080 -ports 18081,18082,65500
# or: ./run.sh   /   make run-toy
```

Other terminal:

```bash
curl -sS http://127.0.0.1:18080/
curl -sS http://127.0.0.1:18081/
curl -sS http://127.0.0.1:18082/
curl -sS http://127.0.0.1:65500/
ss -lntp | grep -E '18081|18082|65500' || echo "no userspace listeners (expected)"
```

### B.3 Expected success body

```text
sk_lookup demo OK
server_listen=127.0.0.1:18080
...
```

Do **not** treat this path as M1 acceptance.

### B.4 Toy pitfalls

| Symptom | Fix |
|---------|-----|
| No sk_lookup / non-root | ≥5.9 kernel + sudo |
| `address already in use` on `:18080` | Free port or change `-listen` |
| bpf2go/clang failure | Install clang + linux headers |
| Expect ss to show steered ports | They must **not** appear — that is the proof |

---

## C. P1 dual-protocol listen — skeleton (fill when Repo branch lands)

> **Status:** placeholder. Do not mark PASS until Repo ships P1 on `feat/product-p1-tls-and-headers` (or successor). Commands below are intentional stubs.
>
> **Product model (Alex):** production OpenResty includes Tengine **`https_allow_http`**. **Each listen can accept both cleartext HTTP and TLS** on that same socket. sk_lookup only steers external ports to the fixed internal listen(s); **protocol discrimination is in OpenResty/Tengine**, not via separate HTTP vs TLS internal ports.
>
> **Stock OpenResty 1.19.3.2** may lack `https_allow_http`. P1 docs/PR must call out that gap vs the stock image and how the demo approximates it (config snippet + test plan). Do **not** treat “8080 = HTTP only / 8443 = TLS only” as the product architecture (that is at most a stock-compat fallback, if present at all).

### C.1 Intent (product)

```
Client :18081  ── HTTP or HTTPS (same external port / same steered map entry)
        │  sk_lookup → fixed internal listen only
        ▼
OpenResty/Tengine  127.0.0.1:<internal>
        listen ... ssl;
        https_allow_http on;   # production (Tengine); stock 1.19.3.2 may need documented fallback
        │  TLS terminates here when client speaks TLS; cleartext HTTP also accepted on same listen
        │  $waf_external_port = client destination (never use $server_port as business port)
        ▼
access_log / internals see $waf_external_port
```

Related: M1 on main is **HTTP-first** to `:8080` (section A). P1 adds dual-protocol semantics + header policy (default **hide** `X-Waf-External-Port`; enable via flag/env for acceptance). M1-6 TLS was **N/A** on the HTTP-first M1 PR.

### C.2 Prerequisites (expected — confirm on P1 PR)

| Item | Expected | Confirmed on P1? |
|------|----------|------------------|
| Internal listen model | **One** (or few) fixed internal listen(s); **not** HTTP-port vs TLS-port hard split | ☐ |
| `https_allow_http` | Production: on (Tengine). Stock 1.19.3.2: documented gap + demo approximation | ☐ |
| Server cert / key | Demo self-signed under `openresty/certs/` or `make certs` | ☐ |
| Steered ports | Same `open_ports` map; client may use `http://` or `https://` to steered port | ☐ |
| Loader flags | Still register internal listen FD(s); no per-protocol sockmap split required for product story | ☐ |
| Header policy | Default: **no** `X-Waf-External-Port`; `$waf_external_port` still in access_log; flag/env to expose for QA | ☐ |
| Verify helper | TBD (`run-openresty-demo.sh` dual-protocol checks) | ☐ |

### C.3 Steps (TO FILL — do not run as-is)

```bash
# 1) Checkout Repo P1 branch / PR
# git fetch origin && git checkout feat/product-p1-tls-and-headers

# 2) Build
# export CGO_ENABLED=0
# make build

# 3) Start OpenResty (dual-protocol listen + certs) + loader
# ./run-openresty-demo.sh start          # flags TBD by Repo
# sudo ./waf-sklookup-demo -mode openresty -target 127.0.0.1:<internal> -ports 18081,18082,65500

# 4a) Cleartext on a steered port (same internal listen)
# curl -sS -D- http://127.0.0.1:18081/
# Expect: OpenResty body; waf_external_port=18081 in log; X-Waf-External-Port absent unless flag/env on

# 4b) TLS on a steered port (same map entry / same internal listen)
# curl -vk https://127.0.0.1:18081/
# Expect: TLS OK; cert from OpenResty; same $waf_external_port semantics; not toy HTTP

# 5) Bind proof
# ss -lntp | rg ':(<internal>|18081|18082|65500)\b'
# Expect: LISTEN only on internal listen; no userspace bind on steered ports

# 6) Negative: close-port one steered port; neighbor still serves HTTP and HTTPS
# ./run-openresty-demo.sh close-port 18081
# curl -sS --max-time 3 http://127.0.0.1:18081/    # expect fail
# curl -vk --max-time 3 https://127.0.0.1:18081/  # expect fail
# curl -sS http://127.0.0.1:18082/                 # still 200
```

### C.4 Expected samples (TO FILL)

**Success — cleartext + TLS on same steered port**

```text
# paste: http:// steered response (no X-Waf-External-Port by default)
# paste: curl -vk https:// steered excerpt (TLS version, CN/SAN, ALPN)
# paste: access_log lines with waf_external_port=<steered>
```

**Success — bind**

```text
# paste: ss -lntp showing only internal listen (dual-protocol), not steered ports
```

**Failure**

```text
# paste: connect fail after close-port / unopened port
# paste: stock image without https_allow_http — documented limitation / fallback behavior
```

### C.5 P1 pitfalls (draft)

| Symptom | Likely cause | Notes |
|---------|--------------|-------|
| Docs still say 8080=HTTP / 8443=TLS only | Stale product model | Prefer `https_allow_http` one-listen story; label any split as stock fallback |
| HTTPS fails on stock 1.19.3.2 | No `https_allow_http` | Expected gap — document; do not pretend stock == production |
| `$waf_external_port` wrong under TLS | Lua path only tested on cleartext | Re-verify `/proc` 4-tuple after SSL |
| `X-Waf-External-Port` always present | Header gate missing | Default hide; flag/env for acceptance only |
| SNI / ALPN mismatch vs old arch | Wrong `ssl_certificate` / listen config | Compare to baseline direct listen |

### C.6 P1 checklist (empty until Repo lands)

- [ ] Internal listen only in `ss` (no steered binds)
- [ ] Same steered port: `http://` and `https://` both hit OpenResty (per P1 demo capability)
- [ ] PR/docs state production `https_allow_http` vs stock 1.19.3.2 difference
- [ ] Default response has **no** `X-Waf-External-Port`; log still has `$waf_external_port`
- [ ] With flag/env, header appears for QA
- [ ] close-port negative; neighbor still works
- [ ] No toy HTTP body on either path

When Repo publishes P1, replace every `TBD` / `TO FILL` here with concrete flags, ports, and pasted samples; keep section A as the HTTP-first main@3487db5 path unless flags fully supersede it.

---

## Scope / non-goals

- No production customer data, no production deploys, no merge/push from this pack alone (Repo owns GitHub).
- M2 hot-add API / M3 memory ladder: out of scope ([acceptance-m3.md](acceptance-m3.md) stub only).
- Multi-worker reuseport sockmap: out of scope for M1.
- Design context: [design-thin-accept-openresty.md](design-thin-accept-openresty.md), [perf-deep-compare.md](perf-deep-compare.md).
