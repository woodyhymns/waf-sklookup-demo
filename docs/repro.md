# Reproduction pack: waf-sklookup-demo

**Aligned to:** `main@ab66cf5` — *feat: P1 TLS in OpenResty + hide X-Waf-External-Port (#4)*

Someone else following this file should see the same success/failure contrast.

| Path | What it proves | Status on main@ab66cf5 |
|------|----------------|------------------------|
| **A. P1-A HAH (product)** | Same steered port: `http://` **and** `https://` → one internal listen with `https_allow_http` | **Primary — run this** |
| **B. Stock 1.19.3.2 fallback** | Dual internal listens (`8080` + `8443 ssl`); TLS on separate steered port | Labeled fallback only |
| **C. M1 HTTP / toy** | Earlier wiring / kernel-only proof | Secondary |

QA: [acceptance-p1.md](acceptance-p1.md) · Design: [openresty-p1.md](openresty-p1.md) · HAH evidence: [acceptance-p1-a-hah-run.log](acceptance-p1-a-hah-run.log) · Build: [third_party/https_allow_http/README.md](../third_party/https_allow_http/README.md)

---

## A. P1-A — OpenResty-HAH / `https_allow_http` (product)

### A.1 Goal

```
Client :18081   http://  OR  https://
        │  sk_lookup  (open_ports → redir_socket[0] only; no -tls-ports)
        ▼
OpenResty-HAH  listen 127.0.0.1:8080 ssl https_allow_http
        │  engine peeks TLS ClientHello vs HTTP
        access_by_lua → $waf_external_port
        ▼
Body "OpenResty M1 OK"  scheme=http|https  waf_external_port=18081
Default: NO X-Waf-External-Port header
```

Prove:

1. Userspace LISTEN only on the **one** internal port (`127.0.0.1:8080`).
2. **Same** steered port answers both plaintext HTTP and TLS.
3. `$waf_external_port` / body = client destination (not `8080`); default response **hides** `X-Waf-External-Port`.
4. Engine is OpenResty **1.19.3.2** built with the HAH patch (`OPENRESTY_PREFIX=/usr/local/openresty-hah`).

### A.2 Environment prerequisites

| Item | Requirement | How to check |
|------|-------------|--------------|
| OS / kernel | Linux ≥ 5.9 + `sk_lookup` | `uname -r`; `sudo bpftool feature list_builtins prog_types \| rg sk_lookup` |
| Privileges | root / `CAP_BPF` | loader via `sudo` |
| Go / clang | Go 1.22+, `CGO_ENABLED=0`, clang + headers | `go version`; `clang --version` |
| **OpenResty-HAH** | Patched 1.19.3.2 at **`/usr/local/openresty-hah`** | See A.2.1 |
| Certs | Demo self-signed under `openresty/certs/` | `make certs` |
| Helpers | curl (`-k` for HTTPS), `ss` optional | |

Stock `/usr/local/openresty` **cannot** parse `https_allow_http` — do **not** use it for path A.

#### A.2.1 Build / confirm OpenResty-HAH

```bash
# From repo root (does NOT overwrite stock /usr/local/openresty)
./third_party/https_allow_http/build-openresty-hah.sh

export OPENRESTY_PREFIX=/usr/local/openresty-hah
"$OPENRESTY_PREFIX/bin/openresty" -v 2>&1
# Expect: nginx version: openresty/1.19.3.2

# Capability: listen flag must be accepted (invalid parameter = wrong binary)
```

If the prefix already exists on the shared box (Test’s HAH run), skip rebuild and export the same prefix.

#### A.2.2 Ports that must be free

| Role | Address |
|------|---------|
| HAH internal listen (HTTP+TLS) | `127.0.0.1:8080` |
| Steered (no userspace bind) | `18081`, `18082`, `65500` |

```bash
ss -lntp | grep -E ':(8080|18081|18082|65500)\b' || echo "ports free (good)"
```

### A.3 Preferred one-shot (Test harness)

```bash
cd /workspace/waf-sklookup-demo
# pin: git checkout ab66cf5   # or current main after that merge
export CGO_ENABLED=0

OPENRESTY_PREFIX=/usr/local/openresty-hah \
  ./scripts/accept-p1-a-dual.sh
# defaults also set:
#   OPENRESTY_NGINX_CONF=openresty/nginx.tengine-https-allow-http.conf.example
#   LOADER_TLS_PORTS=   (empty → no stock 8443/-tls-ports split)
```

Expect **EXIT 0** and `P1-A PASS: same port :18081 HTTP + HTTPS both hit engine`.

### A.4 Manual steps (same as harness)

```bash
export CGO_ENABLED=0
export OPENRESTY_PREFIX=/usr/local/openresty-hah
export OPENRESTY_NGINX_CONF=openresty/nginx.tengine-https-allow-http.conf.example
export LOADER_TLS_PORTS=""          # critical: product path, no -tls-ports

make certs
make build && make test

./run-openresty-demo.sh stop >/dev/null 2>&1 || true
./run-openresty-demo.sh start
./run-openresty-demo.sh verify      # same-port HTTPS must PASS on HAH (not N/A)

# Explicit P1-A pair
curl -sS -D- http://127.0.0.1:18081/
curl -sk -D- https://127.0.0.1:18081/   # -k: demo cert

# Bind proof — only :8080
ss -lntp | grep -E ':(8080|18081|18082|65500|8443|18443)\b'

# Header policy (default hide)
curl -sS -D- -o /dev/null http://127.0.0.1:18081/ | grep -i X-Waf-External-Port \
  || echo "no X-Waf-External-Port (expected)"

# Optional: expose debug header
WAF_EXPOSE_EXTERNAL_PORT=1 ./run-openresty-demo.sh stop
WAF_EXPOSE_EXTERNAL_PORT=1 ./run-openresty-demo.sh start
curl -sS -D- http://127.0.0.1:18081/ | grep -i X-Waf-External-Port
# X-Waf-External-Port: 18081

# Map edit
./run-openresty-demo.sh close-port 18081
curl -sS --max-time 3 http://127.0.0.1:18081/ || echo "closed (expected)"
./run-openresty-demo.sh open-port 18081
curl -sS http://127.0.0.1:18081/

./run-openresty-demo.sh stop
```

Manual loader equivalent (no helper):

```bash
# OpenResty already listening with tengine example conf on 127.0.0.1:8080
sudo ./waf-sklookup-demo -mode openresty \
  -target 127.0.0.1:8080 \
  -ports 18081,18082,65500
# no -tls-ports / no -tls-target
```

### A.5 Expected output samples (from Test HAH run)

#### Success — start

```text
Using nginx conf: openresty/nginx.tengine-https-allow-http.conf.example
OpenResty started (local) nginx version: openresty/1.19.3.2 ... expose=off
Loader PID ...
```

#### Success — P1-A same port

```text
=== P1-A same port HTTP ===
OpenResty M1 OK
waf_external_port=18081
server_port=8080
scheme=http
remote_addr=127.0.0.1

=== P1-A same port HTTPS ===
OpenResty M1 OK
waf_external_port=18081
server_port=8080
scheme=https
remote_addr=127.0.0.1
PASS: default hide header
P1-A PASS: same port :18081 HTTP + HTTPS both hit engine
```

#### Success — summary block

```text
OPENRESTY_PREFIX=/usr/local/openresty-hah
openresty/1.19.3.2 with https_allow_http
P1-A: http://127.0.0.1:18081/ → scheme=http waf_external_port=18081
P1-A: https://127.0.0.1:18081/ → scheme=https waf_external_port=18081
OVERALL: PASS
```

#### Failure samples

| Situation | Typical signal |
|-----------|----------------|
| Stock OpenResty used by mistake | `invalid parameter "https_allow_http"` / harness exit 3 `BLOCKED` |
| `LOADER_TLS_PORTS` left at default `18443` | Stock split path; same-port HTTPS may N/A or miss product proof |
| Missing HAH prefix | `FAIL: OPENRESTY_PREFIX=... has no bin/openresty` |
| No certs | `make certs` / start fails on ssl_certificate paths |
| HTTPS on stock single HTTP listen | connection fail / wrong scheme — expected N/A on stock, **FAIL** on HAH |
| Default header leak | `X-Waf-External-Port` present without `WAF_EXPOSE_EXTERNAL_PORT=1` |

### A.6 Common pitfalls (HAH / P1-A)

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `invalid parameter "https_allow_http"` | Using stock `/usr/local/openresty` | `export OPENRESTY_PREFIX=/usr/local/openresty-hah` |
| Same-port HTTPS fails | Wrong conf or TLS ports fallback | Set `OPENRESTY_NGINX_CONF=...tengine...example` and `LOADER_TLS_PORTS=""` |
| Docs/ss show 8080+8443 | Stock fallback still running | Stop demo; restart with HAH env above |
| Treating 8080=HTTP / 8443=TLS as product | Stale model | Product is **one** listen + `https_allow_http` |
| Header always visible | Expose env left on | Restart without `WAF_EXPOSE_EXTERNAL_PORT` |

### A.7 Minimal checklist (P1-A)

- [ ] `OPENRESTY_PREFIX=/usr/local/openresty-hah` and `openresty -v` → 1.19.3.2  
- [ ] `nginx -t` accepts `listen ... ssl https_allow_http` (not “invalid parameter”)  
- [ ] `ss`: LISTEN only on `127.0.0.1:8080` (no steered ports; no required `:8443`)  
- [ ] `curl http://127.0.0.1:18081/` → `OpenResty M1 OK` `scheme=http` `waf_external_port=18081`  
- [ ] `curl -sk https://127.0.0.1:18081/` → same with `scheme=https`  
- [ ] Default response has **no** `X-Waf-External-Port`  
- [ ] Optional: `./scripts/accept-p1-a-dual.sh` exits 0  

---

## B. Stock OpenResty 1.19.3.2 fallback (not product)

Use when you only have the public image / stock prefix and need TLS handshake proof. **Does not** satisfy P1-A.

```bash
export CGO_ENABLED=0
# unset HAH product overrides
unset OPENRESTY_NGINX_CONF
# default helper uses openresty/nginx.conf + LOADER_TLS_PORTS=18443
export OPENRESTY_PREFIX=/usr/local/openresty   # or docker compose

make certs && make build
./run-openresty-demo.sh start
./run-openresty-demo.sh verify   # same-port HTTPS → N/A on stock (must not fail verify)

curl -sS -D- http://127.0.0.1:18081/
curl -sk -D- https://127.0.0.1:18443/   # steered → :8443 ssl

ss -lntp | grep -E ':(8080|8443|18081|18443)\b'
# Expect LISTEN on 8080 and 8443 only
./run-openresty-demo.sh stop
```

Loader shape:

```bash
sudo ./waf-sklookup-demo -mode openresty \
  -target 127.0.0.1:8080 -ports 18081,18082,65500 \
  -tls-target 127.0.0.1:8443 -tls-ports 18443
```

Details: [openresty-p1.md](openresty-p1.md) “Stock OpenResty 1.19.3.2”.

---

## C. M1 HTTP-only / toy (secondary)

### C.1 M1 OpenResty HTTP (no TLS requirement)

```bash
export CGO_ENABLED=0
export OPENRESTY_PREFIX=/usr/local/openresty   # stock OK for HTTP-only M1
make build
./run-openresty-demo.sh start
./run-openresty-demo.sh verify
./run-openresty-demo.sh close-port 18081
./run-openresty-demo.sh stop
```

See [openresty-m1.md](openresty-m1.md) and [acceptance-m1.md](acceptance-m1.md). Do not treat toy body as M1.

### C.2 Toy Go HTTP

```bash
export CGO_ENABLED=0
make build
sudo ./waf-sklookup-demo -mode toy -listen 127.0.0.1:18080 -ports 18081,18082,65500
# curl :18080/:18081 → "sk_lookup demo OK"
# ss: LISTEN only on :18080
```

---

## Loader flags (quick ref)

| Flag | Default | Notes |
|------|---------|-------|
| `-mode` | `toy` | `openresty`, `close-port`, `open-port`, `dump-ports` |
| `-target` | `127.0.0.1:8080` | Sockmap slot 0 |
| `-ports` | `18081,18082,65500` | → slot 0 |
| `-tls-target` / `-tls-ports` | `127.0.0.1:8443` / empty | **Stock fallback only**; leave `-tls-ports` empty for HAH/product |
| `-pin-dir` | `/sys/fs/bpf/waf-sklookup` | Pinned maps |

Helper env: `OPENRESTY_PREFIX`, `OPENRESTY_NGINX_CONF`, `LOADER_TLS_PORTS` (empty string skips TLS fallback), `WAF_EXPOSE_EXTERNAL_PORT`.

---

## Scope / non-goals

- No production customer data, no production deploys; **Repo** owns GitHub push/merge.
- M2 control plane / M3 perf matrix: out of scope ([acceptance-m3.md](acceptance-m3.md)).
- Multi-worker reuseport sockmap: out of scope.
- Design context: [design-thin-accept-openresty.md](design-thin-accept-openresty.md).
