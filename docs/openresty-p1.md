# P1: TLS in OpenResty + hide `X-Waf-External-Port`

Productization on top of [M1](openresty-m1.md): steered external ports still reach a **fixed internal listen** via `sk_lookup`. TLS is terminated **only** in OpenResty. Protocol (plaintext HTTP vs TLS) is **not** a sk_lookup concern.

## Dual-protocol test cases (explicit)

| Case | What | Engine | Commands |
|------|------|--------|----------|
| **Same external port, both protocols** | Product. One steered port, `http://` and `https://` both succeed. sk_lookup does not split. | **Requires Tengine `https_allow_http`** | `curl -sS http://127.0.0.1:18081/` and `curl -sk https://127.0.0.1:18081/` |
| **Stock TLS handshake** | Fallback only: different internal listen `8443 ssl`, steered `18443`. **Not** the product model. | stock `openresty/1.19.3.2` | `curl -sk https://127.0.0.1:18443/` |

`./run-openresty-demo.sh verify` always probes the **same-port** HTTPS case. On stock 1.19.3.2 that probe is **N/A** (expected). On Tengine it must **PASS**. QA list: [acceptance-p1.md](acceptance-p1.md).

## Product architecture (Tengine)

Production OpenResty incorporates Tengine’s **`https_allow_http`**: **each nginx listen can accept both cleartext HTTP and HTTPS**. Discrimination happens in the engine, on that listen.

Verified listen syntax ([Tengine 3.1.0](https://github.com/alibaba/tengine/releases/tag/3.1.0), [alibaba/tengine#1751](https://github.com/alibaba/tengine/issues/1751)) — a **listen flag**, not `https_allow_http on;`:

```nginx
listen 127.0.0.1:8080 ssl https_allow_http;
```

```
Client :18081  (http:// or https://)
        |
        v  sk_lookup  (open_ports → redir_socket[0] only)
OpenResty/Tengine listen 127.0.0.1:8080 ssl https_allow_http
        |  engine peeks TLS ClientHello vs HTTP
        access_by_lua → $waf_external_port
```

Loader flags on Tengine: **`-ports` + `-target` only**. Do not use `-tls-ports`. Every external port maps to the same internal socket. HTTP vs TLS is not encoded in BPF.

Runnable snippet: [`openresty/nginx.tengine-https-allow-http.conf.example`](../openresty/nginx.tengine-https-allow-http.conf.example).

### Tengine test plan (not runnable on stock 1.19.3.2)

On a Tengine 3.1.0+ (or production OpenResty that includes this listen option):

```bash
# Config: listen 127.0.0.1:8080 ssl https_allow_http;  (example file)
# Loader: sudo ./rust/loader/target/release/waf-sklookup-loader -mode openresty -target 127.0.0.1:8080 -ports 18081,18082,65500
#         (no -tls-ports)

ss -lntp | grep -E ':(8080|18081)\b'   # only 127.0.0.1:8080

curl -sS http://127.0.0.1:18081/       # plaintext on the steered port
curl -sk https://127.0.0.1:18081/      # TLS on the SAME steered port (-k: demo cert)

# Both: body OpenResty M1 OK, waf_external_port=18081, scheme=http vs https
# Default: no X-Waf-External-Port header
# access_log: waf_external_port=18081 scheme=http|https
```

Expect `nginx -t` to accept `https_allow_http`. On stock OpenResty 1.19.3.2 the same line fails (see below).

## Stock OpenResty 1.19.3.2 — what this demo actually runs

Image: **`openresty/openresty:1.19.3.2-bionic`**. Differences vs production:

| Topic | Production (Tengine `https_allow_http`) | This demo (stock 1.19.3.2) |
|-------|------------------------------------------|----------------------------|
| Internal listen | **One** listen, HTTP + TLS | **Two** listens: `127.0.0.1:8080` (HTTP) and `127.0.0.1:8443 ssl` (TLS) |
| Who splits protocols | Engine on the listen | Demo helper / loader **fallback** (`-tls-ports` → 8443) |
| `https_allow_http` | Required | **Unknown parameter** — must not appear in the live `nginx.conf` |
| sk_lookup | All `-ports` → slot 0 | `-ports` → slot 0 (8080); optional `-tls-ports` → slot 1 (8443) |
| TLS | Terminated on the one listen | Terminated on 8443 only (still OpenResty, self-signed demo cert) |

The dual-listen / `-tls-ports` path is a **labeled stock-compat fallback**, not the product model. It exists so this repo can still show TLS handshake + `$waf_external_port` on the public 1.19.3.2 image.

Stock nginx can return **497** (“plain HTTP sent to HTTPS port”) on an `ssl` listen; that is **not** dual-protocol service. `error_page 497` redirects; it does not serve HTTP. stream `ssl_preread` would add a hop and break `$waf_external_port` (getsockname would see the inner connection). Neither is used here.

## Headers

| Surface | Default | `WAF_EXPOSE_EXTERNAL_PORT=1` |
|---------|---------|------------------------------|
| `X-Waf-External-Port` | **omitted** | set to `$waf_external_port` |
| `X-Waf-Internal-Port` | omitted | set to `$server_port` |
| Response body `waf_external_port=` | present (demo) | present |
| access_log `$waf_external_port` | **always** | always |

nginx clears the environment unless declared: `env WAF_EXPOSE_EXTERNAL_PORT;` in `openresty/nginx.conf`. Alternative: `set $waf_expose_external_port 1;` in the server block (no restart of the *loader*, but still an OpenResty reload).

`$waf_external_port` is still filled in `access_by_lua` (same M1 Lua). Do **not** use `$server_port` as the business port.

## Reproduce (stock 1.19.3.2)

```bash
export CGO_ENABLED=0
make certs          # demo-only self-signed certs under openresty/certs/ (gitignored keys)
make build && make test

# OpenResty 1.19.3.2 — pick one:
docker compose -f openresty/docker-compose.yml up -d   # after make certs
# or: OPENRESTY_PREFIX=/usr/local/openresty

./run-openresty-demo.sh start
./run-openresty-demo.sh verify
```

Manual loader (stock fallback TLS port enabled):

```bash
sudo ./rust/loader/target/release/waf-sklookup-loader -mode openresty \
  -target 127.0.0.1:8080 -ports 18081,18082,65500 \
  -tls-target 127.0.0.1:8443 -tls-ports 18443
```

Product-shaped loader (Tengine, or HTTP-only on stock):

```bash
sudo ./rust/loader/target/release/waf-sklookup-loader -mode openresty \
  -target 127.0.0.1:8080 -ports 18081,18082,65500
# no -tls-ports
```

### HTTP

```bash
curl -sS -D- http://127.0.0.1:8080/     # internal
curl -sS -D- http://127.0.0.1:18081/    # steered — no userspace bind
# Expect: OpenResty M1 OK, waf_external_port=18081, NO X-Waf-External-Port
```

### HTTPS (stock fallback; `-k` because the cert is self-signed)

```bash
curl -sk -D- https://127.0.0.1:8443/    # internal TLS listen
curl -sk -D- https://127.0.0.1:18443/   # steered → 8443
# Expect: OpenResty M1 OK, scheme=https, waf_external_port=18443, NO X-Waf-External-Port
```

### Expose debug header

```bash
WAF_EXPOSE_EXTERNAL_PORT=1 ./run-openresty-demo.sh stop
WAF_EXPOSE_EXTERNAL_PORT=1 ./run-openresty-demo.sh start
curl -sS -D- http://127.0.0.1:18081/ | grep -i X-Waf-External-Port
# X-Waf-External-Port: 18081
```

### Bind proof

```bash
ss -lntp | grep -E ':(8080|8443|18081|18082|65500|18443)\b'
# Stock fallback: LISTEN on 127.0.0.1:8080 and 127.0.0.1:8443 only.
# Tengine product: LISTEN on the single https_allow_http port only.
```

### Map open/close (P1.5)

```bash
./run-openresty-demo.sh close-port 18081
curl -sS --max-time 3 http://127.0.0.1:18081/   # expect fail
./run-openresty-demo.sh open-port 18081
curl -sS http://127.0.0.1:18081/                # back

./run-openresty-demo.sh close-port 18443 --tls
./run-openresty-demo.sh open-port 18443 --tls
./run-openresty-demo.sh dump-ports
```

`close-port` on a missing key is OK (already closed). `open-port` / `close-port` only touch ports you pass; they do **not** apply the default `-ports` list.

## Loader flags

| Flag | Default | Role |
|------|---------|------|
| `-mode` | `toy` | `toy`, `openresty`, `close-port`, `open-port`, `dump-ports` |
| `-target` | `127.0.0.1:8080` | Primary internal listen (sockmap slot 0) |
| `-ports` | `18081,18082,65500` | Steered ports → slot 0 |
| `-tls-target` | `127.0.0.1:8443` | **Stock fallback** TLS listen (slot 1) |
| `-tls-ports` | empty | **Stock fallback** steered ports → slot 1. Empty = product path |
| `-wait` | `60s` | Wait for listen socket(s) |
| `-pin-dir` | `/sys/fs/bpf/waf-sklookup` | Pinned maps |

Toy mode is unchanged (`-mode toy`). It rejects `-tls-ports`.

## Demo constraints

- `CGO_ENABLED=0`
- `worker_processes 1` (documented; multi-worker reuseport sockmap is out of scope)
- No userspace bind on external ports
- Demo certs: `make certs` → `openresty/certs/demo.{crt,key}` (keys gitignored, labeled demo-only)
- Compatible with stock OpenResty **1.19.3.2** config + standard Lua only (no private nginx modules). `https_allow_http` is Tengine-only and lives in the example file, not the live conf.
- **Rust is the userspace loader.** The C BPF dataplane and P1 protocol model are unchanged.

## Out of scope

- Running Tengine in this repo’s default helper (no Tengine image pinned here)
- M2 control plane / M3 perf matrix
- Multi-worker reuseport sockmap
- Production certificates / SNI matrix

## Patched OpenResty 1.19.3.2 (`https_allow_http`)

Stock image cannot parse the listen flag. A durable port of Tengine’s feature lives in
[`third_party/https_allow_http/`](../third_party/https_allow_http/) (patch + build script).

```bash
./third_party/https_allow_http/build-openresty-hah.sh
export OPENRESTY_PREFIX=/usr/local/openresty-hah   # separate from stock /usr/local/openresty
$OPENRESTY_PREFIX/bin/openresty -V
# smoke conf uses: listen 127.0.0.1:8443 ssl https_allow_http;
```

On this build, same-port HTTP + HTTPS both return 200 (no 497). Use the product loader
shape (`-ports` + `-target` only; no `-tls-ports`) with
`openresty/nginx.tengine-https-allow-http.conf.example`.
