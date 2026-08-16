# waf-sklookup-demo

Minimal demo: **one** userspace `listen()`, many extra TCP ports opened only via Linux BPF **`sk_lookup`** (no `bind`/`listen` on those ports).

Useful as a building block for WAF / OpenResty-style **runtime dynamic non-standard listen ports** on kernels that support `sk_lookup` (Linux ≥ 5.9; HCE 2.0 / kernel 5.10 qualifies).

**M1:** steer those ports into **OpenResty 1.19.3.2** on a fixed internal listen (`127.0.0.1:8080`) and record the client destination as **`$waf_external_port`**. **P1:** TLS is terminated only in OpenResty; production uses Tengine **`https_allow_http`** so **one listen accepts both HTTP and TLS**. Stock 1.19.3.2 cannot do that — the demo’s second listen (`:8443 ssl`) is a labeled fallback. Default responses **omit** `X-Waf-External-Port` (enable with `WAF_EXPOSE_EXTERNAL_PORT=1`). Toy HTTP remains `-mode toy`. **M2:** hot add/remove/list/bulk against the pinned `open_ports` map (no OpenResty reload); bulk fill is the M3 30K/60K seed path.

## 10-minute quick start (toy HTTP)

```bash
# 0) Host check (must be a real Linux with sk_lookup — not macOS / most CI sandboxes)
uname -r                                          # need ≥ 5.9 (5.10+ preferred)
bpftool feature 2>/dev/null | grep -i sk_lookup   # optional; expect sk_lookup support

# 1) Deps (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y rustc cargo clang llvm libbpf-dev libelf-dev linux-libc-dev
# optional: linux-tools-common / linux-tools-$(uname -r) for bpftool

# 2) Build & run (needs root for BPF attach)
git clone https://github.com/woodyhymns/waf-sklookup-demo.git
cd waf-sklookup-demo
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

**M1 acceptance:** [docs/acceptance-m1.md](docs/acceptance-m1.md). Design: [docs/openresty-m1.md](docs/openresty-m1.md). **P1:** [docs/openresty-p1.md](docs/openresty-p1.md). **M2 control plane:** [docs/openresty-m2.md](docs/openresty-m2.md).

OpenResty binds **fixed internal listens** only. The loader registers those listen FDs into the sockmap and opens extra ports in BPF. Do **not** use `$server_port` as the business/external port (after `sk_lookup` it is often `8080` / `8443`). Use **`$waf_external_port`**.

**Product (Tengine):** one listen, both protocols — `listen 127.0.0.1:8080 ssl https_allow_http;` — sk_lookup does not classify HTTP vs TLS. Snippet: [`openresty/nginx.tengine-https-allow-http.conf.example`](openresty/nginx.tengine-https-allow-http.conf.example). **Same steered port:** `curl http://127.0.0.1:18081/` **and** `curl -k https://127.0.0.1:18081/` — this pair **requires** `https_allow_http` (N/A on the stock 1.19.3.2 image).

**Stock demo (`openresty/openresty:1.19.3.2-bionic`):** that listen flag is **invalid**. Fallback (not the product model): `127.0.0.1:8080` HTTP + `127.0.0.1:8443 ssl`, with `-tls-ports` steered to 8443. P1 checklist: [docs/acceptance-p1.md](docs/acceptance-p1.md).

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
#   # HAH (https_allow_http): OPENRESTY_PREFIX=/usr/local/openresty-hah
./run-openresty-demo.sh start
./run-openresty-demo.sh verify          # HTTP + stock HTTPS fallback; header hidden
curl -sS -D- http://127.0.0.1:18081/   # no X-Waf-External-Port by default
curl -sk -D- https://127.0.0.1:18443/  # steered TLS (stock fallback; -k = self-signed)
./run-openresty-demo.sh remove 18081    # M2: hot-close, no OpenResty reload
./run-openresty-demo.sh add 18081
./run-openresty-demo.sh stop

# Debug header (restart OpenResty so nginx env is picked up):
WAF_EXPOSE_EXTERNAL_PORT=1 ./run-openresty-demo.sh start
```

QA fills the checkboxes in **[docs/acceptance-m1.md](docs/acceptance-m1.md)** after running the PR; do not treat toy HTTP (`make run-toy`) as M1.

## Idea

```
Client → :18081 / :18082 / :65500  ──sk_lookup──►  fixed internal listen(s)
         toy: Rust HTTP on :18080
         product (Tengine): OpenResty 127.0.0.1:8080 ssl https_allow_http  (HTTP+TLS)
         stock 1.19.3.2 fallback: 127.0.0.1:8080 HTTP + 127.0.0.1:8443 ssl
```

- Real bind: toy `:18080`, or OpenResty `:8080` (and stock fallback `:8443`)
- Steered ports (default): `18081`, `18082`, `65500` → primary listen; stock TLS demo also steers `18443` → `:8443`
- Removing a map entry closes that external port without touching nginx/OpenResty config

## M2: port control plane

The product control plane is JSON-lines over `/run/waf-sklookup/ctl.sock`, not HTTP or TCP. The Unix socket is mode `0660`; filesystem ownership plus Linux `SO_PEERCRED` restrict calls to root, the socket owner, or its group. Every mutation is serialized and audited to stderr with uid/gid/pid, operation, compact ports, and success. Override it with `-ctl-sock PATH` or `CTL_SOCK`, set group ownership with `-ctl-group GID`, or disable it with `-no-ctl` (or an empty path).

```bash
./rust/loader/target/release/waf-sklookup-loader ctl list
./rust/loader/target/release/waf-sklookup-loader ctl add 18083
./rust/loader/target/release/waf-sklookup-loader ctl remove 18083
./rust/loader/target/release/waf-sklookup-loader ctl reconcile
```

The top-level `add`/`remove`/`list`/`bulk`/`reconcile` commands directly open pinned maps and remain a root operations escape hatch, not the product API. Add/bulk/fill operations above 10,000 ports require `M3_FULL_LADDER=1` or explicit `-full-ladder` (socket JSON: `full_ladder: true`).

`ports.conf` at the repository root is the source of truth for `open_ports`. Each non-comment line is a port, comma list, or `START-END`; append `tls` to select the stock TLS-fallback slot (for example, `18443 tls`). Blank lines and `#` comments are ignored. Override the path with `-ports-file PATH` (or `PORTS_FILE` in the demo wrapper).

At startup the loader reconciles the map exactly to this file. If the file is missing, `-ports`/`-tls-ports` remain backward-compatible inputs and seed it. While the loader is up (maps pinned), `reconcile`/`apply` re-reads the file without reloading OpenResty or re-attaching `sk_lookup`; sending the loader `SIGHUP` does the same. Add/remove/bulk commands rewrite the desired file as well as updating the live map. Pass `-no-file` to overlay the live map only (stop/hygiene and M3 fill helpers do this so they cannot empty `ports.conf`).

```bash
sudo ./rust/loader/target/release/waf-sklookup-loader add 18083
sudo ./rust/loader/target/release/waf-sklookup-loader remove 18083
sudo ./rust/loader/target/release/waf-sklookup-loader list
sudo ./rust/loader/target/release/waf-sklookup-loader reconcile
sudo ./rust/loader/target/release/waf-sklookup-loader bulk open  -range 5000-34999
sudo ./rust/loader/target/release/waf-sklookup-loader bulk close -range 5000-34999
M3_FULL_LADDER=1 sudo ./rust/loader/target/release/waf-sklookup-loader bulk fill -count 30000 -start 5000
./scripts/m3-fill-ports.sh 60000                               # M3 60K seed
```

Details, file/stdin input, map ceiling (**131072**, ~8–16 MB memlock), and HAH/`OPENRESTY_PREFIX` notes: [docs/openresty-m2.md](docs/openresty-m2.md). The Rust userspace loader is the default; the C BPF program is unchanged. Design history: [docs/rust-loader-plan.md](docs/rust-loader-plan.md) · Test recipe: [docs/acceptance-m3-rust.md](docs/acceptance-m3-rust.md).

## Rust userspace loader

Rust is the default userspace loader. Its dataplane defaults to the C BPF
(`dispatch.bpf.c`); select the source-equivalent Rust BPF twin with `-bpf rust`
or `BPF_IMPL=rust`. This is a **source-language comparison**, not a QPS promise
or performance claim. Isolated steering tax is an **absolute** A vs B delta
(direct `:8080` vs steered port), not a G2 keepalive relative ratio. See
[`docs/rust-bpf.md`](docs/rust-bpf.md) for the shared ABI and build steps.

Optional Rust BPF object: `./scripts/setup-build.sh && make rust-bpf` (see [`docs/rust-bpf.md`](docs/rust-bpf.md)).

```bash
make build
./run-openresty-demo.sh start
./scripts/m3-fill-ports.sh 100
./scripts/m3-fill-ports.sh 1000
./scripts/m3-fill-ports.sh 10000
```

`LOADER_BIN` remains overridable. Details: [docs/acceptance-m3-rust.md](docs/acceptance-m3-rust.md).


## Requirements

| Need | Notes |
|------|--------|
| Linux + `sk_lookup` | Kernel ≥ 5.9; HCE 2.0 / 5.10 OK. Confirm with `uname -r` / `bpftool feature` |
| Privileges | Root, or `CAP_BPF` + `CAP_NET_ADMIN` (and usually ability to attach to current netns) |
| Build tools | rustc **1.85+**, Cargo, clang, libbpf/libelf development packages, and Linux headers. Go **1.22+** is optional and only builds `tools/httpbench`. |
| OpenResty (M1) | **1.19.3.2** — `openresty/openresty:1.19.3.2-bionic` or a local prefix |
| Network | Demo listens on **loopback**; run on a host/VM where BPF attach is allowed |

```bash
# Debian/Ubuntu example
sudo apt-get install -y rustc cargo clang llvm libbpf-dev libelf-dev linux-libc-dev
```

`./run.sh` runs a release Cargo build, then uses `sudo` to start the Rust toy binary.

## systemd deployment

Exception recovery (loader/OpenResty/worker-respawn, wiped pins, missing ctl.sock, map≠file, boot order, StartLimit): [docs/recovery.md](docs/recovery.md) / `./scripts/recover.sh`.

Example foreground OpenResty and loader units, their fail-closed restart policy, environment overrides, and operator-only installation steps are documented in [docs/systemd.md](docs/systemd.md). Run `scripts/check-install.sh` before starting them. Do not enable these services on shared demo VMs.

## Flags

```bash
# Toy (default)
sudo ./rust/loader/target/release/waf-sklookup-loader -mode toy -listen 127.0.0.1:18080 -ports 18081,18082,65500

# OpenResty — product-shaped (all ports → one listen; Tengine https_allow_http)
sudo ./rust/loader/target/release/waf-sklookup-loader -mode openresty -target 127.0.0.1:8080 -ports 18081,18082,65500

# OpenResty — stock 1.19.3.2 TLS fallback (NOT the product model)
sudo ./rust/loader/target/release/waf-sklookup-loader -mode openresty \
  -target 127.0.0.1:8080 -ports 18081,18082,65500 \
  -tls-target 127.0.0.1:8443 -tls-ports 18443

# Drop / re-open a steered port (loader must still be running; maps pinned)
sudo ./rust/loader/target/release/waf-sklookup-loader add 18081
sudo ./rust/loader/target/release/waf-sklookup-loader remove 18081
sudo ./rust/loader/target/release/waf-sklookup-loader list
# legacy: -mode close-port | open-port | dump-ports
```

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `load BPF` / `attach sk_lookup` fails | Not root / missing caps; kernel too old; sk_lookup disabled; restricted container |
| Cargo/libbpf build fails | Missing clang, libbpf/libelf development files, or kernel headers (`linux-libc-dev`) |
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
| `rust/loader/` | Default Rust userspace loader (`waf-sklookup-loader`, libbpf-rs). Loads the same C BPF program and provides toy, OpenResty, and M2 control-plane modes. |
| `docs/rust-loader-plan.md` | Loader-only rewrite plan (R0) + what this crate implements |
| `docs/acceptance-m3-rust.md` | Test recipe: M3 30K/60K via `LOADER_BIN`, isolated abs A vs B tax, Go vs Rust table |
| `scripts/m3-fill-ports.sh` | M3 helper: `bulk fill` 30K or 60K into pinned `open_ports` |
| `openresty/` | OpenResty 1.19.3.2 config + Lua for `$waf_external_port`; Tengine example listen |
| `openresty/certs/` | `make certs` demo-only self-signed material (keys gitignored) |
| `run-openresty-demo.sh` | Start/verify/stop OpenResty demo (HTTP + stock TLS fallback) |
| `deploy/systemd/`, `docs/systemd.md` | Operator systemd units, environment examples, fail-closed policy, and installation guide |
| `scripts/check-install.sh` | Read-only kernel, BPF, bpffs, privilege, loader, and OpenResty installation checks |
| `docs/openresty-m1.md` | M1 HTTP wiring |
| `docs/openresty-m2.md` | M2 control plane: add/remove/list/bulk, M3 seed |
| `docs/openresty-p1.md` | P1 TLS product model, stock vs Tengine, header flag |
| `docs/acceptance-p1.md` | P1 QA: same-port dual protocol (Tengine) vs stock TLS fallback |
| `docs/acceptance-m1.md` | QA checklist (M1-1…M1-5 required) |
| `docs/acceptance-m2.md` | M2 QA: add/remove/list/bulk + 30K/60K fill |
| `docs/acceptance-m3.md` | M3 stub (30K/60K memory ladder); seed via M2 bulk fill |
| `docs/design-thin-accept-openresty.md` | Transition design: PROXY v2 + thin-accept + OpenResty TLS |
| `docs/perf-deep-compare.md` | Reload / PROXY / TPROXY / sk_lookup performance comparison |
| `docs/waf-dynamic-port-sk-lookup-review-zh-CN.md` | 完整中文技术评审：可行性、性能、可观测性、风险分级与落地路线 |
| `docs/waf-dynamic-port-sk-lookup-review-en.md` | Full English technical review: feasibility, performance, observability, risks, and rollout |
| `docs/waf-dynamic-port-action-items-zh-CN.md` | 按优先级可直接拆分的整改行动清单 |
| `docs/production-hardening-fix-progress.md` | 本轮生产硬化修复、真实内核验证、性能结论与剩余 staging 门禁 |
| `docs/acceptance-real-kernel-hardening-2026-08-16.md` | 可提交、可审计的真实内核验收记录 |

## Relation to the WAF plan

- **End state:** BPF sk_lookup → OpenResty (TLS + Lua WAF), with Tengine `https_allow_http` so one listen takes HTTP and TLS. Toy mode is the kernel steering proof; M1 is HTTP wiring; P1 adds TLS + header policy; M2 is the Rust control plane. The C BPF hot path remains unchanged.
- **Transition:** PROXY + thin-accept (see `docs/`). Product semantics first; switch data plane when perf gates pass.
- Design notes live in `docs/`; the Notion summary page links this repo as the runnable demo.

## Not production

This is a **kernel steering proof + M1/P1 wiring + M2 control plane**, not a full WAF integration. It now includes a 64-shard-per-group `SO_REUSEPORT` sockmap model, IPv4/IPv6 destination-family keys, pidfd-backed worker ownership checks, pinned program/link identity validation, Prometheus metrics, and a configurable worker rescan interval (`-rescan-interval`, default `500ms`, minimum `100ms`).

Still out of scope here:

- M3 production hardware performance matrix ([docs/acceptance-m3.md](docs/acceptance-m3.md) stub; use `tests/e2e/bench-sklookup.sh` for reproducible real-kernel A/B sampling)
- HTTP control-plane API (CLI bulk is the M3 contract)
- Tengine runtime in the default helper (example conf + test plan only)
- Full OpenResty WAF policy integration and production TLS/certificate lifecycle

> The loader detects an unclean worker exit during its configured rescan window. Operators should choose `200–500ms` after measuring `/proc` scan cost at their worker count, or send `SIGUSR1` from the WAF worker lifecycle hook for immediate reconciliation.

## License

Demo code: GPL-2.0 for the BPF program (required by helpers); the Rust userspace loader has the license declared in `rust/loader/Cargo.toml`. Review and align all licensing before shipping product code.
