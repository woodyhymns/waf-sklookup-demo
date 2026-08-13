# Rust loader — M3 shared-machine ladder + Go vs Rust table (R1–R3)

**Status:** first-cut Rust **userspace** loader. Hot path is unchanged C BPF (`dispatch.bpf.c` / `sk_lookup`). Go `./waf-sklookup-demo` stays the default and rollback. **Do not** treat this rewrite as a QPS miracle or a G2-rel fix.

Kernel `sk_lookup` is the same object both loaders attach. Userspace choice cannot change dataplane tax except via attach/pin/SOCKMAP bugs.

---

## 0. What Test re-runs (copy-paste)

The shared-machine default is 100 → 1K → 10K, with each tier closed before the next. Only `LOADER_BIN` changes. The historical 30K/60K ladder requires explicit `M3_FULL_LADDER=1` and a dedicated host.

**Go (rollback, still the default):**

```bash
export CGO_ENABLED=0
# stock: OPENRESTY_PREFIX=/usr/local/openresty
# HAH:   OPENRESTY_PREFIX=/usr/local/openresty-hah
unset LOADER_BIN    # or: export LOADER_BIN=./waf-sklookup-demo
./scripts/accept-prod-p1-map-bytes.sh
# Dedicated host only:
M3_FULL_LADDER=1 ./scripts/accept-prod-p1-map-bytes.sh
# The script prints bpftool/RSS samples during each tier, then fully cleans up.
```

**Rust (experimental dual-binary):**

```bash
export CGO_ENABLED=0
# rustc 1.85+ (see rust/loader/rust-toolchain.toml). clang + libelf-dev + zlib1g-dev.
make rust-loader
export LOADER_BIN=./rust/loader/target/release/waf-sklookup-loader
# stock: OPENRESTY_PREFIX=/usr/local/openresty
# HAH:   OPENRESTY_PREFIX=/usr/local/openresty-hah
./scripts/accept-prod-p1-map-bytes.sh
# Dedicated host only:
M3_FULL_LADDER=1 ./scripts/accept-prod-p1-map-bytes.sh
# The script prints bpftool/RSS samples during each tier, then fully cleans up.
```

Also keep M1/P1 `./run-openresty-demo.sh verify` and M2 `add` / `remove` / `list` with the same `LOADER_BIN`.

**Pass means:** functional steering + map fill + the table in §2 filled. It does **not** mean Rust QPS ≥ Go QPS. Record QPS; do not gate on it.

**Rollback:** restart the loader once so pins match the Go object (OpenResty need not reload):

```bash
export LOADER_BIN=./waf-sklookup-demo
./run-openresty-demo.sh stop    # stop helper; or kill only the loader PID
./run-openresty-demo.sh start
```

Do not run two loaders in the same netns (double `sk_lookup`). Ignore leftover bpftool map IDs from old 1024-entry objects.

---

## 1. Isolated BPF tax — absolute A vs B (not G2 keepalive rel)

G2 on HAH used **keepalive** HTTP and a **relative** gate `p99_B / p99_A ≤ 1.05`. That rel failed (~1.29) while **absolute** `|p99_B − p99_A|` was ~2.7 ms (≤ 10 ms). Rel-on-keepalive is **not** a path conclusion and **not** what this loader PR is for. Rust cannot fix a kernel-SYN tax; both loaders attach the same `dispatch.bpf.c`.

Measure **isolated** steering tax as **absolute milliseconds**, short connections, same OpenResty worker:

| Leg | Where | What it includes |
|-----|--------|------------------|
| **A** | `http://127.0.0.1:8080/` | Direct internal listen (no `open_ports` hit; sk_lookup returns `SK_PASS`) |
| **B** | `http://127.0.0.1:18081/` (or another steered port) | SYN-time `sk_lookup` + sockmap assign into the same listen |

```bash
# Loader + OpenResty already up (Go or Rust LOADER_BIN). Prefer Connection: close.
# tools/httpbench if present; curl is enough for a functional abs check.

# A — direct
curl -sS -o /dev/null -w 'A http_code=%{http_code} time_namelookup=%{time_namelookup} time_connect=%{time_connect} time_total=%{time_total}\n' \
  http://127.0.0.1:8080/

# B — steered (must be in open_ports; default demo port 18081)
curl -sS -o /dev/null -w 'B http_code=%{http_code} time_namelookup=%{time_namelookup} time_connect=%{time_connect} time_total=%{time_total}\n' \
  http://127.0.0.1:18081/

# Optional: N closed-connection samples, report p50/p99 of time_connect and time_total (ms).
# abs_tax_ms = |p99_total_B − p99_total_A|   (and same for connect)
# Do NOT convert that into a keepalive relative ratio and treat it as a merge gate.
```

If using `tools/httpbench`, keep **A and B on the same machine**, same `c`, same duration, **no keepalive** (or state it explicitly if you use keepalive). Fill:

| Loader | proto | n | p99_A_ms | p99_B_ms | abs_diff_ms | notes |
|--------|-------|---|----------|----------|-------------|-------|
| Go | HTTP close | | | | | |
| Rust | HTTP close | | | | | |

Expect: abs tax is **small and similar for Go vs Rust** (same BPF). If Rust B fails while A works, that is a **loader** bug (SOCKMAP FD dropped, pin mismatch, wrong key width). If both loaders show the same ~ms abs tax, that is kernel `sk_lookup`, not userspace.

---

## 2. Go vs Rust RSS / functional table (fill at R3)

How to measure (same as M3):

```bash
ps -o pid,rss,comm -p <loader_pid>,<openresty_worker_pids>
sudo bpftool map show name open_ports
# fill elapsed is the bulk-fill stdout line: added n=30000 ... elapsed=...
```

Go baseline already recorded at M2 tip (`a01b5b2` / `09d138b`) on HAH:

| Ladder | Loader | ports_have | loader RSS kB | OpenResty RSS kB | open_ports max_entries / memlock | fill elapsed | QPS (record only) | CPU | probe :34999 | Result |
|--------|--------|------------|---------------|------------------|----------------------------------|--------------|-------------------|-----|--------------|--------|
| baseline (≤10 ports) | Go | 1 | 7024 | 9916 | 131072 / ~10487488 B | — | ~102 | ~0 | — | PASS (`09d138b`) |
| 30K | Go | 30000 | 7024 | 10780 | same | 8 ms | ~100 | ~0 | — | PASS |
| 60K | Go | 60000 | 7024 | 10784 | same | 16 ms | ~85 | ~0 | HTTP 200 | PASS |
| baseline | Rust | | | | | | | | | |
| 30K | Rust | | | | | | | | | |
| 60K | Rust | | | | | | | | | |

Expect: kernel memlock **does not** grow 30K→60K (map is precharged at 131072). Userspace RSS should stay roughly flat like Go. If Rust RSS climbs linearly with port count, that is a **userspace bug** (holding the 60K `Vec<u16>` after the syscall).

This PR may leave HAH OpenResty Rust rows blank when the box is not the demo host; Test fills them there.

### Cloud VM smoke (this PR, toy mode — not HAH OpenResty)

Kernel `6.12.94+`, `bpffs` mounted, no OpenResty on the agent VM. Rust toy loader attached `sk_lookup`, pinned `/sys/fs/bpf/waf-sklookup`, steered curls, bulk fill:

| Ladder | Loader | ports_have | fill elapsed | method | probe | userspace LISTEN on steered ports | Result |
|--------|--------|------------|--------------|--------|-------|-----------------------------------|--------|
| toy + 30K | Rust | 30000 | 4 ms | batch | `:34999` HTTP 200 | only `:18080` | PASS (this VM) |
| toy + 60K | Rust | 60000 | 8 ms | batch | `:34999` HTTP 200 | only `:18080` | PASS (this VM) |

This is **functional + control-plane** evidence, not the HAH RSS table and not a QPS comparison.


---

## 3. Build notes

```bash
# Debian/Ubuntu extras on top of the Go demo deps
sudo apt-get install -y clang llvm libelf-dev zlib1g-dev pkg-config
# rustup toolchain 1.85+ (rust/loader/rust-toolchain.toml)
make rust-loader
make rust-loader-test    # no kernel; portspec/fill/ctl parsing
```

`make build` stays Go-only. Do not make `make build` depend on Cargo.
