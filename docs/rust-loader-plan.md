# Rust userspace loader rewrite — plan (R0)

**Status (implementation PR):** first-cut **userspace loader** (R1–R3). Copied from planning-only [PR #8](https://github.com/woodyhymns/waf-sklookup-demo/pull/8) — **do not merge #8**. Hot path stays **C BPF** (`dispatch.bpf.c`). Go (`./waf-sklookup-demo`) remains the **default and rollback**. Rust is experimental (`LOADER_BIN`); it is **not** a QPS/P99 claim versus Go.

Crate: `rust/loader/` binary `waf-sklookup-loader`. Acceptance recipes: [acceptance-m3-rust.md](acceptance-m3-rust.md).

The original R0 text follows (planning notes kept for history).

---


**Status:** planning only. This document is the R0 deliverable. Do **not** implement the Rust loader in the same change as this plan.

**Base:** `main` tip `09d138b` (M2/M3 landed: Go loader + C BPF, `open_ports` max_entries **131072**, bulk CLI, M3 30K/60K PASS).

**Recommended first-cut scope: loader-only.** Rust replaces the **userspace loader / control plane**. The hot path stays **C BPF** (`dispatch.bpf.c` / `sk_lookup`). Go (`loader.go`, `ctl.go`, `ports_bulk.go`) remains the **reference implementation and rollback** until a Rust ladder PASS.

Rust is for userspace engineering (memory safety, packaging, CLI). It is **not** a kernel datapath change and must **not** be sold as a QPS win. M3 already showed 30K/60K control-plane memory is healthy on Go; userspace RSS stayed flat (~7 MB) while the ~10.5 MB cost lives in the kernel hash map.

---

## 1. Scope

### 1.1 First cut (in)

Rewrite the **userspace** program that today lives in:

| File | Role to port |
|------|----------------|
| `loader.go` | Load C BPF object, attach `sk_lookup` to current netns, pin maps, toy HTTP listen **or** OpenResty sockmap registration, signal/unpin |
| `listen_fd.go` | Discover OpenResty LISTEN inode via `/proc/net/tcp`, `pidfd_getfd` dup into the loader |
| `ctl.go` | Second-process CLI: `add` / `remove` / `list` / `bulk` against the **pinned** `open_ports` map |
| `ports_bulk.go` | Batched map update/delete (default chunk 4096), BatchUpdate fallback to per-key |
| `portspec.go` | Port / range / file / stdin / `bulk fill` generation (skip `8080,8443`) |

Keep the **same** kernel contract:

- Program: `SEC("sk_lookup") int dispatch(...)` in `dispatch.bpf.c` (unchanged).
- Maps: `open_ports` (`HASH`, key `__u16`, value `__u8`, `max_entries` **131072**); `redir_socket` (`SOCKMAP`, max 2).
- Pin directory: `/sys/fs/bpf/waf-sklookup` (`open_ports`, `redir_socket`).
- Sockmap slots: `0` = primary / product listen; `1` = stock OpenResty 1.19.3.2 TLS fallback only.
- Demo helpers: `run-openresty-demo.sh`, `scripts/m3-fill-ports.sh`, `OPENRESTY_PREFIX` / HAH (`/usr/local/openresty-hah`).

### 1.2 Explicitly deferred (not this rewrite)

Do **not** expand the Rust surface in R1–R4:

| Deferred | Why |
|----------|-----|
| Rewrite `dispatch.bpf.c` in Rust (`aya-bpf` / `aya-ebpf`) | Hot path is C; M3/P0 evidence is on this object. Dual BPF sources would split pin/BTF/clang flags. |
| HTTP control-plane API | M2/M3 contract is CLI bulk (`docs/openresty-m2.md`). |
| OpenResty / Lua / `$waf_external_port` | Already in `openresty/`; loader only registers the listen FD. |
| Tengine runtime in the default helper | Example conf + HAH prefix only. |
| Multi-worker `reuseport` sockmap | Out of scope on Go today. |
| P0 perf matrix (CPS / P99 vs direct / PROXY) | After Rust **functional + M3 ladder** PASS, same as the Go sequence. |
| Packaging (`.deb`, systemd) beyond a static/release binary | Later. |
| IPv6 listen discovery | Go `listen_fd.go` is IPv4-only (`/proc/net/tcp`). |

### 1.3 Why loader-only first

The Go binary is two processes in one artifact: a long-running loader (attach + pin) and a short-lived ctl (pinned-map edits). That is the entire userspace surface that Test already runs through `run-openresty-demo.sh` and `scripts/m3-fill-ports.sh`. A larger Rust rewrite (BPF-in-Rust, HTTP API, new pin layout) would block the only acceptance that matters: **re-run the existing M3 ladder to PASS** with Go still available to roll back.

---

## 2. Library choice: libbpf-rs

**Pick: [libbpf-rs](https://docs.rs/libbpf-rs) + [libbpf-cargo](https://docs.rs/libbpf-cargo)** to consume the **existing C object**. Do not introduce a second BPF language.

### 2.1 Why libbpf-rs for *this* repo

The Go loader is `github.com/cilium/ebpf` loading a **clang-compiled** `dispatch.bpf.c` (bpf2go), then:

1. `link.AttachNetNs(netns_fd, prog)` — `sk_lookup` on `/proc/self/ns/net`.
2. `Map.Pin("/sys/fs/bpf/waf-sklookup/{open_ports,redir_socket}")`.
3. `RedirSocket.Put(slot, uint64(fd))` into a **SOCKMAP**.
4. Ctl process: `ebpf.LoadPinnedMap(.../open_ports)` with **no** re-attach.
5. M3: `BatchUpdate` / `BatchDelete` (chunk 4096) with per-key fallback.

libbpf-rs maps onto that surface without rewriting the BPF program:

| Repo need | libbpf-rs |
|-----------|-----------|
| Existing C BPF object | `libbpf-cargo` `SkeletonBuilder` compiles `dispatch.bpf.c` (same clang includes as bpf2go) |
| `sk_lookup` attach | `Program::attach_netns(netns_fd)` → `bpf_program__attach_netns` |
| Pin dir + bpftool | `ObjectBuilder::set_pin_root_path` / `Map::pin`; names stay `open_ports`, `redir_socket` |
| SOCKMAP listen FD | map update with the socket FD (same as Go `Put`) |
| Second-process ctl | `MapHandle` from pinned path (analog of `LoadPinnedMap`) |
| 30K/60K bulk | `update_batch` / `delete_batch` wrapping `bpf_map_*_batch`; fallback to per-key like `ports_bulk.go` |

bpftool operators already inspect this pin dir. Staying on libbpf pin/BTF layout avoids a second on-disk convention during the dual-binary period.

### 2.2 Why not aya for the first cut

[aya](https://docs.rs/aya) is a strong **cilium/ebpf analog** (pure Rust, `bpf()` syscalls, no `libbpf.so`). It has `programs::SkLookup::attach(netns)`, `maps::SockMap`, and `MapData::from_pin`. It can `Ebpf::load` a clang ELF.

It is the wrong *default* here:

- aya’s documented strength is **writing BPF in Rust**. That is explicitly out of scope; the C object stays.
- High-level **batch** update/delete (the M3 30K/60K path) is first-class in libbpf; aya users typically drop to the raw batch syscall.
- Pinned-map ctl without reloading the object is libbpf’s everyday API; aya’s typed `HashMap::from_map_data` path is newer and easy to get wrong (wrong key width / endianness vs `__u16` host-order ports).
- Go’s `CGO_ENABLED=0` packaging is a Go convenience, not a product gate. Rust can statically link libbpf if a shared `libbpf.so` is undesirable.

**Revisit aya** only if an R1 spike shows libbpf-rs cannot attach `sk_lookup` + update SOCKMAP + pin under `/sys/fs/bpf/waf-sklookup` on the demo kernel (≥ 5.9, HCE 5.10 qualifies). If that happens, load the **same** clang `.o` with aya — still no `aya-bpf` rewrite of `dispatch.bpf.c`.

### 2.3 Build: share the existing clang path

Today (`Makefile` / `loader.go`):

```text
go generate  →  bpf2go -no-strip -tags linux
  -cflags "-I/usr/include/x86_64-linux-gnu -I./bpf/headers"
  dispatch dispatch.bpf.c
go build -o waf-sklookup-demo .
```

Generated `dispatch_bpfel.go` / `.o` are **gitignored**. `CGO_ENABLED=0`.

Rust should **not** fork `dispatch.bpf.c`. Proposed `rust/loader/build.rs`:

- `SkeletonBuilder` (or equivalent clang invoke) on repo-root `dispatch.bpf.c`.
- Same include path: `-I/usr/include/$(uname -m)-linux-gnu -I../../bpf/headers` (this tree already vendors `bpf/headers/bpf_helpers.h`).
- Output a libbpf skeleton / `.o` under `OUT_DIR` (also gitignored).
- Keep `go generate` for the Go binary until R4.

Do not make `make build` (Go) depend on Cargo, or `cargo build` depend on `go generate`. Both compile the **same** `.c`. If clang flags drift, `open_ports` `max_entries` or BTF can diverge — add a unit check that the loaded map’s `max_entries == 131072` (Go already has `TestOpenPortsMaxEntries` against the bpf2go spec).

---

## 3. Layout

### 3.1 Proposed crate / directory

Docs-only in R0. Implement from R1:

```text
rust/loader/                    # Cargo package
  Cargo.toml                    # bin: waf-sklookup-loader
  build.rs                      # libbpf-cargo → ../../dispatch.bpf.c
  src/
    main.rs                     # flag/subcommand dispatch (clap)
    load.rs                     # load object, attach_netns, pin, unpin
    toy.rs                      # -mode toy: TCP listen + sockmap slot 0 + tiny HTTP
    openresty.rs                # wait for listen FD, register slot 0/1
    listen_fd.rs                # /proc/net/tcp + pidfd_open/pidfd_getfd
    pin.rs                      # default pin dir + map names
    ctl.rs                      # add/remove/list/bulk (pinned open_ports)
    ports.rs                    # portspec + fill (parity with portspec.go)
    bulk.rs                     # batch update/delete + fallback
```

Binary name: **`waf-sklookup-loader`** (distinct from Go `waf-sklookup-demo`) so both can sit in the repo root / `target/release` during the dual-binary period.

Keep Go sources at repo root. Do not move `loader.go`.

Optional later: `make rust-loader` → `cargo build --release --manifest-path rust/loader/Cargo.toml`. Add `/rust/loader/target/` (or workspace `target/`) to `.gitignore` when the crate lands.

### 3.2 Pin semantics (must match Go)

Verified in `loader.go` (`defaultPinDir`, `pinMaps`, `unpinMaps`):

| Item | Contract |
|------|----------|
| Directory | `/sys/fs/bpf/waf-sklookup` (override: `-pin-dir`) |
| Files | `open_ports`, `redir_socket` (not the program, not the link) |
| Create | `mkdir -p`; **unlink** existing pin files; then pin |
| Lifetime | Pins live while the long-running loader lives; **unpin both files + rmdir** on SIGINT/SIGTERM |
| Ctl | Opens **only** `open_ports`; does not attach; does not touch OpenResty |
| Failure | Pin failure is a **warning** on Go today (close-port / bpftool won’t work). Rust R2 should keep that for toy bring-up, then treat pin failure as fatal in OpenResty mode (M2/M3 need the pin). |

Map types (from `dispatch.bpf.c`):

- `open_ports`: key destination port as `ctx->local_port` (**host byte order** `__u16`); value sockmap index `__u8` (0 or 1).
- `redir_socket`: key `__u32` slot; value socket FD (`__u64` in the map def; libbpf/cilium pass the FD).

### 3.3 CLI parity

Go is one binary: if `os.Args[1]` is a ctl command, skip `flag.Parse` long-running mode (`ctl.go` `isCtlCommand`). Rust should do the same so `run-openresty-demo.sh` and `scripts/m3-fill-ports.sh` can point at either binary.

**Long-running (Go `flag` set — keep names):**

| Flag | Default | Notes |
|------|---------|--------|
| `-mode` | `toy` | `toy` \| `openresty` \| legacy `close-port` \| `open-port` \| `dump-ports` |
| `-listen` | `127.0.0.1:18080` | toy real bind |
| `-target` | `127.0.0.1:8080` | OpenResty primary → sockmap 0 |
| `-ports` | `18081,18082,65500` | comma list; **not** ranges (ranges are ctl-only) |
| `-tls-target` | `127.0.0.1:8443` | stock fallback only |
| `-tls-ports` | empty | empty = product path (all ports → `-target`) |
| `-wait` | `60s` | OpenResty listen wait |
| `-pin-dir` | `/sys/fs/bpf/waf-sklookup` | |

**Ctl (verified `ctl.go` / `ports_bulk.go`):**

| Command | Aliases | Required inputs |
|---------|---------|-----------------|
| `add` | `open` | `PORT`, `START-END`, `-range`, `-file`, `-stdin`; optional `-tls`, `-pin-dir` |
| `remove` | `close` | same sources; no `-tls` (delete is slot-agnostic) |
| `list` | `dump` | `-count` (M3: print `count=N` only) |
| `bulk open` | `load-ports` | `-range` / `-file` / `-stdin`; `-batch` (default **4096**); `-quiet`; `-tls` |
| `bulk close` | `close-ports` | same without `-tls` |
| `bulk fill` | — | `-count` (30000/60000); `-start` default **5000**; `-skip` default `8080,8443` |

Fill must skip internal listens and must **not** start at 10000 for 60K (uint16 overflow). Go tests this in `TestGenerateFillPorts`. Port `0` is rejected.

Stdout/stderr contract (M3 scripts scrape this loosely):

- Progress on **stderr** (`add 4096/30000 ...`).
- One-line summary on **stdout** (`added n=30000 slot=0 (primary) elapsed=... method=batch`).
- `list -count` → `count=N`.

R1 may implement a subset (`-mode toy` + `list`). R3 must be byte-compatible enough that `scripts/m3-fill-ports.sh` works with `LOADER_BIN` swapped.

### 3.4 Script / HAH compatibility

Verified: `run-openresty-demo.sh` and `scripts/m3-fill-ports.sh` **hardcode** `./waf-sklookup-demo`. They already honor `PIN_DIR`, `OPENRESTY_PREFIX`, `LOADER_PORTS`, `LOADER_TLS_PORTS`, `TARGET`, `WAIT`.

R2 change (not R0): introduce `LOADER_BIN` (default `./waf-sklookup-demo`) in both scripts and `build_loader` / `ensure_loader_bin` so:

```bash
# Go (rollback) — unchanged default
./run-openresty-demo.sh start
./scripts/m3-fill-ports.sh 30000

# Rust dual-binary
export LOADER_BIN=./rust/loader/target/release/waf-sklookup-loader
OPENRESTY_PREFIX=/usr/local/openresty-hah ./run-openresty-demo.sh start
./scripts/m3-fill-ports.sh 60000
```

Ready string: Go prints `OPENRESTY P1 READY`. The helper greps that in `loader.log`. Rust must print the **same** marker (or the helper must accept a second marker). Prefer keeping the string.

Unpin vs OpenResty: loader stop must not kill OpenResty (`runOpenRestyMode` log: “OpenResty keeps running”).

---

## 4. Acceptance

### 4.1 Must re-run the existing M3 ladder to PASS

Do not invent a new scale test. Re-use [docs/acceptance-m3.md](acceptance-m3.md) / [docs/acceptance-m3-full-run.md](acceptance-m3-full-run.md):

```bash
export CGO_ENABLED=0
# stock: OPENRESTY_PREFIX=/usr/local/openresty
# HAH:   OPENRESTY_PREFIX=/usr/local/openresty-hah
./run-openresty-demo.sh start          # LOADER_BIN=Rust from R3
./scripts/m3-fill-ports.sh 30000
./scripts/m3-fill-ports.sh 60000
sudo bpftool map show name open_ports  # max_entries 131072, memlock ~8–16 MB
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:34999/   # expect 200
```

Also keep M1/P1 `./run-openresty-demo.sh verify` and M2 add/remove/list on the Rust binary.

**Pass means:** functional steering + map fill + RSS/map table filled. It does **not** mean Rust QPS ≥ Go QPS. Record QPS; do not gate R3 on it. Kernel `sk_lookup` is unchanged.

### 4.2 Go vs Rust comparison table (fill at R3)

Copy this into `docs/acceptance-m3-rust.md` (or extend the existing ladder CSV). Go baseline is already recorded at M2 tip (`a01b5b2` / `09d138b`) on HAH:

| Ladder | Loader | ports_have | loader RSS kB | OpenResty RSS kB | open_ports max_entries / memlock | fill elapsed | QPS (record only) | CPU | probe :34999 | Result |
|--------|--------|------------|---------------|------------------|----------------------------------|--------------|-------------------|-----|--------------|--------|
| baseline (≤10 ports) | Go | 1 | 7024 | 9916 | 131072 / ~10487488 B | — | ~102 | ~0 | — | PASS (`09d138b`) |
| 30K | Go | 30000 | 7024 | 10780 | same | 8 ms | ~100 | ~0 | — | PASS |
| 60K | Go | 60000 | 7024 | 10784 | same | 16 ms | ~85 | ~0 | HTTP 200 | PASS |
| baseline | Rust | | | | | | | | | |
| 30K | Rust | | | | | | | | | |
| 60K | Rust | | | | | | | | | |

How to measure (same as M3):

```bash
ps -o pid,rss,comm -p <loader_pid>,<openresty_worker_pids>
sudo bpftool map show name open_ports
```

Expect: kernel memlock **does not** grow with 30K→60K (map is precharged at 131072). Userspace RSS should stay roughly flat like Go. If Rust RSS climbs linearly with port count, that is a **userspace bug** (holding the 60K `Vec<u16>` after the syscall, or cloning the map). Go’s bulk path does not keep that slice after `applyAdd` returns.

### 4.3 Go remains rollback

Until R4:

- Default `LOADER_BIN` / `make build` / `./run.sh` stay **Go**.
- README still documents `./waf-sklookup-demo`.
- R4 may switch the helper default to Rust **only after** the table above is PASS; keep building and documenting the Go binary.

Rollback drill: `LOADER_BIN=./waf-sklookup-demo ./run-openresty-demo.sh start` (restart loader once so pins match the Go object; OpenResty need not reload).

---

## 5. Risks

| Risk | Why it shows up here | Mitigation |
|------|----------------------|------------|
| **CAP_BPF / memlock** | `open_ports` 131072 precharges ~10.5 MB (`bpftool` memlock 10487488 B on the M3 box). Older kernels still enforce `RLIMIT_MEMLOCK`; cilium/ebpf often raises it implicitly. libbpf-rs may need an explicit `setrlimit(RLIMIT_MEMLOCK, ∞)` or fail at load. Also need `CAP_NET_ADMIN` (netns attach) and `pidfd_getfd` credentials (demo runs `sudo`). | R1: document caps; raise memlock like libbpf tools; fail with the same hint Go prints (`need root/CAP_BPF and kernel sk_lookup`). |
| **CI has no `sk_lookup`** | This repo has **no** GitHub Actions today. Many CI kernels / unprivileged containers cannot attach. Go tests are userspace-only except `TestOpenPortsMaxEntries` (needs `go generate`). | R1+: unit-test `ports.rs` without BPF (port 0, 30K/60K fill, skip 8080/8443). Gate attach tests on `bpftool feature` / `/sys/kernel/btf/vmlinux`. Do not block merge on sandbox attach. |
| **Regenerate bindings** | Two generators (bpf2go + libbpf-cargo) on one `.c`. Include path, `max_entries`, and helper headers can drift. bpf2go artifacts are gitignored; skeletons should be too. | Single source `dispatch.bpf.c`. Shared clang `-I` documented in Makefile comments. Assert `max_entries == 131072` on load. |
| **Dual-binary period** | Scripts hardcode `./waf-sklookup-demo`. Two loaders must not attach in the same netns (double `sk_lookup`). Stale **1024-entry** `open_ports` maps already appeared next to 131072 in M3 `bpftool map show`. | `LOADER_BIN`; one loader process; restart loader after switching binaries; ignore leftover maps from old IDs. |
| **SOCKMAP FD lifetime** | Go keeps the dup’d `*os.File` until process exit so the sockmap entry stays valid. Dropping the FD early can break steering. | Hold `OwnedFd` for the listen socket(s) for the loader lifetime (including toy `TcpListener`). |
| **Endian / key width** | Ports are `__u16` host order (comment in `dispatch.bpf.c`). Wrong padding on `__u8` values (Go uses `uint8` slot) will fail lookup. | Match Go: key `u16`, value `u8`. Dump one key with `bpftool map dump` in R1. |
| **libbpf shared vs static** | Go is `CGO_ENABLED=0`. libbpf-rs may need `libbpf-dev` at build and `libbpf.so` at runtime unless vendored. | Prefer vendored/static libbpf for the release binary; document `libbpf-dev` for dev builds. |
| **Ready-string / CLI drift** | Helper greps `OPENRESTY P1 READY`; fill script calls `bulk fill` then `list -count`. | Treat those strings/subcommands as the compatibility ABI. |

---

## 6. Milestones and rough effort

Sizing is engineer-days on a box that already runs the Go demo (sudo, clang, OpenResty or HAH). Not calendar time.

| ID | Goal | Exit criteria | Rough effort |
|----|------|---------------|--------------|
| **R0** | This plan | Draft PR with this doc + README link. No loader code. | 0.5–1 d (done) |
| **R1** | Toy attach | `cargo build` compiles `dispatch.bpf.c`; load + `attach_netns`; toy listen on `:18080`; steer `18081`; curl both; `ss` shows no userspace listen on 18081. Go binary unchanged. | 3–5 d |
| **R2** | OpenResty + pin parity | `-mode openresty` waits for `:8080` (and optional `:8443`); `pidfd_getfd`; pin `/sys/fs/bpf/waf-sklookup`; `LOADER_BIN` in `run-openresty-demo.sh`; `verify` PASS; HAH `OPENRESTY_PREFIX` still works. `add`/`remove`/`list` on pinned map. | 3–5 d |
| **R3** | Bulk + 30K/60K ladder | CLI parity for `bulk open/close/fill`; `scripts/m3-fill-ports.sh` via `LOADER_BIN`; fill comparison table; 60K `list -count` + curl `:34999` HTTP 200. Go path still default. | 3–5 d |
| **R4** | Rust default, Go retained | Helper/`make run-openresty` default to Rust; README documents both; Go `make build` remains; rollback command in README. Only after R3 PASS. | 1–2 d |

**Total first cut: about 11–18 engineer-days** after R0. R1 is the highest technical risk (attach + SOCKMAP + memlock). R3 is the acceptance gate. Skip R4 if R3 is only “works on the lab box” without the table filled.

Suggested R1 spike order (still implementation, not this PR):

1. Empty crate + `build.rs` compiling `dispatch.bpf.c`.
2. Load + attach + pin empty maps (no HTTP).
3. Toy listen + sockmap + one port.
4. Stop. Do not start OpenResty work until 3 curls.

---

## Appendix A — verified Go surface (do not re-guess)

Inspected on `09d138b`:

- **Attach:** `os.Open("/proc/self/ns/net")` then `link.AttachNetNs`.
- **Toy:** `net.Listen("tcp")` → `TCPListener.File()` → `RedirSocket.Put(0, fd)` → `OpenPorts.Put(port, 0)`.
- **OpenResty:** poll `findListenSocketFile` every 200 ms up to `-wait`; parse `/proc/net/tcp` LISTEN (`st=0A`); `unix.PidfdOpen` + `PidfdGetfd` (comment: `open(/proc/pid/fd/N)` returns `ENXIO` for sockets on some kernels). IPv4 only; fallback to `0.0.0.0` if the specific IP is missing.
- **Ctl detection:** `add`, `open`, `remove`, `close`, `list`, `dump`, `bulk`, `load-ports`, `close-ports`, `help` — not `-mode` / `toy` / `openresty`.
- **Bulk:** `defaultBulkBatch = 4096`; `openPortsMaxEntries = 131072` must match BPF; `BatchUpdate` if the kernel supports it, else per-key `Put`; delete tries `BatchDelete` then per-key, counting missing keys (`ebpf.ErrKeyNotExist`).
- **Tests that must have Rust equivalents (no kernel):** port lists, ranges 30K/60K, fill skip, `max_entries` constant, ctl command set. Kernel tests stay on the demo host.

## Appendix B — what success is not

- Not a QPS/P99 claim versus Go or versus PROXY/TPROXY ([docs/perf-deep-compare.md](perf-deep-compare.md) stays a later P0).
- Not a replacement of OpenResty.
- Not deleting the Go loader in R4.
- Not announcing a product rewrite.

When R3 is PASS, the next engineering step is the **same** M3 remaining rows (perf / rollback drill) and then P0 — on whichever loader is default, with the other kept.
