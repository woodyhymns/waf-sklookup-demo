# Technical Review: BPF `sk_lookup` for WAF Dynamic Non-Standard Ports

**Subject**: [woodyhymns/waf-sklookup-demo](https://github.com/woodyhymns/waf-sklookup-demo) (`main@f353271`, C and Rust BPF implementations plus a Rust userspace loader)
**Review goals**: full production feasibility, no performance regression, observability that survives production
**Author**: Manus AI
**Date**: August 16, 2026

---

## 1. Executive Summary

The headline conclusion, stated so it can be forwarded upward directly:

> **The architectural direction is right, and the engineering maturity is well above a typical demo. However, the current code still has substantive gaps before it can be called production-ready. The gaps are not in BPF itself — they are in the multi-worker model, the way the external port is recovered, and observability that is effectively absent. All three require redesign rather than patching.**

`sk_lookup` is the mechanism the Linux kernel introduced precisely for the case where an L7 proxy must serve a wide range of ports. Its official documentation names "receiving connections on all or a wide range of ports, i.e. an L7 proxy use case" as an explicit motivation, and notes that the conventional approach of creating and `bind()`ing one socket per address/port pair leads to resource consumption and potential latency spikes during socket lookup [1]. Your use case maps onto this directly. Cloudflare uses the same mechanism to serve its Spectrum product across all 2^16 ports, and has open-sourced the control plane, Tubular [2]. **There is no need to second-guess the direction.**

There is, however, one structural fact that must be stated plainly: **the repository was validated with `worker_processes 1`, the `redir_socket` sockmap has only two slots, and the README explicitly lists "multi-worker reuseport sockmap" as out of scope.** A production WAF cannot run single-worker, so this is not a to-be-optimized item — the dataplane model itself has not yet been designed for production.

On your preference for Rust: **Rust for the userspace loader is clearly the right call and the repository already makes it the default with decent quality. Writing the kernel-side BPF program in Rust, as implemented here, is a net risk.** See section 6.1.

| Your three goals | Current state | Verdict |
|---|---|---|
| 1. Full production rollout | Single-host, single-worker, single-VIP, IPv4-only validated; multi-worker / multi-VIP / IPv6 uncovered | **Not met** — dataplane matching and sockmap model need redesign |
| 2. No performance regression | Steady state effectively matches direct bind (G1 rps ratio 1.113/1.003; G2 p99 abs delta 2.7ms/0.025ms), but G6 hot-update p99 ratio 1.827 fails its gate | **Direction confirmed, calibration incomplete**; existing numbers are not representative of production |
| 3. Production-grade observability | Only two file-backed metrics (`apply_fail_total`, `last_apply_central`); zero dataplane counters, no exporter | **Not met** — the single largest gap |

---

## 2. Architecture Reconstruction

The diagram below reconstructs the design from the code. The essence: **external ports are never `bind()`ed in userspace; each exists only as an entry in a BPF hash map. When the kernel looks up a listening socket during TCP connection establishment, SYNs to these "virtual ports" are steered via `bpf_sk_assign` to OpenResty's existing fixed internal listen socket.**

![Architecture reconstruction](assets/arch.png)

The dataplane itself is minimal — `dispatch.bpf.c` is 69 lines: non-TCP returns `SK_PASS`; look up `ctx->local_port` in `open_ports`; a miss returns `SK_PASS` (falling back to normal bind lookup); a hit fetches the socket from `redir_socket` by slot and calls `bpf_sk_assign`. This thin-kernel / thick-userspace ratio matches Cloudflare's experience, which notes the ratio of eBPF code to userspace code typically differs by an order of magnitude or more [2].

Four design decisions in the loader deserve credit:

**No dependency on a resident daemon.** State lives in kernel maps pinned under `/sys/fs/bpf/waf-sklookup`; `ctl` commands are short-lived processes that open the pinned maps directly. This mirrors Tubular's core decision — Cloudflare deliberately avoided a resident daemon because "a tubular daemon, which may crash," and instead relies on short-lived `tubectl` invocations with kernel-persisted state to get crash resilience by default [2].

**Using `pidfd_getfd` to acquire OpenResty's listen fd.** `listen_fd.rs` parses `/proc/net/tcp` for LISTEN inodes, walks `/proc/*/fd` to find the holder, then uses `pidfd_open` + `pidfd_getfd` to duplicate it. This is exactly Tubular's third approach, chosen because "a lot of popular software doesn't use systemd socket activation" and `SCM_RIGHTS` requires modifying the target process [2]. Correct choice.

**Desired-state driven and fail-closed.** `ports.conf` is the local desired state; `policy.conf` supplies a denylist, privileged-port allowlist, and quotas. Any invalid binding (missing tenant/site, denied port, unallowed privileged port, quota exceeded) causes the **entire apply to be refused** rather than partially applied (`desired.rs`, `policy.rs`). `central/desired-state.json` acts as the central desired state, materialized locally only after validation. The semantics here are sound.

**Conflict gating between real listens and virtual ports.** `nginx_listen.rs` parses `listen` lines from the nginx config and hardcodes 80/443/8080/8443 as "real"; `ctl.rs`'s `fail_on_overlap` intersects real against virtual before add/reconcile/apply-central and refuses on conflict. This is a well-considered guard that many implementations of this pattern miss.

---

## 3. Gap Overview

This is the core output of the review — twelve items, graded by whether they block production.

![Risk grading](assets/risks.png)

---

## 4. P0 Blocking Issues

### 4.1 Multi-worker + `SO_REUSEPORT`: semantics diverge from implementation, and the model is unfinished

This is the most serious item.

`redir_socket` is a SOCKMAP with `max_entries=2`: slot 0 holds the HTTP listen fd, slot 1 the stock-OpenResty TLS fallback. `docs/recovery.md` states it bluntly:

> `redir_socket` has two protocol slots, not worker shards: slot 0 is HTTP and slot 1 is the stock-demo TLS fallback. […] There is no listen sharding.

Under a production multi-worker + `SO_REUSEPORT` configuration, **the loader places only one worker's listen fd from the reuseport group into the sockmap**, and `rescan_slot` merely picks "the first inode still reachable through `/proc/*/fd`."

Curiously, the P1-b measurement shows a 25.8% / idle=0 distribution across four workers, which looks balanced. **But that pass is obtained through implicit kernel behavior, not by design.** The reason lies in `bpf_sk_assign`'s `flags`: the kernel provides `BPF_SK_LOOKUP_F_NO_REUSEPORT` "to skip load-balancing within reuseport group for the socket being selected" [3], and both `dispatch.bpf.c` and the Rust twin pass `flags=0`. Consequently, **after the kernel receives your chosen socket, it still performs a selection within that socket's reuseport group.** Kernel history records this design evolution as "Run reuseport logic on sockets selected by BPF sk_lookup" [4].

Three practical consequences follow:

First, **the operator's mental model diverges from actual behavior.** Code comments and the recovery runbook both say "the fd in the slot determines which worker receives the SYN." It does not. When worker distribution skews or a worker hangs, responders will debug against a wrong model.

Second, **rescan semantics become ambiguous.** Since the reuseport group actually decides distribution, which worker's fd occupies the slot does not normally affect dispatch. But once that fd's worker dies and the fd becomes invalid, `bpf_sk_assign` returns `-ESOCKTNOSUPPORT` (socket not in an allowed state) [3] and the program takes `SK_DROP` — even though every other worker is healthy. This means **a single worker's failure can kill new connections on all virtual ports**, while genuinely `bind()`ed ports are unaffected. The failure domain has been artificially amplified, and the hole is open for the duration of the 2-second polling window.

Third, **this hazard is empirically documented in the nginx ecosystem.** The nginx community has disclosed that `quic_bpf` + `reuseport` will eventually drop HTTP/3 traffic because nginx does not close stale reuseport sockets [5]. The failure mode is identical in nature: a real mismatch between BPF socket selection and nginx worker lifecycle management.

**Recommendation**: pick one option and record it in the design document. Option A: convert `redir_socket` into worker shards (`max_entries` = max worker count, keyed by `bpf_get_smp_processor_id()` or a 4-tuple hash) and pass `BPF_SK_LOOKUP_F_NO_REUSEPORT` explicitly, taking full control of distribution. Option B: acknowledge and rely on reuseport group behavior, which then requires guaranteeing that the fd in the sockmap is always a live group member, and replacing the 2-second poll with event-driven updates (netlink socket events, or `inotify` plus notification from the nginx master). I favor Option A because it makes both the failure domain and the behavior explainable.

### 4.2 Protocol discrimination depends entirely on Tengine `https_allow_http` — a single point for the whole design

`sk_lookup` runs at connection establishment, before any application bytes exist, so **the kernel cannot know whether a connection is HTTP or TLS**. The code comments are admirably honest:

> Protocol (plaintext HTTP vs TLS) is NOT decided here — production OpenResty/Tengine does that on the listen via `https_allow_http`.

The product form therefore requires the single internal listen to accept both cleartext and TLS: `listen 127.0.0.1:8080 ssl https_allow_http;`. That `https_allow_http` is a `listen` option added in Tengine 3.1.0 (October 2023) "for receiving HTTP traffic on the TLS listener" [6] [7]; **neither stock nginx nor stock OpenResty has it.** The repository confirms this itself via `nginx -t → invalid parameter` and explicitly labels the `:8080` HTTP + `:8443 ssl` dual listen as a fallback that is "NOT the product model."

Implications:

- Your production engine **must** be Tengine 3.1.0+, or you must maintain an `https_allow_http` patch yourself (which is exactly what `third_party/https_allow_http/` does, against nginx-1.19.3).
- If production runs stock OpenResty, the design degrades to "HTTP port set and HTTPS port set must be separated in the control plane in advance." This conflicts directly with your requirement — onboarding may not know in advance, and moving a domain from HTTP to HTTPS becomes a slot change. Slot changes are fast map writes, but semantically you have made "protocol" a piece of state the control plane must own.
- Maintaining a self-patched Tengine/nginx carries long-term cost. Tengine has recently had worker-crash CVEs [8]; the security-tracking burden for a self-maintained branch must be budgeted up front.

**Recommendation**: settle the engine version decision in Phase 0 — it is a precondition for the entire design. If Tengine 3.1.0+ is unavailable, one viable compromise is to skip protocol discrimination in `sk_lookup` and perform protocol demultiplexing on the OpenResty side using `ssl_preread`/stream or custom client-hello detection — but that adds a hop and needs separate evaluation. **Do not invest in Phase 1 development before the engine decision is settled.**

### 4.3 How `$waf_external_port` is obtained: a per-request linear `/proc` scan — a design defect, not a performance nit

After `sk_lookup`, nginx's `$server_port` becomes the internal listen port (8080) rather than the port the client actually reached. The repository addresses this with `openresty/lua/waf/external_port.lua`, resolving the true external port during `access_by_lua`. But its **preferred path** is:

```lua
local f, err = io.open("/proc/self/net/tcp", "r")
...
for line in f:lines() do  -- linear scan matching remote_addr:remote_port
```

**Every request** opens `/proc/self/net/tcp` and linearly scans the whole table for the ESTABLISHED row matching the remote 4-tuple, in order to read the local port. There are four layers of problem here:

First, **this is blocking file I/O executed synchronously inside the nginx event loop.** `io.open` is a LuaJIT stdlib call, not a cosocket, and blocks the entire worker.

Second, **the complexity is O(connections)** per request, so O(QPS × connections) overall. With tens of thousands of connections per host in production, each request scans tens of thousands of lines. The repository's own measurement quantifies the cost: replacing `resolve()` with a constant stub dropped **p99 absolute latency from roughly 19ms to roughly 0.5ms** (`docs/repro-g2-http-p99.md`, probe 3). That is not a 3–5% tax; it is an order of magnitude — and it was measured with only three ports, one worker, and a few hundred rps.

Third, **it returns wrong results under concurrency.** The match condition is only `remote_ip:remote_port` plus state `01` (ESTABLISHED). Behind NAT with source-port reuse, or with TIME_WAIT residue, the same `remote_ip:remote_port` can match multiple rows and the code takes the first. That **crosses ports** — and this port feeds ACL decisions and rate limiting (exactly the path P1-c validates). A probabilistic parsing error becomes a security-policy misjudgment.

Fourth, **the fallback path is also unresolved.** `port_from_req_socket()` uses `ngx.req.socket(true):getfd()` plus FFI `getsockname()`. The direction is right, but a PR (#10) that promoted getsockname was later reverted (`d5a0128` "Revert: prefer getsockname in waf.external_port resolve"), indicating an unresolved issue that needs re-investigation.

**Recommendation**: abandon the `/proc` scan entirely, in this order of preference:

1. **`ngx.ssl.server_port()`** — `lua-resty-core` provides this API, callable "in any context where downstream https is used," alongside `ssl.raw_server_addr()` which "returns the raw server address actually accessed by the client in the current SSL connection" [9]. Native C implementation, zero `/proc` cost. Verify empirically whether nginx's recorded local sockaddr after `bpf_sk_assign` is the external port.
2. **`getsockname()` on the connection fd** — re-do the reverted PR #10 direction after root-causing it. A single syscall, O(1).
3. **Record in BPF, read directly from userspace** — the most thorough option: have `sk_lookup` write `(remote_ip, remote_port) → local_port` into an LRU hash map, and read the pinned map from OpenResty via FFI. This eliminates even the syscall and removes ambiguity entirely, at the cost of managing map aging.

Whichever is chosen, **it must land in Phase 1, because it affects both performance and correctness.**

### 4.4 Matching on port only — no destination IP, and IPv4 only

`dispatch.bpf.c` makes exactly two decisions: `ctx->protocol != IPPROTO_TCP`, and whether `ctx->local_port` is in the map. **`ctx->local_ip4`, `ctx->local_ip6`, and `ctx->family` are entirely unused.**

The consequence: once a port enters `open_ports`, **that port on every IP address on the host — every VIP, every NIC address, and `127.0.0.1` — is hijacked to the single OpenResty listen.** This contrasts sharply with Tubular, which stores `(protocol, port, prefix) → destination` in an LPM trie precisely to support "multiple services using the same port on different addresses" — a requirement Cloudflare names explicitly [2].

Concrete impact for a production WAF:

- **No multi-VIP isolation.** If a host serves multiple customer VIPs and customer A opens port 30000 on VIP-1, then 30000 on VIP-2 and VIP-3 is also effectively open. Everything still lands in the same OpenResty and gets demultiplexed by SNI/Host, but this is semantically wrong in a multi-tenant model and renders port quotas and conflict detection meaningless.
- **Risk of collateral damage to host management services.** `policy.conf` denies only 22/25/53/3306/6379 and all privileged ports. If someone runs a management service bound to `127.0.0.1:30000` while 30000 happens to be a virtual port, that internal traffic is stolen. `nginx_listen.rs` conflict detection only reads the nginx config file and **cannot see other processes' listens on the host.**
- **IPv6 is entirely unsupported.** `listen_fd.rs` is annotated `(IPv4 only)` and parses only `/proc/net/tcp`, not `/proc/net/tcp6`. Meanwhile the BPF side has no `family` check, meaning **IPv6 SYNs also enter the program**: `ctx->local_port` is equally valid for IPv6, so the lookup hits, and `bpf_sk_assign` is called with an IPv4 socket. The kernel returns `-EAFNOSUPPORT` (socket family not compatible with packet family) [3], and the code takes `SK_DROP`. **Net effect: for any port in the map, IPv6 traffic to that port is silently dropped instead of falling through to `SK_PASS`.** This is a genuine functional bug, and no log or counter exposes it.

**Recommendation**: change the map key from `u16 port` to a struct `{family, port, addr}`, or follow Tubular in using an LPM trie for prefix matching. Add an explicit `family` check where unsupported families return `SK_PASS` rather than reaching `SK_DROP`. Extend conflict detection beyond the nginx config to a full scan of LISTEN rows in `/proc/net/tcp{,6}`.

---

## 5. P1 High-Severity Issues

### 5.1 `pidfd_getfd` fd lifetime and the 2-second polling window

`openresty.rs`'s `rescan_held` compares socket inodes every 2 seconds (or on `SIGUSR1`) and hot-swaps the sockmap slot on change. This self-heals worker restarts, but has weak points:

**The blind window.** From worker death to the next effective rescan is up to 2 seconds. During that time `bpf_sk_assign` targets a dead socket and new connections on all virtual ports are dropped. `docs/recovery.md` acknowledges this: "An empty selected slot makes new steered SYNs `SK_DROP` until it is refilled." Two seconds of refusing new connections on every virtual port is an alert-triggering event in production. And nginx graceful reload necessarily rotates workers — **meaning every OpenResty reload can introduce a 2-second disruption window**, ironically returning to the very problem you set out to avoid.

**Inode comparison is insufficient as a health check.** `socket_inode()` uses `fstat` on `st_ino`. Because the loader holds its own dup of the fd, the kernel keeps the socket structure alive, so **even after nginx closes its side, the loader's fd remains "valid" and the inode unchanged** — rescan detects nothing. What actually needs checking is whether the socket is still in the reuseport group and still in LISTEN state, which requires cross-referencing the inode against `/proc/net/tcp` rather than `fstat`ing your own fd.

**Recommendation**: replace "timer + inode compare" with event-driven updates plus a real health check. The event source can be the nginx master notifying the loader from `ExecStartPost`/`ExecReload` hooks — exactly what Tubular does with `ExecStartPost=tubectl register-pid` [2] — while the health check confirms the inode is still in the LISTEN set via `/proc/net/tcp`. Also evaluate whether both the old and new fd should coexist in the sockmap during reload to eliminate the window.

### 5.2 G6 hot-update p99 ratio 1.827 fails its gate, root cause unidentified

In the repository's own gate framework (`docs/acceptance-prod-gng.md`), G6 is explicitly **Fail**: hot-adding 10,000 ports shows a beautiful `open` time of 23ms, `close` 17ms, and `fail=0` — but the **p99 during the change is 1.827× the pre-change baseline against a 1.10 threshold.** The document says "parked; prioritize G2."

![Normalized gate results](assets/gates.png)

This cannot stay parked through go-live. The value of the dynamic-port feature is precisely that ports can be added at any time. If every bulk add raises p99 by 80%, operators will naturally batch changes into low-traffic windows — **which degrades right back to your current pain point.**

Candidate causes to eliminate one by one: whether BPF hash map writes contend with the lookup path (`open_ports` is a plain `BPF_MAP_TYPE_HASH` with bucket-level locking on write); whether `bulk.rs` should shard writes and yield CPU between shards; and whether it is simply noise from the single-worker demo environment. **Note that the G2 investigation already proved this test environment is extremely noisy** — `docs/repro-g2-http-p99.md` shows the ratio flipping from 1.2897 to 0.5628 when A/B block order is swapped, and passing at 1.0303 with `c=1`. So G6's 1.827 may equally be noise, but **it cannot be assumed to be noise until re-calibrated on real multi-worker hardware.**

**Recommendation**: re-test G6 on production hardware, multi-worker, at realistic QPS. If map write lock contention is confirmed, consider `BPF_MAP_TYPE_LRU_HASH` or sharded maps, or split bulk writes into smaller batches (currently `DEFAULT_BULK_BATCH = 4096`).

### 5.3 Coexistence with other BPF programs: the hidden risk of last-selection-wins

The kernel allows **multiple `sk_lookup` programs attached to the same netns**, invoked in attach order, with the merge rule that if more than one returns `SK_PASS` and selects a socket, **the last selection takes effect** [1].

A production WAF node may simultaneously run Cilium/CNI, other eBPF probes, security agents, or even nginx's own `quic_bpf`. If any of them attaches (or later attaches) a `sk_lookup` program, your selection may be silently overridden, or you may override theirs. `bpf_sk_assign` returns `-EEXIST` when a socket has already been selected by another program and `BPF_SK_LOOKUP_F_REPLACE` was not specified [3] — and **the current code only checks `err ? SK_DROP : SK_PASS`, distinguishing no errno and recording nothing.**

This will not surface today because the demo environment runs a single program. But once deployed to shared nodes, debugging becomes extremely hard: the symptom is "some ports intermittently unreachable" with entirely empty logs.

**Recommendation**: count by errno on the BPF side (see the metric design in 8.1), and add "enumerate `sk_lookup` programs currently attached to this netns" to the deployment checks. `scripts/check-install.sh` does not check this today.

### 5.4 Observability: the largest gap

I read `metrics.rs` in full — 37 lines, maintaining exactly two files: `/run/waf-sklookup/apply_fail_total` (an integer counter) and `/run/waf-sklookup/last-apply-central` (an RFC3339 timestamp). `ctl status` emits somewhat more: `real`/`virtual`/`overlap` port lists, `drift` (put/delete counts), `frozen` state, and those two metrics.

**The dataplane has no counters whatsoever.** No assign successes, no failures classified by errno, no `SK_DROP` count, no hit/miss statistics. When a customer's port goes unreachable in production, you have **no data to distinguish** among: the port is not in the map; the slot is empty; `bpf_sk_assign` returned an error (and which errno); or traffic never reached the host. The only recourse is logging in and running `bpftool map dump` by hand — which is exactly how all fourteen recovery scenarios in `docs/recovery.md` are designed.

There is also an easily overlooked operational fact: **`ss -lnt` cannot see these virtual ports.** `docs/control-plane.md` states it: "`ss -lnt` cannot see `sk_lookup` virtual ports; use `list -virtual` or `status`." Cloudflare hit the same problem and answered it by providing `tubectl bindings` to make up for the shortcoming [2]. Your team needs to internalize that **every existing monitoring script, inspection tool, and capacity-reconciliation process that relies on `ss`/`netstat` will fail on these ports — and fail silently**, producing no error, simply showing nothing.

Cloudflare offers one more directly copyable practice: per-destination metrics live in per-CPU counter maps, exported by opening the pinned maps with `BPF_OBJ_GET` + `BPF_F_RDONLY` under carefully set pin ownership and mode (`-rw-r-----`), so a **non-root exporter** can scrape read-only; `/sys/fs/bpf` also needs `chmod o+x` because systemd mounts it too restrictively [2]. They also note honestly that truly unprivileged access requires `unprivileged_bpf_disabled` to be unset, otherwise `CAP_BPF` is still needed [2]. This pattern is mature and directly adoptable.

**Recommendation**: see the target state in section 8. I estimate 2–3 weeks of work, but it is a necessary condition for "surviving production," not an optional extra.

---

## 6. P2 Items Requiring Reinforcement

### 6.1 The Rust BPF twin is a net risk as implemented — recommend deferring

Since you raised Rust, the userspace and kernel sides must be separated.

**Rust for the userspace loader: fully endorsed.** The repository already defaults to it (`c4f51b3` "default userspace loader to Rust and drop Go"), built on `libbpf-rs`, and the quality is good — `OwnedFd` for fd lifetime, `flock` for single-instance exclusion, `UnpinOnDrop` for cleanup, complete `anyhow` context chains, atomic `ports.conf` writes (tmp + rename + `sync_all` + preserved mode/ownership). Solid engineering.

**Rust for the kernel-side BPF (`rust/bpf/src/lib.rs`): not recommended for production as implemented.** Concretely:

Helper calls are made by `core::mem::transmute`ing integer constants into function pointers:

```rust
let helper: unsafe extern "C" fn(*mut c_void, *const c_void) -> *mut c_void =
    core::mem::transmute(1usize);   // bpf_map_lookup_elem
...core::mem::transmute(86usize);  // bpf_sk_release
...core::mem::transmute(124usize); // bpf_sk_assign
```

Those magic numbers are helper IDs. They are indeed stable in the kernel ABI, but **nothing in this code validates or documents where they come from.** If someone mistypes a digit, it compiles, the verifier may still accept it, and the behavior is silently wrong. The C version obtains typed, named declarations from `bpf_helpers.h` — a tier better in both readability and safety.

Map definitions are more fragile still. The Rust side fakes a set of pointer fields to encode BTF `__uint`/`__type` attributes:

```rust
struct OpenPortsDef {
    r#type: *mut [u32; 1],          // BPF_MAP_TYPE_HASH
    max_entries: *mut [u32; 131072],
    ...
}
```

Constants are encoded as array lengths. Then, because `rustc` emits `r#type` into BTF as `type_`, a post-build step (`scripts/patch-rust-btf-map-type.py`, 223 lines of Python) rewrites the `.BTF` string table and merges two `.maps` sections into one to mimic clang's output. `docs/rust-bpf.md` documents this clearly.

The problem with this chain is that **it depends on rustc's BTF output details, bpf-linker's behavior, and a bespoke ELF post-processor — none of which you control, and all of which can change across versions.** `rust/bpf/rust-toolchain.toml` additionally pins a nightly toolchain. Three extra failure points for a program with thirty lines of effective logic. The repository is clear-eyed about this: the README calls it "a **source-language comparison**, not a QPS promise," C remains the default, and `docs/acceptance-prod-gng.md` records "Rust 仍 DEFER."

**Recommendation**: keep C on the kernel side (thirty lines, type-safe helpers via `bpf_helpers.h`, the most mature toolchain) and Rust in userspace. If kernel-side Rust remains desirable, revisit once a mature framework such as [Aya](https://aya-rs.dev/) covers `sk_lookup` + `SOCKMAP`, rather than maintaining a bespoke BTF patch script.

### 6.2 No prog tag verification and no pinned `bpf_link` — upgrades are not atomic

The repository pins `open_ports` and `redir_socket` (`pin.rs`) but **pins neither the program nor the `bpf_link`.** The `Link` returned by `load_and_attach` lives only for the loader process's lifetime; loader exit means detach.

Tubular's approach is instructive. It pins both `link` and `program` under `/sys/fs/bpf/{netns}_dispatcher/` and uses two mechanisms for safe upgrades [2]:

First, **version verification via prog tag.** The tag is a truncated hash of a program's instructions, exposed by the kernel for every loaded program. `tubectl` compares the loaded program's tag against the tag built into its own binary and refuses to mutate state on mismatch:

> `Error: bind: can't open dispatcher: loaded program #158 has differing tag: "938c70b5a8956ff2" doesn't match "e007bfbbf37171f0"`

Second, **atomic program replacement via `bpf_link`.** On upgrade, the new program is loaded and pinned as `program-upgrade`, the link is updated to point at it (atomically), then the pin file is replaced by `rename`.

Your scenario needs both: the loader binary will iterate with releases while the in-kernel program may have been running for weeks. **Nothing currently prevents "a new loader operating an old BPF program's maps"** — if you ever change the map key structure or slot semantics, a new loader will write incompatible data into the old program's map. `assert_open_ports_max_entries` checks only `max_entries=131072`, which is nowhere near sufficient.

**Recommendation**: pin the program and link; introduce prog tag (or a custom version map) verification; upgrade via link update rather than detach/attach. Note also that `flock` currently locks `/run/waf-sklookup/loader.lock`; Tubular found BPF maps cannot be flocked (it returns an I/O error) and therefore locks the pin directory [2]. Locking a regular file is fine here — `/run` is cleared on reboot, as are bpffs pins, so the lifetimes align correctly.

### 6.3 Quota ceiling (128/host) is wildly inconsistent with map capacity (131072)

`policy.rs` defaults to `max_ports_per_tenant = 32` and `max_ports_per_machine = 128`, while `open_ports` has `max_entries = 131072` and the repository runs 30K/60K bulk-fill benchmarks (M3). Three orders of magnitude apart.

More notably, `ctl.rs` requires `M3_FULL_LADDER=1` for `bulk`/`fill` operations above 10,000 ports — **indicating the bulk path bypasses, or partially bypasses, quota validation.** `desired.rs`'s `load_from_reader_with_policy` does call `policy::validate` at the end, but some bulk paths carry `-no-file` and mutate only the live map. This consistency needs resolving: **if the map can hold 60,000 ports while the desired-state file permits only 128, the "file is the single source of truth" contract is broken**, and `status`'s `file_map_agree` will be permanently false.

On memory, the P1-a finding is correct and important: `open_ports` memlock is a constant 10,487,488 bytes (~10.5MB) **because the kernel pre-charges against `max_entries` regardless of actual population**, and this does not count toward process RSS. This belongs in the capacity-planning documentation to prevent operator misreadings.

**Recommendation**: raise quotas to match real business scale and unify validation across bulk paths; or conversely reduce `max_entries` to what is actually needed to reclaim memlock (10MB is modest, but at high deployment density 10MB per host is still cost). The key is making quota, map capacity, and benchmark scale mutually consistent.

### 6.4 Failure recovery is heavily manual

`docs/recovery.md` lists fourteen failure scenarios, each mapped to a `scripts/recover.sh <case>` command, and states explicitly that "A case name is required. No argument or an unknown argument prints usage and exits 2 with no recovery" — **no auto-detection, no auto-recovery.** Scenario 5 (worker crash storm) and scenario 12 (systemd StartLimit exhausted) simply say "human intervention."

This is a responsible posture for a demo (better to do nothing than the wrong thing), but production needs more automation. In particular:

- The systemd unit uses `OnFailure=waf-sklookup-loader-failed.service` to **stop OpenResty** when the loader fails, combined with `StartLimitBurst=3`, to be fail-closed. That policy is severe: after three rapid failures, OpenResty stays down awaiting a human. In production, "the loader is dead but OpenResty still serves genuinely bound ports" is usually more acceptable than taking the whole host out, especially when virtual ports carry only a subset of customers. **The granularity of fail-closed — whole host versus per port — needs a product-level decision.**
- `scripts/recover.sh` retains the pre-E6 two-field awk validator, which `docs/binding.md` explicitly says "is incompatible with the bound format." **The recovery script and the current desired-state format are already out of sync** — a consistency bug that must be fixed.

---

## 7. Performance Assessment

### 7.1 What the existing data does and does not establish

The repository's performance argument (`docs/perf-deep-compare.md`) is correct in principle: `sk_lookup` fires only when the kernel needs to find a listening socket, and **traffic on established connections never enters the hook** [1]. Therefore the steady-state datapath is identical to direct engine access, with zero extra userspace hops. This is a fundamental advantage over PROXY + thin-accept (which structurally adds a userspace forwarding entity), and it is the core reason I endorse this direction.

The measurements support it: G1 rps ratios are HTTP 1.113 / HTTPS 1.003, and G2 p99 absolute deltas are HTTP 2.704ms / HTTPS 0.025ms. **The near-zero HTTPS delta is the most persuasive evidence** — since TLS dominates CPU, a fixed BPF tax should be visible there too, and it measures 0.025ms.

But these numbers **cannot support a claim of "no production performance regression"**, for the following reasons:

| Limitation | Detail | Impact |
|---|---|---|
| Single worker | `worker_processes 1` (config comments call it "intentional for this demo") | Production's multi-worker + reuseport dispatch path is entirely uncovered |
| QPS far too low | keepalive throughput of only 275–346 rps | Two to three orders of magnitude below production; lock contention and cache behavior differ completely |
| Too few ports | G2 uses only three ports | Map-scale effects on lookup uncovered (hash is O(1), but cache locality changes) |
| Extremely noisy environment | A/B order swap flips p99 ratio from 1.2897 to 0.5628; `c=1` yields 1.0303 | **The same metric can go Fail → Pass → inverse-Fail, meaning the environment is untrustworthy** |
| Non-standard tooling | Image `apt` returned 502, so wrk/ab were unavailable; a bespoke `tools/httpbench` was used | Results are hard to compare against industry baselines and hard to reproduce |
| Lua `/proc` scan contamination | Stubbing resolve dropped p99 abs from 19ms to 0.5ms | **Every absolute latency figure is severely contaminated by this defect and must be re-measured after the fix** |

The G2 investigation (`docs/repro-g2-http-p99.md`) is actually a positive case study — the team honestly recorded contradictory evidence ("sign flips on B-then-A," "rel still 1.34 after stubbing," "passes at c=1") and explicitly refused to green-bar by loosening the threshold ("Do not raise `RATIO_MAX`"). That discipline is worth preserving. But the conclusion is equally clear: **relative metrics measured in this environment are not trustworthy.**

### 7.2 Qualitative comparison against alternatives

![Four-approach comparison](assets/compare.png)

How to read this: `sk_lookup` is genuinely best across the four performance and elasticity axes, with its cost concentrated in observability maturity and operational complexity — which happens to be your third goal. **The technical strengths and the risks you worry about most are complementary on the same chart, which is itself the argument that closing the observability gap is the critical path to production, not a nice-to-have.**

### 7.3 Re-calibration plan

After fixing 4.3 (the Lua `/proc` scan), performance testing must be redone under these conditions:

| Dimension | Requirement |
|---|---|
| Environment | Same hardware model as production, dedicated, CPU-pinned, power-saving and SMT interference disabled |
| Engine | Production worker count (e.g. 16/32), `reuseport` enabled |
| Tooling | wrk2 (constant-rate to avoid coordinated omission) or `h2load`; do not gate on a bespoke tool |
| Port scale | Same port set measured with 10 / 1,000 / 10,000 / 60,000 map entries |
| Control | Genuinely `bind()`ed port on the same host as leg A, virtual port as leg B, alternating rounds, median |
| Metrics | Connection CPS, TLS handshake CPS, keepalive throughput, p99/p999, and **CPU cycles per request** (via `perf stat`, not rps alone) |
| Change perturbation | p99 spike and recovery time on a sustained load leg while bulk adding/removing 1,000/10,000 ports |

"CPU cycles per request" matters most. Environment noise can mask rps and p99, but `perf stat` cycles/instructions counts are highly sensitive to fixed path overhead and are the most reliable way to determine whether BPF imposes a tax at all.

---

## 8. Observability Target State

This is where the work concentrates and where it is least optional. The objective: **when a customer's port becomes unreachable in production, the responsible component can be identified without logging into the host.**

![Observability target state](assets/obs.png)

### 8.1 Required dataplane counters

Add a `BPF_MAP_TYPE_PERCPU_ARRAY` (avoiding atomic overhead) with the following dimensions:

| Metric | Meaning | Purpose |
|---|---|---|
| `assign_ok` | `bpf_sk_assign` succeeded | Baseline; reconcile against nginx accept counts |
| `assign_err_eexist` | `-EEXIST`: already selected by another BPF program | Diagnose conflicts with other BPF components (see 5.3) |
| `assign_err_afnosupport` | `-EAFNOSUPPORT`: family mismatch | Diagnose IPv6 traffic entering wrongly (see 4.4) |
| `assign_err_socktnosupport` | `-ESOCKTNOSUPPORT`: socket not in LISTEN state | Diagnose a stale fd in the slot (see 5.1) |
| `assign_err_other` | Other errnos | Catch-all |
| `no_slot` | Sockmap slot empty | Maps directly to the "empty slot" failure scenario |
| `invalid_slot` | Slot value > 1 | Map corruption or version mismatch |
| `port_miss` | Port absent from `open_ports`, took `SK_PASS` | Distinguish "traffic arrived but port not open" from "traffic never arrived" |

Splitting `assign_err_*` is the key move. The current `return err ? SK_DROP : SK_PASS` collapses every failure cause into one indistinguishable black hole, whereas these errnos correspond to entirely different failure scenarios and remediation actions [3].

Additionally, add a `BPF_MAP_TYPE_RINGBUF` for **rate-limited sampling** of abnormal cases (every non-`assign_ok` branch), reporting the 4-tuple plus errno. The `sk_lookup` program type supports `bpf_ringbuf_output` and `bpf_perf_event_output` [10], so there is no implementation obstacle. Rate limiting is mandatory — during an anomaly storm, reporting must not become the bottleneck.

If per-port attribution is needed, add a `PERCPU_HASH` for per-port counters, but evaluate memory and lookup cost at 60,000 ports; I recommend per-port dimensions only on the anomaly counters, keeping the success path global.

### 8.2 Required control-plane state

`ctl status`'s existing `real`/`virtual`/`overlap`/`drift`/`frozen` is a good start. Additions needed:

| State | Today | Needed |
|---|---|---|
| Listen slot health | None | Per-slot fd validity, corresponding inode, whether still in the LISTEN set, last rescan time and result |
| Rescan statistics | Logs only | Rescan count, swap count, failure count (to detect worker churn) |
| BPF program identity | Only `max_entries` | prog id, prog tag, link id, attached netns inode |
| bpffs and pins | None | Whether pins exist, whether bpffs is mounted |
| Other `sk_lookup` programs in the netns | None | Enumerated list (to detect conflict risk) |
| Desired-state version | Timestamp only | Central desired-state version/digest, to confirm a push took effect |

### 8.3 Export mechanism

Adopt Tubular's mature pattern directly [2]: a separate **read-only exporter** process opening pinned maps with `BPF_OBJ_GET` + `BPF_F_RDONLY`, exposing Prometheus `/metrics`. Set pin file mode to owner-write, group-read (`-rw-r-----`) and run the exporter as a dedicated non-root user in that group. Two pitfalls: systemd mounts `/sys/fs/bpf` too restrictively, requiring `chmod o+x /sys/fs/bpf`; and if the distribution sets the `unprivileged_bpf_disabled` sysctl, the exporter still needs `CAP_BPF` [2].

### 8.4 Required alerts

| Alert | Condition | Severity |
|---|---|---|
| Slot empty or fd stale | `no_slot` or `assign_err_socktnosupport` rate > 0 | P0 — all virtual ports refusing new connections |
| Desired-state drift | `drift.put + drift.delete != 0` for > 1 minute | P1 — configuration not in effect |
| Rising assign failure rate | `assign_err_* / (assign_ok + assign_err_*)` above threshold | P1 |
| Prog tag drift | In-kernel program tag ≠ expected tag | P1 — version mismatch |
| Pin or bpffs lost | Pin file missing or bpffs unmounted | P0 |
| Conflicting ports appear | `overlap_count > 0` | P1 |
| Loader absent | Process/unit missing | P0 |
| Unknown `sk_lookup` program in netns | Enumeration changed | P2, but must be known |

### 8.5 An easily missed operational consequence

To restate: **`ss -lnt`, `netstat -lnp`, and every tool built on them cannot see these virtual ports.** This affects port-occupancy inspection, capacity reconciliation, security-scan baseline comparison, first-response debugging, and the port inventory in your CMDB. All of these processes need parallel adaptation, and the adaptation list should be handed to the operations team before go-live. Cloudflare's answer was `tubectl bindings` as a supplement to `ss` [2]; you need an equivalent command that operators will actually adopt, wired into existing inspection systems.

---

## 9. Recommended Rollout Path

![Rollout path](assets/roadmap.png)

Five phases, with the key point that **Phase 0 is a decision gate — do not commit engineering resources beyond it until it clears.**

### Phase 0: Decision and Loss Prevention (1–2 weeks)

Three questions need answers:

**Kernel baseline inventory.** `sk_lookup` requires Linux ≥ 5.9 [1]. Inventory the kernel version distribution across production WAF hardware, the share of non-compliant hosts, and the upgrade schedule. If a substantial fraction runs older kernels, this design can only cover part of the fleet for the medium term; the control plane needs a capability flag for "can this host use virtual ports," and the product side must accept inconsistent port-provisioning capability.

**Engine version decision.** Tengine 3.1.0+'s `https_allow_http` is a precondition for dual-protocol on a single port [6] [7]. Either upgrade the engine, maintain a patch (accepting the security-tracking cost [8]), or accept the product degradation of pre-separating HTTP and HTTPS ports in the control plane. **Much of Phase 1's design will be reworked if this is not settled first.**

**Multi-worker dispatch semantics.** Option A (own sharding + `NO_REUSEPORT`) or Option B (rely on the reuseport group) from 4.1 must be chosen and documented, because it determines the sockmap structure and the rescan implementation.

Phase 0 exits with one of three conclusions: proceed; do a PROXY transition first and return later; or abandon.

### Phase 1: Dataplane Correctness Rework (3–4 weeks)

In priority order: add `family` / `local_ip4` / IPv6 matching on the BPF side (4.4); rework `redir_socket` per the decision (4.1); switch external-port resolution to `ssl.server_port()` or `getsockname()` (4.3); add prog tag verification and pinned `bpf_link` (6.2); convert rescan to event-driven with health checks (5.1).

Exit criteria: single-host functional and semantic correctness fully green — multi-VIP isolation effective, IPv6 traffic not silently dropped, multi-worker dispatch matching the design, and no `/proc` scan in the request path.

### Phase 2: Observability Build-Out (2–3 weeks)

Implement the target state from section 8. Exit criterion: **without logging into the host, the question "why is this customer's port unreachable?" can be answered.** That criterion is more meaningful than "metrics are complete" and is the recommended acceptance test.

### Phase 3: Gate Re-Calibration (3–4 weeks)

Re-run every performance gate under the conditions in 7.3. Both G2's relative-ratio threshold and G6's hot-update threshold need re-calibration in a real environment — the current rel ≤ 1.05 is indeed harsh against a 9ms baseline, but **re-calibration must happen in a real environment, not by tuning thresholds in a noisy one to produce a green bar.** Add chaos drills: kill the loader, remove pins, unmount bpffs, OOM, worker crash storm, full host reboot.

### Phase 4: Staged Rollout (6–8 weeks)

Single-host canary **while retaining a PROXY fallback track.** `docs/design-thin-accept-openresty.md` already designs PROXY v2 + thin-accept, but P1-d's verdict was "PROXY-fallback: no PROXY implementation in the repository → N/A/blocked," and the current fallback path is merely "connect directly to internal 8080." For production, **fail-closed without a usable degradation path is insufficient** — you need a standby dataplane that can keep serving when the BPF path breaks. Otherwise, a kernel-level problem leaves you with only one mitigation, "disable the feature," at which point those customers' ports all go dark.

During rollout, retain one-shot `freeze` / `close-all` (already implemented in `freeze.rs`) and make an explicit decision on fail-closed granularity — whole host versus per port (see 6.4).

---

## 10. Closing Judgments

**On whether to continue.** Continue. The direction is correct, the theoretical advantage is real, and Cloudflare's production validation lowers the technical risk [2]. The code and acceptance framework you have accumulated also carry genuine value — particularly the gate definitions and the G2 root-cause methodology, which many teams lack entirely.

**On timeline.** From the current state to stable production operation, I estimate four to five months, of which Phases 1 and 2 are not compressible. If business pressure is high, consider **shipping PROXY + thin-accept within one to two months to relieve the immediate pain** (its product semantics are easy to get right and the risk is contained) while advancing `sk_lookup` in parallel and switching the dataplane once the gates pass. `docs/perf-deep-compare.md` already proposes this dual-track approach, and I consider it pragmatic.

**On Rust.** Continue with Rust in userspace; return to C in the kernel. This is not a rejection of Rust but a recognition that the kernel side holds thirty lines of logic, while the current Rust implementation introduces `transmute`d helper IDs, faked BTF structures, a post-build patch script, and a nightly toolchain dependency — risk far exceeding the benefit. Revisit once the Aya ecosystem matures.

**On using the demo data.** I recommend **not presenting the existing G1–G10 results as evidence of "no performance regression."** They demonstrate "no obvious problem in principle," but the environmental limitations (single worker, a few hundred rps, Lua `/proc` contamination, conclusions that flip on A/B reordering) make them unrepresentative of production. Only data re-measured on real hardware after fixing 4.3 will be persuasive — and that data will look considerably better, because the dominant latency source today is a fixable Lua defect, not BPF.

**On the most underestimated item.** If only one thing can be prioritized, I would choose **observability** (section 8) over performance optimization. Performance problems surface in load testing; the cost of missing observability only materializes during a production incident, at which point no data is available. The fact that `ss` cannot see virtual ports is especially dangerous, because it silently invalidates every existing inspection tool.

---

## References

[1] [BPF sk_lookup program — The Linux Kernel documentation](https://docs.kernel.org/bpf/prog_sk_lookup.html)

[2] [Production ready eBPF, or how we fixed the BSD socket API — Cloudflare Blog](https://blog.cloudflare.com/tubular-fixing-the-socket-api-with-ebpf/)

[3] [Helper function bpf_sk_assign — eBPF Docs](https://docs.ebpf.io/linux/helper-function/bpf_sk_assign/)

[4] [Run a BPF program on socket lookup — LWN.net](https://lwn.net/Articles/819618/)

[5] [PSA: Using quic_bpf + reuseport will eventually drop HTTP/3 traffic — NGINX Community](https://community.nginx.org/t/psa-using-quic-bpf-reuseport-will-eventually-drop-http-3-traffic/9137)

[6] [Tengine ChangeLog — https_allow_http of listen](https://tengine.taobao.org/changelog.html)

[7] [https listener allow http request with a directive — alibaba/tengine issue #1751](https://github.com/alibaba/tengine/issues/1751)

[8] [Fixing CVE-2026-42945 in Tengine Servers — Orca Security](https://orca.security/resources/blog/tengine-servers-nginx-vulnerability/)

[9] [ngx.ssl — Lua API for controlling NGINX downstream SSL handshakes](https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/ssl.md)

[10] [Program type BPF_PROG_TYPE_SK_LOOKUP — eBPF Docs](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SK_LOOKUP/)

[11] [cloudflare/tubular — BSD socket API on steroids](https://github.com/cloudflare/tubular)
