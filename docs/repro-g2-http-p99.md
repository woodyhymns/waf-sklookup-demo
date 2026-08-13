# Localization / reproduction pack: G2 HTTP relative p99

**Status:** Hold merge · do **not** relax gates · do **not** start Rust  
**Baseline code:** `main@09d138b` (M2 bulk / open_ports)  
**Evidence tip:** `test/prod-gng-acceptance` @ `a9a4009` / docs tip `662cfaf` (PR [#9](https://github.com/woodyhymns/waf-sklookup-demo/pull/9) draft)  
**Owner:** Repro (pack) · Test (measurement) · Repo (path)

---

## 0. Symptom (locked)

| Gate | Metric | HTTP | HTTPS | Threshold | Result |
|------|--------|------|-------|-----------|--------|
| G2 abs | \|p99_B − p99_A\| | **2.704 ms** | 0.025 ms | ≤ 10 ms | **Pass** |
| G2 rel | p99_B / p99_A | **1.2897** | 1.0056 | ≤ **1.05** | **Fail (HTTP)** |

Primary method (block-order):

| proto | med_p99_A_us | med_p99_B_us | abs_diff_ms | p99_ratio |
|-------|--------------|--------------|-------------|-----------|
| HTTP | 9334 | 12038 | 2.704 | **1.2897** |
| HTTPS | 4461 | 4486 | 0.025 | 1.0056 |

Same conclusion on prior calibrated attempts: paired ABAB @c=8 (~1.30), ABAB @c=4 (**1.3876**).  
G6 hot-update p99 ratio **1.83** remains Fail — **parked** this pack; prioritize HTTP G2 asymmetry.

Full log: [acceptance-prod-gng-g2g6-last.log](acceptance-prod-gng-g2g6-last.log) · short table: [acceptance-prod-gng-g2g6-last.md](acceptance-prod-gng-g2g6-last.md) · gates: [acceptance-prod-gng.md](acceptance-prod-gng.md).

---

## 1. Minimal reproduction (someone else must see HTTP rel Fail)

### 1.1 Environment

| Item | Value |
|------|--------|
| Engine | **HAH** OpenResty `OPENRESTY_PREFIX=/usr/local/openresty-hah` (1.19.3.2 + `https_allow_http`) |
| Conf | `openresty/nginx.tengine-https-allow-http.conf.example` |
| Loader | Product single-listen: **no** `-tls-ports` (`LOADER_TLS_PORTS=""`) |
| Kernel | ≥5.9 + `sk_lookup`, root/CAP_BPF |
| Bench | `tools/httpbench` only (no wrk/ab) |
| Legs | **A** direct `127.0.0.1:8080` · **B** sk_lookup `127.0.0.1:18081` |
| Model | One internal listen, dual protocol (HTTP+HTTPS on `:8080`) |

```bash
# Build HAH once if missing (does not overwrite /usr/local/openresty)
./third_party/https_allow_http/build-openresty-hah.sh
export OPENRESTY_PREFIX=/usr/local/openresty-hah
"$OPENRESTY_PREFIX/bin/openresty" -v   # openresty/1.19.3.2
```

### 1.2 One-shot (preferred)

```bash
cd /path/to/waf-sklookup-demo
git fetch origin
git checkout a9a4009   # or tip of test/prod-gng-acceptance that contains the calibrated scripts

export CGO_ENABLED=0
export OPENRESTY_PREFIX=/usr/local/openresty-hah
export OPENRESTY_NGINX_CONF=openresty/nginx.tengine-https-allow-http.conf.example
export LOADER_TLS_PORTS=""

make certs
go build -o bin/httpbench ./tools/httpbench
make build

# Starts HAH demo if :18081 not already up
./scripts/accept-prod-g2-latency.sh
# Expect exit 1 · G2_ABS_RESULT=Pass · G2_REL_RESULT=Fail
# Look for: G2_HTTP: ... ratio=1.2x… rel_ok=0
#           G2_HTTPS: ... ratio≈1.00… rel_ok=1
```

Defaults inside script (do **not** loosen for a green bar):

- `keepalive` · `warmup=3s` · `d=20s` · `c=8` · `N=5` · median-of-N  
- abs ≤10 ms · rel ≤1.05  

### 1.3 Manual legs (same math)

```bash
# After demo is up (run-openresty-demo.sh start with HAH env above):
HB=./bin/httpbench
W=(-keepalive -warmup 3s -d 20s -c 8 -k)

# Leg A HTTP (×5), then Leg B HTTP (×5) — primary block order
for i in 1 2 3 4 5; do
  $HB -url http://127.0.0.1:8080/  "${W[@]}" -label A-http-s$i
done
for i in 1 2 3 4 5; do
  $HB -url http://127.0.0.1:18081/ "${W[@]}" -label B-http-s$i
done

# Then HTTPS A×5 / B×5 on the SAME ports (HAH)
for i in 1 2 3 4 5; do
  $HB -url https://127.0.0.1:8080/  "${W[@]}" -label A-https-s$i
done
for i in 1 2 3 4 5; do
  $HB -url https://127.0.0.1:18081/ "${W[@]}" -label B-https-s$i
done
```

Compute per proto: `med_p99 = median(p99_us of 5 samples)`, `ratio = med_B / med_A`, `abs_ms = |med_B − med_A| / 1000`.

### 1.4 Expected contrast

| Check | Expect |
|-------|--------|
| `ss -lntp` | LISTEN only `127.0.0.1:8080` (no userspace `:18081`) |
| HTTP rel | **Fail** (ratio ≳ 1.25–1.40 in prior runs) |
| HTTPS rel | **Pass** (~1.00) |
| HTTP abs | **Pass** (~1.4–2.7 ms ≪ 10) |
| fail= | 0 on all RESULT lines |

If HTTP rel unexpectedly Passes on a quiet pinned box, capture full RESULT lines + `vmstat`/`mpstat` and notify Test — do **not** change `RATIO_MAX`.

### 1.5 Optional sensitivity (still must not change gates)

```bash
# Reverse block order (B then A) — isolates “B runs hotter” story
G2_HTTP_ONLY=1  # if added later; else edit script / run manual B-then-A

# Lower concurrency (already Fail @c=4)
G2_CONCURRENCY=4 ./scripts/accept-prod-g2-latency.sh

# Short connections (diagnostic): omit -keepalive in a one-off manual run
# Compare whether HTTP A/B gap shrinks (connect-path / sk_lookup) or stays (per-request Lua)
```

---

## 2. Root-cause hypothesis table (ordered)

**Rank rule (Repo 2026-08-13):** put **order/thermal** and **gate sensitivity** first; treat Lua `/proc` scan as an **amplifier**, not the lead story. Still exclude BPF/reuseport as primary. **Do not raise `RATIO_MAX`** — Hold merge until understood.

Legend: **V** verified by evidence · **U** unverified (next probe) · **X** excluded / weak · **Amp** amplifier

| Rank | ID | Hypothesis | Status | Why |
|------|----|------------|--------|-----|
| 1 | **H_order** | Keepalive + `worker_processes 1` + **A→B block order** / thermal drift | **V (sign)** | Probe1 B-then-A ratio=0.5628 (flip). A-http p99 drifts 5.9→11.3 ms inside one block; B runs after A on a hot single worker. ABAB shows **opposite signs** (HTTP ratio >1, HTTPS ratio <1) with `RATIO_MIN=0` (ratio <1 counts Pass) — order/noise can flip the relative story. |
| 2 | **H_gate** | Rel ≤1.05 is tight vs ~ms noise on a ~9 ms baseline | **U / framing** | Abs already **Pass** (~2.7 ms ≪ 10). A 2–3 ms gap ⇒ ratio ~1.29. Explains Fail **shape**; **not** a license to loosen the locked gate. |
| 3 | **H7** | Per-request Lua `/proc/self/net/tcp` scan (`external_port.lua`) | **Amp V (abs) / X (rel root)** | Stub: abs ~19ms to 0.5ms, ratio still 1.3372. Lua is abs amp, not rel root. |
| — | H1 | Fixed per-request BPF `sk_lookup` tax (~30%) | **X** | No protocol branch in BPF; same sockmap slot0; HTTPS abs≈0 / rel≈1.0. |
| — | H2 | Absolute path “too slow” for abs gate | **X** | HTTP abs 2.7 ms **Pass**. |
| — | H4 | Median / ABAB math bug | **X** | Same aggregator; HTTPS Pass. |
| — | H5 | fail/retries inflate B | **X** | `fail=0`. |
| — | H6 | Multi-worker / reuseport skew | **X** | `worker_processes 1`. |
| — | H8 | HTTPS masks overhead | **Amp-ish** | TLS dominates level; does not by itself prove A→B cause. |
| — | H9 | httpbench pool keyed by URL | **X weak** | Short-conn still ratio 1.2515 -- not keepalive-pool-only. |
| — | H10 | Map pressure (G6) | **Parked** | G2 uses ~3 ports; G6 separate. |
| — | H11 | Wrong 8080/8443 product model | **X** | HAH + empty `LOADER_TLS_PORTS`. |

### Priority experiments (Test / Repo)

| # | Experiment | Interprets |
|---|------------|------------|
| E1 | B-then-A keepalive | **Done** -- ratio 0.5628 (sign flip) |
| E2 | A-A / B-B same-leg | Optional leftover |
| E3 | stub resolve | **Done** -- abs collapsed, rel 1.3372 |
| E4 | short-conn | **Done** -- ratio 1.2515 |

### What the numbers already say

```
HTTP  A p99 samples (us): 5911, 9422, 11324, 8742, 9334  → med 9334
HTTP  B p99 samples (us): 12239, 8505, 12038, 12559, 11735 → med 12038
HTTPS A: 8467, 6216, 4461, 4234, 4243 → med 4461
HTTPS B: 4280, 4486, 4409, 5051, 4627 → med 4486
```

- HTTP gap is **milliseconds**, not tens of microseconds → prefer userspace / scheduling / Lua over raw BPF helper cost.  
- HTTPS nearly flat → any true sk_lookup datapath tax is **≪** HTTP gap or masked.  
- Do not “fix” by raising `RATIO_MAX` or switching to abs-only.

---

## 2.1 Test measurement handoff (2026-08-13)

Source: Test agent · same evidence tip · **Hold merge**. No full G2+G6 re-fire.

**Commands / ports** — confirmed identical to §1:

- A: `http(s)://127.0.0.1:8080/` · B: `http(s)://127.0.0.1:18081/`
- `OPENRESTY_PREFIX=/usr/local/openresty-hah` · tengine HAH conf · `LOADER_TLS_PORTS=""`
- keepalive · warmup=3s · d=20s · c=8 · N=5 · one-shot `./scripts/accept-prod-g2-latency.sh`

**Median math** — confirmed: N=5 odd → middle after sort (`median_of`); HTTP 9334/12038 → **1.2897**.

| Measurement bias item | Test status |
|-----------------------|-------------|
| Pure ABAB order artifact | **Partially excluded** — block-order still Fail |
| Seconds-scale noise / abs gate | **Excluded** as sole cause (abs≈2.7ms Pass) |
| Missing warmup | **Excluded** (warmup=3s) |
| Same-box CPU contention / thermal | **V for sign** — A-http p99 drifts 5.9→11.3ms within block |
| Rel gate sensitive on ~9ms baseline (2–3ms → ratio>1.05) | **Noted** — explain Fail shape; **do not raise RATIO_MAX** |
| CPU pin / isolated cores | **Not yet run** |
| keepalive vs short / B→A / c=1 | **Done** -- see sec 2.3 |

Path ownership: measurement bias → Test; path hypotheses (H7 Lua `/proc` etc.) → this pack / Repo.

---

## 2.2 Repo code-path handoff (2026-08-13)

Source: Repo agent · Hold merge PR #8/#9.

| Code claim | Pack mapping |
|------------|--------------|
| `dispatch.bpf.c` has **no** protocol branch; A/B same sockmap slot 0; `worker_processes 1` | Strengthens **H1 X** / **H6 X** |
| HTTPS abs≈0 ⇒ ~2.7 ms kernel tax **not** primary | Strengthens **H1 X** |
| `external_port.lua` linear `/proc` then getsockname | = **H7 amplifier** (not lead); stub / getsockname-first still useful |
| Suggested experiment: **getsockname-first** or getsockname-only, re-run G2 | Aligns §3.1 M3/M4 |
| Rel gate harsh on ~9 ms baseline; A→B thermal secondary | Aligns §2.1 Test notes — **do not raise gate** |
| HAH `https_allow_http` can raise HTTP baseline vs HTTPS | Explains level shift, **not** A→B gap |

Files cited: `dispatch.bpf.c` · `openresty/nginx.tengine-https-allow-http.conf.example` · `openresty/lua/waf/external_port.lua` · `scripts/accept-prod-g2-latency.sh`.

---


## 2.3 Test probe results (2026-08-13 ~10:29 CST)

Source: Test. Method: httpbench c=8 d=20s warmup=3s N=5, median p99_us, ratio=med_B/med_A. RATIO_MAX=1.05 unchanged. Lua restored after stub. No full G2+G6 re-fire.

Baseline: HTTP A-then-B keepalive rel=**1.2897** (medA=9334 medB=12038).

| # | Probe | med_A_us | med_B_us | ratio | Read |
|---|-------|----------|----------|-------|------|
| 1 | **B-then-A keepalive** | 19329 | 10879 | **0.5628** | Sign **flipped**. Later block slower. **H_order**, not a fixed path tax. |
| 2 | **short-conn A-then-B** (no keepalive) | 216561 | 271028 | **1.2515** | Rel still Fail (~1.25). Not keepalive-only. (p99 is connect-bound, hundreds of ms.) |
| 3 | **stub resolve() A-then-B keepalive** (constant `"18081"`, no `/proc` scan) | 513 | 686 | **1.3372** | Abs **~19ms to ~0.5ms**; ratio still ~1.34. Lua is **abs amplifier**, **not rel root**. |

Logs in-tree: [g2-probes/probe-summary.txt](g2-probes/probe-summary.txt), [probe-b-then-a.log](g2-probes/probe-b-then-a.log), [probe-short.log](g2-probes/probe-short.log), [probe-stub-resolve.log](g2-probes/probe-stub-resolve.log).

**Implication:** do **not** treat PR #10 getsockname-first as the G2 rel fix (abs hygiene only). Rel Fail is dominated by **block order / thermal** on a tight **H_gate**. Hold merge. Next optional: A-A/B-B stability + CPU pin (M5), not another full marathon.

---

## 3. Recommended next moves

### 3.1 Prefer **measurement** first (Test) — no gate change

| # | Probe | Pass criterion for the *probe* | Interprets |
|---|-------|--------------------------------|------------|
| M1 | **B→A** / **BAAB** HTTP blocks (same N/c/d) | Ratio collapses/flips vs 1.2897 → H_order | H_order |
| M2 | **A-A** / **B-B** same-leg stability | Large within-leg drift → thermal/contention | H_order |
| M3 | **Short-conn** HTTP (no `-keepalive`) | Gap shrinks → connect path; stays → per-request/amp | H7/H9 |
| M4 | **Stub resolve** / getsockname-first (temporary) | Ratio drop → H7 amp size; restore after | H7 Amp |
| M5 | Quiet box / CPU pin; re-run primary script | Stable Fail → real; flips → env note (still Hold) | H_order |
| M6 | Do **not** re-fire full G2+G6 marathon unless reproducing | — | — |

**H_gate note:** documenting that rel≤1.05 is harsh on a ~9 ms baseline is allowed; **changing `RATIO_MAX` is not.**

### 3.2 **Path** changes only after a probe pins blame (Repo)

| If probe says… | Change | Out of scope |
|----------------|--------|--------------|
| H7 abs amp (confirmed) | Optional PR #10 getsockname-first as **abs hygiene only** -- not G2 rel fix | Treating #10 as gate Pass |
| H_order (sign confirmed) | Cooldown between A/B blocks; document single-worker thermal; optional CPU pin | Relaxing `RATIO_MAX` |
| True BPF tax (unlikely) | Profile with bpftool; only then consider map/prog tweaks | Opening Rust “for speed” |

### 3.3 Explicit non-goals

- No merge of PR #9 while G2 rel or G6 Fail  
- No raising `G2_RATIO_MAX` / switching to abs-only Go  
- No Rust loader workstream from this pack  
- G6 ratio 1.83: track separately after HTTP G2 story is clear  

---

## 4. File map

| Path | Role |
|------|------|
| `scripts/accept-prod-g2-latency.sh` | G2 harness (block-order A then B) |
| `scripts/lib-prod-gng.sh` | HAH defaults, demo start/stop, httpbench |
| `tools/httpbench/` | Bench binary source |
| `openresty/lua/waf/external_port.lua` | Per-request port resolve (**H7 abs amp**, not rel root) |
| `openresty/nginx.tengine-https-allow-http.conf.example` | Product listen |
| `docs/acceptance-prod-gng-g2g6-last.{md,log}` | Calibrated evidence |
| `docs/g2-probes/` | Test three-shot logs |
| `docs/repro-g2-http-p99.md` | **This pack** |

---

## 5. One-line verdict for Json

HTTP G2 rel Fail is **order/thermal + tight rel gate**, not BPF and not Lua /proc as rel root. B-then-A **flips** to 0.56; stub drops abs 19ms to 0.5ms but rel stays **1.34**; short-conn still **1.25**. PR #10 is abs hygiene only. **Hold merge**, gates unchanged, no Rust.
