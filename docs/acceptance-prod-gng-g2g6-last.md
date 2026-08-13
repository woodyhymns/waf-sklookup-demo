# Production Go/No-Go G2/G6 calibrated retest (last run)

- tip (pre-commit): `bd5c895`
- when: 2026-08-13 09:48:37 CST (utc 2026-08-13T01:48:37Z)
- env: OPENRESTY_PREFIX=/usr/local/openresty-hah · conf=openresty/nginx.tengine-https-allow-http.conf.example · LOADER_TLS_PORTS=""
- engine: nginx version: openresty/1.19.3.2
- bench: tools/httpbench (-warmup) · no wrk/ab
- log: [acceptance-prod-gng-g2g6-last.log](acceptance-prod-gng-g2g6-last.log)

## Method

| Gate | Method |
|------|--------|
| G2 | keepalive + warmup=3s + d=20s + c=8 + N=5 median; **per-protocol A-block then B-block** (also tried paired ABAB @c=8 and @c=4) |
| G6 | warmup=2s + d=15s + c=12 + N_before=3 + N_during=3 median; bulk open/close 10k |

## Results

| 项 | 测了什么 | 结果 |
|----|----------|------|
| G2 abs | abs_diff_ms HTTP=2.704 HTTPS=0.025 (≤10) | **Pass** |
| G2 rel | p99 ratio HTTP=1.2897 HTTPS=1.0056 (≤1.05) | **Fail** (HTTP) |
| G6 ratio | med_during/med_before=1.8270 (≤1.10) | **Fail** |
| G6 open_ms | bulk open 10000 in 23ms (≤50) | **Pass** |
| G6 close_ms | bulk close half in 17ms (≤50) | **Pass** |
| G6 fail=0 | before/during/after total_fail=0/0/0 | **Pass** |

### G2 detail (block-order primary)

| proto | med_p99_A_us | med_p99_B_us | abs_diff_ms | p99_ratio | abs | rel |
|-------|--------------|--------------|-------------|-----------|-----|-----|
| HTTP | 9334 | 12038 | 2.704 | 1.2897 | Pass | Fail |
| HTTPS | 4461 | 4486 | 0.025 | 1.0056 | Pass | Pass |

Prior calibrated attempts (also Fail on HTTP rel):

- paired ABAB c=8: HTTP ratio ~1.30–1.39; abs Pass
- paired ABAB c=4: HTTP ratio **1.3876**; abs Pass (1.393ms)

### G6 detail

| phase | med_p99_us | med_rps | total_fail |
|-------|------------|---------|------------|
| before | 10715 | 1608.4 | 0 |
| during (after 10000 open) | 19576 | 833.2 | 0 |
| after (closed half) | 23423 | 787.95 | 0 |

- ratio=**1.8270** · open_ms=**23** · close_ms=**17**

## Overall

- G2 abs **Pass** · G2 rel **Fail** · G6 **Fail**
- **Hold merge** (need G2 abs AND G2 rel AND G6 Pass)
- Note: AFTER p99 worsened vs DURING on this box (CPU/thermal ratchet); ratio Fail is honest, not faked Pass.

See also: [Written gates (locked)](acceptance-prod-gng.md#written-gates-locked).
