#!/usr/bin/env bash
# G2 calibrated latency: absolute p99 delta ≤10ms + relative ratio ≤1.05
# Paired A(direct :8080) vs B(sk_lookup :PORT), HTTP + HTTPS.
# Method: keepalive + warmup + longer window + low concurrency for ms-scale p99.
#
# Env (tunable):
#   WARMUP=3s DURATION=20s CONCURRENCY=8 N_SAMPLES=5
#   ABS_MS_MAX=10 RATIO_MAX=1.05 RATIO_MIN=0.95
#   OPENRESTY_PREFIX PORT HOST TARGET
set -euo pipefail
source "$(dirname "$0")/lib-prod-gng.sh"

STARTED_HERE=0
install_hygiene_traps

# Calibrated defaults (do not inherit P0 DURATION/CONCURRENCY from lib).
WARMUP="${G2_WARMUP:-${WARMUP:-3s}}"
DURATION="${G2_DURATION:-20s}"
CONCURRENCY="${G2_CONCURRENCY:-8}"
N_SAMPLES="${G2_N_SAMPLES:-5}"
ABS_MS_MAX="${G2_ABS_MS_MAX:-10}"
RATIO_MAX="${G2_RATIO_MAX:-1.05}"
# Locked relative gate is ≤1.05 only (ratio <1 means sk_lookup faster — OK).
RATIO_MIN="${G2_RATIO_MIN:-0}"

echo "=== G2 calibrated latency (abs delta ≤${ABS_MS_MAX}ms, ratio ≤${RATIO_MAX}) ==="
echo "method: keepalive warmup=${WARMUP} d=${DURATION} c=${CONCURRENCY} N=${N_SAMPLES}"
require_hah
ensure_httpbench
ensure_loader_bin

INTERNAL_HOST="${TARGET%%:*}"
INTERNAL_PORT="${TARGET##*:}"
[[ "$INTERNAL_HOST" == "$INTERNAL_PORT" ]] && INTERNAL_HOST="127.0.0.1" && INTERNAL_PORT="8080"

if ! curl -sS --max-time 2 "http://${HOST}:${PORT}/" >/dev/null 2>&1; then
  demo_start
  STARTED_HERE=1
fi

# Arrays of p99_us / rps per sample
declare -a AH_P99 AS_P99 BH_P99 BS_P99
declare -a AH_RPS AS_RPS BH_RPS BS_RPS
declare -a AH_FAIL AS_FAIL BH_FAIL BS_FAIL

run_one() {
  local label="$1" url="$2"
  "$HTTPBENCH_BIN" -url "$url" -d "$DURATION" -c "$CONCURRENCY" -keepalive \
    -warmup "$WARMUP" -k -label "$label"
}

median_of() {
  # stdin: one number per line → stdout median (float ok)
  sort -n | awk '
    { a[NR]=$1 }
    END {
      if (NR==0) { print 0; exit }
      if (NR%2==1) print a[int(NR/2)+1]
      else print (a[NR/2]+a[NR/2+1])/2
    }'
}

echo "--- per-protocol blocks N=${N_SAMPLES} (A-block then B-block; reduces ABAB order bias) ---"
echo "### HTTP leg A direct N=${N_SAMPLES}"
for i in $(seq 1 "$N_SAMPLES"); do
  line="$(run_one "A-http-s${i}" "http://${INTERNAL_HOST}:${INTERNAL_PORT}/")"
  echo "$line"
  AH_P99+=("$(percentile_from_result "$line" p99_us)")
  AH_RPS+=("$(percentile_from_result "$line" rps)")
  AH_FAIL+=("$(percentile_from_result "$line" fail)")
  sleep 0.5
done
echo "### HTTP leg B sk_lookup N=${N_SAMPLES}"
for i in $(seq 1 "$N_SAMPLES"); do
  line="$(run_one "B-http-s${i}" "http://${HOST}:${PORT}/")"
  echo "$line"
  BH_P99+=("$(percentile_from_result "$line" p99_us)")
  BH_RPS+=("$(percentile_from_result "$line" rps)")
  BH_FAIL+=("$(percentile_from_result "$line" fail)")
  sleep 0.5
done
echo "### HTTPS leg A direct N=${N_SAMPLES}"
for i in $(seq 1 "$N_SAMPLES"); do
  line="$(run_one "A-https-s${i}" "https://${INTERNAL_HOST}:${INTERNAL_PORT}/")"
  echo "$line"
  AS_P99+=("$(percentile_from_result "$line" p99_us)")
  AS_RPS+=("$(percentile_from_result "$line" rps)")
  AS_FAIL+=("$(percentile_from_result "$line" fail)")
  sleep 0.5
done
echo "### HTTPS leg B sk_lookup N=${N_SAMPLES}"
for i in $(seq 1 "$N_SAMPLES"); do
  line="$(run_one "B-https-s${i}" "https://${HOST}:${PORT}/")"
  echo "$line"
  BS_P99+=("$(percentile_from_result "$line" p99_us)")
  BS_RPS+=("$(percentile_from_result "$line" rps)")
  BS_FAIL+=("$(percentile_from_result "$line" fail)")
  sleep 0.5
done

med_AH=$(printf '%s\n' "${AH_P99[@]}" | median_of)
med_BH=$(printf '%s\n' "${BH_P99[@]}" | median_of)
med_AS=$(printf '%s\n' "${AS_P99[@]}" | median_of)
med_BS=$(printf '%s\n' "${BS_P99[@]}" | median_of)
med_AH_RPS=$(printf '%s\n' "${AH_RPS[@]}" | median_of)
med_BH_RPS=$(printf '%s\n' "${BH_RPS[@]}" | median_of)
med_AS_RPS=$(printf '%s\n' "${AS_RPS[@]}" | median_of)
med_BS_RPS=$(printf '%s\n' "${BS_RPS[@]}" | median_of)

# abs_diff_ms = |med_B - med_A| / 1000  (p99_us → ms)
eval_proto() {
  local name="$1" med_a="$2" med_b="$3" rps_a="$4" rps_b="$5"
  local abs_ms ratio rps_ratio
  abs_ms=$(awk -v a="$med_a" -v b="$med_b" 'BEGIN{
    d=b-a; if(d<0)d=-d; printf "%.3f", d/1000.0
  }')
  ratio=$(awk -v a="$med_a" -v b="$med_b" 'BEGIN{
    if(a<=0){print "inf"; exit}
    printf "%.4f", b/a
  }')
  rps_ratio=$(awk -v a="$rps_a" -v b="$rps_b" 'BEGIN{
    if(a<=0){print "inf"; exit}
    printf "%.4f", b/a
  }')
  local abs_ok=0 rel_ok=0
  awk -v v="$abs_ms" -v m="$ABS_MS_MAX" 'BEGIN{exit !(v+0 <= m+0)}' && abs_ok=1 || abs_ok=0
  # relative: ratio ≤ RATIO_MAX (and ≥ RATIO_MIN if set)
  awk -v v="$ratio" -v mx="$RATIO_MAX" -v mn="$RATIO_MIN" 'BEGIN{
    exit !(v+0 <= mx+0 && v+0 >= mn+0)
  }' && rel_ok=1 || rel_ok=0

  echo "G2_${name}: med_p99_A_us=${med_a} med_p99_B_us=${med_b} abs_diff_ms=${abs_ms} ratio=${ratio} rps_A=${rps_a} rps_B=${rps_b} rps_ratio=${rps_ratio} abs_ok=${abs_ok} rel_ok=${rel_ok}"
  # export for summary
  eval "G2_${name}_ABS_MS=${abs_ms}"
  eval "G2_${name}_RATIO=${ratio}"
  eval "G2_${name}_RPS_RATIO=${rps_ratio}"
  eval "G2_${name}_MED_A=${med_a}"
  eval "G2_${name}_MED_B=${med_b}"
  eval "G2_${name}_ABS_OK=${abs_ok}"
  eval "G2_${name}_REL_OK=${rel_ok}"
}

eval_proto HTTP "$med_AH" "$med_BH" "$med_AH_RPS" "$med_BH_RPS"
eval_proto HTTPS "$med_AS" "$med_BS" "$med_AS_RPS" "$med_BS_RPS"

# Scale check: warn if median p99 still seconds-scale (>100ms)
scale_note=""
for v in "$med_AH" "$med_BH" "$med_AS" "$med_BS"; do
  if awk -v u="$v" 'BEGIN{exit !(u+0 > 100000)}'; then
    scale_note="WARN: p99 still >100ms (seconds-scale risk); try CONCURRENCY=4 or check CPU starvation"
    break
  fi
done
[[ -n "$scale_note" ]] && echo "$scale_note" >&2

ABS_PASS=0
REL_PASS=0
[[ "${G2_HTTP_ABS_OK}" -eq 1 && "${G2_HTTPS_ABS_OK}" -eq 1 ]] && ABS_PASS=1
[[ "${G2_HTTP_REL_OK}" -eq 1 && "${G2_HTTPS_REL_OK}" -eq 1 ]] && REL_PASS=1

ABS_LABEL="Fail"
REL_LABEL="Fail"
[[ "$ABS_PASS" -eq 1 ]] && ABS_LABEL="Pass"
[[ "$REL_PASS" -eq 1 ]] && REL_LABEL="Pass"

echo
echo "### G2 summary"
echo "| proto | med_p99_A_us | med_p99_B_us | abs_diff_ms | p99_ratio | rps_ratio | abs | rel |"
echo "|-------|--------------|--------------|-------------|-----------|-----------|-----|-----|"
echo "| HTTP | ${G2_HTTP_MED_A} | ${G2_HTTP_MED_B} | ${G2_HTTP_ABS_MS} | ${G2_HTTP_RATIO} | ${G2_HTTP_RPS_RATIO} | ${G2_HTTP_ABS_OK} | ${G2_HTTP_REL_OK} |"
echo "| HTTPS | ${G2_HTTPS_MED_A} | ${G2_HTTPS_MED_B} | ${G2_HTTPS_ABS_MS} | ${G2_HTTPS_RATIO} | ${G2_HTTPS_RPS_RATIO} | ${G2_HTTPS_ABS_OK} | ${G2_HTTPS_REL_OK} |"
echo
echo "| 项 | 测了什么 | 结果 |"
echo "|----|----------|------|"
mark_row "G2 abs" "abs_diff_ms HTTP=${G2_HTTP_ABS_MS} HTTPS=${G2_HTTPS_ABS_MS} (≤${ABS_MS_MAX})" "$ABS_LABEL"
mark_row "G2 rel" "p99 ratio HTTP=${G2_HTTP_RATIO} HTTPS=${G2_HTTPS_RATIO} (≤${RATIO_MAX})" "$REL_LABEL"
mark_row "G1 sanity" "rps ratio HTTP=${G2_HTTP_RPS_RATIO} HTTPS=${G2_HTTPS_RPS_RATIO}" "info"
echo "method_note=keepalive+warmup=${WARMUP}+d=${DURATION}+c=${CONCURRENCY}+N=${N_SAMPLES} median-of-N"
[[ -n "$scale_note" ]] && echo "scale_note=$scale_note"

# Machine-readable for docs
echo "G2_ABS_RESULT=$ABS_LABEL"
echo "G2_REL_RESULT=$REL_LABEL"

if [[ "$ABS_PASS" -eq 1 && "$REL_PASS" -eq 1 ]]; then
  exit 0
fi
exit 1
