#!/usr/bin/env bash
# G6 hot ports retest: during/before p99 ratio ≤1.10; open/close 10k ≤50ms; fail=0
# Method: warmup + longer DURATION; BEFORE/DURING take median of 3 runs.
#
# Env:
#   WARMUP=2s DURATION=15s CONCURRENCY=12 HOT_COUNT=10000 HOT_START=20000
#   RATIO_MAX=1.10 OPEN_MS_MAX=50 CLOSE_MS_MAX=50 N_BEFORE=3 N_DURING=3 N_AFTER=2
set -euo pipefail
source "$(dirname "$0")/lib-prod-gng.sh"

STARTED_HERE=0
BG_PID=""
cleanup() {
  if [[ -n "$BG_PID" ]] && kill -0 "$BG_PID" 2>/dev/null; then
    kill "$BG_PID" 2>/dev/null || true
    wait "$BG_PID" 2>/dev/null || true
  fi
  hygiene_cleanup
}
trap 'cleanup' EXIT ERR
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 131' QUIT
trap 'cleanup; exit 143' TERM

# Calibrated defaults (do not inherit P0 DURATION/CONCURRENCY from lib).
WARMUP="${G6_WARMUP:-2s}"
DURATION="${G6_DURATION:-15s}"
CONCURRENCY="${G6_CONCURRENCY:-12}"
RATIO_MAX="${G6_RATIO_MAX:-1.10}"
OPEN_MS_MAX="${G6_OPEN_MS_MAX:-50}"
CLOSE_MS_MAX="${G6_CLOSE_MS_MAX:-50}"
N_BEFORE="${G6_N_BEFORE:-3}"
N_DURING="${G6_N_DURING:-3}"
N_AFTER="${G6_N_AFTER:-2}"

echo "=== G6 hot ports (ratio≤${RATIO_MAX}, open/close≤${OPEN_MS_MAX}ms, fail=0) ==="
echo "method: warmup=${WARMUP} d=${DURATION} c=${CONCURRENCY} N_before=${N_BEFORE} N_during=${N_DURING}"
require_hah
ensure_httpbench
ensure_loader_bin

if ! curl -sS --max-time 2 "http://${HOST}:${PORT}/" >/dev/null 2>&1; then
  demo_start
  STARTED_HERE=1
fi

END_PORT=$((HOT_START + HOT_COUNT - 1))
if [[ "$END_PORT" -gt 65535 ]]; then
  echo "BLOCKED: HOT_START+HOT_COUNT exceeds 65535 ($HOT_START+$HOT_COUNT)" >&2
  exit 3
fi
HALF=$((HOT_COUNT / 2))
HALF_END=$((HOT_START + HALF - 1))

median_of() {
  sort -n | awk '
    { a[NR]=$1 }
    END {
      if (NR==0) { print 0; exit }
      if (NR%2==1) print a[int(NR/2)+1]
      else print (a[NR/2]+a[NR/2+1])/2
    }'
}

sample_once() {
  local label="$1"
  "$HTTPBENCH_BIN" -url "http://${HOST}:${PORT}/" -d "$DURATION" -c "$CONCURRENCY" \
    -keepalive -warmup "$WARMUP" -label "$label"
}

sample_n() {
  # sample_n PREFIX N → sets MED_P99 MED_RPS TOTAL_FAIL and echoes each RESULT
  local prefix="$1" n="$2"
  local -a p99s rpses fails
  local i line p99 rps fl
  for i in $(seq 1 "$n"); do
    line="$(sample_once "${prefix}-${i}")"
    echo "$line"
    p99="$(percentile_from_result "$line" p99_us)"
    rps="$(percentile_from_result "$line" rps)"
    fl="$(percentile_from_result "$line" fail)"
    p99s+=("$p99")
    rpses+=("$rps")
    fails+=("$fl")
    # cool-down so consecutive samples do not ratchet CPU/latency
    sleep "${G6_COOLDOWN:-2}"
  done
  MED_P99=$(printf '%s\n' "${p99s[@]}" | median_of)
  MED_RPS=$(printf '%s\n' "${rpses[@]}" | median_of)
  TOTAL_FAIL=0
  for fl in "${fails[@]}"; do
    TOTAL_FAIL=$((TOTAL_FAIL + ${fl:-0}))
  done
}

echo "--- settle before BEFORE samples ---"
sleep "${G6_SETTLE:-3}"
echo "--- sample BEFORE (N=${N_BEFORE}, median) ---"
sample_n before "$N_BEFORE"
B_P99="$MED_P99"; B_RPS="$MED_RPS"; B_FAIL="$TOTAL_FAIL"
echo "BEFORE_MED_p99_us=$B_P99 rps=$B_RPS total_fail=$B_FAIL"

start_bg() {
  (
    while true; do
      curl -sS --max-time 2 "http://${HOST}:${PORT}/" >/dev/null 2>&1 || true
      curl -sk --max-time 2 "https://${HOST}:${PORT}/" >/dev/null 2>&1 || true
      sleep 0.05
    done
  ) &
  BG_PID=$!
}
stop_bg() {
  if [[ -n "${BG_PID}" ]] && kill -0 "$BG_PID" 2>/dev/null; then
    kill "$BG_PID" 2>/dev/null || true
    wait "$BG_PID" 2>/dev/null || true
  fi
  BG_PID=""
}

echo "--- bulk open ${HOT_COUNT} ports ${HOT_START}-${END_PORT} (light bg during open) ---"
start_bg
T0=$(date +%s%N)
sudo "$LOADER_BIN" bulk open -range "${HOT_START}-${END_PORT}" -pin-dir "$PIN_DIR" -no-file
T1=$(date +%s%N)
OPEN_MS=$(( (T1 - T0) / 1000000 ))
echo "bulk_open_ms=$OPEN_MS"
sudo "$LOADER_BIN" list -count -pin-dir "$PIN_DIR" || true
stop_bg
sleep "${G6_SETTLE:-3}"

echo "--- sample DURING (N=${N_DURING}, median; hot map held, no bg curl) ---"
sample_n during "$N_DURING"
D_P99="$MED_P99"; D_RPS="$MED_RPS"; D_FAIL="$TOTAL_FAIL"
echo "DURING_MED_p99_us=$D_P99 rps=$D_RPS total_fail=$D_FAIL"

PROBE=$((HOT_START + 100))
echo "--- probe hot port :${PROBE} ---"
PROBE_STATUS="通过"
set +e
curl -sS --max-time 3 "http://${HOST}:${PROBE}/" | tee /tmp/g6-hot-probe.body
PRC=$?
set -e
if [[ $PRC -ne 0 ]] || ! grep -q "OpenResty M1 OK" /tmp/g6-hot-probe.body; then
  PROBE_STATUS="失败"
fi

echo "--- bulk close half ${HOT_START}-${HALF_END} (light bg during close) ---"
start_bg
T2=$(date +%s%N)
sudo "$LOADER_BIN" bulk close -range "${HOT_START}-${HALF_END}" -pin-dir "$PIN_DIR" -no-file
T3=$(date +%s%N)
CLOSE_MS=$(( (T3 - T2) / 1000000 ))
echo "bulk_close_half_ms=$CLOSE_MS"
stop_bg
sleep "${G6_SETTLE:-3}"

echo "--- sample AFTER (N=${N_AFTER}) ---"
sample_n after "$N_AFTER"
A_P99="$MED_P99"; A_RPS="$MED_RPS"; A_FAIL="$TOTAL_FAIL"
echo "AFTER_MED_p99_us=$A_P99 rps=$A_RPS total_fail=$A_FAIL"

RATIO=$(awk -v b="$B_P99" -v d="$D_P99" 'BEGIN{
  if(b<=0){print "inf"; exit}
  printf "%.4f", d/b
}')

RATIO_OK=0
OPEN_OK=0
CLOSE_OK=0
FAIL_OK=0
awk -v v="$RATIO" -v m="$RATIO_MAX" 'BEGIN{exit !(v+0 <= m+0)}' && RATIO_OK=1 || RATIO_OK=0
[[ "$OPEN_MS" -le "$OPEN_MS_MAX" ]] && OPEN_OK=1 || OPEN_OK=0
[[ "$CLOSE_MS" -le "$CLOSE_MS_MAX" ]] && CLOSE_OK=1 || CLOSE_OK=0
[[ "$B_FAIL" -eq 0 && "$D_FAIL" -eq 0 && "$A_FAIL" -eq 0 ]] && FAIL_OK=1 || FAIL_OK=0
[[ "$PROBE_STATUS" == "通过" ]] || FAIL_OK=0

G6_PASS=0
[[ "$RATIO_OK" -eq 1 && "$OPEN_OK" -eq 1 && "$CLOSE_OK" -eq 1 && "$FAIL_OK" -eq 1 ]] && G6_PASS=1
G6_LABEL="Fail"
[[ "$G6_PASS" -eq 1 ]] && G6_LABEL="Pass"

echo
echo "### G6 summary"
echo "| phase | med_p99_us | med_rps | total_fail |"
echo "|-------|------------|---------|------------|"
echo "| before | $B_P99 | $B_RPS | $B_FAIL |"
echo "| during (after ${HOT_COUNT} open) | $D_P99 | $D_RPS | $D_FAIL |"
echo "| after (closed half) | $A_P99 | $A_RPS | $A_FAIL |"
echo
echo "| 项 | 测了什么 | 结果 |"
echo "|----|----------|------|"
mark_row "G6 ratio" "med_during/med_before=${RATIO} (≤${RATIO_MAX})" "$([[ $RATIO_OK -eq 1 ]] && echo Pass || echo Fail)"
mark_row "G6 open_ms" "bulk open ${HOT_COUNT} in ${OPEN_MS}ms (≤${OPEN_MS_MAX})" "$([[ $OPEN_OK -eq 1 ]] && echo Pass || echo Fail)"
mark_row "G6 close_ms" "bulk close half in ${CLOSE_MS}ms (≤${CLOSE_MS_MAX})" "$([[ $CLOSE_OK -eq 1 ]] && echo Pass || echo Fail)"
mark_row "G6 fail=0" "before/during/after total_fail=${B_FAIL}/${D_FAIL}/${A_FAIL}" "$([[ $FAIL_OK -eq 1 ]] && echo Pass || echo Fail)"
mark_row "G6 probe" "curl http://${HOST}:${PROBE}/" "$PROBE_STATUS"
mark_row "G6 overall" "ratio=${RATIO} open_ms=${OPEN_MS} close_ms=${CLOSE_MS}" "$G6_LABEL"
echo "method_note=warmup=${WARMUP}+d=${DURATION}+c=${CONCURRENCY}+median(N_before=${N_BEFORE},N_during=${N_DURING})"

echo "G6_RATIO=$RATIO"
echo "G6_OPEN_MS=$OPEN_MS"
echo "G6_CLOSE_MS=$CLOSE_MS"
echo "G6_RESULT=$G6_LABEL"

[[ "$G6_PASS" -eq 1 ]] || exit 1
exit 0
