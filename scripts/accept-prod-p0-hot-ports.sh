#!/usr/bin/env bash
# P0-4: Hot add/remove ports at ~10k scale while measuring P99 / success-rate.
# Light background traffic on steered PORT; bulk open HOT_COUNT then close half.
#
# Env: OPENRESTY_PREFIX PORT HOT_COUNT (default 10000) HOT_START (default 20000)
#      DURATION (sample window) CONCURRENCY
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

echo "=== P0-4 hot add/remove ~${HOT_COUNT} ports under light traffic ==="
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

sample() {
  local label="$1"
  "$HTTPBENCH_BIN" -url "http://${HOST}:${PORT}/" -d "$DURATION" -c "$CONCURRENCY" -keepalive -label "$label"
}

echo "--- sample BEFORE ---"
BEFORE="$(sample before)"
echo "$BEFORE"

echo "--- start light background traffic ---"
# Background curl loop (no wrk); bounded by cleanup
(
  while true; do
    curl -sS --max-time 2 "http://${HOST}:${PORT}/" >/dev/null 2>&1 || true
    curl -sk --max-time 2 "https://${HOST}:${PORT}/" >/dev/null 2>&1 || true
    sleep 0.05
  done
) &
BG_PID=$!

echo "--- bulk open ${HOT_COUNT} ports ${HOT_START}-${END_PORT} ---"
T0=$(date +%s%N)
sudo "$LOADER_BIN" bulk open -range "${HOT_START}-${END_PORT}" -pin-dir "$PIN_DIR"
T1=$(date +%s%N)
OPEN_MS=$(( (T1 - T0) / 1000000 ))
echo "bulk_open_ms=$OPEN_MS"
sudo "$LOADER_BIN" list -count -pin-dir "$PIN_DIR" || true

echo "--- sample DURING (after open, before close) ---"
DURING="$(sample during)"
echo "$DURING"

# Spot-check a hot port answers
PROBE=$((HOT_START + 100))
echo "--- probe hot port :${PROBE} ---"
PROBE_STATUS="通过"
set +e
curl -sS --max-time 3 "http://${HOST}:${PROBE}/" | tee /tmp/p0-hot-probe.body
PRC=$?
set -e
if [[ $PRC -ne 0 ]] || ! grep -q "OpenResty M1 OK" /tmp/p0-hot-probe.body; then
  PROBE_STATUS="失败"
fi

echo "--- bulk close half ${HOT_START}-${HALF_END} ---"
T2=$(date +%s%N)
sudo "$LOADER_BIN" bulk close -range "${HOT_START}-${HALF_END}" -pin-dir "$PIN_DIR"
T3=$(date +%s%N)
CLOSE_MS=$(( (T3 - T2) / 1000000 ))
echo "bulk_close_half_ms=$CLOSE_MS"

echo "--- sample AFTER ---"
AFTER="$(sample after)"
echo "$AFTER"

# Stop background before table
kill "$BG_PID" 2>/dev/null || true
wait "$BG_PID" 2>/dev/null || true
BG_PID=""

f() { percentile_from_result "$1" "$2"; }
B_RPS=$(f "$BEFORE" rps); B_P99=$(f "$BEFORE" p99_us); B_OK=$(f "$BEFORE" ok); B_FAIL=$(f "$BEFORE" fail)
D_RPS=$(f "$DURING" rps); D_P99=$(f "$DURING" p99_us); D_OK=$(f "$DURING" ok); D_FAIL=$(f "$DURING" fail)
A_RPS=$(f "$AFTER" rps); A_P99=$(f "$AFTER" p99_us); A_OK=$(f "$AFTER" ok); A_FAIL=$(f "$AFTER" fail)

STATUS="通过"
for v in "$B_OK" "$D_OK" "$A_OK"; do
  [[ -z "$v" || "$v" == "0" ]] && STATUS="失败"
done
[[ "$PROBE_STATUS" == "失败" ]] && STATUS="失败"

echo
echo "### P0-4 summary table"
echo "| phase | rps | p99_us | ok | fail |"
echo "|-------|-----|--------|----|------|"
echo "| before | $B_RPS | $B_P99 | $B_OK | $B_FAIL |"
echo "| during (after ${HOT_COUNT} open) | $D_RPS | $D_P99 | $D_OK | $D_FAIL |"
echo "| after (closed half) | $A_RPS | $A_P99 | $A_OK | $A_FAIL |"
echo
echo "| 项 | 测了什么 | 结果 |"
echo "|----|----------|------|"
mark_row "bulk-open-10k" "open ${HOT_COUNT} ports in ${OPEN_MS}ms" "通过"
mark_row "bulk-close-half" "close ${HALF} ports in ${CLOSE_MS}ms" "通过"
mark_row "hot-probe" "curl http://${HOST}:${PROBE}/" "$PROBE_STATUS"
mark_row "p99-under-churn" "before/during/after p99_us=${B_P99}/${D_P99}/${A_P99} rps=${B_RPS}/${D_RPS}/${A_RPS}" "$STATUS"

[[ "$STATUS" == "通过" ]] || exit 1
exit 0
