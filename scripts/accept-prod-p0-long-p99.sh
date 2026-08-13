#!/usr/bin/env bash
# P0-2: Long-lived / keep-alive throughput + P99 for HTTP and HTTPS.
# Two legs: (A) direct internal 127.0.0.1:8080  vs  (B) sk_lookup steered PORT.
# On HAH product single-listen, direct HTTPS is also :8080 (https_allow_http).
#
# Env: OPENRESTY_PREFIX PORT DURATION CONCURRENCY
set -euo pipefail
source "$(dirname "$0")/lib-prod-gng.sh"

STARTED_HERE=0
cleanup() {
  if [[ "$STARTED_HERE" -eq 1 ]]; then
    demo_stop
  fi
}
trap cleanup EXIT

echo "=== P0-2 long-conn throughput + P99 (direct vs sk_lookup) ==="
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

run_leg() {
  local label="$1" url="$2"
  local line
  line="$("$HTTPBENCH_BIN" -url "$url" -d "$DURATION" -c "$CONCURRENCY" -keepalive -label "$label")"
  echo "$line"
  # stash for table
  eval "${label}_LINE=$(printf '%q' "$line")"
}

echo "--- leg A: direct internal HTTP ---"
A_HTTP="$("$HTTPBENCH_BIN" -url "http://${INTERNAL_HOST}:${INTERNAL_PORT}/" -d "$DURATION" -c "$CONCURRENCY" -keepalive -label "A-direct-http")"
echo "$A_HTTP"

echo "--- leg A: direct internal HTTPS (HAH same :8080) ---"
A_HTTPS="$("$HTTPBENCH_BIN" -url "https://${INTERNAL_HOST}:${INTERNAL_PORT}/" -d "$DURATION" -c "$CONCURRENCY" -keepalive -k -label "A-direct-https")"
echo "$A_HTTPS"

echo "--- leg B: sk_lookup steered HTTP :${PORT} ---"
B_HTTP="$("$HTTPBENCH_BIN" -url "http://${HOST}:${PORT}/" -d "$DURATION" -c "$CONCURRENCY" -keepalive -label "B-sklookup-http")"
echo "$B_HTTP"

echo "--- leg B: sk_lookup steered HTTPS :${PORT} ---"
B_HTTPS="$("$HTTPBENCH_BIN" -url "https://${HOST}:${PORT}/" -d "$DURATION" -c "$CONCURRENCY" -keepalive -k -label "B-sklookup-https")"
echo "$B_HTTPS"

field() { percentile_from_result "$1" "$2"; }

AH_RPS=$(field "$A_HTTP" rps); AH_P99=$(field "$A_HTTP" p99_us); AH_OK=$(field "$A_HTTP" ok)
AS_RPS=$(field "$A_HTTPS" rps); AS_P99=$(field "$A_HTTPS" p99_us); AS_OK=$(field "$A_HTTPS" ok)
BH_RPS=$(field "$B_HTTP" rps); BH_P99=$(field "$B_HTTP" p99_us); BH_OK=$(field "$B_HTTP" ok)
BS_RPS=$(field "$B_HTTPS" rps); BS_P99=$(field "$B_HTTPS" p99_us); BS_OK=$(field "$B_HTTPS" ok)

STATUS="通过"
for v in "$AH_OK" "$AS_OK" "$BH_OK" "$BS_OK"; do
  if [[ -z "$v" || "$v" == "0" ]]; then STATUS="失败"; fi
done

echo
echo "### P0-2 comparison table"
echo "| leg | protocol | target | rps | p99_us | ok | 结果 |"
echo "|-----|----------|--------|-----|--------|----|------|"
echo "| A direct | HTTP | ${INTERNAL_HOST}:${INTERNAL_PORT} | ${AH_RPS} | ${AH_P99} | ${AH_OK} | $STATUS |"
echo "| A direct | HTTPS | ${INTERNAL_HOST}:${INTERNAL_PORT} | ${AS_RPS} | ${AS_P99} | ${AS_OK} | $STATUS |"
echo "| B sk_lookup | HTTP | ${HOST}:${PORT} | ${BH_RPS} | ${BH_P99} | ${BH_OK} | $STATUS |"
echo "| B sk_lookup | HTTPS | ${HOST}:${PORT} | ${BS_RPS} | ${BS_P99} | ${BS_OK} | $STATUS |"
echo
echo "| 项 | 测了什么 | 结果 |"
echo "|----|----------|------|"
mark_row "long-http" "keepalive A rps=${AH_RPS} p99=${AH_P99} vs B rps=${BH_RPS} p99=${BH_P99}" "$STATUS"
mark_row "long-https" "keepalive A rps=${AS_RPS} p99=${AS_P99} vs B rps=${BS_RPS} p99=${BS_P99}" "$STATUS"

[[ "$STATUS" == "通过" ]] || exit 1
exit 0
