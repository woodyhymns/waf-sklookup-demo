#!/usr/bin/env bash
# P0-1: Short-conn CPS (HTTP) + TLS handshake storm (HTTPS) on same steered port.
# Also verifies dual protocol (curl http + curl -k https) on one port.
#
# Env: OPENRESTY_PREFIX PORT DURATION CONCURRENCY
# Bench: tools/httpbench (short) + openssl s_time (TLS new handshakes). No wrk/ab.
set -euo pipefail
source "$(dirname "$0")/lib-prod-gng.sh"

STARTED_HERE=0
install_hygiene_traps

echo "=== P0-1 CPS + TLS handshake storm (same-port dual HTTP+HTTPS) ==="
require_hah
ensure_httpbench
ensure_loader_bin

# Start demo if steered port not already answering
if ! curl -sS --max-time 2 "http://${HOST}:${PORT}/" >/dev/null 2>&1; then
  demo_start
  STARTED_HERE=1
fi

echo "--- dual protocol smoke ---"
HTTP_BODY="$(mktemp)"
HTTPS_BODY="$(mktemp)"
curl -sS --max-time 5 "http://${HOST}:${PORT}/" | tee "$HTTP_BODY"
curl -sk --max-time 5 "https://${HOST}:${PORT}/" | tee "$HTTPS_BODY"
DUAL="通过"
if ! grep -q "OpenResty M1 OK" "$HTTP_BODY"; then DUAL="失败"; fi
if ! grep -q "OpenResty M1 OK" "$HTTPS_BODY"; then DUAL="失败"; fi
if grep -q "scheme=http" "$HTTP_BODY" && grep -q "scheme=https" "$HTTPS_BODY"; then
  echo "PASS: same port :${PORT} HTTP+HTTPS (scheme ok)"
else
  echo "WARN: scheme markers missing (still may be OK if body OK)"
fi
echo "DUAL_RESULT=$DUAL"

echo "--- short-conn HTTP CPS (httpbench DisableKeepAlives) ---"
CPS_LINE="$("$HTTPBENCH_BIN" -url "http://${HOST}:${PORT}/" -d "$DURATION" -c "$CONCURRENCY" -label "p0-cps-http" )"
echo "$CPS_LINE"
CPS_RPS="$(percentile_from_result "$CPS_LINE" rps)"
CPS_P99="$(percentile_from_result "$CPS_LINE" p99_us)"
CPS_OK="$(percentile_from_result "$CPS_LINE" ok)"
CPS_FAIL="$(percentile_from_result "$CPS_LINE" fail)"
CPS_STATUS="通过"
if [[ -z "$CPS_OK" || "$CPS_OK" == "0" ]]; then CPS_STATUS="失败"; fi

echo "--- TLS handshake storm (openssl s_time -new) ---"
TLS_STATUS="通过"
TLS_SUMMARY=""
if have_cmd openssl; then
  # s_time -time takes integer seconds
  TLS_SECS="$(echo "$DURATION" | sed 's/s$//;s/[^0-9].*//')"
  [[ -z "$TLS_SECS" || "$TLS_SECS" -lt 1 ]] && TLS_SECS=5
  # -www / fetches a page; -new forces new handshake each time
  set +e
  TLS_OUT="$(openssl s_time -connect "${HOST}:${PORT}" -new -time "$TLS_SECS" -www / 2>&1)"
  TLS_RC=$?
  set -e
  echo "$TLS_OUT" | tail -20
  # Typical: "123 connections in 5.02s; 24.50 connections/user sec, ..."
  TLS_SUMMARY="$(echo "$TLS_OUT" | rg -o '[0-9]+ connections in [0-9.]+s.*' | head -1 || true)"
  if [[ $TLS_RC -ne 0 || -z "$TLS_SUMMARY" ]]; then
    # Some openssl builds still print useful stats on stderr mix; accept non-zero if we saw connections
    if echo "$TLS_OUT" | rg -q '[0-9]+ connections in'; then
      TLS_SUMMARY="$(echo "$TLS_OUT" | rg -o '[0-9]+ connections in [0-9.]+s[^[:space:]]*' | head -1 || echo "$TLS_OUT" | rg 'connections' | head -1)"
    else
      TLS_STATUS="失败"
      TLS_SUMMARY="openssl s_time failed rc=$TLS_RC"
    fi
  fi
else
  TLS_STATUS="阻塞"
  TLS_SUMMARY="openssl missing"
fi

echo
echo "### P0-1 summary table"
echo "| 项 | 测了什么 | 结果 |"
echo "|----|----------|------|"
mark_row "dual-proto" "same port :${PORT} curl http + curl -k https" "$DUAL"
mark_row "http-cps" "short-conn HTTP rps=${CPS_RPS:-?} p99_us=${CPS_P99:-?} ok=${CPS_OK:-?} fail=${CPS_FAIL:-?}" "$CPS_STATUS"
mark_row "tls-hs-storm" "openssl s_time -new ${TLS_SUMMARY:-n/a}" "$TLS_STATUS"

if [[ "$DUAL" == "失败" || "$CPS_STATUS" == "失败" || "$TLS_STATUS" == "失败" ]]; then
  exit 1
fi
if [[ "$TLS_STATUS" == "阻塞" ]]; then
  exit 3
fi
exit 0
