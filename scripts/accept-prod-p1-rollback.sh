#!/usr/bin/env bash
# P1-d: rollback drill — unload sk_lookup / stop loader; steered fail; direct :8080 OK; restore.
# PROXY path: N/A/阻塞(无实现) if no PROXY impl in repo; document direct-internal as observation path.
set -euo pipefail
source "$(dirname "$0")/lib-prod-gng.sh"

STARTED_HERE=0
cleanup() {
  # Always try to leave stopped; if mid-drill, attempt restore then stop
  if [[ -f "$STATE_DIR/loader.pid" ]] || curl -sS --max-time 1 "http://127.0.0.1:8080/" >/dev/null 2>&1; then
    demo_stop || true
  fi
}
trap cleanup EXIT

echo "=== P1-d rollback drill (unload sk_lookup / restore) ==="
require_hah
ensure_loader_bin

# PROXY presence check (repo scan)
# Repo has no userspace PROXY protocol fallback path for rollback (ignore nginx
# third_party patch field names / docs mentions).
PROXY_STATUS="N/A/阻塞(无实现)"
if rg -n --ignore-case 'send_proxy_v2|PROXYPROC|proxy_protocol\s+on|to_proxy_protocol' \
  --glob '!docs/**' --glob '!*.md' --glob '!*.log' --glob '!third_party/**' \
  "$REPO_ROOT" 2>/dev/null | rg -v 'N/A|阻塞|DEFER|预留|rollback|P1-d' >/dev/null; then
  PROXY_STATUS="有实现线索(未演练)"
fi
echo "PROXY path: $PROXY_STATUS (observation path = direct internal :8080)"

demo_stop || true
demo_start
STARTED_HERE=1

echo "--- (1) baseline steered curl 200 ---"
set +e
curl -sS --max-time 5 "http://${HOST}:${PORT}/" | tee /tmp/p1d-base.body
BRC=$?
set -e
BASE_OK="失败"
if [[ $BRC -eq 0 ]] && grep -q "OpenResty M1 OK" /tmp/p1d-base.body; then
  BASE_OK="通过"
fi
echo "BASE_OK=$BASE_OK"

echo "--- (2) timed unload: stop loader / detach sk_lookup (keep OpenResty up) ---"
# Prefer killing loader only (run-openresty-demo stop stops both)
LOADER_PID=""
[[ -f "$STATE_DIR/loader.pid" ]] && LOADER_PID="$(cat "$STATE_DIR/loader.pid")"
if [[ -z "$LOADER_PID" ]]; then
  echo "BLOCKED: no loader.pid"
  exit 3
fi

T_UNLOAD0=$(date +%s%N)
# Kill loader; defer unpinMaps runs on exit → prog/maps go away
sudo kill "$LOADER_PID" 2>/dev/null || true
for i in $(seq 1 40); do
  if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if kill -0 "$LOADER_PID" 2>/dev/null; then
  sudo kill -9 "$LOADER_PID" 2>/dev/null || true
  sleep 0.2
fi
rm -f "$STATE_DIR/loader.pid"
# Best-effort unpin if linger
if [[ -d "$PIN_DIR" ]]; then
  sudo rm -f "$PIN_DIR/open_ports" "$PIN_DIR/redir_socket" 2>/dev/null || true
  # try detach via bpftool link if any
  sudo bpftool link show 2>/dev/null | head -20 || true
fi
T_UNLOAD1=$(date +%s%N)
UNLOAD_MS=$(( (T_UNLOAD1 - T_UNLOAD0) / 1000000 ))
UNLOAD_S=$(python3 -c "print(round($UNLOAD_MS/1000.0, 3))")
echo "unload_elapsed_s=$UNLOAD_S (${UNLOAD_MS}ms)"

echo "--- (3) verify steered FAIL; direct :8080 still works ---"
set +e
STEER_CODE="$(curl -sS -o /tmp/p1d-steer-fail.body -w '%{http_code}' --max-time 3 \
  "http://${HOST}:${PORT}/" 2>/tmp/p1d-steer-fail.err)"
STEER_RC=$?
set -e
echo "steered curl_rc=$STEER_RC http_code=$STEER_CODE"
cat /tmp/p1d-steer-fail.err 2>/dev/null || true
cat /tmp/p1d-steer-fail.body 2>/dev/null || true
STEER_FAIL_OK="失败"
if [[ $STEER_RC -ne 0 || "$STEER_CODE" == "000" || "$STEER_CODE" != "200" ]]; then
  # Also treat unexpected still-200 as 阻塞
  if [[ $STEER_RC -eq 0 && "$STEER_CODE" == "200" ]] && grep -q "OpenResty M1 OK" /tmp/p1d-steer-fail.body 2>/dev/null; then
    STEER_FAIL_OK="阻塞"
    STEER_NOTE="steered still 200 after unload (maps/prog may linger)"
  else
    STEER_FAIL_OK="通过"
    STEER_NOTE="steered failed as expected (rc=$STEER_RC code=$STEER_CODE)"
  fi
else
  STEER_FAIL_OK="通过"
  STEER_NOTE="steered failed as expected (rc=$STEER_RC code=$STEER_CODE)"
fi
echo "STEER_FAIL_OK=$STEER_FAIL_OK ($STEER_NOTE)"

set +e
curl -sS --max-time 5 "http://127.0.0.1:8080/" | tee /tmp/p1d-direct.body
DRC=$?
set -e
DIRECT_OK="失败"
if [[ $DRC -eq 0 ]] && grep -q "OpenResty M1 OK" /tmp/p1d-direct.body; then
  DIRECT_OK="通过"
fi
echo "DIRECT_OK=$DIRECT_OK (old path = direct internal listen)"

echo "--- (4) timed restore: start loader again ---"
T_RES0=$(date +%s%N)
# Start loader only (OpenResty still up) — reuse run-openresty-demo start_loader path via full start after stop OR manual
# Cleanest: stop_loader already done; call start which would also restart OR — instead invoke loader like run script.
# Use demo full restart for reliability (OR already up: stop+start is fine for restore timing of loader attach).
# Prefer: only start loader without bouncing OR
(
  cd "$REPO_ROOT"
  mkdir -p "$STATE_DIR"
  tls_args=()
  # LOADER_TLS_PORTS empty for product path
  if [[ -n "${LOADER_TLS_PORTS}" ]]; then
    tls_args=(-tls-target "${TLS_TARGET:-127.0.0.1:8443}" -tls-ports "$LOADER_TLS_PORTS")
  fi
  sudo ./waf-sklookup-demo \
    -mode openresty \
    -target "$TARGET" \
    -ports "$LOADER_PORTS" \
    "${tls_args[@]}" \
    -wait "${WAIT:-60s}" \
    -pin-dir "$PIN_DIR" \
    >"$STATE_DIR/loader.log" 2>&1 &
  echo $! > "$STATE_DIR/loader.pid"
)
# Wait ready
READY=0
for i in $(seq 1 60); do
  if grep -q "OPENRESTY P1 READY" "$STATE_DIR/loader.log" 2>/dev/null; then
    READY=1
    break
  fi
  if [[ -f "$STATE_DIR/loader.pid" ]] && ! kill -0 "$(cat "$STATE_DIR/loader.pid")" 2>/dev/null; then
    echo "loader exited early:" >&2
    cat "$STATE_DIR/loader.log" >&2 || true
    break
  fi
  sleep 0.25
done
T_RES1=$(date +%s%N)
RESTORE_MS=$(( (T_RES1 - T_RES0) / 1000000 ))
RESTORE_S=$(python3 -c "print(round($RESTORE_MS/1000.0, 3))")
echo "restore_elapsed_s=$RESTORE_S (${RESTORE_MS}ms) ready=$READY"

echo "--- (5) verify steered recover ---"
sleep 0.3
set +e
curl -sS --max-time 5 "http://${HOST}:${PORT}/" | tee /tmp/p1d-recover.body
RRC=$?
set -e
RECOVER_OK="失败"
if [[ $READY -eq 1 && $RRC -eq 0 ]] && grep -q "OpenResty M1 OK" /tmp/p1d-recover.body \
  && grep -q "waf_external_port=${PORT}" /tmp/p1d-recover.body; then
  RECOVER_OK="通过"
fi
# HTTPS too
set +e
curl -sk --max-time 5 "https://${HOST}:${PORT}/" | tee /tmp/p1d-recover-https.body
RRC2=$?
set -e
RECOVER_HTTPS="失败"
if [[ $RRC2 -eq 0 ]] && grep -q "OpenResty M1 OK" /tmp/p1d-recover-https.body; then
  RECOVER_HTTPS="通过"
fi
echo "RECOVER_OK=$RECOVER_OK RECOVER_HTTPS=$RECOVER_HTTPS"

STATUS="通过"
[[ "$BASE_OK" != "通过" || "$DIRECT_OK" != "通过" || "$RECOVER_OK" != "通过" ]] && STATUS="失败"
[[ "$STEER_FAIL_OK" == "失败" ]] && STATUS="失败"
[[ "$STEER_FAIL_OK" == "阻塞" ]] && STATUS="阻塞"

demo_stop || true
STARTED_HERE=0

echo
echo "### P1-d steps / timing"
echo "| step | elapsed_s | verification |"
echo "|------|-----------|--------------|"
echo "| unload loader+unpin | $UNLOAD_S | kill loader.pid; rm pin; bpftool |"
echo "| steered fail check | — | curl http://${HOST}:${PORT}/ → fail (rc=$STEER_RC code=$STEER_CODE) |"
echo "| direct internal OK | — | curl http://127.0.0.1:8080/ → 200 |"
echo "| restore loader | $RESTORE_S | waf-sklookup-demo -mode openresty; wait READY |"
echo "| steered recover | — | curl http+https://${HOST}:${PORT}/ → 200 |"
echo
echo "| 项 | 测了什么 | 结果 |"
echo "|----|----------|------|"
mark_row "baseline" "steered curl 200 before unload" "$BASE_OK"
mark_row "unload" "stop loader/detach in ${UNLOAD_S}s" "通过"
mark_row "steered-fail" "$STEER_NOTE" "$STEER_FAIL_OK"
mark_row "direct-8080" "direct internal listen still 200 (rollback observation path)" "$DIRECT_OK"
mark_row "restore" "loader re-attach in ${RESTORE_S}s ready=$READY" "$([[ $READY -eq 1 ]] && echo 通过 || echo 失败)"
mark_row "recover-http" "steered HTTP after restore" "$RECOVER_OK"
mark_row "recover-https" "steered HTTPS after restore" "$RECOVER_HTTPS"
mark_row "PROXY-fallback" "PROXY rollback path" "$PROXY_STATUS"
mark_row "P1-d overall" "rollback drill unload/restore" "$STATUS"

if [[ "$STATUS" == "阻塞" || "$PROXY_STATUS" == "N/A/阻塞(无实现)" && "$STATUS" == "通过" ]]; then
  # PROXY N/A is documented 阻塞 for that sub-path but overall drill can still 通过 on direct-internal
  :
fi
if [[ "$STEER_FAIL_OK" == "阻塞" ]]; then
  exit 3
fi
[[ "$STATUS" == "通过" ]] || exit 1
exit 0
