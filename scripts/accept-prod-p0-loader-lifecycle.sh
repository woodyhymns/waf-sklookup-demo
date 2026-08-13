#!/usr/bin/env bash
# P0-3: Loader kill/unload/restart — map rebuild after recovery; failure modes observable.
# Observability: loader.log, bpftool map show, ss -lntp, curl.
#
# Env: OPENRESTY_PREFIX PORT
set -euo pipefail
source "$(dirname "$0")/lib-prod-gng.sh"

STARTED_HERE=0
cleanup() {
  # Always try to leave a stopped or healthy state; prefer stop if we started.
  if [[ "$STARTED_HERE" -eq 1 ]]; then
    demo_stop
  fi
}
trap cleanup EXIT

echo "=== P0-3 loader lifecycle (kill → fail → restart → recover) ==="
require_hah
ensure_loader_bin

demo_stop || true
demo_start
STARTED_HERE=1

echo "--- baseline curl ---"
curl -sS --max-time 5 "http://${HOST}:${PORT}/" | tee /tmp/p0-life-baseline.body
grep -q "OpenResty M1 OK" /tmp/p0-life-baseline.body

echo "--- observability before kill ---"
echo "ss (internal listens):"
ss -lntp 2>/dev/null | rg ':(8080|18081)\b' || true
echo "bpftool open_ports:"
sudo bpftool map show name open_ports 2>/dev/null | head -10 || echo "(bpftool show failed)"
echo "pin dir:"
ls -la "$PIN_DIR" 2>/dev/null || echo "(no pin)"
LOADER_PID=""
if [[ -f "$STATE_DIR/loader.pid" ]]; then
  LOADER_PID="$(cat "$STATE_DIR/loader.pid")"
fi
echo "loader.pid=$LOADER_PID"
echo "loader.log tail:"
tail -5 "$STATE_DIR/loader.log" 2>/dev/null || true

echo "--- kill loader ---"
if [[ -n "$LOADER_PID" ]]; then
  sudo kill "$LOADER_PID" 2>/dev/null || true
  sleep 1
  # ensure dead
  if kill -0 "$LOADER_PID" 2>/dev/null; then
    sudo kill -9 "$LOADER_PID" 2>/dev/null || true
    sleep 0.5
  fi
  rm -f "$STATE_DIR/loader.pid"
else
  echo "BLOCKED: no loader.pid" >&2
  exit 3
fi

echo "--- failure mode after kill (expect curl fail or wrong) ---"
set +e
FAIL_OUT="$(curl -sS --max-time 3 -o /tmp/p0-life-fail.body -w '%{http_code}' "http://${HOST}:${PORT}/" 2>/tmp/p0-life-fail.err)"
FAIL_RC=$?
set -e
echo "curl_rc=$FAIL_RC http_code=$FAIL_OUT"
cat /tmp/p0-life-fail.err 2>/dev/null || true
cat /tmp/p0-life-fail.body 2>/dev/null || true
# After loader death, sk_lookup may drop / connection refuse / hang → any non-success is OK evidence
FAIL_MODE="通过"
if [[ $FAIL_RC -eq 0 && "$FAIL_OUT" == "200" ]] && grep -q "OpenResty M1 OK" /tmp/p0-life-fail.body 2>/dev/null; then
  # Unexpected: still works — maybe pin survived with prog? Still document.
  echo "WARN: curl still 200 after loader kill — check if prog/maps linger"
  # On some kernels pin may linger; if traffic still works, mark 阻塞 for unclear unload
  FAIL_MODE="阻塞"
  FAIL_NOTE="curl still 200 after kill (maps/prog may linger)"
else
  FAIL_NOTE="curl failed or non-200 as expected (rc=$FAIL_RC code=$FAIL_OUT)"
fi
echo "FAIL_MODE_RESULT=$FAIL_MODE ($FAIL_NOTE)"

echo "--- pin/map after kill ---"
ls -la "$PIN_DIR" 2>/dev/null || echo "(pin gone or empty — OK)"
sudo bpftool map show name open_ports 2>/dev/null | head -5 || echo "(no open_ports map or gone)"

echo "--- restart loader via run-openresty-demo start ---"
# Full start rebuilds OR+loader; stop first for clean restart
STARTED_HERE=0
demo_stop || true
demo_start
STARTED_HERE=1

echo "--- verify map re-pin ---"
REPIN="通过"
if [[ ! -e "$PIN_DIR/open_ports" ]]; then
  REPIN="失败"
  echo "FAIL: open_ports pin missing after restart"
else
  sudo bpftool map show name open_ports | head -10
  ls -la "$PIN_DIR"
fi

echo "--- curl recover ---"
RECOVER="通过"
set +e
curl -sS --max-time 5 "http://${HOST}:${PORT}/" | tee /tmp/p0-life-recover.body
RC=$?
set -e
if [[ $RC -ne 0 ]] || ! grep -q "OpenResty M1 OK" /tmp/p0-life-recover.body; then
  RECOVER="失败"
fi
# dual also
set +e
curl -sk --max-time 5 "https://${HOST}:${PORT}/" | tee /tmp/p0-life-recover-https.body
RC2=$?
set -e
HTTPS_REC="通过"
if [[ $RC2 -ne 0 ]] || ! grep -q "OpenResty M1 OK" /tmp/p0-life-recover-https.body; then
  HTTPS_REC="失败"
fi

echo
echo "### P0-3 summary table"
echo "| 项 | 测了什么 | 结果 |"
echo "|----|----------|------|"
mark_row "kill-fail-mode" "$FAIL_NOTE" "$FAIL_MODE"
mark_row "map-repin" "bpftool/pin after restart" "$REPIN"
mark_row "curl-recover-http" "HTTP :${PORT} after restart" "$RECOVER"
mark_row "curl-recover-https" "HTTPS :${PORT} after restart" "$HTTPS_REC"
mark_row "observability" "loader.log + bpftool + ss documented above" "通过"

if [[ "$REPIN" == "失败" || "$RECOVER" == "失败" || "$HTTPS_REC" == "失败" ]]; then
  exit 1
fi
if [[ "$FAIL_MODE" == "阻塞" ]]; then
  exit 3
fi
exit 0
