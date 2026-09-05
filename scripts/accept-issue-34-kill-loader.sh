#!/usr/bin/env bash
# Issue #34: pinned sk_lookup link survives loader kill; new SYNs keep steering.
# Requires root/CAP_BPF, sk_lookup, and OpenResty demo stack.
#
# Verify kill-loader new SYN:
#   1) start loader + OpenResty, curl steered port → 200
#   2) kill -9 loader, curl again → 200 (not refuse/SK_DROP)
#
# Optional second phase: restart loader against pinned link (bpf_link_update).
#
# Env: HOST PORT PIN_DIR LOADER_BIN (see lib-prod-gng.sh)
set -euo pipefail
source "$(dirname "$0")/lib-prod-gng.sh"

STARTED_HERE=0
install_hygiene_traps

require_root() {
  if [[ "$(id -u)" != 0 ]] && ! sudo -n true 2>/dev/null; then
    echo "SKIP: need root/CAP_BPF for sk_lookup attach (run with sudo or as root)" >&2
    exit 77
  fi
}

require_root
ensure_loader_bin

echo "=== Issue #34: kill-loader new-SYN continuity (pinned bpf_link) ==="

demo_stop || true
demo_start
STARTED_HERE=1

[[ -e "$PIN_DIR/sk_lookup" ]] || {
  echo "FAIL: pinned sk_lookup link missing at $PIN_DIR/sk_lookup" >&2
  ls -la "$PIN_DIR" 2>/dev/null || true
  exit 1
}
[[ -e "$PIN_DIR/sk_lookup_backup" ]] || {
  echo "FAIL: backup sk_lookup pin missing at $PIN_DIR/sk_lookup_backup" >&2
  ls -la "$PIN_DIR" 2>/dev/null || true
  exit 1
}

echo "--- baseline steered curl (expect 200) ---"
curl -sS --max-time 5 "http://${HOST}:${PORT}/" | tee /tmp/issue34-base.body
grep -q "OpenResty M1 OK" /tmp/issue34-base.body

LOADER_PID=""
[[ -f "$STATE_DIR/loader.pid" ]] && LOADER_PID="$(cat "$STATE_DIR/loader.pid")"
[[ -n "$LOADER_PID" ]] || { echo "FAIL: no loader.pid" >&2; exit 1; }

echo "--- kill -9 loader (pid=$LOADER_PID); dataplane must stay attached ---"
sudo kill -9 "$LOADER_PID" 2>/dev/null || true
sleep 0.5
rm -f "$STATE_DIR/loader.pid"

echo "--- pin dir after kill (link + maps must remain) ---"
ls -la "$PIN_DIR"
[[ -e "$PIN_DIR/sk_lookup" && -e "$PIN_DIR/sk_lookup_backup" && -e "$PIN_DIR/open_ports" && -e "$PIN_DIR/redir_socket" ]]

echo "--- steered curl after loader kill (expect 200, not refuse) ---"
set +e
AFTER_CODE="$(curl -sS -o /tmp/issue34-after-kill.body -w '%{http_code}' --max-time 5 \
  "http://${HOST}:${PORT}/" 2>/tmp/issue34-after-kill.err)"
AFTER_RC=$?
set -e
echo "curl_rc=$AFTER_RC http_code=$AFTER_CODE"
cat /tmp/issue34-after-kill.err 2>/dev/null || true

KILL_SYN="失败"
if [[ $AFTER_RC -eq 0 && "$AFTER_CODE" == "200" ]] && grep -q "OpenResty M1 OK" /tmp/issue34-after-kill.body; then
  KILL_SYN="通过"
fi

echo "--- optional: restart loader (bpf_link_update) ---"
RESTART_SYN="跳过"
LONG_OK="跳过"
if [[ "$KILL_SYN" == "通过" ]]; then
  sudo "$LOADER_BIN" -mode openresty -target "$TARGET" -ports "$LOADER_PORTS" \
    -ports-file ports.conf -wait "$WAIT" -pin-dir "$PIN_DIR" -no-ctl \
    >"$STATE_DIR/loader-restart.log" 2>&1 &
  RESTART_PID=$!
  echo "$RESTART_PID" >"$STATE_DIR/loader.pid"
  for _ in $(seq 1 120); do
    grep -q 'OPENRESTY P1 READY\|bpf_link_update' "$STATE_DIR/loader-restart.log" 2>/dev/null && break
    [[ -d "/proc/$RESTART_PID" ]] || break
    sleep 0.5
  done
  grep -q 'bpf_link_update' "$STATE_DIR/loader-restart.log" || {
    echo "WARN: restart log missing bpf_link_update line:" >&2
    tail -20 "$STATE_DIR/loader-restart.log" >&2 || true
  }
  curl -sS --max-time 5 "http://${HOST}:${PORT}/" | tee /tmp/issue34-after-restart.body
  if grep -q "OpenResty M1 OK" /tmp/issue34-after-restart.body; then
    RESTART_SYN="通过"
  else
    RESTART_SYN="失败"
  fi
fi

echo
echo "### Issue #34 summary"
echo "| 项 | 结果 |"
echo "|----|------|"
mark_row "pin-sk_lookup" "bpffs link at $PIN_DIR/sk_lookup" "通过"
mark_row "kill-loader-new-syn" "curl :${PORT} after kill -9 loader" "$KILL_SYN"
mark_row "loader-restart-update" "bpf_link_update + steered curl" "$RESTART_SYN"

if [[ "$KILL_SYN" != "通过" ]]; then
  echo "FAIL: steered SYN did not survive loader kill (maps-only pin is the old fail path)" >&2
  exit 1
fi
if [[ "$RESTART_SYN" == "失败" ]]; then
  exit 1
fi
exit 0
