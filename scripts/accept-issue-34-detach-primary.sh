#!/usr/bin/env bash
# Issue #34 leftover: detach primary sk_lookup; backup steers new SYNs.
# Established TCP on the accepting listen must stay up (no migrate/rehash).
#
# Re-run:
#   sudo ./scripts/accept-issue-34-detach-primary.sh
#
# Requires root/CAP_BPF, sk_lookup, and the OpenResty demo stack.
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

HOLD_PY=""
cleanup_hold() {
  if [[ -n "${HOLD_PY}" ]] && kill -0 "${HOLD_PY}" 2>/dev/null; then
    kill "${HOLD_PY}" 2>/dev/null || true
  fi
}
trap 'cleanup_hold; hygiene_cleanup' EXIT ERR

echo "=== Issue #34: detach-primary; backup steers new SYN; established stays ==="

demo_stop || true
demo_start
STARTED_HERE=1

[[ -e "$PIN_DIR/sk_lookup_backup" ]] || {
  echo "FAIL: backup sk_lookup pin missing at $PIN_DIR/sk_lookup_backup" >&2
  ls -la "$PIN_DIR" 2>/dev/null || true
  exit 1
}
[[ -e "$PIN_DIR/sk_lookup" ]] || {
  echo "FAIL: primary sk_lookup pin missing" >&2
  exit 1
}

echo "--- baseline steered curl (expect 200) ---"
curl -sS --max-time 5 "http://${HOST}:${PORT}/" | tee /tmp/issue34-detach-base.body
grep -q "OpenResty M1 OK" /tmp/issue34-detach-base.body

HOLD_LOG=/tmp/issue34-detach-hold.log
rm -f "$HOLD_LOG"
# Hold an ESTABLISHED TCP without finishing the request so sk_lookup cannot
# reselect this flow. After detach-primary, complete the HTTP request on the
# same socket (proves no migrate/reset). Works for toy (Connection: close)
# and OpenResty.
python3 - "$HOST" "$PORT" "$HOLD_LOG" <<'PY' &
import socket, sys, time
host, port, log_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.create_connection((host, port), 5)
s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n" % host.encode())
open(log_path, "w").write("held\n")
time.sleep(2.5)
if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != 0:
    open(log_path, "a").write("so_error\n")
    raise SystemExit("hold: socket error after detach")
s.sendall(b"Connection: close\r\n\r\n")
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = s.recv(4096)
    if not chunk:
        open(log_path, "a").write("closed_before_headers\n")
        raise SystemExit("hold: established connection closed after detach")
    buf += chunk
if b"200" not in buf.split(b"\r\n", 1)[0]:
    open(log_path, "a").write("not_200\n")
    raise SystemExit("hold: GET on established TCP was not 200")
open(log_path, "a").write("established_ok\n")
s.close()
PY
HOLD_PY=$!

for _ in $(seq 1 50); do
  [[ -f "$HOLD_LOG" ]] && grep -q '^held$' "$HOLD_LOG" && break
  sleep 0.1
done
grep -q '^held$' "$HOLD_LOG" || {
  echo "FAIL: could not establish hold TCP" >&2
  wait "$HOLD_PY" || true
  exit 1
}

echo "--- detach-primary (backup must remain) ---"
sudo "$LOADER_BIN" detach-primary -pin-dir "$PIN_DIR"
[[ ! -e "$PIN_DIR/sk_lookup" ]] || {
  echo "FAIL: primary pin still present after detach-primary" >&2
  exit 1
}
[[ -e "$PIN_DIR/sk_lookup_backup" && -e "$PIN_DIR/open_ports" && -e "$PIN_DIR/redir_socket" ]] || {
  echo "FAIL: backup/maps disappeared with primary" >&2
  ls -la "$PIN_DIR" 2>/dev/null || true
  exit 1
}

echo "--- new SYN after detach-primary (expect 200 via backup) ---"
set +e
AFTER_CODE="$(curl -sS -o /tmp/issue34-detach-after.body -w '%{http_code}' --max-time 5 \
  "http://${HOST}:${PORT}/" 2>/tmp/issue34-detach-after.err)"
AFTER_RC=$?
set -e
echo "curl_rc=$AFTER_RC http_code=$AFTER_CODE"
cat /tmp/issue34-detach-after.err 2>/dev/null || true

NEW_SYN="失败"
if [[ $AFTER_RC -eq 0 && "$AFTER_CODE" == "200" ]] && grep -q "OpenResty M1 OK" /tmp/issue34-detach-after.body; then
  NEW_SYN="通过"
fi

echo "--- established TCP must complete HTTP on the same socket ---"
wait "$HOLD_PY"
HOLD_RC=$?
HOLD_PY=""
LONG_OK="失败"
if [[ $HOLD_RC -eq 0 ]] && grep -q 'established_ok' "$HOLD_LOG"; then
  LONG_OK="通过"
fi

echo
echo "### Issue #34 detach-primary summary"
echo "| 项 | 结果 |"
echo "|----|------|"
mark_row "backup-sk_lookup" "bpffs link at $PIN_DIR/sk_lookup_backup" "通过"
mark_row "detach-primary-new-syn" "curl :${PORT} after detach-primary" "$NEW_SYN"
mark_row "established-tcp-stays" "same TCP completes HTTP after detach" "$LONG_OK"

if [[ "$NEW_SYN" != "通过" || "$LONG_OK" != "通过" ]]; then
  echo "FAIL: backup did not cover new SYN or established flow moved/died" >&2
  exit 1
fi
exit 0
