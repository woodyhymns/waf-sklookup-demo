#!/usr/bin/env bash
# Main ABI: pidfd listen health re-inserts SOCKMAP FDs after the owner exits.
# Standalone (python worker). Does not use OpenResty, #37 objects, or the
# shared demo pin dir.
#
# Re-run:
#   sudo ./scripts/accept-pidfd-listen-reinsert.sh
# Unit (no BPF): cargo test --manifest-path rust/loader/Cargo.toml
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

LOADER_BIN="${LOADER_BIN:-./rust/loader/target/release/waf-sklookup-loader}"
WORK="${TMPDIR:-/tmp}/waf-pidfd-reinsert-$$"
PIN_DIR="/sys/fs/bpf/waf-pidfd-reinsert-$$"
PORTS_FILE="$WORK/ports.conf"
POLICY_FILE="$WORK/policy.conf"
NGINX_CONF="$WORK/nginx.conf"
LISTEN_PORT="${LISTEN_PORT:-18080}"
STEER_PORT="${STEER_PORT:-18181}"
TARGET="127.0.0.1:${LISTEN_PORT}"
WORKER_LOG="$WORK/worker.log"
LOADER_LOG="$WORK/loader.log"
WORKER_PID=""
LOADER_PID=""

cleanup() {
  trap - EXIT INT TERM
  set +e
  [[ -n "${LOADER_PID}" ]] && kill -TERM "$LOADER_PID" 2>/dev/null
  [[ -n "${WORKER_PID}" ]] && kill -TERM "$WORKER_PID" 2>/dev/null
  wait "$LOADER_PID" 2>/dev/null
  wait "$WORKER_PID" 2>/dev/null
  if [[ -x "$LOADER_BIN" && -d "$PIN_DIR" ]]; then
    "$LOADER_BIN" unpin -pin-dir "$PIN_DIR" >/dev/null 2>&1
  fi
  rm -rf "$WORK"
  rmdir "$PIN_DIR" 2>/dev/null
}
trap cleanup EXIT INT TERM

if [[ "$(id -u)" != 0 ]] && ! sudo -n true 2>/dev/null; then
  echo "SKIP: need root/CAP_BPF for sk_lookup attach (run with sudo or as root)" >&2
  exit 77
fi

if [[ ! -x "$LOADER_BIN" ]]; then
  cargo build --release --manifest-path rust/loader/Cargo.toml
fi
if [[ ! -x "$LOADER_BIN" ]]; then
  echo "FAIL: LOADER_BIN not executable: $LOADER_BIN" >&2
  exit 1
fi

command -v python3 >/dev/null || { echo "FAIL: python3 required" >&2; exit 1; }

if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  echo "SKIP: /sys/fs/bpf is not a bpffs mount" >&2
  exit 77
fi

mkdir -p "$WORK" "$PIN_DIR"
printf 'listen %s;\n' "$LISTEN_PORT" >"$NGINX_CONF"
cat > "$POLICY_FILE" <<'EOF'
deny=22,25,53,3306,6379
reserve=80,443,8080,8443,19099
allow_privileged=
max_ports_per_tenant=32
max_ports_per_machine=128
EOF
cat > "$PORTS_FILE" <<EOF
# desired open_ports
${STEER_PORT} demo local
EOF

start_worker() {
  local port="$1"
  : >"$WORKER_LOG"
  python3 - "$port" <<'PY' >>"$WORKER_LOG" 2>&1 &
import socket, sys
port = int(sys.argv[1])
body = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\npidfd-ok"
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s.bind(("127.0.0.1", port))
s.listen(16)
print("READY", port, flush=True)
while True:
    c, _ = s.accept()
    try:
        c.recv(1024)
        c.sendall(body)
    finally:
        c.close()
PY
  WORKER_PID=$!
  for _ in $(seq 1 50); do
    if grep -q READY "$WORKER_LOG" 2>/dev/null && kill -0 "$WORKER_PID" 2>/dev/null; then
      return 0
    fi
    sleep 0.05
  done
  echo "FAIL: worker did not become READY" >&2
  cat "$WORKER_LOG" >&2 || true
  return 1
}

echo "=== pidfd listen re-insert (main ABI, 2-slot SOCKMAP) ==="
start_worker "$LISTEN_PORT"

"$LOADER_BIN" \
  -mode openresty \
  -target "$TARGET" \
  -ports "$STEER_PORT" \
  -tenant demo -site local \
  -ports-file "$PORTS_FILE" \
  -policy-file "$POLICY_FILE" \
  -pin-dir "$PIN_DIR" \
  -rescan-interval 200ms \
  -wait 5s \
  -no-ctl \
  >"$LOADER_LOG" 2>&1 &
LOADER_PID=$!

for _ in $(seq 1 50); do
  if grep -q "OPENRESTY P1 READY" "$LOADER_LOG" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    echo "FAIL: loader exited early" >&2
    cat "$LOADER_LOG" >&2
    exit 1
  fi
  sleep 0.1
done
grep -q "OPENRESTY P1 READY" "$LOADER_LOG" || {
  echo "FAIL: loader did not become ready" >&2
  cat "$LOADER_LOG" >&2
  exit 1
}

echo "--- local worker sanity ---"
curl -sS --max-time 3 "http://127.0.0.1:${LISTEN_PORT}/" | tee "$WORK/local.body"
grep -q "pidfd-ok" "$WORK/local.body"

echo "--- baseline steered curl ---"
curl -sS --max-time 3 "http://127.0.0.1:${STEER_PORT}/" | tee "$WORK/base.body"
grep -q "pidfd-ok" "$WORK/base.body"

echo "--- reserve= refuses non-inner reserved port ---"
# 8080 is also an inner real listen; overlap fails first. 19099 is reserve-only.
if "$LOADER_BIN" add -tenant demo -site local \
    -pin-dir "$PIN_DIR" -ports-file "$PORTS_FILE" -policy-file "$POLICY_FILE" \
    -nginx-conf "$NGINX_CONF" \
    19099 \
    >"$WORK/reserve.out" 2>"$WORK/reserve.err"; then
  echo "FAIL: add 19099 should be reserved" >&2
  cat "$WORK/reserve.out" "$WORK/reserve.err" >&2
  exit 1
fi
if ! grep -q reserved "$WORK/reserve.err" "$WORK/reserve.out"; then
  echo "FAIL: reserve reject did not mention reserved" >&2
  cat "$WORK/reserve.out" "$WORK/reserve.err" >&2
  exit 1
fi
echo "reserve reject: $(tr '\n' ' ' < "$WORK/reserve.err")"

echo "--- kill worker (loader dup may still look LISTEN) ---"
kill -TERM "$WORKER_PID"
wait "$WORKER_PID" 2>/dev/null || true
WORKER_PID=""

echo "--- steered curl while owner dead (expect fail) ---"
if curl -sS --max-time 1 "http://127.0.0.1:${STEER_PORT}/" 2>/dev/null | grep -q "pidfd-ok"; then
  echo "FAIL: steered curl still worked after owner death with no replacement" >&2
  cat "$LOADER_LOG" >&2
  exit 1
fi

echo "--- start replacement worker ---"
start_worker "$LISTEN_PORT"

echo "--- SIGUSR1 + wait for pidfd SOCKMAP re-insert ---"
# Health-stale alone is not enough: SO_REUSEPORT can answer before SOCKMAP swaps.
ok=0
for _ in $(seq 1 50); do
  kill -USR1 "$LOADER_PID" 2>/dev/null || true
  if grep -E "rescan-listen swapped|listen rescan changed" "$LOADER_LOG"; then
    ok=1
    break
  fi
  sleep 0.1
done
if [[ "$ok" -ne 1 ]]; then
  echo "FAIL: loader log has no SOCKMAP re-insert (swapped/changed)" >&2
  cat "$LOADER_LOG" >&2
  exit 1
fi
grep -E "listen health stale|rescan-listen swapped|listen rescan changed" "$LOADER_LOG"

echo "--- steered curl after re-insert ---"
curl -sS --max-time 3 "http://127.0.0.1:${STEER_PORT}/" | tee "$WORK/after.body"
grep -q "pidfd-ok" "$WORK/after.body"

echo "--- status capacity fields ---"
"$LOADER_BIN" status -pin-dir "$PIN_DIR" -ports-file "$PORTS_FILE" \
  -policy-file "$POLICY_FILE" -nginx-conf "$NGINX_CONF" >"$WORK/status.json"
python3 - "$WORK/status.json" <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["open_ports_max_entries"] == 131072, v
assert v["open_ports_entries"] >= 1, v
assert 8080 in v["reserved"], v
print("status capacity ok entries=%s reserved=%s" % (v["open_ports_entries"], v["reserved"]))
PY

echo "PIDFD_LISTEN_REINSERT_PASS"
