#!/usr/bin/env bash
# Last-resort nft DNAT acceptance.
#
#   ./scripts/accept-nft-dnat-fallback.sh
#
# Exit 77 (SKIP) when `nft` is absent — bake-off E was skipped for that reason.
# When nft is present: standalone DNAT must PASS. Optional unpin path runs
# when the loader can attach; it is last-line only (both sk_lookup pins gone).
#
# Does not merge or import #37 ABI. Default OFF: enable without --enable fails.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib-prod-gng.sh
source "$REPO_ROOT/scripts/lib-prod-gng.sh"
NFT_SH="$REPO_ROOT/scripts/nft-dnat-fallback.sh"
NFT_TABLE="${NFT_TABLE:-waf_sklookup_dnat}"

LISTEN_PORT="${NFT_ACCEPT_LISTEN:-19080}"
VIRT_PORT="${NFT_ACCEPT_VIRT:-19081}"
TARGET_HOST="${HOST:-127.0.0.1}"
TARGET="${TARGET_HOST}:${LISTEN_PORT}"

STARTED_HERE=0
HOLD_PY=""
PY_HTTP=""
PIN_REFUSE="跳过"

install_hygiene_traps
trap 'cleanup_extra; hygiene_cleanup' EXIT

cleanup_extra() {
  if [[ -n "${HOLD_PY}" ]] && kill -0 "${HOLD_PY}" 2>/dev/null; then
    kill "${HOLD_PY}" 2>/dev/null || true
  fi
  if [[ -n "${PY_HTTP}" ]] && kill -0 "${PY_HTTP}" 2>/dev/null; then
    kill "${PY_HTTP}" 2>/dev/null || true
  fi
  if [[ -n "${TOY_PID:-}" ]] && kill -0 "${TOY_PID}" 2>/dev/null; then
    sudo kill "${TOY_PID}" 2>/dev/null || true
  fi
}

skip() {
  echo "SKIP: $*" >&2
  exit 77
}

require_nft() {
  if ! command -v nft >/dev/null 2>&1; then
    skip "nft binary absent (same class as sandbox bake-off E)"
  fi
}

require_root_or_sudo() {
  if [[ "$(id -u)" == 0 ]]; then
    return 0
  fi
  if sudo -n true 2>/dev/null; then
    return 0
  fi
  skip "need root/sudo for nft nat (CAP_NET_ADMIN)"
}

start_http() {
  local port="$1" body="$2" log="$3"
  python3 - "$port" "$body" "$log" <<'PY' &
import socket, sys
port, body, log_path = int(sys.argv[1]), sys.argv[2], sys.argv[3]
payload = body.encode()
hdr = (
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
    f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
).encode()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(16)
open(log_path, "w").write("listen\n")
while True:
    c, _ = s.accept()
    try:
        c.recv(4096)
        c.sendall(hdr + payload)
    finally:
        c.close()
PY
  PY_HTTP=$!
  for _ in $(seq 1 50); do
    [[ -f "$log" ]] && grep -q '^listen$' "$log" && return 0
    sleep 0.05
  done
  echo "FAIL: python listen :$port did not start" >&2
  return 1
}

curl_code() {
  local url="$1" body="$2"
  set +e
  local code
  code="$(curl -sS -o "$body" -w '%{http_code}' --max-time 3 "$url" 2>/dev/null)"
  local rc=$?
  set -e
  echo "$rc $code"
}

echo "=== nft DNAT last-resort acceptance ==="
require_nft
require_root_or_sudo
chmod +x "$NFT_SH"

echo "--- refuse enable without explicit flag (default OFF) ---"
set +e
"$NFT_SH" enable --ports "$VIRT_PORT" --target "$TARGET" >/tmp/nft-dnat-noflag.out 2>/tmp/nft-dnat-noflag.err
NOFLAG_RC=$?
set -e
[[ $NOFLAG_RC -ne 0 ]] || {
  echo "FAIL: enable without --enable / WAF_NFT_FALLBACK=1 must refuse" >&2
  exit 1
}
grep -q 'default OFF\|enable refused' /tmp/nft-dnat-noflag.err || {
  echo "FAIL: missing default-OFF refusal text" >&2
  cat /tmp/nft-dnat-noflag.err >&2
  exit 1
}
FLAG_REFUSE="通过"

echo "--- reserved 80/443/inner reals stay out of the set ---"
mapfile -t RENDERED_PORTS < <("$NFT_SH" ports --ports "80,443,8080,8443,$VIRT_PORT" --target "$TARGET")
printf '%s\n' "${RENDERED_PORTS[@]}" | grep -qx "$VIRT_PORT"
! printf '%s\n' "${RENDERED_PORTS[@]}" | grep -Eqx '80|443|8080|8443'
RESERVED="通过"

echo "--- render is first-packet / NEW SYN ---"
RENDER="$("$NFT_SH" render --ports "$VIRT_PORT" --target "$TARGET")"
echo "$RENDER" | grep -q 'ct state new' || {
  echo "FAIL: render missing ct state new" >&2
  exit 1
}
echo "$RENDER" | grep -q 'tcp flags syn' || {
  echo "FAIL: render missing tcp flags syn" >&2
  exit 1
}
echo "$RENDER" | grep -q "dnat to ${TARGET_HOST}:${LISTEN_PORT}"
RENDER_OK="通过"

echo "--- refuse enable while a sk_lookup pin exists (no BPF needed) ---"
FAKE_PIN="$(mktemp -d "${TMPDIR:-/tmp}/nft-dnat-fake-pin.XXXXXX")"
touch "$FAKE_PIN/sk_lookup" "$FAKE_PIN/sk_lookup_backup"
set +e
"$NFT_SH" enable --enable --ports "$VIRT_PORT" --target "$TARGET" --pin-dir "$FAKE_PIN" \
  >/tmp/nft-dnat-fakepin.out 2>/tmp/nft-dnat-fakepin.err
FAKE_RC=$?
set -e
rm -rf "$FAKE_PIN"
[[ $FAKE_RC -ne 0 ]] || {
  echo "FAIL: enable must refuse while sk_lookup pins exist (no --force)" >&2
  exit 1
}
PIN_REFUSE="通过"

echo "--- standalone DNAT: python listen + NEW SYN on virtual port ---"
"$NFT_SH" disable --table "$NFT_TABLE" >/dev/null
rm -f /tmp/nft-dnat-http.listen
start_http "$LISTEN_PORT" "nft-dnat fallback OK" /tmp/nft-dnat-http.listen

HOLD_LOG=/tmp/nft-dnat-hold.log
rm -f "$HOLD_LOG"
python3 - "$TARGET_HOST" "$LISTEN_PORT" "$HOLD_LOG" <<'PY' &
import socket, sys, time
host, port, log_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.create_connection((host, port), 5)
s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n" % host.encode())
open(log_path, "w").write("held\n")
time.sleep(2.0)
if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != 0:
    open(log_path, "a").write("so_error\n")
    raise SystemExit("hold: socket error")
s.sendall(b"Connection: close\r\n\r\n")
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = s.recv(4096)
    if not chunk:
        open(log_path, "a").write("closed_before_headers\n")
        raise SystemExit("hold: established closed")
    buf += chunk
if b"200" not in buf.split(b"\r\n", 1)[0]:
    open(log_path, "a").write("not_200\n")
    raise SystemExit("hold: not 200")
open(log_path, "a").write("established_ok\n")
s.close()
PY
HOLD_PY=$!
for _ in $(seq 1 50); do
  [[ -f "$HOLD_LOG" ]] && grep -q '^held$' "$HOLD_LOG" && break
  sleep 0.05
done
grep -q '^held$' "$HOLD_LOG" || {
  echo "FAIL: could not hold established TCP on main listen" >&2
  exit 1
}

read -r BEFORE_RC BEFORE_CODE < <(curl_code "http://${TARGET_HOST}:${VIRT_PORT}/" /tmp/nft-dnat-before.body)
echo "before_nft curl_rc=$BEFORE_RC http_code=$BEFORE_CODE (expect fail)"
BEFORE_FAIL="失败"
if [[ "$BEFORE_RC" -ne 0 || "$BEFORE_CODE" != "200" ]]; then
  BEFORE_FAIL="通过"
fi

if ! "$NFT_SH" enable --enable --ports "$VIRT_PORT" --target "$TARGET" --pin-dir "$PIN_DIR" --force; then
  echo "FAIL: nft enable failed (binary present; nat/conntrack missing?)" >&2
  exit 1
fi
# --force is used because this standalone phase does not unpin BPF; pins may
# exist from a leftover demo. Last-line unpin is the next optional phase.

read -r AFTER_RC AFTER_CODE < <(curl_code "http://${TARGET_HOST}:${VIRT_PORT}/" /tmp/nft-dnat-after.body)
echo "after_nft curl_rc=$AFTER_RC http_code=$AFTER_CODE"
NEW_SYN="失败"
if [[ "$AFTER_RC" -eq 0 && "$AFTER_CODE" == "200" ]] && grep -q "nft-dnat fallback OK" /tmp/nft-dnat-after.body; then
  NEW_SYN="通过"
fi

wait "$HOLD_PY"
HOLD_RC=$?
HOLD_PY=""
LONG_OK="失败"
if [[ $HOLD_RC -eq 0 ]] && grep -q 'established_ok' "$HOLD_LOG"; then
  LONG_OK="通过"
fi

"$NFT_SH" disable --table "$NFT_TABLE" >/dev/null
read -r OFF_RC OFF_CODE < <(curl_code "http://${TARGET_HOST}:${VIRT_PORT}/" /tmp/nft-dnat-off.body)
DISABLE_OK="失败"
if [[ "$OFF_RC" -ne 0 || "$OFF_CODE" != "200" ]]; then
  DISABLE_OK="通过"
fi

if [[ -n "${PY_HTTP}" ]] && kill -0 "${PY_HTTP}" 2>/dev/null; then
  kill "${PY_HTTP}" 2>/dev/null || true
fi
PY_HTTP=""

UNPIN_SYN="跳过"
UNPIN_HOLD="跳过"
if [[ "${NFT_ACCEPT_UNPIN:-1}" == "1" ]] && ensure_loader_bin; then
  echo "--- optional: unpin both sk_lookup links, then last-resort nft ---"
  set +e
  sudo "$LOADER_BIN" unpin -pin-dir "$PIN_DIR" >/dev/null 2>&1
  sudo "$LOADER_BIN" -mode toy -listen "${TARGET_HOST}:${LISTEN_PORT}" \
    -ports "$VIRT_PORT" -pin-dir "$PIN_DIR" -no-ctl \
    >"$STATE_DIR/nft-dnat-toy.log" 2>&1 &
  TOY_PID=$!
  echo "$TOY_PID" >"$STATE_DIR/loader.pid"
  for _ in $(seq 1 80); do
    grep -q 'TOY DEMO READY' "$STATE_DIR/nft-dnat-toy.log" 2>/dev/null && break
    [[ -d "/proc/$TOY_PID" ]] || break
    sleep 0.1
  done
  set -e
  if grep -q 'TOY DEMO READY' "$STATE_DIR/nft-dnat-toy.log" 2>/dev/null; then
    STARTED_HERE=1
    curl -sS --max-time 3 "http://${TARGET_HOST}:${VIRT_PORT}/" | grep -q "sk_lookup demo OK"
    set +e
    "$NFT_SH" enable --enable --ports "$VIRT_PORT" --target "$TARGET" --pin-dir "$PIN_DIR" \
      >/tmp/nft-dnat-while-pinned.out 2>/tmp/nft-dnat-while-pinned.err
    PIN_REFUSE_RC=$?
    set -e
    [[ $PIN_REFUSE_RC -ne 0 ]] || {
      echo "FAIL: enable must refuse while sk_lookup pins exist (no --force)" >&2
      exit 1
    }
    PIN_REFUSE="通过"
    UNPIN_HOLD_LOG=/tmp/nft-dnat-unpin-hold.log
    rm -f "$UNPIN_HOLD_LOG"
    python3 - "$TARGET_HOST" "$VIRT_PORT" "$UNPIN_HOLD_LOG" <<'PY' &
import socket, sys, time
host, port, log_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.create_connection((host, port), 5)
s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n" % host.encode())
open(log_path, "w").write("held\n")
time.sleep(2.5)
if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != 0:
    raise SystemExit("hold error")
s.sendall(b"Connection: close\r\n\r\n")
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = s.recv(4096)
    if not chunk:
        raise SystemExit("hold closed")
    buf += chunk
if b"200" not in buf.split(b"\r\n", 1)[0]:
    raise SystemExit("hold not 200")
open(log_path, "a").write("established_ok\n")
s.close()
PY
    HOLD_PY=$!
    for _ in $(seq 1 50); do
      [[ -f "$UNPIN_HOLD_LOG" ]] && grep -q '^held$' "$UNPIN_HOLD_LOG" && break
      sleep 0.05
    done
    sudo "$LOADER_BIN" unpin -pin-dir "$PIN_DIR"
    [[ ! -e "$PIN_DIR/sk_lookup" && ! -e "$PIN_DIR/sk_lookup_backup" ]] || {
      echo "FAIL: unpin left a sk_lookup pin" >&2
      exit 1
    }
    read -r GAP_RC GAP_CODE < <(curl_code "http://${TARGET_HOST}:${VIRT_PORT}/" /tmp/nft-dnat-gap.body)
    echo "after_unpin_before_nft curl_rc=$GAP_RC http_code=$GAP_CODE (expect fail)"
    "$NFT_SH" enable --enable --ports "$VIRT_PORT" --target "$TARGET" --pin-dir "$PIN_DIR"
    read -r U_RC U_CODE < <(curl_code "http://${TARGET_HOST}:${VIRT_PORT}/" /tmp/nft-dnat-unpin-after.body)
    echo "after_unpin_nft curl_rc=$U_RC http_code=$U_CODE"
    if [[ "$U_RC" -eq 0 && "$U_CODE" == "200" ]] && grep -q "sk_lookup demo OK" /tmp/nft-dnat-unpin-after.body; then
      UNPIN_SYN="通过"
    else
      UNPIN_SYN="失败"
    fi
    wait "$HOLD_PY" || true
    HOLD_RC=$?
    HOLD_PY=""
    if [[ $HOLD_RC -eq 0 ]] && grep -q 'established_ok' "$UNPIN_HOLD_LOG"; then
      UNPIN_HOLD="通过"
    else
      UNPIN_HOLD="失败"
    fi
    "$NFT_SH" disable --table "$NFT_TABLE" >/dev/null || true
    sudo kill "$TOY_PID" 2>/dev/null || true
    TOY_PID=""
  else
    echo "NOTE: toy attach skipped (no sk_lookup / loader attach failed)"
    sudo kill "$TOY_PID" 2>/dev/null || true
    TOY_PID=""
  fi
fi

echo
echo "### nft DNAT last-resort summary"
echo "| 项 | 结果 |"
echo "|----|------|"
mark_row "nft-present" "nft binary" "通过"
mark_row "default-off" "enable without flag refuses" "$FLAG_REFUSE"
mark_row "reserved-filtered" "80/443/8080/8443 omitted" "$RESERVED"
mark_row "render-new-syn" "ct state new + tcp flags syn" "$RENDER_OK"
mark_row "virt-fail-before" "virtual port fail before nft" "$BEFORE_FAIL"
mark_row "standalone-new-syn" "DNAT NEW SYN → main listen" "$NEW_SYN"
mark_row "established-stays" "held TCP on main listen completes" "$LONG_OK"
mark_row "disable-rollback" "virtual port fails after disable" "$DISABLE_OK"
mark_row "refuse-while-pinned" "enable refused while sk_lookup pins exist" "$PIN_REFUSE"
mark_row "unpin-then-nft" "both links gone; NEW SYN via nft" "$UNPIN_SYN"
mark_row "unpin-established" "sk_lookup-accepted TCP stays" "$UNPIN_HOLD"

if [[ "$FLAG_REFUSE" != "通过" || "$RESERVED" != "通过" || "$RENDER_OK" != "通过" \
   || "$BEFORE_FAIL" != "通过" || "$NEW_SYN" != "通过" || "$LONG_OK" != "通过" \
   || "$DISABLE_OK" != "通过" ]]; then
  echo "FAIL: nft last-resort criteria not met" >&2
  exit 1
fi
if [[ "$UNPIN_SYN" == "失败" || "$UNPIN_HOLD" == "失败" ]]; then
  echo "FAIL: unpin then nft last-line path failed" >&2
  exit 1
fi
echo "PASS"
exit 0
