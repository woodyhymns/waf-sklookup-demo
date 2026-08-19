#!/usr/bin/env bash
# Exercises the map-first compensation path with a real pinned open_ports map.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LOADER=${LOADER_BIN:-"$ROOT/rust/loader/target/release/waf-sklookup-loader"}
ART=${ART_DIR:-"$ROOT/artifacts/control-plane-file-rollback-real-kernel"}
[[ $EUID -eq 0 ]] || { echo "run as root (or: sudo $0)" >&2; exit 2; }
[[ -x "$LOADER" ]] || { echo "missing release loader: $LOADER" >&2; exit 2; }
rm -rf "$ART"; mkdir -p "$ART"

unshare -m -n -f -- bash -s -- "$ROOT" "$LOADER" "$ART" <<'NS'
set -euo pipefail
ROOT=$1; LOADER=$2; ART=$3
mount --make-rprivate /
ip link set lo up
BASE=/tmp/waf-file-rollback
rm -rf "$BASE"; mkdir -p "$BASE/bpffs" "$BASE/work" "$BASE/desired-ro"
mount -t bpf bpf "$BASE/bpffs"
mkdir -p /run/waf-sklookup; mount -t tmpfs tmpfs /run/waf-sklookup
PIN="$BASE/bpffs/pin"; WORK="$BASE/work"; RODIR="$BASE/desired-ro"
cleanup() {
  set +e
  [[ -n "${LOADER_PID:-}" ]] && kill -TERM "$LOADER_PID" 2>/dev/null
  [[ -n "${SERVER_PID:-}" ]] && kill -TERM "$SERVER_PID" 2>/dev/null
  [[ -n "${LOADER_PID:-}" ]] && wait "$LOADER_PID" 2>/dev/null
  [[ -n "${SERVER_PID:-}" ]] && wait "$SERVER_PID" 2>/dev/null
  umount "$RODIR" 2>/dev/null
  umount /run/waf-sklookup 2>/dev/null
  umount "$BASE/bpffs" 2>/dev/null
}
trap cleanup EXIT
cat >"$WORK/policy.conf" <<'POLICY'
deny=22,25,53,3306,6379
reserve=8080,8443,9101
allow_privileged=
max_ports_per_tenant=32
max_ports_per_machine=128
POLICY
printf '18181 acme www\n' >"$WORK/ports.conf"
python3 "$ROOT/tests/e2e/reuseport_http_server.py" --listen 127.0.0.1:18080 --workers 4 >"$ART/workers.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do grep -q 'READY worker=3' "$ART/workers.log" && break; sleep 0.1; done
grep -q 'READY worker=3' "$ART/workers.log"
"$LOADER" -mode openresty -bpf c -target 127.0.0.1:18080 \
  -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" -pin-dir "$PIN" \
  -metrics-listen 127.0.0.1:19104 -rescan-interval 200ms >"$ART/loader.log" 2>&1 &
LOADER_PID=$!
for _ in $(seq 1 100); do curl -fsS --max-time 0.2 http://127.0.0.1:19104/metrics >"$ART/metrics-before.txt" 2>/dev/null && break; sleep 0.1; done
grep -q '^waf_sklookup_open_ports_entries 1$' "$ART/metrics-before.txt"

# Mount the parent of a copied desired file read-only. The direct CLI can still
# read it and mutate the real BPF map, but its atomic tmp-file/rename commit
# must fail. map_then_file must restore the pre-mutation map snapshot.
cp "$WORK/ports.conf" "$RODIR/ports.conf"
mount -t tmpfs tmpfs "$RODIR"
# Recreate after mount, then make the mount readonly without changing process
# uid/capabilities; this is a real filesystem commit failure, not a fake hook.
printf '18181 acme www\n' >"$RODIR/ports.conf"
mount -o remount,ro "$RODIR"
set +e
"$LOADER" add 32009 -addr 127.0.0.2 -tenant acme -site www \
  -pin-dir "$PIN" -ports-file "$RODIR/ports.conf" -policy-file "$WORK/policy.conf" \
  >"$ART/add-ro.out" 2>"$ART/add-ro.err"
RC=$?
set -e
[[ $RC -ne 0 ]]
grep -q 'dataplane mutation was rolled back' "$ART/add-ro.err"
"$LOADER" status -pin-dir "$PIN" -ports-file "$RODIR/ports.conf" -policy-file "$WORK/policy.conf" \
  >"$ART/status-after-failed-file-commit.json"
grep -q '"map_count":1' "$ART/status-after-failed-file-commit.json"
grep -q '"file_map_agree":true' "$ART/status-after-failed-file-commit.json"
# The failed external port remains unbound/no map entry; no worker response is allowed.
set +e
curl -fsS --max-time 1 http://127.0.0.2:32009/ >"$ART/failed-port-response.txt" 2>"$ART/failed-port-curl.err"
CURL_RC=$?
set -e
[[ $CURL_RC -ne 0 ]]
echo 'CONTROL-PLANE FILE-ROLLBACK REAL-KERNEL PASS' | tee "$ART/result.txt"
NS

echo "PASS: control-plane file rollback evidence: $ART"
