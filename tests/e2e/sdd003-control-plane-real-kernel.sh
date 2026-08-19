#!/usr/bin/env bash
# SDD-003 control-plane production gate: projected map pressure, durable freeze,
# expected-revision compare-and-set, and serialized Unix-socket mutations.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LOADER=${LOADER_BIN:-"$ROOT/rust/loader/target/release/waf-sklookup-loader"}
ART=${ART_DIR:-"$ROOT/artifacts/sdd003-control-plane-real-kernel"}
[[ $EUID -eq 0 ]] || { echo "run as root (or: sudo $0)" >&2; exit 2; }
[[ -x "$LOADER" ]] || { echo "missing release loader: $LOADER" >&2; exit 2; }
rm -rf "$ART"; mkdir -p "$ART"

unshare -m -n -f -- bash -s -- "$ROOT" "$LOADER" "$ART" <<'NS'
set -euo pipefail
ROOT=$1; LOADER=$2; ART=$3
mount --make-rprivate /
ip link set lo up
BASE=/tmp/waf-sdd003-control
rm -rf "$BASE"; mkdir -p "$BASE/bpffs" "$BASE/work"
mount -t bpf bpf "$BASE/bpffs"
mkdir -p /run/waf-sklookup; mount -t tmpfs tmpfs /run/waf-sklookup
PIN="$BASE/bpffs/pin"; WORK="$BASE/work"; FREEZE=/run/waf-sklookup/frozen
cleanup() {
  set +e
  [[ -n "${LOADER_PID:-}" ]] && kill -TERM "$LOADER_PID" 2>/dev/null
  [[ -n "${SERVER_PID:-}" ]] && kill -TERM "$SERVER_PID" 2>/dev/null
  [[ -n "${LOADER_PID:-}" ]] && wait "$LOADER_PID" 2>/dev/null
  [[ -n "${SERVER_PID:-}" ]] && wait "$SERVER_PID" 2>/dev/null
  umount /run/waf-sklookup 2>/dev/null
  umount "$BASE/bpffs" 2>/dev/null
}
trap cleanup EXIT

cat >"$WORK/policy.conf" <<'POLICY'
deny=22,25,53,3306,6379
reserve=8080,8443,9101
allow_privileged=
max_ports_per_tenant=2000
max_ports_per_machine=2000
pressure_freeze_pct=1
POLICY
printf '18181 acme www\n' >"$WORK/ports.conf"
python3 "$ROOT/tests/e2e/reuseport_http_server.py" --listen 127.0.0.1:18080 --workers 4 >"$ART/workers.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do grep -q 'READY worker=3' "$ART/workers.log" && break; sleep 0.1; done
grep -q 'READY worker=3' "$ART/workers.log"
"$LOADER" -mode openresty -bpf c -target 127.0.0.1:18080 \
  -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" -pin-dir "$PIN" \
  -metrics-listen 127.0.0.1:19104 -ctl-sock "$WORK/ctl.sock" -rescan-interval 200ms \
  >"$ART/loader.log" 2>&1 &
LOADER_PID=$!
for _ in $(seq 1 100); do curl -fsS --max-time 0.2 http://127.0.0.1:19104/metrics >"$ART/metrics-before.txt" 2>/dev/null && break; sleep 0.1; done
grep -q '^waf_sklookup_open_ports_entries 1$' "$ART/metrics-before.txt"

# Fill just below the exact 1% threshold: 1 existing + 1309 = 1310 entries,
# below 1% of 131072. The next projected add must freeze before any mutation.
"$LOADER" bulk fill -start 30000 -count 1309 -tenant acme -site www -full-ladder \
  -pin-dir "$PIN" -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" \
  -freeze-file "$FREEZE" -quiet >"$ART/fill-below-threshold.out" 2>"$ART/fill-below-threshold.err"
"$LOADER" status -pin-dir "$PIN" -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" \
  -freeze-file "$FREEZE" >"$ART/status-before-pressure.json"
grep -q '"map_count":1310' "$ART/status-before-pressure.json"
BEFORE_REV=$(python3 -c 'import json; print(json.load(open("'$ART'/status-before-pressure.json"))["desired_revision"])')
set +e
CTL_SOCK="$WORK/ctl.sock" "$LOADER" ctl add 32000 -addr 127.0.0.2 -tenant acme -site www \
  -expected-revision "$BEFORE_REV" >"$ART/pressure-reject.json" 2>"$ART/pressure-reject.err"
RC=$?
set -e
[[ $RC -ne 0 ]]
grep -qi 'pressure\|capacity' "$ART/pressure-reject.json"
[[ -e "$FREEZE" ]]
"$LOADER" status -pin-dir "$PIN" -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" \
  -freeze-file "$FREEZE" >"$ART/status-after-pressure.json"
grep -q '"map_count":1310' "$ART/status-after-pressure.json"
grep -q "\"desired_revision\":\"$BEFORE_REV\"" "$ART/status-after-pressure.json"
grep -q '"last_rejection_reason":"capacity"' "$ART/status-after-pressure.json"
curl -fsS --max-time 1 http://127.0.0.1:19104/metrics >"$ART/metrics-after-pressure.txt"
grep -q '^waf_sklookup_control_plane_frozen 1$' "$ART/metrics-after-pressure.txt"

# Explicit recovery is required before the next approved mutation.
"$LOADER" unfreeze -freeze-file "$FREEZE" >"$ART/unfreeze.out"
[[ ! -e "$FREEZE" ]]
# Leave pressure policy in place but use a fresh smaller desired-state scenario
# for CAS: it has enough remaining quota and is below threshold.
"$LOADER" bulk remove -range 30000-31308 -full-ladder -quiet \
  -pin-dir "$PIN" -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" \
  -freeze-file "$FREEZE" >"$ART/drain.out" 2>"$ART/drain.err"
"$LOADER" status -pin-dir "$PIN" -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" \
  -freeze-file "$FREEZE" >"$ART/status-before-cas.json"
REV=$(python3 -c 'import json; print(json.load(open("'$ART'/status-before-cas.json"))["desired_revision"])')

# Two clients intentionally race with one revision. One is accepted; one must
# receive a bounded revision rejection, proving stale writers cannot overwrite
# an intervening desired-state mutation.
set +e
CTL_SOCK="$WORK/ctl.sock" "$LOADER" ctl add 32001 -addr 127.0.0.2 -tenant acme -site www -expected-revision "$REV" >"$ART/cas-a.json" 2>"$ART/cas-a.err" &
A=$!
CTL_SOCK="$WORK/ctl.sock" "$LOADER" ctl add 32002 -addr 127.0.0.2 -tenant acme -site www -expected-revision "$REV" >"$ART/cas-b.json" 2>"$ART/cas-b.err" &
B=$!
wait "$A"; RA=$?
wait "$B"; RB=$?
set -e
[[ $((RA + RB)) -ne 0 ]]
[[ $RA -eq 0 || $RB -eq 0 ]]
grep -q 'stale desired revision' "$ART/cas-a.json" "$ART/cas-b.json"
"$LOADER" status -pin-dir "$PIN" -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" \
  -freeze-file "$FREEZE" >"$ART/status-after-cas.json"
grep -q '"map_count":2' "$ART/status-after-cas.json"
grep -q '"file_map_agree":true' "$ART/status-after-cas.json"
grep -q '"last_rejection_reason":"revision"' "$ART/status-after-cas.json"
curl -fsS --max-time 2 http://127.0.0.1:18181/ >"$ART/http-after-cas.txt"
grep -q '^local=127.0.0.1:18181$' "$ART/http-after-cas.txt"
echo 'SDD-003 CONTROL-PLANE REAL-KERNEL PASS' | tee "$ART/result.txt"
NS

echo "PASS: SDD-003 control-plane real-kernel evidence: $ART"
