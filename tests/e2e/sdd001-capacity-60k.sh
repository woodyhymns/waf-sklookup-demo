#!/usr/bin/env bash
# SDD-001 / T-005, T-006, T-007.
#
# This test intentionally creates a private network namespace *and* a private
# bpffs mount. It validates that identity sidecars stay on /run (not bpffs),
# policy reserves keep the metrics listener reachable, and a real 60K BPF map
# snapshot reports coherent capacity gauges.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LOADER=${LOADER_BIN:-"$ROOT/rust/loader/target/release/waf-sklookup-loader"}
ART=${ART_DIR:-"$ROOT/artifacts/sdd001-capacity-60k"}
COUNT=${COUNT:-60000}

if [[ "${1:-}" != "--inside" ]]; then
  [[ $EUID -eq 0 ]] || { echo "run as root (or: sudo $0)" >&2; exit 2; }
  [[ $COUNT -eq 60000 ]] || { echo "this acceptance script requires COUNT=60000" >&2; exit 2; }
  [[ -x "$LOADER" ]] || { echo "missing release loader: $LOADER" >&2; exit 2; }
  rm -rf "$ART"
  mkdir -p "$ART"
  exec unshare -m -n -f -- "$0" --inside "$ROOT" "$LOADER" "$ART"
fi

ROOT=$2
LOADER=$3
ART=$4
mount --make-rprivate /
ip link set lo up
mkdir -p /tmp/waf-sdd001-capacity/bpffs /tmp/waf-sdd001-capacity/work
mount -t bpf bpf /tmp/waf-sdd001-capacity/bpffs
PIN=/tmp/waf-sdd001-capacity/bpffs/pin
WORK=/tmp/waf-sdd001-capacity/work

cleanup() {
  set +e
  [[ -n "${LOADER_PID:-}" ]] && kill -TERM "$LOADER_PID" 2>/dev/null
  [[ -n "${SERVER_PID:-}" ]] && kill -TERM "$SERVER_PID" 2>/dev/null
  [[ -n "${LOADER_PID:-}" ]] && wait "$LOADER_PID" 2>/dev/null
  [[ -n "${SERVER_PID:-}" ]] && wait "$SERVER_PID" 2>/dev/null
  umount /tmp/waf-sdd001-capacity/bpffs 2>/dev/null
}
trap cleanup EXIT

cat >"$WORK/policy.conf" <<'POLICY'
deny=22,25,53,3306,6379
# Protect management and fixed listeners from wildcard dynamic bindings.
reserve=8080,8443,9101
allow_privileged=
# no-file bulk admission includes the one seeded binding plus the 60K request.
max_ports_per_tenant=60001
max_ports_per_machine=60001
POLICY
printf '18181 m3 capacity\n' >"$WORK/ports.conf"

python3 "$ROOT/tests/e2e/reuseport_http_server.py" \
  --listen 127.0.0.1:18080 --workers 4 >"$ART/workers.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  grep -q 'READY worker=3' "$ART/workers.log" && break
  sleep 0.1
done
grep -q 'READY worker=3' "$ART/workers.log"

"$LOADER" -mode openresty -bpf c -target 127.0.0.1:18080 \
  -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" \
  -pin-dir "$PIN" -metrics-listen 127.0.0.1:9101 -no-ctl \
  -rescan-interval 200ms >"$ART/loader.log" 2>&1 &
LOADER_PID=$!
for _ in $(seq 1 100); do
  curl -fsS --max-time 0.2 http://127.0.0.1:9101/metrics >"$ART/baseline.metrics" 2>/dev/null && break
  sleep 0.1
done
grep -q '^waf_sklookup_open_ports_entries 1$' "$ART/baseline.metrics"

START_NS=$(date +%s%N)
"$LOADER" bulk fill -count 60000 -start 5000 \
  -skip 22,25,53,3306,6379,8080,8443,9101,18080 \
  -tenant m3 -site capacity -pin-dir "$PIN" -policy-file "$WORK/policy.conf" \
  -no-file -full-ladder >"$ART/60k.fill.out" 2>"$ART/60k.fill.err"
END_NS=$(date +%s%N)
printf 'wall_ms=%.3f\n' "$((END_NS - START_NS))e-6" >"$ART/60k.wall"

"$LOADER" list -count -pin-dir "$PIN" >"$ART/60k.count"
grep -qx 'count=60000' "$ART/60k.count"
curl -fsS --max-time 2 http://127.0.0.1:9101/metrics >"$ART/60k.metrics"
grep -qx 'waf_sklookup_open_ports_entries 60000' "$ART/60k.metrics"
grep -qx 'waf_sklookup_open_ports_max_entries 131072' "$ART/60k.metrics"
grep -qx 'waf_sklookup_open_ports_headroom_entries 71072' "$ART/60k.metrics"
grep -qx 'waf_sklookup_open_ports_pressure_ratio 0.457763671875' "$ART/60k.metrics"

curl -fsS --max-time 2 http://127.0.0.1:5000/ >"$ART/60k.port-5000.txt"
grep -qx 'local=127.0.0.1:5000' "$ART/60k.port-5000.txt"

"$LOADER" close-all -pin-dir "$PIN" >"$ART/60k.close.out" 2>"$ART/60k.close.err"
"$LOADER" list -count -pin-dir "$PIN" >"$ART/60k.post-close.count"
grep -qx 'count=0' "$ART/60k.post-close.count"

echo 'SDD-001 60K REAL-KERNEL PASS' | tee "$ART/result.txt"
