#!/usr/bin/env bash
# SDD-002 / T-020..T-026.
#
# Verifies that a loopback metrics listener and a public ingress VIP can share
# a numeric port without a wildcard binding capturing the management endpoint.
# The test runs in a private network+mount namespace because sk_lookup wildcard
# keys are intentionally netns-wide.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LOADER=${LOADER_BIN:-"$ROOT/rust/loader/target/release/waf-sklookup-loader"}
ART=${ART_DIR:-"$ROOT/artifacts/sdd002-real-kernel"}

[[ $EUID -eq 0 ]] || { echo "run as root (or: sudo $0)" >&2; exit 2; }
[[ -x "$LOADER" ]] || { echo "missing release loader: $LOADER" >&2; exit 2; }
rm -rf "$ART"
mkdir -p "$ART"

unshare -m -n -f -- bash -s -- "$ROOT" "$LOADER" "$ART" <<'NS'
set -euo pipefail
ROOT=$1
LOADER=$2
ART=$3
mount --make-rprivate /
ip link set lo up
mkdir -p /tmp/waf-sdd002/bpffs
mount -t bpf bpf /tmp/waf-sdd002/bpffs
PIN=/tmp/waf-sdd002/bpffs/pin
WORK=/tmp/waf-sdd002/work
mkdir -p "$WORK"

cleanup() {
  set +e
  [[ -n "${LOADER_PID:-}" ]] && kill -TERM "$LOADER_PID" 2>/dev/null
  [[ -n "${SERVER_PID:-}" ]] && kill -TERM "$SERVER_PID" 2>/dev/null
  [[ -n "${LOADER_PID:-}" ]] && wait "$LOADER_PID" 2>/dev/null
  [[ -n "${SERVER_PID:-}" ]] && wait "$SERVER_PID" 2>/dev/null
  umount /tmp/waf-sdd002/bpffs 2>/dev/null
}
trap cleanup EXIT

cat >"$WORK/policy.conf" <<'POLICY'
deny=22,25,53,3306,6379
# Keep the legacy policy conservative while runtime endpoints demonstrate
# address-aware isolation on the same numeric port.
reserve=8080,8443,9101
allow_privileged=
max_ports_per_tenant=32
max_ports_per_machine=128
POLICY
cat >"$WORK/ports.conf" <<'PORTS'
18181 acme www
PORTS

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
  -pin-dir "$PIN" -metrics-listen 127.0.0.1:19104 -ctl-sock "$WORK/ctl.sock" \
  -rescan-interval 200ms >"$ART/loader.log" 2>&1 &
LOADER_PID=$!
for _ in $(seq 1 100); do
  curl -fsS --max-time 0.2 http://127.0.0.1:19104/metrics >"$ART/metrics-before.txt" 2>/dev/null && break
  sleep 0.1
done
grep -q '^waf_sklookup_open_ports_entries 1$' "$ART/metrics-before.txt"

# T-023/R3: loader wrote a sidecar outside private bpffs. The file itself is
# readable by detached ctl; its content is intentionally inspected only for
# bounded schema/source assertions here.
find /run/waf-sklookup/reservations -name '*.json' -print >"$ART/manifest-paths.txt"
[[ -s "$ART/manifest-paths.txt" ]]
grep -q 'metrics-listen' "$(head -1 "$ART/manifest-paths.txt")"

# T-021/R2: exact loopback metrics reservation rejects before map mutation.
set +e
"$LOADER" add 19104 -addr 127.0.0.1 -tenant acme -site www \
  -pin-dir "$PIN" -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" \
  >"$ART/loopback-reject.out" 2>"$ART/loopback-reject.err"
RC=$?
set -e
[[ $RC -ne 0 ]]
grep -q 'metrics-listen' "$ART/loopback-reject.err"
"$LOADER" status -pin-dir "$PIN" -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" \
  >"$ART/status-after-reject.json"
grep -q '"last_rejection_reason":"reservation"' "$ART/status-after-reject.json"
grep -q '"state":"active"' "$ART/status-after-reject.json"

# T-020/R1: the different exact VIP is admitted at the same numeric port.
"$LOADER" add 19104 -addr 127.0.0.2 -tenant acme -site www \
  -pin-dir "$PIN" -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" \
  >"$ART/public-vip-add.out" 2>"$ART/public-vip-add.err"
curl -fsS --max-time 2 http://127.0.0.2:19104/ >"$ART/public-vip-19104.txt"
grep -q '^local=127.0.0.2:19104$' "$ART/public-vip-19104.txt"
# The metrics endpoint remains local management traffic, not redirected.
curl -fsS --max-time 1 http://127.0.0.1:19104/metrics >"$ART/metrics-after-vip.txt"
grep -q '^waf_sklookup_open_ports_entries 2$' "$ART/metrics-after-vip.txt"

# The production socket path serializes mutations under the loader-owned mutex.
# Eight concurrent exact-VIP requests must all land in desired state/map; direct
# root CLI remains an emergency escape hatch and is intentionally not the
# concurrent production API.
client_pids=()
for port in $(seq 19120 19127); do
  CTL_SOCK="$WORK/ctl.sock" "$LOADER" ctl add "$port" -addr 127.0.0.2 \
    -tenant acme -site www >"$ART/socket-add-${port}.json" 2>"$ART/socket-add-${port}.err" &
  client_pids+=("$!")
done
for pid in "${client_pids[@]}"; do
  wait "$pid"
done
for port in $(seq 19120 19127); do
  grep -q '"ok":true' "$ART/socket-add-${port}.json"
done
curl -fsS --max-time 1 http://127.0.0.1:19104/metrics >"$ART/metrics-after-concurrency.txt"
grep -q '^waf_sklookup_open_ports_entries 10$' "$ART/metrics-after-concurrency.txt"
"$LOADER" status -pin-dir "$PIN" -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" \
  >"$ART/status-after-concurrency.json"
grep -q '"map_count":10' "$ART/status-after-concurrency.json"

# T-022/R1: an IPv4 reservation does not reject IPv6-only desired state at
# policy level. The real BPF listener stays IPv4 in this script, so exercise
# parser/admission through the unit test rather than sending an incompatible SYN.

echo 'SDD-002 REAL-KERNEL PASS' | tee "$ART/result.txt"
NS

echo "PASS: SDD-002 real-kernel evidence: $ART"
