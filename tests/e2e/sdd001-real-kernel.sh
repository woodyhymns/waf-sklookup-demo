#!/usr/bin/env bash
# SDD-001 / T-002, T-005, T-007.
#
# Run the BPF dataplane inside a private network+mount namespace. This is not
# merely test hygiene: wildcard sk_lookup bindings legitimately match every
# address in their netns, so running a broad port test in the host management
# namespace could capture a CI agent or metrics connection.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LOADER=${LOADER_BIN:-"$ROOT/rust/loader/target/release/waf-sklookup-loader"}
ART=${ART_DIR:-"$ROOT/artifacts/sdd001-real-kernel"}

[[ $EUID -eq 0 ]] || { echo "run as root (or: sudo $0)" >&2; exit 2; }
[[ -x "$LOADER" ]] || { echo "missing release loader: $LOADER" >&2; exit 2; }

rm -rf "$ART"
mkdir -p "$ART"

# Keep the outer shell's management network untouched. The nested shell owns
# loopback, bpffs, the BPF link, and all temporary sockets.
unshare -m -n -f -- bash -s -- "$ROOT" "$LOADER" "$ART" <<'NS'
set -euo pipefail
ROOT=$1
LOADER=$2
ART=$3

mount --make-rprivate /
ip link set lo up
mkdir -p /tmp/waf-sdd001/bpffs
mount -t bpf bpf /tmp/waf-sdd001/bpffs
PIN=/tmp/waf-sdd001/bpffs/pin
WORK=/tmp/waf-sdd001/work
mkdir -p "$WORK"

cleanup() {
  set +e
  [[ -n "${LOADER_PID:-}" ]] && kill -TERM "$LOADER_PID" 2>/dev/null
  [[ -n "${SERVER_PID:-}" ]] && kill -TERM "$SERVER_PID" 2>/dev/null
  [[ -n "${LOADER_PID:-}" ]] && wait "$LOADER_PID" 2>/dev/null
  [[ -n "${SERVER_PID:-}" ]] && wait "$SERVER_PID" 2>/dev/null
  umount /tmp/waf-sdd001/bpffs 2>/dev/null
}
trap cleanup EXIT

cat >"$WORK/policy.conf" <<'POLICY'
deny=22,25,53,3306,6379
# SDD-001: bind management plane only on reserved endpoints.
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
  -pin-dir "$PIN" -metrics-listen 127.0.0.1:9101 -no-ctl \
  -rescan-interval 200ms >"$ART/loader.log" 2>&1 &
LOADER_PID=$!
for _ in $(seq 1 100); do
  curl -fsS --max-time 0.2 http://127.0.0.1:9101/metrics >"$ART/metrics-before.txt" 2>/dev/null && break
  sleep 0.1
done
grep -q '^waf_sklookup_open_ports_entries 1$' "$ART/metrics-before.txt"
grep -q '^waf_sklookup_open_ports_max_entries 131072$' "$ART/metrics-before.txt"
grep -q '^waf_sklookup_open_ports_pressure_ratio 0.00000762939453125$' "$ART/metrics-before.txt"
grep -q '^waf_sklookup_open_ports_headroom_entries 131071$' "$ART/metrics-before.txt"

# A real SYN to an unbound external port must reach the internal listener and
# preserve its original local port for WAF/Lua policy classification.
curl -fsS --max-time 2 http://127.0.0.1:18181/ >"$ART/steered-18181.txt"
grep -q '^local=127.0.0.1:18181$' "$ART/steered-18181.txt"

# Direct pinned-map control invocation must fail before mutation because policy
# reserves the exporter port. The exporter remains reachable and the entry
# count remains exactly one afterwards.
set +e
"$LOADER" add 9101 -tenant acme -site www -pin-dir "$PIN" \
  -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" \
  >"$ART/reserve-reject.out" 2>"$ART/reserve-reject.err"
RC=$?
set -e
[[ $RC -ne 0 ]]
grep -q 'reserved by policy' "$ART/reserve-reject.err"
curl -fsS --max-time 1 http://127.0.0.1:9101/metrics >"$ART/metrics-after-reject.txt"
grep -q '^waf_sklookup_open_ports_entries 1$' "$ART/metrics-after-reject.txt"

echo 'SDD-001 REAL-KERNEL PASS' | tee "$ART/result.txt"
NS

echo "PASS: SDD-001 real-kernel evidence: $ART"
