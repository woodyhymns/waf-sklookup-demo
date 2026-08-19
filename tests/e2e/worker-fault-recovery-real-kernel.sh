#!/usr/bin/env bash
# Real-kernel worker-loss gate for the sk_lookup data plane.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LOADER=${LOADER_BIN:-"$ROOT/rust/loader/target/release/waf-sklookup-loader"}
ART=${ART_DIR:-"$ROOT/artifacts/worker-fault-recovery-real-kernel"}
[[ $EUID -eq 0 ]] || { echo "run as root (or: sudo $0)" >&2; exit 2; }
[[ -x "$LOADER" ]] || { echo "missing release loader: $LOADER" >&2; exit 2; }
rm -rf "$ART"; mkdir -p "$ART"

unshare -m -n -f -- bash -s -- "$ROOT" "$LOADER" "$ART" <<'NS'
set -euo pipefail
ROOT=$1; LOADER=$2; ART=$3
mount --make-rprivate /
ip link set lo up
BASE=/tmp/waf-worker-fault
rm -rf "$BASE"; mkdir -p "$BASE/bpffs" "$BASE/work"
mount -t bpf bpf "$BASE/bpffs"
mkdir -p /run/waf-sklookup; mount -t tmpfs tmpfs /run/waf-sklookup
PIN="$BASE/bpffs/pin"; WORK="$BASE/work"
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
grep -q '^waf_sklookup_listen_shards 4$' "$ART/metrics-before.txt"
curl -fsS --max-time 2 http://127.0.0.1:18181/ >"$ART/http-before.txt"
grep -q '^local=127.0.0.1:18181$' "$ART/http-before.txt"

WORKER=$(awk '/READY worker=0 / {for (i=1;i<=NF;i++) if ($i ~ /^pid=/) {sub(/^pid=/,"",$i); print $i; exit}}' "$ART/workers.log")
[[ -n "$WORKER" ]]
kill -TERM "$WORKER"
# Owner pidfd detection plus 200ms rescan must converge to the remaining three
# listener sockets before the no-loss sample begins.
for _ in $(seq 1 20); do
  curl -fsS --max-time 1 http://127.0.0.1:19104/metrics >"$ART/metrics-after-kill.txt" && \
    grep -q '^waf_sklookup_listen_shards 3$' "$ART/metrics-after-kill.txt" && break
  sleep 0.2
done
grep -q '^waf_sklookup_listen_shards 3$' "$ART/metrics-after-kill.txt"
for _ in $(seq 1 300); do
  curl -fsS --max-time 1 http://127.0.0.1:18181/ >>"$ART/http-after-kill.txt"
done
grep -c '^local=127.0.0.1:18181$' "$ART/http-after-kill.txt" | grep -qx '300'
curl -fsS --max-time 1 http://127.0.0.1:19104/metrics >"$ART/metrics-after-sample.txt"
grep -q '^waf_sklookup_no_slot_total 0$' "$ART/metrics-after-sample.txt"
grep -q '^waf_sklookup_assign_err_esocktnosupport_total 0$' "$ART/metrics-after-sample.txt"
echo 'WORKER FAULT RECOVERY REAL-KERNEL PASS' | tee "$ART/result.txt"
NS

echo "PASS: worker fault recovery evidence: $ART"
