#!/usr/bin/env bash
# SDD-003 / T-040..T-047: live single-link upgrade and rollback.
# Run as root. A private network+mount namespace prevents the temporary
# sk_lookup dataplane from intercepting host management traffic.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LOADER=${LOADER_BIN:-"$ROOT/rust/loader/target/release/waf-sklookup-loader"}
ART=${ART_DIR:-"$ROOT/artifacts/sdd003-real-kernel-upgrade"}
[[ $EUID -eq 0 ]] || { echo "run as root (or: sudo $0)" >&2; exit 2; }
[[ -x "$LOADER" ]] || { echo "missing release loader: $LOADER" >&2; exit 2; }
command -v clang >/dev/null || { echo "missing clang" >&2; exit 2; }
rm -rf "$ART"; mkdir -p "$ART"

unshare -m -n -f -- bash -s -- "$ROOT" "$LOADER" "$ART" <<'NS'
set -euo pipefail
ROOT=$1; LOADER=$2; ART=$3
mount --make-rprivate /
ip link set lo up
BASE=/tmp/waf-sdd003
# /tmp itself is a shared filesystem even in this private network/mount
# namespace. Remove prior run state so an intentional rollback freeze never
# contaminates a later commit-path drill.
rm -rf "$BASE"
PIN="$BASE/bpffs/pin"; WORK="$BASE/work"
mkdir -p "$BASE/bpffs" "$WORK"
mount -t bpf bpf "$BASE/bpffs"
# Keep default runtime sidecars/freeze private to this drill while letting the
# exporter exercise the exact production default path.
mkdir -p /run/waf-sklookup
mount -t tmpfs tmpfs /run/waf-sklookup
FREEZE=/run/waf-sklookup/frozen
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
pressure_freeze_pct=85
POLICY
printf '18181 acme www\n' >"$WORK/ports.conf"

python3 "$ROOT/tests/e2e/reuseport_http_server.py" --listen 127.0.0.1:18080 --workers 4 >"$ART/workers.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do grep -q 'READY worker=3' "$ART/workers.log" && break; sleep 0.1; done
grep -q 'READY worker=3' "$ART/workers.log"

"$LOADER" -mode openresty -bpf c -target 127.0.0.1:18080 \
  -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" \
  -pin-dir "$PIN" -metrics-listen 127.0.0.1:19104 -ctl-sock "$WORK/ctl.sock" \
  -rescan-interval 200ms >"$ART/loader.log" 2>&1 &
LOADER_PID=$!
for _ in $(seq 1 100); do curl -fsS --max-time 0.2 http://127.0.0.1:19104/metrics >"$ART/metrics-before.txt" 2>/dev/null && break; sleep 0.1; done
grep -q '^waf_sklookup_open_ports_entries 1$' "$ART/metrics-before.txt"
curl -fsS --max-time 1 http://127.0.0.1:19104/healthz >"$ART/health-before.txt"
grep -qx 'ready' "$ART/health-before.txt"
curl -fsS --max-time 2 http://127.0.0.1:18181/ >"$ART/http-before.txt"
grep -q '^local=127.0.0.1:18181$' "$ART/http-before.txt"

# Build a ABI-compatible candidate with a deliberately different instruction
# tag. The branch is unreachable for legal ports but survives compilation.
cp "$ROOT/dispatch.bpf.c" "$WORK/candidate.c"
sed -i '/^int dispatch(struct bpf_sk_lookup \*ctx)/,/^{$/{ /^{$/a\\    if (ctx->local_port == 0) return SK_PASS; /* SDD-003 upgrade drill marker */
}' "$WORK/candidate.c"
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I"$ROOT/bpf/headers" -I/usr/include/x86_64-linux-gnu \
  -c "$WORK/candidate.c" -o "$WORK/candidate.bpf.o"

"$LOADER" status -pin-dir "$PIN" -ports-file "$WORK/ports.conf" -policy-file "$WORK/policy.conf" >"$ART/status-before.json"
"$LOADER" upgrade -candidate "$WORK/candidate.bpf.o" -health-window-ms 25 \
  -pin-dir "$PIN" -freeze-file "$FREEZE" >"$ART/upgrade-commit.json" 2>"$ART/upgrade-commit.err"
grep -q '"phase":"committed"' "$ART/upgrade-commit.json"
[[ ! -e "$FREEZE" ]]
"$LOADER" upgrade status -pin-dir "$PIN" >"$ART/upgrade-status-commit.json"
grep -q '"phase":"committed"' "$ART/upgrade-status-commit.json"
curl -fsS --max-time 2 http://127.0.0.1:18181/ >"$ART/http-after-commit.txt"
grep -q '^local=127.0.0.1:18181$' "$ART/http-after-commit.txt"
curl -fsS --max-time 1 http://127.0.0.1:19104/metrics >"$ART/metrics-after-commit.txt"
grep -q '^waf_sklookup_control_plane_frozen 0$' "$ART/metrics-after-commit.txt"
grep -q 'waf_sklookup_upgrade_phase{phase="committed"} 1' "$ART/metrics-after-commit.txt"
curl -fsS --max-time 1 http://127.0.0.1:19104/healthz >"$ART/health-after-commit.txt"
grep -qx 'ready' "$ART/health-after-commit.txt"

# Build another different-but-compatible tag and force health failure. The
# command must leave a rolled_back journal and preserve traffic.
sed -i 's/ctx->local_port == 0/ctx->local_port == 1/' "$WORK/candidate.c"
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I"$ROOT/bpf/headers" -I/usr/include/x86_64-linux-gnu \
  -c "$WORK/candidate.c" -o "$WORK/candidate-rollback.bpf.o"
set +e
WAF_UPGRADE_FAIL_HEALTH=1 "$LOADER" upgrade -candidate "$WORK/candidate-rollback.bpf.o" \
  -health-window-ms 25 -pin-dir "$PIN" -freeze-file "$FREEZE" \
  >"$ART/upgrade-rollback.out" 2>"$ART/upgrade-rollback.err"
RC=$?
set -e
[[ $RC -ne 0 ]]
[[ -e "$FREEZE" ]]
curl -sS --max-time 1 -o "$ART/health-during-rollback.txt" -w '%{http_code}' http://127.0.0.1:19104/healthz >"$ART/health-during-rollback.code"
grep -qx '503' "$ART/health-during-rollback.code"
grep -qx 'frozen' "$ART/health-during-rollback.txt"
curl -fsS --max-time 1 http://127.0.0.1:19104/metrics >"$ART/metrics-after-rollback.txt"
grep -q '^waf_sklookup_control_plane_frozen 1$' "$ART/metrics-after-rollback.txt"
grep -q 'waf_sklookup_upgrade_phase{phase="rolledback"} 1' "$ART/metrics-after-rollback.txt"
"$LOADER" upgrade status -pin-dir "$PIN" >"$ART/upgrade-status-rollback.json"
grep -q '"phase":"rolled_back"' "$ART/upgrade-status-rollback.json"
curl -fsS --max-time 2 http://127.0.0.1:18181/ >"$ART/http-after-rollback.txt"
grep -q '^local=127.0.0.1:18181$' "$ART/http-after-rollback.txt"

# Operators explicitly clear fail-closed state only after journal inspection.
"$LOADER" unfreeze -freeze-file "$FREEZE" >"$ART/unfreeze.out"
[[ ! -e "$FREEZE" ]]
curl -fsS --max-time 1 http://127.0.0.1:19104/healthz >"$ART/health-after-unfreeze.txt"
grep -qx 'ready' "$ART/health-after-unfreeze.txt"
echo 'SDD-003 REAL-KERNEL UPGRADE PASS' | tee "$ART/result.txt"
NS

echo "PASS: SDD-003 real-kernel upgrade evidence: $ART"
