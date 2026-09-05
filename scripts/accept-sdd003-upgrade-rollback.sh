#!/usr/bin/env bash
# SDD-003 on main ABI: bpf_link_update upgrade + health-fail rollback.
# Live primary link is never left without a program. New SYNs stay 200.
#
# Re-run:
#   sudo ./scripts/accept-sdd003-upgrade-rollback.sh
# Trap/hygiene regression (no BPF): ./tests/hygiene-trap-status.sh
#
# Builds a candidate from dispatch.bpf.c (u16 open_ports, 2-slot SOCKMAP).
# Does not use #37 objects.
set -euo pipefail
source "$(dirname "$0")/lib-prod-gng.sh"

STARTED_HERE=0
# Hygiene is EXIT-only. Missing-obj / WAF_UPGRADE_FAIL_HEALTH=1 are expected
# non-zero; those statuses are checked explicitly below (do not trap ERR).
install_hygiene_traps

require_root() {
  if [[ "$(id -u)" != 0 ]] && ! sudo -n true 2>/dev/null; then
    echo "SKIP: need root/CAP_BPF for sk_lookup attach (run with sudo or as root)" >&2
    exit 77
  fi
}

require_root
ensure_loader_bin

OBJ="${TMPDIR:-/tmp}/waf-sdd003-dispatch.bpf.o"
echo "=== SDD-003: compile main-ABI candidate $OBJ ==="
ARCH="$(uname -m)"
GNU_INC="/usr/include/${ARCH}-linux-gnu"
clang -O2 -g -target bpf \
  -I "$REPO_ROOT/bpf/headers" \
  ${GNU_INC:+-I "$GNU_INC"} \
  -I /usr/include \
  -c "$REPO_ROOT/dispatch.bpf.c" -o "$OBJ"

echo "=== start demo ==="
demo_stop || true
demo_start
STARTED_HERE=1

[[ -e "$PIN_DIR/sk_lookup" && -e "$PIN_DIR/prog" && -e "$PIN_DIR/sk_lookup_backup" ]] || {
  echo "FAIL: missing primary/backup/prog pins" >&2
  ls -la "$PIN_DIR" 2>/dev/null || true
  exit 1
}

curl -sS --max-time 5 "http://${HOST}:${PORT}/" | tee /tmp/sdd003-base.body
grep -q "OpenResty M1 OK" /tmp/sdd003-base.body

echo "--- upgrade -obj (expect committed) ---"
sudo "$LOADER_BIN" upgrade -obj "$OBJ" -pin-dir "$PIN_DIR" -health-window 200ms \
  | tee /tmp/sdd003-upgrade.json
grep -q '"committed"' /tmp/sdd003-upgrade.json
curl -sS --max-time 5 "http://${HOST}:${PORT}/" | tee /tmp/sdd003-after-commit.body
grep -q "OpenResty M1 OK" /tmp/sdd003-after-commit.body
COMMIT="通过"

echo "--- missing candidate (live link unchanged) ---"
set +e
sudo "$LOADER_BIN" upgrade -obj /tmp/waf-sdd003-no-such.bpf.o -pin-dir "$PIN_DIR" \
  -health-window 200ms >/tmp/sdd003-missing.out 2>/tmp/sdd003-missing.err
MISS_RC=$?
set -e
[[ $MISS_RC -ne 0 ]]
curl -sS --max-time 5 "http://${HOST}:${PORT}/" | tee /tmp/sdd003-after-missing.body
grep -q "OpenResty M1 OK" /tmp/sdd003-after-missing.body
PREFLIGHT="通过"

echo "--- WAF_UPGRADE_FAIL_HEALTH=1 (expect rolled_back, SYN still 200) ---"
set +e
WAF_UPGRADE_FAIL_HEALTH=1 sudo --preserve-env=WAF_UPGRADE_FAIL_HEALTH \
  "$LOADER_BIN" upgrade -obj "$OBJ" -pin-dir "$PIN_DIR" -health-window 200ms \
  >/tmp/sdd003-health.out 2>/tmp/sdd003-health.err
HEALTH_RC=$?
set -e
echo "health_upgrade_rc=$HEALTH_RC"
cat /tmp/sdd003-health.err || true
[[ $HEALTH_RC -ne 0 ]]
if grep -q '"rolled_back"' /tmp/sdd003-health.out /tmp/sdd003-health.err \
  || sudo "$LOADER_BIN" upgrade-status -pin-dir "$PIN_DIR" | tee /tmp/sdd003-status.json | grep -q rolled_back; then
  HEALTH="通过"
else
  HEALTH="失败"
fi
curl -sS --max-time 5 "http://${HOST}:${PORT}/" | tee /tmp/sdd003-after-rollback.body
grep -q "OpenResty M1 OK" /tmp/sdd003-after-rollback.body || HEALTH="失败"

echo "--- backup still pinned (upgrade must not unload second line) ---"
BACKUP="失败"
[[ -e "$PIN_DIR/sk_lookup_backup" ]] && BACKUP="通过"

echo
echo "### SDD-003 summary"
echo "| 项 | 结果 |"
echo "|----|------|"
mark_row "upgrade-commit" "bpf_link_update + steered curl" "$COMMIT"
mark_row "preflight-missing-obj" "missing ELF; SYN still 200" "$PREFLIGHT"
mark_row "health-rollback" "WAF_UPGRADE_FAIL_HEALTH=1 rolls back" "$HEALTH"
mark_row "backup-untouched" "$PIN_DIR/sk_lookup_backup remains" "$BACKUP"

if [[ "$COMMIT" != "通过" || "$PREFLIGHT" != "通过" || "$HEALTH" != "通过" || "$BACKUP" != "通过" ]]; then
  exit 1
fi
exit 0
