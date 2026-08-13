#!/usr/bin/env bash
# Umbrella: run production Go/No-Go P1 scripts a–d; write last report + log.
set -euo pipefail
source "$(dirname "$0")/lib-prod-gng.sh"
install_hygiene_traps

OUT_MD="docs/acceptance-prod-gng-p1-last.md"
OUT_LOG="docs/acceptance-prod-gng-p1-last.log"
mkdir -p docs bin

require_hah | tee "$OUT_LOG"
ensure_httpbench
ensure_loader_bin

export OPENRESTY_PREFIX OPENRESTY_NGINX_CONF
export LOADER_TLS_PORTS=""
export DURATION="${DURATION:-8s}"
export CONCURRENCY="${CONCURRENCY:-50}"

demo_stop || true

declare -a ROWS=()
OVERALL="通过"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TS_LOCAL="$(TZ=Asia/Shanghai date +'%Y-%m-%d %H:%M:%S %Z')"

run_one() {
  local id="$1" title="$2" script="$3"
  echo
  echo "########## $id $title ##########" | tee -a "$OUT_LOG"
  demo_stop || true
  set +e
  bash "$script" 2>&1 | tee -a "$OUT_LOG"
  local rc=${PIPESTATUS[0]}
  set -e
  local result="通过"
  if [[ $rc -eq 3 ]]; then
    result="阻塞"
    OVERALL="阻塞"
  elif [[ $rc -ne 0 ]]; then
    result="失败"
    [[ "$OVERALL" == "通过" ]] && OVERALL="失败"
  fi
  ROWS+=("| $id | $title | $result (rc=$rc) |")
  echo ">>> $id => $result (rc=$rc)" | tee -a "$OUT_LOG"
}

run_one "P1-a" "BPF map bytes curve (memlock vs RSS)" "./scripts/accept-prod-p1-map-bytes.sh"
run_one "P1-b" "multi-worker / SO_REUSEPORT skew" "./scripts/accept-prod-p1-reuseport.sh"
run_one "P1-c" "\$waf_external_port ACL/log/limit true path" "./scripts/accept-prod-p1-waf-port-path.sh"
run_one "P1-d" "rollback drill unload/restore (+ PROXY N/A)" "./scripts/accept-prod-p1-rollback.sh"

TIP="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
ENG="$("$OPENRESTY_PREFIX/bin/openresty" -v 2>&1 | tr -d '\n')"

{
  echo "# Production Go/No-Go P1 last run"
  echo
  echo "- tip: \`$TIP\`"
  echo "- when: $TS_LOCAL (utc $TS)"
  echo "- env: OPENRESTY_PREFIX=$OPENRESTY_PREFIX · conf=$OPENRESTY_NGINX_CONF · LOADER_TLS_PORTS=\"\" · DURATION=$DURATION"
  echo "- engine: ${ENG}"
  echo "- bench: tools/httpbench + curl + bpftool + openssl (no wrk/ab)"
  echo "- log: [acceptance-prod-gng-p1-last.log](acceptance-prod-gng-p1-last.log)"
  echo
  echo "| 项 | 测了什么 | 结果 |"
  echo "|----|----------|------|"
  for r in "${ROWS[@]}"; do echo "$r"; done
  echo
  echo "## Notes"
  echo
  echo "- P1-a: map **memlock ≠ process RSS** (kernel-charged open_ports)."
  echo "- P1-b: temp conf \`worker_processes 4\` + \`reuseport\`; restored to 1 after."
  echo "- P1-c: ACL deny + per-\`\$waf_external_port\` rate limit (not Host)."
  echo "- P1-d: PROXY path documented N/A if unimplemented; direct :8080 is observation path."
  echo
  echo "## Overall"
  echo
  echo "overall=$OVERALL"
} > "$OUT_MD"

echo
echo "Wrote $OUT_MD"
cat "$OUT_MD"
demo_stop || true
# Do not fail umbrella solely on 阻塞 from expected sub-items? Still non-zero if not 通过.
[[ "$OVERALL" == "通过" ]] || exit 1
exit 0
