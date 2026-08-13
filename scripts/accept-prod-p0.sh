#!/usr/bin/env bash
# Umbrella: run all production Go/No-Go P0 scripts; write last report + log.
# Usage:
#   OPENRESTY_PREFIX=/usr/local/openresty-hah ./scripts/accept-prod-p0.sh
set -euo pipefail
source "$(dirname "$0")/lib-prod-gng.sh"

OUT_MD="docs/acceptance-prod-gng-p0-last.md"
OUT_LOG="docs/acceptance-prod-gng-p0-last.log"
mkdir -p docs bin

require_hah | tee "$OUT_LOG"
ensure_httpbench
ensure_loader_bin

# One shared demo lifecycle for the suite (individual scripts may start if needed)
export OPENRESTY_PREFIX OPENRESTY_NGINX_CONF
export LOADER_TLS_PORTS=""
export DURATION="${DURATION:-8s}"
export CONCURRENCY="${CONCURRENCY:-50}"
export HOT_COUNT="${HOT_COUNT:-10000}"

demo_stop || true
demo_start
cleanup() { demo_stop || true; }
trap cleanup EXIT

declare -a ROWS=()
OVERALL="通过"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Asia/Shanghai display
TS_LOCAL="$(TZ=Asia/Shanghai date +'%Y-%m-%d %H:%M:%S %Z')"

run_one() {
  local id="$1" title="$2" script="$3"
  echo
  echo "########## $id $title ##########" | tee -a "$OUT_LOG"
  set +e
  # Scripts that would start/stop their own demo: skip their stop by leaving demo up.
  # They detect curl success and won't restart.
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

run_one "P0-1" "短连接 CPS + TLS 握手风暴 / 同口双协议" "./scripts/accept-prod-p0-cps-tls.sh"
run_one "P0-2" "长连接吞吐+P99 直连 vs sk_lookup" "./scripts/accept-prod-p0-long-p99.sh"
run_one "P0-3" "Loader kill/unload/restart + map rebuild" "./scripts/accept-prod-p0-loader-lifecycle.sh"
# After lifecycle, ensure demo is up for hot ports
if ! curl -sS --max-time 2 "http://${HOST}:${PORT}/" >/dev/null 2>&1; then
  demo_start
fi
run_one "P0-4" "热加删 ~10k 端口 + P99 采样" "./scripts/accept-prod-p0-hot-ports.sh"

TIP="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

{
  echo "# Production Go/No-Go P0 last run"
  echo
  echo "- tip: \`$TIP\`"
  echo "- when: $TS_LOCAL (utc $TS)"
  echo "- env: OPENRESTY_PREFIX=$OPENRESTY_PREFIX · conf=$OPENRESTY_NGINX_CONF · LOADER_TLS_PORTS=\"\" · DURATION=$DURATION · HOT_COUNT=$HOT_COUNT"
  echo "- engine: \$($OPENRESTY_PREFIX/bin/openresty -v 2>&1 | tr -d '\n')"
  echo "- bench: tools/httpbench + openssl s_time (no wrk/ab)"
  echo "- log: [acceptance-prod-gng-p0-last.log](acceptance-prod-gng-p0-last.log)"
  echo
  echo "| 项 | 测了什么 | 结果 |"
  echo "|----|----------|------|"
  for r in "${ROWS[@]}"; do echo "$r"; done
  echo
  echo "## Go/No-Go"
  echo
  if [[ "$OVERALL" == "通过" ]]; then
    echo "**推荐: Go（P0 全通过）** — 仍待 Alex / Json 书面门槛确认后再上线。"
  elif [[ "$OVERALL" == "阻塞" ]]; then
    echo "**推荐: 阻塞（No-Go）** — P0 存在环境/工具/行为不明项，补齐前不建议生产放行。"
  else
    echo "**推荐: No-Go** — P0 存在失败项，见上表与 log。"
  fi
  echo
  echo "overall=$OVERALL"
} > "$OUT_MD"

# Fix engine line properly
ENG="$("$OPENRESTY_PREFIX/bin/openresty" -v 2>&1 | tr -d '\n')"
sed -i "s|^- engine:.*|- engine: ${ENG}|" "$OUT_MD"

echo
echo "Wrote $OUT_MD"
cat "$OUT_MD"
[[ "$OVERALL" == "通过" ]] || exit 1
exit 0
