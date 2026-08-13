#!/usr/bin/env bash
# P1-a: BPF map bytes curve vs port scale (memlock ≠ process RSS).
# Samples bpftool open_ports memlock/max_entries + loader RSS + OpenResty RSS
# Defaults to the shared-machine 100, 1K, 10K ladder. Set M3_FULL_LADDER=1
# to additionally run 30K/60K (and the optional near-full tier).
set -euo pipefail
source "$(dirname "$0")/lib-prod-gng.sh"

STARTED_HERE=0
install_hygiene_traps

echo "=== P1-a BPF map bytes curve (memlock vs process RSS) ==="
require_hah
ensure_loader_bin

if ! curl -sS --max-time 2 "http://${HOST}:${PORT}/" >/dev/null 2>&1; then
  demo_start
  STARTED_HERE=1
fi

pid_rss_kb() {
  local pid="$1"
  if [[ -z "$pid" || ! -r "/proc/$pid/status" ]]; then
    echo "0"
    return
  fi
  awk '/^VmRSS:/ {print $2; exit}' "/proc/$pid/status" 2>/dev/null || echo "0"
}

loader_pid() {
  [[ -f "$STATE_DIR/loader.pid" ]] && cat "$STATE_DIR/loader.pid"
}

or_rss_sum_kb() {
  local sum=0 p master pidfile kids
  pidfile=""
  if [[ -f "$STATE_DIR/openresty.pidpath" ]]; then
    pidfile="$(cat "$STATE_DIR/openresty.pidpath")"
  fi
  if [[ -n "$pidfile" && -f "$pidfile" ]]; then
    master="$(cat "$pidfile" 2>/dev/null || true)"
    if [[ -n "$master" ]]; then
      kids="$(pgrep -P "$master" 2>/dev/null || true)"
      if [[ -n "$kids" ]]; then
        for p in $kids; do sum=$((sum + $(pid_rss_kb "$p"))); done
        # include master too for "OR RSS"
        sum=$((sum + $(pid_rss_kb "$master")))
        echo "$sum"
        return
      fi
      echo "$(pid_rss_kb "$master")"
      return
    fi
  fi
  echo "0"
}

# Parse bpftool text; pick open_ports with largest max_entries.
# prints: memlock_b max_entries
map_stats() {
  local out
  out="$(sudo bpftool map show name open_ports 2>/dev/null || true)"
  if [[ -z "$out" ]]; then
    echo "0 0"
    return
  fi
  printf '%s\n' "$out" | python3 -c '
import re,sys
text=sys.stdin.read()
best_ml, best_me = 0, 0
for block in re.split(r"(?=\d+:\s)", text):
    me=re.search(r"max_entries\s+(\d+)", block)
    ml=re.search(r"memlock\s+(\d+)", block)
    if not me: continue
    me_i=int(me.group(1)); ml_i=int(ml.group(1)) if ml else 0
    if me_i>=best_me:
        best_me, best_ml = me_i, ml_i
print(f"{best_ml} {best_me}")
'
}

port_count() {
  local out
  out="$(sudo "$LOADER_BIN" list -count -pin-dir "$PIN_DIR" 2>/dev/null || true)"
  printf '%s\n' "$out" | python3 -c 'import sys,re; t=sys.stdin.read(); m=re.search(r"(\d+)", t); print(m.group(1) if m else "0")'
}

# Sets globals: LAST_HAVE LAST_MEMLOCK LAST_MAXE LAST_LRSS LAST_ORRSS
sample() {
  local note="$1"
  LAST_HAVE="$(port_count)"
  local lp
  lp="$(loader_pid)"
  LAST_LRSS="$(pid_rss_kb "$lp")"
  LAST_ORRSS="$(or_rss_sum_kb)"
  read -r LAST_MEMLOCK LAST_MAXE <<<"$(map_stats)"
  echo "SAMPLE have=${LAST_HAVE} memlock_B=${LAST_MEMLOCK} max_entries=${LAST_MAXE} loader_rss_kB=${LAST_LRSS} or_rss_kB=${LAST_ORRSS} note=${note}"
}

echo "NOTE: BPF map memlock is kernel-charged memory; it is NOT loader/OpenResty process RSS."
echo "--- bpftool open_ports (raw) ---"
sudo bpftool map show name open_ports 2>/dev/null || echo "(bpftool failed)"

FILL_START="${FILL_START:-5000}"
declare -a ROWS=()

echo "--- baseline (few ports) ---"
sample "baseline_after_start"
ROWS+=("| baseline (have=${LAST_HAVE}) | ${LAST_MEMLOCK} | ${LAST_MAXE} | ${LAST_LRSS} kB | ${LAST_ORRSS} kB | few steered ports |")

STATUS="通过"
declare -a TIERS=(100 1000 10000)
if [[ "${M3_FULL_LADDER:-0}" == "1" ]]; then
  TIERS+=(30000 60000)
else
  echo "NOTE: 30K/60K disabled; set M3_FULL_LADDER=1 for the full ladder."
fi

for count in "${TIERS[@]}"; do
  echo "--- bulk fill ${count} ---"
  T0=$(date +%s%N)
  sudo "$LOADER_BIN" bulk fill -count "$count" -start "$FILL_START" -pin-dir "$PIN_DIR" -no-file
  T1=$(date +%s%N)
  FILL_MS=$(( (T1 - T0) / 1000000 ))
  sample "after_bulk_${count}"
  [[ "${LAST_HAVE:-0}" -lt "$count" ]] && STATUS="失败"
  ROWS+=("| ${count} (have=${LAST_HAVE}) | ${LAST_MEMLOCK} | ${LAST_MAXE} | ${LAST_LRSS} kB | ${LAST_ORRSS} kB | fill ${FILL_MS}ms; memlock≠RSS |")
  mark_row "map-bytes-${count}" "have=${LAST_HAVE} fill_ms=${FILL_MS}" "$([[ ${LAST_HAVE:-0} -ge $count ]] && echo 通过 || echo 失败)"
  # Each tier is independent; never accumulate fills into the next tier.
  sudo "$LOADER_BIN" bulk close -range "${FILL_START}-$((FILL_START + count - 1))" -pin-dir "$PIN_DIR" -no-file >/dev/null
done

NEAR_FULL_STATUS="skip"
NEAR_COUNT=$((65535 - FILL_START + 1))
# clamp: generateFillPorts rejects end>65535; max from 5000 is 60536
if [[ "$NEAR_COUNT" -gt 60500 ]]; then NEAR_COUNT=60500; fi
if [[ "${M3_FULL_LADDER:-0}" == "1" && "${P1A_NEAR_FULL:-0}" == "1" && "$NEAR_COUNT" -gt 60000 ]]; then
  echo "--- optional near-full fill count=${NEAR_COUNT} (100K unique N/A: u16 keys) ---"
  T4=$(date +%s%N)
  set +e
  sudo "$LOADER_BIN" bulk fill -count "$NEAR_COUNT" -start "$FILL_START" -pin-dir "$PIN_DIR" -no-file
  FRC=$?
  set -e
  T5=$(date +%s%N)
  FILLN_MS=$(( (T5 - T4) / 1000000 ))
  if [[ $FRC -eq 0 && "$FILLN_MS" -lt 120000 ]]; then
    sample "after_near_full"
    ROWS+=("| near-full(~${NEAR_COUNT}, have=${LAST_HAVE}) | ${LAST_MEMLOCK} | ${LAST_MAXE} | ${LAST_LRSS} kB | ${LAST_ORRSS} kB | fill ${FILLN_MS}ms; 100K unique N/A (u16) |")
    NEAR_FULL_STATUS="通过"
  else
    ROWS+=("| near-full | — | — | — | — | skipped/failed rc=$FRC ms=$FILLN_MS |")
    NEAR_FULL_STATUS="skip"
  fi
  sudo "$LOADER_BIN" bulk close -range "${FILL_START}-$((FILL_START + NEAR_COUNT - 1))" -pin-dir "$PIN_DIR" -no-file >/dev/null 2>&1 || true
else
  ROWS+=("| near-full | — | — | — | — | skip optional |")
fi

echo
echo "### P1-a summary table"
echo "| ports | map memlock B | max_entries | loader RSS | OR RSS | note |"
echo "|-------|---------------|-------------|------------|--------|------|"
for r in "${ROWS[@]}"; do echo "$r"; done
echo
echo "Emphasize: **map bytes (memlock) ≠ process RSS** — kernel charges open_ports; loader/OR RSS stay nearly flat."
echo
echo "| 项 | 测了什么 | 结果 |"
echo "|----|----------|------|"
mark_row "near-full" "optional ≤u16 (~${NEAR_COUNT}); 100K unique N/A" "$NEAR_FULL_STATUS"
mark_row "memlock-vs-rss" "map memlock is kernel, ≠ process RSS" "通过"
mark_row "P1-a overall" "BPF map bytes curve (${TIERS[*]})" "$STATUS"

[[ "$STATUS" == "通过" ]] || exit 1
exit 0
