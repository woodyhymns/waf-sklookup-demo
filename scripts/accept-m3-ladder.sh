#!/usr/bin/env bash
# M3 port-ladder harness (Go loader baseline).
# Samples loader/OpenResty RSS, BPF open_ports map, optional light QPS/CPU.
# Default LADDER is small; full 30K/60K needs M2 bulk or long batched open-port.
#
# Usage:
#   OPENRESTY_PREFIX=/usr/local/openresty-hah ./scripts/accept-m3-ladder.sh
#   LADDER=10,100,1000,30000,60000 ./scripts/accept-m3-ladder.sh   # full (slow without bulk)
#
# Env:
#   OPENRESTY_PREFIX   default /usr/local/openresty-hah
#   OPENRESTY_NGINX_CONF  default tengine https_allow_http example
#   LOADER_TLS_PORTS   default "" (product path)
#   LADDER             comma port-counts (default 10,100,1000)
#   BASE_PORT          first steered port (default 20000)
#   BATCH              ports per open-port call (default 500)
#   QPS_DURATION       seconds for light curl QPS (default 5; 0=skip)
#   PIN_DIR TARGET WAIT
set -euo pipefail
cd "$(dirname "$0")/.."
export CGO_ENABLED=0

OPENRESTY_PREFIX="${OPENRESTY_PREFIX:-/usr/local/openresty-hah}"
export OPENRESTY_PREFIX
export OPENRESTY_NGINX_CONF="${OPENRESTY_NGINX_CONF:-openresty/nginx.tengine-https-allow-http.conf.example}"
export LOADER_TLS_PORTS=""
export TARGET="${TARGET:-127.0.0.1:8080}"
export PIN_DIR="${PIN_DIR:-/sys/fs/bpf/waf-sklookup}"
export WAIT="${WAIT:-60s}"
LADDER="${LADDER:-10,100,1000}"
BASE_PORT="${BASE_PORT:-20000}"
BATCH="${BATCH:-500}"
QPS_DURATION="${QPS_DURATION:-5}"
OUT_CSV="${OUT_CSV:-docs/acceptance-m3-ladder-last.csv}"
HOST="${TARGET%%:*}"
[[ "$HOST" == "$TARGET" ]] && HOST="127.0.0.1"

if [[ ! -x "$OPENRESTY_PREFIX/bin/openresty" ]]; then
  echo "FAIL: OPENRESTY_PREFIX=$OPENRESTY_PREFIX missing bin/openresty" >&2
  exit 2
fi

have_bulk=0
if ./waf-sklookup-demo -h 2>&1 | rg -q 'load-ports|ports-file'; then
  have_bulk=1
elif [[ -n "${BULK_CMD:-}" ]]; then
  have_bulk=1
fi

cleanup() {
  ./run-openresty-demo.sh stop >/dev/null 2>&1 || true
  pkill -f '[.]/waf-sklookup-demo -mode openresty' 2>/dev/null || true
}
trap cleanup EXIT

rss_kb() {
  local pid="$1"
  [[ -n "$pid" && -r "/proc/$pid/status" ]] || { echo 0; return; }
  awk '/^VmRSS:/ {print $2}' "/proc/$pid/status"
}

loader_pid() {
  local f
  f="${TMPDIR:-/tmp}/waf-sklookup-m1/loader.pid"
  [[ -f "$f" ]] && cat "$f" || pgrep -f '[.]/waf-sklookup-demo -mode openresty' | head -1
}

openresty_pids() {
  pgrep -f "openresty.*waf-sklookup-m1" || pgrep -x openresty || true
}

map_info() {
  sudo bpftool map show name open_ports 2>/dev/null || \
    sudo bpftool map show pinned "${PIN_DIR}/open_ports" 2>/dev/null || \
    echo "map_unavailable"
}

map_entries() {
  local info
  info="$(map_info)"
  echo "$info" | rg -o 'key[^\n]*' | head -1 || true
  # try dump count
  local n
  n="$(sudo bpftool map dump name open_ports 2>/dev/null | rg -c 'key:' || echo 0)"
  echo "$n"
}

ensure_ports() {
  local want="$1"
  local have need chunk i p list existing
  existing="$(sudo ./waf-sklookup-demo -mode dump-ports -pin-dir "$PIN_DIR" 2>/dev/null | awk 'NF{print $1}' | rg '^[0-9]+$' | sort -u || true)"
  have="$(printf '%s
' "$existing" | rg -c '^[0-9]+$' || echo 0)"
  have="${have:-0}"
  if [[ "$have" -ge "$want" ]]; then
    echo "ports already >= $want (have $have)"
    return 0
  fi
  need=$((want - have))
  echo "opening $need ports (have $have → want $want) batch=$BATCH bulk=$have_bulk"
  if [[ "$want" -ge 30000 && "$have_bulk" -eq 0 ]]; then
    echo "WARN: no M2 bulk API; using batched open-port (slow). Prefer LADDER without 30K/60K until M2." >&2
  fi
  list=()
  p=$BASE_PORT
  while [[ ${#list[@]} -lt $need && $p -lt 65535 ]]; do
    if [[ $p -ne 8080 && $p -ne 8443 ]] && ! printf '%s
' "$existing" | rg -qx "$p"; then
      list+=("$p")
    fi
    p=$((p + 1))
  done
  if [[ "$have_bulk" -eq 1 && -n "${BULK_CMD:-}" ]]; then
    printf '%s\n' "${list[@]}" > /tmp/m3-ports.txt
    eval "$BULK_CMD" || return 1
    return 0
  fi
  i=0
  while [[ $i -lt ${#list[@]} ]]; do
    chunk=("${list[@]:$i:$BATCH}")
    csv=$(IFS=,; echo "${chunk[*]}")
    sudo ./waf-sklookup-demo -mode open-port -ports "$csv" -pin-dir "$PIN_DIR" >/dev/null
    i=$((i + BATCH))
    echo "  ... opened through index $i / ${#list[@]}"
  done
}

sample_qps() {
  local port="$1"
  local dur="$2"
  [[ "$dur" != "0" ]] || { echo "na"; return; }
  local n=0 t0 t1
  t0=$(date +%s)
  while [[ $(( $(date +%s) - t0 )) -lt $dur ]]; do
    if curl -sS --max-time 1 "http://${HOST}:${port}/" >/dev/null 2>&1; then
      n=$((n + 1))
    fi
  done
  t1=$(( $(date +%s) - t0 ))
  [[ $t1 -lt 1 ]] && t1=1
  echo $(( n / t1 ))
}

sample_cpu() {
  local pid="$1"
  if command -v pidstat >/dev/null 2>&1 && [[ -n "$pid" ]]; then
    pidstat -p "$pid" 1 2 2>/dev/null | awk '/[0-9]/{v=$8} END{print v+0}'
  else
    echo "na"
  fi
}

echo "=== M3 ladder (Go) ==="
echo "OPENRESTY_PREFIX=$OPENRESTY_PREFIX LADDER=$LADDER"
"$OPENRESTY_PREFIX/bin/openresty" -v 2>&1 || true

# Build binary first
export CGO_ENABLED=0
go build -o waf-sklookup-demo . 2>/dev/null || make build

./run-openresty-demo.sh stop >/dev/null 2>&1 || true
# Start with minimal ports; ladder adds more
export LOADER_PORTS="${BASE_PORT}"
./run-openresty-demo.sh start

LPID="$(loader_pid)"
echo "loader_pid=$LPID"
mkdir -p "$(dirname "$OUT_CSV")"
echo "ladder,ports_want,ports_have,loader_rss_kb,openresty_rss_kb_sum,bpf_map_info,qps,cpu_loader,notes" > "$OUT_CSV"

IFS=',' read -ra STEPS <<< "$LADDER"
probe_port="$BASE_PORT"
for step in "${STEPS[@]}"; do
  step="${step// /}"
  [[ -z "$step" ]] && continue
  echo
  echo "=== ladder step: $step ports ==="
  if [[ "$step" -ge 30000 && "$have_bulk" -eq 0 ]]; then
    note="BLOCKED_or_SLOW_no_M2_bulk"
  else
    note="ok"
  fi
  ensure_ports "$step" || note="open_failed"
  sleep 1
  LPID="$(loader_pid)"
  lrss="$(rss_kb "$LPID")"
  or_sum=0
  for op in $(openresty_pids); do
    or_sum=$((or_sum + $(rss_kb "$op")))
  done
  minfo="$(map_info | tr '\n' ' ' | tr ',' ';')"
  have="$(sudo ./waf-sklookup-demo -mode dump-ports -pin-dir "$PIN_DIR" 2>/dev/null | awk 'NF{print $1}' | rg '^[0-9]+$' | sort -u | wc -l | tr -d ' ')"
  qps="$(sample_qps "$probe_port" "$QPS_DURATION")"
  cpu="$(sample_cpu "$LPID")"
  echo "$step,$step,$have,$lrss,$or_sum,\"$minfo\",$qps,$cpu,$note" >> "$OUT_CSV"
  echo "RSS loader=${lrss}kB openresty_sum=${or_sum}kB have=$have qps=$qps cpu=$cpu note=$note"
done

echo
echo "=== summary table ==="
echo "| 端口档 | Go loader RSS (kB) | OpenResty RSS sum (kB) | ports_have | QPS | CPU% | notes |"
echo "|--------|--------------------|-------------------------|------------|-----|------|-------|"
tail -n +2 "$OUT_CSV" | while IFS=',' read -r ladder want have lr or map qps cpu notes; do
  echo "| $ladder | $lr | $or | $have | $qps | $cpu | $notes |"
done
echo "Wrote $OUT_CSV"
echo "Rust: DEFERRED (Go baseline only)."
if echo "$LADDER" | rg -q '30000|60000' && [[ "$have_bulk" -eq 0 ]]; then
  echo "BLOCKER: M2 bulk load-ports API missing — 30K/60K via batched open-port only."
fi
