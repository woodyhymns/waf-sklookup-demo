#!/usr/bin/env bash
# M3 port-ladder harness (Go loader baseline) — draft.
# Samples: port count, Go loader RSS, OpenResty RSS, BPF open_ports map,
# optional light QPS (wrk or curl) + CPU (pidstat if present).
#
# Default LADDER is small (NOT full 30k/60k):
#   OPENRESTY_PREFIX=/usr/local/openresty-hah ./scripts/accept-m3-ladder.sh
# Full ladder (blocked efficiently without M2 bulk + larger open_ports map):
#   LADDER=10,100,1000,30000,60000 ./scripts/accept-m3-ladder.sh
#
# Env:
#   OPENRESTY_PREFIX       default /usr/local/openresty-hah
#   OPENRESTY_NGINX_CONF   default openresty/nginx.tengine-https-allow-http.conf.example
#   LOADER_TLS_PORTS       forced "" (product path; skip stock 8443)
#   LADDER                 comma counts (default 10,100,1000)
#   BASE_PORT              first steered port (default 20000; for 60K use e.g. 2048)
#   BATCH                  ports per open-port call (default 1000; range 500–2000)
#   PIN_DIR                default /sys/fs/bpf/waf-sklookup
#   TARGET                 default 127.0.0.1:8080
#   QPS_TOOL               auto|wrk|curl|none (default auto)
#   DURATION               QPS sample seconds (default 5; 0=skip)
#   BULK_CMD               optional override for bulk load (PORTS_FILE passed / $1)
#   OUT_CSV                default docs/acceptance-m3-ladder-last.csv
#
# Rust: DEFERRED — Go columns only.
set -euo pipefail
cd "$(dirname "$0")/.."
export CGO_ENABLED=0

OPENRESTY_PREFIX="${OPENRESTY_PREFIX:-/usr/local/openresty-hah}"
export OPENRESTY_PREFIX
export OPENRESTY_NGINX_CONF="${OPENRESTY_NGINX_CONF:-openresty/nginx.tengine-https-allow-http.conf.example}"
# Empty string (not unset): skip stock -tls-ports fallback (main run-openresty-demo.sh honors this).
export LOADER_TLS_PORTS=""
export TARGET="${TARGET:-127.0.0.1:8080}"
export PIN_DIR="${PIN_DIR:-/sys/fs/bpf/waf-sklookup}"
export WAIT="${WAIT:-60s}"
LADDER="${LADDER:-10,100,1000}"
BASE_PORT="${BASE_PORT:-20000}"
BATCH="${BATCH:-1000}"
QPS_TOOL="${QPS_TOOL:-auto}"
DURATION="${DURATION:-${QPS_DURATION:-5}}"
OUT_CSV="${OUT_CSV:-docs/acceptance-m3-ladder-last.csv}"
HOST="${TARGET%%:*}"
[[ "$HOST" == "$TARGET" ]] && HOST="127.0.0.1"
STATE_DIR="${TMPDIR:-/tmp}/waf-sklookup-m1"
# Current open_ports max_entries in dispatch.bpf.c (hard blocker for 30K/60K).
MAP_MAX_HINT="${MAP_MAX_HINT:-1024}"

if [[ ! -x "$OPENRESTY_PREFIX/bin/openresty" ]]; then
  echo "FAIL: OPENRESTY_PREFIX=$OPENRESTY_PREFIX missing bin/openresty" >&2
  exit 2
fi

loader_supports_bulk() {
  ./waf-sklookup-demo -h 2>&1 | rg -q 'load-ports|ports-file' && return 0
  strings ./waf-sklookup-demo 2>/dev/null | rg -q 'load-ports' && return 0
  return 1
}

have_bulk=0
bulk_mode=""
if [[ -n "${BULK_CMD:-}" ]]; then
  have_bulk=1
  bulk_mode="BULK_CMD"
elif [[ -x ./waf-sklookup-demo ]] && loader_supports_bulk; then
  have_bulk=1
  bulk_mode="load-ports"
fi

cleanup() {
  ./run-openresty-demo.sh stop >/dev/null 2>&1 || true
}
trap cleanup EXIT

rss_kb() {
  local pid="$1"
  [[ -n "${pid:-}" && -r "/proc/$pid/status" ]] || { echo 0; return; }
  awk '/^VmRSS:/ {print $2; exit}' "/proc/$pid/status"
}

resolve_loader_pid() {
  local f pid cmd child
  f="${STATE_DIR}/loader.pid"
  if [[ -f "$f" ]]; then
    pid="$(cat "$f" 2>/dev/null || true)"
    if [[ -n "$pid" && -r "/proc/$pid/cmdline" ]]; then
      cmd="$(tr '\0' ' ' <"/proc/$pid/cmdline" || true)"
      if [[ "$cmd" == *waf-sklookup-demo* ]]; then
        echo "$pid"
        return
      fi
      child="$(pgrep -P "$pid" -f 'waf-sklookup-demo' 2>/dev/null | head -1 || true)"
      if [[ -n "$child" ]]; then
        echo "$child"
        return
      fi
    fi
  fi
  pgrep -f '[.]/waf-sklookup-demo -mode openresty' 2>/dev/null | head -1 || true
}

openresty_rss_sum() {
  local sum=0 p
  while read -r p; do
    [[ -z "$p" ]] && continue
    sum=$((sum + $(rss_kb "$p")))
  done < <(pgrep -f "openresty.*waf-sklookup-m1" 2>/dev/null || pgrep -x openresty 2>/dev/null || true)
  echo "$sum"
}

dump_port_count() {
  sudo ./waf-sklookup-demo -mode dump-ports -pin-dir "$PIN_DIR" 2>/dev/null \
    | awk 'NF && $1 ~ /^[0-9]+$/ {print $1}' | sort -nu | wc -l | tr -d ' '
}

map_info_oneline() {
  local info
  info="$(sudo bpftool map show name open_ports 2>/dev/null || \
          sudo bpftool map show pinned "${PIN_DIR}/open_ports" 2>/dev/null || \
          echo map_unavailable)"
  echo "$info" | tr '\n' ' ' | tr ',' ';' | sed 's/  */ /g'
}

# Absolute set of `want` ports starting at BASE_PORT, skipping 8080/8443.
build_port_list() {
  local want="$1" p=$BASE_PORT n=0
  while [[ $n -lt $want && $p -lt 65535 ]]; do
    if [[ $p -ne 8080 && $p -ne 8443 ]]; then
      echo "$p"
      n=$((n + 1))
    fi
    p=$((p + 1))
  done
}

first_port() {
  build_port_list 1
}

bulk_or_batch_open() {
  local ports_file="$1"
  local i csv
  local -a arr=()
  if [[ "$have_bulk" -eq 1 && "$bulk_mode" == "BULK_CMD" ]]; then
    PORTS_FILE="$ports_file" eval "$BULK_CMD" "$ports_file"
    return
  fi
  if [[ "$have_bulk" -eq 1 && "$bulk_mode" == "load-ports" ]]; then
    sudo ./waf-sklookup-demo -mode load-ports -ports-file "$ports_file" -pin-dir "$PIN_DIR"
    return
  fi
  mapfile -t arr <"$ports_file"
  i=0
  while [[ $i -lt ${#arr[@]} ]]; do
    local -a chunk=("${arr[@]:$i:$BATCH}")
    csv=$(IFS=,; echo "${chunk[*]}")
    sudo ./waf-sklookup-demo -mode open-port -ports "$csv" -pin-dir "$PIN_DIR" >/dev/null 2>&1
    i=$((i + ${#chunk[@]}))
    echo "  ... batched open-port progress $i / ${#arr[@]}"
  done
}

ensure_ports() {
  local want="$1"
  local have need tmp missing existing
  have="$(dump_port_count)"
  have="${have:-0}"

  if [[ "$want" -gt "$MAP_MAX_HINT" ]]; then
    echo "WARN: want=$want > open_ports max_entries hint=$MAP_MAX_HINT (dispatch.bpf.c) — open will fail until map resized." >&2
  fi
  if [[ "$want" -ge 30000 && "$have_bulk" -eq 0 ]]; then
    echo "BLOCKED WARN: LADDER step ≥30000 without M2 bulk API — trying batched open-port (slow; may also hit map size)." >&2
  fi

  if [[ "$have" -ge "$want" ]]; then
    echo "ports already >= $want (have $have)"
    return 0
  fi

  tmp="$(mktemp)"
  missing="$(mktemp)"
  existing="$(mktemp)"
  build_port_list "$want" >"$tmp"
  sudo ./waf-sklookup-demo -mode dump-ports -pin-dir "$PIN_DIR" 2>/dev/null \
    | awk 'NF && $1 ~ /^[0-9]+$/ {print $1}' | sort -nu >"$existing" || true
  if [[ -s "$existing" ]]; then
    comm -13 "$existing" <(sort -nu "$tmp") >"$missing"
  else
    cp "$tmp" "$missing"
  fi
  need="$(wc -l <"$missing" | tr -d ' ')"
  echo "opening $need ports (have $have → want $want) batch=$BATCH bulk=$have_bulk($bulk_mode)"
  if [[ "$need" -gt 0 ]]; then
    if ! bulk_or_batch_open "$missing"; then
      rm -f "$tmp" "$missing" "$existing"
      return 1
    fi
  fi
  rm -f "$tmp" "$missing" "$existing"
  return 0
}

sample_qps() {
  local port="$1"
  local dur="$2"
  local tool="$QPS_TOOL"
  [[ "$dur" != "0" && "$tool" != "none" ]] || { echo "na"; return; }
  if [[ "$tool" == "auto" ]]; then
    if command -v wrk >/dev/null 2>&1; then
      tool=wrk
    else
      tool=curl
    fi
  fi
  case "$tool" in
    wrk)
      wrk -t2 -c20 -d"${dur}s" --latency "http://${HOST}:${port}/" 2>/dev/null \
        | awk '/Requests\/sec/ {printf "%.0f"; found=1} END{if(!found) print "na"}'
      ;;
    curl)
      local n=0 t0 t1
      t0=$(date +%s)
      while [[ $(( $(date +%s) - t0 )) -lt $dur ]]; do
        if curl -sS --max-time 1 "http://${HOST}:${port}/" >/dev/null 2>&1; then
          n=$((n + 1))
        fi
      done
      t1=$(( $(date +%s) - t0 ))
      [[ $t1 -lt 1 ]] && t1=1
      echo $((n / t1))
      ;;
    *)
      echo "na"
      ;;
  esac
}

sample_cpu() {
  local pid="$1"
  if command -v pidstat >/dev/null 2>&1 && [[ -n "${pid:-}" ]]; then
    pidstat -p "$pid" 1 2 2>/dev/null | awk '/Average:/ && $NF ~ /^[0-9]/ {print $NF; found=1} END{if(!found) print "na"}'
  else
    echo "na"
  fi
}

echo "=== M3 ladder harness (Go only; Rust DEFERRED) ==="
echo "OPENRESTY_PREFIX=$OPENRESTY_PREFIX"
echo "OPENRESTY_NGINX_CONF=$OPENRESTY_NGINX_CONF"
echo "LOADER_TLS_PORTS='${LOADER_TLS_PORTS}' (empty=product path)"
echo "LADDER=$LADDER BASE_PORT=$BASE_PORT BATCH=$BATCH DURATION=$DURATION QPS_TOOL=$QPS_TOOL"
echo "bulk_api=$have_bulk($bulk_mode) map_max_hint=$MAP_MAX_HINT"
"$OPENRESTY_PREFIX/bin/openresty" -v 2>&1 || true

go build -o waf-sklookup-demo . 2>/dev/null || make build

if [[ "$have_bulk" -eq 0 ]] && loader_supports_bulk; then
  have_bulk=1
  bulk_mode="load-ports"
fi

if echo ",$LADDER," | rg -q ',(30000|60000),'; then
  if [[ "$have_bulk" -eq 0 ]]; then
    echo "BLOCKED WARN: LADDER includes ≥30000 and no M2 bulk API — will try batched open-port with progress." >&2
  fi
  if [[ "$MAP_MAX_HINT" -lt 30000 ]]; then
    echo "BLOCKED WARN: open_ports max_entries hint=$MAP_MAX_HINT < 30000 — full ladder cannot succeed until BPF map resized." >&2
  fi
fi

./run-openresty-demo.sh stop >/dev/null 2>&1 || true
export LOADER_PORTS="$(first_port)"
# Helper start uses setsid (run-openresty-demo.sh start_loader) so loader survives.
./run-openresty-demo.sh start

LPID="$(resolve_loader_pid)"
echo "loader_pid=$LPID"
mkdir -p "$(dirname "$OUT_CSV")"
echo "ladder,ports_want,ports_have,loader_rss_kb,openresty_rss_kb_sum,bpf_map,qps,cpu_pct,p99,notes" >"$OUT_CSV"

IFS=',' read -ra STEPS <<<"$LADDER"
probe_port="$(first_port)"
declare -a MD_ROWS=()

for step in "${STEPS[@]}"; do
  step="${step// /}"
  [[ -z "$step" ]] && continue
  echo
  echo "=== ladder step: $step ports ==="
  note="ok"
  if [[ "$step" -ge 30000 && "$have_bulk" -eq 0 ]]; then
    note="BLOCKED_slow_no_M2_bulk"
  fi
  if [[ "$step" -gt "$MAP_MAX_HINT" ]]; then
    note="BLOCKED_map_max_entries_${MAP_MAX_HINT}"
  fi
  if ! ensure_ports "$step"; then
    note="${note};open_failed"
  fi
  sleep 0.5
  LPID="$(resolve_loader_pid)"
  lrss="$(rss_kb "$LPID")"
  or_sum="$(openresty_rss_sum)"
  minfo="$(map_info_oneline)"
  have="$(dump_port_count)"
  if [[ "$have" -lt "$step" && "$step" -gt "$MAP_MAX_HINT" ]]; then
    note="BLOCKED_map_max_entries_${MAP_MAX_HINT};have=${have}"
  elif [[ "$have" -lt "$step" ]]; then
    note="${note};have_lt_want"
  fi
  qps="$(sample_qps "$probe_port" "$DURATION")"
  cpu="$(sample_cpu "$LPID")"
  p99="na"
  echo "$step,$step,$have,$lrss,$or_sum,\"$minfo\",$qps,$cpu,$p99,$note" >>"$OUT_CSV"
  echo "RSS loader=${lrss}kB openresty_sum=${or_sum}kB have=$have qps=$qps cpu=$cpu p99=$p99 note=$note"
  echo "bpf: $minfo"
  MD_ROWS+=("| $step | ${lrss} kB | ${or_sum} kB | \`$minfo\` | $qps | $cpu | $p99 | $note |")
done

echo
echo "=== markdown summary (项/测了什么/结果) ==="
echo "| 项 | 测了什么 | 结果 |"
echo "|----|----------|------|"
echo "| harness | default/small ladder executable | ran |"
echo "| Go only | Rust deferred | DEFER |"
echo "| bulk | M2 load-ports / ports-file | $([[ "$have_bulk" -eq 1 ]] && echo AVAILABLE || echo BLOCKED) |"
echo "| map size | open_ports max_entries | hint=$MAP_MAX_HINT (30K/60K need resize) |"
echo
echo "| 端口档 | Go loader RSS | OpenResty RSS | BPF map | QPS | CPU% | P99 | notes |"
echo "|--------|---------------|---------------|---------|-----|------|-----|-------|"
for row in "${MD_ROWS[@]}"; do
  echo "$row"
done
echo
echo "Wrote $OUT_CSV"
echo "Rust: DEFERRED (Go baseline only)."
if echo ",$LADDER," | rg -q ',(30000|60000),' && [[ "$have_bulk" -eq 0 ]]; then
  echo "BLOCKER: M2 bulk load-ports API missing — 30K/60K via batched open-port only."
fi
if [[ "$MAP_MAX_HINT" -lt 30000 ]]; then
  echo "BLOCKER: BPF open_ports max_entries=$MAP_MAX_HINT — cannot hold 30K/60K until resized."
fi
