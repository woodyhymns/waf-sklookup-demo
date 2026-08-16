#!/usr/bin/env bash
# Real-kernel performance gate for the sk_lookup dynamic-port path.
#
# Prerequisites:
#   * a four-worker SO_REUSEPORT listener at INTERNAL (default 127.0.0.1:18080)
#   * waf-sklookup-loader in openresty mode redirecting STEERED to that listener
#   * bpffs pin directory with `prog` (default /sys/fs/bpf/waf-perf)
#
# We deliberately measure A/B pairs in both orders. Comparing one baseline run
# followed by one BPF run was how the original G2 document got order-dependent
# conclusions: CPU frequency and noisy neighbours move more than a 30-line BPF
# program. A pair is therefore `internal → steered → steered → internal`.
#
# The script captures:
#   - wrk RPS and p99 for keep-alive HTTP (end-user latency gate),
#   - the same figures with `Connection: close` (new TCP/SYN cost exposed),
#   - BPF runtime_ns/run_cnt, an exact kernel-provided ns/SYN measure when
#     hardware perf counters are unavailable in virtualized CI,
#   - perf software events (`task-clock`, context switches, migrations).
#
# The VM running this repo exposes cycles/instructions as <not supported>, so
# hardware cycles are *not fabricated*. On bare metal, extend PERF_EVENTS with
# `cycles,instructions` and the same output layout remains valid.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
INTERNAL=${INTERNAL:-http://127.0.0.1:18080/}
STEERED=${STEERED:-http://127.0.0.1:18181/}
PIN_DIR=${PIN_DIR:-/sys/fs/bpf/waf-perf}
DURATION=${DURATION:-5s}
THREADS=${THREADS:-2}
CONNECTIONS=${CONNECTIONS:-32}
PAIRS=${PAIRS:-3}
CPU=${CPU:-0}
OUT_DIR=${OUT_DIR:-"$ROOT/artifacts/perf-$(date -u +%Y%m%dT%H%M%SZ)"}
BPFTOOL=${BPFTOOL:-/usr/lib/linux-tools/6.8.0-137-generic/bpftool}
PERF=${PERF:-/usr/lib/linux-tools/6.8.0-137-generic/perf}

mkdir -p "$OUT_DIR"
command -v wrk >/dev/null
command -v taskset >/dev/null
[[ -x "$BPFTOOL" ]] || { echo "missing bpftool at $BPFTOOL" >&2; exit 2; }
[[ -x "$PERF" ]] || { echo "missing perf at $PERF" >&2; exit 2; }
[[ -e "$PIN_DIR/prog" ]] || { echo "missing pinned program $PIN_DIR/prog" >&2; exit 2; }

cat > "$OUT_DIR/close.lua" <<'LUA'
-- Every request uses a fresh TCP connection, so sk_lookup runs once per HTTP
-- request. The normal benchmark uses keep-alive and measures request latency.
request = function()
  return "GET / HTTP/1.1\r\nHost: benchmark\r\nConnection: close\r\n\r\n"
end
LUA

runtime_ns() {
  sudo "$BPFTOOL" prog show pinned "$PIN_DIR/prog" | awk '
    /run_time_ns/ { for (i=1;i<=NF;i++) if ($i=="run_time_ns") { print $(i+1); exit } }
  '
}
runtime_cnt() {
  sudo "$BPFTOOL" prog show pinned "$PIN_DIR/prog" | awk '
    /run_cnt/ { for (i=1;i<=NF;i++) if ($i=="run_cnt") { print $(i+1); exit } }
  '
}
run_wrk() {
  local label=$1
  local url=$2
  local mode=$3
  local file="$OUT_DIR/${label}-${mode}.wrk"
  local extra=()
  [[ "$mode" == "close" ]] && extra=(-s "$OUT_DIR/close.lua")
  taskset -c "$CPU" wrk -t"$THREADS" -c"$CONNECTIONS" -d"$DURATION" --latency "${extra[@]}" "$url" >"$file" 2>&1
  local rps p99
  rps=$(awk '/Requests\/sec:/ {print $2; exit}' "$file")
  p99=$(awk '$1 == "99%" {print $2; exit}' "$file")
  printf '%s\t%s\t%s\n' "$label" "$rps" "${p99:-NA}"
}

printf 'case\trps\tp99\n' > "$OUT_DIR/samples.tsv"
printf 'pair\tphase\tbefore_ns\tbefore_cnt\tafter_ns\tafter_cnt\tdelta_ns\tdelta_cnt\tns_per_syn\n' > "$OUT_DIR/bpf-runtime.tsv"

# Warm caches and JIT paths. Fail loudly if either endpoint is not functional.
curl -fsS --max-time 2 "$INTERNAL" >/dev/null
curl -fsS --max-time 2 "$STEERED" >/dev/null

echo "internal=$INTERNAL steered=$STEERED duration=$DURATION threads=$THREADS connections=$CONNECTIONS pairs=$PAIRS cpu=$CPU" | tee "$OUT_DIR/config.txt"

for pair in $(seq 1 "$PAIRS"); do
  # ABBA keeps both order directions in each pair.
  run_wrk "p${pair}-A-internal" "$INTERNAL" keepalive | tee -a "$OUT_DIR/samples.tsv"

  before_ns=$(runtime_ns); before_cnt=$(runtime_cnt)
  run_wrk "p${pair}-B-steered" "$STEERED" keepalive | tee -a "$OUT_DIR/samples.tsv"
  after_ns=$(runtime_ns); after_cnt=$(runtime_cnt)
  awk -v p="$pair" -v a="$before_ns" -v b="$before_cnt" -v c="$after_ns" -v d="$after_cnt" 'BEGIN {
    ns=c-a; cnt=d-b; per=(cnt>0 ? ns/cnt : 0);
    printf "%s\tB-steered\t%s\t%s\t%s\t%s\t%s\t%s\t%.2f\n",p,a,b,c,d,ns,cnt,per
  }' >> "$OUT_DIR/bpf-runtime.tsv"

  before_ns=$(runtime_ns); before_cnt=$(runtime_cnt)
  run_wrk "p${pair}-C-steered" "$STEERED" keepalive | tee -a "$OUT_DIR/samples.tsv"
  after_ns=$(runtime_ns); after_cnt=$(runtime_cnt)
  awk -v p="$pair" -v a="$before_ns" -v b="$before_cnt" -v c="$after_ns" -v d="$after_cnt" 'BEGIN {
    ns=c-a; cnt=d-b; per=(cnt>0 ? ns/cnt : 0);
    printf "%s\tC-steered\t%s\t%s\t%s\t%s\t%s\t%s\t%.2f\n",p,a,b,c,d,ns,cnt,per
  }' >> "$OUT_DIR/bpf-runtime.tsv"

  run_wrk "p${pair}-D-internal" "$INTERNAL" keepalive | tee -a "$OUT_DIR/samples.tsv"
done

# New-connection measurement. We sample it once in each direction to expose
# SYN path cost without letting close-heavy traffic dominate the main p99 gate.
run_wrk "close-internal" "$INTERNAL" close | tee -a "$OUT_DIR/samples.tsv"
before_ns=$(runtime_ns); before_cnt=$(runtime_cnt)
run_wrk "close-steered" "$STEERED" close | tee -a "$OUT_DIR/samples.tsv"
after_ns=$(runtime_ns); after_cnt=$(runtime_cnt)
awk -v a="$before_ns" -v b="$before_cnt" -v c="$after_ns" -v d="$after_cnt" 'BEGIN {
  ns=c-a; cnt=d-b; per=(cnt>0 ? ns/cnt : 0);
  printf "close\tsteered\t%s\t%s\t%s\t%s\t%s\t%s\t%.2f\n",a,b,c,d,ns,cnt,per
}' >> "$OUT_DIR/bpf-runtime.tsv"

# Hardware cycles may be intentionally unavailable in a VM. Software events
# remain useful to detect a gross scheduler regression and are always labelled
# as such, never substituted for cycles.
sudo "$PERF" stat -o "$OUT_DIR/perf-software.txt" -e task-clock,context-switches,cpu-migrations,page-faults \
  -- taskset -c "$CPU" wrk -t"$THREADS" -c"$CONNECTIONS" -d"$DURATION" "$STEERED" >/dev/null 2>&1 || true

awk -F '\t' '
  NR==1 {next}
  /internal/ { irps[ic]=$2; ip99[ic++]=$3 }
  /steered/ { srps[sc]=$2; sp99[sc++]=$3 }
  function median(a,n,  b,i,j,t) {
    for(i=0;i<n;i++) b[i]=a[i]
    for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(b[j]<b[i]) {t=b[i];b[i]=b[j];b[j]=t}
    return b[int((n-1)/2)]
  }
  END {
    # p99 units are left as wrk text because it can report us/ms. Raw samples
    # are authoritative; ratios use RPS only and the report notes units.
    printf "internal_median_rps=%.2f\n", median(irps,ic)
    printf "steered_median_rps=%.2f\n", median(srps,sc)
    if (median(irps,ic)>0) printf "steered_internal_rps_ratio=%.4f\n", median(srps,sc)/median(irps,ic)
  }
' "$OUT_DIR/samples.tsv" > "$OUT_DIR/summary.txt"

{
  echo "=== summary ==="
  cat "$OUT_DIR/summary.txt"
  echo "=== BPF runtime ==="
  cat "$OUT_DIR/bpf-runtime.tsv"
  echo "=== software perf ==="
  cat "$OUT_DIR/perf-software.txt" 2>/dev/null || true
} | tee "$OUT_DIR/report.txt"

echo "artifacts=$OUT_DIR"
