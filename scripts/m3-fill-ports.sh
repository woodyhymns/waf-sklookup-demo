#!/usr/bin/env bash
# M3 collaboration helper: flood pinned open_ports for RSS / map / QPS / CPU tests.
# Does not reload OpenResty and does not re-attach BPF. The loader must already
# be running so maps are pinned (./run-openresty-demo.sh start).
#
# Capacity fills use wildcard port keys by default. Never let the generated
# range contain a metrics, control, SSH, orchestration, or host-agent listener
# in the same network namespace; sk_lookup would legitimately steer that
# management traffic too. For counts >10K M3_MGMT_PORTS is mandatory.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib-prod-gng.sh
install_hygiene_traps

COUNT="${1:?usage: $0 COUNT [START]   # default ladder: 100, 1000, 10000}"
START="${2:-5000}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/waf-sklookup}"
LOADER_BIN="${LOADER_BIN:-./rust/loader/target/release/waf-sklookup-loader}"
TENANT="${M3_TENANT:-m3}"
SITE="${M3_SITE:-capacity}"
# Keep product-denied and default internal listeners out of generated ranges.
BASE_SKIP="${M3_BASE_SKIP:-22,25,53,3306,6379,8080,8443,9101}"
M3_MGMT_PORTS="${M3_MGMT_PORTS:-}"

if (( COUNT > 10000 )) && [[ "${M3_FULL_LADDER:-0}" != "1" ]]; then
  echo "COUNT=$COUNT is disabled on shared machines; set M3_FULL_LADDER=1 explicitly." >&2
  exit 2
fi
if (( COUNT > 10000 )) && [[ -z "$M3_MGMT_PORTS" ]]; then
  cat >&2 <<'EOF'
Refusing a >10K wildcard fill without M3_MGMT_PORTS.
Set it to every TCP management listener in this network namespace, for example:
  M3_MGMT_PORTS=9101,17171 M3_FULL_LADDER=1 ./scripts/m3-fill-ports.sh 30000
Use an isolated management IP/interface/netns for production-like capacity runs.
EOF
  exit 2
fi
if [[ -n "$M3_MGMT_PORTS" ]]; then
  SKIP="$BASE_SKIP,$M3_MGMT_PORTS"
else
  SKIP="$BASE_SKIP"
fi

if [[ ! -x "$LOADER_BIN" ]]; then
  if [[ "$(basename "$LOADER_BIN")" == "waf-sklookup-loader" ]]; then
    cargo build --release --manifest-path rust/loader/Cargo.toml
  fi
fi
if [[ ! -x "$LOADER_BIN" ]]; then
  echo "LOADER_BIN not executable: $LOADER_BIN" >&2
  exit 1
fi

args=(bulk fill -count "$COUNT" -start "$START" -skip "$SKIP"
      -tenant "$TENANT" -site "$SITE" -pin-dir "$PIN_DIR" -no-file)
if (( COUNT > 10000 )); then
  args+=(-full-ladder)
fi

echo "M3 fill: count=$COUNT start=$START skip=$SKIP pin=$PIN_DIR loader=$LOADER_BIN (no OpenResty reload)"
sudo "$LOADER_BIN" "${args[@]}"
sudo "$LOADER_BIN" list -count -pin-dir "$PIN_DIR"
