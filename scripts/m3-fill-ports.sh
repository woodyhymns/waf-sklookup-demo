#!/usr/bin/env bash
# M3 collaboration helper: flood pinned open_ports for RSS / map / QPS / CPU tests.
# Does not reload OpenResty and does not re-attach BPF. The loader must already
# be running so maps are pinned (./run-openresty-demo.sh start).
#
# Shared-machine examples: 100, 1000, then 10000. Counts above 10000 require
# explicit M3_FULL_LADDER=1. Every invocation closes its fill range on exit.
# Default loader is Go (./waf-sklookup-demo). Optional:
#   LOADER_BIN=./rust/loader/target/release/waf-sklookup-loader ./scripts/m3-fill-ports.sh 10000
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib-prod-gng.sh
install_hygiene_traps

COUNT="${1:?usage: $0 COUNT [START]   # default ladder: 100, 1000, 10000}"
START="${2:-5000}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/waf-sklookup}"
LOADER_BIN="${LOADER_BIN:-./waf-sklookup-demo}"
export CGO_ENABLED=0

if (( COUNT > 10000 )) && [[ "${M3_FULL_LADDER:-0}" != "1" ]]; then
  echo "COUNT=$COUNT is disabled on shared machines; set M3_FULL_LADDER=1 explicitly." >&2
  exit 2
fi

if [[ ! -x "$LOADER_BIN" ]]; then
  if [[ "$(basename "$LOADER_BIN")" == "waf-sklookup-demo" ]]; then
    go generate ./...
    go build -o waf-sklookup-demo .
  else
    cargo build --release --manifest-path rust/loader/Cargo.toml
  fi
fi
if [[ ! -x "$LOADER_BIN" ]]; then
  echo "LOADER_BIN not executable: $LOADER_BIN" >&2
  exit 1
fi

echo "M3 fill: count=$COUNT start=$START pin=$PIN_DIR loader=$LOADER_BIN (no OpenResty reload)"
sudo "$LOADER_BIN" bulk fill -count "$COUNT" -start "$START" -pin-dir "$PIN_DIR"
sudo "$LOADER_BIN" list -count -pin-dir "$PIN_DIR"
