#!/usr/bin/env bash
# M3 collaboration helper: flood pinned open_ports for RSS / map / QPS / CPU tests.
# Does not reload OpenResty and does not re-attach BPF. The loader must already
# be running so maps are pinned (./run-openresty-demo.sh start).
#
# Usage:
#   ./scripts/m3-fill-ports.sh 30000
#   ./scripts/m3-fill-ports.sh 60000
#   ./scripts/m3-fill-ports.sh 30000 5000    # COUNT START
#   sudo ./waf-sklookup-demo bulk fill -count 30000 -start 5000
#   LOADER_BIN=./rust/loader/target/release/waf-sklookup-loader ./scripts/m3-fill-ports.sh 60000
set -euo pipefail
cd "$(dirname "$0")/.."

COUNT="${1:?usage: $0 COUNT [START]   # M3: 30000 or 60000}"
START="${2:-5000}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/waf-sklookup}"
LOADER_BIN="${LOADER_BIN:-./waf-sklookup-demo}"
export CGO_ENABLED=0

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
