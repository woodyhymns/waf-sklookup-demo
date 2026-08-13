#!/usr/bin/env bash
# M3 collaboration helper: flood pinned open_ports for RSS / map / QPS / CPU tests.
# Does not reload OpenResty and does not re-attach BPF. The loader must already
# be running so maps are pinned (./run-openresty-demo.sh start).
#
# Shared-machine examples: 100, 1000, then 10000. Counts above 10000 require
# explicit M3_FULL_LADDER=1. Every invocation closes its fill range on exit.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib-prod-gng.sh
install_hygiene_traps

COUNT="${1:?usage: $0 COUNT [START]   # default ladder: 100, 1000, 10000}"
START="${2:-5000}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/waf-sklookup}"
export CGO_ENABLED=0

if (( COUNT > 10000 )) && [[ "${M3_FULL_LADDER:-0}" != "1" ]]; then
  echo "COUNT=$COUNT is disabled on shared machines; set M3_FULL_LADDER=1 explicitly." >&2
  exit 2
fi

if [[ ! -x ./waf-sklookup-demo ]]; then
  go generate ./...
  go build -o waf-sklookup-demo .
fi

echo "M3 fill: count=$COUNT start=$START pin=$PIN_DIR (no OpenResty reload)"
sudo ./waf-sklookup-demo bulk fill -count "$COUNT" -start "$START" -pin-dir "$PIN_DIR"
sudo ./waf-sklookup-demo list -count -pin-dir "$PIN_DIR"
