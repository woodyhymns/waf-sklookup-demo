#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export CGO_ENABLED=0
go generate ./...
go build -o waf-sklookup-demo .
exec sudo ./waf-sklookup-demo "$@"
