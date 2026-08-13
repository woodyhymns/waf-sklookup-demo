# Shared helpers for production Go/No-Go P0 scripts.
# shellcheck shell=bash
# Source from repo root scripts:  # shellcheck source=lib-prod-gng.sh
#   source "$(dirname "$0")/lib-prod-gng.sh"

export CGO_ENABLED=0

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OPENRESTY_PREFIX="${OPENRESTY_PREFIX:-/usr/local/openresty-hah}"
OPENRESTY_NGINX_CONF="${OPENRESTY_NGINX_CONF:-openresty/nginx.tengine-https-allow-http.conf.example}"
# Empty: product single-listen HAH path (skip stock TLS fallback ports).
LOADER_TLS_PORTS="${LOADER_TLS_PORTS-}"
LOADER_PORTS="${LOADER_PORTS:-18081,18082,65500}"
TARGET="${TARGET:-127.0.0.1:8080}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/waf-sklookup}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-18081}"
DURATION="${DURATION:-8s}"
CONCURRENCY="${CONCURRENCY:-50}"
HOT_COUNT="${HOT_COUNT:-10000}"
HOT_START="${HOT_START:-20000}"

export OPENRESTY_PREFIX OPENRESTY_NGINX_CONF LOADER_TLS_PORTS LOADER_PORTS TARGET PIN_DIR

STATE_DIR="${TMPDIR:-/tmp}/waf-sklookup-m1"
HTTPBENCH_BIN="${HTTPBENCH_BIN:-$REPO_ROOT/bin/httpbench}"

ensure_httpbench() {
  if [[ -x "$HTTPBENCH_BIN" ]]; then
    return 0
  fi
  mkdir -p "$(dirname "$HTTPBENCH_BIN")"
  go build -o "$HTTPBENCH_BIN" ./tools/httpbench
}

ensure_loader_bin() {
  if [[ ! -x ./waf-sklookup-demo ]]; then
    go generate ./...
    go build -o waf-sklookup-demo .
  fi
}

demo_start() {
  ensure_loader_bin
  ./run-openresty-demo.sh stop >/dev/null 2>&1 || true
  ./run-openresty-demo.sh start
}

demo_stop() {
  ./run-openresty-demo.sh stop >/dev/null 2>&1 || true
}

mark_row() {
  # mark_row ITEM WHAT RESULT
  printf '| %s | %s | %s |\n' "$1" "$2" "$3"
}

require_hah() {
  if [[ ! -x "$OPENRESTY_PREFIX/bin/openresty" ]]; then
    echo "BLOCKED: OPENRESTY_PREFIX=$OPENRESTY_PREFIX missing bin/openresty" >&2
    return 3
  fi
  "$OPENRESTY_PREFIX/bin/openresty" -v 2>&1 || true
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

percentile_from_result() {
  # extract field from RESULT line: p99_us=123
  local line="$1" key="$2"
  echo "$line" | sed -n "s/.*${key}=\([0-9.][0-9.]*\).*/\1/p" | head -1
}
