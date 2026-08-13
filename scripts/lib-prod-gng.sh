# Shared helpers for production Go/No-Go P0 scripts.
# shellcheck shell=bash
# Source from repo root scripts:  # shellcheck source=lib-prod-gng.sh
#   source "$(dirname "$0")/lib-prod-gng.sh"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OPENRESTY_PREFIX="${OPENRESTY_PREFIX:-/usr/local/openresty-hah}"
OPENRESTY_NGINX_CONF="${OPENRESTY_NGINX_CONF:-openresty/nginx.tengine-https-allow-http.conf.example}"
# Empty: product single-listen HAH path (skip stock TLS fallback ports).
LOADER_TLS_PORTS="${LOADER_TLS_PORTS-}"
LOADER_PORTS="${LOADER_PORTS:-18081,18082,65500}"
TARGET="${TARGET:-127.0.0.1:8080}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/waf-sklookup}"
LOADER_BIN="${LOADER_BIN:-./rust/loader/target/release/waf-sklookup-loader}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-18081}"
DURATION="${DURATION:-8s}"
CONCURRENCY="${CONCURRENCY:-50}"
HOT_COUNT="${HOT_COUNT:-10000}"
HOT_START="${HOT_START:-20000}"

export OPENRESTY_PREFIX OPENRESTY_NGINX_CONF LOADER_TLS_PORTS LOADER_PORTS TARGET PIN_DIR LOADER_BIN

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
  if [[ ! -x "$LOADER_BIN" ]]; then
    if [[ "$(basename "$LOADER_BIN")" == "waf-sklookup-loader" ]]; then
      cargo build --release --manifest-path rust/loader/Cargo.toml
    fi
  fi
  if [[ ! -x "$LOADER_BIN" ]]; then
    echo "LOADER_BIN not executable: $LOADER_BIN" >&2
    return 1
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

# Idempotent, unconditional test cleanup.  Do not key this on STARTED_HERE: a
# previous/parallel failed test may own the surviving processes or map entries.
HYGIENE_CLEANING=0
hygiene_cleanup() {
  local rc=$?
  [[ "$HYGIENE_CLEANING" -eq 1 ]] && return "$rc"
  HYGIENE_CLEANING=1
  if [[ "${HYGIENE_DRY_RUN:-0}" == "1" ]]; then
    echo "HYGIENE_DRY_RUN: would close map entries, stop both loaders, detach/unpin BPF, stop OpenResty, and docker compose down"
    return "$rc"
  fi
  set +e

  # Close every possible test/fill range while the pinned map is still usable.
  # The demo's default ports are included intentionally: final cleanup is a
  # machine-hygiene boundary, not a request to preserve a running demo.
  if [[ -x "${LOADER_BIN:-./rust/loader/target/release/waf-sklookup-loader}" ]]; then
    sudo "${LOADER_BIN:-./rust/loader/target/release/waf-sklookup-loader}" bulk close -range 1-65535 -pin-dir "$PIN_DIR" -no-file >/dev/null 2>&1 || true
  fi

  demo_stop || true
  # Best-effort fallback for stale pins/links left by a crashed loader.
  if [[ -d "$PIN_DIR" ]]; then
    sudo find "$PIN_DIR" -mindepth 1 -maxdepth 1 -delete >/dev/null 2>&1 || true
    sudo rmdir "$PIN_DIR" >/dev/null 2>&1 || true
  fi
  set -e
  return "$rc"
}

install_hygiene_traps() {
  trap 'hygiene_cleanup' EXIT ERR
  trap 'hygiene_cleanup; exit 130' INT
  trap 'hygiene_cleanup; exit 131' QUIT
  trap 'hygiene_cleanup; exit 143' TERM
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
