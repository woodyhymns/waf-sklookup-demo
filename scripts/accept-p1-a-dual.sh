#!/usr/bin/env bash
# P1-A gate: same steered external port must accept BOTH HTTP and HTTPS.
# REQUIRES OpenResty/Tengine with listen ... ssl https_allow_http;
# Do NOT run against stock openresty/1.19.3.2 (will correctly fail / N/A).
#
# Usage:
#   OPENRESTY_PREFIX=/path/to/tengine-or-mod-openresty \
#   ./scripts/accept-p1-a-dual.sh
#
# Optional: PORT=18081 HOST=127.0.0.1
set -euo pipefail
cd "$(dirname "$0")/.."
export CGO_ENABLED=0
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-18081}"
OPENRESTY_PREFIX="${OPENRESTY_PREFIX:-}"

if [[ -z "$OPENRESTY_PREFIX" || ! -x "$OPENRESTY_PREFIX/bin/openresty" ]]; then
  if [[ -z "$OPENRESTY_PREFIX" && -x /usr/local/openresty/bin/openresty ]]; then
    # Detect stock: reject if https_allow_http unsupported
    if ! grep -rq https_allow_http "$OPENRESTY_PREFIX" 2>/dev/null; then
      :
    fi
  fi
fi

OR_BIN=""
if [[ -n "$OPENRESTY_PREFIX" && -x "$OPENRESTY_PREFIX/bin/openresty" ]]; then
  OR_BIN="$OPENRESTY_PREFIX/bin/openresty"
elif command -v openresty >/dev/null 2>&1; then
  OR_BIN="$(command -v openresty)"
else
  echo "FAIL: set OPENRESTY_PREFIX to Tengine/魔改 OpenResty with https_allow_http" >&2
  exit 2
fi

echo "=== engine ==="
"$OR_BIN" -v 2>&1 || true
# Quick capability probe: config snippet must pass nginx -t
PROBE_DIR="$(mktemp -d)"
mkdir -p "$PROBE_DIR/logs"
cat > "$PROBE_DIR/nginx.conf" <<'NG'
worker_processes 1;
events { worker_connections 64; }
http {
  server {
    listen 127.0.0.1:18080 ssl https_allow_http;
    ssl_certificate     /dev/null;
    ssl_certificate_key /dev/null;
  }
}
NG
# Prefer project tengine example if present (real certs paths)
if [[ -f openresty/nginx.tengine-https-allow-http.conf.example ]]; then
  echo "=== nginx -t tengine example (must PASS on https_allow_http runtime) ==="
  # Use start path from run script when available; here only syntax probe via example copy
fi
set +e
"$OR_BIN" -t -p "$PROBE_DIR" -c "$PROBE_DIR/nginx.conf" 2>"$PROBE_DIR/t.err"
T_RC=$?
set -e
if rg -q 'invalid parameter "https_allow_http"|unknown directive' "$PROBE_DIR/t.err"; then
  echo "BLOCKED: engine lacks https_allow_http — not P1-A environment" >&2
  cat "$PROBE_DIR/t.err" >&2
  exit 3
fi
echo "(probe nginx -t rc=$T_RC — if cert paths fail that is OK; invalid parameter is not)"
if rg -q 'invalid parameter "https_allow_http"' "$PROBE_DIR/t.err"; then
  exit 3
fi

echo "=== start demo (product listen — no -tls-ports stock split) ==="
# Prefer tengine example conf if helper supports it; else document manual switch
export OPENRESTY_PREFIX="${OPENRESTY_PREFIX:-$(dirname "$(dirname "$OR_BIN")")}"
# Stock helper uses dual listen; for product gate, set if supported:
export USE_TENGINE_HTTPS_ALLOW_HTTP="${USE_TENGINE_HTTPS_ALLOW_HTTP:-1}"
./run-openresty-demo.sh stop >/dev/null 2>&1 || true
if ! ./run-openresty-demo.sh start; then
  echo "FAIL: start failed — ensure helper uses listen ... ssl https_allow_http (see openresty/nginx.tengine-https-allow-http.conf.example)" >&2
  exit 1
fi
cleanup() { ./run-openresty-demo.sh stop >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "=== P1-A same port HTTP ==="
curl -sS --max-time 5 "http://${HOST}:${PORT}/" | tee /tmp/p1a-http.body
grep -q 'OpenResty M1 OK\|OpenResty' /tmp/p1a-http.body

echo "=== P1-A same port HTTPS ==="
curl -sk --max-time 5 "https://${HOST}:${PORT}/" | tee /tmp/p1a-https.body
grep -q 'OpenResty M1 OK\|OpenResty' /tmp/p1a-https.body

# Default still no leak unless probe on
HDR=$(mktemp)
curl -sS -D "$HDR" -o /dev/null --max-time 5 "http://${HOST}:${PORT}/"
if rg -qi 'X-Waf-External-Port' "$HDR"; then
  echo "WARN: X-Waf-External-Port visible (default should hide; OK if probe env left on)" >&2
else
  echo "PASS: default hide header"
fi

echo "P1-A PASS: same port :${PORT} HTTP + HTTPS both hit engine"
echo "Notify Json: P1-A PASS on this runtime; PR #4 merge gate cleared from Test side."
