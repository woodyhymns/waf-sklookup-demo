#!/usr/bin/env bash
# P1 demo: OpenResty internal listen(s) + sk_lookup loader steers external ports.
# Product model: all steered ports → one internal listen; Tengine https_allow_http
# accepts HTTP+TLS on that listen. Stock 1.19.3.2 has no https_allow_http, so this
# helper also registers a labeled TLS fallback listen (8443 / -tls-ports).
set -euo pipefail
cd "$(dirname "$0")"

export CGO_ENABLED=0

OPENRESTY_PREFIX="${OPENRESTY_PREFIX:-}"
LOADER_PORTS="${LOADER_PORTS:-18081,18082,65500}"
# Stock-compat fallback only (not the Tengine product model). Empty to skip.
LOADER_TLS_PORTS="${LOADER_TLS_PORTS:-18443}"
TARGET="${TARGET:-127.0.0.1:8080}"
TLS_TARGET="${TLS_TARGET:-127.0.0.1:8443}"
WAIT="${WAIT:-60s}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/waf-sklookup}"
# Default: do not send X-Waf-External-Port. Set to 1 for acceptance/debug.
WAF_EXPOSE_EXTERNAL_PORT="${WAF_EXPOSE_EXTERNAL_PORT:-}"

usage() {
  cat <<EOF
Usage: $0 [start|stop|verify|close-port PORT|open-port PORT|dump-ports|certs]

  start              Build loader, start OpenResty, attach sk_lookup
  stop               Stop loader + OpenResty started by this script
  verify             Bind check + HTTP/HTTPS curls (header hidden by default)
  close-port PORT    Remove PORT from open_ports; loader must be running
  open-port PORT     Re-insert PORT into open_ports (primary slot, or TLS if --tls)
  dump-ports         List steered ports currently in the pinned map
  certs              Generate demo-only self-signed certs

Environment:
  OPENRESTY_PREFIX           Local OpenResty prefix (else docker-compose, else PATH)
  LOADER_PORTS               Steered HTTP/primary ports (default: 18081,18082,65500)
  LOADER_TLS_PORTS           STOCK FALLBACK steered TLS ports (default: 18443; empty to skip)
  TARGET                     Primary internal listen (default: 127.0.0.1:8080)
  TLS_TARGET                 STOCK FALLBACK TLS listen (default: 127.0.0.1:8443)
  WAIT                       Loader wait for OpenResty listen (default: 60s)
  PIN_DIR                    Pinned BPF maps (default: /sys/fs/bpf/waf-sklookup)
  WAF_EXPOSE_EXTERNAL_PORT   Set to 1 to send X-Waf-External-Port (default: unset/off)

Requires: root/CAP_BPF for loader, Linux sk_lookup, curl, openssl, OpenResty 1.19.3.2.
Product Tengine listen: see openresty/nginx.tengine-https-allow-http.conf.example
EOF
}

state_dir() {
  echo "${TMPDIR:-/tmp}/waf-sklookup-m1"
}

ensure_certs() {
  ./openresty/certs/gen-demo-certs.sh
}

write_local_nginx_conf() {
  local out="$1"
  local logdir="$2"
  local certdir
  certdir="$(pwd)/openresty/certs"
  mkdir -p "$logdir"
  sed "s|logs/|${logdir}/|g" openresty/nginx.conf > "$out"
  sed -i "s|\$prefix/lua|$(pwd)/openresty/lua|g" "$out"
  sed -i "s|certs/demo.crt|${certdir}/demo.crt|g" "$out"
  sed -i "s|certs/demo.key|${certdir}/demo.key|g" "$out"
}

find_openresty_bin() {
  if [[ -n "$OPENRESTY_PREFIX" && -x "$OPENRESTY_PREFIX/bin/openresty" ]]; then
    echo "$OPENRESTY_PREFIX/bin/openresty"
    return 0
  fi
  if command -v openresty >/dev/null 2>&1; then
    command -v openresty
    return 0
  fi
  return 1
}

start_openresty_local() {
  local or_bin logdir confdir conf runtime
  or_bin="$(find_openresty_bin)"
  logdir="$(state_dir)/logs"
  confdir="$(state_dir)/conf"
  runtime="$(state_dir)/runtime"
  mkdir -p "$confdir" "$logdir" "$runtime/logs"
  conf="$confdir/nginx.conf"
  write_local_nginx_conf "$conf" "$logdir"
  "$or_bin" -t -p "$runtime" -c "$conf"
  "$or_bin" -p "$runtime" -c "$conf" -s stop 2>/dev/null || true
  WAF_EXPOSE_EXTERNAL_PORT="$WAF_EXPOSE_EXTERNAL_PORT" "$or_bin" -p "$runtime" -c "$conf"
  echo "$logdir/nginx.pid" > "$(state_dir)/openresty.pidpath"
  echo "OpenResty started (local) $($or_bin -v 2>&1) prefix=$runtime config=$conf expose=${WAF_EXPOSE_EXTERNAL_PORT:-off}"
}

start_openresty_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "No local OpenResty and docker not found. Install OpenResty 1.19.3.2 or docker." >&2
    exit 1
  fi
  WAF_EXPOSE_EXTERNAL_PORT="$WAF_EXPOSE_EXTERNAL_PORT" docker compose -f openresty/docker-compose.yml up -d
  echo "OpenResty started via docker compose (host network, image openresty/openresty:1.19.3.2-bionic) expose=${WAF_EXPOSE_EXTERNAL_PORT:-off}"
}

start_openresty() {
  ensure_certs
  if find_openresty_bin >/dev/null 2>&1; then
    start_openresty_local
  else
    start_openresty_docker
  fi
}

stop_openresty() {
  if [[ -f "$(state_dir)/openresty.pidpath" ]]; then
    local or_bin conf
    or_bin="$(find_openresty_bin || true)"
    conf="$(state_dir)/conf/nginx.conf"
    if [[ -n "$or_bin" && -f "$conf" ]]; then
      "$or_bin" -p "$(state_dir)/runtime" -c "$conf" -s quit 2>/dev/null || true
    fi
  fi
  if command -v docker >/dev/null 2>&1; then
    docker compose -f openresty/docker-compose.yml down 2>/dev/null || true
  fi
}

build_loader() {
  go generate ./...
  go build -o waf-sklookup-demo .
}

start_loader() {
  build_loader
  mkdir -p "$(state_dir)"
  sudo ./waf-sklookup-demo \
    -mode openresty \
    -target "$TARGET" \
    -ports "$LOADER_PORTS" \
    -tls-target "$TLS_TARGET" \
    -tls-ports "$LOADER_TLS_PORTS" \
    -wait "$WAIT" \
    -pin-dir "$PIN_DIR" \
    >"$(state_dir)/loader.log" 2>&1 &
  echo $! > "$(state_dir)/loader.pid"
  local i
  for i in $(seq 1 40); do
    if grep -q "OPENRESTY P1 READY" "$(state_dir)/loader.log" 2>/dev/null; then
      echo "Loader PID $(cat "$(state_dir)/loader.pid")"
      return 0
    fi
    if ! kill -0 "$(cat "$(state_dir)/loader.pid")" 2>/dev/null; then
      echo "Loader exited early:" >&2
      cat "$(state_dir)/loader.log" >&2 || true
      exit 1
    fi
    sleep 0.5
  done
  echo "Loader did not become ready; log:" >&2
  cat "$(state_dir)/loader.log" >&2 || true
  exit 1
}

stop_loader() {
  if [[ -f "$(state_dir)/loader.pid" ]]; then
    sudo kill "$(cat "$(state_dir)/loader.pid")" 2>/dev/null || true
    rm -f "$(state_dir)/loader.pid"
  fi
}

listen_ports_from_proc() {
  python3 - <<'PY'
from pathlib import Path
wanted = {8080, 8443, 18081, 18082, 65500, 18443}
for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
    f = line.split()
    if len(f) < 10 or f[3] != "0A":
        continue
    port = int(f[1].split(":")[1], 16)
    if port in wanted:
        print(f"LISTEN {f[1]} port={port}")
PY
}

assert_body_openresty() {
  local file="$1"
  if grep -q "sk_lookup demo OK" "$file"; then
    echo "FAIL: hit toy HTTP demo, not OpenResty ($file)" >&2
    cat "$file" >&2
    return 1
  fi
  if ! grep -q "OpenResty M1 OK" "$file"; then
    echo "FAIL: missing OpenResty M1 OK in $file" >&2
    cat "$file" >&2
    return 1
  fi
}

assert_header_hidden() {
  local hdr="$1"
  if grep -qi "^X-Waf-External-Port:" "$hdr"; then
    echo "FAIL: X-Waf-External-Port present but WAF_EXPOSE_EXTERNAL_PORT is off" >&2
    cat "$hdr" >&2
    return 1
  fi
}

assert_header_exposed() {
  local hdr="$1"
  local port="$2"
  if ! grep -qi "^X-Waf-External-Port: ${port}" "$hdr"; then
    echo "FAIL: expected X-Waf-External-Port: $port (WAF_EXPOSE_EXTERNAL_PORT=1)" >&2
    cat "$hdr" >&2
    return 1
  fi
}

curl_check() {
  local url="$1"
  local expect_port="$2"
  local hdr="$3"
  local body="$4"
  local extra_curl=("${@:5}")
  curl -sS -D "$hdr" -o "$body" --max-time 5 "${extra_curl[@]}" "$url"
  cat "$hdr"
  cat "$body"
  assert_body_openresty "$body"
  if ! grep -qi "Server: openresty" "$hdr"; then
    echo "FAIL: Server header is not OpenResty" >&2
    exit 1
  fi
  if ! grep -q "waf_external_port=${expect_port}" "$body"; then
    echo "FAIL: body waf_external_port != $expect_port" >&2
    exit 1
  fi
  if [[ "${WAF_EXPOSE_EXTERNAL_PORT}" == "1" || "${WAF_EXPOSE_EXTERNAL_PORT}" == "true" ]]; then
    assert_header_exposed "$hdr" "$expect_port"
  else
    assert_header_hidden "$hdr"
  fi
}

cmd_start() {
  mkdir -p "$(state_dir)"
  start_openresty
  sleep 1
  start_loader
  echo "Run '$0 verify' to check steered HTTP/HTTPS ports."
  echo "Default: X-Waf-External-Port is hidden. Restart with WAF_EXPOSE_EXTERNAL_PORT=1 to expose it."
}

cmd_stop() {
  stop_loader
  stop_openresty
  echo "Stopped."
}

cmd_verify() {
  local host port hdr body
  host="${TARGET%%:*}"
  port="${TARGET##*:}"
  [[ "$host" == "$port" ]] && host="127.0.0.1" && port="8080"

  echo "=== OpenResty version (if local binary) ==="
  if find_openresty_bin >/dev/null 2>&1; then
    "$(find_openresty_bin)" -v 2>&1 || true
  else
    echo "(docker image openresty/openresty:1.19.3.2-bionic; check Server header below)"
  fi
  echo "WAF_EXPOSE_EXTERNAL_PORT=${WAF_EXPOSE_EXTERNAL_PORT:-off}"

  echo
  echo "=== bind check (ss -lntp; only internal listens expected) ==="
  if command -v ss >/dev/null 2>&1; then
    ss -lntp | grep -E ':(8080|8443|18081|18082|65500|18443)\b' || true
  else
    echo "(ss not installed; /proc/net/tcp LISTEN:)"
    listen_ports_from_proc
  fi
  if listen_ports_from_proc | grep -Eq 'port=(18081|18082|65500|18443)'; then
    echo "FAIL: steered port has a userspace LISTEN" >&2
    exit 1
  fi
  echo "PASS: no userspace LISTEN on steered ports"

  hdr="$(mktemp)"
  body="$(mktemp)"

  echo
  echo "=== curl internal HTTP $TARGET ==="
  curl_check "http://${host}:${port}/" "$port" "$hdr" "$body"

  local p
  for p in ${LOADER_PORTS//,/ }; do
    p="${p// /}"
    [[ -z "$p" ]] && continue
    echo
    echo "=== curl steered HTTP :$p ==="
    curl_check "http://${host}:${p}/" "$p" "$hdr" "$body"
    if grep -q "waf_external_port=8080" "$body" && [[ "$p" != "8080" ]]; then
      echo "FAIL: steered port reported internal listen 8080" >&2
      exit 1
    fi
  done

  if [[ -n "${LOADER_TLS_PORTS}" ]]; then
    local tls_host tls_port
    tls_host="${TLS_TARGET%%:*}"
    tls_port="${TLS_TARGET##*:}"
    [[ "$tls_host" == "$tls_port" ]] && tls_host="127.0.0.1" && tls_port="8443"
    echo
    echo "=== curl internal HTTPS $TLS_TARGET (stock fallback, curl -k) ==="
    echo "NOTE: this second listen exists because stock OpenResty 1.19.3.2 has no https_allow_http."
    curl_check "https://${tls_host}:${tls_port}/" "$tls_port" "$hdr" "$body" -k
    for p in ${LOADER_TLS_PORTS//,/ }; do
      p="${p// /}"
      [[ -z "$p" ]] && continue
      echo
      echo "=== curl steered HTTPS :$p (stock fallback, curl -k) ==="
      curl_check "https://${host}:${p}/" "$p" "$hdr" "$body" -k
      if grep -q "waf_external_port=8443" "$body" && [[ "$p" != "8443" ]]; then
        echo "FAIL: steered TLS port reported internal listen 8443" >&2
        exit 1
      fi
    done
  fi

  if [[ -f "$(state_dir)/logs/access.log" ]]; then
    echo
    echo "=== access log tail (must include waf_external_port= even when header is hidden) ==="
    tail -12 "$(state_dir)/logs/access.log"
  fi
  echo
  echo "verify OK"
  echo "  HTTP steered ports hit OpenResty; body/log have \$waf_external_port"
  echo "  X-Waf-External-Port default hidden (set WAF_EXPOSE_EXTERNAL_PORT=1 and restart to expose)"
  echo "  Stock TLS fallback uses -k against :18443 → 127.0.0.1:8443 ssl"
  echo "  Tengine product: same external port, http:// and https://, one internal listen — see docs/openresty-p1.md"
  echo "close-port: $0 close-port 18081"
  echo "open-port:  $0 open-port 18081"
}

cmd_close_port() {
  local p="${1:-}"
  local kind="${2:-}"
  if [[ -z "$p" ]]; then
    echo "usage: $0 close-port PORT [--tls]" >&2
    exit 1
  fi
  if [[ ! -x ./waf-sklookup-demo ]]; then
    build_loader
  fi
  if [[ "$kind" == "--tls" || "$kind" == "tls" ]]; then
    sudo ./waf-sklookup-demo -mode close-port -tls-ports "$p" -pin-dir "$PIN_DIR"
  else
    sudo ./waf-sklookup-demo -mode close-port -ports "$p" -pin-dir "$PIN_DIR"
  fi
}

cmd_open_port() {
  local p="${1:-}"
  local kind="${2:-}"
  if [[ -z "$p" ]]; then
    echo "usage: $0 open-port PORT [--tls]" >&2
    exit 1
  fi
  if [[ ! -x ./waf-sklookup-demo ]]; then
    build_loader
  fi
  if [[ "$kind" == "--tls" || "$kind" == "tls" ]]; then
    sudo ./waf-sklookup-demo -mode open-port -tls-ports "$p" -pin-dir "$PIN_DIR"
  else
    sudo ./waf-sklookup-demo -mode open-port -ports "$p" -pin-dir "$PIN_DIR"
  fi
}

cmd_dump_ports() {
  if [[ ! -x ./waf-sklookup-demo ]]; then
    build_loader
  fi
  sudo ./waf-sklookup-demo -mode dump-ports -pin-dir "$PIN_DIR"
}

case "${1:-start}" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  verify) cmd_verify ;;
  close-port) cmd_close_port "${2:-}" "${3:-}" ;;
  open-port) cmd_open_port "${2:-}" "${3:-}" ;;
  dump-ports) cmd_dump_ports ;;
  certs) ensure_certs ;;
  -h|--help|help) usage ;;
  *) echo "Unknown command: $1" >&2; usage; exit 1 ;;
esac
