#!/usr/bin/env bash
# P1 demo: OpenResty internal listen(s) + sk_lookup loader steers external ports.
# Product model: all steered ports → one internal listen; Tengine https_allow_http
# accepts HTTP+TLS on that listen. Stock 1.19.3.2 has no https_allow_http, so this
# helper also registers a labeled TLS fallback listen (8443 / -tls-ports).
# M2: add/remove/list/bulk/fill edit pinned open_ports without reloading OpenResty.
set -euo pipefail
cd "$(dirname "$0")"

OPENRESTY_PREFIX="${OPENRESTY_PREFIX:-}"
LOADER_PORTS="${LOADER_PORTS:-18081,18082,65500}"
# Stock-compat fallback only (not the Tengine product model). Empty to skip.
LOADER_TLS_PORTS="${LOADER_TLS_PORTS-18443}"  # empty string skips TLS fallback ports
TARGET="${TARGET:-127.0.0.1:8080}"
TLS_TARGET="${TLS_TARGET:-127.0.0.1:8443}"
WAIT="${WAIT:-60s}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/waf-sklookup}"
# Default: do not send X-Waf-External-Port. Set to 1 for acceptance/debug.
WAF_EXPOSE_EXTERNAL_PORT="${WAF_EXPOSE_EXTERNAL_PORT:-}"
LOADER_BIN="${LOADER_BIN:-./rust/loader/target/release/waf-sklookup-loader}"

usage() {
  cat <<EOF
Usage: $0 [start|stop|verify|add PORT|remove PORT|list|load-ports ...|bulk ...|fill COUNT|close-port PORT|open-port PORT|dump-ports|certs]

  start              Build loader, start OpenResty, attach sk_lookup
  stop               Stop loader + OpenResty started by this script
  verify             Bind check + HTTP; dual-protocol SAME-port case; stock TLS fallback
  add PORT [...]     M2: insert port(s) or START-END into pinned open_ports (no reload)
  remove PORT [...]  M2: delete port(s) from pinned open_ports (no reload)
  list               M2: list steered ports currently in the pinned map
  load-ports         M2/M3: bulk open via -range / -file / -stdin (no OpenResty reload)
  close-ports        M2/M3: bulk close via -range / -file / -stdin
  bulk open|close|fill
                     M2: range/file/stdin or M3 seed (30K/60K); see docs/openresty-m2.md
  fill COUNT [START] M3 helper: bulk fill COUNT ports from START (default 5000; >10K needs M3_FULL_LADDER=1)
  close-port PORT    Legacy alias for remove (optional --tls)
  open-port PORT     Legacy alias for add (optional --tls)
  dump-ports         Legacy alias for list
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
  LOADER_BIN                 Userspace loader (default:
                             ./rust/loader/target/release/waf-sklookup-loader)

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
  local certdir src
  certdir="$(pwd)/openresty/certs"
  src="${OPENRESTY_NGINX_CONF:-openresty/nginx.conf}"
  mkdir -p "$logdir"
  if [[ ! -f "$src" ]]; then
    echo "nginx conf not found: $src" >&2
    exit 1
  fi
  echo "Using nginx conf: $src"
  sed "s|logs/|${logdir}/|g" "$src" > "$out"
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
      "$or_bin" -p "$(state_dir)/runtime" -c "$conf" -s stop 2>/dev/null || true
    fi
  fi
  if command -v docker >/dev/null 2>&1; then
    docker compose -f openresty/docker-compose.yml down 2>/dev/null || true
  fi
  sudo pkill -x openresty 2>/dev/null || true
}

build_loader() {
  if [[ "$(basename "$LOADER_BIN")" == "waf-sklookup-loader" ]]; then
    cargo build --release --manifest-path rust/loader/Cargo.toml
  fi
}

start_loader() {
  mkdir -p "$(state_dir)"
  local tls_args=()
  if [[ -n "${LOADER_TLS_PORTS}" ]]; then
    tls_args=(-tls-target "$TLS_TARGET" -tls-ports "$LOADER_TLS_PORTS")
  fi
  sudo "$LOADER_BIN" \
    -mode openresty \
    -target "$TARGET" \
    -ports "$LOADER_PORTS" \
    "${tls_args[@]}" \
    -wait "$WAIT" \
    -pin-dir "$PIN_DIR" \
    >"$(state_dir)/loader.log" 2>&1 &
  local pid=$!
  echo "$pid" > "$(state_dir)/loader.pid"
  local i
  for i in $(seq 1 40); do
    # The sudo-launched loader may be owned by root, so an unprivileged
    # kill -0 can report EPERM even though it is alive.
    if [[ ! -d "/proc/$pid" ]]; then
      echo "Loader exited early:" >&2
      cat "$(state_dir)/loader.log" >&2 || true
      exit 1
    fi
    if grep -q "OPENRESTY P1 READY" "$(state_dir)/loader.log" 2>/dev/null; then
      echo "Loader PID $pid"
      return 0
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
  # loader.pid historically contained the sudo wrapper. Linux comm is 15 chars,
  # so pkill -x cannot match these names. Anchor at argv[0] to match only an
  # actual loader executable, never a shell whose arguments mention the repo.
  sudo pkill -TERM -f '^([^ ]*/)?waf-sklookup-demo( |$)' 2>/dev/null || true
  sudo pkill -TERM -f '^([^ ]*/)?waf-sklookup-loader( |$)' 2>/dev/null || true
  sleep 0.1
  sudo pkill -KILL -f '^([^ ]*/)?waf-sklookup-demo( |$)' 2>/dev/null || true
  sudo pkill -KILL -f '^([^ ]*/)?waf-sklookup-loader( |$)' 2>/dev/null || true
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

# Product case: SAME steered port accepts both http:// and https://.
# Requires Tengine https_allow_http (or production OpenResty that includes it).
# Stock 1.19.3.2: HTTPS on the HTTP-steered port is expected to fail — N/A, not FAIL.
probe_dual_protocol_same_port() {
  local host="$1"
  local hdr="$2"
  local body="$3"
  local p=""
  local err
  for p in ${LOADER_PORTS//,/ }; do
    p="${p// /}"
    [[ -n "$p" ]] && break
  done
  if [[ -z "$p" ]]; then
    echo "skip dual-protocol probe (no LOADER_PORTS)"
    return 0
  fi

  echo
  echo "=== P1 dual-protocol SAME steered port :$p (REQUIRES Tengine https_allow_http) ==="
  echo "Product: sk_lookup steers :$p to ONE internal listen; OpenResty accepts both:"
  echo "  curl -sS http://${host}:${p}/"
  echo "  curl -sk https://${host}:${p}/"
  echo "Stock openresty/1.19.3.2 has no https_allow_http — HTTPS on this same port is N/A here."

  err="$(mktemp)"
  if curl -sk -D "$hdr" -o "$body" --max-time 3 "https://${host}:${p}/" 2>"$err"; then
    if grep -q "OpenResty M1 OK" "$body" && grep -q "waf_external_port=${p}" "$body" && grep -q "scheme=https" "$body"; then
      echo "PASS: same port accepted TLS (https_allow_http available on this engine)"
      cat "$hdr"
      cat "$body"
      if [[ "${WAF_EXPOSE_EXTERNAL_PORT}" == "1" || "${WAF_EXPOSE_EXTERNAL_PORT}" == "true" ]]; then
        assert_header_exposed "$hdr" "$p"
      else
        assert_header_hidden "$hdr"
      fi
      rm -f "$err"
      return 0
    fi
  fi
  echo "N/A on this engine (expected on stock OpenResty 1.19.3.2)."
  echo "Production/Tengine must PASS: curl -sk https://${host}:${p}/  (same port as HTTP)"
  if grep -qi "^HTTP/.* 400" "$hdr" 2>/dev/null; then
    echo "stock evidence: TLS bytes reached the HTTP listen (HTTP 400) — not dual-protocol."
  fi
  if [[ -s "$err" ]]; then
    echo "stock probe stderr (TLS to HTTP listen):"
    cat "$err"
  fi
  rm -f "$err"
}

cmd_start() {
  mkdir -p "$(state_dir)"
  # Removing the guard is the explicit-start opt-in. A stop racing this build
  # recreates it; the post-build check then prevents delayed resurrection.
  rm -f "$(state_dir)/stop-in-progress"
  build_loader
  if [[ -e "$(state_dir)/stop-in-progress" ]]; then
    echo "Start cancelled: stop/cleanup began while the loader was building." >&2
    return 1
  fi
  start_openresty
  sleep 1
  start_loader
  echo "Run '$0 verify' to check steered HTTP/HTTPS ports."
  echo "Default: X-Waf-External-Port is hidden. Restart with WAF_EXPOSE_EXTERNAL_PORT=1 to expose it."
}

cmd_stop() {
  mkdir -p "$(state_dir)"
  : > "$(state_dir)/stop-in-progress"
  if [[ -x "$LOADER_BIN" ]]; then
    sudo "$LOADER_BIN" bulk close -range 1-65535 -pin-dir "$PIN_DIR" >/dev/null 2>&1 || true
  fi
  stop_loader
  stop_openresty
  if [[ -d "$PIN_DIR" ]]; then
    sudo find "$PIN_DIR" -mindepth 1 -maxdepth 1 -delete >/dev/null 2>&1 || true
    sudo rmdir "$PIN_DIR" >/dev/null 2>&1 || true
  fi
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

  probe_dual_protocol_same_port "$host" "$hdr" "$body"

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
  echo "  Dual-protocol SAME port (http+https on :18081): REQUIRES Tengine https_allow_http"
  echo "  X-Waf-External-Port default hidden (set WAF_EXPOSE_EXTERNAL_PORT=1 and restart to expose)"
  echo "  Stock TLS fallback (NOT product): curl -k https://127.0.0.1:18443/ → 127.0.0.1:8443 ssl"
  echo "close-port: $0 remove 18081   # or: $0 close-port 18081"
  echo "open-port:  $0 add 18081"
  echo "M2 bulk:    $0 bulk open -range 20000-20010"
  echo "M2 close:   $0 bulk close -range 20000-20010"
  echo "M3 fill:    $0 fill 30000     # or ./scripts/m3-fill-ports.sh 30000"
}

ensure_loader_bin() {
  if [[ ! -x "$LOADER_BIN" ]]; then
    build_loader
  fi
  if [[ ! -x "$LOADER_BIN" ]]; then
    echo "LOADER_BIN not executable: $LOADER_BIN" >&2
    exit 1
  fi
}

cmd_add() {
  ensure_loader_bin
  sudo "$LOADER_BIN" add -pin-dir "$PIN_DIR" "$@"
}

cmd_remove() {
  ensure_loader_bin
  sudo "$LOADER_BIN" remove -pin-dir "$PIN_DIR" "$@"
}

cmd_list() {
  ensure_loader_bin
  sudo "$LOADER_BIN" list -pin-dir "$PIN_DIR" "$@"
}

cmd_bulk() {
  local sub="${1:-}"
  if [[ -z "$sub" ]]; then
    echo "usage: $0 bulk add|remove|fill [flags]" >&2
    exit 1
  fi
  shift
  ensure_loader_bin
  sudo "$LOADER_BIN" bulk "$sub" -pin-dir "$PIN_DIR" "$@"
}

cmd_fill() {
  local count="${1:-}"
  local start="${2:-5000}"
  if [[ -z "$count" ]]; then
    echo "usage: $0 fill COUNT [START]" >&2
    echo "Shared-machine examples: $0 fill 100    $0 fill 1000    $0 fill 10000" >&2
    echo "30K/60K requires M3_FULL_LADDER=1" >&2
    exit 1
  fi
  if (( count > 10000 )) && [[ "${M3_FULL_LADDER:-0}" != "1" ]]; then
    echo "COUNT=$count is disabled on shared machines; set M3_FULL_LADDER=1 explicitly." >&2
    exit 2
  fi
  ensure_loader_bin
  sudo "$LOADER_BIN" bulk fill -count "$count" -start "$start" -pin-dir "$PIN_DIR"
}

cmd_close_port() {
  local p="${1:-}"
  local kind="${2:-}"
  if [[ -z "$p" ]]; then
    echo "usage: $0 close-port PORT [--tls]" >&2
    exit 1
  fi
  # Slot is irrelevant for delete; --tls kept for M1/P1 script compatibility.
  cmd_remove "$p"
  if [[ "$kind" != "--tls" && "$kind" != "tls" && -n "$kind" ]]; then
    echo "warning: ignoring extra arg $kind" >&2
  fi
}

cmd_open_port() {
  local p="${1:-}"
  local kind="${2:-}"
  if [[ -z "$p" ]]; then
    echo "usage: $0 open-port PORT [--tls]" >&2
    exit 1
  fi
  if [[ "$kind" == "--tls" || "$kind" == "tls" ]]; then
    cmd_add -tls "$p"
  else
    cmd_add "$p"
  fi
}

cmd_dump_ports() {
  cmd_list
}

if [[ $# -eq 0 ]]; then
  echo "A subcommand is required; nothing was started." >&2
  usage >&2
  exit 2
fi

case "$1" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  verify) cmd_verify ;;
  add) shift; cmd_add "$@" ;;
  remove) shift; cmd_remove "$@" ;;
  list) shift; cmd_list "$@" ;;
  load-ports) shift; cmd_bulk open "$@" ;;
  close-ports) shift; cmd_bulk close "$@" ;;
  bulk) shift; cmd_bulk "$@" ;;
  fill) shift; cmd_fill "$@" ;;
  close-port) cmd_close_port "${2:-}" "${3:-}" ;;
  open-port) cmd_open_port "${2:-}" "${3:-}" ;;
  dump-ports) cmd_dump_ports ;;
  certs) ensure_certs ;;
  -h|--help|help) usage ;;
  *) echo "Unknown command: $1" >&2; usage; exit 1 ;;
esac
