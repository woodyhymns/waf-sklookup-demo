#!/usr/bin/env bash
# M1 demo: OpenResty internal listen + sk_lookup loader steers external ports.
set -euo pipefail
cd "$(dirname "$0")"

export CGO_ENABLED=0

OPENRESTY_PREFIX="${OPENRESTY_PREFIX:-}"
LOADER_PORTS="${LOADER_PORTS:-18081,18082,65500}"
TARGET="${TARGET:-127.0.0.1:8080}"
WAIT="${WAIT:-60s}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/waf-sklookup}"

usage() {
  cat <<EOF
Usage: $0 [start|stop|verify|close-port PORT|dump-ports]

  start              Build loader, start OpenResty, attach sk_lookup
  stop               Stop loader + OpenResty started by this script
  verify             Bind check + curl internal/steered ports (M1-1..3)
  close-port PORT    Remove PORT from open_ports (M1-4); loader must be running
  dump-ports         List steered ports currently in the pinned map

Environment:
  OPENRESTY_PREFIX  Local OpenResty prefix (else docker-compose, else PATH)
  LOADER_PORTS      Steered ports (default: 18081,18082,65500)
  TARGET            Internal listen (default: 127.0.0.1:8080)
  WAIT              Loader wait for OpenResty listen (default: 60s)
  PIN_DIR           Pinned BPF maps (default: /sys/fs/bpf/waf-sklookup)

Requires: root/CAP_BPF for loader, Linux sk_lookup, curl, OpenResty 1.19.3.2.
EOF
}

state_dir() {
  echo "${TMPDIR:-/tmp}/waf-sklookup-m1"
}

write_local_nginx_conf() {
  local out="$1"
  local logdir="$2"
  mkdir -p "$logdir"
  sed "s|logs/|${logdir}/|g" openresty/nginx.conf > "$out"
  sed -i "s|\$prefix/lua|$(pwd)/openresty/lua|g" "$out"
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
  "$or_bin" -p "$runtime" -c "$conf"
  echo "$logdir/nginx.pid" > "$(state_dir)/openresty.pidpath"
  echo "OpenResty started (local) $($or_bin -v 2>&1) prefix=$runtime config=$conf"
}

start_openresty_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "No local OpenResty and docker not found. Install OpenResty 1.19.3.2 or docker." >&2
    exit 1
  fi
  docker compose -f openresty/docker-compose.yml up -d
  echo "OpenResty started via docker compose (host network, image openresty/openresty:1.19.3.2-bionic)"
}

start_openresty() {
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
    -wait "$WAIT" \
    -pin-dir "$PIN_DIR" \
    >"$(state_dir)/loader.log" 2>&1 &
  echo $! > "$(state_dir)/loader.pid"
  local i
  for i in $(seq 1 40); do
    if grep -q "OPENRESTY M1 READY" "$(state_dir)/loader.log" 2>/dev/null; then
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
wanted = {8080, 18081, 18082, 65500}
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

cmd_start() {
  mkdir -p "$(state_dir)"
  start_openresty
  sleep 1
  start_loader
  echo "Run '$0 verify' to check steered ports (M1-1..3)."
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

  echo "=== M1-5 OpenResty version (if local binary) ==="
  if find_openresty_bin >/dev/null 2>&1; then
    "$(find_openresty_bin)" -v 2>&1 || true
  else
    echo "(docker image openresty/openresty:1.19.3.2-bionic; check Server header below)"
  fi

  echo
  echo "=== M1-1 bind check (ss -lntp; only internal listen expected) ==="
  if command -v ss >/dev/null 2>&1; then
    ss -lntp | grep -E ':(8080|18081|18082|65500)\b' || true
  else
    echo "(ss not installed; /proc/net/tcp LISTEN:)"
    listen_ports_from_proc
  fi
  if listen_ports_from_proc | grep -Eq 'port=(18081|18082|65500)'; then
    echo "FAIL: steered port has a userspace LISTEN" >&2
    exit 1
  fi
  echo "PASS: no userspace LISTEN on steered ports"

  echo
  echo "=== M1-2/M1-3 curl internal $TARGET ==="
  hdr="$(mktemp)"
  body="$(mktemp)"
  curl -sS -D "$hdr" -o "$body" "http://${host}:${port}/"
  cat "$hdr"
  cat "$body"
  assert_body_openresty "$body"
  if ! grep -qi "Server: openresty" "$hdr"; then
    echo "FAIL: internal response Server header is not OpenResty" >&2
    exit 1
  fi
  if ! grep -q "waf_external_port=${port}" "$body"; then
    echo "FAIL: internal curl missing waf_external_port=${port}" >&2
    exit 1
  fi

  local p
  for p in ${LOADER_PORTS//,/ }; do
    p="${p// /}"
    [[ -z "$p" ]] && continue
    echo
    echo "=== curl steered :$p ==="
    curl -sS -D "$hdr" -o "$body" --max-time 5 "http://${host}:${p}/"
    cat "$hdr"
    cat "$body"
    assert_body_openresty "$body"
    if ! grep -qi "Server: openresty" "$hdr"; then
      echo "FAIL: Server header is not OpenResty" >&2
      exit 1
    fi
    if ! grep -qi "X-Waf-External-Port: ${p}" "$hdr"; then
      echo "FAIL: header X-Waf-External-Port != $p" >&2
      exit 1
    fi
    if ! grep -q "waf_external_port=${p}" "$body"; then
      echo "FAIL: body waf_external_port != $p" >&2
      exit 1
    fi
    if grep -q "waf_external_port=8080" "$body" && [[ "$p" != "8080" ]]; then
      echo "FAIL: steered port reported internal listen 8080" >&2
      exit 1
    fi
  done

  if [[ -f "$(state_dir)/logs/access.log" ]]; then
    echo
    echo "=== access log tail ==="
    tail -8 "$(state_dir)/logs/access.log"
  fi
  echo
  echo "verify OK (M1-1 bind, M1-2 OpenResty body, M1-3 distinct external ports, M1-5 version header)"
  echo "M1-4: ./run-openresty-demo.sh close-port 18081   # or: sudo bpftool map delete name open_ports key hex a9 46"
}

cmd_close_port() {
  local p="${1:-}"
  if [[ -z "$p" ]]; then
    echo "usage: $0 close-port PORT" >&2
    exit 1
  fi
  if [[ ! -x ./waf-sklookup-demo ]]; then
    build_loader
  fi
  sudo ./waf-sklookup-demo -mode close-port -ports "$p" -pin-dir "$PIN_DIR"
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
  close-port) cmd_close_port "${2:-}" ;;
  dump-ports) cmd_dump_ports ;;
  -h|--help|help) usage ;;
  *) echo "Unknown command: $1" >&2; usage; exit 1 ;;
esac
