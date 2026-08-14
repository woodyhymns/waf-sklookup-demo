#!/usr/bin/env bash
# E5 DFX-complete operator recovery. Re-entrant: every action checks current state.
# Established connections stay on their fd/worker; only new SYNs reselect.
set -euo pipefail

cd "$(dirname "$0")/.."

LOADER_BIN="${LOADER_BIN:-./rust/loader/target/release/waf-sklookup-loader}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/waf-sklookup}"
PORTS_FILE="${PORTS_FILE:-ports.conf}"
TARGET="${TARGET:-127.0.0.1:8080}"
TLS_TARGET="${TLS_TARGET-127.0.0.1:8443}"
LOADER_PORTS="${LOADER_PORTS:-18081,18082,65500}"
LOADER_TLS_PORTS="${LOADER_TLS_PORTS-18443}"
WAIT="${WAIT:-60s}"
CTL_SOCK="${CTL_SOCK:-/run/waf-sklookup/ctl.sock}"
OPENRESTY_PREFIX="${OPENRESTY_PREFIX:-}"
STATE_DIR="${STATE_DIR:-${TMPDIR:-/tmp}/waf-sklookup-m1}"
PID_FILE="$STATE_DIR/loader.pid"
STORM_FILE="$STATE_DIR/worker-rescans"
STORM_WINDOW="${STORM_WINDOW:-30}"
STORM_LIMIT="${STORM_LIMIT:-3}"
PROBE_COUNT=3
HINT=""

HINTS="loader|pin-race|master|openresty|worker|worker-storm|pin|pins|bpffs|sockmap|ctl|ctl-sock|state|reconcile|boot-wait|boot-loader|start-limit|reboot|detect-worker"

usage() {
  echo "Usage: $0 [--count N] [$HINTS]" >&2
  echo "A case name is required. Reboot recovery runs only via $0 reboot. No argument or an unknown argument prints usage and exits 2 with no recovery." >&2
}

while (( $# )); do
  case "$1" in
    --count)
      [[ $# -ge 2 && "$2" =~ ^[0-9]+$ ]] || { usage; exit 2; }
      PROBE_COUNT="$2"; shift 2 ;;
    loader|pin-race|master|openresty|worker|worker-storm|pin|pins|bpffs|sockmap|ctl|ctl-sock|state|reconcile|boot-wait|boot-loader|start-limit|reboot|detect-worker)
      [[ -z "$HINT" ]] || { usage; exit 2; }
      HINT="$1"; shift ;;
    -h|--help|help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

if [[ -z "$HINT" ]]; then
  usage
  exit 2
fi

if (( PROBE_COUNT > 10000 )) && [[ "${M3_FULL_LADDER:-0}" != "1" ]]; then
  echo "COUNT=$PROBE_COUNT is disabled on shared machines; set M3_FULL_LADDER=1 explicitly." >&2
  exit 2
fi
if (( PROBE_COUNT > 3 )); then
  echo "Recovery probes only a handful of ports; limiting requested count $PROBE_COUNT to 3."
  PROBE_COUNT=3
fi

trap 'echo "Recovery interrupted; the script did not intentionally stop a healthy dataplane." >&2; exit 130' INT TERM

ok() { echo "OK: $*"; }
fail() { echo "FAIL: $*" >&2; }
say_case() { echo "CASE: $1"; }
sudo_run() { if [[ "$(id -u)" == 0 ]]; then "$@"; else sudo "$@"; fi; }

loader_pid() {
  local pid=""
  if [[ -r "$PID_FILE" ]]; then
    pid="$(<"$PID_FILE")"
    if [[ "$pid" =~ ^[0-9]+$ && -d "/proc/$pid" ]] && tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -q 'waf-sklookup-loader'; then
      echo "$pid"; return 0
    fi
  fi
  pgrep -f '^([^ ]*/)?waf-sklookup-loader( |$)' 2>/dev/null | head -1
}
loader_up() { [[ -n "$(loader_pid || true)" ]]; }

master_pid() {
  local pidpath pid=""
  if [[ -r "$STATE_DIR/openresty.pidpath" ]]; then
    pidpath="$(<"$STATE_DIR/openresty.pidpath")"
    [[ -r "$pidpath" ]] && pid="$(<"$pidpath")"
    [[ "$pid" =~ ^[0-9]+$ && -d "/proc/$pid" ]] && { echo "$pid"; return; }
  fi
  pgrep -xo openresty 2>/dev/null | head -1 || pgrep -xo nginx 2>/dev/null | head -1 || true
}
worker_pids() {
  local master="$1"
  [[ -n "$master" ]] || return 0
  pgrep -P "$master" 2>/dev/null | sort -n | paste -sd, - || true
}

target_listen_inodes() {
  local target="$1" host port want_addr want_port
  [[ -n "$target" ]] || return 0
  host="${target%:*}"; port="${target##*:}"
  [[ "$port" =~ ^[0-9]+$ ]] || return 0
  printf -v want_port '%04X' "$port"
  want_addr="$(awk -v ip="$host" 'BEGIN { n=split(ip,a,"."); if (n != 4) exit 1; printf "%02X%02X%02X%02X",a[4],a[3],a[2],a[1] }' 2>/dev/null || true)"
  [[ -n "$want_addr" ]] || return 0
  awk -v a="$want_addr" -v p="$want_port" '$4 == "0A" && toupper($2) == a ":" p {print $10}' /proc/net/tcp 2>/dev/null | sort -n | paste -sd, -
}
listen_snapshot() {
  local primary tls=""
  primary="$(target_listen_inodes "$TARGET")"
  [[ -n "$TLS_TARGET" ]] && tls="$(target_listen_inodes "$TLS_TARGET")"
  printf 'http=%s tls=%s\n' "${primary:-none}" "${tls:-disabled}"
}
listen_up() { [[ "$(target_listen_inodes "${1:-$TARGET}")" != "" ]]; }
pins_ok() { [[ -e "$PIN_DIR/open_ports" && -e "$PIN_DIR/redir_socket" ]]; }
bpffs_mounted() { mountpoint -q /sys/fs/bpf; }

ensure_bpffs() {
  if bpffs_mounted; then ok "bpffs already mounted at /sys/fs/bpf"; return 0; fi
  echo "ACTION: mount bpffs at /sys/fs/bpf"
  sudo_run mount -t bpf bpf /sys/fs/bpf
}

ensure_loader_bin() {
  if [[ ! -x "$LOADER_BIN" && "$(basename "$LOADER_BIN")" == "waf-sklookup-loader" ]]; then
    cargo build --release --manifest-path rust/loader/Cargo.toml
  fi
  [[ -x "$LOADER_BIN" ]] || { fail "LOADER_BIN is not executable: $LOADER_BIN"; return 1; }
}

sockmap_slot_status() {
  local slot="$1" key output
  command -v bpftool >/dev/null 2>&1 || { echo unknown; return; }
  [[ -e "$PIN_DIR/redir_socket" ]] || { echo empty; return; }
  printf -v key '%02x 00 00 00' "$slot"
  if output="$(bpftool map lookup pinned "$PIN_DIR/redir_socket" key hex $key 2>/dev/null)"; then
    [[ -n "$output" ]] && echo present || echo empty
  else
    # EPERM vs absent key: stay unknown so auto-detect does not invent a restart.
    echo unknown
  fi
}
sockmap_empty() {
  local s0 s1
  s0="$(sockmap_slot_status 0)"
  [[ "$s0" == empty ]] && return 0
  if [[ -n "$TLS_TARGET" ]]; then
    s1="$(sockmap_slot_status 1)"
    [[ "$s1" == empty ]] && return 0
  fi
  return 1
}

clear_sockmap() {
  pins_ok || return 0
  command -v bpftool >/dev/null 2>&1 || { echo "bpftool not present; leaving sockmap as-is (no further rescan)"; return 0; }
  sudo_run bpftool map delete pinned "$PIN_DIR/redir_socket" key hex 00 00 00 00 2>/dev/null || true
  sudo_run bpftool map delete pinned "$PIN_DIR/redir_socket" key hex 01 00 00 00 2>/dev/null || true
  echo "ACTION: sockmap slots cleared (new steered SYNs SK_DROP); loader and OpenResty were not restarted"
}

validate_ports_file() {
  if [[ ! -f "$PORTS_FILE" ]]; then
    fail "ports.conf missing ($PORTS_FILE); refusing to change open_ports"
    return 1
  fi
  if ! awk '
    BEGIN { n=0 }
    { line=$0; sub(/#.*/, "", line) }
    line ~ /^[[:space:]]*$/ { next }
    {
      nf=split(line, f, /[[:space:]]+/)
      if (nf < 1) next
      if (nf > 2) { print "unexpected extra token on line " NR > "/dev/stderr"; exit 2 }
      if (nf == 2 && f[2] != "tls") { print "unexpected token " f[2] " on line " NR > "/dev/stderr"; exit 2 }
      spec=f[1]
      if (spec ~ /^[0-9]+-[0-9]+$/) {
        split(spec, r, "-")
        if (r[1] > r[2] || r[1] < 1 || r[2] > 65535) { print "bad range " spec > "/dev/stderr"; exit 2 }
        n += r[2] - r[1] + 1
      } else if (spec ~ /^[0-9]+$/) {
        if (spec+0 < 1 || spec+0 > 65535) { print "bad port " spec > "/dev/stderr"; exit 2 }
        n++
      } else { print "bad port spec " spec " on line " NR > "/dev/stderr"; exit 2 }
    }
    END { if (n > 131072) { print "desired file has " n " ports; open_ports max_entries is 131072" > "/dev/stderr"; exit 2 } }
  ' "$PORTS_FILE"; then
    fail "ports.conf corrupt or overlarge ($PORTS_FILE); refusing to change open_ports"
    return 1
  fi
  return 0
}

desired_state() {
  awk '{ sub(/#.*/, "") } /^[[:space:]]*$/ { next } {
    slot=0; if ($2 == "tls") slot=1
    if ($1 ~ /^[0-9]+-[0-9]+$/) { split($1,r,"-"); for (p=r[1]; p<=r[2]; p++) print p " " slot }
    else print $1 " " slot
  }' "$PORTS_FILE" | sort -n -k1,1
}
map_state() {
  sudo_run "$LOADER_BIN" list -pin-dir "$PIN_DIR" 2>/dev/null |
    awk -F '[\t=]' '/^[0-9]+\tredir=[0-9]+/ { print $1 " " $3 }' | sort -n -k1,1
}
maps_match_file() { [[ -f "$PORTS_FILE" ]] && diff -q <(desired_state) <(map_state) >/dev/null 2>&1; }

reconcile_if_needed() {
  validate_ports_file || return 1
  ensure_loader_bin
  if maps_match_file; then ok "open_ports already matches $PORTS_FILE"; return 0; fi
  echo "ACTION: reconcile open_ports from $PORTS_FILE (no reattach, no OpenResty reload)"
  sudo_run "$LOADER_BIN" reconcile -pin-dir "$PIN_DIR" -ports-file "$PORTS_FILE"
  maps_match_file || { fail "open_ports still differs from $PORTS_FILE after reconcile"; return 1; }
  ok "final reconcile confirmed"
}

rescan() {
  ensure_loader_bin
  pins_ok || { fail "rescan refuses: pins missing; use '$0 pin'"; return 1; }
  local args=(rescan-listen -pin-dir "$PIN_DIR" -target "$TARGET")
  [[ -n "$TLS_TARGET" ]] && args+=(-tls-target "$TLS_TARGET")
  echo "ACTION: rescan-listen only (loader, BPF, and open_ports stay untouched)"
  sudo_run "$LOADER_BIN" "${args[@]}"
}

note_worker_rescan() {
  mkdir -p "$STATE_DIR"
  local now cut
  now="$(date +%s)"
  cut=$((now - STORM_WINDOW))
  if [[ -f "$STORM_FILE" ]]; then
    awk -v c="$cut" '$1+0 >= c {print}' "$STORM_FILE" >"$STORM_FILE.tmp" || true
    mv "$STORM_FILE.tmp" "$STORM_FILE"
  fi
  echo "$now" >>"$STORM_FILE"
}

storm_count() {
  local now cut
  now="$(date +%s)"; cut=$((now - STORM_WINDOW))
  [[ -f "$STORM_FILE" ]] || { echo 0; return; }
  awk -v c="$cut" '$1+0 >= c { n++ } END { print n+0 }' "$STORM_FILE"
}
storm_exhausted() { (( $(storm_count) >= STORM_LIMIT )); }

snapshot_worker_state() {
  local master workers listens
  master="$(master_pid)"; [[ -n "$master" ]] || return 0
  workers="$(worker_pids "$master")"; listens="$(listen_snapshot)"
  mkdir -p "$STATE_DIR"
  printf '%s\n' "$master" >"$STATE_DIR/recovery-master.snapshot"
  printf '%s\n' "$workers" >"$STATE_DIR/recovery-workers.snapshot"
  printf '%s\n' "$listens" >"$STATE_DIR/recovery-listens.snapshot"
}

detect_worker() {
  local master workers listens old_master="" old_workers="" old_listens=""
  local slot0 slot1 changed=1
  master="$(master_pid)"
  if [[ -z "$master" ]]; then
    echo "worker-detect: not running"
    return 1
  fi
  workers="$(worker_pids "$master")"; listens="$(listen_snapshot)"
  [[ -r "$STATE_DIR/recovery-master.snapshot" ]] && old_master="$(<"$STATE_DIR/recovery-master.snapshot")"
  [[ -r "$STATE_DIR/recovery-workers.snapshot" ]] && old_workers="$(<"$STATE_DIR/recovery-workers.snapshot")"
  [[ -r "$STATE_DIR/recovery-listens.snapshot" ]] && old_listens="$(<"$STATE_DIR/recovery-listens.snapshot")"
  slot0="$(sockmap_slot_status 0)"
  if [[ -n "$TLS_TARGET" ]]; then slot1="$(sockmap_slot_status 1)"; else slot1=disabled; fi
  echo "worker-detect: master=$master workers=${workers:-none} listens='$listens' redir_socket[0]=$slot0 redir_socket[1]=$slot1"
  if [[ -n "$old_master" && "$master" == "$old_master" && -n "$old_workers" && "$workers" != "$old_workers" ]]; then
    echo "worker-detect: worker PID set changed (master unchanged)"; changed=0
  fi
  if [[ -n "$old_master" && "$master" == "$old_master" && -n "$old_listens" && "$listens" != "$old_listens" ]]; then
    echo "worker-detect: listen inode set changed (master unchanged)"; changed=0
  fi
  if [[ "$slot0" == empty || "$slot1" == empty ]]; then
    echo "worker-detect: redir_socket protocol slot is empty"; changed=0
  fi
  return "$changed"
}

start_limit_hit() {
  command -v systemctl >/dev/null 2>&1 || return 1
  local unit result failed
  for unit in waf-sklookup-loader.service waf-sklookup-openresty.service; do
    systemctl cat "$unit" >/dev/null 2>&1 || continue
    result="$(systemctl show -p Result --value "$unit" 2>/dev/null || true)"
    failed="$(systemctl is-failed "$unit" 2>/dev/null || true)"
    if [[ "$result" == start-limit-hit || "$failed" == start-limit-hit || "$failed" == *start-limit* ]]; then
      return 0
    fi
  done
  return 1
}

start_openresty_only() {
  if listen_up; then ok "OpenResty already listening on $TARGET"; return 0; fi
  echo "ACTION: start OpenResty only (loader and maps untouched)"
  OPENRESTY_PREFIX="$OPENRESTY_PREFIX" ./run-openresty-demo.sh start-openresty-only
}

start_loader_only() {
  if loader_up; then
    echo "one loader is already running; a second long-running loader is refused by /run/waf-sklookup/loader.lock"
    return 0
  fi
  ensure_loader_bin
  ensure_bpffs
  mkdir -p "$STATE_DIR"
  local tls_args=()
  [[ -z "$LOADER_TLS_PORTS" || -z "$TLS_TARGET" ]] || tls_args=(-tls-target "$TLS_TARGET" -tls-ports "$LOADER_TLS_PORTS")
  echo "ACTION: start loader (attach, reconcile ports.conf, recreate ctl.sock); OpenResty is not stopped"
  sudo_run "$LOADER_BIN" -mode openresty -target "$TARGET" -ports "$LOADER_PORTS" \
    -ports-file "$PORTS_FILE" "${tls_args[@]}" -wait "$WAIT" -pin-dir "$PIN_DIR" \
    -ctl-sock "$CTL_SOCK" >"$STATE_DIR/loader.log" 2>&1 &
  local pid=$!
  echo "$pid" >"$PID_FILE"
  local i
  for i in $(seq 1 120); do
    if [[ ! -d "/proc/$pid" ]]; then
      if grep -q 'another loader owns' "$STATE_DIR/loader.log" 2>/dev/null; then
        fail "second loader refused (pin race); existing owner kept"
        return 1
      fi
      fail "loader exited early"; tail -40 "$STATE_DIR/loader.log" >&2 || true
      return 1
    fi
    if grep -q 'OPENRESTY P1 READY' "$STATE_DIR/loader.log" 2>/dev/null; then
      ok "loader running (PID $pid)"
      return 0
    fi
    sleep 0.5
  done
  fail "loader did not become ready (wait timeout fail-closed; empty slots were not exposed)"
  tail -40 "$STATE_DIR/loader.log" >&2 || true
  return 1
}

restart_loader() {
  local pid
  pid="$(loader_pid || true)"
  if [[ -n "$pid" ]]; then
    sudo_run kill "$pid" 2>/dev/null || true
    local i
    for i in $(seq 1 30); do [[ ! -d "/proc/$pid" ]] && break; sleep 0.1; done
    [[ ! -d "/proc/$pid" ]] || sudo_run kill -KILL "$pid" 2>/dev/null || true
  fi
  rm -f "$PID_FILE"
  start_loader_only
}

recover_ctl() {
  if loader_up; then
    if [[ -e "$CTL_SOCK" && ! -S "$CTL_SOCK" ]]; then
      echo "ACTION: unlink leftover non-socket $CTL_SOCK (maps stay loaded)"
      sudo_run rm -f "$CTL_SOCK"
    fi
    local i
    for i in $(seq 1 20); do [[ -S "$CTL_SOCK" ]] && { ok "ctl.sock present at $CTL_SOCK"; return 0; }; sleep 0.1; done
    echo "ACTION: SIGHUP running loader to rebind ctl.sock without unloading BPF"
    sudo_run kill -HUP "$(loader_pid)"
    for i in $(seq 1 20); do [[ -S "$CTL_SOCK" ]] && { ok "ctl.sock rebound at $CTL_SOCK"; return 0; }; sleep 0.1; done
    fail "ctl.sock not recreated; use '$0 loader' (no BPF unload attempted)"
    return 1
  fi
  echo "ACTION: loader is down; recreate ctl.sock by starting the loader"
  start_loader_only
}

recover_worker() {
  local master
  master="$(master_pid)"
  [[ -n "$master" ]] || { fail "worker recovery refuses: OpenResty master is dead; use '$0 master'"; return 1; }
  pins_ok || { fail "worker recovery refuses: pins missing; use '$0 pin'"; return 1; }
  listen_up || { fail "worker recovery refuses: master has no live $TARGET listen; use '$0 master'"; return 1; }
  say_case worker
  echo "Worker respawn: rescan only; do NOT restart loader, detach BPF, or touch open_ports."
  rescan
  note_worker_rescan
  snapshot_worker_state
}

recover_storm() {
  local tries=0
  say_case worker-storm
  if pins_ok && [[ -n "$(master_pid || true)" ]] && listen_up && ! storm_exhausted; then
    echo "ACTION: worker-storm limited rescan retries (no loader/OpenResty restart loop)"
    while ! storm_exhausted && (( tries < STORM_LIMIT )); do
      rescan || break
      note_worker_rescan
      tries=$((tries + 1))
    done
  fi
  echo "worker crash-loop budget exhausted ($STORM_LIMIT rescans / ${STORM_WINDOW}s): fail-closed empty sockmap"
  pins_ok && clear_sockmap
  echo "human intervention required to fix the worker crash; loader and OpenResty were not restarted" >&2
  return 1
}

recover_sockmap() {
  local master
  master="$(master_pid)"
  [[ -n "$master" ]] || { fail "sockmap recovery refuses: OpenResty master is dead; use '$0 master'"; return 1; }
  pins_ok || { fail "sockmap recovery refuses: pins missing; use '$0 pin'"; return 1; }
  listen_up || { fail "sockmap recovery refuses: master has no live $TARGET listen; use '$0 master'"; return 1; }
  say_case sockmap
  echo "Empty sockmap slot: rescan-listen only (loader, BPF, and open_ports stay untouched)."
  rescan
  snapshot_worker_state
}

tiny_confirm() {
  local host="${TARGET%:*}" internal_port="${TARGET##*:}" port slot n=0
  [[ "$host" != "$TARGET" ]] || host=127.0.0.1
  if ! listen_up; then
    echo "confirm skipped: inner listen $TARGET is down"
    return 0
  fi
  if curl -fsS --max-time 5 "http://$host:$internal_port/" >/dev/null; then
    ok "internal OpenResty probe $TARGET"
  else
    fail "internal OpenResty probe $TARGET"; return 1
  fi
  if [[ ! -f "$PORTS_FILE" ]] || ! validate_ports_file >/dev/null 2>&1; then
    echo "confirm: steered probes skipped (ports file missing/corrupt; map was not changed)"
    return 0
  fi
  while read -r port slot; do
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    (( n >= PROBE_COUNT )) && break
    if [[ "$slot" == 1 ]]; then
      curl -fkSs --max-time 5 "https://$host:$port/" >/dev/null || { fail "steered probe $host:$port (empty/stale slot fails closed until refilled)"; return 1; }
    else
      curl -fsS --max-time 5 "http://$host:$port/" >/dev/null || { fail "steered probe $host:$port (empty/stale slot fails closed until refilled)"; return 1; }
    fi
    ok "steered probe $host:$port"
    ((n+=1))
  done < <(desired_state)
  (( n > 0 )) || echo "confirm: no steered ports listed in $PORTS_FILE"
}

needs_file() {
  case "$HINT" in
    worker|worker-storm|sockmap|ctl|ctl-sock|pin-race|detect-worker|start-limit) return 1 ;;
    *) return 0 ;;
  esac
}

start_limit_applies() {
  case "$HINT" in
    ""|loader|pin-race|master|openresty|pin|pins|bpffs|boot-wait|boot-loader|reboot|start-limit) return 0 ;;
    *) return 1 ;;
  esac
}

if [[ "$HINT" == detect-worker || "${RECOVERY_DRY_RUN:-0}" == 1 ]]; then
  detect_worker || true
  exit 0
fi

if start_limit_applies && start_limit_hit; then
  say_case start-limit
  echo "systemd StartLimit is hit: stay down; human intervention required (no start/reset-failed/enable attempted)" >&2
  exit 1
fi

if needs_file && ! validate_ports_file; then
  exit 1
fi

if [[ "$HINT" == worker-storm ]] || { [[ -z "$HINT" ]] && storm_exhausted; }; then
  recover_storm
  exit 1
fi

case "$HINT" in
  loader)
    say_case loader
    listen_up || start_openresty_only
    if loader_up; then
      ok "loader already running; not starting a second process"
      recover_ctl
    else
      start_loader_only
    fi
    reconcile_if_needed
    tiny_confirm
    exit 0 ;;
  pin-race)
    say_case pin-race
    if loader_up; then
      echo "one loader is running; a second long-running loader is refused by /run/waf-sklookup/loader.lock"
      exit 0
    fi
    start_loader_only
    exit 0 ;;
  master|openresty)
    say_case master
    if pins_ok; then start_openresty_only; rescan; reconcile_if_needed
    else ensure_bpffs; start_openresty_only; start_loader_only; reconcile_if_needed; fi
    tiny_confirm
    exit 0 ;;
  worker)
    recover_worker
    tiny_confirm
    exit 0 ;;
  pin|pins|bpffs)
    say_case pin
    ensure_bpffs
    listen_up || start_openresty_only
    if loader_up && pins_ok; then ok "pins already present"
    elif loader_up; then fail "loader is running without required pins; refusing to start a second loader; stop the failed owner and rerun '$0 pin'"; exit 1
    else start_loader_only; fi
    reconcile_if_needed
    tiny_confirm
    exit 0 ;;
  sockmap)
    recover_sockmap
    tiny_confirm
    exit 0 ;;
  ctl|ctl-sock)
    say_case ctl
    recover_ctl
    exit 0 ;;
  state|reconcile)
    say_case state
    reconcile_if_needed
    exit 0 ;;
  boot-wait)
    say_case boot-wait
    echo "ACTION: start frontend first so the loader does not wait on an empty listen (no empty sockmap slots)"
    start_openresty_only
    start_loader_only
    reconcile_if_needed
    tiny_confirm
    exit 0 ;;
  boot-loader)
    say_case boot-loader
    listen_up || { fail "boot-loader expects OpenResty to be listening; inner listen is down"; exit 1; }
    start_loader_only
    reconcile_if_needed
    tiny_confirm
    exit 0 ;;
  start-limit)
    say_case start-limit
    echo "StartLimit is not currently detected; no enable/start/reset-failed attempted."
    echo "Human intervention required if a unit later reports start-limit-hit; clear the root cause and follow site policy manually."
    exit 0 ;;
  reboot)
    say_case reboot
    ensure_bpffs
    start_openresty_only
    start_loader_only
    reconcile_if_needed
    tiny_confirm
    exit 0 ;;
esac

# Auto-detect: smallest matching repair. Re-running after a mid-way failure is safe.
echo "Checking StartLimit, loader, OpenResty, pins, ctl.sock, sockmap, worker identity, and desired state..."

if start_limit_hit; then
  say_case start-limit
  echo "systemd StartLimit is hit: stay down; human intervention required" >&2
  exit 1
fi

if storm_exhausted && listen_up && loader_up; then
  recover_storm
  exit 1
fi

if listen_up && loader_up && pins_ok && [[ -S "$CTL_SOCK" ]] && { detect_worker || sockmap_empty; }; then
  recover_worker
  tiny_confirm
  ok "worker-respawn / empty-slot recovery complete; loader, BPF, and open_ports were not restarted"
  exit 0
fi

if loader_up && pins_ok && [[ ! -S "$CTL_SOCK" ]]; then
  say_case ctl
  recover_ctl
fi

if ! listen_up && pins_ok; then
  say_case master
  start_openresty_only
  rescan
  reconcile_if_needed
elif ! listen_up && ! loader_up; then
  say_case reboot
  ensure_bpffs
  start_openresty_only
  start_loader_only
  reconcile_if_needed
elif ! listen_up && loader_up; then
  say_case boot-wait
  echo "ACTION: OpenResty is not listening; start frontend first (loader already up; do not expose empty slots)"
  start_openresty_only
  rescan
  reconcile_if_needed
elif ! loader_up && listen_up; then
  say_case boot-loader
  echo "ACTION: loader is down while OpenResty listens; inner bind works, external steered ports fail until attach"
  start_loader_only
  reconcile_if_needed
elif ! bpffs_mounted || ! pins_ok; then
  say_case pin
  ensure_bpffs
  if loader_up; then
    fail "loader is running without required pins; refusing to start a second loader; stop the failed owner and rerun '$0 pin'"
    exit 1
  fi
  listen_up || start_openresty_only
  start_loader_only
  reconcile_if_needed
else
  ok "loader, OpenResty, pinned maps, and control socket are present"
  if [[ -f "$PORTS_FILE" ]]; then
    say_case state
    reconcile_if_needed
  fi
fi

if [[ -e "$CTL_SOCK" && ! -S "$CTL_SOCK" ]]; then
  say_case ctl
  recover_ctl
elif [[ ! -S "$CTL_SOCK" ]] && loader_up; then
  say_case ctl
  recover_ctl
fi

[[ -S "$CTL_SOCK" ]] || { fail "control socket was not recreated at $CTL_SOCK"; exit 1; }
tiny_confirm
snapshot_worker_state
ok "recovery complete; loader and OpenResty remain running (re-run this command if a prior attempt stopped halfway)"
