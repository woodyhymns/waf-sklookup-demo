#!/usr/bin/env bash
# Last-resort nftables DNAT when both sk_lookup links are gone.
#
# Default OFF. Never invoked by loader attach / unpin / upgrade / systemd.
# Enable requires an explicit flag: --enable or WAF_NFT_FALLBACK=1.
#
# Redirects NEW TCP SYNs on dynamic non-standard ports to the existing main
# listen. Established TCP is not rewritten (ct state new + exact SYN only).
# 80/443 and inner real listens never enter the set.
#
# Usage:
#   ./scripts/nft-dnat-fallback.sh render|ports|status [options]
#   WAF_NFT_FALLBACK=1 ./scripts/nft-dnat-fallback.sh enable [options]
#   ./scripts/nft-dnat-fallback.sh enable --enable [options]
#   ./scripts/nft-dnat-fallback.sh disable
set -euo pipefail

NFT_TABLE="${NFT_TABLE:-waf_sklookup_dnat}"
NFT_FAMILY="${NFT_FAMILY:-inet}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/waf-sklookup}"
PORTS_FILE="${PORTS_FILE:-ports.conf}"
TARGET="${TARGET:-127.0.0.1:8080}"
PORTS_OVERRIDE="${PORTS_OVERRIDE:-}"
SKIP_TLS=0
FORCE=0
ENABLE_ACK=0
DRY_RUN=0
INCLUDE_REAL_SKIP="${INCLUDE_REAL_SKIP:-1}"

# Product reserved + inner real binds (nginx_listen.rs inner_real_ports).
RESERVED_PORTS=(80 443)
INNER_REAL_PORTS=(80 443 8080 8443)

usage() {
  cat <<EOF
Last-resort nftables DNAT (default OFF). Not a substitute for pin-link (#38)
or backup sk_lookup (#40). Apply only after both links are gone.

Commands:
  render     Print the ruleset (no apply; no --enable required)
  ports      Print the filtered destination-port list
  status     Pins + table presence
  enable     Install the table (requires --enable or WAF_NFT_FALLBACK=1)
  disable    Delete the table (idempotent rollback)

Options:
  --enable              Confirm enable (or set WAF_NFT_FALLBACK=1)
  --force               Allow enable while a sk_lookup pin still exists
  --ports-file PATH     Desired-state file (default ports.conf)
  --ports LIST          Override (comma / START-END); reserved still filtered
  --target HOST:PORT    Main listen (default 127.0.0.1:8080)
  --pin-dir DIR         bpffs pin dir (default /sys/fs/bpf/waf-sklookup)
  --skip-tls            Omit ports.conf lines marked tls
  --table NAME          nft table (default waf_sklookup_dnat)
  --dry-run             Print actions; do not apply
EOF
}

die() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "NOTE: $*" >&2; }

have_nft() { command -v nft >/dev/null 2>&1; }

nft_run() {
  if [[ "$(id -u)" == 0 ]]; then
    nft "$@"
  else
    sudo nft "$@"
  fi
}

split_host_port() {
  local addr="$1"
  if [[ "$addr" == \[*\]:* ]]; then
    TARGET_HOST="${addr%]*}"; TARGET_HOST="${TARGET_HOST#\[}"
    TARGET_PORT="${addr##*\]:}"
  else
    TARGET_HOST="${addr%:*}"
    TARGET_PORT="${addr##*:}"
  fi
  [[ "$TARGET_PORT" =~ ^[0-9]+$ ]] && (( TARGET_PORT >= 1 && TARGET_PORT <= 65535 )) \
    || die "bad --target $addr (want HOST:PORT)"
}

is_reserved_port() {
  local p="$1" r
  for r in "${RESERVED_PORTS[@]}"; do
    [[ "$p" == "$r" ]] && return 0
  done
  if [[ "$INCLUDE_REAL_SKIP" == "1" ]]; then
    for r in "${INNER_REAL_PORTS[@]}"; do
      [[ "$p" == "$r" ]] && return 0
    done
  fi
  [[ -n "${TARGET_PORT:-}" && "$p" == "$TARGET_PORT" ]] && return 0
  return 1
}

expand_port_spec() {
  local spec="$1" tok a b
  local -a out=()
  IFS=',' read -r -a toks <<<"$spec"
  for tok in "${toks[@]}"; do
    tok="${tok//[[:space:]]/}"
    [[ -z "$tok" ]] && continue
    if [[ "$tok" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"
      (( a >= 1 && b <= 65535 && a <= b )) || die "bad port range $tok"
      local i
      for (( i = a; i <= b; i++ )); do
        out+=("$i")
      done
    elif [[ "$tok" =~ ^[0-9]+$ ]] && (( tok >= 1 && tok <= 65535 )); then
      out+=("$tok")
    else
      die "bad port token $tok"
    fi
  done
  printf '%s\n' "${out[@]}"
}

collect_ports() {
  local -a raw=() collected=()
  local line spec rest tok skip_line
  if [[ -n "$PORTS_OVERRIDE" ]]; then
    mapfile -t raw < <(expand_port_spec "$PORTS_OVERRIDE")
  else
    [[ -f "$PORTS_FILE" ]] || die "ports file missing: $PORTS_FILE"
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="${line#"${line%%[![:space:]]*}"}"
      line="${line%"${line##*[![:space:]]}"}"
      [[ -z "$line" ]] && continue
      read -r spec rest <<<"$line"
      skip_line=0
      if [[ "$SKIP_TLS" -eq 1 ]]; then
        for tok in $rest; do
          [[ "$tok" == "tls" ]] && skip_line=1 && break
        done
      fi
      [[ "$skip_line" -eq 1 ]] && continue
      mapfile -t more < <(expand_port_spec "$spec")
      raw+=("${more[@]}")
    done <"$PORTS_FILE"
  fi
  local p seen="|"
  for p in "${raw[@]}"; do
    is_reserved_port "$p" && continue
    [[ "$seen" == *"|$p|"* ]] && continue
    seen+="$p|"
    collected+=("$p")
  done
  if [[ ${#collected[@]} -eq 0 ]]; then
    die "no dynamic ports left after filtering 80/443/inner reals/target"
  fi
  printf '%s\n' "${collected[@]}"
}

elements_csv() {
  local -a ports=()
  mapfile -t ports < <(collect_ports)
  local i s=""
  for (( i = 0; i < ${#ports[@]}; i++ )); do
    [[ $i -gt 0 ]] && s+=", "
    s+="${ports[$i]}"
  done
  printf '%s' "$s"
}

render_ruleset() {
  split_host_port "$TARGET"
  local elems
  elems="$(elements_csv)"
  cat <<EOF
# last-resort only; delete table ${NFT_FAMILY} ${NFT_TABLE} to roll back
# first-packet / NEW SYN; established TCP is not DNATed
table ${NFT_FAMILY} ${NFT_TABLE} {
	set dyn_ports {
		type inet_service
		elements = { ${elems} }
	}

	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		meta nfproto ipv4 meta l4proto tcp tcp dport @dyn_ports tcp flags syn ct state new dnat to ${TARGET_HOST}:${TARGET_PORT}
	}

	chain output {
		type nat hook output priority dstnat; policy accept;
		meta nfproto ipv4 meta l4proto tcp tcp dport @dyn_ports tcp flags syn ct state new dnat to ${TARGET_HOST}:${TARGET_PORT}
	}
}
EOF
}

pins_present() {
  local n=0
  [[ -e "$PIN_DIR/sk_lookup" ]] && n=$((n + 1))
  [[ -e "$PIN_DIR/sk_lookup_backup" ]] && n=$((n + 1))
  echo "$n"
}

table_present() {
  have_nft || return 1
  nft_run list table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1
}

cmd_status() {
  split_host_port "$TARGET"
  local primary=missing backup=missing table=absent applicable=no
  [[ -e "$PIN_DIR/sk_lookup" ]] && primary=present
  [[ -e "$PIN_DIR/sk_lookup_backup" ]] && backup=present
  if have_nft && table_present; then
    table=present
  elif ! have_nft; then
    table="nft-absent"
  fi
  if [[ "$primary" == "missing" && "$backup" == "missing" ]]; then
    applicable=yes
  fi
  echo "primary_sk_lookup=$primary"
  echo "backup_sk_lookup=$backup"
  echo "nft_table=$NFT_FAMILY $NFT_TABLE $table"
  echo "target=$TARGET"
  echo "last_resort_applicable=$applicable"
  echo "enabled=$([[ "$table" == "present" ]] && echo yes || echo no)"
  echo "default=OFF"
  if have_nft && table_present; then
    nft_run list table "$NFT_FAMILY" "$NFT_TABLE" || true
  fi
}

require_enable_ack() {
  if [[ "$ENABLE_ACK" -eq 1 || "${WAF_NFT_FALLBACK:-}" == "1" ]]; then
    return 0
  fi
  die "enable refused: pass --enable or WAF_NFT_FALLBACK=1 (default OFF; no production auto-enable)"
}

require_last_line() {
  local n
  n="$(pins_present)"
  if [[ "$n" -gt 0 && "$FORCE" -ne 1 ]]; then
    die "enable refused: $n sk_lookup pin(s) still present under $PIN_DIR (nft is last line only; unpin both, or --force for experiments)"
  fi
  if [[ "$n" -gt 0 && "$FORCE" -eq 1 ]]; then
    note " --force: installing nft while sk_lookup pin(s) exist; dest port is rewritten before lookup"
  fi
}

cmd_enable() {
  require_enable_ack
  split_host_port "$TARGET"
  require_last_line
  local rules
  rules="$(render_ruleset)"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "$rules"
    echo "DRY-RUN: would install table $NFT_FAMILY $NFT_TABLE → $TARGET"
    return 0
  fi
  have_nft || die "nft binary not found"
  nft_run delete table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1 || true
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/waf-nft-dnat.XXXXXX")"
  printf '%s\n' "$rules" >"$tmp"
  if ! nft_run -f "$tmp"; then
    rm -f "$tmp"
    die "nft -f failed (need nf_tables + nat; CAP_NET_ADMIN/root)"
  fi
  rm -f "$tmp"
  echo "enabled: table $NFT_FAMILY $NFT_TABLE dnat NEW SYN → $TARGET"
}

cmd_disable() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN: would delete table $NFT_FAMILY $NFT_TABLE"
    return 0
  fi
  if ! have_nft; then
    note "nft absent; nothing to delete"
    return 0
  fi
  if nft_run delete table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1; then
    echo "disabled: deleted table $NFT_FAMILY $NFT_TABLE"
  else
    echo "disabled: table $NFT_FAMILY $NFT_TABLE already absent"
  fi
  echo "NOTE: existing DNATed flows may continue via conntrack until they close"
}

parse_args() {
  local cmd="${1:-}"
  [[ -n "$cmd" ]] || { usage; exit 2; }
  shift || true
  case "$cmd" in
    -h|--help|help) usage; exit 0 ;;
    render|ports|status|enable|disable) COMMAND="$cmd" ;;
    *) usage; die "unknown command $cmd" ;;
  esac
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --enable) ENABLE_ACK=1; shift ;;
      --force) FORCE=1; shift ;;
      --skip-tls) SKIP_TLS=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --ports-file)
        [[ $# -ge 2 ]] || die "--ports-file needs PATH"
        PORTS_FILE="$2"; shift 2 ;;
      --ports)
        [[ $# -ge 2 ]] || die "--ports needs LIST"
        PORTS_OVERRIDE="$2"; shift 2 ;;
      --target)
        [[ $# -ge 2 ]] || die "--target needs HOST:PORT"
        TARGET="$2"; shift 2 ;;
      --pin-dir)
        [[ $# -ge 2 ]] || die "--pin-dir needs DIR"
        PIN_DIR="$2"; shift 2 ;;
      --table)
        [[ $# -ge 2 ]] || die "--table needs NAME"
        NFT_TABLE="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option $1" ;;
    esac
  done
}

nft_dnat_main() {
  parse_args "$@"
  split_host_port "$TARGET"
  case "$COMMAND" in
    render) render_ruleset ;;
    ports) collect_ports ;;
    status) cmd_status ;;
    enable) cmd_enable ;;
    disable) cmd_disable ;;
    *) die "internal: bad command $COMMAND" ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  nft_dnat_main "$@"
fi
