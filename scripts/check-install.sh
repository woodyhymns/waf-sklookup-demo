#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failures=0

ok() { printf 'OK: %s\n' "$*"; }
warn() { printf 'NOTE: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; failures=$((failures + 1)); }

kernel_release="$(uname -r)"
kernel_core="${kernel_release%%-*}"
kernel_major="${kernel_core%%.*}"
kernel_rest="${kernel_core#*.}"
kernel_minor="${kernel_rest%%.*}"
if [[ "$kernel_major" =~ ^[0-9]+$ && "$kernel_minor" =~ ^[0-9]+$ ]] && \
   (( kernel_major > 5 || (kernel_major == 5 && kernel_minor >= 9) )); then
  ok "kernel $kernel_release is >= 5.9"
else
  fail "kernel >= 5.9 is required; found $kernel_release"
fi

if command -v bpftool >/dev/null 2>&1; then
  feature_output="$(bpftool feature 2>&1 || true)"
  if grep -Eiq '(program_type[[:space:]]+sk_lookup|BPF_SK_LOOKUP).*(is available|yes|enabled|supported)' <<<"$feature_output"; then
    ok "BPF_SK_LOOKUP support reported by bpftool"
  else
    fail "BPF_SK_LOOKUP support was not reported by 'bpftool feature'"
  fi
else
  warn "bpftool is missing; using kernel symbol/BTF fallback for BPF_SK_LOOKUP"
  if [[ -r /proc/kallsyms ]] && grep -Eiq '(^|[[:space:]])(bpf_)?sk_lookup([[:space:]]|$)' /proc/kallsyms; then
    ok "BPF_SK_LOOKUP support indicated by /proc/kallsyms"
  elif [[ -r /sys/kernel/btf/vmlinux ]]; then
    fail "BPF_SK_LOOKUP support cannot be confirmed from readable symbols (kernel BTF exists); install bpftool to verify"
  else
    fail "BPF_SK_LOOKUP support cannot be verified; bpftool, matching /proc/kallsyms symbols, and /sys/kernel/btf/vmlinux are unavailable"
  fi
fi

if command -v findmnt >/dev/null 2>&1 && findmnt -rn -t bpf /sys/fs/bpf >/dev/null 2>&1; then
  ok "bpffs is mounted at /sys/fs/bpf"
elif mount 2>/dev/null | grep -Eq ' type bpf .* on /sys/fs/bpf | on /sys/fs/bpf type bpf'; then
  ok "bpffs is mounted at /sys/fs/bpf"
else
  fail "bpffs is not mounted at /sys/fs/bpf"
fi

if (( EUID == 0 )); then
  ok "effective uid is root (required BPF privileges available)"
else
  capsh_current=""
  if command -v capsh >/dev/null 2>&1; then
    capsh_current="$(capsh --print 2>/dev/null | sed -n 's/^Current: //p' | head -n1)"
  fi
  proc_cap_hex="$(awk '/^CapEff:/ {print $2}' /proc/self/status 2>/dev/null || true)"
  has_net_admin=0
  has_bpf=0
  if [[ -n "$proc_cap_hex" ]]; then
    cap_value=$((16#$proc_cap_hex))
    (( (cap_value & (1 << 12)) != 0 )) && has_net_admin=1
    (( (cap_value & (1 << 39)) != 0 )) && has_bpf=1
  fi
  [[ "$capsh_current" =~ (^|,)cap_net_admin([=,+]|$) ]] && has_net_admin=1
  [[ "$capsh_current" =~ (^|,)cap_bpf([=,+]|$) ]] && has_bpf=1
  (( has_bpf == 1 )) && ok "CAP_BPF is effective" || fail "CAP_BPF (capability bit 39) is missing and euid is not 0"
  (( has_net_admin == 1 )) && ok "CAP_NET_ADMIN is effective" || fail "CAP_NET_ADMIN (capability bit 12) is missing and euid is not 0"
fi

loader=""
if [[ -n "${LOADER_BIN:-}" ]]; then
  [[ -x "$LOADER_BIN" ]] && loader="$LOADER_BIN" || fail "loader binary from LOADER_BIN is missing or not executable: $LOADER_BIN"
elif [[ -x "$repo_root/rust/loader/target/release/waf-sklookup-loader" ]]; then
  loader="$repo_root/rust/loader/target/release/waf-sklookup-loader"
elif command -v waf-sklookup-loader >/dev/null 2>&1; then
  loader="$(command -v waf-sklookup-loader)"
else
  fail "loader binary is missing; expected $repo_root/rust/loader/target/release/waf-sklookup-loader or waf-sklookup-loader in PATH"
fi
[[ -n "$loader" ]] && ok "loader binary is executable: $loader"

openresty_bin=""
if [[ -n "${OPENRESTY_PREFIX:-}" ]]; then
  expected_openresty="$OPENRESTY_PREFIX/bin/openresty"
  [[ -x "$expected_openresty" ]] && openresty_bin="$expected_openresty" || fail "OpenResty binary from OPENRESTY_PREFIX is missing or not executable: $expected_openresty"
else
  for candidate in /usr/local/openresty/bin/openresty /usr/local/openresty-hah/bin/openresty; do
    if [[ -x "$candidate" ]]; then openresty_bin="$candidate"; break; fi
  done
  if [[ -z "$openresty_bin" ]] && command -v openresty >/dev/null 2>&1; then
    openresty_bin="$(command -v openresty)"
  fi
  [[ -n "$openresty_bin" ]] || fail "OpenResty binary is missing; expected /usr/local/openresty/bin/openresty, /usr/local/openresty-hah/bin/openresty, or openresty in PATH"
fi
[[ -n "$openresty_bin" ]] && ok "OpenResty binary is executable: $openresty_bin"

if command -v nft >/dev/null 2>&1; then
  warn "nft is present; last-resort DNAT stays OFF unless scripts/nft-dnat-fallback.sh enable --enable"
else
  warn "nft is missing; SDD-005 last-resort DNAT unavailable (accept-nft-dnat-fallback.sh exits 77)"
fi

if (( failures == 0 )); then
  printf 'SUMMARY: all install checks passed\n'
  exit 0
fi
printf 'SUMMARY: %d install check(s) failed\n' "$failures"
exit 1
