#!/usr/bin/env bash
# Unit checks for nft DNAT last-resort (no nft / no BPF required).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NFT_SH="$REPO_ROOT/scripts/nft-dnat-fallback.sh"
chmod +x "$NFT_SH"

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "=== nft-dnat-fallback unit (no nft required) ==="

set +e
"$NFT_SH" enable --ports 19081 --target 127.0.0.1:19080 >/tmp/nft-unit-noflag.out 2>/tmp/nft-unit-noflag.err
rc=$?
set -e
[[ $rc -ne 0 ]] || fail "enable without --enable must fail"
grep -q 'default OFF\|enable refused' /tmp/nft-unit-noflag.err || fail "refusal text missing"

mapfile -t ports < <("$NFT_SH" ports --ports "80,443,8080,8443,19081,19082" --target 127.0.0.1:19080)
joined="|$(IFS='|'; echo "${ports[*]}")|"
[[ "$joined" == *"|19081|"* && "$joined" == *"|19082|"* ]] || fail "dynamic ports dropped: ${ports[*]}"
for bad in 80 443 8080 8443 19080; do
  [[ "$joined" == *"|$bad|"* ]] && fail "reserved/target $bad leaked into set"
done

tmp_ports="$(mktemp "${TMPDIR:-/tmp}/nft-unit-ports.XXXXXX")"
cat >"$tmp_ports" <<'EOF'
# desired
80 demo local
443 demo local
19081 demo local
18443 demo local tls
EOF
mapfile -t from_file < <("$NFT_SH" ports --ports-file "$tmp_ports" --target 127.0.0.1:8080 --skip-tls)
from_joined="|$(IFS='|'; echo "${from_file[*]}")|"
[[ "$from_joined" == *"|19081|"* ]] || fail "ports.conf 19081 missing"
[[ "$from_joined" == *"|18443|"* ]] && fail "--skip-tls kept 18443"
[[ "$from_joined" == *"|80|"* || "$from_joined" == *"|443|"* ]] && fail "80/443 from file"
rm -f "$tmp_ports"

mapfile -t repo_ports < <("$NFT_SH" ports --ports-file "$REPO_ROOT/ports.conf" --target 127.0.0.1:8080)
repo_joined="|$(IFS='|'; echo "${repo_ports[*]}")|"
[[ "$repo_joined" == *"|18081|"* && "$repo_joined" == *"|18082|"* && "$repo_joined" == *"|65500|"* ]] \
  || fail "repo ports.conf missing primary ports: ${repo_ports[*]}"
[[ "$repo_joined" == *"|18443|"* ]] || fail "tls port 18443 should map to main listen by default"
for bad in 80 443 8080 8443; do
  [[ "$repo_joined" == *"|$bad|"* ]] && fail "repo ports.conf leaked $bad"
done

rules="$("$NFT_SH" render --ports 19081 --target 127.0.0.1:19080)"
echo "$rules" | grep -q 'table inet waf_sklookup_dnat' || fail "table name"
echo "$rules" | grep -q 'ct state new' || fail "missing ct state new"
echo "$rules" | grep -q 'tcp flags syn' || fail "missing tcp flags syn"
echo "$rules" | grep -q 'dnat to 127.0.0.1:19080' || fail "missing dnat dest"
echo "$rules" | grep -q 'hook prerouting' || fail "missing prerouting"
echo "$rules" | grep -q 'hook output' || fail "missing output (local SYN)"
echo "$rules" | grep -q '19081' || fail "missing virt port in set"
echo "$rules" | grep -Eq 'elements = \{[^}]*\b80\b' && fail "80 in render"

"$NFT_SH" disable --dry-run | grep -q 'waf_sklookup_dnat' || fail "dry-run disable"
"$NFT_SH" enable --enable --dry-run --ports 19081 --target 127.0.0.1:19080 \
  | grep -q 'dnat to 127.0.0.1:19080' || fail "dry-run enable render"

echo "nft-dnat-fallback unit: PASS"
exit 0
