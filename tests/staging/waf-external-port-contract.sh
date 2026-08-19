#!/usr/bin/env bash
# Exact-image staging contract for SDD-004.
#
# Required environment:
#   WAF_NGINX_BIN          exact OpenResty/Tengine binary
#   WAF_NGINX_PREFIX       prefix containing the native-module configuration
#   WAF_HTTP_URL           external HTTP URL, e.g. http://VIP:18081/waf-port-contract
#   WAF_HTTPS_URL          external HTTPS URL, e.g. https://VIP:18443/waf-port-contract
#   WAF_EXPECT_HTTP_PORT   expected numeric HTTP destination port
#   WAF_EXPECT_HTTPS_PORT  expected numeric HTTPS destination port
# Optional:
#   WAF_METRICS_URL        loader exporter URL; default http://127.0.0.1:9101/metrics
#   WAF_RELOAD_CMD         approved graceful reload command (not shell-evaluated)
#
# The target configuration must load ngx_http_waf_external_port_module.so,
# expose /waf-port-contract, and return that variable as a single line.
set -euo pipefail

need() { [[ -n "${!1:-}" ]] || { echo "missing required environment: $1" >&2; exit 2; }; }
need WAF_NGINX_BIN
need WAF_NGINX_PREFIX
need WAF_HTTP_URL
need WAF_HTTPS_URL
need WAF_EXPECT_HTTP_PORT
need WAF_EXPECT_HTTPS_PORT

ART=${ART_DIR:-"$(pwd)/artifacts/staging-waf-external-port-$(date -u +%Y%m%dT%H%M%SZ)"}
mkdir -p "$ART"
METRICS_URL=${WAF_METRICS_URL:-http://127.0.0.1:9101/metrics}

"$WAF_NGINX_BIN" -p "$WAF_NGINX_PREFIX" -t >"$ART/nginx-test.out" 2>"$ART/nginx-test.err"

expect_port() {
    local name=$1 url=$2 expected=$3 extra=${4:-}
    # `extra` intentionally supports only a fixed HTTP/2 flag selected below;
    # no untrusted shell evaluation is performed.
    local actual
    if [[ "$extra" == "http2" ]]; then
        actual=$(curl -ksS --http2 --max-time 5 "$url")
    else
        actual=$(curl -ksS --max-time 5 "$url")
    fi
    printf '%s\n' "$actual" >"$ART/$name.txt"
    [[ "$actual" == "$expected" ]] || {
        echo "$name: expected external port $expected, got '$actual'" >&2
        exit 1
    }
}

expect_port http "$WAF_HTTP_URL" "$WAF_EXPECT_HTTP_PORT"
# Two sequential requests exercise keep-alive reuse without taking a Lua socket.
curl -ksS --http1.1 --keepalive-time 20 --max-time 5 "$WAF_HTTP_URL" "$WAF_HTTP_URL" \
    >"$ART/http-keepalive.txt"
grep -qx "$WAF_EXPECT_HTTP_PORT" "$ART/http-keepalive.txt"
expect_port https "$WAF_HTTPS_URL" "$WAF_EXPECT_HTTPS_PORT"
expect_port https-http2 "$WAF_HTTPS_URL" "$WAF_EXPECT_HTTPS_PORT" http2

curl -fsS --max-time 2 "$METRICS_URL" >"$ART/loader-metrics.txt"
grep -q '^waf_sklookup_exporter_up 1$' "$ART/loader-metrics.txt"
grep -q '^waf_sklookup_runtime_reservation_state{state="active"} 1$' "$ART/loader-metrics.txt"

# WebSocket is an explicit staging command because the WAF's actual WS route,
# origin policy, and client tool are product-specific. The CI/staging job must
# write its transcript to this artifact before declaring the case passed.
cat >"$ART/websocket-required.txt" <<'EOF'
PENDING EXTERNAL EVIDENCE: execute the product WebSocket upgrade test against
both external ports and store the request/response transcript here. Assert the
WAF route sees the numeric $waf_external_port and the upgraded connection stays
open through the configured observation interval.
EOF

if [[ -n "${WAF_RELOAD_CMD:-}" ]]; then
    echo "WAF_RELOAD_CMD is intentionally not executed by this script." >&2
    echo "Run the approved service-manager graceful reload, then re-run this" >&2
    echo "script to prove a new external connection resolves its port." >&2
fi

printf 'PASS: SDD-004 HTTP/keep-alive/TLS/HTTP2 external-port contract: %s\n' "$ART"
