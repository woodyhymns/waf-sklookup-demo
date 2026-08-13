#!/usr/bin/env bash
# P1-c: $waf_external_port true path — ACL / access_log / limit keyed by external port.
# Temp conf from tengine example:
#   1) access_log keeps waf_external_port
#   2) ACL deny if tonumber(waf_external_port)==19999 AFTER resolve()
#   3) lua shared-dict rate limit keyed by external port (tight)
# Prove: port A → 200 + correct body/log; deny port → 403; burst on A limited while B OK.
set -euo pipefail
source "$(dirname "$0")/lib-prod-gng.sh"

STARTED_HERE=0
GEN_CONF=""
ORIG_CONF="${OPENRESTY_NGINX_CONF}"
DENY_PORT="${DENY_PORT:-19999}"
PORT_A="${PORT_A:-18081}"
PORT_B="${PORT_B:-18082}"
# Rate: N requests / window seconds per external port
RATE_LIMIT="${RATE_LIMIT:-8}"
RATE_WINDOW="${RATE_WINDOW:-2}"

cleanup() {
  export OPENRESTY_NGINX_CONF="$ORIG_CONF"
  rm -f "$GEN_CONF" 2>/dev/null || true
  hygiene_cleanup
}
trap 'cleanup' EXIT ERR
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 131' QUIT
trap 'cleanup; exit 143' TERM

echo "=== P1-c \$waf_external_port true path (ACL / log / limit) ==="
require_hah
ensure_loader_bin

GEN_CONF="$(mktemp /tmp/waf-p1c-wafport-XXXXXX.conf)"
cat > "$GEN_CONF" <<NGINX
worker_processes 1;
error_log logs/error.log info;
pid logs/nginx.pid;

env WAF_EXPOSE_EXTERNAL_PORT;

events {
    worker_connections 1024;
}

http {
    default_type  application/octet-stream;
    lua_package_path "\$prefix/lua/?.lua;;";
    init_by_lua_block { require "resty.core" }
    lua_shared_dict waf_port_rl 1m;

    log_format waf_m1 '\$remote_addr:\$remote_port \$request '
                      'scheme=\$scheme '
                      'internal_port=\$server_port waf_external_port=\$waf_external_port '
                      'status=\$status';
    access_log logs/access.log waf_m1;

    server {
        listen 127.0.0.1:8080 ssl https_allow_http;
        server_name waf-p1;

        ssl_certificate     certs/demo.crt;
        ssl_certificate_key certs/demo.key;
        ssl_protocols       TLSv1.2 TLSv1.3;

        set \$waf_external_port '';
        set \$waf_expose_external_port '';

        access_by_lua_block {
            local port = require("waf.external_port").resolve()
            ngx.var.waf_external_port = port

            -- ACL: deny deny-list external port (NOT Host / NOT server_port)
            local n = tonumber(port)
            if n == ${DENY_PORT} then
                ngx.status = 403
                ngx.header.content_type = "text/plain"
                ngx.say("denied waf_external_port=" .. tostring(port))
                return ngx.exit(403)
            end

            -- Per-external-port rate limit (shared dict). Key is external port only.
            local dict = ngx.shared.waf_port_rl
            local key = "p:" .. tostring(port)
            local lim = ${RATE_LIMIT}
            local win = ${RATE_WINDOW}
            local cur = dict:get(key)
            if not cur then
                local ok, err = dict:set(key, 1, win)
                if not ok then
                    ngx.log(ngx.ERR, "rl set: ", err)
                end
            else
                local newv, err = dict:incr(key, 1)
                if not newv then
                    ngx.log(ngx.ERR, "rl incr: ", err)
                elseif newv > lim then
                    ngx.status = 503
                    ngx.header.content_type = "text/plain"
                    ngx.header["Retry-After"] = tostring(win)
                    ngx.say("limited waf_external_port=" .. tostring(port) .. " n=" .. tostring(newv))
                    return ngx.exit(503)
                end
            end
        }

        location / {
            content_by_lua_block {
                local port = ngx.var.waf_external_port or ""
                require("waf.headers").apply_debug_headers(port)
                ngx.header.content_type = "text/plain"
                ngx.say("OpenResty M1 OK")
                ngx.say("waf_external_port=" .. port)
                ngx.say("server_port=" .. (ngx.var.server_port or ""))
                ngx.say("scheme=" .. (ngx.var.scheme or ""))
                ngx.say("remote_addr=" .. (ngx.var.remote_addr or ""))
                ngx.say("host=" .. (ngx.var.http_host or ""))
            }
        }
    }
}
NGINX

echo "Generated conf: $GEN_CONF (deny=${DENY_PORT} rate=${RATE_LIMIT}/${RATE_WINDOW}s)"

demo_stop || true
export OPENRESTY_NGINX_CONF="$GEN_CONF"
# Ensure PORT_A/B in loader ports
export LOADER_PORTS="${PORT_A},${PORT_B},65500"
demo_start
STARTED_HERE=1

# Open deny port into map for ACL test
sudo "$LOADER_BIN" add -pin-dir "$PIN_DIR" "$DENY_PORT"

# Truncate access log for clean assertions
: > "$STATE_DIR/logs/access.log" 2>/dev/null || true

echo "--- (1) steered port A=${PORT_A} → expect 200 + waf_external_port=A ---"
set +e
curl -sS -D /tmp/p1c-a.hdr -o /tmp/p1c-a.body --max-time 5 \
  -H "Host: wrong-host.example" \
  "http://127.0.0.1:${PORT_A}/"
RC_A=$?
set -e
cat /tmp/p1c-a.hdr; echo; cat /tmp/p1c-a.body
A_OK="失败"
if [[ $RC_A -eq 0 ]] && grep -q "OpenResty M1 OK" /tmp/p1c-a.body \
  && grep -q "waf_external_port=${PORT_A}" /tmp/p1c-a.body \
  && ! grep -q "waf_external_port=8080" /tmp/p1c-a.body; then
  A_OK="通过"
fi
# access_log check
sleep 0.2
LOG_A="失败"
if rg -q "waf_external_port=${PORT_A}.*status=200|status=200.*waf_external_port=${PORT_A}" "$STATE_DIR/logs/access.log" 2>/dev/null \
  || rg -q "waf_external_port=${PORT_A}" "$STATE_DIR/logs/access.log" 2>/dev/null; then
  LOG_A="通过"
fi
echo "A_OK=$A_OK LOG_A=$LOG_A"

echo "--- (2) deny port ${DENY_PORT} → expect 403 ---"
set +e
CODE_DENY="$(curl -sS -o /tmp/p1c-deny.body -w '%{http_code}' --max-time 5 \
  -H "Host: wrong-host.example" \
  "http://127.0.0.1:${DENY_PORT}/")"
RC_D=$?
set -e
echo "http_code=$CODE_DENY rc=$RC_D"
cat /tmp/p1c-deny.body || true
DENY_OK="失败"
if [[ "$CODE_DENY" == "403" ]] || grep -q "denied waf_external_port=${DENY_PORT}" /tmp/p1c-deny.body 2>/dev/null; then
  DENY_OK="通过"
fi
echo "DENY_OK=$DENY_OK"

echo "--- (3) burst on port A hits limit; port B still OK (same Host) ---"
# Reset rate window: sleep past window
sleep $((RATE_WINDOW + 1))
LIMITED=0
OK_BURST=0
for i in $(seq 1 $((RATE_LIMIT + 12))); do
  code="$(curl -sS -o /tmp/p1c-burst.body -w '%{http_code}' --max-time 2 \
    -H "Host: same-host.example" \
    "http://127.0.0.1:${PORT_A}/" || echo 000)"
  if [[ "$code" == "503" ]]; then
    LIMITED=$((LIMITED + 1))
  elif [[ "$code" == "200" ]]; then
    OK_BURST=$((OK_BURST + 1))
  fi
done
echo "burst A: ok200=$OK_BURST limited503=$LIMITED"
set +e
CODE_B="$(curl -sS -o /tmp/p1c-b.body -w '%{http_code}' --max-time 5 \
  -H "Host: same-host.example" \
  "http://127.0.0.1:${PORT_B}/")"
set -e
echo "port B code=$CODE_B"
cat /tmp/p1c-b.body || true
LIMIT_OK="失败"
if [[ "$LIMITED" -ge 1 && "$CODE_B" == "200" ]] && grep -q "waf_external_port=${PORT_B}" /tmp/p1c-b.body; then
  LIMIT_OK="通过"
fi
# If B also limited somehow keyed by Host, that would fail — good.
echo "LIMIT_OK=$LIMIT_OK"

echo "--- access_log tail ---"
tail -20 "$STATE_DIR/logs/access.log" 2>/dev/null || true

STATUS="通过"
[[ "$A_OK" != "通过" || "$LOG_A" != "通过" || "$DENY_OK" != "通过" || "$LIMIT_OK" != "通过" ]] && STATUS="失败"

export OPENRESTY_NGINX_CONF="$ORIG_CONF"
demo_stop || true
STARTED_HERE=0

echo
echo "### P1-c summary table"
echo "| 项 | 测了什么 | 结果 |"
echo "|----|----------|------|"
mark_row "port-A-body" "curl :${PORT_A} Host=wrong → waf_external_port=${PORT_A}" "$A_OK"
mark_row "port-A-access-log" "access_log waf_external_port=${PORT_A}" "$LOG_A"
mark_row "acl-deny" "curl :${DENY_PORT} → 403" "$DENY_OK"
mark_row "limit-by-ext-port" "burst A→503 (${LIMITED}x) while B→200 same Host" "$LIMIT_OK"
mark_row "P1-c overall" "\$waf_external_port ACL/log/limit true path" "$STATUS"

[[ "$STATUS" == "通过" ]] || exit 1
exit 0
