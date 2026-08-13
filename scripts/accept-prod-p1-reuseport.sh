#!/usr/bin/env bash
# P1-b: multi-worker / SO_REUSEPORT skew observation.
# Generates temp conf with worker_processes 4 + listen ... reuseport,
# drives concurrent short traffic, collects per-worker request counts.
# Pass: no single worker has ~100% while others idle. If sk_lookup+multi-worker
# is broken on this stack, mark 阻塞 with exact error (do not fake PASS).
set -euo pipefail
source "$(dirname "$0")/lib-prod-gng.sh"

STARTED_HERE=0
GEN_CONF=""
ORIG_CONF="${OPENRESTY_NGINX_CONF}"
cleanup() {
  export OPENRESTY_NGINX_CONF="$ORIG_CONF"
  if [[ "$STARTED_HERE" -eq 1 ]]; then
    demo_stop || true
  fi
  # Restore default single-worker by restarting with original conf if still up
  # (umbrella will restart next suite member as needed)
  rm -f "$GEN_CONF" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== P1-b multi-worker / SO_REUSEPORT skew ==="
require_hah
ensure_loader_bin
ensure_httpbench

GEN_CONF="$(mktemp /tmp/waf-p1b-reuseport-XXXXXX.conf)"
LOGDIR_PLACEHOLDER="logs/"

# Temp conf: 4 workers, reuseport on HAH product listen, shared-dict worker counters
cat > "$GEN_CONF" <<'NGINX'
worker_processes 4;
error_log logs/error.log info;
pid logs/nginx.pid;

env WAF_EXPOSE_EXTERNAL_PORT;

events {
    worker_connections 1024;
}

http {
    default_type  application/octet-stream;
    lua_package_path "$prefix/lua/?.lua;;";
    init_by_lua_block { require "resty.core" }
    lua_shared_dict waf_worker_hits 1m;

    log_format waf_m1 '$remote_addr:$remote_port $request '
                      'scheme=$scheme '
                      'internal_port=$server_port waf_external_port=$waf_external_port '
                      'worker=$pid status=$status';
    access_log logs/access.log waf_m1;

    server {
        listen 127.0.0.1:8080 ssl https_allow_http reuseport;
        server_name waf-p1;

        ssl_certificate     certs/demo.crt;
        ssl_certificate_key certs/demo.key;
        ssl_protocols       TLSv1.2 TLSv1.3;

        set $waf_external_port '';
        set $waf_expose_external_port '';

        access_by_lua_block {
            ngx.var.waf_external_port = require("waf.external_port").resolve()
        }

        location / {
            content_by_lua_block {
                local dict = ngx.shared.waf_worker_hits
                local wid = tostring(ngx.worker.id())
                dict:incr(wid, 1, 0)
                local port = ngx.var.waf_external_port or ""
                require("waf.headers").apply_debug_headers(port)
                ngx.header.content_type = "text/plain"
                ngx.say("OpenResty M1 OK")
                ngx.say("waf_external_port=" .. port)
                ngx.say("server_port=" .. (ngx.var.server_port or ""))
                ngx.say("scheme=" .. (ngx.var.scheme or ""))
                ngx.say("remote_addr=" .. (ngx.var.remote_addr or ""))
                ngx.say("worker_id=" .. wid)
                ngx.say("worker_pid=" .. tostring(ngx.worker.pid()))
            }
        }

        location = /worker-stats {
            content_by_lua_block {
                local dict = ngx.shared.waf_worker_hits
                ngx.header.content_type = "text/plain"
                local keys = dict:get_keys(0)
                table.sort(keys, function(a,b) return tonumber(a)<tonumber(b) end)
                local total = 0
                for _, k in ipairs(keys) do
                    local v = dict:get(k) or 0
                    total = total + v
                    ngx.say("worker_id=" .. k .. " hits=" .. tostring(v))
                end
                ngx.say("total=" .. tostring(total))
                ngx.say("worker_count=" .. tostring(ngx.worker.count()))
            }
        }

        location = /worker-stats-reset {
            content_by_lua_block {
                ngx.shared.waf_worker_hits:flush_all()
                ngx.say("ok")
            }
        }
    }
}
NGINX

echo "Generated conf: $GEN_CONF"
echo "--- conf listen / workers ---"
rg -n "worker_processes|listen |lua_shared_dict" "$GEN_CONF" || true

# Syntax check before start
OR_BIN="$OPENRESTY_PREFIX/bin/openresty"
RUNTIME_TMP="$(mktemp -d /tmp/waf-p1b-runtime-XXXXXX)"
mkdir -p "$RUNTIME_TMP/logs"
# Minimal sed like run-openresty-demo for -t (paths fixed by start later)
CONF_TEST="$(mktemp /tmp/waf-p1b-test-XXXXXX.conf)"
sed "s|logs/|${RUNTIME_TMP}/logs/|g" "$GEN_CONF" > "$CONF_TEST"
sed -i "s|\$prefix/lua|${REPO_ROOT}/openresty/lua|g" "$CONF_TEST"
sed -i "s|certs/demo.crt|${REPO_ROOT}/openresty/certs/demo.crt|g" "$CONF_TEST"
sed -i "s|certs/demo.key|${REPO_ROOT}/openresty/certs/demo.key|g" "$CONF_TEST"
set +e
"$OR_BIN" -t -p "$RUNTIME_TMP" -c "$CONF_TEST" 2>&1 | tee /tmp/p1b-nginx-t.out
TRC=${PIPESTATUS[0]}
set -e
rm -rf "$RUNTIME_TMP" "$CONF_TEST"
if [[ $TRC -ne 0 ]]; then
  echo "BLOCKED: nginx -t failed for worker_processes=4 reuseport conf"
  echo "| 项 | 测了什么 | 结果 |"
  echo "|----|----------|------|"
  mark_row "P1-b" "nginx -t reuseport×4 failed: $(tr '\n' ' ' </tmp/p1b-nginx-t.out | head -c 200)" "阻塞"
  exit 3
fi

demo_stop || true
export OPENRESTY_NGINX_CONF="$GEN_CONF"
demo_start
STARTED_HERE=1

# Confirm 4 workers
sleep 0.5
MASTER=""
if [[ -f "$STATE_DIR/openresty.pidpath" ]]; then
  pf="$(cat "$STATE_DIR/openresty.pidpath")"
  [[ -f "$pf" ]] && MASTER="$(cat "$pf")"
fi
WORKER_N=0
if [[ -n "$MASTER" ]]; then
  WORKER_N="$(pgrep -P "$MASTER" 2>/dev/null | wc -l | tr -d ' ')"
fi
echo "master=$MASTER worker_children=$WORKER_N"
ss -lntp 2>/dev/null | rg ':8080\b' || true

# Baseline: does steered port even work with multi-worker?
echo "--- steered curl smoke ---"
set +e
curl -sS --max-time 5 "http://${HOST}:${PORT}/" | tee /tmp/p1b-smoke.body
SMOKE_RC=$?
set -e
if [[ $SMOKE_RC -ne 0 ]] || ! grep -q "OpenResty M1 OK" /tmp/p1b-smoke.body; then
  echo "BLOCKED: steered curl failed under worker_processes=4 reuseport (sk_lookup+multi-worker broken?)"
  echo "loader.log:"
  tail -30 "$STATE_DIR/loader.log" 2>/dev/null || true
  echo "error.log:"
  tail -30 "$STATE_DIR/logs/error.log" 2>/dev/null || true
  echo "| 项 | 测了什么 | 结果 |"
  echo "|----|----------|------|"
  mark_row "P1-b" "steered curl fail under 4 workers+reuseport (rc=$SMOKE_RC); see loader/error.log" "阻塞"
  exit 3
fi

# Reset counters then drive concurrent short traffic
curl -sS --max-time 3 "http://${HOST}:${PORT}/worker-stats-reset" >/dev/null || true
# Also hit internal to reset if needed
curl -sS --max-time 3 "http://127.0.0.1:8080/worker-stats-reset" >/dev/null 2>&1 || true

echo "--- drive concurrent short traffic (${DURATION}, c=${CONCURRENCY}) ---"
"$HTTPBENCH_BIN" -url "http://${HOST}:${PORT}/" -d "${DURATION}" -c "${CONCURRENCY}" -label p1b-reuseport | tee /tmp/p1b-bench.out

# Extra parallel curls to diversify
for i in $(seq 1 200); do
  curl -sS --max-time 2 "http://${HOST}:${PORT}/" >/dev/null 2>&1 || true
done &
for i in $(seq 1 200); do
  curl -sS --max-time 2 "http://${HOST}:${PORT}/" >/dev/null 2>&1 || true
done &
wait || true

echo "--- worker-stats ---"
STATS="$(curl -sS --max-time 3 "http://${HOST}:${PORT}/worker-stats" || true)"
echo "$STATS"
# Fallback: internal listen if steered stats path somehow broken
if [[ -z "$STATS" || "$STATS" != *total=* ]]; then
  STATS="$(curl -sS --max-time 3 "http://127.0.0.1:8080/worker-stats" || true)"
  echo "(fallback internal) $STATS"
fi

# Analyze distribution
DIST_RESULT="$(printf '%s\n' "$STATS" | python3 -c '
import sys,re
text=sys.stdin.read()
hits=[]
for m in re.finditer(r"worker_id=(\d+)\s+hits=(\d+)", text):
    hits.append((int(m.group(1)), int(m.group(2))))
total_m=re.search(r"total=(\d+)", text)
total=int(total_m.group(1)) if total_m else sum(h for _,h in hits)
print("PARSED total=%d workers_with_keys=%d" % (total, len(hits)))
if total<=0 or not hits:
    print("RESULT=阻塞")
    print("REASON=no worker hit counters (total=%d keys=%d)" % (total, len(hits)))
    raise SystemExit
# pad to expected 4 workers (missing key = 0)
by={w:h for w,h in hits}
vals=[by.get(i,0) for i in range(4)]
# if worker.count differs, use observed keys
if len(hits)>4:
    vals=[h for _,h in sorted(hits)]
mx=max(vals); mn=min(vals)
pct=100.0*mx/total if total else 0
print("DIST " + " ".join("w%d=%d"%(i,v) for i,v in enumerate(vals)))
print("max=%d min=%d max_pct=%.1f" % (mx, mn, pct))
# Extreme skew: one worker ~100% and others idle (max>=98% and min==0 and total>=50)
idle=sum(1 for v in vals if v==0)
if total>=50 and pct>=98.0 and idle>=len(vals)-1:
    print("RESULT=阻塞")
    print("REASON=extreme skew: one worker ~100%% (max_pct=%.1f) others idle" % pct)
elif total>=50 and pct>=95.0 and idle>=2:
    print("RESULT=阻塞")
    print("REASON=severe skew max_pct=%.1f idle=%d (sk_lookup likely pinned to one reuseport FD)" % (pct, idle))
else:
    print("RESULT=通过")
    print("REASON=distribution acceptable (max_pct=%.1f idle=%d)" % (pct, idle))
')"

echo "$DIST_RESULT"
RESULT="$(echo "$DIST_RESULT" | sed -n 's/^RESULT=//p' | head -1)"
REASON="$(echo "$DIST_RESULT" | sed -n 's/^REASON=//p' | head -1)"
RESULT="${RESULT:-阻塞}"

# Document listen sockets count (reuseport ⇒ multiple LISTEN inodes)
LISTEN_N="$(ss -lntp 2>/dev/null | rg -c ':8080\b' || echo 0)"
echo "listen_lines_8080=$LISTEN_N worker_children=$WORKER_N"

# Restore worker_processes=1 path: stop and leave ORIG_CONF for next
export OPENRESTY_NGINX_CONF="$ORIG_CONF"
demo_stop || true
STARTED_HERE=0
# Bring back single-worker default briefly so we leave a clean system? umbrella cleans.
# Explicit restore start+stop optional — just stop is enough; note restoration.
echo "Restored OPENRESTY_NGINX_CONF to default (worker_processes 1); demo stopped."

echo
echo "### P1-b summary table"
echo "| 项 | 测了什么 | 结果 |"
echo "|----|----------|------|"
mark_row "conf-4-reuseport" "worker_processes=4 listen reuseport nginx -t" "通过"
mark_row "steered-smoke" "curl steered :${PORT} under 4 workers" "通过"
mark_row "worker-dist" "${REASON}" "$RESULT"
mark_row "restore-wp1" "OPENRESTY_NGINX_CONF restored to single-worker default" "通过"
mark_row "P1-b overall" "multi-worker reuseport skew" "$RESULT"

if [[ "$RESULT" == "阻塞" ]]; then
  exit 3
fi
if [[ "$RESULT" != "通过" ]]; then
  exit 1
fi
exit 0
