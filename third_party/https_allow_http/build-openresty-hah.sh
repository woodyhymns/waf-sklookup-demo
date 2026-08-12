#!/usr/bin/env bash
# Build OpenResty 1.19.3.2 + Tengine https_allow_http into a separate prefix.
set -euo pipefail
# Debian/Ubuntu put ldconfig in /sbin; OpenResty configure requires it in PATH for LuaJIT.
export PATH="/usr/sbin:/sbin:${PATH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PATCH="$SCRIPT_DIR/nginx-1.19.3-https_allow_http.patch"

OPENRESTY_VER="${OPENRESTY_VER:-1.19.3.2}"
OPENRESTY_PREFIX="${OPENRESTY_PREFIX:-/usr/local/openresty-hah}"
BUILD_ROOT="${BUILD_ROOT:-/workspace/openresty-build-hah}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

OPENRESTY_TGZ_URL="${OPENRESTY_TGZ_URL:-https://openresty.org/download/openresty-${OPENRESTY_VER}.tar.gz}"
PCRE_VER="${PCRE_VER:-8.45}"
PCRE_TGZ_URL="${PCRE_TGZ_URL:-https://downloads.sourceforge.net/project/pcre/pcre/${PCRE_VER}/pcre-${PCRE_VER}.tar.gz}"
# Fallback mirror if sourceforge is slow/blocked
PCRE_TGZ_URL_FALLBACK="${PCRE_TGZ_URL_FALLBACK:-https://ftp.exim.org/pub/pcre/pcre-${PCRE_VER}.tar.gz}"

log() { printf '+ %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }

need_cmd curl
need_cmd tar
need_cmd patch
need_cmd perl
need_cmd gcc
need_cmd make
need_cmd gmake

[[ -f "$PATCH" ]] || die "patch not found: $PATCH"

mkdir -p "$BUILD_ROOT"
cd "$BUILD_ROOT"

# Prefer already-downloaded artifacts from sibling openresty-build if present.
if [[ ! -f "openresty-${OPENRESTY_VER}.tar.gz" ]]; then
  if [[ -f "/workspace/openresty-build/openresty-${OPENRESTY_VER}.tar.gz" ]]; then
    log "reusing /workspace/openresty-build/openresty-${OPENRESTY_VER}.tar.gz"
    cp -a "/workspace/openresty-build/openresty-${OPENRESTY_VER}.tar.gz" .
  else
    log "download openresty-${OPENRESTY_VER}"
    curl -fL --retry 3 -o "openresty-${OPENRESTY_VER}.tar.gz" "$OPENRESTY_TGZ_URL"
  fi
fi

if [[ ! -f "pcre-${PCRE_VER}.tar.gz" ]]; then
  if [[ -f "/workspace/openresty-build/pcre-${PCRE_VER}.tar.gz" ]]; then
    log "reusing /workspace/openresty-build/pcre-${PCRE_VER}.tar.gz"
    cp -a "/workspace/openresty-build/pcre-${PCRE_VER}.tar.gz" .
  else
    log "download pcre-${PCRE_VER}"
    curl -fL --retry 3 -o "pcre-${PCRE_VER}.tar.gz" "$PCRE_TGZ_URL" \
      || curl -fL --retry 3 -o "pcre-${PCRE_VER}.tar.gz" "$PCRE_TGZ_URL_FALLBACK"
  fi
fi
# Always extract fresh to avoid leftover objects from other prefixes.
rm -rf "pcre-${PCRE_VER}"
tar -xzf "pcre-${PCRE_VER}.tar.gz"

# Fresh OpenResty tree each build so patch applies cleanly.
rm -rf "openresty-${OPENRESTY_VER}"
tar -xzf "openresty-${OPENRESTY_VER}.tar.gz"
OR_SRC="$BUILD_ROOT/openresty-${OPENRESTY_VER}"
NGINX_SRC="$OR_SRC/bundle/nginx-1.19.3"
[[ -d "$NGINX_SRC" ]] || die "expected nginx-1.19.3 under $OR_SRC/bundle"

log "apply $PATCH"
( cd "$NGINX_SRC" && patch -p1 < "$PATCH" )

# Ensure install prefix parent is writable.
if [[ ! -d "$OPENRESTY_PREFIX" ]]; then
  if mkdir -p "$OPENRESTY_PREFIX" 2>/dev/null; then
    :
  else
    log "creating $OPENRESTY_PREFIX with sudo"
    sudo mkdir -p "$OPENRESTY_PREFIX"
    sudo chown "$(id -u):$(id -g)" "$OPENRESTY_PREFIX"
  fi
fi

log "configure --prefix=$OPENRESTY_PREFIX"
cd "$OR_SRC"
# Match prior demo build: bundled PCRE (Debian 13 has no libpcre3-dev),
# system OpenSSL/zlib, ssl + v2 + stream, default OpenResty Lua modules.
./configure \
  --prefix="$OPENRESTY_PREFIX" \
  --with-pcre="$BUILD_ROOT/pcre-${PCRE_VER}" \
  --with-pcre-jit \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_stub_status_module \
  --with-http_realip_module \
  --with-http_gzip_static_module \
  --with-stream \
  --with-stream_ssl_module \
  --with-stream_ssl_preread_module \
  --with-threads \
  --with-file-aio \
  -j"$JOBS" \
  2>&1 | tee "$BUILD_ROOT/configure.log"

# Confirm feature macro was emitted.
if ! rg -q 'T_NGX_HTTPS_ALLOW_HTTP' "$OR_SRC/build/nginx-1.19.3/objs/ngx_auto_config.h" 2>/dev/null; then
  # rg may be missing; fall back
  if ! grep -q 'T_NGX_HTTPS_ALLOW_HTTP' "$OR_SRC/build/nginx-1.19.3/objs/ngx_auto_config.h"; then
    die "T_NGX_HTTPS_ALLOW_HTTP not present in ngx_auto_config.h — patch/auto/modules failed"
  fi
fi
log "T_NGX_HTTPS_ALLOW_HTTP present in ngx_auto_config.h"

log "make -j$JOBS"
gmake -j"$JOBS" 2>&1 | tee "$BUILD_ROOT/make.log"
log "make install"
gmake install 2>&1 | tee "$BUILD_ROOT/install.log"

BIN="$OPENRESTY_PREFIX/bin/openresty"
[[ -x "$BIN" ]] || die "missing binary: $BIN"

log "openresty -V"
"$BIN" -V

# Smoke nginx -t with https_allow_http
SMOKE_ROOT="$BUILD_ROOT/hah-smoke"
rm -rf "$SMOKE_ROOT"
mkdir -p "$SMOKE_ROOT"/{logs,conf/certs,html}
cp "$SCRIPT_DIR/smoke.nginx.conf" "$SMOKE_ROOT/conf/nginx.conf"

# Reuse demo certs if present; else make a throwaway self-signed cert.
DEMO_CRT="$REPO_ROOT/openresty/certs/demo.crt"
DEMO_KEY="$REPO_ROOT/openresty/certs/demo.key"
if [[ -f "$DEMO_CRT" && -f "$DEMO_KEY" ]]; then
  cp "$DEMO_CRT" "$DEMO_KEY" "$SMOKE_ROOT/conf/certs/"
else
  need_cmd openssl
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$SMOKE_ROOT/certs/demo.key" \
    -out "$SMOKE_ROOT/certs/demo.crt" \
    -subj "/CN=hah-smoke" 2>/dev/null
fi

log "nginx -t (listen ... ssl https_allow_http)"
"$BIN" -p "$SMOKE_ROOT" -c conf/nginx.conf -t

# Negative check: stock openresty (if present) should still reject the flag.
STOCK="${STOCK_OPENRESTY:-/usr/local/openresty/bin/openresty}"
if [[ -x "$STOCK" && "$STOCK" != "$BIN" ]]; then
  log "stock openresty rejects https_allow_http (expected):"
  if "$STOCK" -p "$SMOKE_ROOT" -c conf/nginx.conf -t 2>&1 | tee /tmp/stock-hah-t.log; then
    log "WARNING: stock openresty unexpectedly accepted https_allow_http"
  else
    log "stock rejection OK"
  fi
fi

cat <<SUMMARY

=== BUILD OK ===
OPENRESTY_PREFIX=$OPENRESTY_PREFIX
binary: $BIN
patch:  $PATCH
logs:   $BUILD_ROOT/{configure,make,install}.log

Verify later:
  export OPENRESTY_PREFIX=$OPENRESTY_PREFIX
  \$OPENRESTY_PREFIX/bin/openresty -V
  \$OPENRESTY_PREFIX/bin/openresty -p $SMOKE_ROOT -c conf/nginx.conf -t
SUMMARY
