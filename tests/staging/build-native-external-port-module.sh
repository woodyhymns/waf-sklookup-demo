#!/usr/bin/env bash
# Build the source-coupled native external-port variable module.
#
# Usage:
#   ./tests/staging/build-native-external-port-module.sh /path/to/exact/nginx-source \
#       [the exact production ./configure flags ...]
#
# The source directory MUST correspond to the deployed OpenResty/Tengine build.
# Copy flags from `nginx -V`; do not install a .so built for another Nginx core.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
MODULE_DIR="$ROOT/openresty/modules"
SOURCE=${1:?usage: $0 /path/to/exact/nginx-source [configure flags...]}
shift

[[ -x "$SOURCE/configure" ]] || {
    echo "missing executable configure under exact Nginx source: $SOURCE" >&2
    exit 2
}
[[ -f "$MODULE_DIR/ngx_http_waf_external_port_module.c" ]] || {
    echo "missing module source: $MODULE_DIR" >&2
    exit 2
}

# Do not use an existing objs directory: it may retain configure state from an
# incompatible build. This script changes only the supplied source worktree.
rm -rf "$SOURCE/objs"
(
    cd "$SOURCE"
    ./configure --with-compat --add-dynamic-module="$MODULE_DIR" "$@"
    make -f objs/Makefile modules
)

MODULE_SO="$SOURCE/objs/ngx_http_waf_external_port_module.so"
[[ -s "$MODULE_SO" ]] || {
    echo "expected dynamic module was not produced: $MODULE_SO" >&2
    exit 1
}
sha256sum "$MODULE_SO"
printf 'PASS: native module built: %s\n' "$MODULE_SO"
