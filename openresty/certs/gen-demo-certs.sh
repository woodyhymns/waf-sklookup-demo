#!/usr/bin/env bash
# Generate a DEMO-ONLY self-signed cert for OpenResty TLS.
# Not a CA, not for production. Safe to regenerate anytime.
set -euo pipefail
cd "$(dirname "$0")"

OUT_CRT="${OUT_CRT:-demo.crt}"
OUT_KEY="${OUT_KEY:-demo.key}"
DAYS="${DAYS:-3650}"
CN="${CN:-waf-sklookup-demo}"

if [[ -f "$OUT_CRT" && -f "$OUT_KEY" && "${FORCE:-}" != "1" ]]; then
  echo "certs already present: $PWD/$OUT_CRT $PWD/$OUT_KEY (FORCE=1 to regenerate)"
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found; cannot generate demo certs" >&2
  exit 1
fi

# OpenSSL 1.1.1+ supports -addext. Fall back for older binaries.
if openssl req -help 2>&1 | grep -q -- '-addext'; then
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -keyout "$OUT_KEY" -out "$OUT_CRT" -days "$DAYS" \
    -subj "/CN=${CN}" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
else
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -keyout "$OUT_KEY" -out "$OUT_CRT" -days "$DAYS" \
    -subj "/CN=${CN}"
fi

chmod 600 "$OUT_KEY"
echo "wrote DEMO-ONLY $PWD/$OUT_CRT and $PWD/$OUT_KEY"
echo "label: self-signed demo identity for waf-sklookup-demo; not a production cert"
