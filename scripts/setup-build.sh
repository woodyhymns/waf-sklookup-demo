#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"
echo 'PATH note: put $HOME/.cargo/bin first so rustup nightly wins over Debian /usr/bin/rustc 1.85.0.'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if command -v rustup >/dev/null 2>&1; then
    echo "OK: rustup already present."
else
    echo "Installing rustup nightly with rust-src (user-level, noninteractive)..."
    command -v curl >/dev/null 2>&1 || {
        echo "ERROR: curl is required to install rustup from rustup.rs." >&2
        exit 1
    }
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain nightly --component rust-src
    echo "OK: rustup nightly and rust-src installed."
fi

if rustup show | grep -Eq '^nightly(-[^[:space:]]+)?([[:space:]]|$)' \
    && rustup component list --toolchain nightly | grep -Eq '^rust-src.*\(installed\)$'; then
    echo "OK/skip: nightly and rust-src already present."
else
    echo "Installing missing nightly toolchain and rust-src..."
    rustup toolchain install nightly --profile minimal --component rust-src
    echo "OK: nightly and rust-src installed."
fi

linker_required=false
while IFS= read -r config_file; do
    if grep -Eq 'linker[[:space:]]*=[[:space:]]*"bpf-linker"' "$config_file"; then
        linker_required=true
        break
    fi
done < <(find rust/bpf -path '*/target' -prune -o \
    \( -name Cargo.toml -o -path '*/.cargo/config' -o -path '*/.cargo/config.toml' \) \
    -type f -print)

if [[ "$linker_required" == false ]]; then
    echo "OK/skip: this tree does not configure bpf-linker; it is optional unless make rust-bpf reports it missing."
elif command -v bpf-linker >/dev/null 2>&1; then
    echo "OK/skip: required bpf-linker already present."
else
    echo "Installing required bpf-linker..."
    cargo install bpf-linker
    echo "OK: bpf-linker installed."
fi

echo "Build setup ready."
