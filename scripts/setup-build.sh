#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if [[ -f "$HOME/.cargo/env" ]]; then
    # Make an existing user-level rustup installation visible in this shell.
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi

if command -v rustup >/dev/null 2>&1; then
    echo "OK/skip: rustup is already installed."
else
    echo "Installing rustup (user-level, noninteractive)..."
    command -v curl >/dev/null 2>&1 || {
        echo "ERROR: curl is required to install rustup from rustup.rs." >&2
        exit 1
    }
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
    echo "OK: rustup installed."
fi

if rustup toolchain list | awk '{print $1}' | grep -Eq '^nightly(-|$)' \
    && rustup component list --toolchain nightly --installed | grep -Eq '^rust-src(-|$)'; then
    echo "OK/skip: nightly toolchain and rust-src are already installed."
else
    rustup toolchain install nightly --profile minimal --component rust-src
    echo "OK: nightly toolchain installed with rust-src."
fi

if rustup toolchain list | awk '{print $1}' | grep -Eq '^1\.85\.0(-|$)'; then
    echo "OK/skip: Rust 1.85.0 toolchain is already installed."
else
    rustup toolchain install 1.85.0 --profile minimal
    echo "OK: Rust 1.85.0 toolchain installed."
fi

missing_c_tools=()
command -v clang >/dev/null 2>&1 || missing_c_tools+=(clang)
command -v llvm-config >/dev/null 2>&1 || missing_c_tools+=(llvm)

if ((${#missing_c_tools[@]} == 0)); then
    echo "OK/skip: clang and llvm are already installed."
else
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "ERROR: missing ${missing_c_tools[*]}; install clang, llvm, libbpf-dev, libelf-dev, and Linux libc headers with this distribution's package manager." >&2
        exit 1
    fi

    apt_prefix=()
    if ((EUID != 0)); then
        command -v sudo >/dev/null 2>&1 || {
            echo "ERROR: sudo is required to install missing distro packages." >&2
            exit 1
        }
        apt_prefix=(sudo)
    fi

    echo "Installing Debian/Ubuntu C BPF build packages (missing: ${missing_c_tools[*]})..."
    "${apt_prefix[@]}" apt-get update
    "${apt_prefix[@]}" apt-get install -y clang llvm libbpf-dev libelf-dev linux-libc-dev
    echo "OK: C BPF build packages installed."
fi

echo "Next step: ./scripts/setup-build.sh && make rust-bpf"
