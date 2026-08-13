#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
cargo build --release --manifest-path rust/loader/Cargo.toml
exec sudo ./rust/loader/target/release/waf-sklookup-loader "$@"
