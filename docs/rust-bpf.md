# Rust BPF twin

`rust/bpf/src/lib.rs` is a Rust source twin of `dispatch.bpf.c`. This is a
**source-language comparison**, not a QPS promise or performance claim. The C
dataplane remains the default.

## Selection

The long-running loader accepts either Go-style flag spelling:

```sh
sudo ./rust/loader/target/release/waf-sklookup-loader -bpf c    # default
sudo ./rust/loader/target/release/waf-sklookup-loader --bpf rust
BPF_IMPL=rust sudo --preserve-env=BPF_IMPL ./rust/loader/target/release/waf-sklookup-loader
```

The flag wins over `BPF_IMPL`; if neither is set, `c` is used. Only `c` and
`rust` are valid. The demo wrapper also passes its `BPF_IMPL` value to the
loader. Selecting Rust never falls back to C: a missing object reports the
`make rust-bpf` build instruction.

## Shared ABI and behavior

Both objects expose a program named `dispatch` in section `sk_lookup` and the
same maps:

| map | type | key | value | max entries |
| --- | --- | --- | --- | ---: |
| `open_ports` | hash | host-order `u16` local port | `u8` sockmap slot | 131072 |
| `redir_socket` | sockmap | `u32` slot | `u64` socket value | 2 |

Both pass non-TCP traffic and ports absent from `open_ports`. A present port is
assigned to `redir_socket[slot]`; an invalid slot, empty socket entry, or assign
error drops the lookup. A successful assign releases the socket reference and
passes. Because the names and layouts match, pinning and the existing ctl,
reconcile, toy, and OpenResty paths are shared unchanged.

## Build

The Rust object needs a nightly compiler with `rust-src`; the BPF target builds
`core` because precompiled `bpfel-unknown-none` target libraries are commonly
not distributed:

```sh
./scripts/setup-build.sh && make rust-bpf
cargo build --release --manifest-path rust/loader/Cargo.toml
```

The setup script installs the pinned Rust 1.85.0 userspace toolchain, nightly
with `rust-src`, and missing Debian/Ubuntu C BPF build packages. It is safe to
run again; the equivalent manual nightly setup is
`rustup toolchain install nightly --profile minimal --component rust-src`.

`make rust-bpf` writes
`rust/bpf/target/bpfel-unknown-none/release/dispatch-rust.o`. The loader embeds
that repository path at userspace build time. Rebuild the loader after moving
the checkout.
