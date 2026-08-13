# Rust userspace loader

**Status:** Rust is the default and only userspace loader. The hot path remains the C BPF program in `dispatch.bpf.c`; the OpenResty and Lua layers are unchanged.

The loader lives in `rust/loader` and builds as:

```bash
cargo build --release --manifest-path rust/loader/Cargo.toml
```

Its default path is `./rust/loader/target/release/waf-sklookup-loader`. `make`, `make build`, `./run.sh`, `run-openresty-demo.sh`, and the acceptance helpers all use that binary. `LOADER_BIN` remains available when a caller needs an explicit executable path.

The crate compiles the repository-root `dispatch.bpf.c` through `libbpf-cargo`. It supports toy and OpenResty long-running modes, pinned-map `add`/`remove`/`list`, and bulk range/file/stdin/fill operations. The CLI retains Go-style single-dash flags for script compatibility.

Build requirements are rustc 1.85+, Cargo, clang, libbpf/libelf development files, and Linux headers. Go is not part of the loader build; it is only used for the standalone `tools/httpbench` helper.

The default shared-machine fill ladder is 100 → 1K → 10K. Counts above 10K require `M3_FULL_LADDER=1`. Historical Go/Rust comparison results remain in the archived acceptance logs and `*-last.md` files; they describe past runs and are not current build instructions.

This change is a userspace implementation switch, not a QPS/P99 claim: both implementations used the same kernel dataplane.
