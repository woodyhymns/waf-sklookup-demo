# Rust loader M3 acceptance recipe

**Status:** the Rust userspace loader is the default. The kernel `sk_lookup` hot path remains `dispatch.bpf.c`.

Build and start:

```bash
make build
./run-openresty-demo.sh start
./run-openresty-demo.sh verify
```

Run the shared-machine ladder one tier at a time; each helper invocation cleans up its fill range:

```bash
./scripts/m3-fill-ports.sh 100
./scripts/m3-fill-ports.sh 1000
./scripts/m3-fill-ports.sh 10000
```

The 30K/60K tiers are dedicated-host tests and require explicit opt-in:

```bash
M3_FULL_LADDER=1 ./scripts/m3-fill-ports.sh 30000
M3_FULL_LADDER=1 ./scripts/m3-fill-ports.sh 60000
```

Do not run those tiers on a shared machine. Confirm `open_ports` has `max_entries 131072`, record loader/OpenResty RSS separately, and verify a filled external port reaches OpenResty. `LOADER_BIN` may override the default `./rust/loader/target/release/waf-sklookup-loader`.

Historical Go/Rust comparison results in acceptance logs and `*-last.md` files are preserved as records of those past runs.
