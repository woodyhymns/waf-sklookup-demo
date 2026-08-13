# M2: port control plane (hot add/remove, bulk seed)

The long-running Rust loader pins `open_ports` under `/sys/fs/bpf/waf-sklookup` by default. A second invocation edits that map without reloading OpenResty or re-attaching `sk_lookup`.

```bash
make build
./run-openresty-demo.sh start

LOADER=./rust/loader/target/release/waf-sklookup-loader
sudo "$LOADER" add 18083
sudo "$LOADER" remove 18083
sudo "$LOADER" list
sudo "$LOADER" list -count
sudo "$LOADER" bulk open -range 20000-20010
sudo "$LOADER" bulk close -range 20000-20010
sudo "$LOADER" load-ports -file ports.txt
sudo "$LOADER" close-ports -stdin < ports.txt
```

Aliases are `open`=`add`, `close`=`remove`, `dump`=`list`, `load-ports`=`bulk open`, and `close-ports`=`bulk close`. Range, file, and stdin input accept single ports, comma lists, and `START-END`; blank lines and `#` comments are ignored.

`open_ports` has `max_entries 131072`. The default shared-machine ladder is:

```bash
./scripts/m3-fill-ports.sh 100
./scripts/m3-fill-ports.sh 1000
./scripts/m3-fill-ports.sh 10000
```

The helper closes its fill range on exit. Dedicated-host 30K/60K runs require `M3_FULL_LADDER=1`; do not run them on shared machines. The default fill start is 5000, and internal listens 8080/8443 are skipped.

`LOADER_BIN` remains overridable in the demo and acceptance scripts. See [acceptance-m3-rust.md](acceptance-m3-rust.md) for the current acceptance recipe.
