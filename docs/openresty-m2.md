# M2: port control plane (hot add/remove, bulk seed)

The long-running Rust loader pins `open_ports` under `/sys/fs/bpf/waf-sklookup` by default. The repository-root `ports.conf` is the desired state: plain ports use the primary slot and an optional trailing `tls` selects the stock TLS-fallback slot. Comma lists, `START-END`, blank lines, and `#` comments are supported. Use `-ports-file PATH` to select another file.

Startup reconciles the map exactly to the file. If it does not exist, the backward-compatible `-ports` and `-tls-ports` flags seed it. A second invocation can edit the pinned map without reloading OpenResty or re-attaching `sk_lookup`; every add/remove/bulk mutation also atomically rewrites the desired file so a later reconcile cannot undo it. Pass `-no-file` to mutate the live map only (used by stop/hygiene and M3 fill helpers so they cannot empty `ports.conf`).

```bash
make build
./run-openresty-demo.sh start

LOADER=./rust/loader/target/release/waf-sklookup-loader
sudo "$LOADER" add 18083
sudo "$LOADER" remove 18083
sudo "$LOADER" list
sudo "$LOADER" list -count
sudo "$LOADER" reconcile                 # alias: apply
sudo "$LOADER" bulk open -range 20000-20010
sudo "$LOADER" bulk close -range 20000-20010
sudo "$LOADER" load-ports -file ports.txt
sudo "$LOADER" close-ports -stdin < ports.txt
```

After editing `ports.conf`, run `sudo "$LOADER" reconcile` or send `SIGHUP` to the long-running loader. SIGHUP re-reads and reconciles in place; SIGINT and SIGTERM still shut it down. Reconcile adds missing ports, corrects wrong slots, and deletes map entries absent from the file.

Aliases are `open`=`add`, `close`=`remove`, `dump`=`list`, `load-ports`=`bulk open`, and `close-ports`=`bulk close`. Range, file, and stdin input accept single ports, comma lists, and `START-END`; blank lines and `#` comments are ignored.

`open_ports` has `max_entries 131072`. The default shared-machine ladder is:

```bash
./scripts/m3-fill-ports.sh 100
./scripts/m3-fill-ports.sh 1000
./scripts/m3-fill-ports.sh 10000
```

The helper closes its fill range on exit. Dedicated-host 30K/60K runs require `M3_FULL_LADDER=1`; do not run them on shared machines. The default fill start is 5000, and internal listens 8080/8443 are skipped.

`LOADER_BIN` remains overridable in the demo and acceptance scripts. See [acceptance-m3-rust.md](acceptance-m3-rust.md) for the current acceptance recipe.
