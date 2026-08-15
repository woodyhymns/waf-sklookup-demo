# Dual-track ports

The loader treats network ports as two distinct tracks:

- **Real listens** are nginx `listen` sockets. The product's inner ports 80, 443, 8080, and 8443 are always considered real, along with ports read from the nginx configuration.
- **Virtual listens** are ports steered by `sk_lookup` through the `open_ports` BPF map. Their bindings live in desired state (`ports.conf`).

Virtual ports are intentionally invisible to `ss -lnt`. Operators should use `waf-sklookup-loader status` or `waf-sklookup-loader list -kind virtual` to inspect them.

`import-listens -tenant T -site S` reads nginx configuration and imports eligible non-standard listen ports into the existing desired-state format. It never writes nginx and does not update the BPF map. Ports 80, 443, 8080, and 8443 are never imported. Policy validation, including the denylist and privileged-port rules, remains fail-closed. `--dry-run` reports imports and skips without writing desired state or the optional version 1 central cache.

`check-overlap` is a fail-closed safety gate. If a real listen intersects desired state, the current `open_ports` map, or ports being added, the whole mutation is refused before either the desired-state file or map is changed. `add`, `apply-central`, and `reconcile` use this gate.

`retire-conf-listen PORT` only prints matching nginx `listen` lines and reminds the operator to edit nginx manually and reload. It never edits or reloads nginx.

`status` reports real and virtual ports, overlap, freeze state, desired/map agreement, and small userspace metrics. This adds neither a desired-state schema version nor a BPF map.
