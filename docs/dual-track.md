# Dual-track ports

The loader treats network ports as two distinct tracks:

- **Real listens** are nginx/OpenResty `listen` sockets. 80 and 443 stay real bind and never enter the `open_ports` map. Product internal listens 8080 and 8443 are treated as real by default.
- **Virtual listens** are ports steered by `sk_lookup` through the `open_ports` BPF map. Their bindings live in `desired state` (`ports.conf` is this machine's local cache of central/desired state).

`sk_lookup` virtual ports are **not** visible in `ss -lnt`. Use `waf-sklookup-loader list -virtual` or `waf-sklookup-loader status` / `metrics`. Established connections stay pinned; only a new SYN reselects. Enforcement is `fail-closed`.

## Import (explicit)

`import-listen` (alias `import-listens`, `migrate --from-nginx`) scans nginx/OpenResty conf for non-standard `listen` ports and writes them into `ports.conf` using the E6 format:

```
PORT TENANT SITE [tls] [cert=ID] [policy=ID]
```

`-tenant` and `-site` are required (or `TENANT` / `SITE` env) so unbound lines are never written. Import does **not** edit nginx/OpenResty conf and does **not** update the BPF map.

80/443 are never imported. Policy denylist ports and privileged 1–1023 (when `allow_privileged` is empty) are skipped. Default `-skip` is 80,443,8080,8443.

When the machine is frozen, import/migrate that would mutate desired state is rejected and audited.

## Conflict detection

A port cannot be both a real nginx listen and in `open_ports` (or in the desired set that would be applied). `add` / `open` / `apply` / `apply-central` / `reconcile` compute `real listen ∩ candidates` and refuse the **whole** operation before any map write: `fail-closed`. No partial map writes.

## Drop listen (separate explicit step)

`migrate --drop-listen` (alias `retire-conf-listen`) is **dry-run only**. It prints the `listen` lines that would be removed. `--apply` is refused; rewrite the conf yourself, then reload. Import never drops listen directives.

## Metrics

`status` / `metrics` prints JSON (no Prometheus):

```json
{
  "port_count": 4,
  "frozen": false,
  "drift": {"put": 0, "delete": 1},
  "last_apply_central": null,
  "conflict_count": 0
}
```

`list -virtual` prints a table that marks each port `kind=virtual`, `kind=real`, or `kind=conflict`.
