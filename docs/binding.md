# Single-machine port binding

The userspace loader requires every open port to bind to a tenant and site. The BPF `open_ports` map remains a port-to-slot set; binding, denylist, privileged-port, and quota enforcement happens in Rust before any map write. Optional `cert` and `policy` identifiers are stored and validated but are not currently used by the dataplane.

## Desired state format

`ports.conf` uses one binding per line:

```text
# PORT TENANT SITE [tls] [cert=ID] [policy=ID]
8080 acme www
8443 acme www tls
18443 acme www tls cert=www policy=default
20000-20010 acme api
```

The port token accepts a single port, comma list, or `START-END`; every expanded port inherits the binding and identifiers. `tls` selects the stock TLS-fallback slot. Blank lines and `#` comments are accepted. Identity tokens must be non-empty and contain no whitespace.

Old port-only lines are refused with a pointer to this document. This is fail-closed: no desired-file or map write occurs for an unbound request.

## Policy

By default the loader looks for `policy.conf` beside `ports.conf`. Use `-policy-file PATH` to override it. If the file is absent, these defaults apply:

- Ports 22, 25, 53, 3306, and 6379 are always denied.
- All privileged ports (1–1023) are denied unless present in `allow_privileged`.
- A tenant may open at most 32 ports.
- The machine may open at most 128 ports.

Example:

```text
# deny additional ports; the five default-denied ports remain denied
deny=22,25,53,3306,6379
allow_privileged=80,443
max_ports_per_tenant=32
max_ports_per_machine=128
```

Repeated `deny=` and `allow_privileged=` lines and comma/range values are accepted. Replacing an existing port number changes its binding without increasing the machine count.

## Commands and enforcement

Opening through the root loader CLI or Unix socket requires `-tenant TENANT -site SITE`; `-cert ID` and `-policy ID` are optional. This applies to `add`, `open`, `load-ports`, `bulk open/add`, and `bulk fill`. Long-running `-ports`/`-tls-ports` seeding also requires `-tenant` and `-site` when `ports.conf` is missing. Closing does not require a binding.

The same policy implementation covers desired-file parsing, loader add/open/bulk/fill, Unix socket control, startup, CLI `reconcile`/`apply`, SIGHUP, and startup reconcile. A desired state containing any unbound, denied, privileged-without-allowlist, or over-quota port refuses the whole apply before a plan is applied. It never partially punches holes; this is fail-closed.

## Migration

Before restarting, convert every old `PORT [tls]` line to `PORT TENANT SITE [tls]`, add optional identifiers if used, create `policy.conf` if defaults are insufficient, and run the loader's parse/reconcile path to validate the complete desired state.

`scripts/recover.sh` retains its pre-E6 two-field awk validator and is incompatible with the bound format. After migration, operators must use the loader's parse/reconcile validation instead; the recovery script and `docs/recovery.md` are intentionally unchanged.
