# Dual-track dry-run runbook (issue #30)

This runbook describes the **machine-side dry-run workflow** for importing non-standard nginx listens into desired state (`ports.conf`) without touching live nginx or the BPF map. It was written and verified against a **product-shaped fixture**, not executed on a live product box.

## Preconditions

- `waf-sklookup-loader` built (`cargo build --release --manifest-path rust/loader/Cargo.toml`).
- Product-shaped nginx layout with `include` directives (e.g. `conf.d/*.conf`, `sites-enabled/*`). The loader resolves relative includes against the including file's directory and expands globs.
- Reserved real listens stay on nginx: **80, 443, 8080, 8443** (default skip). They must never enter `ports.conf` or `open_ports`.
- Empty or minimal `policy.conf` is fine for dry-run:

```
allow_privileged=
max_ports_per_tenant=32
max_ports_per_machine=128
```

## Step 1 — import dry-run

Scan nginx (including expanded `include` files) and print importable ports without writing `ports.conf`:

```bash
sudo ./rust/loader/target/release/waf-sklookup-loader import-listens --dry-run \
  -tenant TENANT -site SITE \
  -nginx-conf /path/to/nginx.conf \
  -ports-file /path/to/ports.conf \
  -policy-file /path/to/policy.conf
```

Expected: non-standard listens from included conf (e.g. 18081, 18082, 19001, 19002) listed under `import=`; reserved 80/443/8080/8443 under `skipped=`. **`ports.conf` must not be created or modified.**

## Step 2 — check overlap

With desired empty (or after a deliberate reset), confirm no virtual/real overlap:

```bash
sudo ./rust/loader/target/release/waf-sklookup-loader check-overlap \
  -nginx-conf /path/to/nginx.conf \
  -ports-file /path/to/ports.conf \
  -policy-file /path/to/policy.conf
```

Expected: `overlap: none` when `ports.conf` has no bindings that intersect real nginx listens.

## Step 3 — operator edits nginx (manual)

Remove or retire real `listen` lines for ports that will become virtual **yourself**. Do not use loader conf rewrite:

- `migrate --drop-listen` and `retire-conf-listen` are **dry-run only**.
- `--apply` on those commands is **hard rejected**.

Reload nginx only after you have edited conf on the product host.

## Step 4 — import desired (optional, still no nginx/BPF mutation)

When ready to persist desired state only (still does not edit nginx or the pinned map by itself):

```bash
sudo ./rust/loader/target/release/waf-sklookup-loader import-listens \
  -tenant TENANT -site SITE \
  -nginx-conf /path/to/nginx.conf \
  -ports-file /path/to/ports.conf \
  -policy-file /path/to/policy.conf
```

Then reconcile/apply through your normal control plane when appropriate. Overlap checks remain fail-closed.

## Step 5 — verify virtual-only view

After nginx no longer listens on migrated ports:

```bash
sudo ./rust/loader/target/release/waf-sklookup-loader list -virtual \
  -nginx-conf /path/to/nginx.conf \
  -ports-file /path/to/ports.conf
```

Expected: imported ports show `kind=virtual`; reserved 80/443/8080/8443 remain `kind=real`.

```bash
sudo ./rust/loader/target/release/waf-sklookup-loader status \
  -nginx-conf /path/to/nginx.conf \
  -ports-file /path/to/ports.conf
```

JSON should show `overlap_count: 0` and virtual ports absent from `real`.

## Fixture used for verification (not live product)

Repository fixture: `tests/fixtures/issue-30-product-nginx/` (main `nginx.conf` + `conf.d/` + `sites-enabled/`). Manual dry-run fixture may also exist at `/tmp/waf-issue30-fixture` on dev machines.

## Explicit non-goals on product

- Do **not** start 30K listeners, reload nginx from this workflow, or write the live `open_ports` BPF map as part of dry-run.
- Do **not** use `migrate --drop-listen --apply` or `retire-conf-listen --apply` — both are refused.
