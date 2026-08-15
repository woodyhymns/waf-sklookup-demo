# Single-machine control-plane contract

This contract is deliberately local: it does not provide a public HTTP control plane, remote agents, or multi-machine fan-out.

## Central desired state and cache

The central JSON file is the source of `desired state`. `ports.conf` is only this machine's local cache, materialized after validation. The example source is `central/desired-state.example.json`; production operators can place the active source at `central/desired-state.json` and run:

```sh
sudo ./waf-sklookup-loader apply-central -from central/desired-state.json
```

The top-level object has `version` (currently `1`) and a `ports` array. Every entry requires `tenant`, `site`, and `port`. Optional `cert` and `policy` strings match the existing binding contract. Optional `tls: true` selects the stock TLS-fallback slot; omission or `false` selects the primary slot.

`apply-central` parses the complete JSON and applies the existing binding, deny, privileged-port, and quota policy before replacing `ports.conf`. Invalid, unbound, denied, conflicting, or over-quota input refuses the whole apply without changing the cache or map: this is `fail-closed`. After a successful cache write, the existing reconcile plan updates the pinned `open_ports` map used by `sk_lookup`. `apply --from-central FILE` is an alias.

## Freeze and emergency close

`freeze` persists the gate at `/run/waf-sklookup/frozen` (override with `-freeze-file PATH`). Opening mutations, bulk mutations, and `apply-central` are rejected while it exists. `unfreeze` only removes the gate; it does not reopen ports. Run apply/reconcile explicitly when ready.

`close-all` immediately deletes every current `open_ports` key without changing `ports.conf`; it is allowed while frozen and does not itself freeze the machine. `freeze --close-all` writes the freeze file first and then performs the same emergency close. This makes new SYNs drop; it does not migrate established connections.

## Gray / canary

Gray or canary rollout means running apply on this host and observing it before applying independently on another host. This single-machine contract records no cluster state and makes no claim that any other machine applied.
