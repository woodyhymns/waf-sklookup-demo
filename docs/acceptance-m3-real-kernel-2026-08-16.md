# M3 real-kernel capacity acceptance — 2026-08-16

## Verdict

The C `sk_lookup` dataplane completed real-kernel capacity tests at **30,000** and **60,000** dynamic ports. Both fills completed successfully, the expected map count was observed, sampled unbound external ports were steered to a four-worker `SO_REUSEPORT` internal listener, the Prometheus endpoint remained reachable, classified assignment errors remained zero, and each run was closed and restored before the next stage.

The result is a **functional map-capacity pass**, not a full production capacity sign-off. The test deliberately measures live map population, lookup steering, worker sharding, management-plane reservation, and cleanup. It does **not** establish target-hardware memory cost, sustained QPS, CPU cycles/request, or an OpenResty/Tengine runtime SLA.

| Gate | 30K | 60K | Result |
|---|---:|---:|---|
| Live map count | 30,000 | 60,000 | Pass |
| Fill wall time | 44 ms | 66 ms | Pass; informational, not an SLA |
| Sampled external HTTP ports | 6 / 6 | 9 / 9 | Pass |
| `listen_shards` | 4 | 4 | Pass |
| `no_slot` | 0 | 0 | Pass |
| Classified `bpf_sk_assign` errors | 0 | 0 | Pass |
| Prometheus management endpoint reserved | Yes | Yes | Pass |
| Post-fill `close-all` count | 0 | 0 | Pass |
| Base steered port restored | Yes | Yes | Pass |

At 60,000 entries the real `open_ports` map reported `max_entries=131072`, `key_size=20`, and `value_size=4`. This is **45.7763%** occupancy, leaving **71,072** nominal map slots (**54.2236%**). The nominal headroom must not be interpreted as a production capacity reservation without target-kernel memory accounting and workload tests.

## Test environment and isolation model

The test ran on Linux kernel `6.1.102` inside a dedicated root-created **network namespace and mount namespace**. A private bpffs mount was created inside that namespace, and the loader attached `sk_lookup` to that namespace only. This isolation was required because wildcard `Dest::AnyV4` map keys legitimately match every IPv4 destination on their included ports; a prior, non-isolated exploratory fill captured a sandbox management connection and demonstrated that a broad port range must not overlap management listeners.

| Component | Test value |
|---|---|
| Internal listener | `127.0.0.1:18080` |
| Worker model | 4 independent `SO_REUSEPORT` workers |
| Primary externally steered port | `127.0.0.1:18181` |
| Management endpoint | `127.0.0.1:19104/metrics` |
| BPF implementation | C `dispatch.bpf.c` through the Rust loader |
| Pinned map | `/sys/fs/bpf/waf-m3ns/open_ports` inside private bpffs |
| Map type / layout | `BPF_MAP_TYPE_HASH` (type `1`), 20-byte key, 4-byte value, 131,072 entries |
| Temporary test policy | Per-tenant/per-machine limit 70,000; production denied ports retained |

The fill generator reserved the denied ports and all internal/management listeners:

```text
22,25,53,3306,6379,8080,8443,19104
```

> **Production requirement:** large wildcard dynamic-port fills must reserve every metrics, control, SSH, orchestration, health-check, debug, and host-agent listener in the same network namespace. Prefer a distinct management address, interface, or namespace, and use exact ingress-VIP keys where the deployment can provide them.

## Procedure

The loader was started first, one base virtual port was opened, then the test checked the map, one real steered response, the metrics endpoint, and the four-listener registration. Each capacity stage used `bulk fill` with `-no-file` and `-full-ladder`, then performed map-count, metrics, sampled-steering, management-endpoint, `close-all`, and base-port restore checks.

```bash
sudo ./rust/loader/target/release/waf-sklookup-loader bulk fill \
  -count 60000 -start 5000 \
  -skip 22,25,53,3306,6379,8080,8443,19104 \
  -tenant m3 -site netns-capacity \
  -pin-dir /sys/fs/bpf/waf-m3ns \
  -ports-file /tmp/waf-m3ns/ports.conf \
  -policy-file /tmp/waf-m3ns/policy.conf \
  -no-file -full-ladder
```

The checked 30K sample ports were `5000`, `10000`, `18181`, `20000`, `30000`, and `35003`. The 60K run repeated those and added `50000`, `60000`, and `65003`. Every response included `local=127.0.0.1:<requested-external-port>`, proving that the external destination remained observable after steering rather than falling back to the internal port.

## Observed dataplane metrics

| Metric | 30K | 60K | Interpretation |
|---|---:|---:|---|
| `waf_sklookup_open_ports_entries` | 30,000 | 60,000 | Exact live map entry count |
| `waf_sklookup_listen_shards` | 4 | 4 | All four internal listener shards remained registered |
| `waf_sklookup_no_slot_total` | 0 | 0 | No BPF selection of an empty shard slot |
| `waf_sklookup_assign_err_eafnosupport_total` | 0 | 0 | No address-family mismatch |
| `waf_sklookup_assign_err_eexist_total` | 0 | 0 | No duplicate-assignment conflict |
| `waf_sklookup_assign_err_eprototype_total` | 0 | 0 | No protocol-type mismatch |
| `waf_sklookup_assign_err_esocktnosupport_total` | 0 | 0 | No invalid target socket assignment |
| `waf_sklookup_assign_err_other_total` | 0 | 0 | No unclassified assignment error |
| `waf_sklookup_fault_ratio` | 0 | 0 | No recorded dataplane fault during the measured snapshots |

## Cleanup and recovery

After each fill, `close-all` returned a map count of `0`. The test then added back port `18181` through the pinned-map control path and confirmed an HTTP response whose local address was `127.0.0.1:18181`. The harness finally terminated the loader and workers, removed the private pin directory, and unmounted the private bpffs. The host namespace and its management connections were not part of the dynamic-port map.

## Reproducibility and evidence

The raw text evidence is committed under [`artifacts/m3-real-kernel-2026-08-16/`](../artifacts/m3-real-kernel-2026-08-16/), including environment, map-layout, fill stdout/stderr, counts, metrics snapshots, every sampled response, close/restore outputs, loader log, and a result summary. The M3 helper [`scripts/m3-fill-ports.sh`](../scripts/m3-fill-ports.sh) has also been hardened to refuse fills above 10,000 ports unless the caller explicitly supplies `M3_MGMT_PORTS` and `M3_FULL_LADDER=1`.

## Remaining production gates

1. Repeat the same isolated 30K/60K workflow on the production kernel and instance family while collecting a target-kernel map memory measurement via kernel-matched `bpftool` or audited `BPF_OBJ_GET_INFO_BY_FD` tooling.
2. Run sustained traffic and mutation concurrency tests at the intended connection count, including p99, errors, CPU cycles/request, BPF runtime per SYN, and control-plane latency budgets.
3. Validate the real OpenResty/Tengine process model, Lua external-port extraction, TLS behavior, worker reload/respawn, and systemd restart sequence.
4. Enforce a deployment-level management-port reservation policy; application code alone cannot infer every host-agent or orchestration listener in an arbitrary namespace.
