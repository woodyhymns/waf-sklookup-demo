# Real-kernel hardening acceptance — 2026-08-16

## Scope and environment

This acceptance run exercised the C `sk_lookup` program and Rust loader against a real Linux **6.1.102** kernel. The sandbox had root BPF capabilities, a mounted bpffs, a successful `BPF_LINK_CREATE` attachment to the current network namespace, and four independent `SO_REUSEPORT` listener processes. This is not a mock verifier-only result.

The product OpenResty container could not be started in this environment because neither Docker nor Podman was available. The E2E listener therefore uses `tests/e2e/reuseport_http_server.py`: four independent TCP listener processes with the same listener ownership, inode discovery, `pidfd_getfd`, sockmap and connection-steering semantics that the loader uses for OpenResty. The Lua/OpenResty hook itself remains a staging gate.

| Gate | Result | Evidence |
|---|---|---|
| BPF load and netns attach | Pass | C program passed the live verifier and attached as `sk_lookup`; final observed tag `54d365048953e520` |
| IPv4 external destination preservation | Pass | A request to unbound `127.0.0.1:18181` returned `local=127.0.0.1:18181`, while the internal listener was `:18080` |
| IPv6 listener discovery and steering | Pass | Loader found all four tcp6 listener inodes for `[::1]:18090`; request to `[::1]:18184` returned `local=::1:18184` |
| Four-worker distribution | Pass | IPv4 120-SYN samples reached all four workers; IPv6 distribution was `25 / 27 / 32 / 36` |
| Dynamic add/remove without listener reload | Pass | `add 18183 -tenant …` served immediately and preserved port 18183; `remove` made it unreachable; listener worker PIDs did not change |
| Control-plane program identity | Pass | Maps, program and link were pinned; a deliberately altered identity tag caused `ctl list` to fail closed; restoration recovered normal operation |
| Worker death and stale FD handling | Pass with bounded window | Killing 1/4 workers caused pidfd detection, removal of the stale shard, retarget of `open_ports`, then `300/300` successful requests |
| 100-port online add/remove under load | Pass | Four 25-port tenant batches added in **42 ms**, probe on port 18250 succeeded, and one bulk remove took **10 ms** while persistent traffic continued |
| Prometheus telemetry | Pass | `assign_ok`, per-errno counters, `no_slot`, `shard_fallback`, `fault_ratio`, `open_ports_entries`, and `listen_shards` were exposed |

## Worker failure recovery

The first real failure test disclosed an important issue: a loader-held duplicate FD can remain `SO_ACCEPTCONN` after its source worker exits. Checking only the held FD therefore cannot prove worker health. The fix records the worker PID and a pidfd with each captured socket, requires the original process to retain the original socket inode, and excludes loader-owned FDs from recapture.

At the default 2-second legacy interval, there was a short temporary failure window. The loader now accepts `-rescan-interval` (default `500ms`, minimum `100ms`) and a `SIGUSR1` immediate-rescan signal. At an explicit `200ms` interval, killing one worker produced `58/60` short-timeout successes in the immediate window and **300/300** successes after one second; metrics reported `listen_shards=3`, `no_slot=0`, `shard_fallback=0`, `assign_err_esocktnosupport=0`.

> This is a bounded failover mechanism, not zero-loss crash detection. Production should set an empirically justified `200–500ms` interval or invoke `SIGUSR1` from the Nginx/OpenResty worker lifecycle integration.

## Performance method and result

`tests/e2e/bench-sklookup.sh` pins `wrk` to CPU 0 and executes ABBA pairs (`internal → steered → steered → internal`) rather than relying on an order-sensitive single A/B run. The final sample used 4 workers, 2 `wrk` threads, 24 connections, 3 seconds per run, and 5 pairs. Keep-alive samples measure request-path latency; `Connection: close` samples measure a new SYN on every request and expose the dispatch cost.

| Metric | Internal listener | sk_lookup steered port | Result |
|---|---:|---:|---|
| Keep-alive median RPS (10 samples) | 90,859.88 | 85,764.86 | 0.9439x; below a proposed 0.95 RPS gate, so not a clean throughput pass |
| Keep-alive median p99 | 61 µs | 59 µs | -2 µs |
| New-connection RPS | 22,560.78 | 22,518.07 | 0.9981x |
| New-connection p99 | 12.96 ms | 12.92 ms | -40 µs |
| BPF runtime, close-connection sample | — | 1,828.93 ns/SYN | 68,828 actual BPF invocations |
| BPF runtime, keep-alive connection samples | — | median 2,030.15 ns/SYN | kernel `run_time_ns / run_cnt` |

The virtual machine exposes `cycles` and `instructions` as `<not supported>` even under root and a versioned `perf` executable. It would be misleading to report task-clock as hardware cycles. Therefore there is **no cycles/request result** in this acceptance. Re-run the supplied script on the production kernel class, with PMU access, for at least 30 seconds and five pairs before claiming that CPU performance gate.

## Required staging gates before rollout

1. Run against the actual OpenResty/Tengine package and its exact multi-worker/reload process model; verify `$waf_external_port` Lua behavior under HTTP and TLS.
2. Rerun `tests/e2e/bench-sklookup.sh` on target hardware/VM with `cycles,instructions` enabled; retain raw artifacts and apply an agreed RPS/p99/cycles-per-SYN budget.
3. Measure `/proc` capture/rescan CPU cost at production worker count and choose `RESCAN_INTERVAL`; wire `SIGUSR1` into the actual worker lifecycle if available.
4. Validate systemd capabilities, bpffs mount ordering, sidecar directory permissions, process restart behavior, exporter scrape policy, and alert thresholds in a non-production WAF staging cluster.
5. Canary with explicit dashboards for `assign_err_*`, `no_slot`, `shard_fallback`, `fault_ratio`, `listen_shards`, map occupancy, reconcile failures and control-plane audit events.
