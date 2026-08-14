# E5 recovery runbook

Recovery never migrates established connections: an accepted connection stays
pinned to its fd/worker, and only a new SYN is reselected. A connection owned by
a dead worker dies normally. Steering fails closed: an empty or stale sockmap
slot makes a new external steered SYN fail with `SK_DROP`, while the inner bind
(`127.0.0.1:8080`) remains directly reachable.

`redir_socket` has two protocol slots, not worker shards: slot 0 is HTTP and
slot 1 is the stock-demo TLS fallback. With `SO_REUSEPORT`, `bpf_sk_assign`
sends each new SYN to the one worker listen currently installed in its protocol
slot. After replacement, discovery walks `/proc/net/tcp` LISTEN rows and chooses
the first inode still reachable through `/proc/*/fd`, skipping vanished
reuseport inodes. `register_listen_fd` swaps the slot, replaces the held fd, and
drops the stale duplicate. There is no listen sharding.

The loader rescans about every two seconds and on `SIGUSR1`. The root hatch is:

```bash
sudo waf-sklookup-loader rescan-listen -pin-dir /sys/fs/bpf/waf-sklookup \
  -target 127.0.0.1:8080 -tls-target 127.0.0.1:8443
```

It changes only listen slots: no `open_ports`, detach, or loader restart.

## Worker respawn

A respawn is visible when the OpenResty master PID is unchanged but the worker
PID set differs from the snapshot under
`${STATE_DIR:-${TMPDIR:-/tmp}/waf-sklookup-m1}`. It can also be visible as an
empty pinned `redir_socket` protocol slot (`bpftool map lookup`; report the
slot as unknown when unprivileged), or as a changed `/proc/net/tcp` LISTEN
inode set for `TARGET`/`TLS_TARGET` while the master PID remains unchanged.

Recover with one rescan-only command:

```bash
sudo -E scripts/recover.sh worker
```

For a read-only view, use `scripts/recover.sh detect-worker` or
`RECOVERY_DRY_RUN=1 scripts/recover.sh`. It prints the master, workers, listen
inodes, and protocol-slot presence; reports not running or unknown where
appropriate; requires no sudo; and does not start, stop, or kill anything.

Confirm that the listen fd was replaced, an external probe answers, and the
inner listen still works. An empty selected slot makes new steered SYNs
`SK_DROP` until it is refilled. This path does **not** restart the loader,
master, or OpenResty; detach BPF; reconcile as a side effect; or touch
`open_ports`. It does not migrate established connections on other workers.
Sessions on the dead worker drop, as with nginx.

With no argument, a detected respawn takes this same rescan-only path and exits
without reconcile or loader restart when the listener, loader, pins, and
control socket otherwise look healthy. The underlying operation is
`waf-sklookup-loader rescan-listen`; if the master/listener is actually down,
use the frontend-only `run-openresty-demo.sh start-openresty-only` path instead.

## 1. Loader kill, OOM, or abnormal exit

- See: loader PID/unit is absent or failed; new external SYNs fail while the
  inner listen still answers.
- Recover: `sudo -E scripts/recover.sh loader`.
- Confirm: loader and `ctl.sock` exist, pins are present, file/map agree, and
  the helper's small probes pass. Do not migrate established connections.

## 2. Two loaders racing for pins

- See: the second loader exits saying another loader owns the pin-directory lock.
- Recover: `sudo -E scripts/recover.sh pin-race` (it keeps the existing owner).
- Confirm: exactly one loader is alive. The exclusive nonblocking flock is held
  for the attach owner's lifetime; ctl/rescan/reconcile one-shots do not take
  it. Do not migrate established connections.

## 3. OpenResty master fully dead

- See: master and inner LISTEN are absent.
- Recover: `sudo -E scripts/recover.sh master` (`openresty` is an alias).
- Confirm: `start-openresty-only` restored the frontend, listen slots were
  rescanned, and reconcile ran only on mismatch. Existing pins are retained; if
  missing, the full loader path runs. Do not migrate established connections.

## 4. One worker dies and the master respawns it

- See: follow the PID, listen-inode, and protocol-slot checks in
  [Worker respawn](#worker-respawn).
- Recover: `sudo -E scripts/recover.sh worker`.
- Confirm: follow the rescan-only checks in [Worker respawn](#worker-respawn).
  Do not migrate established connections.

## 5. Worker crash loop / respawn storm

- See: three worker rescans within 30 seconds are recorded in
  `${STATE_DIR}/worker-rescans` (default `${TMPDIR:-/tmp}/waf-sklookup-m1`).
- Recover: `sudo -E scripts/recover.sh worker-storm`.
- Confirm: the sockmap slots are empty and new external SYNs fail closed; the
  inner bind remains direct. Human intervention must fix the crash. The helper
  does not restart loader or OpenResty. Do not migrate established connections.

## 6. BPF unloaded, pins wiped, or bpffs unmounted

- See: `/sys/fs/bpf` is not a mountpoint or either pinned map is missing.
- Recover: `sudo -E scripts/recover.sh pin` (`bpffs` is an alias).
- Confirm: bpffs is mounted, both maps are pinned, attachment is live, and file
  state is reconciled. The helper never intentionally leaves an empty
  attachment. Do not migrate established connections.

## 7. Sockmap slot empty

- See: `bpftool map dump pinned .../redir_socket` has no required slot; new
  external SYNs fail (`SK_DROP`) while the inner bind answers.
- Recover: `sudo -E scripts/recover.sh sockmap`.
- Confirm: rescan reports live fd(s) and a new external probe answers. Do not
  migrate established connections.

## 8. `ctl.sock` missing, wrong permissions, or a non-socket leftover

- See: `test -S "$CTL_SOCK"` fails or access is wrong.
- Recover: `sudo -E scripts/recover.sh ctl`.
- Confirm: the running loader recreates a mode-controlled Unix socket in place.
  A non-socket is unlinked first; maps are not unloaded. If loader is dead, the
  loader path is used. Do not migrate established connections.

## 9. `ports.conf` missing/corrupt or map differs from file

- See: parsing fails, or loader `list` differs from the desired file.
- Recover: `sudo -E scripts/recover.sh state` (`reconcile` is an alias).
- Confirm: a bad/missing/overlarge file causes refusal with no map mutation; a
  valid mismatch uses reconcile only, with no reattach or OpenResty reload. The
  file is source of truth. Do not migrate established connections.

## 10. Boot order: loader first, OpenResty not listening

- See: loader waits up to `-wait` (default 60s) and exits without registering
  empty slots.
- Recover: `sudo -E scripts/recover.sh boot-wait` (starts frontend first).
- Confirm: the inner LISTEN precedes loader readiness and external probes pass.
  Do not migrate established connections.

## 11. Boot order: loader down, OpenResty up

- See: inner listen answers and external steered SYNs fail.
- Recover: `sudo -E scripts/recover.sh boot-loader`.
- Confirm: only the loader was started and external probes pass. Do not migrate
  established connections.

## 12. systemd StartLimit hit

- See: the loaded unit's read-only `systemctl show ... -p Result` reports
  `start-limit-hit` (or `is-failed` reports the equivalent).
- Recover: `sudo -E scripts/recover.sh start-limit` reports human intervention;
  clear the root cause and follow site policy manually.
- Confirm: services stay down. The helper never enables, starts, or
  `reset-failed`s a unit. Do not migrate established connections.

## 13. Host reboot

- See: old connections and volatile attachment are gone; services may be down.
- Recover: `sudo -E scripts/recover.sh reboot`.
- Confirm: bpffs, frontend, loader, pins, desired map, socket, and small probes
  are healthy. Old connections are already gone; do not migrate established
  connections.

## 14. Recovery failed halfway

- See: a prior helper invocation exited after only some checks/actions.
- Recover: rerun the same command, for example `sudo -E scripts/recover.sh pin`.
- Confirm: it reports already-correct state and completes probes. Actions check
  current state first and do not stop a healthy dataplane. Do not migrate
  established connections.

## Helper reference

No argument auto-detects and prints the smallest selected case. Hints are
`loader`, `pin-race`, `master`/`openresty`, `worker`, `worker-storm`,
`pin`/`bpffs`, `sockmap`, `ctl`, `state`/`reconcile`, `boot-wait`,
`boot-loader`, `start-limit`, `reboot`, and the read-only `detect-worker`.
Unsafe hints still refuse: worker requires pins and a live master/listen, and
state requires a valid file. Probes cover at most three ports;
`--count > 10000` is refused unless `M3_FULL_LADDER=1`, and recovery never calls
bulk fill or `m3-fill-ports`.

Environment: `PIN_DIR`, `TARGET`, `TLS_TARGET` (empty disables TLS),
`LOADER_BIN`, `PORTS_FILE`, `CTL_SOCK`, `OPENRESTY_PREFIX`, `WAIT`, and
`STATE_DIR` (default `${TMPDIR:-/tmp}/waf-sklookup-m1`). The binary is built only
when missing. `run-openresty-demo.sh start-openresty-only` starts the frontend
without touching loader/maps.

Recommended unit policy is `Restart=on-failure`, `StartLimitBurst=3`, and an
`OnFailure` unit that stops OpenResty so failure stays closed. StartLimit means
human intervention. Do **not** enable or start these units on the shared demo
VM; examples are in [systemd.md](systemd.md).
