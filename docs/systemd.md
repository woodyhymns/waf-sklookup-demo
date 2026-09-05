# systemd installation

These units are operator examples for a host where the repository is installed at `/opt/waf-sklookup-demo`. Run `scripts/check-install.sh` first. Do not enable these services on a shared demo VM.

Build the release loader, copy the repository to the intended location, and adjust the absolute paths in `deploy/systemd/waf-sklookup.env.example`. Then, on the operator machine only:

```bash
sudo install -d /etc/waf-sklookup /etc/systemd/system/waf-sklookup-openresty.service.d
sudo install -m 0644 deploy/systemd/waf-sklookup-*.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/waf-sklookup.env.example /etc/waf-sklookup/waf-sklookup.env
# Edit /etc/waf-sklookup/waf-sklookup.env before continuing.
sudo systemctl daemon-reload
sudo systemctl enable --now waf-sklookup-loader.service
```

Starting the loader pulls in OpenResty first. OpenResty runs in the foreground with the existing repository config. For HAH/Tengine, either set `OPENRESTY_PREFIX=/usr/local/openresty-hah` and the Tengine `OPENRESTY_CONF` in the environment file, or install `deploy/systemd/waf-sklookup-openresty.service.d/hah.conf.example` as a `.conf` drop-in. Leave `TLS_TARGET` and `TLS_PORTS` empty for its single `https_allow_http` listen. The stock OpenResty fallback sets them to `127.0.0.1:8443` and `18443`.

The loader runs as root by default. A non-root deployment needs `CAP_BPF` and `CAP_NET_ADMIN`; older kernels commonly also require `CAP_PERFMON` and/or `CAP_SYS_ADMIN`. Tighten privileges only after validating the target kernel and systemd version.

The example unit creates `/run/waf-sklookup` with `RuntimeDirectory=` and serves the product control plane at `CTL_SOCK=/run/waf-sklookup/ctl.sock`. The loader creates this Unix socket mode `0660`; configure `-ctl-group GID` when an operator group needs access. It verifies Linux `SO_PEERCRED`, rejects world-accessible modes, and audits every mutation. This is not an HTTP API. The direct pinned-map CLI remains a root operations escape hatch.

The loader uses `Restart=on-failure`, a two-second delay, and a three-failures-in-30-seconds start limit. On every loader failure, `OnFailure` immediately invokes a oneshot that stops OpenResty. A permitted loader restart pulls its required OpenResty unit back in; once the restart budget is exhausted, both remain stopped. This is the fail-closed boundary: the frontend does not remain running with an empty or stale `sk_lookup` attachment.

`PORTS_FILE` defaults to the absolute repository-root `ports.conf`, and `ExecStart` always passes `-ports-file`. The loader reconciles `open_ports` from it at startup. Edit that file and send `SIGHUP` (`systemctl reload waf-sklookup-loader`) to reconcile it without reloading OpenResty; the E1 `reconcile`/`apply` commands continue to work too.

The supplied `[Install]` sections are for deliberate operator installation. Merely keeping these files in the repository does not activate anything.

Last-resort nft DNAT (SDD-005) is **not** wired into these units. Do not set
`WAF_NFT_FALLBACK=1` in the environment file. If both `sk_lookup` links are
gone, an operator may run `scripts/nft-dnat-fallback.sh enable --enable`
by hand; see [nft-dnat-fallback.md](nft-dnat-fallback.md).
