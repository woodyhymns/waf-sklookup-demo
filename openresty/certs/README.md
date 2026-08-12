# Demo TLS certificates (NOT for production)

Self-signed material for the stock OpenResty 1.19.3.2 HTTPS fallback listen
(`127.0.0.1:8443 ssl`) and for a Tengine `https_allow_http` listen.

**Do not use these identities anywhere except this demo.** Private keys are
gitignored. Generate locally:

```bash
make certs
# or: ./openresty/certs/gen-demo-certs.sh
```

Writes `demo.crt` + `demo.key` in this directory. `run-openresty-demo.sh start`
runs the same script if the files are missing.

curl against the demo cert:

```bash
curl -sk https://127.0.0.1:8443/          # internal TLS listen (stock fallback)
curl -sk https://127.0.0.1:18443/         # steered TLS port (stock fallback)
```
