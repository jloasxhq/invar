# Deployment

The backend is **HTTPS-only** and **zero-trust by default** (privileged endpoints
require an ML-DSA-65 capability token). This guide covers build variants, config, and
two operational caveats that bite in real deployments.

## Build variants

| Build | TLS provider | Key exchange | Notes |
|---|---|---|---|
| default (`cargo build`) | rustls + **ring** | classical (X25519) | no cmake; portable |
| `--features pqc-tls` | rustls + **aws-lc-rs** | **hybrid `X25519MLKEM768`** (ML-KEM) | needs cmake + C toolchain + Go + perl |
| `--features fips` | rustls + **AWS-LC-FIPS** | classical (CMVP module) | needs the same toolchain |

The container builds the PQC variant by default (`CARGO_FEATURES=pqc-tls` in
`docker-compose.yml`); set it to `""` for the classical ring build, or `fips` for the
CMVP-validated module.

## Configuration (environment)

See [`.env.example`](../.env.example). Key variables:

- `INVAR_BIND` (default `0.0.0.0:8443`) — TLS listen address.
- `INVAR_REQUIRE_CAPS` (default `true`) — zero-trust; set `false` only for dev.
- `INVAR_TLS_CERT` / `INVAR_TLS_KEY` — PEM paths. **Required.** If unset, the
  container entrypoint and `scripts/run.sh` auto-generate a **self-signed** pair.
  **Provide real certificates in production** (mount them, e.g. `./certs:/etc/invar/tls:ro`).
- `INVAR_ADMIN`, `INVAR_TOKEN_NAME/SYMBOL/DECIMALS` — identity/token config.

## Run

```bash
docker compose up --build          # builds pqc-tls image, serves on :8443
# or classical:
docker build --build-arg CARGO_FEATURES="" -t invar:0.1.0 .
```

Verify the hybrid PQC group is negotiated:

```bash
echo | openssl s_client -connect HOST:8443 -groups X25519MLKEM768 2>/dev/null | grep "group:"
# => Negotiated TLS1.3 group: X25519MLKEM768
```

## Using the API (zero-trust)

Privileged endpoints require a capability token. Obtain one, then send it as a header:

```bash
TOKEN=$(curl -sk -X POST https://HOST:8443/auth/token \
  -H 'content-type: application/json' \
  -d '{"subject":"issuer","scopes":["*"],"ttl_secs":300}' | jq -r .token)

curl -sk -X POST https://HOST:8443/mint -H "x-invar-capability: $TOKEN" \
  -H 'content-type: application/json' -d '{"to":"acme","amount":100}'
```

The Go CLI: `invar-cli -url https://HOST:8443 -insecure token` (drop `-insecure`
with real certs).

> `/auth/token` is a **dev issuance stub**. In production the token issuer is an
> external IdP (holding the pinned ML-DSA-65 issuer key); the backend only verifies.

---

## ⚠️ Caveat 1 — PQC key exchange requires a modern client

`X25519MLKEM768` only engages when **both** ends support it. Clients that do:

- OpenSSL **3.5+**, and curl built against it
- Chrome/Edge **131+**, Firefox **132+** (recent)
- Go **1.24+** clients with the hybrid group enabled

Older clients silently negotiate **classical X25519** instead — the handshake still
succeeds (hybrid degrades gracefully), those sessions just aren't post-quantum. There
is **no breakage**; only reduced protection on legacy clients. To require PQC, restrict
the server's offered groups (and accept that old clients will fail).

## ⚠️ Caveat 2 — PQC capability tokens exceed default proxy header limits

An ML-DSA-65 signature is 3309 bytes, so a capability token is **~7 KB** (compact
`hex(cap).hex(sig)` form). That is **larger than the default ~8 KB header limit** in
most reverse proxies and will be rejected (HTTP **431 / 400**) unless you raise it.

If you front the backend with a proxy, raise the header/buffer size:

- **nginx**:
  ```nginx
  large_client_header_buffers 4 32k;
  # and for any proxied upstream:
  proxy_buffer_size 32k;
  proxy_buffers 4 32k;
  ```
- **HAProxy**: `tune.bufsize 32768` (global).
- **Caddy**: default request header limit is generous; usually fine.
- **Envoy / API gateways**: raise `max_request_headers_kb` (default 60 in Envoy is
  fine; many managed gateways cap lower — check yours).

Direct-to-container (no proxy) works out of the box — the backend accepts the token.

## Production checklist

- [ ] Mount **real TLS certificates** (don't ship the self-signed pair).
- [ ] Keep `INVAR_REQUIRE_CAPS=true`; issue capabilities from an external IdP.
- [ ] Move the reserve-attestor and capability-issuer keys to an **HSM/KMS**
      (the `CryptoProvider` PKCS#11 seam — see [`FIPS-PQC.md`](FIPS-PQC.md)).
- [ ] Build with `--features fips` where a CMVP-validated module is required.
- [ ] Raise proxy header limits (Caveat 2) if fronting with a proxy.
- [ ] Replace the in-memory ledger/governance with durable storage before real value.
- [ ] Security review + legal/regulatory counsel — this is not audited.
