# Threat Model (STRIDE)

A first-pass, living threat model for Invar. It is **not** a substitute for an
independent security review — it scopes what the design defends against, what it
does not, and the residual risks an operator must own.

## Assets

1. **Peg integrity** — `total_supply ≤ attested_reserve` must always hold.
2. **Custody keys** — reserve-attestor, capability issuer, and multisig signer keys.
3. **Capability tokens** — the authorization grants.
4. **Ledger integrity & audit trail** — the append-only entry log and balances.
5. **Availability** — the service issuing/verifying and settling.

## Trust boundaries

- **Client ↔ backend** — untrusted network; TLS 1.3 (hybrid ML-KEM in `pqc-tls`).
- **Backend ↔ IdP (issuer)** — in verify-only mode the issuer's private key lives at
  an external IdP; the backend only pins its public key.
- **Backend ↔ ledger store** — SQLite file (or in-memory). DB host is trusted.
- **Backend ↔ HSM/KMS** — the intended custody boundary (PKCS#11 seam).

## STRIDE

| Threat | Vector | Mitigation | Residual risk |
|---|---|---|---|
| **Spoofing** | Impersonate an operator/caller | ML-DSA-65 capability tokens (signed, scoped, TTL) + TLS; pinned issuer key | Issuer-key compromise mints any capability; **no replay cache** — a stolen token is usable until its TTL expires |
| **Tampering** | Alter request or ledger rows | TLS integrity; append-only `entries`; `sum(balances)==supply` integrity check | Tokens are **bearer + scoped but not request-bound** (a valid token authorizes any body within scope); DB rows are **not yet tamper-evident** (transparency-log/Merkle checkpoints are roadmap) |
| **Repudiation** | Deny having acted | Append-only entry log; ML-DSA-signed reserve attestations; capability carries subject | Individual privileged actions are **not signed into the log** by the acting operator |
| **Information disclosure** | Sniff traffic / read keys | TLS 1.3 + hybrid ML-KEM (anti harvest-now-decrypt-later); Argon2id-sealed keystore | Dev holds keys in memory (no HSM yet); **DB is not encrypted at rest**; large PQC tokens in headers |
| **Denial of service** | Flood / oversized requests | (structural) HTTPS only; capability check rejects early | **No rate limiting, request-size, or connection caps** — must be added at the edge/proxy |
| **Elevation of privilege** | Gain unauthorized capability | RBAC (11 roles), scoped caps, **M-of-N multisig** for privileged ops; two-key wipe (freeze→wipe) | Multisig **executor** account holds broad roles (only the quorum operates it); `require_caps=false` dev mode falls back to an ambient admin |

## Post-quantum posture

- **Confidentiality** against a future quantum adversary: hybrid `X25519MLKEM768` key
  exchange (harvest-now-decrypt-later resistant) in the `pqc-tls` build.
- **Authentication/authorization**: ML-DSA-65 signatures on capabilities, attestations,
  and multisig approvals.
- TLS **certificate** signatures remain classical (no PQC PKI ecosystem yet).

## Key mitigations already in place

- HTTPS-only; zero-trust (capabilities required by default).
- Reserve-gated minting (peg invariant enforced in core).
- **Durable, ACID, append-only ledger** (SQLite/WAL) with governance persisted.
- Verify-only issuer mode (external IdP holds the signing key).
- Supply-chain: pinned `Cargo.lock`, Dependabot, OSV scanning; `clippy -D warnings`.

## Known gaps / operator responsibilities (do before real funds)

1. **Token replay cache** (jti/nonce) and optionally **request-binding** of tokens.
2. **Rate limiting / request-size / connection limits** at the edge.
3. **Cryptographic tamper-evidence** for the ledger (Merkle transparency log +
   ML-DSA checkpoints — roadmap).
4. **Transactional multi-step operations** (wrap mint's balance+supply+entry writes
   in one DB transaction) and **encryption at rest** for the DB.
5. **HSM/PKCS#11 custody** for attestor/issuer/signer keys (the `CryptoProvider` seam).
6. **HA / disaster recovery** (SQLite is single-node; use replication/backups).
7. **Independent security audit, formal threat review, and legal/regulatory review.**
