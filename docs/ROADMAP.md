# Roadmap

Status legend: ✅ done · 🔨 partial · ⬜ planned

## Implemented

**Domain (`invar-core`)**
- ✅ Token ops: mint (peg- and allowance-gated), burn, transfer, redeem.
- ✅ RBAC (11 roles): Admin, Minter, Burner, Pauser, Freezer, Wiper,
  ComplianceOfficer, ReserveAttestor, Deleter, SupplyAdmin, Rescuer.
- ✅ Compliance: KYB registration, KYC, per-minter supply allowances.
- ✅ Freeze / wipe / pause; **rescue** of misdirected treasury funds.
- ✅ **Holds (escrow)**: create / execute / release.
- ✅ **Token lifecycle**: mutable metadata + irreversible delete.
- ✅ Peg invariant (`total_supply ≤ attested_reserve`); external reserve-oracle port.
- ✅ **Proof-of-reserve**: ML-DSA-65-signed attestations.
- ✅ **PQC multi-signature**: M-of-N ML-DSA-65 approval for privileged operations.
- ✅ **Capability tokens**: scoped, TTL-bounded, ML-DSA-65-signed authorization.

**Crypto (`invar-crypto`)**
- ✅ ML-DSA-65 (FIPS 204) provider; Argon2id KEK; canonical-JSON/HKDF-SHA3/
  AES-GCM/SHA-384 glue with golden-vector conformance.
- ✅ **Argon2id-sealed software keystore** (Phase-0 key custody).

**Adapters & surfaces**
- ✅ **Durable SQLite ledger** (`invar-ledger-sqlite`): ACID writes (WAL),
  append-only entry log, and **persisted balances/reserve/holds/governance that
  survive a restart** (selected via `INVAR_DB_PATH`).
- ✅ **Persistent governance**: roles/KYC/pause/allowances are written through the
  `LedgerPort` on every mutation and reloaded on startup (no longer in-memory-only).
- ✅ **Verify-only issuer mode**: `INVAR_ISSUER_PUBKEY` pins an external IdP's key and
  disables in-process token issuance.
- ✅ In-memory custodial ledger adapter with JSON snapshot + integrity check
  (reference/dev backend).
- ✅ **HTTPS-only** backend (rustls); **zero-trust** (capability tokens required by
  default).
- ✅ **Hybrid post-quantum TLS** (`X25519MLKEM768`) via the `pqc-tls` feature;
  `fips` feature selects the CMVP-validated AWS-LC-FIPS provider.
- ✅ Go FIPS/PQC glue + ML-KEM-768 + FIPS-mode check; operator CLI (HTTPS);
  Fabric DLT adapter stub.
- ✅ React + Vite + TypeScript operator dashboard.
- ✅ CI (fmt/clippy/test, Go vet + FIPS test, web build), Dependabot,
  containerization; **built and verified on Portainer** (hybrid PQC TLS negotiated,
  zero-trust enforced).

## Near-term (remaining hardening)

- ⬜ **Transactional multi-step ops**: wrap a domain operation's writes (e.g. mint =
  balance + supply + entry) in a single DB transaction for cross-op atomicity. Today
  each write is individually ACID/durable.
- ⬜ **Encryption at rest** for the SQLite DB; **backups / HA** (SQLite is single-node).
- ⬜ **Token replay cache** (jti/nonce) and optional **request-binding** of tokens.
- ⬜ **Rate limiting / request-size / connection caps** (edge or middleware).
- ⬜ **Live PKCS#11 HSM driver**: the `CryptoProvider` seam is done; the concrete
  driver needs an HSM/SoftHSM to test (see `docs/FIPS-PQC.md`).

## Mid-term

- ⬜ **PQC transparency log**: Merkle log over all ledger entries, periodic
  **ML-DSA-65-signed checkpoints**, per-entry inclusion proofs.
- ⬜ **ML-DSA TLS certificate signatures**: deferred until a PQC PKI/verifier
  ecosystem exists (hybrid ML-KEM key exchange already provides PQC confidentiality).

## Longer-term (optional, only if a multi-party ledger is needed)

- ⬜ **Fabric DLT adapter**: implement `go/ledger-dlt` against a permissioned
  Hyperledger Fabric network; token logic as chaincode; SW BCCSP → PKCS#11 BCCSP;
  build Fabric under Go FIPS mode.
- ⬜ **Funding/lending module**: a *separately capitalized* pool that moves
  already-backed units (never mints), preserving the 1:1 peg. See below.

## Design guardrail: funding must not break the peg

If a lending/funding layer is added, it must transfer **already-backed** units from
a separately-capitalized pool. The core `mint` path stays reserve-gated; funding
never mints outside a reserve authorization. This keeps `total_supply ≤ reserve`
true even while credit is extended.
