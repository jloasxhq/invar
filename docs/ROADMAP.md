# Roadmap

Status legend: ✅ done · 🔨 partial · ⬜ planned

## Implemented (this scaffold)

- ✅ Ledger-agnostic domain core (`forge-core`): token ops, RBAC, KYC/KYB,
  freeze/wipe/pause, peg invariant, proof-of-reserve.
- ✅ ML-DSA-65 crypto provider + Argon2id KEK + glue (`forge-crypto`).
- ✅ Custodial ledger adapter with integrity check (`forge-ledger-custodial`).
- ✅ REST backend with HTTP tests (`forge-backend`).
- ✅ Go FIPS/PQC glue + ML-KEM-768 + FIPS-mode check, conformance-tested against the
  same vectors as Rust (`go/crypto`).
- ✅ Operator CLI (`go/cli`); Fabric DLT adapter stub (`go/ledger-dlt`).
- ✅ Static dashboard stub (`web/`).

## Near-term

- ⬜ **AuthN/Z**: replace the backend's fixed-admin caller with per-request
  **ML-DSA-65 capability tokens** (QETF-style: signed, short-TTL, device-scoped).
- ⬜ **Persistence**: back `forge-ledger-custodial` with a real database
  (append-only entries table + balances), not in-memory.
- ⬜ **Governance persistence**: move roles/KYC/pause out of process memory.
- ⬜ **Attestor key custody**: move the reserve-attestor key to Argon2id-sealed
  keystore now, PKCS#11 HSM at Phase 1.

## Mid-term

- ⬜ **PQC transparency log**: Merkle log over all ledger entries, periodic
  **ML-DSA-65-signed checkpoints**, per-entry inclusion proofs — trust-but-verify
  auditability without running consensus.
- ⬜ **HSM (Phase 1)**: PKCS#11 signing + KEK-unwrap; re-key ceremony.
- ⬜ **Hybrid PQC TLS** termination (X25519+ML-KEM-768) in front of the backend.

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
