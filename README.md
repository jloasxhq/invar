# stablecoin-forge

A **generic, ledger-agnostic stablecoin framework** with a first-class **FIPS / post-quantum
cryptography** layer. It provides the domain building blocks of a compliant stablecoin —
mint, burn, transfer, redeem, freeze, wipe, pause, KYC/KYB, role-based access control, and
**proof-of-reserve** — behind clean ports so the same core can drive a **custodial ledger**
today and a **distributed ledger (DLT)** later, without rewriting business logic.

> **Clean-room by reference.** The module decomposition and the compliance operation set were
> informed by the *publicly documented architecture* of Hashgraph's
> [stablecoin-studio](https://github.com/hashgraph/stablecoin-studio) (Apache-2.0). **No source
> was copied.** stablecoin-forge is ledger-agnostic and adds a FIPS/PQC layer with no counterpart
> in the reference. See [`NOTICE`](./NOTICE).

## Why it exists

Every public-chain stablecoin inherits its signature scheme from a chain you do not control
(secp256k1 on EVM, ed25519/ECDSA on Hedera) — none of which is post-quantum, and most of which
is not a NIST-approved curve. stablecoin-forge inverts that: **you own every byte of the
cryptography**, so the ledger's own signatures and attestations can be **ML-DSA-65 (FIPS 204)**
today, with a **FIPS 140-3 validated module** boundary as a configuration choice (Go crypto
module / PKCS#11 HSM) rather than a rewrite.

## Architecture (hexagonal / ports & adapters)

```
                 ┌─────────────────────────────────────────────┐
                 │                 forge-core (Rust)            │
                 │  token · roles · compliance · reserve        │
                 │  StablecoinService  ── depends on ports ──►  │
                 │     LedgerPort            CryptoProvider      │
                 └───────┬───────────────────────┬──────────────┘
        adapters ────────┼───────────────────────┼───────── adapters
        ┌────────────────▼──────┐      ┌──────────▼───────────────┐
        │ forge-ledger-custodial│      │ forge-crypto (Rust)      │
        │ double-entry, 1:1     │      │ ML-DSA-65, Argon2id KEK, │
        │ reserve invariant     │      │ glue (canon-JSON/HKDF/   │
        └───────────────────────┘      │ AES-GCM/SHA-384)         │
        ┌───────────────────────┐      └──────────────────────────┘
        │ go/ledger-dlt (stub)  │      ┌──────────────────────────┐
        │ Fabric / DLT adapter  │      │ go/crypto (FIPS mode,    │
        └───────────────────────┘      │ ML-KEM std, glue confor.)│
                                       └──────────────────────────┘
  forge-backend (Rust/axum REST)   ·   go/cli (Go, FIPS boundary)   ·   web/ (dashboard)
```

## Layout

| Path | Lang | Role |
|---|---|---|
| `crates/forge-core` | Rust | Domain SDK: token model, `LedgerPort`, `CryptoProvider` port, roles, compliance, reserve invariant |
| `crates/forge-crypto` | Rust | `CryptoProvider` impl: ML-DSA-65, Argon2id KEK, canonical-JSON/HKDF/AES-GCM/SHA-384 glue |
| `crates/forge-ledger-custodial` | Rust | Custodial double-entry ledger adapter (`totalSupply ≤ reserve` enforced) |
| `crates/forge-backend` | Rust | axum REST API: mint/burn/transfer/redeem/attest |
| `go/cli` | Go | Operator CLI, runs under `GODEBUG=fips140` |
| `go/crypto` | Go | Go crypto provider: FIPS module boundary + ML-KEM (std) + same glue conformance |
| `go/ledger-dlt` | Go | Hyperledger-Fabric / DLT adapter (stub) |
| `web/` | TS/React | Minimal operator dashboard (stub) |
| `conformance/` | — | Cross-language golden vectors (glue byte-equality) |
| `docs/` | — | `ARCHITECTURE.md`, `FIPS-PQC.md`, `ROADMAP.md` |

## The peg invariant

The custodial adapter enforces the rule that keeps a fiat-backed coin honest:

```
totalSupply ≤ attestedReserve      (checked on every mint)
```

Funding/lending programs (if built on top) must move **already-backed** units from a
separately-capitalized pool — the core never mints outside a reserve authorization.

## Crypto conformance

Primitives are KAT-locked to their standards (FIPS 203/204/180-4/202). The **composition**
("glue") is where polyglot systems diverge, so Rust and Go both assert **byte-equality**
against a shared `conformance/vectors.json` (canonical JSON signing-preimage, SHA-384
fingerprint, HKDF-SHA3, AES-GCM framing). See [`docs/FIPS-PQC.md`](./docs/FIPS-PQC.md).

## Build

```bash
# Rust workspace
cargo build
cargo test

# Go (requires Go 1.24+)
cd go && GODEBUG=fips140=on go test ./...
```

## Status

Working scaffold with feature parity to the reference on the custodial/compliance surface,
and additional PQC/FIPS capabilities. Implemented and tested:

- **Token ops**: mint (peg- and allowance-gated), burn, transfer, redeem, freeze, wipe, pause.
- **Compliance**: KYB registration, KYC, role-based access control, supply allowances, rescue.
- **Escrow & lifecycle**: holds (create/execute/release), token delete + metadata.
- **Proof-of-reserve**: ML-DSA-65-signed attestations + external reserve-oracle port.
- **PQC multi-signature**: M-of-N ML-DSA-65 approval for privileged operations.
- **Auth**: ML-DSA-65 capability tokens (scoped, TTL) enforced on the backend.
- **Key custody**: Argon2id-sealed software keystore (pre-HSM).
- **Persistence**: file-backed custodial ledger snapshots.
- **Surfaces**: Rust SDK + axum REST backend, Go CLI + FIPS/glue crypto, React dashboard.

CI runs Rust (fmt/clippy/test), Go (vet + FIPS-mode test), and web (build) on every PR.

**Not audited. Not a validated FIPS 140-3 module.** See [`SECURITY.md`](SECURITY.md) and
[`docs/FIPS-PQC.md`](docs/FIPS-PQC.md). Do not use in production without a security review and
legal/regulatory counsel appropriate to your jurisdiction.

Remaining hardening (tracked in [`docs/ROADMAP.md`](docs/ROADMAP.md)): HSM/PKCS#11 custody,
DB-backed persistence, and the Hyperledger-Fabric DLT adapter (currently a documented stub).

## License

[Apache-2.0](./LICENSE).
