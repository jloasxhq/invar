# Architecture

invar is a **hexagonal (ports & adapters)** system. Business rules live
in `invar-core` and depend on two ports; everything else is a replaceable adapter.

## Crate / package map

| Component | Lang | Kind | Depends on |
|---|---|---|---|
| `invar-core` | Rust | domain (hexagon): token ops, roles, compliance, reserve, **multisig**, **capabilities** | — |
| `invar-crypto` | Rust | adapter (CryptoProvider): ML-DSA-65, Argon2id KEK, **sealed keystore** | invar-core |
| `invar-ledger-custodial` | Rust | adapter (LedgerPort): double-entry + file persistence | invar-core |
| `invar-backend` | Rust | driver: **HTTPS** REST + capability auth | all Rust crates |
| `go/crypto` | Go | crypto glue + ML-KEM + FIPS check | — (std only) |
| `go/ledger-dlt` | Go | adapter stub (Fabric) | — |
| `go/cli` | Go | driver (HTTPS client) | — (std only) |
| `web/` | React/TS | driver (operator dashboard) | Vite |

## The two ports (`invar-core`)

- **`LedgerPort`** — persistence of accounts, supply, reserve, holds, and the
  append-only entry log. Implemented by `invar-ledger-custodial` (custodial, file
  persistence) today; by `go/ledger-dlt` (Hyperledger Fabric) later.
- **`CryptoProvider`** — signatures + deterministic glue. Implemented by
  `invar-crypto` (ML-DSA-65). Keys/signatures are opaque bytes, so the core is
  signature-scheme agnostic — and this is the **HSM drop-in seam** (a PKCS#11 impl
  slots in unchanged; see `FIPS-PQC.md`).

## Domain service

`StablecoinService<L: LedgerPort, C: CryptoProvider>` orchestrates:

- **RBAC** — 11 roles (Admin, Minter, Burner, Pauser, Freezer, Wiper,
  ComplianceOfficer, ReserveAttestor, Deleter, SupplyAdmin, Rescuer). No single key
  does everything.
- **Compliance** — accounts must be *registered* (KYB) and *verified* (KYC); freeze,
  wipe, and **rescue** (recover misdirected treasury funds) for regulatory action.
- **Supply** — mint (peg- and allowance-gated), burn, redeem; per-minter allowances.
- **Escrow** — holds: lock funds, then execute to a beneficiary or release.
- **Lifecycle** — mutable metadata; irreversible token delete.
- **Peg invariant** — `mint` enforces `total_supply + amount ≤ attested_reserve`.
- **Proof-of-reserve** — ML-DSA-65-signed attestations + an external reserve-oracle
  port.

## Authorization & multisig (`invar-core`)

- **Capability tokens** (`capability`) — an **ML-DSA-65-signed**, scoped, TTL-bounded
  grant. The backend verifies each request's token against a pinned issuer key and
  derives the caller identity + permissions from it (zero-trust; no ambient admin).
- **PQC multisig** (`multisig`) — `MultisigController` collects **M-of-N ML-DSA-65**
  signatures over a canonical operation preimage, then executes the privileged
  operation (mint/burn/wipe/pause/set-reserve/grant-role/rescue) via an executor
  account it solely operates.

## Transport & custody

- **HTTPS-only** (rustls). No plaintext listener; the service refuses to start
  without a TLS cert.
- **Hybrid post-quantum TLS** — the `pqc-tls` build (aws-lc-rs) negotiates
  `X25519MLKEM768` (ML-KEM key exchange) for quantum-safe confidentiality; `fips`
  builds against the CMVP-validated AWS-LC-FIPS module. Default build uses ring
  (classical). See `DEPLOYMENT.md` / `FIPS-PQC.md`.
- **Key custody** — Argon2id-sealed software keystore (Phase 0) → PKCS#11 HSM
  (Phase 1) via the `CryptoProvider` seam.

## Data flow (capability-gated mint)

```
HTTPS POST /mint (X-Invar-Capability: <token>)
   └► invar-backend: AuthCaller verifies ML-DSA-65 token, checks "mint" scope
        └► StablecoinService.mint(caller = token.subject)
             ├─ not paused/deleted? caller has Minter? `to` verified?
             ├─ consume caller's supply allowance (Admins exempt)
             ├─ LedgerPort: supply + amount ≤ attested_reserve?  (peg)
             ├─ LedgerPort: credit balance, bump supply
             └─ LedgerPort: append Mint entry
```

Privileged operations may instead be routed through the **multisig controller**,
which requires an M-of-N ML-DSA-65 quorum before the same service call executes.

## Cross-language conformance

The signing preimage is **canonical JSON**. Rust (`invar-crypto`) and Go
(`go/crypto`) both assert byte-equality against `conformance/vectors.json`
(canonical JSON, SHA-384, HKDF-SHA3, AES-256-GCM), so an attestation or capability
signed on one side verifies on the other. Primitives (ML-DSA/ML-KEM) are KAT-locked
to NIST.

## Why generic / ledger-agnostic

The reference (Hedera stablecoin-studio) is bound to one network's signature scheme.
By keeping persistence and crypto behind ports, the same domain drives a custodial
ledger or a permissioned DLT, and the signature scheme is a choice — which is what
makes **post-quantum** ledger signatures possible at all.
