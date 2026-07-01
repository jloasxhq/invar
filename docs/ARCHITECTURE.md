# Architecture

stablecoin-forge is a **hexagonal (ports & adapters)** system. Business rules live
in `forge-core` and depend on two ports; everything else is a replaceable adapter.

## Crate / package map

| Component | Lang | Kind | Depends on |
|---|---|---|---|
| `forge-core` | Rust | domain (hexagon) | — |
| `forge-crypto` | Rust | adapter (CryptoProvider) | forge-core |
| `forge-ledger-custodial` | Rust | adapter (LedgerPort) | forge-core |
| `forge-backend` | Rust | driver (HTTP) | all Rust crates |
| `go/crypto` | Go | crypto glue + KEM + FIPS | — (std only) |
| `go/ledger-dlt` | Go | adapter stub (Fabric) | — |
| `go/cli` | Go | driver (client) | — (std only) |
| `web/` | HTML/JS | driver (UI stub) | — |

## The two ports (`forge-core`)

- **`LedgerPort`** — persistence of accounts, supply, reserve, and the append-only
  entry log. Implemented by `forge-ledger-custodial` (custodial DB) today; by
  `go/ledger-dlt` (Hyperledger Fabric) later. Both honor the same contract.
- **`CryptoProvider`** — signatures + deterministic glue. Implemented by
  `forge-crypto` (ML-DSA-65). Keys/signatures are opaque bytes so the core never
  hard-codes a signature scheme.

## Domain service

`StablecoinService<L: LedgerPort, C: CryptoProvider>` orchestrates:

- **RBAC** — `Admin, Minter, Burner, Pauser, Freezer, Wiper, ComplianceOfficer,
  ReserveAttestor`. No single key does everything.
- **Compliance** — accounts must be *registered* (KYB) and *verified* (KYC) to hold
  or receive; freeze/wipe for regulatory action.
- **Peg invariant** — `mint` enforces `total_supply + amount ≤ attested_reserve`.
- **Proof-of-reserve** — `attest_reserve` records reserve and returns an
  **ML-DSA-65-signed** attestation any party can verify.

## Data flow (mint)

```
HTTP POST /mint ─► forge-backend ─► StablecoinService.mint()
                                     ├─ gov: not paused? caller has Minter? `to` verified?
                                     ├─ LedgerPort: registered? supply+amt ≤ reserve?
                                     ├─ LedgerPort: credit balance, bump supply
                                     └─ LedgerPort: append Mint entry
```

## Cross-language conformance

The signing preimage is **canonical JSON**. Rust (`forge-crypto`) and Go
(`go/crypto`) both assert byte-equality against `conformance/vectors.json`
(canonical JSON, SHA-384, HKDF-SHA3, AES-256-GCM), so an attestation signed on one
side verifies on the other. Primitives (ML-DSA/ML-KEM) are KAT-locked to NIST.

## Why generic / ledger-agnostic

The reference (Hedera stablecoin-studio) is bound to one network's signature
scheme. By keeping persistence and crypto behind ports, the same domain drives a
custodial ledger or a permissioned DLT, and the signature scheme is a choice — which
is what makes a **post-quantum** ledger signature possible at all.
