# FIPS / PQC posture

This document states **exactly** what is and is not claimed, so the posture is not
oversold. Read it before describing the project as "FIPS" anything.

## Algorithms and standards used

| Purpose | Algorithm | Standard | Where |
|---|---|---|---|
| Signatures (attestations, future checkpoints) | **ML-DSA-65** | FIPS 204 | `forge-crypto` (`fips204` crate, KAT-locked) |
| Key establishment (hybrid transport) | **ML-KEM-768** | FIPS 203 | `go/crypto` (Go std `crypto/mlkem`) |
| KEK / key wrapping | **Argon2id** | RFC 9106 | `forge-crypto::kek` |
| Content fingerprint | **SHA-384** | FIPS 180-4 | both providers |
| KDF | **HKDF / SHA3-256** | RFC 5869 / FIPS 202 | both providers |
| AEAD (keystore-at-rest, framing) | **AES-256-GCM** | SP 800-38D | both providers |
| Canonical signing preimage | canonical JSON | RFC 8259 | both providers |

Project policy: reversible/base64 encodings are **not** used for key or password
wrapping — only an Argon2id-derived KEK.

## Two distinct claims — do not conflate them

1. **FIPS-approved *algorithms*** — every primitive above is a NIST/IETF-standardized
   algorithm. ✅ True today.
2. **FIPS 140-3 *validated module*** — a CMVP-certificated cryptographic module.
   - The **Go** side, built with Go 1.24+ and run under `GODEBUG=fips140=on`, uses
     the **Go Cryptographic Module v1.0.0, CMVP certificate #5247** — a genuine
     validated software boundary. ✅ Available now for the classical/transport and
     ML-KEM crypto that lives in Go.
   - The **Rust ML-DSA-65** path (`fips204`) is **algorithm-conformant (KAT-locked),
     not a CMVP-validated module.** There is essentially no CMVP-validated ML-DSA
     module yet industry-wide. ⚠️ Do not call the ML-DSA path "FIPS 140-3 validated."

So today: *validated module* for the Go/classical/KEM boundary; *algorithm-conformant*
for Rust ML-DSA. The HSM (below) closes the remaining gap for key custody.

## Software boundary now → HSM later (no re-architecture)

The `CryptoProvider` port is the swap seam.

- **Phase 0 (now, no HSM):** software keys. Seal the software keystore under an
  Argon2id KEK + AES-256-GCM. Run Go components under `GODEBUG=fips140=on` for the
  validated software boundary. Never assume key bytes are extractable.
- **Phase 1 (HSM acquired):** move signing/KEK-unwrap into a **FIPS 140-3 L3
  HSM via PKCS#11**. Because keys were always behind the port and were **enrolled,
  not hand-placed**, adoption is a **re-key ceremony** (generate keys inside the
  HSM), not a code change or a key import.

If/when the ledger becomes a permissioned DLT (Hyperledger Fabric, `go/ledger-dlt`),
the same principle applies to Fabric's BCCSP/MSP: SW BCCSP → PKCS#11 BCCSP, keys
re-enrolled in the HSM, Fabric built with Go FIPS mode.

## Verifying the posture locally

```bash
# Rust: ML-DSA-65 KAT sizes + roundtrip + glue conformance
cargo test

# Go: glue conformance + ML-KEM + FIPS boundary observable
cd go && GODEBUG=fips140=on go test ./...
```

## What this is NOT

- Not audited. Not penetration-tested. Not a validated ML-DSA module.
- Not legal/regulatory compliance. A stablecoin has money-transmission, reserve,
  and (for some designs) lending/securities obligations that are **out of scope of
  this repository** and require qualified counsel.
