# Security Policy

## Status

stablecoin-forge is an early-stage framework. It has **not** been independently
audited or penetration-tested, and it is **not** a validated FIPS 140-3
cryptographic module (see [`docs/FIPS-PQC.md`](docs/FIPS-PQC.md) for the exact
posture). Do not deploy it to hold real value without a security review and
legal/regulatory counsel appropriate to your jurisdiction.

## Reporting a vulnerability

Please report suspected vulnerabilities privately — do **not** open a public issue
for security problems. Use GitHub's **"Report a vulnerability"** (Security →
Advisories) on this repository, or email the maintainers listed in the repository
metadata. Include:

- affected component (crate / Go package / endpoint),
- a description and, ideally, a minimal reproduction,
- impact assessment.

We aim to acknowledge reports within a few business days.

## Cryptography notes

- Signatures use **ML-DSA-65** (FIPS 204); KEM uses **ML-KEM-768** (FIPS 203); key
  wrapping uses **Argon2id** (RFC 9106). These are standardized algorithms, but the
  ML-DSA path is **algorithm-conformant, not a CMVP-validated module**.
- The Go components can run under `GODEBUG=fips140=on` (Go Cryptographic Module,
  CMVP certificate #5247) for a validated software boundary on the classical/KEM
  crypto.
- Signing keys can be sealed at rest with the Argon2id-KEK software keystore; an
  HSM (PKCS#11) is the intended production custody boundary.

## Scope caveats in the current scaffold

- The backend's capability issuer and multisig demo signers are held in-process for
  demonstration; production uses an external IdP and HSM/KMS-held keys.
- Persistence is file-based; governance state is in-memory.
