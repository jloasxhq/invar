//! # forge-crypto
//!
//! The FIPS/PQC [`CryptoProvider`](forge_core::crypto::CryptoProvider) adapter for
//! stablecoin-forge:
//!
//! - **Signatures**: ML-DSA-65 (NIST FIPS 204) via `fips204` (KAT-locked).
//! - **KEK**: Argon2id (RFC 9106) for sealing the software keystore until an HSM
//!   assumes custody.
//! - **Glue**: canonical JSON (RFC 8259), SHA-384 (FIPS 180-4), HKDF-SHA3
//!   (RFC 5869 / FIPS 202), AES-256-GCM (SP 800-38D) — all conformance-tested
//!   against `conformance/vectors.json` for cross-language byte-equality.

pub mod glue;
pub mod kek;
pub mod keystore;
pub mod provider;

pub use keystore::{seal_signing_key, unseal_signing_key, SealedKey};
pub use provider::FipsPqcProvider;
