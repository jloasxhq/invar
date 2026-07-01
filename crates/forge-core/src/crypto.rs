//! Cryptography **port** (hexagonal architecture). The core depends only on this
//! trait; a concrete provider (e.g. `forge-crypto` with ML-DSA-65) is injected as
//! an adapter. Keys and signatures are opaque byte strings so the core stays
//! agnostic to the signature scheme.

use crate::error::Result;
use serde::{Deserialize, Serialize};

/// Secret signing key material, opaque to the core. Concrete providers are
/// responsible for zeroizing the underlying bytes on drop.
#[derive(Clone)]
pub struct SigningKey(pub Vec<u8>);

/// Public verification key bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VerifyingKey(pub Vec<u8>);

/// Detached signature bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Signature(pub Vec<u8>);

/// The cryptographic operations the domain needs: a post-quantum signature
/// scheme plus the deterministic "glue" (canonical JSON, fingerprint hash) that
/// must agree byte-for-byte across a polyglot deployment.
pub trait CryptoProvider: Send + Sync {
    /// Human-readable signature algorithm identifier, e.g. `"ML-DSA-65"`.
    fn signature_algorithm(&self) -> &'static str;

    /// Generate a fresh signing keypair.
    fn generate_keypair(&self) -> Result<(VerifyingKey, SigningKey)>;

    /// Sign `msg`, returning a detached signature.
    fn sign(&self, sk: &SigningKey, msg: &[u8]) -> Result<Signature>;

    /// Verify a detached signature. Returns `false` on any failure (never panics).
    fn verify(&self, vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool;

    /// Produce the canonical byte encoding of a JSON value (deterministic key
    /// order, minimal separators) — the exact preimage that gets signed.
    fn canonical_json(&self, value: &serde_json::Value) -> Result<Vec<u8>>;

    /// Deterministic content fingerprint (SHA-384) used for logs and receipts.
    fn fingerprint(&self, data: &[u8]) -> Vec<u8>;
}
