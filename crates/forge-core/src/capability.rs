//! PQC **capability tokens** for authorization. A capability is a short-lived,
//! **ML-DSA-65-signed** grant: it names a subject, the scopes it may exercise, and
//! an expiry. A verifier checks the signature against a pinned issuer key, checks
//! the TTL, and derives the caller's identity and permissions from the token — so
//! services stop relying on a single ambient admin identity.
//!
//! This mirrors the QETF capability model (signed, short-TTL, scoped) using the same
//! `CryptoProvider` and canonical-JSON preimage as the rest of the system.

use crate::account::AccountId;
use crate::crypto::{CryptoProvider, Signature, SigningKey, VerifyingKey};
use crate::error::{ForgeError, Result};
use serde::{Deserialize, Serialize};

/// The signed body of a capability. Field set is fixed because it forms the
/// canonical signing preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub schema: String,
    pub subject: AccountId,
    pub scopes: Vec<String>,
    /// Unix expiry; `0` means non-expiring (discouraged).
    pub not_after_unix: u64,
    pub nonce: String,
}

impl Capability {
    pub const SCHEMA: &'static str = "forge.capability.v1";

    pub fn new(
        subject: AccountId,
        scopes: Vec<String>,
        not_after_unix: u64,
        nonce: impl Into<String>,
    ) -> Self {
        Capability {
            schema: Self::SCHEMA.to_string(),
            subject,
            scopes,
            not_after_unix,
            nonce: nonce.into(),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": self.schema,
            "subject": self.subject,
            "scopes": self.scopes,
            "not_after_unix": self.not_after_unix,
            "nonce": self.nonce,
        })
    }

    /// True if the capability grants `scope` (explicitly or via the `*` wildcard).
    pub fn allows(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == "*" || s == scope)
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.not_after_unix != 0 && now_unix >= self.not_after_unix
    }
}

/// A capability plus its issuer signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCapability {
    pub capability: Capability,
    pub signature: Signature,
}

/// Sign a capability with the issuer's key.
pub fn issue(
    crypto: &dyn CryptoProvider,
    issuer_sk: &SigningKey,
    capability: Capability,
) -> Result<SignedCapability> {
    let preimage = crypto.canonical_json(&capability.to_json())?;
    let signature = crypto.sign(issuer_sk, &preimage)?;
    Ok(SignedCapability {
        capability,
        signature,
    })
}

/// Verify a capability against the pinned issuer key and the current time. Returns
/// the inner capability on success.
pub fn verify<'a>(
    crypto: &dyn CryptoProvider,
    issuer_vk: &VerifyingKey,
    signed: &'a SignedCapability,
    now_unix: u64,
) -> Result<&'a Capability> {
    if signed.capability.schema != Capability::SCHEMA {
        return Err(ForgeError::MalformedCapability("unexpected schema".into()));
    }
    let preimage = crypto.canonical_json(&signed.capability.to_json())?;
    if !crypto.verify(issuer_vk, &preimage, &signed.signature) {
        return Err(ForgeError::BadSignature);
    }
    if signed.capability.is_expired(now_unix) {
        return Err(ForgeError::CapabilityExpired);
    }
    Ok(&signed.capability)
}

/// Verify and additionally require a specific scope.
pub fn verify_scope<'a>(
    crypto: &dyn CryptoProvider,
    issuer_vk: &VerifyingKey,
    signed: &'a SignedCapability,
    now_unix: u64,
    scope: &str,
) -> Result<&'a Capability> {
    let cap = verify(crypto, issuer_vk, signed, now_unix)?;
    if !cap.allows(scope) {
        return Err(ForgeError::InsufficientScope(scope.to_string()));
    }
    Ok(cap)
}
