//! Proof-of-reserve attestations. A reserve attestation is a signed statement,
//! `attested_reserve ≥ total_supply`, reconciling the on-ledger supply against the
//! custodian's held fiat at a point in time. It is signed with the PQC provider so
//! auditors and counterparties can verify the peg without trusting the operator's
//! database.

use crate::amount::Amount;
use crate::crypto::{CryptoProvider, Signature, VerifyingKey};
use crate::error::{ForgeError, Result};
use serde::{Deserialize, Serialize};

/// The signed body of an attestation. Field names are fixed because they form the
/// canonical signing preimage — changing them changes the bytes that are signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationBody {
    pub schema: String,
    pub token_symbol: String,
    pub total_supply_minor: u128,
    pub attested_reserve_minor: u128,
    pub custodian_ref: String,
    pub as_of_unix: u64,
}

impl AttestationBody {
    /// Fixed schema tag so verifiers can pin the preimage format.
    pub const SCHEMA: &'static str = "forge.reserve-attestation.v1";

    /// Render the body as the canonical JSON value used as the signing preimage.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": self.schema,
            "token_symbol": self.token_symbol,
            "total_supply_minor": self.total_supply_minor,
            "attested_reserve_minor": self.attested_reserve_minor,
            "custodian_ref": self.custodian_ref,
            "as_of_unix": self.as_of_unix,
        })
    }

    /// True iff the attestation shows the coin fully backed (or over-collateralized).
    pub fn is_fully_backed(&self) -> bool {
        self.attested_reserve_minor >= self.total_supply_minor
    }
}

/// A complete, signed attestation: body + PQC signature + the verifying key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveAttestation {
    pub body: AttestationBody,
    pub algorithm: String,
    pub public_key: VerifyingKey,
    pub signature: Signature,
}

impl ReserveAttestation {
    /// Re-derive the preimage and verify the signature against the embedded key.
    pub fn verify(&self, crypto: &dyn CryptoProvider) -> Result<bool> {
        let preimage = crypto.canonical_json(&self.body.to_json())?;
        Ok(crypto.verify(&self.public_key, &preimage, &self.signature))
    }
}

/// Enforce the core peg invariant used at mint time.
pub fn assert_within_reserve(new_supply: Amount, reserve: Amount) -> Result<()> {
    if new_supply.get() > reserve.get() {
        return Err(ForgeError::ReserveExceeded {
            supply: new_supply.get(),
            reserve: reserve.get(),
        });
    }
    Ok(())
}

/// External reserve-source **port** (the analog of studio's Chainlink feed). An
/// adapter reports the currently-held reserve so the service can sync its attested
/// reserve from an authoritative source instead of a manual figure.
pub trait ReserveOracle: Send + Sync {
    /// Identifier of the reserve source (e.g. `"custodian-api"`, `"chainlink:USDC"`).
    fn source(&self) -> &str;
    /// Current reserve, in the token's minor units.
    fn current_reserve(&self) -> Result<Amount>;
}

/// A trivial, manually-updated reserve oracle — useful for tests and for a
/// custodian that pushes balances over a control channel. A real deployment
/// implements `ReserveOracle` against an HTTP/oracle feed.
pub struct ManualReserveOracle {
    source: String,
    reserve: std::sync::Mutex<Amount>,
}

impl ManualReserveOracle {
    pub fn new(source: impl Into<String>, initial: Amount) -> Self {
        ManualReserveOracle {
            source: source.into(),
            reserve: std::sync::Mutex::new(initial),
        }
    }
    pub fn set(&self, reserve: Amount) {
        *self.reserve.lock().unwrap() = reserve;
    }
}

impl ReserveOracle for ManualReserveOracle {
    fn source(&self) -> &str {
        &self.source
    }
    fn current_reserve(&self) -> Result<Amount> {
        Ok(*self.reserve.lock().unwrap())
    }
}
