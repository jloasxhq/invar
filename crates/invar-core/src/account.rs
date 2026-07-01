//! Accounts and their identities. In a stablecoin every holder is a KYB-onboarded
//! entity, so an `AccountId` is an onboarded operator identity, not an anonymous key.

use crate::amount::Amount;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountId(pub String);

impl AccountId {
    pub fn new(id: impl Into<String>) -> Self {
        AccountId(id.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Verification state for an onboarded account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum KycStatus {
    #[default]
    Unverified,
    Verified,
    Revoked,
}

/// The persisted per-account balance sheet position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: AccountId,
    pub balance: Amount,
    pub frozen: bool,
}

impl Account {
    pub fn new(id: AccountId) -> Self {
        Account {
            id,
            balance: Amount::ZERO,
            frozen: false,
        }
    }
}
