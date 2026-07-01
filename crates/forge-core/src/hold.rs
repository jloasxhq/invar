//! Holds (escrow). A hold locks part of a holder's balance so it can later be
//! either **executed** (delivered to a beneficiary) or **released** (returned).
//! Locked funds are debited from the holder's spendable balance at creation, so
//! total supply is unchanged while a hold is active.

use crate::account::AccountId;
use crate::amount::Amount;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HoldStatus {
    Active,
    Executed,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hold {
    pub id: String,
    pub from: AccountId,
    /// Optional fixed beneficiary. If `None`, the executor supplies the target.
    pub beneficiary: Option<AccountId>,
    pub amount: Amount,
    /// Unix expiry; `0` means no expiry.
    pub expires_unix: u64,
    pub status: HoldStatus,
    pub created_unix: u64,
}

impl Hold {
    pub fn is_active(&self) -> bool {
        self.status == HoldStatus::Active
    }
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_unix != 0 && now >= self.expires_unix
    }
}
