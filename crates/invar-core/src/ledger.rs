//! Ledger **port** (hexagonal architecture). Persistence of balances, supply,
//! reserve, and the append-only entry log lives behind this trait. A custodial
//! database, or a DLT adapter, implements it without the core knowing which.
//!
//! Methods take `&self` and rely on interior mutability in the adapter, so the
//! port can be shared behind an `Arc` across request handlers.

use crate::account::{Account, AccountId};
use crate::amount::Amount;
use crate::error::Result;
use crate::hold::Hold;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    Mint,
    Burn,
    Transfer,
    Redeem,
    Freeze,
    Unfreeze,
    Wipe,
    HoldCreate,
    HoldExecute,
    HoldRelease,
    Delete,
    Rescue,
}

/// An immutable record appended to the ledger for every state-changing operation.
/// This is the raw material a transparency log / PQC checkpoint is built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub id: String,
    pub kind: EntryKind,
    pub from: Option<AccountId>,
    pub to: Option<AccountId>,
    pub amount: Amount,
    pub as_of_unix: u64,
}

pub trait LedgerPort: Send + Sync {
    /// Whether an account has been onboarded (KYB) and may hold the token.
    fn is_registered(&self, id: &AccountId) -> Result<bool>;

    /// Register (onboard) an account with a zero balance.
    fn register(&self, id: &AccountId) -> Result<()>;

    /// Fetch an account; returns `UnknownAccount` if not registered.
    fn account(&self, id: &AccountId) -> Result<Account>;

    /// Persist an account's updated position.
    fn set_account(&self, account: &Account) -> Result<()>;

    fn total_supply(&self) -> Result<Amount>;
    fn set_total_supply(&self, supply: Amount) -> Result<()>;

    fn attested_reserve(&self) -> Result<Amount>;
    fn set_attested_reserve(&self, reserve: Amount) -> Result<()>;

    fn append_entry(&self, entry: &LedgerEntry) -> Result<()>;
    fn entries(&self) -> Result<Vec<LedgerEntry>>;

    // ---- holds (escrow) ----
    fn put_hold(&self, hold: &Hold) -> Result<()>;
    fn get_hold(&self, id: &str) -> Result<Hold>;
    fn holds(&self) -> Result<Vec<Hold>>;

    // ---- governance persistence ----
    /// Load the persisted governance blob (roles, KYC, pause/delete flags,
    /// metadata, supply allowances), if any. Returns `None` on a fresh store.
    fn load_governance(&self) -> Result<Option<Vec<u8>>>;
    /// Persist the governance blob (write-through on every governance mutation),
    /// so roles/KYC/allowances survive a restart.
    fn save_governance(&self, data: &[u8]) -> Result<()>;
}

/// Allow a `LedgerPort` to be shared behind an `Arc` (e.g. as axum state) while
/// still satisfying the `L: LedgerPort` bound on the service.
impl<T: LedgerPort + ?Sized> LedgerPort for std::sync::Arc<T> {
    fn is_registered(&self, id: &AccountId) -> Result<bool> {
        (**self).is_registered(id)
    }
    fn register(&self, id: &AccountId) -> Result<()> {
        (**self).register(id)
    }
    fn account(&self, id: &AccountId) -> Result<Account> {
        (**self).account(id)
    }
    fn set_account(&self, account: &Account) -> Result<()> {
        (**self).set_account(account)
    }
    fn total_supply(&self) -> Result<Amount> {
        (**self).total_supply()
    }
    fn set_total_supply(&self, supply: Amount) -> Result<()> {
        (**self).set_total_supply(supply)
    }
    fn attested_reserve(&self) -> Result<Amount> {
        (**self).attested_reserve()
    }
    fn set_attested_reserve(&self, reserve: Amount) -> Result<()> {
        (**self).set_attested_reserve(reserve)
    }
    fn append_entry(&self, entry: &LedgerEntry) -> Result<()> {
        (**self).append_entry(entry)
    }
    fn entries(&self) -> Result<Vec<LedgerEntry>> {
        (**self).entries()
    }
    fn put_hold(&self, hold: &Hold) -> Result<()> {
        (**self).put_hold(hold)
    }
    fn get_hold(&self, id: &str) -> Result<Hold> {
        (**self).get_hold(id)
    }
    fn holds(&self) -> Result<Vec<Hold>> {
        (**self).holds()
    }
    fn load_governance(&self) -> Result<Option<Vec<u8>>> {
        (**self).load_governance()
    }
    fn save_governance(&self, data: &[u8]) -> Result<()> {
        (**self).save_governance(data)
    }
}
