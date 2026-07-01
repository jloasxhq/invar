//! `StablecoinService` — the domain orchestrator. It enforces authorization,
//! compliance, and the peg invariant, delegating persistence to a `LedgerPort`
//! and signatures to a `CryptoProvider`. It is generic over both ports, so the
//! same logic drives a custodial ledger today and a DLT adapter later.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::account::{AccountId, KycStatus};
use crate::allowance::Allowance;
use crate::amount::Amount;
use crate::crypto::{CryptoProvider, SigningKey, VerifyingKey};
use crate::error::{InvarError, Result};
use crate::hold::{Hold, HoldStatus};
use crate::ledger::{EntryKind, LedgerEntry, LedgerPort};
use crate::reserve::{assert_within_reserve, AttestationBody, ReserveAttestation, ReserveOracle};
use crate::roles::{Role, RoleSet};
use crate::token::TokenConfig;

/// Injectable clock so tests are deterministic.
pub trait Clock: Send + Sync {
    fn now_unix(&self) -> u64;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Governance state (roles, KYC, pause flag) held in the service. In a production
/// deployment this would also be persisted; kept in-memory here for the scaffold.
#[derive(Default)]
struct Governance {
    paused: bool,
    deleted: bool,
    metadata: Option<String>,
    roles: HashMap<AccountId, RoleSet>,
    kyc: HashMap<AccountId, KycStatus>,
    allowances: HashMap<AccountId, Allowance>,
}

/// Fixed identity of the system treasury account (recipient of misdirected funds,
/// source for rescue).
pub const TREASURY_ID: &str = "__treasury__";

pub struct StablecoinService<L: LedgerPort, C: CryptoProvider> {
    pub config: TokenConfig,
    ledger: L,
    crypto: C,
    clock: Arc<dyn Clock>,
    gov: Mutex<Governance>,
    treasury: AccountId,
}

impl<L: LedgerPort, C: CryptoProvider> StablecoinService<L, C> {
    /// Create a service and bootstrap `admin` with the full role bundle, registered
    /// and KYC-verified so it can perform the first onboarding operations.
    pub fn new(config: TokenConfig, ledger: L, crypto: C, admin: AccountId) -> Result<Self> {
        Self::with_clock(config, ledger, crypto, admin, Arc::new(SystemClock))
    }

    pub fn with_clock(
        config: TokenConfig,
        ledger: L,
        crypto: C,
        admin: AccountId,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let treasury = AccountId::new(TREASURY_ID);
        let mut gov = Governance::default();
        gov.roles.insert(admin.clone(), RoleSet::admin_bundle());
        gov.kyc.insert(admin.clone(), KycStatus::Verified);
        // The treasury is a verified system account so misdirected transfers can
        // land there and be rescued out.
        gov.kyc.insert(treasury.clone(), KycStatus::Verified);
        let svc = StablecoinService {
            config,
            ledger,
            crypto,
            clock,
            gov: Mutex::new(gov),
            treasury: treasury.clone(),
        };
        svc.ledger.register(&admin)?;
        svc.ledger.register(&treasury)?;
        Ok(svc)
    }

    /// The system treasury account id.
    pub fn treasury(&self) -> &AccountId {
        &self.treasury
    }

    // ---- authorization / compliance helpers ----

    fn require_role(&self, gov: &Governance, caller: &AccountId, role: Role) -> Result<()> {
        match gov.roles.get(caller) {
            Some(set) if set.has(role) => Ok(()),
            _ => Err(InvarError::Unauthorized(role.to_string())),
        }
    }

    fn require_any_role(&self, gov: &Governance, caller: &AccountId, roles: &[Role]) -> Result<()> {
        if roles
            .iter()
            .any(|r| gov.roles.get(caller).map(|s| s.has(*r)).unwrap_or(false))
        {
            Ok(())
        } else {
            Err(InvarError::Unauthorized(
                roles
                    .iter()
                    .map(|r| r.to_string())
                    .collect::<Vec<_>>()
                    .join("|"),
            ))
        }
    }

    fn require_verified(&self, gov: &Governance, id: &AccountId) -> Result<()> {
        match gov.kyc.get(id) {
            Some(KycStatus::Verified) => Ok(()),
            _ => Err(InvarError::NotVerified(id.to_string())),
        }
    }

    fn ensure_not_paused(&self, gov: &Governance) -> Result<()> {
        if gov.deleted {
            return Err(InvarError::TokenDeleted);
        }
        if gov.paused {
            return Err(InvarError::Paused);
        }
        Ok(())
    }

    fn consume_allowance(gov: &mut Governance, minter: &AccountId, amount: Amount) -> Result<()> {
        match gov.allowances.get_mut(minter) {
            Some(Allowance::Unlimited) => Ok(()),
            Some(Allowance::Limited(remaining)) => {
                if remaining.get() < amount.get() {
                    return Err(InvarError::AllowanceExceeded {
                        minter: minter.to_string(),
                        remaining: remaining.get(),
                        requested: amount.get(),
                    });
                }
                *remaining = remaining.checked_sub(amount)?;
                Ok(())
            }
            None => Err(InvarError::AllowanceExceeded {
                minter: minter.to_string(),
                remaining: 0,
                requested: amount.get(),
            }),
        }
    }

    fn now(&self) -> u64 {
        self.clock.now_unix()
    }

    fn make_entry(
        &self,
        kind: EntryKind,
        from: Option<AccountId>,
        to: Option<AccountId>,
        amount: Amount,
    ) -> LedgerEntry {
        LedgerEntry {
            id: uuid::Uuid::new_v4().to_string(),
            kind,
            from,
            to,
            amount,
            as_of_unix: self.now(),
        }
    }

    // ---- privileged supply operations ----

    /// Mint new units to a holder. Enforces the peg (`total_supply + amount ≤
    /// reserve`) and the caller's cash-in allowance (Admins are exempt).
    pub fn mint(&self, caller: &AccountId, to: &AccountId, amount: Amount) -> Result<LedgerEntry> {
        // Pre-checks that don't require governance state.
        if !self.ledger.is_registered(to)? {
            return Err(InvarError::NotRegistered(to.to_string()));
        }
        let new_supply = self.ledger.total_supply()?.checked_add(amount)?;
        assert_within_reserve(new_supply, self.ledger.attested_reserve()?)?;
        let mut acct = self.ledger.account(to)?;
        if acct.frozen {
            return Err(InvarError::Frozen(to.to_string()));
        }
        // Authorize and consume the caller's cash-in allowance atomically.
        {
            let mut gov = self.gov.lock().unwrap();
            self.ensure_not_paused(&gov)?;
            self.require_role(&gov, caller, Role::Minter)?;
            self.require_verified(&gov, to)?;
            let is_admin = gov
                .roles
                .get(caller)
                .map(|s| s.has(Role::Admin))
                .unwrap_or(false);
            if !is_admin {
                Self::consume_allowance(&mut gov, caller, amount)?;
            }
        }
        acct.balance = acct.balance.checked_add(amount)?;
        self.ledger.set_account(&acct)?;
        self.ledger.set_total_supply(new_supply)?;
        let entry = self.make_entry(EntryKind::Mint, None, Some(to.clone()), amount);
        self.ledger.append_entry(&entry)?;
        Ok(entry)
    }

    /// Burn units from a holder (supply-reducing, e.g. administrative correction).
    pub fn burn(
        &self,
        caller: &AccountId,
        from: &AccountId,
        amount: Amount,
    ) -> Result<LedgerEntry> {
        {
            let gov = self.gov.lock().unwrap();
            self.ensure_not_paused(&gov)?;
            self.require_role(&gov, caller, Role::Burner)?;
        }
        let mut acct = self.ledger.account(from)?;
        acct.balance = acct.balance.checked_sub(amount)?;
        let new_supply = self.ledger.total_supply()?.checked_sub(amount)?;
        self.ledger.set_account(&acct)?;
        self.ledger.set_total_supply(new_supply)?;

        let entry = self.make_entry(EntryKind::Burn, Some(from.clone()), None, amount);
        self.ledger.append_entry(&entry)?;
        Ok(entry)
    }

    /// Redeem (cash-out): burn a holder's units after off-ledger fiat settlement.
    pub fn redeem(
        &self,
        caller: &AccountId,
        from: &AccountId,
        amount: Amount,
    ) -> Result<LedgerEntry> {
        {
            let gov = self.gov.lock().unwrap();
            self.ensure_not_paused(&gov)?;
            self.require_role(&gov, caller, Role::Burner)?;
        }
        let mut acct = self.ledger.account(from)?;
        if acct.frozen {
            return Err(InvarError::Frozen(from.to_string()));
        }
        acct.balance = acct.balance.checked_sub(amount)?;
        let new_supply = self.ledger.total_supply()?.checked_sub(amount)?;
        self.ledger.set_account(&acct)?;
        self.ledger.set_total_supply(new_supply)?;

        let entry = self.make_entry(EntryKind::Redeem, Some(from.clone()), None, amount);
        self.ledger.append_entry(&entry)?;
        Ok(entry)
    }

    /// Transfer units between two holders. Both must be verified and unfrozen.
    pub fn transfer(
        &self,
        caller: &AccountId,
        from: &AccountId,
        to: &AccountId,
        amount: Amount,
    ) -> Result<LedgerEntry> {
        {
            let gov = self.gov.lock().unwrap();
            self.ensure_not_paused(&gov)?;
            if caller != from {
                self.require_role(&gov, caller, Role::Admin)?;
            }
            self.require_verified(&gov, from)?;
            self.require_verified(&gov, to)?;
        }
        let mut src = self.ledger.account(from)?;
        let mut dst = self.ledger.account(to)?;
        if src.frozen {
            return Err(InvarError::Frozen(from.to_string()));
        }
        if dst.frozen {
            return Err(InvarError::Frozen(to.to_string()));
        }
        src.balance = src.balance.checked_sub(amount)?;
        dst.balance = dst.balance.checked_add(amount)?;
        self.ledger.set_account(&src)?;
        self.ledger.set_account(&dst)?;

        let entry = self.make_entry(
            EntryKind::Transfer,
            Some(from.clone()),
            Some(to.clone()),
            amount,
        );
        self.ledger.append_entry(&entry)?;
        Ok(entry)
    }

    // ---- compliance / account controls ----

    pub fn register_account(&self, caller: &AccountId, id: &AccountId) -> Result<()> {
        {
            let gov = self.gov.lock().unwrap();
            self.require_any_role(&gov, caller, &[Role::Admin, Role::ComplianceOfficer])?;
        }
        self.ledger.register(id)
    }

    pub fn set_kyc(&self, caller: &AccountId, target: &AccountId, status: KycStatus) -> Result<()> {
        let mut gov = self.gov.lock().unwrap();
        self.require_role(&gov, caller, Role::ComplianceOfficer)?;
        gov.kyc.insert(target.clone(), status);
        Ok(())
    }

    pub fn set_frozen(
        &self,
        caller: &AccountId,
        target: &AccountId,
        frozen: bool,
    ) -> Result<LedgerEntry> {
        {
            let gov = self.gov.lock().unwrap();
            self.require_role(&gov, caller, Role::Freezer)?;
        }
        let mut acct = self.ledger.account(target)?;
        acct.frozen = frozen;
        self.ledger.set_account(&acct)?;
        let kind = if frozen {
            EntryKind::Freeze
        } else {
            EntryKind::Unfreeze
        };
        let entry = self.make_entry(kind, None, Some(target.clone()), Amount::ZERO);
        self.ledger.append_entry(&entry)?;
        Ok(entry)
    }

    /// Wipe a frozen account's balance (regulatory seizure). Requires the account
    /// to be frozen first — a two-key safeguard against a single-role seizure.
    pub fn wipe(&self, caller: &AccountId, target: &AccountId) -> Result<LedgerEntry> {
        {
            let gov = self.gov.lock().unwrap();
            self.require_role(&gov, caller, Role::Wiper)?;
        }
        let mut acct = self.ledger.account(target)?;
        if !acct.frozen {
            return Err(InvarError::InvalidState(
                "account must be frozen before it can be wiped".into(),
            ));
        }
        let amount = acct.balance;
        acct.balance = Amount::ZERO;
        let new_supply = self.ledger.total_supply()?.checked_sub(amount)?;
        self.ledger.set_account(&acct)?;
        self.ledger.set_total_supply(new_supply)?;
        let entry = self.make_entry(EntryKind::Wipe, Some(target.clone()), None, amount);
        self.ledger.append_entry(&entry)?;
        Ok(entry)
    }

    pub fn set_paused(&self, caller: &AccountId, paused: bool) -> Result<()> {
        let mut gov = self.gov.lock().unwrap();
        self.require_role(&gov, caller, Role::Pauser)?;
        gov.paused = paused;
        Ok(())
    }

    // ---- roles ----

    pub fn grant_role(&self, caller: &AccountId, target: &AccountId, role: Role) -> Result<()> {
        let mut gov = self.gov.lock().unwrap();
        self.require_role(&gov, caller, Role::Admin)?;
        gov.roles.entry(target.clone()).or_default().grant(role);
        Ok(())
    }

    pub fn revoke_role(&self, caller: &AccountId, target: &AccountId, role: Role) -> Result<()> {
        let mut gov = self.gov.lock().unwrap();
        self.require_role(&gov, caller, Role::Admin)?;
        if let Some(set) = gov.roles.get_mut(target) {
            set.revoke(role);
        }
        Ok(())
    }

    // ---- proof of reserve ----

    /// Record an attested reserve level and return a PQC-signed attestation. The
    /// caller supplies the attestor keypair (kept in an HSM/KMS in production).
    pub fn attest_reserve(
        &self,
        caller: &AccountId,
        attestor_vk: &VerifyingKey,
        attestor_sk: &SigningKey,
        reserve: Amount,
        custodian_ref: &str,
    ) -> Result<ReserveAttestation> {
        {
            let gov = self.gov.lock().unwrap();
            self.require_role(&gov, caller, Role::ReserveAttestor)?;
        }
        self.ledger.set_attested_reserve(reserve)?;
        let body = AttestationBody {
            schema: AttestationBody::SCHEMA.to_string(),
            token_symbol: self.config.symbol.clone(),
            total_supply_minor: self.ledger.total_supply()?.get(),
            attested_reserve_minor: reserve.get(),
            custodian_ref: custodian_ref.to_string(),
            as_of_unix: self.now(),
        };
        let preimage = self.crypto.canonical_json(&body.to_json())?;
        let signature = self.crypto.sign(attestor_sk, &preimage)?;
        Ok(ReserveAttestation {
            body,
            algorithm: self.crypto.signature_algorithm().to_string(),
            public_key: attestor_vk.clone(),
            signature,
        })
    }

    // ---- holds (escrow) ----

    /// Lock `amount` of `from`'s balance into a hold. Debits spendable balance now;
    /// supply is unchanged. `beneficiary` may be fixed here or supplied at execute.
    pub fn create_hold(
        &self,
        caller: &AccountId,
        from: &AccountId,
        amount: Amount,
        beneficiary: Option<AccountId>,
        expires_unix: u64,
    ) -> Result<Hold> {
        {
            let gov = self.gov.lock().unwrap();
            self.ensure_not_paused(&gov)?;
            if caller != from {
                self.require_role(&gov, caller, Role::Admin)?;
            }
            self.require_verified(&gov, from)?;
        }
        let mut acct = self.ledger.account(from)?;
        if acct.frozen {
            return Err(InvarError::Frozen(from.to_string()));
        }
        acct.balance = acct.balance.checked_sub(amount)?;
        self.ledger.set_account(&acct)?;

        let hold = Hold {
            id: uuid::Uuid::new_v4().to_string(),
            from: from.clone(),
            beneficiary: beneficiary.clone(),
            amount,
            expires_unix,
            status: HoldStatus::Active,
            created_unix: self.now(),
        };
        self.ledger.put_hold(&hold)?;
        let entry = self.make_entry(
            EntryKind::HoldCreate,
            Some(from.clone()),
            beneficiary,
            amount,
        );
        self.ledger.append_entry(&entry)?;
        Ok(hold)
    }

    /// Execute an active hold, delivering its funds to the beneficiary (or `target`
    /// if the hold had none). Authorized by the beneficiary or an Admin.
    pub fn execute_hold(
        &self,
        caller: &AccountId,
        hold_id: &str,
        target: Option<AccountId>,
    ) -> Result<LedgerEntry> {
        let mut hold = self.ledger.get_hold(hold_id)?;
        if !hold.is_active() {
            return Err(InvarError::HoldNotActive(hold_id.to_string()));
        }
        if hold.is_expired(self.now()) {
            return Err(InvarError::HoldExpired(hold_id.to_string()));
        }
        let dest = match (hold.beneficiary.clone(), target) {
            (Some(b), _) => b,
            (None, Some(t)) => t,
            (None, None) => {
                return Err(InvarError::InvalidState(
                    "hold has no beneficiary; a target must be supplied".into(),
                ))
            }
        };
        {
            let gov = self.gov.lock().unwrap();
            self.ensure_not_paused(&gov)?;
            let is_beneficiary = hold.beneficiary.as_ref() == Some(caller);
            if !is_beneficiary {
                self.require_role(&gov, caller, Role::Admin)?;
            }
        }
        let mut dst = self.ledger.account(&dest)?;
        if dst.frozen {
            return Err(InvarError::Frozen(dest.to_string()));
        }
        dst.balance = dst.balance.checked_add(hold.amount)?;
        self.ledger.set_account(&dst)?;
        hold.status = HoldStatus::Executed;
        self.ledger.put_hold(&hold)?;
        let entry = self.make_entry(
            EntryKind::HoldExecute,
            Some(hold.from.clone()),
            Some(dest),
            hold.amount,
        );
        self.ledger.append_entry(&entry)?;
        Ok(entry)
    }

    /// Release an active hold, returning its funds to the originator. Authorized by
    /// the originator or an Admin (e.g. after expiry).
    pub fn release_hold(&self, caller: &AccountId, hold_id: &str) -> Result<LedgerEntry> {
        let mut hold = self.ledger.get_hold(hold_id)?;
        if !hold.is_active() {
            return Err(InvarError::HoldNotActive(hold_id.to_string()));
        }
        {
            let gov = self.gov.lock().unwrap();
            self.ensure_not_paused(&gov)?;
            if caller != &hold.from {
                self.require_role(&gov, caller, Role::Admin)?;
            }
        }
        let mut acct = self.ledger.account(&hold.from)?;
        acct.balance = acct.balance.checked_add(hold.amount)?;
        self.ledger.set_account(&acct)?;
        hold.status = HoldStatus::Released;
        self.ledger.put_hold(&hold)?;
        let entry = self.make_entry(
            EntryKind::HoldRelease,
            None,
            Some(hold.from.clone()),
            hold.amount,
        );
        self.ledger.append_entry(&entry)?;
        Ok(entry)
    }

    // ---- token lifecycle ----

    /// Set or clear mutable token metadata (e.g. a URI to terms/attestations).
    pub fn set_metadata(&self, caller: &AccountId, metadata: Option<String>) -> Result<()> {
        let mut gov = self.gov.lock().unwrap();
        self.require_any_role(&gov, caller, &[Role::Admin, Role::Deleter])?;
        gov.metadata = metadata;
        Ok(())
    }

    /// Permanently decommission the token. All state-changing operations are
    /// rejected thereafter. Irreversible.
    pub fn delete_token(&self, caller: &AccountId) -> Result<LedgerEntry> {
        {
            let mut gov = self.gov.lock().unwrap();
            self.require_role(&gov, caller, Role::Deleter)?;
            if gov.deleted {
                return Err(InvarError::TokenDeleted);
            }
            gov.deleted = true;
        }
        let entry = self.make_entry(EntryKind::Delete, None, None, Amount::ZERO);
        self.ledger.append_entry(&entry)?;
        Ok(entry)
    }

    // ---- supply allowances ----

    /// Set (or replace) a minter's cash-in allowance. Requires Admin or SupplyAdmin.
    pub fn set_supply_allowance(
        &self,
        caller: &AccountId,
        minter: &AccountId,
        allowance: Allowance,
    ) -> Result<()> {
        let mut gov = self.gov.lock().unwrap();
        self.require_any_role(&gov, caller, &[Role::Admin, Role::SupplyAdmin])?;
        gov.allowances.insert(minter.clone(), allowance);
        Ok(())
    }

    pub fn allowance_of(&self, minter: &AccountId) -> Option<Allowance> {
        self.gov.lock().unwrap().allowances.get(minter).copied()
    }

    // ---- rescue ----

    /// Recover `amount` from the treasury (where misdirected funds accumulate) to a
    /// recipient. Requires the Rescuer role.
    pub fn rescue(
        &self,
        caller: &AccountId,
        to: &AccountId,
        amount: Amount,
    ) -> Result<LedgerEntry> {
        {
            let gov = self.gov.lock().unwrap();
            self.ensure_not_paused(&gov)?;
            self.require_role(&gov, caller, Role::Rescuer)?;
        }
        let mut treasury = self.ledger.account(&self.treasury)?;
        treasury.balance = treasury.balance.checked_sub(amount)?;
        let mut dst = self.ledger.account(to)?;
        dst.balance = dst.balance.checked_add(amount)?;
        self.ledger.set_account(&treasury)?;
        self.ledger.set_account(&dst)?;
        let entry = self.make_entry(
            EntryKind::Rescue,
            Some(self.treasury.clone()),
            Some(to.clone()),
            amount,
        );
        self.ledger.append_entry(&entry)?;
        Ok(entry)
    }

    // ---- reserve ----

    /// Directly set the attested reserve (used by the multisig executor). Requires
    /// the ReserveAttestor role.
    pub fn set_reserve(&self, caller: &AccountId, amount: Amount) -> Result<()> {
        {
            let gov = self.gov.lock().unwrap();
            self.require_role(&gov, caller, Role::ReserveAttestor)?;
        }
        self.ledger.set_attested_reserve(amount)
    }

    // ---- reserve oracle ----

    /// Pull the current reserve from an external oracle and set it as the attested
    /// reserve. Requires the ReserveAttestor role.
    pub fn sync_reserve_from_oracle(
        &self,
        caller: &AccountId,
        oracle: &dyn ReserveOracle,
    ) -> Result<Amount> {
        {
            let gov = self.gov.lock().unwrap();
            self.require_role(&gov, caller, Role::ReserveAttestor)?;
        }
        let reserve = oracle.current_reserve()?;
        self.ledger.set_attested_reserve(reserve)?;
        Ok(reserve)
    }

    // ---- queries ----

    pub fn balance_of(&self, id: &AccountId) -> Result<Amount> {
        Ok(self.ledger.account(id)?.balance)
    }
    pub fn total_supply(&self) -> Result<Amount> {
        self.ledger.total_supply()
    }
    pub fn attested_reserve(&self) -> Result<Amount> {
        self.ledger.attested_reserve()
    }
    pub fn is_paused(&self) -> bool {
        self.gov.lock().unwrap().paused
    }
    pub fn entries(&self) -> Result<Vec<LedgerEntry>> {
        self.ledger.entries()
    }
    pub fn is_deleted(&self) -> bool {
        self.gov.lock().unwrap().deleted
    }
    pub fn metadata(&self) -> Option<String> {
        self.gov.lock().unwrap().metadata.clone()
    }
    pub fn holds(&self) -> Result<Vec<Hold>> {
        self.ledger.holds()
    }
    pub fn get_hold(&self, id: &str) -> Result<Hold> {
        self.ledger.get_hold(id)
    }
    pub fn crypto(&self) -> &C {
        &self.crypto
    }
}
