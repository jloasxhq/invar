//! # invar-ledger-custodial
//!
//! An in-memory, double-entry **custodial** ledger implementing
//! [`invar_core::LedgerPort`]. This is the "you are the issuer/custodian" backend:
//! fiat lands with a custodian, the operator mints 1:1, holders transfer, and
//! cash-out burns. It is the reference adapter; a DLT adapter (see `go/ledger-dlt`)
//! implements the same port.
//!
//! Interior mutability (a `Mutex`) lets the ledger be shared behind an `Arc` across
//! request handlers. It additionally offers [`CustodialLedger::verify_integrity`] to
//! assert the accounting identity `sum(balances) == total_supply`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use invar_core::account::{Account, AccountId};
use invar_core::amount::Amount;
use invar_core::error::{InvarError, Result};
use invar_core::hold::Hold;
use invar_core::ledger::{LedgerEntry, LedgerPort};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
struct State {
    accounts: HashMap<AccountId, Account>,
    supply: Amount,
    reserve: Amount,
    entries: Vec<LedgerEntry>,
    holds: HashMap<String, Hold>,
}

#[derive(Default)]
pub struct CustodialLedger {
    state: Mutex<State>,
}

impl CustodialLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sum of all account balances (the "credit" side of the ledger).
    pub fn sum_balances(&self) -> Amount {
        let s = self.state.lock().unwrap();
        let total: u128 = s.accounts.values().map(|a| a.balance.get()).sum();
        Amount::new(total)
    }

    /// Persist the full ledger state to a JSON file (durable snapshot).
    pub fn save_to(&self, path: impl AsRef<Path>) -> Result<()> {
        let state = self.state.lock().unwrap();
        let json = serde_json::to_string_pretty(&*state)
            .map_err(|e| InvarError::Ledger(format!("serialize: {e}")))?;
        std::fs::write(path, json).map_err(|e| InvarError::Ledger(format!("write: {e}")))
    }

    /// Load a ledger from a JSON snapshot written by [`CustodialLedger::save_to`].
    pub fn load_from(path: impl AsRef<Path>) -> Result<Self> {
        let json =
            std::fs::read_to_string(path).map_err(|e| InvarError::Ledger(format!("read: {e}")))?;
        let state: State =
            serde_json::from_str(&json).map_err(|e| InvarError::Ledger(format!("parse: {e}")))?;
        Ok(CustodialLedger {
            state: Mutex::new(state),
        })
    }

    /// Accounting identity: total minted supply must equal the sum of balances.
    pub fn verify_integrity(&self) -> Result<()> {
        let (supply, sum) = {
            let s = self.state.lock().unwrap();
            let sum: u128 = s.accounts.values().map(|a| a.balance.get()).sum();
            (s.supply.get(), sum)
        };
        if supply != sum {
            return Err(InvarError::InvalidState(format!(
                "ledger integrity broken: supply {supply} != sum(balances) {sum}"
            )));
        }
        Ok(())
    }
}

impl LedgerPort for CustodialLedger {
    fn is_registered(&self, id: &AccountId) -> Result<bool> {
        Ok(self.state.lock().unwrap().accounts.contains_key(id))
    }

    fn register(&self, id: &AccountId) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .accounts
            .entry(id.clone())
            .or_insert_with(|| Account::new(id.clone()));
        Ok(())
    }

    fn account(&self, id: &AccountId) -> Result<Account> {
        self.state
            .lock()
            .unwrap()
            .accounts
            .get(id)
            .cloned()
            .ok_or_else(|| InvarError::UnknownAccount(id.to_string()))
    }

    fn set_account(&self, account: &Account) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .accounts
            .insert(account.id.clone(), account.clone());
        Ok(())
    }

    fn total_supply(&self) -> Result<Amount> {
        Ok(self.state.lock().unwrap().supply)
    }

    fn set_total_supply(&self, supply: Amount) -> Result<()> {
        self.state.lock().unwrap().supply = supply;
        Ok(())
    }

    fn attested_reserve(&self) -> Result<Amount> {
        Ok(self.state.lock().unwrap().reserve)
    }

    fn set_attested_reserve(&self, reserve: Amount) -> Result<()> {
        self.state.lock().unwrap().reserve = reserve;
        Ok(())
    }

    fn append_entry(&self, entry: &LedgerEntry) -> Result<()> {
        self.state.lock().unwrap().entries.push(entry.clone());
        Ok(())
    }

    fn entries(&self) -> Result<Vec<LedgerEntry>> {
        Ok(self.state.lock().unwrap().entries.clone())
    }

    fn put_hold(&self, hold: &Hold) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .holds
            .insert(hold.id.clone(), hold.clone());
        Ok(())
    }

    fn get_hold(&self, id: &str) -> Result<Hold> {
        self.state
            .lock()
            .unwrap()
            .holds
            .get(id)
            .cloned()
            .ok_or_else(|| InvarError::HoldNotFound(id.to_string()))
    }

    fn holds(&self) -> Result<Vec<Hold>> {
        Ok(self.state.lock().unwrap().holds.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use invar_core::{Amount, CryptoProvider, KycStatus, StablecoinService, TokenConfig};
    use invar_crypto::FipsPqcProvider;

    /// Full end-to-end flow with the REAL ML-DSA-65 provider and the custodial ledger.
    #[test]
    fn end_to_end_mint_transfer_redeem_with_real_pqc() {
        let admin = AccountId::new("issuer");
        let svc = StablecoinService::new(
            TokenConfig::new("Generic USD", "gUSD", 2),
            CustodialLedger::new(),
            FipsPqcProvider::new(),
            admin.clone(),
        )
        .unwrap();

        // Onboard two businesses.
        for id in ["acme", "globex"] {
            let a = AccountId::new(id);
            svc.register_account(&admin, &a).unwrap();
            svc.set_kyc(&admin, &a, KycStatus::Verified).unwrap();
        }
        let acme = AccountId::new("acme");
        let globex = AccountId::new("globex");

        // Attest a real, PQC-signed reserve of $10,000.00 (in cents) and verify it.
        let (vk, sk) = svc.crypto().generate_keypair().unwrap();
        let att = svc
            .attest_reserve(
                &admin,
                &vk,
                &sk,
                Amount::new(1_000_000),
                "custodian:acct-42",
            )
            .unwrap();
        assert_eq!(att.algorithm, "ML-DSA-65");
        assert!(att.verify(svc.crypto()).unwrap());

        // Mint $4,000 to acme, transfer $1,500 to globex, redeem $500 from globex.
        svc.mint(&admin, &acme, Amount::new(400_000)).unwrap();
        svc.transfer(&acme, &acme, &globex, Amount::new(150_000))
            .unwrap();
        svc.redeem(&admin, &globex, Amount::new(50_000)).unwrap();

        assert_eq!(svc.balance_of(&acme).unwrap(), Amount::new(250_000));
        assert_eq!(svc.balance_of(&globex).unwrap(), Amount::new(100_000));
        assert_eq!(svc.total_supply().unwrap(), Amount::new(350_000));
    }

    #[test]
    fn persistence_round_trip() {
        use invar_core::ledger::{EntryKind, LedgerEntry};

        let ledger = CustodialLedger::new();
        let acme = AccountId::new("acme");
        ledger.register(&acme).unwrap();
        let mut a = ledger.account(&acme).unwrap();
        a.balance = Amount::new(777);
        ledger.set_account(&a).unwrap();
        ledger.set_total_supply(Amount::new(777)).unwrap();
        ledger.set_attested_reserve(Amount::new(1000)).unwrap();
        ledger
            .append_entry(&LedgerEntry {
                id: "e1".into(),
                kind: EntryKind::Mint,
                from: None,
                to: Some(acme.clone()),
                amount: Amount::new(777),
                as_of_unix: 1,
            })
            .unwrap();

        let path = std::env::temp_dir().join("invar_ledger_round_trip.json");
        ledger.save_to(&path).unwrap();

        let reloaded = CustodialLedger::load_from(&path).unwrap();
        assert_eq!(reloaded.account(&acme).unwrap().balance, Amount::new(777));
        assert_eq!(reloaded.total_supply().unwrap(), Amount::new(777));
        assert_eq!(reloaded.attested_reserve().unwrap(), Amount::new(1000));
        assert_eq!(reloaded.entries().unwrap().len(), 1);
        reloaded.verify_integrity().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// End-to-end 2-of-3 multisig mint using the REAL ML-DSA-65 provider.
    #[test]
    fn multisig_mint_with_real_ml_dsa() {
        use invar_core::multisig::{MultisigController, MultisigPolicy, OperationRequest};
        use invar_core::Role;
        use std::sync::Arc;

        let admin = AccountId::new("issuer");
        let svc = Arc::new(
            StablecoinService::new(
                TokenConfig::new("Generic USD", "gUSD", 2),
                CustodialLedger::new(),
                FipsPqcProvider::new(),
                admin.clone(),
            )
            .unwrap(),
        );
        let alice = AccountId::new("acme");
        svc.register_account(&admin, &alice).unwrap();
        svc.set_kyc(&admin, &alice, KycStatus::Verified).unwrap();
        svc.set_reserve(&admin, Amount::new(1_000_000)).unwrap();

        let exec = AccountId::new("executor");
        svc.grant_role(&admin, &exec, Role::Minter).unwrap();
        svc.grant_role(&admin, &exec, Role::Admin).unwrap();

        // Three real ML-DSA-65 signer keypairs; threshold 2.
        let (vk1, sk1) = svc.crypto().generate_keypair().unwrap();
        let (vk2, sk2) = svc.crypto().generate_keypair().unwrap();
        let (vk3, _sk3) = svc.crypto().generate_keypair().unwrap();
        let policy = MultisigPolicy::new(2, vec![vk1.clone(), vk2.clone(), vk3.clone()]);
        let ctrl = MultisigController::new(svc.clone(), exec, policy);

        let op = ctrl
            .propose(OperationRequest::Mint {
                to: alice.clone(),
                amount: Amount::new(250_000),
            })
            .unwrap();
        let preimage = ctrl.preimage_for(&op.id).unwrap();

        // Two signers sign the canonical preimage with real ML-DSA-65.
        let sig1 = svc.crypto().sign(&sk1, &preimage).unwrap();
        let sig2 = svc.crypto().sign(&sk2, &preimage).unwrap();
        ctrl.approve(&op.id, &vk1, &sig1).unwrap();
        ctrl.approve(&op.id, &vk2, &sig2).unwrap();
        ctrl.execute(&op.id).unwrap();

        assert_eq!(svc.balance_of(&alice).unwrap(), Amount::new(250_000));
    }

    #[test]
    fn integrity_holds_after_operations() {
        let admin = AccountId::new("issuer");
        let ledger = std::sync::Arc::new(CustodialLedger::new());
        let svc = StablecoinService::new(
            TokenConfig::new("Generic USD", "gUSD", 2),
            ledger.clone(),
            FipsPqcProvider::new(),
            admin.clone(),
        )
        .unwrap();

        let a = AccountId::new("acme");
        svc.register_account(&admin, &a).unwrap();
        svc.set_kyc(&admin, &a, KycStatus::Verified).unwrap();
        let (vk, sk) = svc.crypto().generate_keypair().unwrap();
        svc.attest_reserve(&admin, &vk, &sk, Amount::new(1_000_000), "c")
            .unwrap();
        svc.mint(&admin, &a, Amount::new(300_000)).unwrap();

        ledger.verify_integrity().unwrap();
    }
}
