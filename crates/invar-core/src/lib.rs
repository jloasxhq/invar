//! # invar-core
//!
//! Ledger-agnostic stablecoin domain SDK. Business rules (authorization,
//! compliance, the reserve peg invariant) live here and depend only on two
//! ports — [`LedgerPort`] for persistence and [`CryptoProvider`] for signatures —
//! following the hexagonal / ports-and-adapters style.

pub mod account;
pub mod allowance;
pub mod amount;
pub mod capability;
pub mod crypto;
pub mod error;
pub mod hold;
pub mod ledger;
pub mod multisig;
pub mod reserve;
pub mod roles;
pub mod service;
pub mod token;

pub use account::{Account, AccountId, KycStatus};
pub use allowance::Allowance;
pub use amount::Amount;
pub use capability::{Capability, SignedCapability};
pub use crypto::{CryptoProvider, Signature, SigningKey, VerifyingKey};
pub use error::{InvarError, Result};
pub use hold::{Hold, HoldStatus};
pub use ledger::{EntryKind, LedgerEntry, LedgerPort};
pub use multisig::{
    Approval, MultisigController, MultisigPolicy, OpStatus, OperationRequest, PendingOp,
};
pub use reserve::{
    assert_within_reserve, AttestationBody, ManualReserveOracle, ReserveAttestation, ReserveOracle,
};
pub use roles::{Role, RoleSet};
pub use service::{Clock, StablecoinService, SystemClock, TREASURY_ID};
pub use token::TokenConfig;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // ---- in-crate mock adapters (real ones live in sibling crates) ----

    #[derive(Default)]
    struct MockState {
        accounts: HashMap<AccountId, Account>,
        supply: Amount,
        reserve: Amount,
        entries: Vec<LedgerEntry>,
        holds: HashMap<String, crate::hold::Hold>,
    }

    #[derive(Default)]
    struct MockLedger(Mutex<MockState>);

    impl LedgerPort for MockLedger {
        fn is_registered(&self, id: &AccountId) -> Result<bool> {
            Ok(self.0.lock().unwrap().accounts.contains_key(id))
        }
        fn register(&self, id: &AccountId) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .accounts
                .entry(id.clone())
                .or_insert_with(|| Account::new(id.clone()));
            Ok(())
        }
        fn account(&self, id: &AccountId) -> Result<Account> {
            self.0
                .lock()
                .unwrap()
                .accounts
                .get(id)
                .cloned()
                .ok_or_else(|| InvarError::UnknownAccount(id.to_string()))
        }
        fn set_account(&self, account: &Account) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .accounts
                .insert(account.id.clone(), account.clone());
            Ok(())
        }
        fn total_supply(&self) -> Result<Amount> {
            Ok(self.0.lock().unwrap().supply)
        }
        fn set_total_supply(&self, supply: Amount) -> Result<()> {
            self.0.lock().unwrap().supply = supply;
            Ok(())
        }
        fn attested_reserve(&self) -> Result<Amount> {
            Ok(self.0.lock().unwrap().reserve)
        }
        fn set_attested_reserve(&self, reserve: Amount) -> Result<()> {
            self.0.lock().unwrap().reserve = reserve;
            Ok(())
        }
        fn append_entry(&self, entry: &LedgerEntry) -> Result<()> {
            self.0.lock().unwrap().entries.push(entry.clone());
            Ok(())
        }
        fn entries(&self) -> Result<Vec<LedgerEntry>> {
            Ok(self.0.lock().unwrap().entries.clone())
        }
        fn put_hold(&self, hold: &crate::hold::Hold) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .holds
                .insert(hold.id.clone(), hold.clone());
            Ok(())
        }
        fn get_hold(&self, id: &str) -> Result<crate::hold::Hold> {
            self.0
                .lock()
                .unwrap()
                .holds
                .get(id)
                .cloned()
                .ok_or_else(|| InvarError::HoldNotFound(id.to_string()))
        }
        fn holds(&self) -> Result<Vec<crate::hold::Hold>> {
            Ok(self.0.lock().unwrap().holds.values().cloned().collect())
        }
    }

    /// Deterministic mock signer (NOT cryptographic — real PQC lives in invar-crypto).
    struct MockCrypto;

    fn canon(value: &serde_json::Value) -> Vec<u8> {
        fn write(v: &serde_json::Value, out: &mut String) {
            match v {
                serde_json::Value::Object(m) => {
                    let mut keys: Vec<&String> = m.keys().collect();
                    keys.sort();
                    out.push('{');
                    for (i, k) in keys.iter().enumerate() {
                        if i > 0 {
                            out.push(',');
                        }
                        out.push_str(&serde_json::to_string(k).unwrap());
                        out.push(':');
                        write(&m[*k], out);
                    }
                    out.push('}');
                }
                serde_json::Value::Array(a) => {
                    out.push('[');
                    for (i, e) in a.iter().enumerate() {
                        if i > 0 {
                            out.push(',');
                        }
                        write(e, out);
                    }
                    out.push(']');
                }
                other => out.push_str(&other.to_string()),
            }
        }
        let mut s = String::new();
        write(value, &mut s);
        s.into_bytes()
    }

    impl CryptoProvider for MockCrypto {
        fn signature_algorithm(&self) -> &'static str {
            "MOCK"
        }
        fn generate_keypair(&self) -> Result<(VerifyingKey, SigningKey)> {
            Ok((VerifyingKey(vec![7, 7, 7]), SigningKey(vec![7, 7, 7])))
        }
        fn sign(&self, sk: &SigningKey, msg: &[u8]) -> Result<Signature> {
            let mut b = sk.0.clone();
            b.extend_from_slice(msg);
            Ok(Signature(b))
        }
        fn verify(&self, vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
            let mut b = vk.0.clone();
            b.extend_from_slice(msg);
            b == sig.0
        }
        fn canonical_json(&self, value: &serde_json::Value) -> Result<Vec<u8>> {
            Ok(canon(value))
        }
        fn fingerprint(&self, data: &[u8]) -> Vec<u8> {
            data.to_vec()
        }
    }

    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn now_unix(&self) -> u64 {
            self.0
        }
    }

    type Svc = StablecoinService<MockLedger, MockCrypto>;

    fn setup() -> (Svc, AccountId) {
        let admin = AccountId::new("admin");
        let svc = StablecoinService::with_clock(
            TokenConfig::new("Test USD", "TUSD", 2),
            MockLedger::default(),
            MockCrypto,
            admin.clone(),
            Arc::new(FixedClock(1_700_000_000)),
        )
        .unwrap();
        (svc, admin)
    }

    /// Onboard a fresh, verified holder.
    fn onboard(svc: &Svc, admin: &AccountId, id: &str) -> AccountId {
        let a = AccountId::new(id);
        svc.register_account(admin, &a).unwrap();
        svc.set_kyc(admin, &a, KycStatus::Verified).unwrap();
        a
    }

    #[test]
    fn mint_within_reserve_credits_holder_and_supply() {
        let (svc, admin) = setup();
        let alice = onboard(&svc, &admin, "alice");
        // Attest reserve of 1000 before minting.
        let (vk, sk) = svc.crypto().generate_keypair().unwrap();
        svc.attest_reserve(&admin, &vk, &sk, Amount::new(1000), "bank:acct-1")
            .unwrap();

        svc.mint(&admin, &alice, Amount::new(600)).unwrap();
        assert_eq!(svc.balance_of(&alice).unwrap(), Amount::new(600));
        assert_eq!(svc.total_supply().unwrap(), Amount::new(600));
    }

    #[test]
    fn mint_beyond_reserve_breaks_peg_and_is_rejected() {
        let (svc, admin) = setup();
        let alice = onboard(&svc, &admin, "alice");
        let (vk, sk) = svc.crypto().generate_keypair().unwrap();
        svc.attest_reserve(&admin, &vk, &sk, Amount::new(500), "bank:acct-1")
            .unwrap();

        let err = svc.mint(&admin, &alice, Amount::new(600)).unwrap_err();
        assert_eq!(
            err,
            InvarError::ReserveExceeded {
                supply: 600,
                reserve: 500
            }
        );
        // No partial state change.
        assert_eq!(svc.total_supply().unwrap(), Amount::ZERO);
    }

    #[test]
    fn transfer_moves_balance_between_verified_holders() {
        let (svc, admin) = setup();
        let alice = onboard(&svc, &admin, "alice");
        let bob = onboard(&svc, &admin, "bob");
        let (vk, sk) = svc.crypto().generate_keypair().unwrap();
        svc.attest_reserve(&admin, &vk, &sk, Amount::new(1000), "bank")
            .unwrap();
        svc.mint(&admin, &alice, Amount::new(300)).unwrap();

        svc.transfer(&alice, &alice, &bob, Amount::new(120))
            .unwrap();
        assert_eq!(svc.balance_of(&alice).unwrap(), Amount::new(180));
        assert_eq!(svc.balance_of(&bob).unwrap(), Amount::new(120));
    }

    #[test]
    fn frozen_account_cannot_transfer() {
        let (svc, admin) = setup();
        let alice = onboard(&svc, &admin, "alice");
        let bob = onboard(&svc, &admin, "bob");
        let (vk, sk) = svc.crypto().generate_keypair().unwrap();
        svc.attest_reserve(&admin, &vk, &sk, Amount::new(1000), "bank")
            .unwrap();
        svc.mint(&admin, &alice, Amount::new(300)).unwrap();
        svc.set_frozen(&admin, &alice, true).unwrap();

        let err = svc
            .transfer(&alice, &alice, &bob, Amount::new(10))
            .unwrap_err();
        assert_eq!(err, InvarError::Frozen("alice".into()));
    }

    #[test]
    fn wipe_requires_frozen_then_zeroes_and_reduces_supply() {
        let (svc, admin) = setup();
        let alice = onboard(&svc, &admin, "alice");
        let (vk, sk) = svc.crypto().generate_keypair().unwrap();
        svc.attest_reserve(&admin, &vk, &sk, Amount::new(1000), "bank")
            .unwrap();
        svc.mint(&admin, &alice, Amount::new(300)).unwrap();

        // Cannot wipe an unfrozen account.
        assert!(svc.wipe(&admin, &alice).is_err());
        svc.set_frozen(&admin, &alice, true).unwrap();
        svc.wipe(&admin, &alice).unwrap();
        assert_eq!(svc.balance_of(&alice).unwrap(), Amount::ZERO);
        assert_eq!(svc.total_supply().unwrap(), Amount::ZERO);
    }

    #[test]
    fn unauthorized_mint_is_rejected() {
        let (svc, admin) = setup();
        let mallory = onboard(&svc, &admin, "mallory");
        let (vk, sk) = svc.crypto().generate_keypair().unwrap();
        svc.attest_reserve(&admin, &vk, &sk, Amount::new(1000), "bank")
            .unwrap();
        let err = svc.mint(&mallory, &mallory, Amount::new(10)).unwrap_err();
        assert_eq!(err, InvarError::Unauthorized("Minter".into()));
    }

    #[test]
    fn paused_blocks_operations() {
        let (svc, admin) = setup();
        let alice = onboard(&svc, &admin, "alice");
        let (vk, sk) = svc.crypto().generate_keypair().unwrap();
        svc.attest_reserve(&admin, &vk, &sk, Amount::new(1000), "bank")
            .unwrap();
        svc.set_paused(&admin, true).unwrap();
        assert_eq!(
            svc.mint(&admin, &alice, Amount::new(10)).unwrap_err(),
            InvarError::Paused
        );
    }

    #[test]
    fn attestation_verifies_and_reports_backing() {
        let (svc, admin) = setup();
        let (vk, sk) = svc.crypto().generate_keypair().unwrap();
        let att = svc
            .attest_reserve(&admin, &vk, &sk, Amount::new(1000), "bank:acct-1")
            .unwrap();
        assert!(att.verify(svc.crypto()).unwrap());
        assert!(att.body.is_fully_backed());
    }

    fn funded(svc: &Svc, admin: &AccountId, id: &str, amount: u128) -> AccountId {
        let a = onboard(svc, admin, id);
        let (vk, sk) = svc.crypto().generate_keypair().unwrap();
        svc.attest_reserve(admin, &vk, &sk, Amount::new(10_000_000), "bank")
            .unwrap();
        svc.mint(admin, &a, Amount::new(amount)).unwrap();
        a
    }

    #[test]
    fn hold_execute_delivers_to_beneficiary() {
        let (svc, admin) = setup();
        let alice = funded(&svc, &admin, "alice", 1000);
        let bob = onboard(&svc, &admin, "bob");

        let hold = svc
            .create_hold(&alice, &alice, Amount::new(300), Some(bob.clone()), 0)
            .unwrap();
        // Funds are locked out of alice's spendable balance immediately.
        assert_eq!(svc.balance_of(&alice).unwrap(), Amount::new(700));

        svc.execute_hold(&admin, &hold.id, None).unwrap();
        assert_eq!(svc.balance_of(&bob).unwrap(), Amount::new(300));
        // Total supply unchanged by the escrow lifecycle.
        assert_eq!(svc.total_supply().unwrap(), Amount::new(1000));
    }

    #[test]
    fn hold_release_returns_funds() {
        let (svc, admin) = setup();
        let alice = funded(&svc, &admin, "alice", 1000);
        let hold = svc
            .create_hold(&alice, &alice, Amount::new(400), None, 0)
            .unwrap();
        assert_eq!(svc.balance_of(&alice).unwrap(), Amount::new(600));
        svc.release_hold(&alice, &hold.id).unwrap();
        assert_eq!(svc.balance_of(&alice).unwrap(), Amount::new(1000));
    }

    #[test]
    fn delete_token_blocks_further_ops() {
        let (svc, admin) = setup();
        let alice = funded(&svc, &admin, "alice", 1000);
        svc.delete_token(&admin).unwrap();
        assert!(svc.is_deleted());
        assert_eq!(
            svc.mint(&admin, &alice, Amount::new(1)).unwrap_err(),
            InvarError::TokenDeleted
        );
    }

    #[test]
    fn metadata_set_and_read() {
        let (svc, admin) = setup();
        svc.set_metadata(&admin, Some("ipfs://terms".into()))
            .unwrap();
        assert_eq!(svc.metadata(), Some("ipfs://terms".to_string()));
    }

    #[test]
    fn reserve_oracle_sync_sets_attested_reserve() {
        use crate::ManualReserveOracle;
        let (svc, admin) = setup();
        let oracle = ManualReserveOracle::new("custodian-api", Amount::new(5000));
        let r = svc.sync_reserve_from_oracle(&admin, &oracle).unwrap();
        assert_eq!(r, Amount::new(5000));
        assert_eq!(svc.attested_reserve().unwrap(), Amount::new(5000));
    }

    #[test]
    fn supply_allowance_bounds_non_admin_minter() {
        use crate::Allowance;
        let (svc, admin) = setup();
        let sup = onboard(&svc, &admin, "supplier");
        svc.grant_role(&admin, &sup, Role::Minter).unwrap();
        svc.set_supply_allowance(&admin, &sup, Allowance::Limited(Amount::new(500)))
            .unwrap();
        svc.set_reserve(&admin, Amount::new(10_000)).unwrap();

        // Within allowance: ok, and allowance decrements.
        svc.mint(&sup, &sup, Amount::new(300)).unwrap();
        // Beyond remaining allowance (200 left): rejected.
        assert_eq!(
            svc.mint(&sup, &sup, Amount::new(300)).unwrap_err(),
            InvarError::AllowanceExceeded {
                minter: "supplier".into(),
                remaining: 200,
                requested: 300
            }
        );
    }

    #[test]
    fn minter_without_allowance_is_rejected() {
        let (svc, admin) = setup();
        let sup = onboard(&svc, &admin, "supplier");
        svc.grant_role(&admin, &sup, Role::Minter).unwrap();
        svc.set_reserve(&admin, Amount::new(10_000)).unwrap();
        // No allowance set for a non-admin minter -> rejected.
        assert!(matches!(
            svc.mint(&sup, &sup, Amount::new(1)).unwrap_err(),
            InvarError::AllowanceExceeded { .. }
        ));
    }

    #[test]
    fn rescue_recovers_misdirected_treasury_funds() {
        use crate::TREASURY_ID;
        let (svc, admin) = setup();
        let alice = funded(&svc, &admin, "alice", 1000);
        let bob = onboard(&svc, &admin, "bob");
        let treasury = AccountId::new(TREASURY_ID);

        // Alice misdirects 250 into the treasury.
        svc.transfer(&alice, &alice, &treasury, Amount::new(250))
            .unwrap();
        assert_eq!(svc.balance_of(&treasury).unwrap(), Amount::new(250));

        // Rescuer recovers it to bob.
        svc.rescue(&admin, &bob, Amount::new(250)).unwrap();
        assert_eq!(svc.balance_of(&bob).unwrap(), Amount::new(250));
        assert_eq!(svc.balance_of(&treasury).unwrap(), Amount::ZERO);
    }

    // ---- PQC M-of-N multisig ----

    fn signer(byte: u8) -> (VerifyingKey, SigningKey) {
        (VerifyingKey(vec![byte; 4]), SigningKey(vec![byte; 4]))
    }

    #[test]
    fn multisig_two_of_three_mint() {
        use crate::multisig::{MultisigController, MultisigPolicy, OperationRequest};

        let admin = AccountId::new("admin");
        let svc = std::sync::Arc::new(
            StablecoinService::with_clock(
                TokenConfig::new("Test USD", "TUSD", 2),
                MockLedger::default(),
                MockCrypto,
                admin.clone(),
                Arc::new(FixedClock(1_700_000_000)),
            )
            .unwrap(),
        );
        // Onboard recipient and set reserve.
        let alice = AccountId::new("alice");
        svc.register_account(&admin, &alice).unwrap();
        svc.set_kyc(&admin, &alice, KycStatus::Verified).unwrap();
        svc.set_reserve(&admin, Amount::new(10_000)).unwrap();

        // Executor holds the roles; only the controller operates it.
        let exec = AccountId::new("executor");
        svc.grant_role(&admin, &exec, Role::Minter).unwrap();
        svc.grant_role(&admin, &exec, Role::Admin).unwrap();

        let (vk1, sk1) = signer(1);
        let (vk2, sk2) = signer(2);
        let (vk3, _sk3) = signer(3);
        let policy = MultisigPolicy::new(2, vec![vk1.clone(), vk2.clone(), vk3.clone()]);
        let ctrl = MultisigController::new(svc.clone(), exec, policy);

        let op = ctrl
            .propose(OperationRequest::Mint {
                to: alice.clone(),
                amount: Amount::new(400),
            })
            .unwrap();
        let preimage = ctrl.preimage_for(&op.id).unwrap();

        // Unknown signer rejected.
        let (vk_bad, sk_bad) = signer(9);
        let sig_bad = MockCrypto.sign(&sk_bad, &preimage).unwrap();
        assert_eq!(
            ctrl.approve(&op.id, &vk_bad, &sig_bad).unwrap_err(),
            InvarError::UnknownSigner
        );

        // Bad signature rejected (vk3 with signer-1 signature bytes).
        let sig1 = MockCrypto.sign(&sk1, &preimage).unwrap();
        assert_eq!(
            ctrl.approve(&op.id, &vk3, &sig1).unwrap_err(),
            InvarError::BadSignature
        );

        // First valid approval; quorum not yet met.
        ctrl.approve(&op.id, &vk1, &sig1).unwrap();
        assert_eq!(
            ctrl.execute(&op.id).unwrap_err(),
            InvarError::QuorumNotMet { have: 1, need: 2 }
        );
        // Duplicate approval rejected.
        assert_eq!(
            ctrl.approve(&op.id, &vk1, &sig1).unwrap_err(),
            InvarError::DuplicateApproval
        );

        // Second valid approval reaches quorum; execute mints.
        let sig2 = MockCrypto.sign(&sk2, &preimage).unwrap();
        ctrl.approve(&op.id, &vk2, &sig2).unwrap();
        ctrl.execute(&op.id).unwrap();
        assert_eq!(svc.balance_of(&alice).unwrap(), Amount::new(400));

        // Re-execute rejected.
        assert_eq!(
            ctrl.execute(&op.id).unwrap_err(),
            InvarError::AlreadyExecuted(op.id.clone())
        );
    }

    // ---- capability tokens ----

    #[test]
    fn capability_issue_verify_scope_and_expiry() {
        use crate::capability::{issue, verify_scope, Capability};

        let crypto = MockCrypto;
        // Issuer keypair (mock: vk bytes == sk bytes).
        let (issuer_vk, issuer_sk) = (VerifyingKey(vec![42; 4]), SigningKey(vec![42; 4]));

        let cap = Capability::new(
            AccountId::new("ops-bot"),
            vec!["mint".into(), "attest".into()],
            2_000_000_000,
            "n1",
        );
        let signed = issue(&crypto, &issuer_sk, cap).unwrap();

        // Valid, in-scope, not expired.
        let now = 1_700_000_000;
        let ok = verify_scope(&crypto, &issuer_vk, &signed, now, "mint").unwrap();
        assert_eq!(ok.subject, AccountId::new("ops-bot"));

        // Wrong scope rejected.
        assert_eq!(
            verify_scope(&crypto, &issuer_vk, &signed, now, "delete").unwrap_err(),
            InvarError::InsufficientScope("delete".into())
        );

        // Expired rejected.
        assert_eq!(
            verify_scope(&crypto, &issuer_vk, &signed, 2_000_000_001, "mint").unwrap_err(),
            InvarError::CapabilityExpired
        );

        // Wrong issuer key rejected.
        let wrong_vk = VerifyingKey(vec![7; 4]);
        assert_eq!(
            verify_scope(&crypto, &wrong_vk, &signed, now, "mint").unwrap_err(),
            InvarError::BadSignature
        );
    }

    #[test]
    fn capability_wildcard_scope() {
        use crate::capability::{issue, verify_scope, Capability};
        let crypto = MockCrypto;
        let (vk, sk) = (VerifyingKey(vec![9; 4]), SigningKey(vec![9; 4]));
        let cap = Capability::new(AccountId::new("admin"), vec!["*".into()], 0, "n2");
        let signed = issue(&crypto, &sk, cap).unwrap();
        // Wildcard grants any scope; not_after 0 = non-expiring.
        assert!(verify_scope(&crypto, &vk, &signed, 9_999_999_999, "anything").is_ok());
    }

    /// Exercise EVERY multisig OperationRequest arm through the controller so no
    /// privileged apply() path is untested.
    #[test]
    fn multisig_covers_all_operation_types() {
        use crate::multisig::{MultisigController, MultisigPolicy, OperationRequest};

        let admin = AccountId::new("admin");
        let svc = std::sync::Arc::new(
            StablecoinService::with_clock(
                TokenConfig::new("Test USD", "TUSD", 2),
                MockLedger::default(),
                MockCrypto,
                admin.clone(),
                Arc::new(FixedClock(1_700_000_000)),
            )
            .unwrap(),
        );
        let alice = AccountId::new("alice");
        svc.register_account(&admin, &alice).unwrap();
        svc.set_kyc(&admin, &alice, KycStatus::Verified).unwrap();
        svc.set_reserve(&admin, Amount::new(100_000)).unwrap();

        let exec = AccountId::new("exec");
        for r in [
            Role::Admin,
            Role::Minter,
            Role::Burner,
            Role::Wiper,
            Role::Pauser,
            Role::ReserveAttestor,
            Role::Rescuer,
        ] {
            svc.grant_role(&admin, &exec, r).unwrap();
        }

        let (vk1, sk1) = signer(1);
        let (vk2, sk2) = signer(2);
        let ctrl = MultisigController::new(
            svc.clone(),
            exec,
            MultisigPolicy::new(2, vec![vk1.clone(), vk2.clone()]),
        );
        let run = |req: OperationRequest| {
            let op = ctrl.propose(req).unwrap();
            let pre = ctrl.preimage_for(&op.id).unwrap();
            ctrl.approve(&op.id, &vk1, &MockCrypto.sign(&sk1, &pre).unwrap())
                .unwrap();
            ctrl.approve(&op.id, &vk2, &MockCrypto.sign(&sk2, &pre).unwrap())
                .unwrap();
            ctrl.execute(&op.id).unwrap();
        };

        // Mint -> SetReserve -> Burn -> GrantRole -> Pause(on/off) -> Rescue -> Wipe
        run(OperationRequest::Mint {
            to: alice.clone(),
            amount: Amount::new(1000),
        });
        assert_eq!(svc.balance_of(&alice).unwrap(), Amount::new(1000));

        run(OperationRequest::SetReserve {
            amount: Amount::new(200_000),
        });
        assert_eq!(svc.attested_reserve().unwrap(), Amount::new(200_000));

        run(OperationRequest::Burn {
            from: alice.clone(),
            amount: Amount::new(200),
        });
        assert_eq!(svc.balance_of(&alice).unwrap(), Amount::new(800));

        run(OperationRequest::GrantRole {
            target: alice.clone(),
            role: Role::Pauser,
        });

        run(OperationRequest::Pause { paused: true });
        assert!(svc.is_paused());
        run(OperationRequest::Pause { paused: false });

        // Fund treasury (misdirect) then rescue via multisig.
        let treasury = AccountId::new(crate::TREASURY_ID);
        svc.transfer(&alice, &alice, &treasury, Amount::new(100))
            .unwrap();
        run(OperationRequest::Rescue {
            to: alice.clone(),
            amount: Amount::new(100),
        });
        assert_eq!(svc.balance_of(&alice).unwrap(), Amount::new(800));

        // Freeze then wipe via multisig.
        svc.set_frozen(&admin, &alice, true).unwrap();
        run(OperationRequest::Wipe {
            target: alice.clone(),
        });
        assert_eq!(svc.balance_of(&alice).unwrap(), Amount::ZERO);
    }

    #[test]
    fn allowance_unlimited_permits_minting() {
        use crate::Allowance;
        let (svc, admin) = setup();
        let sup = onboard(&svc, &admin, "sup");
        svc.grant_role(&admin, &sup, Role::Minter).unwrap();
        svc.set_supply_allowance(&admin, &sup, Allowance::Unlimited)
            .unwrap();
        svc.set_reserve(&admin, Amount::new(10_000)).unwrap();
        // Unlimited allowance: repeated mints succeed with no decrement.
        svc.mint(&sup, &sup, Amount::new(3000)).unwrap();
        svc.mint(&sup, &sup, Amount::new(3000)).unwrap();
        assert_eq!(svc.balance_of(&sup).unwrap(), Amount::new(6000));
        assert_eq!(svc.allowance_of(&sup), Some(Allowance::Unlimited));
    }

    #[test]
    fn execute_hold_with_target_and_no_beneficiary() {
        let (svc, admin) = setup();
        let alice = funded(&svc, &admin, "alice", 1000);
        let bob = onboard(&svc, &admin, "bob");
        // Hold with NO fixed beneficiary; executor supplies the target.
        let hold = svc
            .create_hold(&alice, &alice, Amount::new(250), None, 0)
            .unwrap();
        svc.execute_hold(&admin, &hold.id, Some(bob.clone()))
            .unwrap();
        assert_eq!(svc.balance_of(&bob).unwrap(), Amount::new(250));
        // Executing a hold with neither beneficiary nor target is an error.
        let h2 = svc
            .create_hold(&alice, &alice, Amount::new(10), None, 0)
            .unwrap();
        assert!(svc.execute_hold(&admin, &h2.id, None).is_err());
    }
}
