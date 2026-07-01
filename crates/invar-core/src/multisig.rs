//! Post-quantum **M-of-N multi-signature** for privileged operations.
//!
//! A privileged operation (mint, wipe, pause, reserve change, role grant, rescue)
//! is *proposed*, producing a canonical, deterministic **preimage**. Authorized
//! signers each sign that preimage with **ML-DSA-65** and submit their approval;
//! once the policy threshold of distinct valid signatures is collected, the
//! operation may be *executed*. Execution applies the operation through the domain
//! service via an `executor` account whose keys are, by construction, operated only
//! by this controller — so the quorum, not any single key, authorizes the action.
//!
//! This is the analog of studio's keyList/thresholdKey multisig, but the signatures
//! are post-quantum and verified against the same `CryptoProvider` (and thus the
//! same golden-vector canonical-JSON) as the rest of the system.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::account::AccountId;
use crate::amount::Amount;
use crate::crypto::{CryptoProvider, Signature, VerifyingKey};
use crate::error::{InvarError, Result};
use crate::ledger::LedgerPort;
use crate::roles::Role;
use crate::service::StablecoinService;

/// A privileged operation subject to multisig. Externally tagged (e.g.
/// `{"mint":{"to":"acme","amount":400000}}`) — internal tagging is avoided because
/// serde's tag buffer cannot carry the `u128` amounts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationRequest {
    Mint { to: AccountId, amount: Amount },
    Burn { from: AccountId, amount: Amount },
    Wipe { target: AccountId },
    Pause { paused: bool },
    SetReserve { amount: Amount },
    GrantRole { target: AccountId, role: Role },
    Rescue { to: AccountId, amount: Amount },
}

/// Policy: how many distinct authorized signers must approve, and who they are.
#[derive(Debug, Clone)]
pub struct MultisigPolicy {
    pub threshold: u32,
    pub signers: Vec<VerifyingKey>,
}

impl MultisigPolicy {
    pub fn new(threshold: u32, signers: Vec<VerifyingKey>) -> Self {
        MultisigPolicy { threshold, signers }
    }
    fn is_authorized(&self, vk: &VerifyingKey) -> bool {
        self.signers.iter().any(|s| s == vk)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpStatus {
    Pending,
    Executed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub signer: VerifyingKey,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingOp {
    pub id: String,
    pub request: OperationRequest,
    pub approvals: Vec<Approval>,
    pub status: OpStatus,
}

impl PendingOp {
    pub fn approval_count(&self) -> u32 {
        self.approvals.len() as u32
    }
}

pub struct MultisigController<L: LedgerPort, C: CryptoProvider> {
    svc: Arc<StablecoinService<L, C>>,
    executor: AccountId,
    policy: MultisigPolicy,
    pending: Mutex<HashMap<String, PendingOp>>,
}

impl<L: LedgerPort, C: CryptoProvider> MultisigController<L, C> {
    pub fn new(
        svc: Arc<StablecoinService<L, C>>,
        executor: AccountId,
        policy: MultisigPolicy,
    ) -> Self {
        MultisigController {
            svc,
            executor,
            policy,
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Access the underlying service for non-governed operations.
    pub fn service(&self) -> &StablecoinService<L, C> {
        &self.svc
    }

    pub fn threshold(&self) -> u32 {
        self.policy.threshold
    }

    /// The deterministic signing preimage for a request under a given op id. Signers
    /// sign exactly these bytes.
    pub fn preimage(&self, id: &str, request: &OperationRequest) -> Result<Vec<u8>> {
        let value = serde_json::json!({
            "schema": "invar.multisig-op.v1",
            "op_id": id,
            "request": serde_json::to_value(request)
                .map_err(|e| InvarError::Serialization(e.to_string()))?,
        });
        self.svc.crypto().canonical_json(&value)
    }

    /// Propose a new operation; returns the pending op (its `id` and canonical
    /// preimage are what signers need).
    pub fn propose(&self, request: OperationRequest) -> Result<PendingOp> {
        let id = uuid::Uuid::new_v4().to_string();
        let op = PendingOp {
            id: id.clone(),
            request,
            approvals: Vec::new(),
            status: OpStatus::Pending,
        };
        self.pending.lock().unwrap().insert(id.clone(), op.clone());
        Ok(op)
    }

    /// Preimage for an existing pending op.
    pub fn preimage_for(&self, id: &str) -> Result<Vec<u8>> {
        let op = self.get(id)?;
        self.preimage(id, &op.request)
    }

    /// Record a signer's approval: the signer must be authorized by the policy and
    /// the signature must verify over the operation preimage.
    pub fn approve(&self, id: &str, signer: &VerifyingKey, signature: &Signature) -> Result<()> {
        if !self.policy.is_authorized(signer) {
            return Err(InvarError::UnknownSigner);
        }
        let preimage = self.preimage_for(id)?;
        if !self.svc.crypto().verify(signer, &preimage, signature) {
            return Err(InvarError::BadSignature);
        }
        let mut pending = self.pending.lock().unwrap();
        let op = pending
            .get_mut(id)
            .ok_or_else(|| InvarError::UnknownPendingOp(id.to_string()))?;
        if op.status == OpStatus::Executed {
            return Err(InvarError::AlreadyExecuted(id.to_string()));
        }
        if op.approvals.iter().any(|a| &a.signer == signer) {
            return Err(InvarError::DuplicateApproval);
        }
        op.approvals.push(Approval {
            signer: signer.clone(),
            signature: signature.clone(),
        });
        Ok(())
    }

    /// Execute a pending op once quorum is reached, applying it via the executor.
    pub fn execute(&self, id: &str) -> Result<()> {
        let request = {
            let mut pending = self.pending.lock().unwrap();
            let op = pending
                .get_mut(id)
                .ok_or_else(|| InvarError::UnknownPendingOp(id.to_string()))?;
            if op.status == OpStatus::Executed {
                return Err(InvarError::AlreadyExecuted(id.to_string()));
            }
            let have = op.approval_count();
            if have < self.policy.threshold {
                return Err(InvarError::QuorumNotMet {
                    have,
                    need: self.policy.threshold,
                });
            }
            op.status = OpStatus::Executed;
            op.request.clone()
        };
        self.apply(request)
    }

    fn apply(&self, request: OperationRequest) -> Result<()> {
        let ex = &self.executor;
        match request {
            OperationRequest::Mint { to, amount } => {
                self.svc.mint(ex, &to, amount)?;
            }
            OperationRequest::Burn { from, amount } => {
                self.svc.burn(ex, &from, amount)?;
            }
            OperationRequest::Wipe { target } => {
                self.svc.wipe(ex, &target)?;
            }
            OperationRequest::Pause { paused } => {
                self.svc.set_paused(ex, paused)?;
            }
            OperationRequest::SetReserve { amount } => {
                self.svc.set_reserve(ex, amount)?;
            }
            OperationRequest::GrantRole { target, role } => {
                self.svc.grant_role(ex, &target, role)?;
            }
            OperationRequest::Rescue { to, amount } => {
                self.svc.rescue(ex, &to, amount)?;
            }
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<PendingOp> {
        self.pending
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| InvarError::UnknownPendingOp(id.to_string()))
    }

    pub fn pending_ops(&self) -> Vec<PendingOp> {
        self.pending.lock().unwrap().values().cloned().collect()
    }
}
