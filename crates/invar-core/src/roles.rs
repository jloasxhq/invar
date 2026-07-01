//! Role-based access control. Mirrors the privileged-operation split common to
//! compliant stablecoins (admin, minter, burner, pauser, freezer, wiper, compliance,
//! reserve attestor) so that no single key can perform every sensitive action.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    /// Grants/revokes roles, registers accounts.
    Admin,
    /// Authorizes mint against reserve.
    Minter,
    /// Burns supply.
    Burner,
    /// Pauses/unpauses all token operations.
    Pauser,
    /// Freezes/unfreezes individual accounts.
    Freezer,
    /// Wipes a frozen account's balance (regulatory seizure).
    Wiper,
    /// Sets KYC/KYB status.
    ComplianceOfficer,
    /// Signs proof-of-reserve attestations.
    ReserveAttestor,
    /// Deletes / decommissions the token and edits token metadata.
    Deleter,
    /// Sets per-minter cash-in allowances.
    SupplyAdmin,
    /// Recovers funds misdirected to the treasury account.
    Rescuer,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RoleSet(pub BTreeSet<Role>);

impl RoleSet {
    pub fn new() -> Self {
        RoleSet(BTreeSet::new())
    }
    pub fn with(mut self, role: Role) -> Self {
        self.0.insert(role);
        self
    }
    pub fn grant(&mut self, role: Role) {
        self.0.insert(role);
    }
    pub fn revoke(&mut self, role: Role) {
        self.0.remove(&role);
    }
    pub fn has(&self, role: Role) -> bool {
        self.0.contains(&role)
    }
    /// The full set of roles held by a bootstrap administrator.
    pub fn admin_bundle() -> Self {
        let mut s = RoleSet::new();
        for r in [
            Role::Admin,
            Role::Minter,
            Role::Burner,
            Role::Pauser,
            Role::Freezer,
            Role::Wiper,
            Role::ComplianceOfficer,
            Role::ReserveAttestor,
            Role::Deleter,
            Role::SupplyAdmin,
            Role::Rescuer,
        ] {
            s.grant(r);
        }
        s
    }
}
