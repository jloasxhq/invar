//! Error type for the stablecoin domain.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ForgeError {
    #[error("amount arithmetic overflow")]
    AmountOverflow,

    #[error("insufficient balance")]
    InsufficientBalance,

    #[error("caller is not authorized for role {0}")]
    Unauthorized(String),

    #[error("token operations are paused")]
    Paused,

    #[error("account {0} is not registered (KYB onboarding required)")]
    NotRegistered(String),

    #[error("account {0} is not KYC/KYB verified")]
    NotVerified(String),

    #[error("account {0} is frozen")]
    Frozen(String),

    #[error("mint would break the peg: supply {supply} + amount would exceed attested reserve {reserve}")]
    ReserveExceeded { supply: u128, reserve: u128 },

    #[error("unknown account {0}")]
    UnknownAccount(String),

    #[error("crypto provider error: {0}")]
    Crypto(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid state: {0}")]
    InvalidState(String),

    #[error("ledger backend error: {0}")]
    Ledger(String),

    #[error("hold {0} not found")]
    HoldNotFound(String),

    #[error("hold {0} is not active")]
    HoldNotActive(String),

    #[error("hold {0} has expired")]
    HoldExpired(String),

    #[error("token is deleted; operations are disabled")]
    TokenDeleted,

    #[error("reserve oracle error: {0}")]
    Oracle(String),

    #[error(
        "minter {minter} cash-in allowance exceeded: {remaining} remaining, {requested} requested"
    )]
    AllowanceExceeded {
        minter: String,
        remaining: u128,
        requested: u128,
    },

    // ---- multisig ----
    #[error("signer is not authorized by the multisig policy")]
    UnknownSigner,

    #[error("signer has already approved this operation")]
    DuplicateApproval,

    #[error("approval signature is invalid")]
    BadSignature,

    #[error("unknown pending operation {0}")]
    UnknownPendingOp(String),

    #[error("pending operation {0} already executed")]
    AlreadyExecuted(String),

    #[error("multisig quorum not met: {have} of {need} approvals")]
    QuorumNotMet { have: u32, need: u32 },

    // ---- capabilities ----
    #[error("capability has expired")]
    CapabilityExpired,

    #[error("capability lacks required scope {0}")]
    InsufficientScope(String),

    #[error("capability is malformed: {0}")]
    MalformedCapability(String),
}

pub type Result<T> = std::result::Result<T, ForgeError>;
