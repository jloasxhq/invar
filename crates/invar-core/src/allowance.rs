//! Per-minter cash-in allowances. A minter (other than an Admin) may only mint up
//! to its allowance — either unlimited or a decrementing limited amount — mirroring
//! stablecoin-studio's bounded/unbounded supplier model.

use crate::amount::Amount;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Allowance {
    /// No cap.
    Unlimited,
    /// Remaining mintable amount; decrements on each mint.
    Limited(Amount),
}
