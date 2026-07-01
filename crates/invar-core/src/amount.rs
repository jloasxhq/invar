//! Fixed-point token amounts, held in integer minor units (like cents) to avoid
//! floating-point drift. `u128` gives headroom far beyond any realistic supply.

use crate::error::{InvarError, Result};
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Amount(pub u128);

impl Amount {
    pub const ZERO: Amount = Amount(0);

    pub const fn new(minor_units: u128) -> Self {
        Amount(minor_units)
    }

    pub const fn get(self) -> u128 {
        self.0
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Checked addition — errors on overflow rather than wrapping.
    pub fn checked_add(self, other: Amount) -> Result<Amount> {
        self.0
            .checked_add(other.0)
            .map(Amount)
            .ok_or(InvarError::AmountOverflow)
    }

    /// Checked subtraction — errors if it would go negative (insufficient funds).
    pub fn checked_sub(self, other: Amount) -> Result<Amount> {
        self.0
            .checked_sub(other.0)
            .map(Amount)
            .ok_or(InvarError::InsufficientBalance)
    }
}

impl std::fmt::Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_sub() {
        assert_eq!(Amount(5).checked_add(Amount(3)).unwrap(), Amount(8));
        assert_eq!(Amount(5).checked_sub(Amount(3)).unwrap(), Amount(2));
    }

    #[test]
    fn overflow_is_error() {
        assert_eq!(
            Amount(u128::MAX).checked_add(Amount(1)),
            Err(InvarError::AmountOverflow)
        );
    }

    #[test]
    fn underflow_is_insufficient_balance() {
        assert_eq!(
            Amount(1).checked_sub(Amount(2)),
            Err(InvarError::InsufficientBalance)
        );
    }
}
