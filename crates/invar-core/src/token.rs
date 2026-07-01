//! Token configuration and mutable token-wide state.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenConfig {
    pub name: String,
    pub symbol: String,
    /// Number of decimal places represented by the minor units in `Amount`.
    pub decimals: u8,
}

impl TokenConfig {
    pub fn new(name: impl Into<String>, symbol: impl Into<String>, decimals: u8) -> Self {
        TokenConfig {
            name: name.into(),
            symbol: symbol.into(),
            decimals,
        }
    }
}
