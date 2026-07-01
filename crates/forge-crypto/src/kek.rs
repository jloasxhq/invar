//! Key-encryption-key (KEK) derivation via Argon2id (RFC 9106).
//!
//! Project policy: reversible/base64 encodings are not used for key or password
//! wrapping — only an Argon2id-derived KEK. This module derives that KEK; the
//! software keystore is sealed under it (AES-256-GCM, see [`crate::glue`]) until an
//! HSM assumes custody.

use argon2::{Algorithm, Argon2, Params, Version};
use forge_core::error::{ForgeError, Result};
use zeroize::Zeroize;

/// RFC 9106 "second recommended" option, tuned for interactive use:
/// 64 MiB memory, 3 iterations, 1 lane.
pub const M_COST_KIB: u32 = 65_536;
pub const T_COST: u32 = 3;
pub const P_COST: u32 = 1;

/// Derive a KEK of `out_len` bytes from `password` and `salt` (>= 8 bytes).
/// Deterministic for fixed inputs, so a keystore sealed under it can be reopened.
pub fn derive_kek(password: &[u8], salt: &[u8], out_len: usize) -> Result<Vec<u8>> {
    if salt.len() < 8 {
        return Err(ForgeError::Crypto(
            "Argon2id salt must be >= 8 bytes".into(),
        ));
    }
    let params = Params::new(M_COST_KIB, T_COST, P_COST, Some(out_len))
        .map_err(|e| ForgeError::Crypto(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; out_len];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| {
            out.zeroize();
            ForgeError::Crypto(format!("argon2 derive: {e}"))
        })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kek_is_deterministic_and_correct_length() {
        let a = derive_kek(b"correct horse battery staple", b"a-16-byte-saltxx", 32).unwrap();
        let b = derive_kek(b"correct horse battery staple", b"a-16-byte-saltxx", 32).unwrap();
        assert_eq!(a, b, "same inputs must yield same KEK");
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn different_salt_yields_different_kek() {
        let a = derive_kek(b"pw", b"salt-one-xxxxxxx", 32).unwrap();
        let b = derive_kek(b"pw", b"salt-two-xxxxxxx", 32).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn short_salt_rejected() {
        assert!(derive_kek(b"pw", b"short", 32).is_err());
    }
}
