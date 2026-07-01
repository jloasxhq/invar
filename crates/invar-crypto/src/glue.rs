//! Deterministic "glue" around standard primitives — the composition layer that
//! must agree byte-for-byte across languages. Each function maps to a recipe in
//! `conformance/vectors.json`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use invar_core::error::{InvarError, Result};
use sha2::{Digest, Sha384};
use sha3::Sha3_256;

/// Canonical JSON encoding (RFC 8259): compact separators, key order preserved
/// (serde_json is built with `preserve_order`). This is the exact byte string
/// that gets signed.
///
/// Note: matches Python `json.dumps(separators=(",",":"))`. Non-ASCII is emitted
/// as UTF-8 (not `\uXXXX`); keep signing preimages ASCII for cross-stack parity.
pub fn canonical_json(value: &serde_json::Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| InvarError::Serialization(e.to_string()))
}

/// SHA-384 content fingerprint (FIPS 180-4).
pub fn fingerprint(data: &[u8]) -> Vec<u8> {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize().to_vec()
}

/// HKDF (RFC 5869) with SHA3-256 (FIPS 202) as the hash. `salt` empty means the
/// RFC's all-zero salt of hash-length.
pub fn hkdf_sha3_256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha3_256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .map_err(|e| InvarError::Crypto(format!("hkdf expand: {e}")))?;
    Ok(okm)
}

/// AES-256-GCM seal (NIST SP 800-38D). 12-byte nonce; the 16-byte tag is appended
/// to the ciphertext (the `aes-gcm` crate's default framing).
pub fn aes256gcm_seal(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(InvarError::Crypto("AES-256 key must be 32 bytes".into()));
    }
    if nonce.len() != 12 {
        return Err(InvarError::Crypto("GCM nonce must be 12 bytes".into()));
    }
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| InvarError::Crypto(format!("aes-gcm seal: {e}")))
}

/// AES-256-GCM open (inverse of [`aes256gcm_seal`]).
pub fn aes256gcm_open(key: &[u8], nonce: &[u8], aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct_tag, aad })
        .map_err(|e| InvarError::Crypto(format!("aes-gcm open: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_bad_key_or_nonce_length_errors() {
        assert!(aes256gcm_seal(&[0u8; 16], &[0u8; 12], b"", b"x").is_err()); // key too short
        assert!(aes256gcm_seal(&[0u8; 32], &[0u8; 8], b"", b"x").is_err()); // nonce wrong
    }

    #[test]
    fn aead_open_rejects_tampered_ciphertext() {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let mut sealed = aes256gcm_seal(&key, &nonce, b"", b"secret").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff; // corrupt the tag
        assert!(aes256gcm_open(&key, &nonce, b"", &sealed).is_err());
    }
}
