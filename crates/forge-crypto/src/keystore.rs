//! Software keystore: seal a signing key at rest under an **Argon2id-derived KEK**
//! (RFC 9106) and **AES-256-GCM** (SP 800-38D). This is the Phase-0 custody boundary
//! used before an HSM assumes the key — the key bytes never sit in plaintext at rest,
//! and the wrapping is authenticated (a wrong passphrase fails to open).
//!
//! Per project policy, key wrapping uses only an Argon2id KEK — never a reversible
//! encoding.

use forge_core::crypto::SigningKey;
use forge_core::error::{ForgeError, Result};
use serde::{Deserialize, Serialize};

use crate::glue::{aes256gcm_open, aes256gcm_seal};
use crate::kek::derive_kek;

/// A signing key sealed at rest. `salt`/`nonce` are non-secret and stored alongside
/// the ciphertext; the caller supplies random values when sealing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedKey {
    pub kdf: String,
    pub aead: String,
    #[serde(with = "hex_bytes")]
    pub salt: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Seal `sk` under `passphrase`. `salt` must be >= 8 bytes and `nonce` exactly 12;
/// both should be random and unique per sealing.
pub fn seal_signing_key(
    sk: &SigningKey,
    passphrase: &[u8],
    salt: &[u8],
    nonce: &[u8],
) -> Result<SealedKey> {
    let kek = derive_kek(passphrase, salt, 32)?;
    let ciphertext = aes256gcm_seal(&kek, nonce, b"", &sk.0)?;
    Ok(SealedKey {
        kdf: "argon2id".into(),
        aead: "aes-256-gcm".into(),
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Unseal a signing key. Returns an error if the passphrase is wrong (the GCM tag
/// fails to authenticate).
pub fn unseal_signing_key(sealed: &SealedKey, passphrase: &[u8]) -> Result<SigningKey> {
    let kek = derive_kek(passphrase, &sealed.salt, 32)?;
    let plaintext = aes256gcm_open(&kek, &sealed.nonce, b"", &sealed.ciphertext)
        .map_err(|_| ForgeError::Crypto("keystore unseal failed (wrong passphrase?)".into()))?;
    Ok(SigningKey(plaintext))
}

/// Serde helper: encode byte vectors as hex strings (transport encoding only — not a
/// security mechanism).
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::FipsPqcProvider;
    use forge_core::crypto::CryptoProvider;

    #[test]
    fn seal_unseal_roundtrip_and_sign() {
        let p = FipsPqcProvider::new();
        let (vk, sk) = p.generate_keypair().unwrap();

        let sealed =
            seal_signing_key(&sk, b"correct horse", b"a-16-byte-saltxx", &[0u8; 12]).unwrap();
        // Ciphertext is not the plaintext key.
        assert_ne!(sealed.ciphertext, sk.0);

        let unsealed = unseal_signing_key(&sealed, b"correct horse").unwrap();
        let sig = p.sign(&unsealed, b"msg").unwrap();
        assert!(
            p.verify(&vk, b"msg", &sig),
            "signature from unsealed key must verify"
        );
    }

    #[test]
    fn wrong_passphrase_fails() {
        let p = FipsPqcProvider::new();
        let (_vk, sk) = p.generate_keypair().unwrap();
        let sealed = seal_signing_key(&sk, b"right", b"a-16-byte-saltxx", &[1u8; 12]).unwrap();
        assert!(unseal_signing_key(&sealed, b"wrong").is_err());
    }

    #[test]
    fn sealed_key_serializes_to_json() {
        let p = FipsPqcProvider::new();
        let (_vk, sk) = p.generate_keypair().unwrap();
        let sealed = seal_signing_key(&sk, b"pw", b"a-16-byte-saltxx", &[2u8; 12]).unwrap();
        let json = serde_json::to_string(&sealed).unwrap();
        let back: SealedKey = serde_json::from_str(&json).unwrap();
        let unsealed = unseal_signing_key(&back, b"pw").unwrap();
        assert_eq!(unsealed.0, sk.0);
    }
}
