//! The concrete [`CryptoProvider`] for stablecoin-forge, backed by **ML-DSA-65**
//! (NIST FIPS 204) via the `fips204` crate, which is KAT-locked to the NIST
//! reference vectors. Signatures over reserve attestations and (future) ledger
//! checkpoints are therefore post-quantum.

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use forge_core::crypto::{CryptoProvider, Signature, SigningKey, VerifyingKey};
use forge_core::error::{ForgeError, Result};

use crate::glue;

/// FIPS/PQC provider: ML-DSA-65 signatures + deterministic glue.
#[derive(Debug, Clone, Copy, Default)]
pub struct FipsPqcProvider;

impl FipsPqcProvider {
    pub fn new() -> Self {
        FipsPqcProvider
    }
}

impl CryptoProvider for FipsPqcProvider {
    fn signature_algorithm(&self) -> &'static str {
        "ML-DSA-65"
    }

    fn generate_keypair(&self) -> Result<(VerifyingKey, SigningKey)> {
        let (pk, sk) = ml_dsa_65::try_keygen()
            .map_err(|e| ForgeError::Crypto(format!("ml-dsa keygen: {e}")))?;
        Ok((
            VerifyingKey(pk.into_bytes().to_vec()),
            SigningKey(sk.into_bytes().to_vec()),
        ))
    }

    fn sign(&self, sk: &SigningKey, msg: &[u8]) -> Result<Signature> {
        let arr = <[u8; ml_dsa_65::SK_LEN]>::try_from(sk.0.as_slice())
            .map_err(|_| ForgeError::Crypto("invalid ML-DSA-65 secret key length".into()))?;
        let key = ml_dsa_65::PrivateKey::try_from_bytes(arr)
            .map_err(|e| ForgeError::Crypto(format!("ml-dsa load sk: {e}")))?;
        let sig = key
            .try_sign(msg, &[])
            .map_err(|e| ForgeError::Crypto(format!("ml-dsa sign: {e}")))?;
        Ok(Signature(sig.to_vec()))
    }

    fn verify(&self, vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
        let Ok(pk_arr) = <[u8; ml_dsa_65::PK_LEN]>::try_from(vk.0.as_slice()) else {
            return false;
        };
        let Ok(key) = ml_dsa_65::PublicKey::try_from_bytes(pk_arr) else {
            return false;
        };
        let Ok(sig_arr) = <[u8; ml_dsa_65::SIG_LEN]>::try_from(sig.0.as_slice()) else {
            return false;
        };
        key.verify(msg, &sig_arr, &[])
    }

    fn canonical_json(&self, value: &serde_json::Value) -> Result<Vec<u8>> {
        glue::canonical_json(value)
    }

    fn fingerprint(&self, data: &[u8]) -> Vec<u8> {
        glue::fingerprint(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa_sign_verify_roundtrip() {
        let p = FipsPqcProvider::new();
        let (vk, sk) = p.generate_keypair().unwrap();
        let msg = b"reserve attestation preimage";
        let sig = p.sign(&sk, msg).unwrap();
        assert!(p.verify(&vk, msg, &sig));
        assert!(!p.verify(&vk, b"tampered", &sig));
    }

    #[test]
    fn ml_dsa_key_and_sig_sizes_match_fips204() {
        let p = FipsPqcProvider::new();
        let (vk, sk) = p.generate_keypair().unwrap();
        assert_eq!(vk.0.len(), ml_dsa_65::PK_LEN);
        assert_eq!(sk.0.len(), ml_dsa_65::SK_LEN);
        let sig = p.sign(&sk, b"x").unwrap();
        assert_eq!(sig.0.len(), ml_dsa_65::SIG_LEN);
    }
}
