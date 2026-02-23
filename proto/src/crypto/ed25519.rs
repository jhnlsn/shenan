//! Ed25519 signing and verification.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::ProtoError;

/// Sign `SHA256(data)` with the given Ed25519 private key.
pub fn sign_sha256(signing_key: &SigningKey, data: &[u8]) -> Signature {
    let hash = Sha256::digest(data);
    signing_key.sign(&hash)
}

/// Verify a signature over `SHA256(data)` with the given Ed25519 public key.
pub fn verify_sha256(
    verifying_key: &VerifyingKey,
    data: &[u8],
    signature: &Signature,
) -> Result<(), ProtoError> {
    let hash = Sha256::digest(data);
    verifying_key
        .verify(&hash, signature)
        .map_err(|_| ProtoError::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_and_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let data = b"test nonce data";
        let sig = sign_sha256(&signing_key, data);
        assert!(verify_sha256(&verifying_key, data, &sig).is_ok());
    }

    #[test]
    fn verify_wrong_data_fails() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let sig = sign_sha256(&signing_key, b"correct data");
        assert!(verify_sha256(&verifying_key, b"wrong data", &sig).is_err());
    }

    #[test]
    fn verify_wrong_key_fails() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let other_key = SigningKey::generate(&mut OsRng);
        let data = b"test data";
        let sig = sign_sha256(&signing_key, data);
        assert!(verify_sha256(&other_key.verifying_key(), data, &sig).is_err());
    }
}
