//! Channel admission logic (SPEC §8).

use ed25519_dalek::{Signature, VerifyingKey};

use shenan_proto::channel;

/// Verify a channel proof: signature over SHA256(channel_token) using the provided pubkey.
pub fn verify_channel_proof(
    pubkey_bytes: &[u8; 32],
    token_bytes: &[u8; 32],
    proof_bytes: &[u8],
) -> Result<(), String> {
    let verifying_key =
        VerifyingKey::from_bytes(pubkey_bytes).map_err(|e| format!("invalid pubkey: {e}"))?;

    let signature =
        Signature::from_slice(proof_bytes).map_err(|e| format!("invalid signature: {e}"))?;

    channel::verify_proof(&verifying_key, token_bytes, &signature)
        .map_err(|e| format!("proof verification failed: {e}"))
}

/// Admission check: two distinct parties (§7.4 check_1).
pub fn admission_check(pubkey_1: &[u8], pubkey_2: &[u8]) -> Result<(), String> {
    if pubkey_1 == pubkey_2 {
        return Err("same pubkey on both sides of channel".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    #[test]
    fn verify_channel_proof_rejects_invalid_pubkey() {
        let bad_pubkey = [0u8; 32];
        let token = [1u8; 32];
        let proof = [2u8; 64];
        assert!(verify_channel_proof(&bad_pubkey, &token, &proof).is_err());
    }

    #[test]
    fn verify_channel_proof_rejects_invalid_signature_length() {
        let signer = SigningKey::generate(&mut OsRng);
        let pubkey = signer.verifying_key().to_bytes();
        let token = [1u8; 32];
        assert!(verify_channel_proof(&pubkey, &token, &[1, 2, 3]).is_err());
    }

    #[test]
    fn verify_channel_proof_accepts_valid_signature() {
        let signer = SigningKey::generate(&mut OsRng);
        let pubkey = signer.verifying_key().to_bytes();
        let token = [7u8; 32];
        let hash = Sha256::digest(token);
        let sig = signer.sign(&hash);
        assert!(verify_channel_proof(&pubkey, &token, &sig.to_bytes()).is_ok());
    }

    #[test]
    fn admission_check_rejects_identical_keys() {
        let key = vec![1u8; 32];
        assert!(admission_check(&key, &key).is_err());
    }
}
