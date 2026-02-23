//! Channel admission logic (SPEC §8).

use ed25519_dalek::{Signature, VerifyingKey};

use shenan_proto::channel;

/// Verify a channel proof: signature over SHA256(channel_token) using the provided pubkey.
pub fn verify_channel_proof(
    pubkey_bytes: &[u8; 32],
    token_bytes: &[u8; 32],
    proof_bytes: &[u8],
) -> Result<(), String> {
    let verifying_key = VerifyingKey::from_bytes(pubkey_bytes)
        .map_err(|e| format!("invalid pubkey: {e}"))?;

    let signature = Signature::from_slice(proof_bytes)
        .map_err(|e| format!("invalid signature: {e}"))?;

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
