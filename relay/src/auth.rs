//! Authentication state machine (SPEC §6).

use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Authentication state for a single connection.
pub enum AuthState {
    /// Waiting for `hello` message.
    AwaitingHello,
    /// Challenge sent, waiting for `auth` response.
    AwaitingAuth {
        nonce_bytes: [u8; 32],
        verifying_key: Box<VerifyingKey>,
    },
    /// Successfully authenticated.
    Authenticated,
}

/// Generate a 32-byte random nonce (§6.4).
pub fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Verify an auth signature: client signs SHA256(nonce_bytes) (§6.5).
pub fn verify_auth_signature(
    verifying_key: &VerifyingKey,
    nonce_bytes: &[u8; 32],
    signature: &Signature,
) -> bool {
    use ed25519_dalek::Verifier;
    let hash = Sha256::digest(nonce_bytes);
    verifying_key.verify(&hash, signature).is_ok()
}
