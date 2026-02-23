//! Payload encryption and decryption (SPEC §9).

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::ProtoError;

const PAYLOAD_HKDF_INFO: &[u8] = b"shenan-payload-v1";

// Wire payload layout offsets
const EPHEMERAL_PUB_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = EPHEMERAL_PUB_LEN + NONCE_LEN; // 44 bytes

/// The plaintext payload envelope (§9.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    pub version: u32,
    pub secrets: BTreeMap<String, String>,
    pub sender_pubkey_fingerprint: String,
    pub timestamp: u64,
}

impl Payload {
    /// Create a new payload with the current timestamp.
    pub fn new(secrets: BTreeMap<String, String>, sender_fingerprint: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs();
        Self {
            version: 1,
            secrets,
            sender_pubkey_fingerprint: sender_fingerprint,
            timestamp,
        }
    }
}

/// Encrypt a payload for a recipient (§9.2).
///
/// Generates a fresh ephemeral X25519 keypair for forward secrecy.
/// Returns the wire payload: `ephemeral_pub(32) || nonce(12) || ciphertext`.
pub fn encrypt(
    payload: &Payload,
    recipient_pubkey: &VerifyingKey,
) -> Result<Vec<u8>, ProtoError> {
    let plaintext = serde_json::to_vec(payload)?;

    // Generate ephemeral X25519 keypair
    let ephemeral_secret = X25519StaticSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // DH with recipient's Ed25519 public key (converted to X25519)
    let recipient_x_pub = crypto::x25519::ed25519_pub_to_x25519(recipient_pubkey);
    let shared_secret = Zeroizing::new(ephemeral_secret.diffie_hellman(&recipient_x_pub).to_bytes());

    // Derive encryption key
    let encryption_key = crypto::kdf::derive_key(&*shared_secret, None, PAYLOAD_HKDF_INFO);

    // Random nonce
    let mut nonce = Zeroizing::new([0u8; 12]);
    rand::thread_rng().fill_bytes(nonce.as_mut());

    // Encrypt
    let ciphertext = crypto::aead::encrypt(&encryption_key, &nonce, &plaintext)?;

    // Build wire payload
    let mut wire = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    wire.extend_from_slice(ephemeral_public.as_bytes());
    wire.extend_from_slice(&*nonce);
    wire.extend_from_slice(&ciphertext);

    Ok(wire)
}

/// Decrypt a wire payload (§9.3).
///
/// Uses the recipient's Ed25519 private key to perform DH with the
/// sender's ephemeral X25519 public key.
pub fn decrypt(
    wire_payload: &[u8],
    recipient_signing_key: &SigningKey,
) -> Result<Payload, ProtoError> {
    if wire_payload.len() < HEADER_LEN {
        return Err(ProtoError::PayloadTooShort {
            expected: HEADER_LEN,
            got: wire_payload.len(),
        });
    }

    // Parse wire layout
    let ephemeral_pub_bytes: [u8; 32] = wire_payload[..EPHEMERAL_PUB_LEN]
        .try_into()
        .unwrap();
    let nonce: [u8; 12] = wire_payload[EPHEMERAL_PUB_LEN..HEADER_LEN]
        .try_into()
        .unwrap();
    let ciphertext = &wire_payload[HEADER_LEN..];

    let ephemeral_pub = X25519PublicKey::from(ephemeral_pub_bytes);

    // Convert recipient's Ed25519 private key to X25519
    let recipient_x_priv = crypto::x25519::ed25519_priv_to_x25519(recipient_signing_key);
    let shared_secret = Zeroizing::new(recipient_x_priv.diffie_hellman(&ephemeral_pub).to_bytes());

    // Derive encryption key
    let encryption_key = crypto::kdf::derive_key(&*shared_secret, None, PAYLOAD_HKDF_INFO);

    // Decrypt
    let plaintext = crypto::aead::decrypt(&encryption_key, &nonce, ciphertext)?;

    let payload: Payload = serde_json::from_slice(&plaintext)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let recipient = SigningKey::generate(&mut OsRng);

        let mut secrets = BTreeMap::new();
        secrets.insert("API_KEY".into(), "sk-test123".into());
        secrets.insert("DB_URL".into(), "postgres://localhost/db".into());

        let payload = Payload::new(secrets.clone(), "SHA256:test".into());
        let wire = encrypt(&payload, &recipient.verifying_key()).unwrap();
        let decrypted = decrypt(&wire, &recipient).unwrap();

        assert_eq!(decrypted.version, 1);
        assert_eq!(decrypted.secrets, secrets);
        assert_eq!(decrypted.sender_pubkey_fingerprint, "SHA256:test");
    }

    #[test]
    fn wrong_recipient_fails() {
        let recipient = SigningKey::generate(&mut OsRng);
        let wrong = SigningKey::generate(&mut OsRng);

        let mut secrets = BTreeMap::new();
        secrets.insert("KEY".into(), "value".into());

        let payload = Payload::new(secrets, "SHA256:x".into());
        let wire = encrypt(&payload, &recipient.verifying_key()).unwrap();

        assert!(decrypt(&wire, &wrong).is_err());
    }

    #[test]
    fn truncated_payload_fails() {
        assert!(decrypt(&[0u8; 10], &SigningKey::generate(&mut OsRng)).is_err());
    }

    #[test]
    fn forward_secrecy_different_ciphertexts() {
        let recipient = SigningKey::generate(&mut OsRng);
        let mut secrets = BTreeMap::new();
        secrets.insert("K".into(), "V".into());

        let payload = Payload::new(secrets, "fp".into());
        let wire1 = encrypt(&payload, &recipient.verifying_key()).unwrap();
        let wire2 = encrypt(&payload, &recipient.verifying_key()).unwrap();

        // Each encryption uses a different ephemeral key and nonce
        assert_ne!(wire1, wire2);
        // Both decrypt correctly
        assert!(decrypt(&wire1, &recipient).is_ok());
        assert!(decrypt(&wire2, &recipient).is_ok());
    }
}
