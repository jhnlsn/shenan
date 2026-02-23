//! Channel token derivation (SPEC §7.2).

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::crypto;
use crate::ssh;

/// Compute the current time window (floor(unix_seconds / 3600)).
pub fn current_window() -> u64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();
    secs / 3600
}

/// Derive a channel token for a given time window.
///
/// Both sender and receiver compute the same token:
/// ```text
/// shared_secret  = X25519(my_ed25519_private, other_ed25519_public)
/// ikm            = shared_secret || canonical_pubkey(sender) || canonical_pubkey(recipient)
/// channel_token  = HKDF-SHA256(ikm, salt=nil, info="shenan-channel-v1:s2r:<window>", length=32)
/// ```
pub fn derive_token(
    my_signing_key: &SigningKey,
    sender_pubkey: &VerifyingKey,
    recipient_pubkey: &VerifyingKey,
    window: u64,
) -> Zeroizing<[u8; 32]> {
    // X25519 DH: convert Ed25519 keys to X25519
    let my_x_priv = crypto::x25519::ed25519_priv_to_x25519(my_signing_key);
    let other_verifying = if my_signing_key.verifying_key() == *sender_pubkey {
        recipient_pubkey
    } else {
        sender_pubkey
    };
    let other_x_pub = crypto::x25519::ed25519_pub_to_x25519(other_verifying);
    let shared_secret = crypto::x25519::dh(&my_x_priv, &other_x_pub);

    // Build IKM: shared_secret || canonical_pubkey(sender) || canonical_pubkey(recipient)
    let sender_wire = ssh::ed25519_to_ssh_wire(&sender_pubkey.to_bytes());
    let recipient_wire = ssh::ed25519_to_ssh_wire(&recipient_pubkey.to_bytes());

    let mut ikm = Vec::with_capacity(32 + sender_wire.len() + recipient_wire.len());
    ikm.extend_from_slice(&*shared_secret);
    ikm.extend_from_slice(&sender_wire);
    ikm.extend_from_slice(&recipient_wire);

    // Info string: "shenan-channel-v1:s2r:<window>"
    let info = format!("shenan-channel-v1:s2r:{window}");

    crypto::kdf::derive_key(&ikm, None, info.as_bytes())
}

/// Sign a channel token to produce a channel proof.
///
/// `channel_proof = Sign(SHA256(channel_token), my_private_key)`
pub fn sign_token(signing_key: &SigningKey, token: &[u8; 32]) -> ed25519_dalek::Signature {
    crypto::ed25519::sign_sha256(signing_key, token)
}

/// Verify a channel proof against a channel token and public key.
pub fn verify_proof(
    verifying_key: &VerifyingKey,
    token: &[u8; 32],
    proof: &ed25519_dalek::Signature,
) -> Result<(), crate::error::ProtoError> {
    crypto::ed25519::verify_sha256(verifying_key, token, proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn both_parties_derive_same_token() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);

        let window = 123456u64;

        // Alice is sender, Bob is recipient
        let token_alice = derive_token(
            &alice,
            &alice.verifying_key(),
            &bob.verifying_key(),
            window,
        );
        let token_bob = derive_token(
            &bob,
            &alice.verifying_key(),
            &bob.verifying_key(),
            window,
        );

        assert_eq!(*token_alice, *token_bob);
    }

    #[test]
    fn different_window_different_token() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);

        let t1 = derive_token(&alice, &alice.verifying_key(), &bob.verifying_key(), 100);
        let t2 = derive_token(&alice, &alice.verifying_key(), &bob.verifying_key(), 101);

        assert_ne!(*t1, *t2);
    }

    #[test]
    fn third_party_cannot_derive() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let eve = SigningKey::generate(&mut OsRng);

        let window = 42u64;
        let real_token = derive_token(
            &alice,
            &alice.verifying_key(),
            &bob.verifying_key(),
            window,
        );
        // Eve tries to derive using her own key
        let eve_token = derive_token(
            &eve,
            &alice.verifying_key(),
            &bob.verifying_key(),
            window,
        );
        assert_ne!(*real_token, *eve_token);
    }

    #[test]
    fn proof_round_trip() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let window = 99u64;

        let token = derive_token(
            &alice,
            &alice.verifying_key(),
            &bob.verifying_key(),
            window,
        );
        let proof = sign_token(&alice, &token);
        assert!(verify_proof(&alice.verifying_key(), &token, &proof).is_ok());
        // Bob's key can't verify Alice's proof
        assert!(verify_proof(&bob.verifying_key(), &token, &proof).is_err());
    }
}
