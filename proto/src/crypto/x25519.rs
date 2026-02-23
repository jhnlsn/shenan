//! X25519 Diffie-Hellman and Ed25519-to-X25519 key conversion.

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

/// Convert an Ed25519 public key to X25519 (Curve25519 Montgomery form).
///
/// Uses `to_montgomery()` on the Edwards point.
pub fn ed25519_pub_to_x25519(verifying_key: &VerifyingKey) -> X25519PublicKey {
    let compressed = CompressedEdwardsY(verifying_key.to_bytes());
    let edwards = compressed
        .decompress()
        .expect("valid Ed25519 public key must decompress");
    let montgomery = edwards.to_montgomery();
    X25519PublicKey::from(montgomery.to_bytes())
}

/// Convert an Ed25519 private key to X25519 (Curve25519 scalar).
///
/// Takes SHA-512 of the seed, clamps the lower 32 bytes per RFC 7748.
pub fn ed25519_priv_to_x25519(signing_key: &SigningKey) -> Zeroizing<X25519StaticSecret> {
    let seed = signing_key.to_bytes();
    let hash = Sha512::digest(seed);

    let mut scalar = Zeroizing::new([0u8; 32]);
    scalar.copy_from_slice(&hash[..32]);
    // Clamp per RFC 7748
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    Zeroizing::new(X25519StaticSecret::from(*scalar))
}

/// Perform X25519 Diffie-Hellman key agreement.
pub fn dh(
    my_private: &X25519StaticSecret,
    their_public: &X25519PublicKey,
) -> Zeroizing<[u8; 32]> {
    let shared = my_private.diffie_hellman(their_public);
    Zeroizing::new(shared.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn dh_symmetric() {
        // Both parties derive the same shared secret
        let alice_ed = SigningKey::generate(&mut OsRng);
        let bob_ed = SigningKey::generate(&mut OsRng);

        let alice_x_priv = ed25519_priv_to_x25519(&alice_ed);
        let bob_x_priv = ed25519_priv_to_x25519(&bob_ed);

        let alice_x_pub = ed25519_pub_to_x25519(&alice_ed.verifying_key());
        let bob_x_pub = ed25519_pub_to_x25519(&bob_ed.verifying_key());

        let shared_a = dh(&alice_x_priv, &bob_x_pub);
        let shared_b = dh(&bob_x_priv, &alice_x_pub);

        assert_eq!(*shared_a, *shared_b);
    }

    #[test]
    fn different_keys_different_secret() {
        let alice_ed = SigningKey::generate(&mut OsRng);
        let bob_ed = SigningKey::generate(&mut OsRng);
        let carol_ed = SigningKey::generate(&mut OsRng);

        let alice_x_priv = ed25519_priv_to_x25519(&alice_ed);
        let bob_x_pub = ed25519_pub_to_x25519(&bob_ed.verifying_key());
        let carol_x_pub = ed25519_pub_to_x25519(&carol_ed.verifying_key());

        let shared_ab = dh(&alice_x_priv, &bob_x_pub);
        let shared_ac = dh(&alice_x_priv, &carol_x_pub);

        assert_ne!(*shared_ab, *shared_ac);
    }
}
