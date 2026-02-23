//! ChaCha20-Poly1305 AEAD encryption/decryption.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use zeroize::Zeroizing;

use crate::error::ProtoError;

/// Encrypt plaintext using ChaCha20-Poly1305.
///
/// Returns ciphertext with 16-byte auth tag appended.
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| ProtoError::EncryptionFailed(e.to_string()))
}

/// Decrypt ciphertext using ChaCha20-Poly1305.
///
/// Input includes the 16-byte auth tag.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProtoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| ProtoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn round_trip() {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut key);
        rand::thread_rng().fill_bytes(&mut nonce);

        let plaintext = b"hello world secrets";
        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut key);
        rand::thread_rng().fill_bytes(&mut nonce);

        let ciphertext = encrypt(&key, &nonce, b"secret").unwrap();

        let mut wrong_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut wrong_key);
        assert!(decrypt(&wrong_key, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut key);
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut ciphertext = encrypt(&key, &nonce, b"secret").unwrap();
        ciphertext[0] ^= 0xff; // flip a byte
        assert!(decrypt(&key, &nonce, &ciphertext).is_err());
    }
}
