//! HKDF-SHA256 key derivation.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Derive a 32-byte key using HKDF-SHA256.
///
/// - `ikm`: input key material
/// - `salt`: optional salt (pass `None` for nil salt per spec)
/// - `info`: context/info string
pub fn derive_key(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, output.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let ikm = b"input key material";
        let info = b"test-context";
        let k1 = derive_key(ikm, None, info);
        let k2 = derive_key(ikm, None, info);
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn different_info_different_key() {
        let ikm = b"input key material";
        let k1 = derive_key(ikm, None, b"context-a");
        let k2 = derive_key(ikm, None, b"context-b");
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn different_ikm_different_key() {
        let info = b"context";
        let k1 = derive_key(b"ikm-a", None, info);
        let k2 = derive_key(b"ikm-b", None, info);
        assert_ne!(*k1, *k2);
    }
}
