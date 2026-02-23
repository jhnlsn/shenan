//! OpenSSH key parsing — extract Ed25519 keys from authorized_keys format.

use base64::Engine;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::error::ProtoError;

/// An Ed25519 public key parsed from SSH authorized_keys format.
#[derive(Debug, Clone)]
pub struct SshEd25519PubKey {
    /// The raw 32-byte Ed25519 public key.
    pub key_bytes: [u8; 32],
    /// The full SSH wire format blob (type string + key data).
    pub wire_bytes: Vec<u8>,
    /// The original line from authorized_keys.
    pub original_line: String,
}

impl SshEd25519PubKey {
    /// SHA256 fingerprint in the format `SHA256:<base64>`.
    pub fn fingerprint(&self) -> String {
        let hash = Sha256::digest(&self.wire_bytes);
        let b64 = base64::engine::general_purpose::STANDARD.encode(hash);
        // Trim trailing '=' to match OpenSSH format
        let trimmed = b64.trim_end_matches('=');
        format!("SHA256:{trimmed}")
    }

    /// Convert to an ed25519-dalek VerifyingKey.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey, ProtoError> {
        VerifyingKey::from_bytes(&self.key_bytes)
            .map_err(|e| ProtoError::InvalidKeyFormat(e.to_string()))
    }
}

/// Parse an OpenSSH authorized_keys response and extract all Ed25519 keys.
///
/// Returns an error if zero Ed25519 keys are found. Multiple keys are supported.
pub fn parse_ed25519_keys_required(
    authorized_keys: &str,
) -> Result<Vec<SshEd25519PubKey>, ProtoError> {
    let keys = parse_ed25519_keys(authorized_keys)?;
    if keys.is_empty() {
        return Err(ProtoError::NoEd25519Key);
    }
    Ok(keys)
}

/// Parse all Ed25519 keys from an authorized_keys string.
pub fn parse_ed25519_keys(authorized_keys: &str) -> Result<Vec<SshEd25519PubKey>, ProtoError> {
    let mut keys = Vec::new();

    for line in authorized_keys.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // authorized_keys format: <key-type> <base64-blob> [comment]
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            continue;
        }

        if parts[0] != "ssh-ed25519" {
            continue;
        }

        let wire_bytes = base64::engine::general_purpose::STANDARD
            .decode(parts[1])
            .map_err(|e| ProtoError::InvalidSshKey(e.to_string()))?;

        // SSH wire format for ed25519: 4-byte length + "ssh-ed25519" + 4-byte length + 32-byte key
        let key_bytes = extract_ed25519_from_wire(&wire_bytes)?;

        keys.push(SshEd25519PubKey {
            key_bytes,
            wire_bytes,
            original_line: line.to_string(),
        });
    }

    Ok(keys)
}

/// Extract the raw 32-byte Ed25519 public key from SSH wire format.
fn extract_ed25519_from_wire(wire: &[u8]) -> Result<[u8; 32], ProtoError> {
    let mut pos = 0;

    // Read key type string length
    if wire.len() < 4 {
        return Err(ProtoError::InvalidSshKey("too short".into()));
    }
    let type_len = u32::from_be_bytes(wire[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;

    if wire.len() < pos + type_len {
        return Err(ProtoError::InvalidSshKey("truncated type".into()));
    }
    let key_type = std::str::from_utf8(&wire[pos..pos + type_len])
        .map_err(|_| ProtoError::InvalidSshKey("invalid type string".into()))?;
    pos += type_len;

    if key_type != "ssh-ed25519" {
        return Err(ProtoError::InvalidSshKey(format!(
            "expected ssh-ed25519, got {key_type}"
        )));
    }

    // Read key data length
    if wire.len() < pos + 4 {
        return Err(ProtoError::InvalidSshKey("truncated key length".into()));
    }
    let key_len = u32::from_be_bytes(wire[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;

    if key_len != 32 {
        return Err(ProtoError::InvalidSshKey(format!(
            "expected 32-byte key, got {key_len}"
        )));
    }

    if wire.len() < pos + 32 {
        return Err(ProtoError::InvalidSshKey("truncated key data".into()));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&wire[pos..pos + 32]);
    Ok(key)
}

/// Build SSH wire format bytes from a raw 32-byte Ed25519 public key.
pub fn ed25519_to_ssh_wire(key_bytes: &[u8; 32]) -> Vec<u8> {
    let key_type = b"ssh-ed25519";
    let mut wire = Vec::with_capacity(4 + key_type.len() + 4 + 32);
    wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    wire.extend_from_slice(key_type);
    wire.extend_from_slice(&32u32.to_be_bytes());
    wire.extend_from_slice(key_bytes);
    wire
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn make_test_key() -> ([u8; 32], String) {
        // Build a valid SSH wire format blob for testing
        let key_bytes = [42u8; 32];
        let wire = ed25519_to_ssh_wire(&key_bytes);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&wire);
        let line = format!("ssh-ed25519 {b64} test@example.com");
        (key_bytes, line)
    }

    #[test]
    fn parse_single_key() {
        let (expected_key, line) = make_test_key();
        let keys = parse_ed25519_keys_required(&line).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_bytes, expected_key);
    }

    #[test]
    fn parse_skips_non_ed25519() {
        let (_, ed_line) = make_test_key();
        let input = format!("ssh-rsa AAAA fake@example.com\n{ed_line}");
        let keys = parse_ed25519_keys_required(&input).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_bytes, [42u8; 32]);
    }

    #[test]
    fn parse_accepts_multiple() {
        let (_, line1) = make_test_key();
        let key_bytes_2 = [99u8; 32];
        let wire_2 = ed25519_to_ssh_wire(&key_bytes_2);
        let b64_2 = base64::engine::general_purpose::STANDARD.encode(&wire_2);
        let line2 = format!("ssh-ed25519 {b64_2} second@example.com");
        let input = format!("{line1}\n{line2}");
        let keys = parse_ed25519_keys_required(&input).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].key_bytes, [42u8; 32]);
        assert_eq!(keys[1].key_bytes, key_bytes_2);
    }

    #[test]
    fn parse_rejects_none() {
        let input = "ssh-rsa AAAA fake@host\n# comment\n";
        assert!(matches!(
            parse_ed25519_keys_required(input),
            Err(ProtoError::NoEd25519Key)
        ));
    }

    #[test]
    fn fingerprint_format() {
        let (_, line) = make_test_key();
        let keys = parse_ed25519_keys_required(&line).unwrap();
        let fp = keys[0].fingerprint();
        assert!(fp.starts_with("SHA256:"));
    }

    #[test]
    fn wire_round_trip() {
        let key_bytes = [7u8; 32];
        let wire = ed25519_to_ssh_wire(&key_bytes);
        let extracted = extract_ed25519_from_wire(&wire).unwrap();
        assert_eq!(extracted, key_bytes);
    }

    #[test]
    fn invalid_base64_rejected() {
        let line = "ssh-ed25519 !!!not-base64!!! attacker@test";
        assert!(matches!(
            parse_ed25519_keys_required(line),
            Err(ProtoError::InvalidSshKey(_))
        ));
    }

    #[test]
    fn truncated_wire_rejected() {
        let b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 3]);
        let line = format!("ssh-ed25519 {b64}");
        assert!(matches!(
            parse_ed25519_keys_required(&line),
            Err(ProtoError::InvalidSshKey(_))
        ));
    }

    #[test]
    fn wrong_wire_key_type_rejected() {
        let key_type = b"ssh-rsa";
        let mut wire = Vec::new();
        wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        wire.extend_from_slice(key_type);
        wire.extend_from_slice(&32u32.to_be_bytes());
        wire.extend_from_slice(&[9u8; 32]);

        let b64 = base64::engine::general_purpose::STANDARD.encode(wire);
        let line = format!("ssh-ed25519 {b64} wrong-type@test");

        assert!(matches!(
            parse_ed25519_keys_required(&line),
            Err(ProtoError::InvalidSshKey(_))
        ));
    }

    #[test]
    fn wrong_key_length_rejected() {
        let key_type = b"ssh-ed25519";
        let mut wire = Vec::new();
        wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        wire.extend_from_slice(key_type);
        wire.extend_from_slice(&31u32.to_be_bytes());
        wire.extend_from_slice(&[1u8; 31]);

        let b64 = base64::engine::general_purpose::STANDARD.encode(wire);
        let line = format!("ssh-ed25519 {b64} badlen@test");
        assert!(matches!(
            parse_ed25519_keys_required(&line),
            Err(ProtoError::InvalidSshKey(_))
        ));
    }
}
