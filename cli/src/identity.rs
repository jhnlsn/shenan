//! Local SSH key discovery — scan ~/.ssh/ for Ed25519 keys.

use std::path::PathBuf;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;

/// Discovered SSH key on disk.
#[derive(Debug, Clone)]
pub struct SshKeyFile {
    pub path: PathBuf,
    pub fingerprint: String,
}

/// Scan ~/.ssh/ for Ed25519 private key files.
pub fn discover_ed25519_keys() -> Result<Vec<SshKeyFile>> {
    let ssh_dir = dirs::home_dir()
        .context("cannot determine home directory")?
        .join(".ssh");

    if !ssh_dir.exists() {
        return Ok(Vec::new());
    }

    let mut keys = Vec::new();

    for entry in std::fs::read_dir(&ssh_dir)? {
        let entry = entry?;
        let path = entry.path();

        // Skip non-files and public keys
        if !path.is_file() || path.extension().is_some_and(|e| e == "pub") {
            continue;
        }

        // Try to parse as Ed25519 private key
        if let Ok(fingerprint) = try_read_ed25519_fingerprint(&path) {
            keys.push(SshKeyFile { path, fingerprint });
        }
    }

    Ok(keys)
}

/// Try to read an SSH private key file and return its fingerprint if it's Ed25519.
fn try_read_ed25519_fingerprint(path: &PathBuf) -> Result<String> {
    let contents = std::fs::read_to_string(path)?;

    // Use ssh-key crate to parse
    let private_key = ssh_key::PrivateKey::from_openssh(&contents)
        .context("not a valid OpenSSH private key")?;

    // Check if it's Ed25519
    if !matches!(private_key.algorithm(), ssh_key::Algorithm::Ed25519) {
        anyhow::bail!("not Ed25519");
    }

    // Get the public key fingerprint
    let pub_key = private_key.public_key();
    let fp = pub_key.fingerprint(ssh_key::HashAlg::Sha256);
    Ok(fp.to_string())
}

/// Load an Ed25519 signing key from an SSH private key file.
pub fn load_signing_key(path: &PathBuf) -> Result<SigningKey> {
    let contents = std::fs::read_to_string(path)?;
    let private_key = ssh_key::PrivateKey::from_openssh(&contents)
        .context("failed to parse SSH private key")?;

    match private_key.key_data() {
        ssh_key::private::KeypairData::Ed25519(kp) => {
            let seed = kp.private.to_bytes();
            Ok(SigningKey::from_bytes(&seed))
        }
        _ => anyhow::bail!("not an Ed25519 key"),
    }
}
