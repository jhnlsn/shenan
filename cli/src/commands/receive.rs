//! `shenan receive` — receive and decrypt secrets.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::dotenv;
use crate::fanout;
use crate::github;
use crate::identity;
use crate::session::Role;
use crate::storage;

pub async fn run(
    from: &str,
    out: Option<PathBuf>,
    merge: bool,
    relay_override: Option<String>,
) -> Result<()> {
    let from_username = from
        .strip_prefix("github:")
        .ok_or_else(|| anyhow::anyhow!("--from must be in format github:<username>"))?;

    // Load local identity
    let id = storage::load_identity()?
        .context("not initialized — run `shenan init` first")?;
    let signing_key = identity::load_signing_key(&PathBuf::from(&id.ssh_key_path))?;
    let config = storage::load_config()?;

    // Verify sender is trusted
    let trusted = storage::load_trusted_senders()?;
    if !trusted.senders.iter().any(|s| s.github == from_username) {
        anyhow::bail!(
            "{from_username} is not in your trusted senders list.\n\
             Add them with: shenan trust add github:{from_username}"
        );
    }

    // Fetch sender's public keys from GitHub (may be multiple)
    let sender_keys = github::fetch_ed25519_pubkeys(from_username).await?;
    let mut sender_verifying_keys = Vec::with_capacity(sender_keys.len());
    for key in &sender_keys {
        sender_verifying_keys.push(
            key.to_verifying_key()
                .map_err(|e| anyhow::anyhow!("invalid sender key: {e}"))?,
        );
    }

    // Collect all sender fingerprints for verification
    let sender_fingerprints: Vec<String> = sender_keys.iter().map(|k| k.fingerprint()).collect();

    if sender_keys.len() > 1 {
        eprintln!(
            "Sender has {} Ed25519 keys — opening parallel channels...",
            sender_keys.len()
        );
    }

    let relay_url = relay_override.unwrap_or(config.relay);

    eprintln!("Waiting for secrets from {}...", from_username);

    // Build payloads (None for receiver on each channel)
    let payloads = vec![None; sender_verifying_keys.len()];

    // Run fan-out session
    let result = fanout::fan_out_sessions(
        &relay_url,
        &signing_key,
        &id.github_username,
        &sender_verifying_keys,
        Role::Receiver,
        payloads,
    )
    .await?;

    let wire_payload = match result.result {
        crate::session::SessionResult::Received(data) => data,
        _ => unreachable!(),
    };

    // Decrypt
    let payload = shenan_proto::payload::decrypt(&wire_payload, &signing_key)
        .context("failed to decrypt payload — the sender may not have your correct public key")?;

    // Verify sender fingerprint is in the known fingerprints list
    if !sender_fingerprints.contains(&payload.sender_pubkey_fingerprint) {
        anyhow::bail!(
            "sender fingerprint mismatch: got {}, expected one of: {}",
            payload.sender_pubkey_fingerprint,
            sender_fingerprints.join(", ")
        );
    }

    // Output
    if let Some(out_path) = out {
        dotenv::write_dotenv_file(&out_path, &payload.secrets, merge)?;
        eprintln!("Wrote {} secret(s) to {}", payload.secrets.len(), out_path.display());
    } else {
        // Print to stdout
        print!("{}", dotenv::format_dotenv(&payload.secrets));
    }

    eprintln!("Received {} secret(s) from {}", payload.secrets.len(), from_username);

    Ok(())
}
