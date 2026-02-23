//! `shenan receive` — receive and decrypt secrets.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::dotenv;
use crate::github;
use crate::identity;
use crate::session::{self, Role};
use crate::storage;

pub async fn run(
    from: &str,
    out: Option<PathBuf>,
    merge: bool,
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

    // Fetch sender's public key from GitHub
    let sender_key = github::fetch_ed25519_pubkey(from_username).await?;
    let sender_verifying = sender_key.to_verifying_key()
        .map_err(|e| anyhow::anyhow!("invalid sender key: {e}"))?;

    eprintln!("Waiting for secrets from {}...", from_username);

    // Run session
    let wire_payload = match session::run_session(
        &config.relay,
        &signing_key,
        &id.github_username,
        &sender_verifying,
        Role::Receiver,
        None,
    )
    .await?
    {
        session::SessionResult::Received(data) => data,
        _ => unreachable!(),
    };

    // Decrypt
    let payload = shenan_proto::payload::decrypt(&wire_payload, &signing_key)
        .context("failed to decrypt payload — the sender may not have your correct public key")?;

    // Verify sender fingerprint matches trusted sender
    let expected_fingerprint = sender_key.fingerprint();
    if payload.sender_pubkey_fingerprint != expected_fingerprint {
        anyhow::bail!(
            "sender fingerprint mismatch: expected {expected_fingerprint}, got {}",
            payload.sender_pubkey_fingerprint
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
