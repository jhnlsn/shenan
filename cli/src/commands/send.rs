//! `shenan send` — encrypt and transmit secrets.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::dotenv;
use crate::github;
use crate::identity;
use crate::session::{self, Role};
use crate::storage;

pub async fn run(
    to: &str,
    key_values: Vec<String>,
    from_file: Option<PathBuf>,
    stdin: bool,
) -> Result<()> {
    let to_username = to
        .strip_prefix("github:")
        .ok_or_else(|| anyhow::anyhow!("--to must be in format github:<username>"))?;

    // Load local identity
    let id = storage::load_identity()?
        .context("not initialized — run `shenan init` first")?;
    let signing_key = identity::load_signing_key(&PathBuf::from(&id.ssh_key_path))?;
    let config = storage::load_config()?;

    // Collect secrets
    let secrets = if let Some(file_path) = from_file {
        dotenv::parse_dotenv_file(&file_path)?
    } else if stdin || key_values.is_empty() {
        // Check if stdin has data
        if atty::is(atty::Stream::Stdin) && key_values.is_empty() {
            anyhow::bail!("no secrets provided. Use KEY=value args, --from-file, or pipe via stdin");
        }
        if !key_values.is_empty() {
            parse_key_values(&key_values)?
        } else {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            dotenv::parse_dotenv(&input)?
        }
    } else {
        parse_key_values(&key_values)?
    };

    if secrets.is_empty() {
        anyhow::bail!("no secrets to send");
    }

    eprintln!("Sending {} secret(s) to {}...", secrets.len(), to_username);

    // Fetch recipient's public key from GitHub
    let recipient_key = github::fetch_ed25519_pubkey(to_username).await?;
    let recipient_verifying = recipient_key.to_verifying_key()
        .map_err(|e| anyhow::anyhow!("invalid recipient key: {e}"))?;

    // Build and encrypt payload
    let my_fingerprint = shenan_proto::ssh::SshEd25519PubKey {
        key_bytes: signing_key.verifying_key().to_bytes(),
        wire_bytes: shenan_proto::ssh::ed25519_to_ssh_wire(&signing_key.verifying_key().to_bytes()),
        original_line: String::new(),
    }
    .fingerprint();

    let payload = shenan_proto::payload::Payload::new(secrets, my_fingerprint);
    let wire_payload = shenan_proto::payload::encrypt(&payload, &recipient_verifying)?;

    // Run session
    match session::run_session(
        &config.relay,
        &signing_key,
        &id.github_username,
        &recipient_verifying,
        Role::Sender,
        Some(wire_payload),
    )
    .await?
    {
        session::SessionResult::Delivered => {
            eprintln!("Delivered successfully.");
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn parse_key_values(args: &[String]) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for arg in args {
        let (key, value) = arg
            .split_once('=')
            .with_context(|| format!("invalid format: '{arg}' (expected KEY=value)"))?;
        map.insert(key.to_string(), value.to_string());
    }
    Ok(map)
}
