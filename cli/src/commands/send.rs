//! `shenan send` — encrypt and transmit secrets.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::dotenv;
use crate::fanout;
use crate::github;
use crate::identity;
use crate::session::Role;
use crate::storage;

pub async fn run(
    to: &str,
    key_values: Vec<String>,
    from_file: Option<PathBuf>,
    stdin: bool,
    relay_override: Option<String>,
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

    // Fetch recipient's public keys from GitHub (may be multiple)
    let recipient_keys = github::fetch_ed25519_pubkeys(to_username).await?;
    let mut recipient_verifying_keys = Vec::with_capacity(recipient_keys.len());
    for key in &recipient_keys {
        recipient_verifying_keys.push(
            key.to_verifying_key()
                .map_err(|e| anyhow::anyhow!("invalid recipient key: {e}"))?,
        );
    }

    if recipient_keys.len() > 1 {
        eprintln!(
            "Recipient has {} Ed25519 keys — opening parallel channels...",
            recipient_keys.len()
        );
    }

    // Build sender fingerprint
    let my_fingerprint = shenan_proto::ssh::SshEd25519PubKey {
        key_bytes: signing_key.verifying_key().to_bytes(),
        wire_bytes: shenan_proto::ssh::ed25519_to_ssh_wire(&signing_key.verifying_key().to_bytes()),
        original_line: String::new(),
    }
    .fingerprint();

    // Encrypt payload separately per recipient key (each uses different DH)
    let mut payloads = Vec::with_capacity(recipient_verifying_keys.len());
    for vk in &recipient_verifying_keys {
        let payload = shenan_proto::payload::Payload::new(secrets.clone(), my_fingerprint.clone());
        let wire_payload = shenan_proto::payload::encrypt(&payload, vk)?;
        payloads.push(Some(wire_payload));
    }

    let relay_url = relay_override.unwrap_or(config.relay);

    // Run fan-out session
    let result = fanout::fan_out_sessions(
        &relay_url,
        &signing_key,
        &id.github_username,
        &recipient_verifying_keys,
        Role::Sender,
        payloads,
    )
    .await?;

    match result.result {
        crate::session::SessionResult::Delivered => {
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
        if !is_valid_env_key(key) {
            anyhow::bail!(
                "invalid key '{}' in '{}' (must match [A-Za-z_][A-Za-z0-9_]*)",
                key,
                arg
            );
        }
        map.insert(key.to_string(), value.to_string());
    }
    Ok(map)
}

fn is_valid_env_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    let mut chars = key.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::parse_key_values;

    #[test]
    fn parse_key_values_basic() {
        let args = vec!["API_KEY=abc".to_string(), "DB_URL=postgres://db".to_string()];
        let parsed = parse_key_values(&args).unwrap();
        assert_eq!(parsed["API_KEY"], "abc");
        assert_eq!(parsed["DB_URL"], "postgres://db");
    }

    #[test]
    fn parse_key_values_allows_value_with_equals() {
        let args = vec!["TOKEN=abc=def==".to_string()];
        let parsed = parse_key_values(&args).unwrap();
        assert_eq!(parsed["TOKEN"], "abc=def==");
    }

    #[test]
    fn parse_key_values_rejects_missing_equals() {
        let args = vec!["BROKEN".to_string()];
        assert!(parse_key_values(&args).is_err());
    }

    #[test]
    fn parse_key_values_rejects_empty_key() {
        let args = vec!["=value".to_string()];
        assert!(parse_key_values(&args).is_err());
    }

    #[test]
    fn parse_key_values_rejects_invalid_env_key_chars() {
        let args = vec!["BAD-KEY=value".to_string()];
        assert!(parse_key_values(&args).is_err());
    }
}
