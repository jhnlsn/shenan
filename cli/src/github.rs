//! Client-side GitHub key fetching.

use anyhow::{Context, Result};
use shenan_proto::ssh::SshEd25519PubKey;

/// Fetch the single Ed25519 public key for a GitHub user.
pub async fn fetch_ed25519_pubkey(username: &str) -> Result<SshEd25519PubKey> {
    let url = format!("https://github.com/{username}.keys");
    let body = reqwest::get(&url)
        .await
        .context("failed to fetch GitHub keys")?
        .text()
        .await
        .context("failed to read response body")?;

    shenan_proto::ssh::parse_single_ed25519(&body)
        .map_err(|e| anyhow::anyhow!("GitHub key error for {username}: {e}"))
}
