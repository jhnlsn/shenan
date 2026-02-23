//! Client-side GitHub key fetching.

use anyhow::{Context, Result};
use shenan_proto::ssh::SshEd25519PubKey;

/// Fetch all Ed25519 public keys for a GitHub user.
pub async fn fetch_ed25519_pubkeys(username: &str) -> Result<Vec<SshEd25519PubKey>> {
    let url = format!("https://github.com/{username}.keys");
    let body = reqwest::get(&url)
        .await
        .context("failed to fetch GitHub keys")?
        .text()
        .await
        .context("failed to read response body")?;

    shenan_proto::ssh::parse_ed25519_keys_required(&body)
        .map_err(|e| anyhow::anyhow!("GitHub key error for {username}: {e}"))
}
