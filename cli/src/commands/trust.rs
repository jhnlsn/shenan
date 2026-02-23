//! `shenan trust add/remove/list` — trusted senders management.

use anyhow::Result;
use crate::storage::{self, TrustedSender};

/// Parse "github:<username>" format.
fn parse_github_ref(s: &str) -> Result<String> {
    let username = s
        .strip_prefix("github:")
        .ok_or_else(|| anyhow::anyhow!("expected format: github:<username>"))?;
    if username.is_empty() {
        anyhow::bail!("username cannot be empty");
    }
    Ok(username.to_string())
}

pub fn add(target: &str) -> Result<()> {
    let username = parse_github_ref(target)?;
    let mut ts = storage::load_trusted_senders()?;

    if ts.senders.iter().any(|s| s.github == username) {
        eprintln!("{username} is already trusted");
        return Ok(());
    }

    ts.senders.push(TrustedSender { github: username.clone() });
    storage::save_trusted_senders(&ts)?;
    eprintln!("Added {username} to trusted senders");
    Ok(())
}

pub fn remove(target: &str) -> Result<()> {
    let username = parse_github_ref(target)?;
    let mut ts = storage::load_trusted_senders()?;

    let before = ts.senders.len();
    ts.senders.retain(|s| s.github != username);

    if ts.senders.len() == before {
        eprintln!("{username} was not in trusted senders");
    } else {
        storage::save_trusted_senders(&ts)?;
        eprintln!("Removed {username} from trusted senders");
    }

    Ok(())
}

pub fn list() -> Result<()> {
    let ts = storage::load_trusted_senders()?;

    if ts.senders.is_empty() {
        eprintln!("No trusted senders. Add one with: shenan trust add github:<username>");
        return Ok(());
    }

    for sender in &ts.senders {
        println!("github:{}", sender.github);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_github_ref;

    #[test]
    fn parse_github_ref_valid() {
        assert_eq!(parse_github_ref("github:alice-123").unwrap(), "alice-123");
    }

    #[test]
    fn parse_github_ref_rejects_missing_prefix() {
        assert!(parse_github_ref("alice").is_err());
    }

    #[test]
    fn parse_github_ref_rejects_empty_username() {
        assert!(parse_github_ref("github:").is_err());
    }

    #[test]
    fn parse_github_ref_rejects_whitespace_and_path_chars() {
        assert!(parse_github_ref("github:alice bob").is_err());
        assert!(parse_github_ref("github:alice/../../etc/passwd").is_err());
    }
}
