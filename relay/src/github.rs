//! GitHub key fetching with validation and caching (SPEC §6.3).

use std::time::{Duration, Instant};

use dashmap::DashMap;

use shenan_proto::ssh::SshEd25519PubKey;

/// Short-TTL cache for GitHub key responses.
pub struct GitHubKeyCache {
    cache: DashMap<String, CacheEntry>,
    ttl: Duration,
}

struct CacheEntry {
    result: Result<Vec<SshEd25519PubKey>, String>,
    fetched_at: Instant,
}

impl GitHubKeyCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: DashMap::new(),
            ttl,
        }
    }

    /// Fetch all Ed25519 keys for a GitHub user.
    ///
    /// Validates username format, fetches from GitHub, parses, and caches.
    pub async fn fetch(&self, username: &str) -> Result<Vec<SshEd25519PubKey>, String> {
        // Validate username: ^[a-zA-Z0-9\-]+$
        if !is_valid_github_username(username) {
            return Err("invalid GitHub username".into());
        }

        // Check cache
        if let Some(entry) = self.cache.get(username) {
            if entry.fetched_at.elapsed() < self.ttl {
                return entry.result.clone();
            }
        }

        // Fetch from GitHub
        let url = format!("https://github.com/{username}.keys");
        let result = fetch_and_parse(&url).await;

        // Cache the result
        self.cache.insert(
            username.to_string(),
            CacheEntry {
                result: result.clone(),
                fetched_at: Instant::now(),
            },
        );

        result
    }

    /// Pre-insert keys into the cache (for testing without GitHub API).
    pub fn insert(&self, username: &str, keys: Vec<SshEd25519PubKey>) {
        self.cache.insert(
            username.to_string(),
            CacheEntry {
                result: Ok(keys),
                fetched_at: Instant::now(),
            },
        );
    }

    /// Remove expired entries.
    #[allow(dead_code)]
    pub fn sweep(&self) {
        self.cache.retain(|_, entry| entry.fetched_at.elapsed() < self.ttl);
    }
}

/// Validate GitHub username using GitHub constraints:
/// 1-39 chars, alphanumeric or single hyphens between alnum chars.
fn is_valid_github_username(username: &str) -> bool {
    if username.is_empty() || username.len() > 39 {
        return false;
    }
    if username.starts_with('-') || username.ends_with('-') {
        return false;
    }

    let mut prev_hyphen = false;
    for c in username.chars() {
        if c.is_ascii_alphanumeric() {
            prev_hyphen = false;
            continue;
        }
        if c == '-' && !prev_hyphen {
            prev_hyphen = true;
            continue;
        }
        return false;
    }

    true
}

/// Fetch keys from URL and parse all Ed25519 keys.
async fn fetch_and_parse(url: &str) -> Result<Vec<SshEd25519PubKey>, String> {
    let body = reqwest::get(url)
        .await
        .map_err(|e| format!("fetch failed: {e}"))?
        .text()
        .await
        .map_err(|e| format!("read body failed: {e}"))?;

    shenan_proto::ssh::parse_ed25519_keys_required(&body).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_usernames() {
        assert!(is_valid_github_username("alice"));
        assert!(is_valid_github_username("bob-123"));
        assert!(is_valid_github_username("A-B-C"));
    }

    #[test]
    fn invalid_usernames() {
        assert!(!is_valid_github_username(""));
        assert!(!is_valid_github_username("alice/../../etc/passwd"));
        assert!(!is_valid_github_username("user name"));
        assert!(!is_valid_github_username("user.name"));
        assert!(!is_valid_github_username("user@name"));
        assert!(!is_valid_github_username("-alice"));
        assert!(!is_valid_github_username("alice-"));
        assert!(!is_valid_github_username("a".repeat(40).as_str()));
        assert!(!is_valid_github_username("alice\nbob"));
    }
}
