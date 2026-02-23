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
    result: Result<SshEd25519PubKey, String>,
    fetched_at: Instant,
}

impl GitHubKeyCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: DashMap::new(),
            ttl,
        }
    }

    /// Fetch the single Ed25519 key for a GitHub user.
    ///
    /// Validates username format, fetches from GitHub, parses, and caches.
    pub async fn fetch(&self, username: &str) -> Result<SshEd25519PubKey, String> {
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

    /// Remove expired entries.
    #[allow(dead_code)]
    pub fn sweep(&self) {
        self.cache.retain(|_, entry| entry.fetched_at.elapsed() < self.ttl);
    }
}

/// Validate GitHub username: `^[a-zA-Z0-9\-]+$`
fn is_valid_github_username(username: &str) -> bool {
    !username.is_empty()
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Fetch keys from URL and parse the single Ed25519 key.
async fn fetch_and_parse(url: &str) -> Result<SshEd25519PubKey, String> {
    let body = reqwest::get(url)
        .await
        .map_err(|e| format!("fetch failed: {e}"))?
        .text()
        .await
        .map_err(|e| format!("read body failed: {e}"))?;

    shenan_proto::ssh::parse_single_ed25519(&body).map_err(|e| e.to_string())
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
    }
}
