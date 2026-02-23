//! IP-based rate limiting for authentication (SPEC §6.7).

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::state::SharedState;

const WINDOW: Duration = Duration::from_secs(60);

/// Check if an IP is rate-limited. Returns `true` if the request should be allowed.
pub fn check_and_record(state: &SharedState, addr: SocketAddr) -> bool {
    let ip_addr = SocketAddr::new(addr.ip(), 0); // normalize port
    let now = Instant::now();
    let max = state.config.rate_limit_auth;

    let mut entry = state.rate_limits.entry(ip_addr).or_default();
    // Prune old entries outside the window
    entry.retain(|t| now.duration_since(*t) < WINDOW);

    if entry.len() >= max as usize {
        return false;
    }

    entry.push(now);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::config::RelayConfig;
    use crate::state::RelayState;

    fn state_with_limit(limit: u32) -> SharedState {
        Arc::new(RelayState::new(RelayConfig {
            bind: "127.0.0.1:0".into(),
            tls_cert: None,
            tls_key: None,
            admission_window: Duration::from_secs(30),
            session_expiry: Duration::from_secs(60),
            max_payload_size: 1024,
            rate_limit_auth: limit,
            log_level: "warn".into(),
        }))
    }

    #[test]
    fn rate_limit_blocks_after_max_attempts() {
        let state = state_with_limit(2);
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(check_and_record(&state, addr));
        assert!(check_and_record(&state, addr));
        assert!(!check_and_record(&state, addr));
    }

    #[test]
    fn rate_limit_normalizes_ports_to_same_ip_bucket() {
        let state = state_with_limit(1);
        let a: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        assert!(check_and_record(&state, a));
        assert!(!check_and_record(&state, b));
    }
}
