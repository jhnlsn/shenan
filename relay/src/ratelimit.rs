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
