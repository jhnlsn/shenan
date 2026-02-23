//! Background state cleanup (SPEC §14.4).

use std::time::Instant;

use crate::state::SharedState;

/// Sweep expired sessions, pending channels, and stale rate limit entries.
pub async fn run_cleanup_loop(state: SharedState) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));

    loop {
        interval.tick().await;
        sweep(&state);
    }
}

fn sweep(state: &SharedState) {
    let now = Instant::now();

    // Expired authenticated sessions
    state.sessions.retain(|_, session| {
        session.expires_at > now
    });

    // Expired pending channels
    let admission_window = state.config.admission_window;
    state.pending_channels.retain(|_, pending| {
        now.duration_since(pending.arrived_at) < admission_window
    });

    // Stale rate limit entries (older than 2 minutes)
    let rl_window = std::time::Duration::from_secs(120);
    state.rate_limits.retain(|_, timestamps| {
        timestamps.retain(|t| now.duration_since(*t) < rl_window);
        !timestamps.is_empty()
    });
}
