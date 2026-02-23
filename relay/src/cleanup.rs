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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::Message;

    use crate::config::RelayConfig;
    use crate::state::{AuthenticatedSession, PendingChannel, RelayState};

    fn make_state() -> SharedState {
        Arc::new(RelayState::new(RelayConfig {
            bind: "127.0.0.1:0".into(),
            tls_cert: None,
            tls_key: None,
            admission_window: Duration::from_secs(5),
            session_expiry: Duration::from_secs(5),
            max_payload_size: 1024,
            rate_limit_auth: 10,
            log_level: "warn".into(),
        }))
    }

    #[test]
    fn sweep_removes_expired_session_and_pending_channel() {
        let state = make_state();
        let (tx, _rx) = mpsc::unbounded_channel::<Message>();
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        state.sessions.insert(
            1,
            AuthenticatedSession {
                expires_at: Instant::now() - Duration::from_secs(1),
                sender: tx.clone(),
                peer_addr: addr,
            },
        );

        state.pending_channels.insert(
            "token".into(),
            PendingChannel {
                proof: vec![1; 64],
                pubkey: vec![2; 32],
                conn_id: 1,
                sender: tx,
                arrived_at: Instant::now() - Duration::from_secs(10),
            },
        );

        sweep(&state);

        assert!(state.sessions.is_empty());
        assert!(state.pending_channels.is_empty());
    }

    #[test]
    fn sweep_prunes_stale_rate_limit_entries() {
        let state = make_state();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        state.rate_limits.insert(
            addr,
            vec![
                Instant::now() - Duration::from_secs(130),
                Instant::now() - Duration::from_secs(1),
            ],
        );

        sweep(&state);

        let entry = state.rate_limits.get(&addr).unwrap();
        assert_eq!(entry.len(), 1);
    }
}
