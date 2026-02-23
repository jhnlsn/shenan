//! Global relay state (SPEC §8.4 memory model).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::config::RelayConfig;

/// Unique identifier for a connection (socket address as string).
pub type ConnId = u64;

/// A handle to send messages to a connected WebSocket.
pub type WsSender = mpsc::UnboundedSender<Message>;

/// An authenticated session (§6.6).
#[derive(Debug)]
#[allow(dead_code)]
pub struct AuthenticatedSession {
    pub expires_at: Instant,
    pub sender: WsSender,
    pub peer_addr: SocketAddr,
}

/// A pending channel entry (§8.1) — first party waiting for second.
#[allow(dead_code)]
pub struct PendingChannel {
    pub proof: Vec<u8>,
    pub pubkey: Vec<u8>, // raw Ed25519 public key bytes (32)
    pub conn_id: ConnId,
    pub sender: WsSender,
    pub arrived_at: Instant,
}

/// An active pipe (§8.3) — two sockets forwarding to each other.
pub struct ActivePipe {
    pub sender_a: WsSender,
    pub sender_b: WsSender,
}

/// Pipe assignment for a connection: (pipe_id, is_side_a).
pub type PipeAssignment = (u64, bool);

/// The complete relay state. This is the *only* state the relay holds.
pub struct RelayState {
    /// Authenticated connections: conn_id → session
    pub sessions: DashMap<ConnId, AuthenticatedSession>,
    /// Pending channels: channel_token_hex → pending entry
    pub pending_channels: DashMap<String, PendingChannel>,
    /// Active pipes: pipe_id → pipe
    pub active_pipes: DashMap<u64, ActivePipe>,
    /// Pipe assignments: conn_id → (pipe_id, is_side_a)
    pub pipe_assignments: DashMap<ConnId, PipeAssignment>,
    /// Rate limit tracking: IP → list of attempt timestamps
    pub rate_limits: DashMap<SocketAddr, Vec<Instant>>,
    /// Configuration
    pub config: RelayConfig,
    /// Monotonic connection ID counter
    conn_counter: std::sync::atomic::AtomicU64,
}

impl RelayState {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            sessions: DashMap::new(),
            pending_channels: DashMap::new(),
            active_pipes: DashMap::new(),
            pipe_assignments: DashMap::new(),
            rate_limits: DashMap::new(),
            config,
            conn_counter: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn next_conn_id(&self) -> ConnId {
        self.conn_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    pub fn next_pipe_id(&self) -> u64 {
        // Reuse counter for pipe IDs — they're just unique identifiers
        self.conn_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
}

pub type SharedState = Arc<RelayState>;
