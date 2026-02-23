//! Relay configuration (SPEC §11).

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "shenan-relay", about = "Shenan protocol relay server")]
pub struct RelayArgs {
    /// Address to bind (e.g. "0.0.0.0:443")
    #[arg(long, default_value = "0.0.0.0:443")]
    pub bind: String,

    /// Path to TLS certificate (PEM). Omit for plaintext WS (test mode only).
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// Path to TLS private key (PEM). Omit for plaintext WS (test mode only).
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Channel admission window in seconds.
    #[arg(long, default_value = "300")]
    pub admission_window: u64,

    /// Authenticated session expiry in seconds.
    #[arg(long, default_value = "600")]
    pub session_expiry: u64,

    /// Maximum payload size in bytes.
    #[arg(long, default_value = "1048576")]
    pub max_payload_size: usize,

    /// Auth rate limit: max attempts per IP per minute.
    #[arg(long, default_value = "10")]
    pub rate_limit_auth: u32,
}

/// Parsed configuration used throughout the relay.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub bind: String,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub admission_window: Duration,
    pub session_expiry: Duration,
    pub max_payload_size: usize,
    pub rate_limit_auth: u32,
}

impl From<RelayArgs> for RelayConfig {
    fn from(args: RelayArgs) -> Self {
        Self {
            bind: args.bind,
            tls_cert: args.tls_cert,
            tls_key: args.tls_key,
            admission_window: Duration::from_secs(args.admission_window),
            session_expiry: Duration::from_secs(args.session_expiry),
            max_payload_size: args.max_payload_size,
            rate_limit_auth: args.rate_limit_auth,
        }
    }
}
