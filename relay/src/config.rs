//! Relay configuration (SPEC §11).

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "shenan-relay", about = "Shenan protocol relay server")]
pub struct RelayArgs {
    /// Address to bind (e.g. "0.0.0.0:443")
    #[arg(long, default_value = "0.0.0.0:443", env = "SHENAN_BIND")]
    pub bind: String,

    /// Path to TLS certificate (PEM). Omit for plaintext WS (test mode only).
    #[arg(long, env = "SHENAN_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,

    /// Path to TLS private key (PEM). Omit for plaintext WS (test mode only).
    #[arg(long, env = "SHENAN_TLS_KEY")]
    pub tls_key: Option<PathBuf>,

    /// Channel admission window in seconds.
    #[arg(long, default_value = "300", env = "SHENAN_ADMISSION_WINDOW")]
    pub admission_window: u64,

    /// Authenticated session expiry in seconds.
    #[arg(long, default_value = "600", env = "SHENAN_SESSION_EXPIRY")]
    pub session_expiry: u64,

    /// Maximum payload size in bytes.
    #[arg(long, default_value = "1048576", env = "SHENAN_MAX_PAYLOAD_SIZE")]
    pub max_payload_size: usize,

    /// Auth rate limit: max attempts per IP per minute.
    #[arg(long, default_value = "10", env = "SHENAN_RATE_LIMIT_AUTH")]
    pub rate_limit_auth: u32,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info", env = "SHENAN_LOG")]
    pub log_level: String,
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
    pub log_level: String,
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
            log_level: args.log_level,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn relay_args_defaults_parse() {
        let args = RelayArgs::parse_from(["shenan-relay"]);
        assert_eq!(args.bind, "0.0.0.0:443");
        assert_eq!(args.admission_window, 300);
        assert_eq!(args.session_expiry, 600);
        assert_eq!(args.max_payload_size, 1_048_576);
        assert_eq!(args.rate_limit_auth, 10);
    }

    #[test]
    fn relay_args_custom_values_parse() {
        let args = RelayArgs::parse_from([
            "shenan-relay",
            "--bind",
            "127.0.0.1:9000",
            "--admission-window",
            "5",
            "--session-expiry",
            "7",
            "--max-payload-size",
            "4096",
            "--rate-limit-auth",
            "3",
            "--log-level",
            "debug",
        ]);

        let cfg: RelayConfig = args.into();
        assert_eq!(cfg.bind, "127.0.0.1:9000");
        assert_eq!(cfg.admission_window, Duration::from_secs(5));
        assert_eq!(cfg.session_expiry, Duration::from_secs(7));
        assert_eq!(cfg.max_payload_size, 4096);
        assert_eq!(cfg.rate_limit_auth, 3);
        assert_eq!(cfg.log_level, "debug");
    }

    #[test]
    fn relay_args_reject_non_numeric_limits() {
        let parsed = RelayArgs::try_parse_from([
            "shenan-relay",
            "--max-payload-size",
            "not-a-number",
        ]);
        assert!(parsed.is_err());
    }
}
