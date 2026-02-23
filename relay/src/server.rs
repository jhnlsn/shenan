//! WebSocket server — accept loop and connection spawning.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;

use crate::config::RelayConfig;
use crate::connection;
use crate::github::GitHubKeyCache;
use crate::state::{RelayState, SharedState};

/// Start the relay server.
pub async fn run(config: RelayConfig) -> Result<(), Box<dyn std::error::Error>> {
    let state: SharedState = Arc::new(RelayState::new(config.clone()));
    let github_cache = Arc::new(GitHubKeyCache::new(Duration::from_secs(300)));

    // Spawn background cleanup
    {
        let state = state.clone();
        tokio::spawn(crate::cleanup::run_cleanup_loop(state));
    }

    let listener = TcpListener::bind(&config.bind).await?;
    eprintln!("shenan-relay listening on {}", config.bind);

    // Determine if TLS is configured
    let tls_acceptor = if let (Some(cert_path), Some(key_path)) = (&config.tls_cert, &config.tls_key) {
        let certs = load_certs(cert_path)?;
        let key = load_key(key_path)?;

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        Some(tokio_rustls::TlsAcceptor::from(Arc::new(server_config)))
    } else {
        eprintln!("WARNING: running without TLS (test mode only)");
        None
    };

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;

        let state = state.clone();
        let github_cache = github_cache.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            if let Some(tls_acceptor) = tls_acceptor {
                // TLS mode
                match tls_acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        match accept_async(tls_stream).await {
                            Ok(ws) => {
                                connection::handle_connection(ws, peer_addr, state, github_cache).await;
                            }
                            Err(e) => {
                                eprintln!("WebSocket handshake failed from {peer_addr}: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("TLS handshake failed from {peer_addr}: {e}");
                    }
                }
            } else {
                // Plaintext mode (test only)
                match accept_async(tcp_stream).await {
                    Ok(ws) => {
                        connection::handle_connection(ws, peer_addr, state, github_cache).await;
                    }
                    Err(e) => {
                        eprintln!("WebSocket handshake failed from {peer_addr}: {e}");
                    }
                }
            }
        });
    }
}

/// Start the relay on a random port for testing. Returns the bound address.
///
/// The relay runs in a background task. Cancel it by dropping the returned `JoinHandle`.
pub async fn run_test(
    config: RelayConfig,
    github_cache: Arc<GitHubKeyCache>,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let state: SharedState = Arc::new(RelayState::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        loop {
            let (tcp_stream, peer_addr) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };

            let state = state.clone();
            let github_cache = github_cache.clone();

            tokio::spawn(async move {
                if let Ok(ws) = accept_async(tcp_stream).await {
                    connection::handle_connection(ws, peer_addr, state, github_cache).await;
                }
            });
        }
    });

    Ok((addr, handle))
}

fn load_certs(
    path: &std::path::Path,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_key(
    path: &std::path::Path,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or("no private key found in file")?;
    Ok(key)
}
