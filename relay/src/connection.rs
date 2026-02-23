//! Per-connection state machine — handles the full lifecycle of a single WebSocket connection.

use std::net::SocketAddr;
use std::time::Instant;

use base64::Engine;
use ed25519_dalek::Signature;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use shenan_proto::wire;

use crate::admission;
use crate::auth::{self, AuthState};
use crate::github::GitHubKeyCache;
use crate::ratelimit;
use crate::state::*;

pub async fn handle_connection(
    ws_stream: tokio_tungstenite::WebSocketStream<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>,
    peer_addr: SocketAddr,
    state: SharedState,
    github_cache: std::sync::Arc<GitHubKeyCache>,
) {
    let (mut ws_sink, mut ws_stream_rx) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    let conn_id = state.next_conn_id();

    // Spawn a task to forward outbound messages
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    let mut auth_state = AuthState::AwaitingHello;
    // Once piped, we track the pipe_id and which side we are
    let mut pipe_info: Option<(u64, bool)> = None; // (pipe_id, is_side_a)

    while let Some(Ok(msg)) = ws_stream_rx.next().await {
        match msg {
            Message::Text(text) => {
                let parsed = match wire::Message::from_json(&text) {
                    Ok(m) => m,
                    Err(_) => {
                        let _ = send_error(&tx, "internal_error", "invalid message format");
                        break;
                    }
                };

                match (&auth_state, parsed) {
                    // ── Hello ──
                    (AuthState::AwaitingHello, wire::Message::Hello { version, user }) => {
                        if version != wire::PROTOCOL_VERSION {
                            let _ = send_error(&tx, wire::error_codes::UNSUPPORTED_VERSION, "unsupported protocol version");
                            break;
                        }

                        // Rate limit check
                        if !ratelimit::check_and_record(&state, peer_addr) {
                            let _ = send_error(&tx, wire::error_codes::RATE_LIMITED, "too many attempts");
                            break;
                        }

                        // Fetch GitHub keys
                        let key = match github_cache.fetch(&user).await {
                            Ok(k) => k,
                            Err(_) => {
                                let _ = send_error(&tx, wire::error_codes::AUTH_FAILED, None);
                                break;
                            }
                        };

                        let verifying_key = match key.to_verifying_key() {
                            Ok(vk) => vk,
                            Err(_) => {
                                let _ = send_error(&tx, wire::error_codes::AUTH_FAILED, None);
                                break;
                            }
                        };

                        let nonce_bytes = auth::generate_nonce();
                        let fingerprint = key.fingerprint();

                        let challenge = wire::Message::Challenge {
                            nonce: hex::encode(nonce_bytes),
                            pubkey_fingerprint: fingerprint,
                        };
                        let _ = tx.send(Message::Text(challenge.to_json().unwrap()));

                        // NOTE: username and pubkey are kept only until auth verification,
                        // then discarded per §6.6
                        auth_state = AuthState::AwaitingAuth {
                            nonce_bytes,
                            verifying_key,
                        };
                    }

                    // ── Auth ──
                    (AuthState::AwaitingAuth { nonce_bytes, verifying_key }, wire::Message::Auth { signature }) => {
                        let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(&signature) {
                            Ok(b) => b,
                            Err(_) => {
                                let _ = send_error(&tx, wire::error_codes::AUTH_FAILED, None);
                                break;
                            }
                        };

                        let sig = match Signature::from_slice(&sig_bytes) {
                            Ok(s) => s,
                            Err(_) => {
                                let _ = send_error(&tx, wire::error_codes::AUTH_FAILED, None);
                                break;
                            }
                        };

                        if !auth::verify_auth_signature(verifying_key, nonce_bytes, &sig) {
                            let _ = send_error(&tx, wire::error_codes::AUTH_FAILED, None);
                            break;
                        }

                        // §6.6: discard username and pubkey, mark connection as authenticated
                        let session = AuthenticatedSession {
                            expires_at: Instant::now() + state.config.session_expiry,
                            sender: tx.clone(),
                            peer_addr,
                        };
                        state.sessions.insert(conn_id, session);

                        auth_state = AuthState::Authenticated;

                        let ack = wire::Message::Authenticated;
                        let _ = tx.send(Message::Text(ack.to_json().unwrap()));
                    }

                    // ── Channel join ──
                    (AuthState::Authenticated, wire::Message::Channel { token, proof, pubkey }) => {
                        // Verify session is still valid
                        if !state.sessions.contains_key(&conn_id) {
                            let _ = send_error(&tx, wire::error_codes::AUTH_FAILED, "session expired");
                            break;
                        }

                        let token_bytes: [u8; 32] = match hex::decode(&token)
                            .ok()
                            .and_then(|b| b.try_into().ok())
                        {
                            Some(t) => t,
                            None => {
                                let _ = send_error(&tx, wire::error_codes::AUTH_FAILED, "invalid token");
                                break;
                            }
                        };

                        let proof_bytes = match base64::engine::general_purpose::STANDARD.decode(&proof) {
                            Ok(b) => b,
                            Err(_) => {
                                let _ = send_error(&tx, wire::error_codes::AUTH_FAILED, "invalid proof");
                                break;
                            }
                        };

                        let pubkey_bytes_vec = match base64::engine::general_purpose::STANDARD.decode(&pubkey) {
                            Ok(b) => b,
                            Err(_) => {
                                let _ = send_error(&tx, wire::error_codes::AUTH_FAILED, "invalid pubkey");
                                break;
                            }
                        };

                        // Extract raw 32-byte Ed25519 key from pubkey (which may be SSH wire format or raw)
                        let pubkey_32: [u8; 32] = if pubkey_bytes_vec.len() == 32 {
                            pubkey_bytes_vec.as_slice().try_into().unwrap()
                        } else {
                            // Try parsing as SSH wire format
                            match shenan_proto::ssh::parse_single_ed25519(
                                &format!("ssh-ed25519 {pubkey}")
                            ) {
                                Ok(k) => k.key_bytes,
                                Err(_) => {
                                    let _ = send_error(&tx, wire::error_codes::AUTH_FAILED, "invalid pubkey format");
                                    break;
                                }
                            }
                        };

                        // Verify channel proof
                        if let Err(_) = admission::verify_channel_proof(&pubkey_32, &token_bytes, &proof_bytes) {
                            let _ = send_error(&tx, wire::error_codes::AUTH_FAILED, "invalid channel proof");
                            break;
                        }

                        // Check for existing pending channel
                        if let Some((_, pending)) = state.pending_channels.remove(&token) {
                            // Second arrival — admission check
                            if let Err(_) = admission::admission_check(&pending.pubkey, &pubkey_bytes_vec) {
                                // Same pubkey — drop both
                                let _ = send_error(&tx, wire::error_codes::AUTH_FAILED, None);
                                let _ = send_error(&pending.sender, wire::error_codes::AUTH_FAILED, None);
                                break;
                            }

                            // Open pipe — discard all channel state
                            let pipe_id = state.next_pipe_id();
                            let pipe = ActivePipe {
                                sender_a: pending.sender.clone(),
                                sender_b: tx.clone(),
                            };
                            state.active_pipes.insert(pipe_id, pipe);

                            // Remove sessions — they're now in the pipe
                            state.sessions.remove(&pending.conn_id);
                            state.sessions.remove(&conn_id);

                            // Send connected to both
                            let connected = wire::Message::Connected.to_json().unwrap();
                            let _ = pending.sender.send(Message::Text(connected.clone()));
                            let _ = tx.send(Message::Text(connected));

                            // Track pipe info: pending is side_a, we are side_b
                            pipe_info = Some((pipe_id, false));

                            // The first party's connection handler also needs to know
                            // about the pipe, but since we're managing it here via
                            // forwarding, this side handles both directions.
                        } else {
                            // First arrival
                            let pending = crate::state::PendingChannel {
                                proof: proof_bytes,
                                pubkey: pubkey_bytes_vec,
                                conn_id,
                                sender: tx.clone(),
                                arrived_at: Instant::now(),
                            };
                            state.pending_channels.insert(token, pending);

                            let waiting = wire::Message::Waiting {
                                expires_in_seconds: state.config.admission_window.as_secs(),
                            };
                            let _ = tx.send(Message::Text(waiting.to_json().unwrap()));
                        }
                    }

                    // ── Received (forwarded through pipe) ──
                    (_, wire::Message::Received) => {
                        if let Some((pipe_id, is_a)) = &pipe_info {
                            if let Some(pipe) = state.active_pipes.get(pipe_id) {
                                let target = if *is_a { &pipe.sender_b } else { &pipe.sender_a };
                                let _ = target.send(Message::Text(text.to_string()));
                            }
                        }
                    }

                    _ => {
                        let _ = send_error(&tx, wire::error_codes::AUTH_FAILED, "unexpected message");
                        break;
                    }
                }
            }

            // Binary messages — forward through pipe
            Message::Binary(data) => {
                if let Some((pipe_id, is_a)) = &pipe_info {
                    // Check payload size
                    if data.len() > state.config.max_payload_size {
                        let _ = send_error(&tx, wire::error_codes::PAYLOAD_TOO_LARGE, None);
                        crate::pipe::close_pipe(&state, *pipe_id);
                        break;
                    }
                    if let Some(pipe) = state.active_pipes.get(pipe_id) {
                        let target = if *is_a { &pipe.sender_b } else { &pipe.sender_a };
                        if target.send(Message::Binary(data)).is_err() {
                            crate::pipe::close_pipe(&state, *pipe_id);
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }

            Message::Close(_) => break,
            _ => {}
        }
    }

    // Cleanup on disconnect
    state.sessions.remove(&conn_id);
    if let Some((pipe_id, _)) = pipe_info {
        crate::pipe::close_pipe(&state, pipe_id);
    }

    send_task.abort();
}

fn send_error(tx: &WsSender, code: &str, message: impl Into<Option<&'static str>>) -> Result<(), ()> {
    let msg = wire::Message::Error {
        code: code.into(),
        message: message.into().map(String::from),
    };
    tx.send(Message::Text(msg.to_json().unwrap())).map_err(|_| ())
}
