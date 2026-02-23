//! WebSocket session lifecycle — connect, authenticate, join channel, pipe.

use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio_tungstenite::tungstenite::Message;

use shenan_proto::wire;
use shenan_proto::ssh;
use shenan_proto::channel;

/// Role in a shenan session.
#[derive(Debug, Clone, Copy)]
pub enum Role {
    Sender,
    Receiver,
}

/// Result of a completed session.
pub enum SessionResult {
    /// Sender: payload was delivered and ACKed.
    Delivered,
    /// Receiver: received wire payload bytes.
    Received(Vec<u8>),
}

/// Run a full session: connect → auth → channel → pipe.
pub async fn run_session(
    relay_url: &str,
    signing_key: &SigningKey,
    my_github: &str,
    other_pubkey: &VerifyingKey,
    role: Role,
    payload_data: Option<Vec<u8>>, // Sender provides encrypted payload
) -> Result<SessionResult> {
    // Connect
    let (ws_stream, _) = tokio_tungstenite::connect_async(relay_url)
        .await
        .context("failed to connect to relay")?;

    let (mut sink, mut stream) = ws_stream.split();

    // ── Authentication ──

    // Send hello
    let hello = wire::Message::Hello {
        version: wire::PROTOCOL_VERSION,
        user: my_github.to_string(),
    };
    sink.send(Message::Text(hello.to_json()?)).await?;

    // Receive challenge
    let challenge_msg = read_text_message(&mut stream).await?;
    let (nonce_hex, _fingerprint) = match wire::Message::from_json(&challenge_msg)? {
        wire::Message::Challenge { nonce, pubkey_fingerprint } => (nonce, pubkey_fingerprint),
        wire::Message::Error { code, message } => {
            anyhow::bail!("relay error: {code}{}", message.map(|m| format!(" — {m}")).unwrap_or_default());
        }
        other => anyhow::bail!("unexpected message: {other:?}"),
    };

    // Sign the nonce
    let nonce_bytes = hex::decode(&nonce_hex)?;
    let hash = Sha256::digest(&nonce_bytes);
    let signature = signing_key.sign(&hash);

    let auth = wire::Message::Auth {
        signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    };
    sink.send(Message::Text(auth.to_json()?)).await?;

    // Wait for authenticated
    let auth_resp = read_text_message(&mut stream).await?;
    match wire::Message::from_json(&auth_resp)? {
        wire::Message::Authenticated => {}
        wire::Message::Error { code, message } => {
            anyhow::bail!("auth failed: {code}{}", message.map(|m| format!(" — {m}")).unwrap_or_default());
        }
        other => anyhow::bail!("unexpected message: {other:?}"),
    }

    // ── Channel Join ──

    let my_pubkey = signing_key.verifying_key();
    let (sender_pub, recipient_pub) = match role {
        Role::Sender => (&my_pubkey, other_pubkey),
        Role::Receiver => (other_pubkey, &my_pubkey),
    };

    // Try current window, then window-1, then window+1
    let result = try_channel_join(
        &mut sink, &mut stream,
        signing_key, sender_pub, recipient_pub,
        role, payload_data,
    ).await;

    result
}

async fn try_channel_join<S, R>(
    sink: &mut S,
    stream: &mut R,
    signing_key: &SigningKey,
    sender_pub: &VerifyingKey,
    recipient_pub: &VerifyingKey,
    role: Role,
    payload_data: Option<Vec<u8>>,
) -> Result<SessionResult>
where
    S: SinkExt<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::error::Error + Send + Sync + 'static,
    R: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let windows = {
        let w = channel::current_window();
        vec![w, w.wrapping_sub(1), w + 1]
    };

    for (attempt, &window) in windows.iter().enumerate() {
        let token = channel::derive_token(signing_key, sender_pub, recipient_pub, window);
        let proof = channel::sign_token(signing_key, &token);

        let my_pub_wire = ssh::ed25519_to_ssh_wire(&signing_key.verifying_key().to_bytes());

        let channel_msg = wire::Message::Channel {
            token: hex::encode(&*token),
            proof: base64::engine::general_purpose::STANDARD.encode(proof.to_bytes()),
            pubkey: base64::engine::general_purpose::STANDARD.encode(&my_pub_wire),
        };

        sink.send(Message::Text(channel_msg.to_json()?))
            .await
            .map_err(|e| anyhow::anyhow!("send failed: {e}"))?;

        // Wait for response
        let resp = read_text_message_raw(stream).await?;
        match wire::Message::from_json(&resp)? {
            wire::Message::Waiting { expires_in_seconds } => {
                eprintln!("Waiting for other party... (timeout: {expires_in_seconds}s)");
                // Wait for connected
                let connected_msg = read_text_message_raw(stream).await?;
                match wire::Message::from_json(&connected_msg)? {
                    wire::Message::Connected => {
                        return handle_pipe(sink, stream, role, payload_data).await;
                    }
                    wire::Message::Error { code, .. } if code == wire::error_codes::CHANNEL_EXPIRED && attempt < 2 => {
                        continue; // try next window
                    }
                    wire::Message::Error { code, message } => {
                        anyhow::bail!("channel error: {code}{}", message.map(|m| format!(" — {m}")).unwrap_or_default());
                    }
                    other => anyhow::bail!("unexpected: {other:?}"),
                }
            }
            wire::Message::Connected => {
                return handle_pipe(sink, stream, role, payload_data).await;
            }
            wire::Message::Error { code, .. } if code == wire::error_codes::CHANNEL_EXPIRED && attempt < 2 => {
                continue; // try next window
            }
            wire::Message::Error { code, message } => {
                anyhow::bail!("channel error: {code}{}", message.map(|m| format!(" — {m}")).unwrap_or_default());
            }
            other => anyhow::bail!("unexpected: {other:?}"),
        }
    }

    anyhow::bail!("failed to join channel after trying current and adjacent time windows")
}

async fn handle_pipe<S, R>(
    sink: &mut S,
    stream: &mut R,
    role: Role,
    payload_data: Option<Vec<u8>>,
) -> Result<SessionResult>
where
    S: SinkExt<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::error::Error + Send + Sync + 'static,
    R: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    match role {
        Role::Sender => {
            let data = payload_data.expect("sender must provide payload data");

            // Send binary payload
            sink.send(Message::Binary(data))
                .await
                .map_err(|e| anyhow::anyhow!("send failed: {e}"))?;

            // Wait for received ACK (timeout 30s)
            let ack = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                read_text_message_raw(stream),
            )
            .await
            .context("timed out waiting for delivery confirmation")??;

            match wire::Message::from_json(&ack)? {
                wire::Message::Received => {
                    // Close cleanly
                    let _ = sink.send(Message::Close(None)).await;
                    Ok(SessionResult::Delivered)
                }
                other => anyhow::bail!("expected 'received', got: {other:?}"),
            }
        }
        Role::Receiver => {
            // Wait for binary payload
            let payload = read_binary_message(stream).await?;

            // Send received ACK
            let ack = wire::Message::Received;
            sink.send(Message::Text(ack.to_json()?))
                .await
                .map_err(|e| anyhow::anyhow!("send failed: {e}"))?;

            // Close cleanly
            let _ = sink.send(Message::Close(None)).await;
            Ok(SessionResult::Received(payload))
        }
    }
}

async fn read_text_message<R>(stream: &mut R) -> Result<String>
where
    R: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    read_text_message_raw(stream).await
}

async fn read_text_message_raw<R>(stream: &mut R) -> Result<String>
where
    R: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(text))) => return Ok(text.to_string()),
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) => anyhow::bail!("connection closed"),
            Some(Ok(other)) => anyhow::bail!("expected text message, got: {other:?}"),
            Some(Err(e)) => anyhow::bail!("WebSocket error: {e}"),
            None => anyhow::bail!("connection closed"),
        }
    }
}

async fn read_binary_message<R>(stream: &mut R) -> Result<Vec<u8>>
where
    R: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        match stream.next().await {
            Some(Ok(Message::Binary(data))) => return Ok(data.to_vec()),
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) => anyhow::bail!("connection closed"),
            Some(Ok(other)) => anyhow::bail!("expected binary message, got: {other:?}"),
            Some(Err(e)) => anyhow::bail!("WebSocket error: {e}"),
            None => anyhow::bail!("connection closed"),
        }
    }
}
