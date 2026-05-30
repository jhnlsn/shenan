//! WebSocket session lifecycle — connect, authenticate, join channel, pipe.

use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

use shenan_proto::channel;
use shenan_proto::payload::{self, Payload};
use shenan_proto::ssh;
use shenan_proto::wire;

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
    /// Receiver: decrypted and validated payload.
    Received(Payload),
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
    let (nonce_hex, _fingerprints) = match wire::Message::from_json(&challenge_msg)? {
        wire::Message::Challenge {
            nonce,
            pubkey_fingerprints,
        } => (nonce, pubkey_fingerprints),
        wire::Message::Error { code, message } => {
            anyhow::bail!(
                "relay error: {code}{}",
                message.map(|m| format!(" — {m}")).unwrap_or_default()
            );
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
            anyhow::bail!(
                "auth failed: {code}{}",
                message.map(|m| format!(" — {m}")).unwrap_or_default()
            );
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
        &mut sink,
        &mut stream,
        signing_key,
        sender_pub,
        recipient_pub,
        role,
        payload_data,
    )
    .await;

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
            token: hex::encode(*token),
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
                match wait_for_connected_or_expired(stream, expires_in_seconds).await? {
                    ChannelWait::Connected => {
                        return handle_pipe(
                            sink,
                            stream,
                            role,
                            payload_data,
                            signing_key,
                            sender_pub,
                        )
                        .await;
                    }
                    ChannelWait::Expired if attempt < 2 => continue,
                    ChannelWait::Expired => {
                        anyhow::bail!(
                            "failed to join channel after trying current and adjacent time windows"
                        )
                    }
                }
            }
            wire::Message::Connected => {
                return handle_pipe(sink, stream, role, payload_data, signing_key, sender_pub)
                    .await;
            }
            wire::Message::Error { code, .. }
                if code == wire::error_codes::CHANNEL_EXPIRED && attempt < 2 =>
            {
                continue; // try next window
            }
            wire::Message::Error { code, message } => {
                anyhow::bail!(
                    "channel error: {code}{}",
                    message.map(|m| format!(" — {m}")).unwrap_or_default()
                );
            }
            other => anyhow::bail!("unexpected: {other:?}"),
        }
    }

    anyhow::bail!("failed to join channel after trying current and adjacent time windows")
}

enum ChannelWait {
    Connected,
    Expired,
}

async fn wait_for_connected_or_expired<R>(
    stream: &mut R,
    expires_in_seconds: u64,
) -> Result<ChannelWait>
where
    R: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    if expires_in_seconds == 0 {
        return Ok(ChannelWait::Expired);
    }

    let connected_msg = match tokio::time::timeout(
        Duration::from_secs(expires_in_seconds),
        read_text_message_raw(stream),
    )
    .await
    {
        Ok(msg) => msg?,
        Err(_) => return Ok(ChannelWait::Expired),
    };

    match wire::Message::from_json(&connected_msg)? {
        wire::Message::Connected => Ok(ChannelWait::Connected),
        wire::Message::Error { code, .. } if code == wire::error_codes::CHANNEL_EXPIRED => {
            Ok(ChannelWait::Expired)
        }
        wire::Message::Error { code, message } => {
            anyhow::bail!(
                "channel error: {code}{}",
                message.map(|m| format!(" — {m}")).unwrap_or_default()
            );
        }
        other => anyhow::bail!("unexpected: {other:?}"),
    }
}

async fn handle_pipe<S, R>(
    sink: &mut S,
    stream: &mut R,
    role: Role,
    payload_data: Option<Vec<u8>>,
    signing_key: &SigningKey,
    expected_sender_pubkey: &VerifyingKey,
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
            let wire_payload = read_binary_message(stream).await?;

            let payload =
                match validate_received_payload(&wire_payload, signing_key, expected_sender_pubkey)
                {
                    Ok(payload) => payload,
                    Err(e) => {
                        let _ = sink.send(Message::Close(None)).await;
                        return Err(e);
                    }
                };

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

fn validate_received_payload(
    wire_payload: &[u8],
    signing_key: &SigningKey,
    expected_sender_pubkey: &VerifyingKey,
) -> Result<Payload> {
    let payload = payload::decrypt(wire_payload, signing_key)
        .context("failed to decrypt payload — the sender may not have your correct public key")?;
    let expected_sender_fingerprint = fingerprint_for_pubkey(expected_sender_pubkey);
    if payload.sender_pubkey_fingerprint != expected_sender_fingerprint {
        anyhow::bail!(
            "sender fingerprint mismatch: got {}, expected {}",
            payload.sender_pubkey_fingerprint,
            expected_sender_fingerprint
        );
    }
    Ok(payload)
}

fn fingerprint_for_pubkey(pubkey: &VerifyingKey) -> String {
    let key_bytes = pubkey.to_bytes();
    shenan_proto::ssh::SshEd25519PubKey {
        key_bytes,
        wire_bytes: ssh::ed25519_to_ssh_wire(&key_bytes),
        original_line: String::new(),
    }
    .fingerprint()
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use ed25519_dalek::SigningKey;
    use futures_util::{stream, Sink};
    use rand::rngs::OsRng;

    #[derive(Clone, Default)]
    struct RecordingSink {
        messages: Arc<Mutex<Vec<Message>>>,
    }

    impl RecordingSink {
        fn messages(&self) -> Vec<Message> {
            self.messages.lock().unwrap().clone()
        }
    }

    impl Sink<Message> for RecordingSink {
        type Error = std::io::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Message) -> std::result::Result<(), Self::Error> {
            self.messages.lock().unwrap().push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn receiver_does_not_ack_payload_that_cannot_be_decrypted() {
        let sender = SigningKey::generate(&mut OsRng);
        let receiver = SigningKey::generate(&mut OsRng);
        let mut sink = RecordingSink::default();
        let sent_messages = sink.clone();
        let invalid_wire_payload = vec![0u8; 64];
        let mut stream = stream::iter(vec![Ok(Message::Binary(invalid_wire_payload))]);

        let result = handle_pipe(
            &mut sink,
            &mut stream,
            Role::Receiver,
            None,
            &receiver,
            &sender.verifying_key(),
        )
        .await;

        assert!(
            result.is_err(),
            "receiver should reject payload before acknowledging delivery"
        );
        assert!(
            !has_received_ack(&sent_messages.messages()),
            "receiver must not send a received ACK for an undecryptable payload"
        );
    }

    #[tokio::test]
    async fn receiver_does_not_ack_payload_with_wrong_sender_fingerprint() {
        let sender = SigningKey::generate(&mut OsRng);
        let impostor = SigningKey::generate(&mut OsRng);
        let receiver = SigningKey::generate(&mut OsRng);
        let mut secrets = BTreeMap::new();
        secrets.insert("API_KEY".to_string(), "secret".to_string());
        let payload = Payload::new(secrets, fingerprint_for_pubkey(&impostor.verifying_key()));
        let wire_payload = payload::encrypt(&payload, &receiver.verifying_key()).unwrap();

        let mut sink = RecordingSink::default();
        let sent_messages = sink.clone();
        let mut stream = stream::iter(vec![Ok(Message::Binary(wire_payload))]);

        let result = handle_pipe(
            &mut sink,
            &mut stream,
            Role::Receiver,
            None,
            &receiver,
            &sender.verifying_key(),
        )
        .await;

        assert!(
            result.is_err(),
            "receiver should reject payload before acknowledging delivery"
        );
        assert!(
            !has_received_ack(&sent_messages.messages()),
            "receiver must not send a received ACK for a sender fingerprint mismatch"
        );
    }

    #[tokio::test]
    async fn receiver_acks_after_decrypting_and_validating_payload() {
        let sender = SigningKey::generate(&mut OsRng);
        let receiver = SigningKey::generate(&mut OsRng);
        let mut secrets = BTreeMap::new();
        secrets.insert("API_KEY".to_string(), "secret".to_string());
        let payload = Payload::new(
            secrets.clone(),
            fingerprint_for_pubkey(&sender.verifying_key()),
        );
        let wire_payload = payload::encrypt(&payload, &receiver.verifying_key()).unwrap();

        let mut sink = RecordingSink::default();
        let sent_messages = sink.clone();
        let mut stream = stream::iter(vec![Ok(Message::Binary(wire_payload))]);

        let result = handle_pipe(
            &mut sink,
            &mut stream,
            Role::Receiver,
            None,
            &receiver,
            &sender.verifying_key(),
        )
        .await
        .unwrap();

        match result {
            SessionResult::Received(received) => {
                assert_eq!(received.secrets, secrets);
            }
            SessionResult::Delivered => panic!("receiver should not return sender result"),
        }
        assert!(
            has_received_ack(&sent_messages.messages()),
            "receiver should ACK only after payload validation succeeds"
        );
    }

    #[tokio::test]
    async fn channel_join_retries_adjacent_windows_after_waiting_expires() {
        let sender = SigningKey::generate(&mut OsRng);
        let receiver = SigningKey::generate(&mut OsRng);
        let mut sink = RecordingSink::default();
        let sent_messages = sink.clone();
        let waiting = wire::Message::Waiting {
            expires_in_seconds: 0,
        }
        .to_json()
        .unwrap();
        let mut stream = stream::iter(vec![
            Ok(Message::Text(waiting.clone())),
            Ok(Message::Text(waiting.clone())),
            Ok(Message::Text(waiting)),
        ]);

        let result = try_channel_join(
            &mut sink,
            &mut stream,
            &sender,
            &sender.verifying_key(),
            &receiver.verifying_key(),
            Role::Sender,
            Some(Vec::new()),
        )
        .await;

        assert!(result.is_err(), "all expired windows should fail the join");
        assert_eq!(
            channel_join_count(&sent_messages.messages()),
            3,
            "client should try current, previous, and next windows"
        );
    }

    fn has_received_ack(messages: &[Message]) -> bool {
        messages.iter().any(|msg| {
            matches!(
                msg,
                Message::Text(text)
                    if matches!(wire::Message::from_json(text), Ok(wire::Message::Received))
            )
        })
    }

    fn channel_join_count(messages: &[Message]) -> usize {
        messages
            .iter()
            .filter(|msg| {
                matches!(
                    msg,
                    Message::Text(text)
                        if matches!(wire::Message::from_json(text), Ok(wire::Message::Channel { .. }))
                )
            })
            .count()
    }
}
