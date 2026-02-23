//! Integration tests: full send/receive cycle through an in-process relay.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use shenan_proto::{channel, payload, ssh, wire};
use shenan_relay::config::RelayConfig;
use shenan_relay::github::GitHubKeyCache;

type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type WsStream = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

/// Build a test relay config with generous limits.
fn test_config() -> RelayConfig {
    RelayConfig {
        bind: "127.0.0.1:0".to_string(),
        tls_cert: None,
        tls_key: None,
        admission_window: Duration::from_secs(30),
        session_expiry: Duration::from_secs(60),
        max_payload_size: 1024 * 1024,
        rate_limit_auth: 1000,
    }
}

/// Create a GitHubKeyCache pre-populated with test keys (no real HTTP calls).
fn test_cache(users: &[(&str, &SigningKey)]) -> Arc<GitHubKeyCache> {
    let cache = GitHubKeyCache::new(Duration::from_secs(3600));
    for (username, signing_key) in users {
        let vk = signing_key.verifying_key();
        let wire_bytes = ssh::ed25519_to_ssh_wire(&vk.to_bytes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(&wire_bytes);
        let line = format!("ssh-ed25519 {b64} {username}@test");
        let key = ssh::parse_single_ed25519(&line).unwrap();
        cache.insert(username, key);
    }
    Arc::new(cache)
}

/// Connect a WebSocket client to the relay and run through the auth handshake.
/// Returns the split (sink, stream) in authenticated state.
async fn connect_and_auth(
    url: &str,
    signing_key: &SigningKey,
    username: &str,
) -> (WsSink, WsStream) {
    let (ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let (mut sink, mut stream) = ws.split();

    // Send hello
    let hello = wire::Message::Hello {
        version: wire::PROTOCOL_VERSION,
        user: username.to_string(),
    };
    sink.send(Message::Text(hello.to_json().unwrap())).await.unwrap();

    // Receive challenge
    let challenge_text = read_text(&mut stream).await;
    let (nonce_hex, _fingerprint) = match wire::Message::from_json(&challenge_text).unwrap() {
        wire::Message::Challenge { nonce, pubkey_fingerprint } => (nonce, pubkey_fingerprint),
        other => panic!("expected challenge, got: {other:?}"),
    };

    // Sign nonce
    let nonce_bytes = hex::decode(&nonce_hex).unwrap();
    let hash = Sha256::digest(&nonce_bytes);
    let signature = signing_key.sign(&hash);

    let auth = wire::Message::Auth {
        signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    };
    sink.send(Message::Text(auth.to_json().unwrap())).await.unwrap();

    // Wait for authenticated
    let auth_resp = read_text(&mut stream).await;
    match wire::Message::from_json(&auth_resp).unwrap() {
        wire::Message::Authenticated => {}
        other => panic!("expected authenticated, got: {other:?}"),
    }

    (sink, stream)
}

/// Send a channel join message and return the response.
async fn send_channel_join(
    sink: &mut WsSink,
    stream: &mut WsStream,
    signing_key: &SigningKey,
    sender_pub: &ed25519_dalek::VerifyingKey,
    recipient_pub: &ed25519_dalek::VerifyingKey,
    window: u64,
) -> wire::Message {
    let token = channel::derive_token(signing_key, sender_pub, recipient_pub, window);
    let proof = channel::sign_token(signing_key, &token);
    let my_pub_wire = ssh::ed25519_to_ssh_wire(&signing_key.verifying_key().to_bytes());

    let channel_msg = wire::Message::Channel {
        token: hex::encode(*token),
        proof: base64::engine::general_purpose::STANDARD.encode(proof.to_bytes()),
        pubkey: base64::engine::general_purpose::STANDARD.encode(&my_pub_wire),
    };

    sink.send(Message::Text(channel_msg.to_json().unwrap())).await.unwrap();

    let resp = read_text(stream).await;
    wire::Message::from_json(&resp).unwrap()
}

async fn read_text(stream: &mut WsStream) -> String {
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(t))) => return t.to_string(),
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) => panic!("connection closed unexpectedly"),
            Some(Ok(other)) => panic!("expected text, got: {other:?}"),
            Some(Err(e)) => panic!("ws error: {e}"),
            None => panic!("stream ended"),
        }
    }
}

/// Read text, returning None if the connection was reset (for error-path tests).
async fn try_read_text(stream: &mut WsStream) -> Option<String> {
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(t))) => return Some(t.to_string()),
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return None,
            Some(Ok(_)) => return None,
        }
    }
}

async fn read_binary(stream: &mut WsStream) -> Vec<u8> {
    loop {
        match stream.next().await {
            Some(Ok(Message::Binary(data))) => return data.to_vec(),
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) => panic!("connection closed unexpectedly"),
            Some(Ok(other)) => panic!("expected binary, got: {other:?}"),
            Some(Err(e)) => panic!("ws error: {e}"),
            None => panic!("stream ended"),
        }
    }
}

// ── Tests ──

#[tokio::test]
async fn full_send_receive_cycle() {
    // Generate test keypairs
    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);

    let alice_pub = alice_key.verifying_key();
    let bob_pub = bob_key.verifying_key();

    // Start relay with pre-populated cache
    let cache = test_cache(&[("alice", &alice_key), ("bob", &bob_key)]);
    let (addr, _handle) = shenan_relay::server::run_test(test_config(), cache)
        .await
        .unwrap();
    let url = format!("ws://{addr}");

    // Build encrypted payload (alice → bob)
    let mut secrets = BTreeMap::new();
    secrets.insert("API_KEY".to_string(), "sk-secret-123".to_string());
    secrets.insert("DB_URL".to_string(), "postgres://localhost/mydb".to_string());

    let sender_fingerprint = {
        let wire = ssh::ed25519_to_ssh_wire(&alice_pub.to_bytes());
        let hash = Sha256::digest(&wire);
        let b64 = base64::engine::general_purpose::STANDARD.encode(hash);
        format!("SHA256:{}", b64.trim_end_matches('='))
    };

    let payload_obj = payload::Payload::new(secrets.clone(), sender_fingerprint);
    let encrypted = payload::encrypt(&payload_obj, &bob_pub).unwrap();

    let window = channel::current_window();

    // Connect and authenticate both parties
    let (mut alice_sink, mut alice_stream) =
        connect_and_auth(&url, &alice_key, "alice").await;
    let (mut bob_sink, mut bob_stream) =
        connect_and_auth(&url, &bob_key, "bob").await;

    // Alice joins channel first (sender) — alice is sender, bob is recipient
    let alice_resp = send_channel_join(
        &mut alice_sink,
        &mut alice_stream,
        &alice_key,
        &alice_pub,
        &bob_pub,
        window,
    )
    .await;

    match alice_resp {
        wire::Message::Waiting { .. } => {} // expected: first arrival waits
        other => panic!("expected waiting, got: {other:?}"),
    }

    // Bob joins channel (receiver)
    let bob_resp = send_channel_join(
        &mut bob_sink,
        &mut bob_stream,
        &bob_key,
        &alice_pub,
        &bob_pub,
        window,
    )
    .await;

    match bob_resp {
        wire::Message::Connected => {} // expected: second arrival triggers pipe
        other => panic!("expected connected, got: {other:?}"),
    }

    // Alice should also get connected
    let alice_connected = read_text(&mut alice_stream).await;
    match wire::Message::from_json(&alice_connected).unwrap() {
        wire::Message::Connected => {}
        other => panic!("expected connected for alice, got: {other:?}"),
    }

    // Alice sends encrypted payload
    alice_sink
        .send(Message::Binary(encrypted.clone()))
        .await
        .unwrap();

    // Bob receives the binary payload
    let received_data = read_binary(&mut bob_stream).await;
    assert_eq!(received_data, encrypted, "payload should arrive byte-for-byte identical");

    // Bob sends received ACK
    let ack = wire::Message::Received;
    bob_sink
        .send(Message::Text(ack.to_json().unwrap()))
        .await
        .unwrap();

    // Alice receives ACK
    let alice_ack = read_text(&mut alice_stream).await;
    match wire::Message::from_json(&alice_ack).unwrap() {
        wire::Message::Received => {}
        other => panic!("expected received ack, got: {other:?}"),
    }

    // Decrypt and verify the payload
    let decrypted = payload::decrypt(&received_data, &bob_key).unwrap();
    assert_eq!(decrypted.secrets, secrets);
    assert_eq!(decrypted.version, 1);
}

#[tokio::test]
async fn wrong_version_rejected() {
    let alice_key = SigningKey::generate(&mut OsRng);
    let cache = test_cache(&[("alice", &alice_key)]);
    let (addr, _handle) = shenan_relay::server::run_test(test_config(), cache)
        .await
        .unwrap();
    let url = format!("ws://{addr}");

    let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut sink, mut stream) = ws.split();

    // Send hello with wrong version
    let hello = wire::Message::Hello {
        version: 99,
        user: "alice".to_string(),
    };
    sink.send(Message::Text(hello.to_json().unwrap())).await.unwrap();

    let resp = read_text(&mut stream).await;
    match wire::Message::from_json(&resp).unwrap() {
        wire::Message::Error { code, .. } => {
            assert_eq!(code, wire::error_codes::UNSUPPORTED_VERSION);
        }
        other => panic!("expected error, got: {other:?}"),
    }
}

#[tokio::test]
async fn auth_with_wrong_key_rejected() {
    let alice_key = SigningKey::generate(&mut OsRng);
    let imposter_key = SigningKey::generate(&mut OsRng);

    // Cache has alice's real key
    let cache = test_cache(&[("alice", &alice_key)]);
    let (addr, _handle) = shenan_relay::server::run_test(test_config(), cache)
        .await
        .unwrap();
    let url = format!("ws://{addr}");

    let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut sink, mut stream) = ws.split();

    // Send hello as alice
    let hello = wire::Message::Hello {
        version: wire::PROTOCOL_VERSION,
        user: "alice".to_string(),
    };
    sink.send(Message::Text(hello.to_json().unwrap())).await.unwrap();

    // Get challenge
    let challenge_text = read_text(&mut stream).await;
    let nonce_hex = match wire::Message::from_json(&challenge_text).unwrap() {
        wire::Message::Challenge { nonce, .. } => nonce,
        other => panic!("expected challenge, got: {other:?}"),
    };

    // Sign with imposter's key (wrong key)
    let nonce_bytes = hex::decode(&nonce_hex).unwrap();
    let hash = Sha256::digest(&nonce_bytes);
    let signature = imposter_key.sign(&hash);

    let auth = wire::Message::Auth {
        signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    };
    sink.send(Message::Text(auth.to_json().unwrap())).await.unwrap();

    let resp = read_text(&mut stream).await;
    match wire::Message::from_json(&resp).unwrap() {
        wire::Message::Error { code, .. } => {
            assert_eq!(code, wire::error_codes::AUTH_FAILED);
        }
        other => panic!("expected auth error, got: {other:?}"),
    }
}

#[tokio::test]
async fn same_pubkey_both_sides_rejected() {
    // Alice tries to be both sender and receiver
    let alice_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key();

    let cache = test_cache(&[("alice", &alice_key), ("alice2", &alice_key)]);
    let (addr, _handle) = shenan_relay::server::run_test(test_config(), cache)
        .await
        .unwrap();
    let url = format!("ws://{addr}");

    let window = channel::current_window();

    // Connect two sessions with same key
    let (mut sink_a, mut stream_a) = connect_and_auth(&url, &alice_key, "alice").await;
    let (mut sink_b, mut stream_b) = connect_and_auth(&url, &alice_key, "alice2").await;

    // First joins channel
    let resp_a = send_channel_join(
        &mut sink_a,
        &mut stream_a,
        &alice_key,
        &alice_pub,
        &alice_pub,
        window,
    )
    .await;
    assert!(matches!(resp_a, wire::Message::Waiting { .. }));

    // Second joins with same pubkey — should be rejected
    // Send channel message manually since error may race with connection drop
    let token = channel::derive_token(&alice_key, &alice_pub, &alice_pub, window);
    let proof = channel::sign_token(&alice_key, &token);
    let my_pub_wire = ssh::ed25519_to_ssh_wire(&alice_key.verifying_key().to_bytes());

    let channel_msg = wire::Message::Channel {
        token: hex::encode(*token),
        proof: base64::engine::general_purpose::STANDARD.encode(proof.to_bytes()),
        pubkey: base64::engine::general_purpose::STANDARD.encode(&my_pub_wire),
    };
    sink_b.send(Message::Text(channel_msg.to_json().unwrap())).await.unwrap();

    let resp = try_read_text(&mut stream_b).await;
    if let Some(resp) = resp {
        match wire::Message::from_json(&resp).unwrap() {
            wire::Message::Error { code, .. } => {
                assert_eq!(code, wire::error_codes::AUTH_FAILED);
            }
            other => panic!("expected error for same pubkey, got: {other:?}"),
        }
    }
    // Connection may also just be reset for same-pubkey rejection
}

#[tokio::test]
async fn payload_too_large_rejected() {
    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key();
    let bob_pub = bob_key.verifying_key();

    let cache = test_cache(&[("alice", &alice_key), ("bob", &bob_key)]);

    // Config with tiny max payload
    let mut config = test_config();
    config.max_payload_size = 64;

    let (addr, _handle) = shenan_relay::server::run_test(config, cache)
        .await
        .unwrap();
    let url = format!("ws://{addr}");

    let window = channel::current_window();

    let (mut alice_sink, mut alice_stream) = connect_and_auth(&url, &alice_key, "alice").await;
    let (mut bob_sink, mut bob_stream) = connect_and_auth(&url, &bob_key, "bob").await;

    // Alice joins first
    let _ = send_channel_join(
        &mut alice_sink,
        &mut alice_stream,
        &alice_key,
        &alice_pub,
        &bob_pub,
        window,
    )
    .await;

    // Bob joins — both get connected
    let _ = send_channel_join(
        &mut bob_sink,
        &mut bob_stream,
        &bob_key,
        &alice_pub,
        &bob_pub,
        window,
    )
    .await;

    // Read alice's connected message
    let _ = read_text(&mut alice_stream).await;

    // Alice sends oversized payload
    let big_payload = vec![0u8; 128];
    alice_sink
        .send(Message::Binary(big_payload))
        .await
        .unwrap();

    let resp = read_text(&mut alice_stream).await;
    match wire::Message::from_json(&resp).unwrap() {
        wire::Message::Error { code, .. } => {
            assert_eq!(code, wire::error_codes::PAYLOAD_TOO_LARGE);
        }
        other => panic!("expected payload_too_large, got: {other:?}"),
    }
}
