//! Wire format types for the Shenan protocol (SPEC §10).
//!
//! All control messages are JSON objects sent as WebSocket text frames.
//! Payload data is sent as binary WebSocket frames after pipe establishment.

use serde::{Deserialize, Serialize};

/// Protocol version supported by this implementation.
pub const PROTOCOL_VERSION: u32 = 1;

// ── Client → Relay ──────────────────────────────────────────────────────

/// `hello` — initiates authentication (§6.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    #[serde(rename = "type")]
    pub msg_type: HelloType,
    pub version: u32,
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HelloType {
    #[serde(rename = "hello")]
    Hello,
}

/// `auth` — responds to challenge with signature (§6.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth {
    #[serde(rename = "type")]
    pub msg_type: AuthType,
    pub signature: String, // base64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthType {
    #[serde(rename = "auth")]
    Auth,
}

/// `channel` — presents channel token after authentication (§7.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelJoin {
    #[serde(rename = "type")]
    pub msg_type: ChannelJoinType,
    pub token: String,  // hex-encoded 32 bytes
    pub proof: String,  // base64-encoded signature
    pub pubkey: String, // base64-encoded SSH public key bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelJoinType {
    #[serde(rename = "channel")]
    Channel,
}

/// `received` — delivery confirmation from recipient (§8.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Received {
    #[serde(rename = "type")]
    pub msg_type: ReceivedType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReceivedType {
    #[serde(rename = "received")]
    Received,
}

// ── Relay → Client ──────────────────────────────────────────────────────

/// `challenge` — issued after hello (§6.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub msg_type: ChallengeType,
    pub nonce: String, // hex-encoded 32 bytes
    pub pubkey_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeType {
    #[serde(rename = "challenge")]
    Challenge,
}

/// `authenticated` — confirms successful auth (§6.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authenticated {
    #[serde(rename = "type")]
    pub msg_type: AuthenticatedType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticatedType {
    #[serde(rename = "authenticated")]
    Authenticated,
}

/// `waiting` — first party acknowledged (§8.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Waiting {
    #[serde(rename = "type")]
    pub msg_type: WaitingType,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WaitingType {
    #[serde(rename = "waiting")]
    Waiting,
}

/// `connected` — pipe established (§8.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connected {
    #[serde(rename = "type")]
    pub msg_type: ConnectedType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectedType {
    #[serde(rename = "connected")]
    Connected,
}

/// `error` — error condition (§10.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMsg {
    #[serde(rename = "type")]
    pub msg_type: ErrorMsgType,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorMsgType {
    #[serde(rename = "error")]
    Error,
}

// ── Unified message enum for parsing ────────────────────────────────────

/// Any message that can appear on the wire, parsed by `type` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
    #[serde(rename = "hello")]
    Hello {
        version: u32,
        user: String,
    },
    #[serde(rename = "challenge")]
    Challenge {
        nonce: String,
        pubkey_fingerprint: String,
    },
    #[serde(rename = "auth")]
    Auth {
        signature: String,
    },
    #[serde(rename = "authenticated")]
    Authenticated,
    #[serde(rename = "channel")]
    Channel {
        token: String,
        proof: String,
        pubkey: String,
    },
    #[serde(rename = "waiting")]
    Waiting {
        expires_in_seconds: u64,
    },
    #[serde(rename = "connected")]
    Connected,
    #[serde(rename = "received")]
    Received,
    #[serde(rename = "error")]
    Error {
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
}

impl Message {
    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse from JSON string.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

// ── Error code constants ────────────────────────────────────────────────

pub mod error_codes {
    pub const UNSUPPORTED_VERSION: &str = "unsupported_version";
    pub const AUTH_FAILED: &str = "auth_failed";
    pub const CHANNEL_EXPIRED: &str = "channel_expired";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const PAYLOAD_TOO_LARGE: &str = "payload_too_large";
    pub const INTERNAL_ERROR: &str = "internal_error";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_round_trip() {
        let msg = Message::Hello {
            version: 1,
            user: "alice".into(),
        };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"hello""#));
        let parsed = Message::from_json(&json).unwrap();
        match parsed {
            Message::Hello { version, user } => {
                assert_eq!(version, 1);
                assert_eq!(user, "alice");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn error_round_trip() {
        let msg = Message::Error {
            code: error_codes::AUTH_FAILED.into(),
            message: Some("bad signature".into()),
        };
        let json = msg.to_json().unwrap();
        let parsed = Message::from_json(&json).unwrap();
        match parsed {
            Message::Error { code, message } => {
                assert_eq!(code, "auth_failed");
                assert_eq!(message.as_deref(), Some("bad signature"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn error_no_message() {
        let json = r#"{"type":"error","code":"rate_limited"}"#;
        let parsed = Message::from_json(json).unwrap();
        match parsed {
            Message::Error { code, message } => {
                assert_eq!(code, "rate_limited");
                assert!(message.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }
}
