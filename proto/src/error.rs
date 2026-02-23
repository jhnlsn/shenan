use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("no Ed25519 key found")]
    NoEd25519Key,

    #[error("multiple Ed25519 keys found — exactly one required")]
    MultipleEd25519Keys,

    #[error("invalid SSH key format: {0}")]
    InvalidSshKey(String),

    #[error("invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("invalid wire payload: expected at least {expected} bytes, got {got}")]
    PayloadTooShort { expected: usize, got: usize },

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
}
