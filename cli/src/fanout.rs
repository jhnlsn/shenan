//! Fan-out orchestrator — open parallel sessions, one per counterpart key.

use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::sync::mpsc;

use crate::session::{self, Role, SessionResult};

/// Result from a fan-out: index of the key that matched, plus the session result.
pub struct FanOutResult {
    pub key_index: usize,
    pub result: SessionResult,
}

/// Run parallel sessions for each counterpart key.
///
/// - `relay_url`: WebSocket URL of the relay
/// - `signing_key`: local identity key
/// - `my_github`: local GitHub username
/// - `counterpart_keys`: all keys for the counterpart (one session per key)
/// - `role`: Sender or Receiver
/// - `payloads`: per-key encrypted payloads (Sender) or None (Receiver)
///
/// Returns the first successful result. All other sessions are cancelled.
pub async fn fan_out_sessions(
    relay_url: &str,
    signing_key: &SigningKey,
    my_github: &str,
    counterpart_keys: &[VerifyingKey],
    role: Role,
    payloads: Vec<Option<Vec<u8>>>,
) -> Result<FanOutResult> {
    assert_eq!(counterpart_keys.len(), payloads.len());

    // Fast path: single key, no fan-out needed
    if counterpart_keys.len() == 1 {
        let result = session::run_session(
            relay_url,
            signing_key,
            my_github,
            &counterpart_keys[0],
            role,
            payloads.into_iter().next().unwrap(),
        )
        .await?;
        return Ok(FanOutResult {
            key_index: 0,
            result,
        });
    }

    let (result_tx, mut result_rx) =
        mpsc::channel::<(usize, Result<SessionResult>)>(counterpart_keys.len());

    let mut handles = Vec::with_capacity(counterpart_keys.len());

    for (i, (key, payload)) in counterpart_keys
        .iter()
        .zip(payloads.into_iter())
        .enumerate()
    {
        let relay_url = relay_url.to_string();
        let signing_key = signing_key.clone();
        let my_github = my_github.to_string();
        let key = *key;
        let result_tx = result_tx.clone();

        let handle = tokio::spawn(async move {
            let res =
                session::run_session(&relay_url, &signing_key, &my_github, &key, role, payload)
                    .await;
            let _ = result_tx.send((i, res)).await;
        });
        handles.push(handle);
    }

    // Drop our copy so the channel closes when all tasks finish
    drop(result_tx);

    // Wait for first success
    let mut last_err = None;
    while let Some((idx, res)) = result_rx.recv().await {
        match res {
            Ok(result) => {
                // Cancel all other tasks
                for handle in &handles {
                    handle.abort();
                }
                return Ok(FanOutResult {
                    key_index: idx,
                    result,
                });
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("all fan-out sessions failed")))
}
