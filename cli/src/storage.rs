//! ~/.shenan/ config management (SPEC §12.1).

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Get the shenan config directory (~/.shenan/).
pub fn config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".shenan"))
}

/// Ensure ~/.shenan/ exists.
pub fn ensure_config_dir() -> Result<PathBuf> {
    let dir = config_dir()?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

// ── config.toml ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_relay")]
    pub relay: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            relay: default_relay(),
        }
    }
}

fn default_relay() -> String {
    "wss://relay.shenan.dev".into()
}

pub fn load_config() -> Result<Config> {
    let path = config_dir()?.join("config.toml");
    if !path.exists() {
        return Ok(Config::default());
    }
    let contents = std::fs::read_to_string(&path)?;
    let mut config: Config = toml::from_str(&contents)?;
    if config.relay.is_empty() {
        config.relay = default_relay();
    } else if !config.relay.starts_with("ws://") && !config.relay.starts_with("wss://") {
        anyhow::bail!(
            "invalid relay URL {:?} in ~/.shenan/config.toml — must start with ws:// or wss://\n\
             Reset it with: shenan config set relay {}",
            config.relay,
            default_relay()
        );
    }
    Ok(config)
}

pub fn save_config(config: &Config) -> Result<()> {
    let dir = ensure_config_dir()?;
    let path = dir.join("config.toml");
    let contents = toml::to_string_pretty(config)?;
    std::fs::write(&path, contents)?;
    Ok(())
}

// ── identity.toml ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub ssh_key_path: String,
    pub github_username: String,
}

pub fn load_identity() -> Result<Option<Identity>> {
    let path = config_dir()?.join("identity.toml");
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&path)?;
    let id: Identity = toml::from_str(&contents)?;
    Ok(Some(id))
}

pub fn save_identity(identity: &Identity) -> Result<()> {
    let dir = ensure_config_dir()?;
    let path = dir.join("identity.toml");
    let contents = toml::to_string_pretty(identity)?;
    std::fs::write(&path, contents)?;
    Ok(())
}

// ── trusted_senders.toml ──

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustedSenders {
    #[serde(default)]
    pub senders: Vec<TrustedSender>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedSender {
    pub github: String,
}

pub fn load_trusted_senders() -> Result<TrustedSenders> {
    let path = config_dir()?.join("trusted_senders.toml");
    if !path.exists() {
        return Ok(TrustedSenders::default());
    }
    let contents = std::fs::read_to_string(&path)?;
    let ts: TrustedSenders = toml::from_str(&contents)?;
    Ok(ts)
}

pub fn save_trusted_senders(ts: &TrustedSenders) -> Result<()> {
    let dir = ensure_config_dir()?;
    let path = dir.join("trusted_senders.toml");
    let contents = toml::to_string_pretty(ts)?;
    std::fs::write(&path, contents)?;
    Ok(())
}
