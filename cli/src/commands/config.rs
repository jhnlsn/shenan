//! `shenan config set/get` — relay URL management.

use crate::storage;
use anyhow::Result;

pub fn set(key: &str, value: &str) -> Result<()> {
    let mut config = storage::load_config()?;

    match key {
        "relay" => {
            config.relay = value.to_string();
            storage::save_config(&config)?;
            eprintln!("relay = {value}");
        }
        _ => anyhow::bail!("unknown config key: {key} (valid keys: relay)"),
    }

    Ok(())
}

pub fn get(key: &str) -> Result<()> {
    let config = storage::load_config()?;

    match key {
        "relay" => println!("{}", config.relay),
        _ => anyhow::bail!("unknown config key: {key} (valid keys: relay)"),
    }

    Ok(())
}
