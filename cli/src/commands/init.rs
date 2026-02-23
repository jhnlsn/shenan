//! `shenan init` — discover local SSH keys, select identity.

use anyhow::Result;
use dialoguer::Select;

use crate::identity;
use crate::storage;

pub async fn run() -> Result<()> {
    eprintln!("Scanning ~/.ssh/ for Ed25519 keys...");

    let keys = identity::discover_ed25519_keys()?;

    if keys.is_empty() {
        anyhow::bail!(
            "No Ed25519 SSH keys found in ~/.ssh/.\n\
             Generate one with: ssh-keygen -t ed25519"
        );
    }

    let items: Vec<String> = keys
        .iter()
        .map(|k| format!("{} ({})", k.path.display(), k.fingerprint))
        .collect();

    let selection = if keys.len() == 1 {
        eprintln!("Found 1 Ed25519 key: {}", items[0]);
        0
    } else {
        Select::new()
            .with_prompt("Select your SSH key")
            .items(&items)
            .default(0)
            .interact()?
    };

    let selected = &keys[selection];

    // Ask for GitHub username
    let github_username: String = dialoguer::Input::new()
        .with_prompt("GitHub username (this key must be registered on GitHub)")
        .interact_text()?;

    // Verify key is on GitHub
    eprintln!("Verifying key on GitHub...");
    match crate::github::fetch_ed25519_pubkeys(&github_username).await {
        Ok(github_keys) => {
            let local_key = identity::load_signing_key(&selected.path)?;
            let local_pub = local_key.verifying_key().to_bytes();
            if !github_keys.iter().any(|k| k.key_bytes == local_pub) {
                let github_fps: Vec<String> = github_keys.iter().map(|k| k.fingerprint()).collect();
                anyhow::bail!(
                    "The selected local key is not among the Ed25519 keys on GitHub for {}.\n\
                     Local fingerprint: {}\n\
                     GitHub fingerprints: {}",
                    github_username,
                    selected.fingerprint,
                    github_fps.join(", ")
                );
            }
            eprintln!("Key verified on GitHub.");
        }
        Err(e) => {
            eprintln!("Warning: could not verify key on GitHub: {e}");
            eprintln!("Continuing anyway — make sure this key is registered on GitHub.");
        }
    }

    let id = storage::Identity {
        ssh_key_path: selected.path.to_string_lossy().to_string(),
        github_username,
    };

    storage::save_identity(&id)?;
    eprintln!("Identity saved to ~/.shenan/identity.toml");

    // Ensure config exists with defaults
    if storage::load_config()?.relay.is_empty() {
        storage::save_config(&storage::Config::default())?;
    }

    Ok(())
}
