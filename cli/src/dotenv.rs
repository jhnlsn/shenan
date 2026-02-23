//! .env file parsing and writing (SPEC §12.4).

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};

/// Parse a .env file into key-value pairs.
///
/// Rules:
/// - One KEY=value per line
/// - Lines starting with # are comments (ignored)
/// - Empty lines are ignored
/// - Values may be quoted with single or double quotes; quotes are stripped
/// - No variable interpolation
/// - Keys must match [A-Za-z_][A-Za-z0-9_]*
pub fn parse_dotenv(content: &str) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("line {}: missing '='", line_num + 1))?;

        let key = key.trim();
        if !is_valid_key(key) {
            anyhow::bail!(
                "line {}: invalid key '{}' (must match [A-Za-z_][A-Za-z0-9_]*)",
                line_num + 1,
                key
            );
        }

        let value = strip_quotes(value.trim());
        map.insert(key.to_string(), value.to_string());
    }

    Ok(map)
}

/// Parse a .env file from a path.
pub fn parse_dotenv_file(path: &Path) -> Result<BTreeMap<String, String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    parse_dotenv(&content)
}

/// Write secrets to .env format.
pub fn format_dotenv(secrets: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for (key, value) in secrets {
        out.push_str(key);
        out.push('=');
        out.push_str(value);
        out.push('\n');
    }
    out
}

/// Write secrets to a file. With merge=true, update existing keys in place and append new ones.
pub fn write_dotenv_file(
    path: &Path,
    secrets: &BTreeMap<String, String>,
    merge: bool,
) -> Result<()> {
    if merge && path.exists() {
        let existing = std::fs::read_to_string(path)?;
        let merged = merge_dotenv(&existing, secrets);
        std::fs::write(path, merged)?;
    } else {
        std::fs::write(path, format_dotenv(secrets))?;
    }
    Ok(())
}

/// Merge new secrets into existing .env content.
/// Existing keys are updated in place; new keys are appended.
fn merge_dotenv(existing: &str, new_secrets: &BTreeMap<String, String>) -> String {
    let mut remaining: BTreeMap<String, String> = new_secrets.clone();
    let mut lines: Vec<String> = Vec::new();

    for line in existing.lines() {
        let trimmed = line.trim();
        if let Some((key, _)) = trimmed.split_once('=') {
            let key = key.trim();
            if let Some(new_value) = remaining.remove(key) {
                lines.push(format!("{key}={new_value}"));
                continue;
            }
        }
        lines.push(line.to_string());
    }

    // Append remaining new keys
    for (key, value) in remaining {
        lines.push(format!("{key}={value}"));
    }

    let mut out = lines.join("\n");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn is_valid_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    let mut chars = key.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn strip_quotes(value: &str) -> &str {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
        {
            return &value[1..value.len() - 1];
        }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let input = r#"
# Database
DATABASE_URL=postgres://user:pass@host:5432/db
API_KEY="sk-abc123"
REDIS_URL='redis://localhost:6379'
"#;
        let secrets = parse_dotenv(input).unwrap();
        assert_eq!(secrets["DATABASE_URL"], "postgres://user:pass@host:5432/db");
        assert_eq!(secrets["API_KEY"], "sk-abc123");
        assert_eq!(secrets["REDIS_URL"], "redis://localhost:6379");
    }

    #[test]
    fn format_round_trip() {
        let mut secrets = BTreeMap::new();
        secrets.insert("A".into(), "1".into());
        secrets.insert("B".into(), "2".into());
        let formatted = format_dotenv(&secrets);
        let parsed = parse_dotenv(&formatted).unwrap();
        assert_eq!(parsed, secrets);
    }

    #[test]
    fn merge_updates_and_appends() {
        let existing = "A=old\nB=keep\n";
        let mut new = BTreeMap::new();
        new.insert("A".into(), "new".into());
        new.insert("C".into(), "added".into());
        let merged = merge_dotenv(existing, &new);
        assert!(merged.contains("A=new"));
        assert!(merged.contains("B=keep"));
        assert!(merged.contains("C=added"));
    }

    #[test]
    fn invalid_key_rejected() {
        assert!(parse_dotenv("123BAD=value").is_err());
    }
}
