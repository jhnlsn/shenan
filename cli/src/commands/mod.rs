pub mod config;
pub mod init;
pub mod receive;
pub mod send;
pub mod trust;

/// Returns true if `username` is the `"me"` self-alias (case-insensitive).
pub(super) fn is_me(username: &str) -> bool {
    username.eq_ignore_ascii_case("me")
}

#[cfg(test)]
mod tests {
    use super::is_me;

    #[test]
    fn is_me_matches_case_insensitively() {
        assert!(is_me("me"));
        assert!(is_me("ME"));
        assert!(is_me("Me"));
        assert!(!is_me("alice"));
        assert!(!is_me("myself"));
    }
}
