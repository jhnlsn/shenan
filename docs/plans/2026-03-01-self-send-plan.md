# Self-Send Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Allow `shenan send --to=github:me` on one machine and `shenan receive --from=github:me` on another machine with the same SSH key to successfully transfer a secret through the relay.

**Architecture:** Remove the CLI guard that rejects self-sends, add a `github:me` alias that resolves to the local GitHub username, and remove the relay admission check that rejects same-pubkey channels. The existing channel proof requirement already ensures only the key owner can form either side of the channel. Full design rationale in `docs/plans/2026-03-01-self-send-design.md`.

**Tech Stack:** Rust, Cargo workspace (`proto`, `relay`, `cli` crates). Run `cargo test --workspace` to verify. Run `cargo clippy --all-targets` to lint.

---

### Task 1: Prove self-DH token derivation works (proto)

**Files:**
- Modify: `proto/src/channel.rs` (tests block at bottom)

**Step 1: Write the failing test**

In `proto/src/channel.rs`, add this test inside the existing `#[cfg(test)] mod tests` block after the `proof_round_trip` test:

```rust
#[test]
fn self_send_derives_same_token_on_both_sides() {
    let alice = SigningKey::generate(&mut OsRng);
    let window = 123456u64;

    // When sender == recipient (same key), both "sides" must derive the same token
    let token_a = derive_token(&alice, &alice.verifying_key(), &alice.verifying_key(), window);
    let token_b = derive_token(&alice, &alice.verifying_key(), &alice.verifying_key(), window);

    // Token must be non-zero (self-DH is a valid, non-degenerate operation)
    assert_ne!(*token_a, [0u8; 32]);
    assert_eq!(*token_a, *token_b);
}
```

**Step 2: Run test to verify it passes**

```bash
cargo test -p shenan-proto channel::tests::self_send_derives_same_token_on_both_sides
```

Expected: PASS (self-DH is already valid — this test documents the behavior)

**Step 3: Commit**

```bash
git add proto/src/channel.rs
git commit -m "test(proto): document self-DH token derivation for self-send"
```

---

### Task 2: Remove same-pubkey admission check from relay

**Files:**
- Modify: `relay/src/admission.rs`
- Modify: `relay/src/connection.rs`

**Step 1: Remove `admission_check` from `relay/src/admission.rs`**

Delete these lines entirely (lines 23–29 and the associated test at lines 65–68):

```rust
/// Admission check: two distinct parties (§7.4 check_1).
pub fn admission_check(pubkey_1: &[u8], pubkey_2: &[u8]) -> Result<(), String> {
    if pubkey_1 == pubkey_2 {
        return Err("same pubkey on both sides of channel".into());
    }
    Ok(())
}
```

Also delete this test:
```rust
#[test]
fn admission_check_rejects_identical_keys() {
    let key = vec![1u8; 32];
    assert!(admission_check(&key, &key).is_err());
}
```

**Step 2: Run relay tests to confirm they still pass**

```bash
cargo test -p shenan-relay
```

Expected: all tests pass (the deleted test no longer runs)

**Step 3: Remove the `admission_check` call from `relay/src/connection.rs`**

In `connection.rs`, find the second-arrival block inside the channel-join handler. Remove only the `if admission::admission_check(...)` block (approximately lines 260–270). Leave everything else intact.

Before (remove this block):
```rust
if let Some((_, pending)) = state.pending_channels.remove(&token) {
    // Second arrival — admission check
    if admission::admission_check(&pending.pubkey, &pubkey_bytes_vec)
        .is_err()
    {
        // Same pubkey — drop both
        let _ = send_error(&tx, wire::error_codes::AUTH_FAILED, None);
        let _ = send_error(
            &pending.sender,
            wire::error_codes::AUTH_FAILED,
            None,
        );
        break;
    }

    // Open pipe — discard all channel state
    // ...
```

After (just the block removed — the pipe-open code stays):
```rust
if let Some((_, pending)) = state.pending_channels.remove(&token) {
    // Open pipe — discard all channel state
    // ...
```

Also remove the `// Second arrival — admission check` comment.

**Step 4: Build and test relay**

```bash
cargo build -p shenan-relay && cargo test -p shenan-relay
```

Expected: clean build, all tests pass

**Step 5: Commit**

```bash
git add relay/src/admission.rs relay/src/connection.rs
git commit -m "feat(relay): allow same-pubkey channels for self-send"
```

---

### Task 3: Add `github:me` alias and remove self-send guard (CLI send)

**Files:**
- Modify: `cli/src/commands/send.rs`

**Step 1: Write the failing test**

In `send.rs`, add this test to the `#[cfg(test)] mod tests` block:

```rust
#[test]
fn github_me_resolves_to_own_username() {
    // "me" (any case) should resolve to the caller's username
    // This is tested via the is_me helper used in run()
    assert!(is_me("me"));
    assert!(is_me("ME"));
    assert!(is_me("Me"));
    assert!(!is_me("alice"));
    assert!(!is_me("myself"));
}
```

**Step 2: Run test to verify it fails**

```bash
cargo test -p shenan 'send::tests::github_me_resolves_to_own_username'
```

Expected: FAIL — `is_me` doesn't exist yet

**Step 3: Implement**

In `send.rs`:

1. Add this helper function near the bottom of the file:
```rust
fn is_me(username: &str) -> bool {
    username.eq_ignore_ascii_case("me")
}
```

2. Replace the username extraction and guard block. Find this existing code:
```rust
let to_username = to
    .strip_prefix("github:")
    .ok_or_else(|| anyhow::anyhow!("--to must be in format github:<username>"))?;

// Load local identity
let id = storage::load_identity()?.context("not initialized — run `shenan init` first")?;
if is_self_target(to_username, &id.github_username) {
    anyhow::bail!(
        "refusing to send to yourself (target: github:{to_username}). use a different recipient"
    );
}
```

Replace with:
```rust
let to_raw = to
    .strip_prefix("github:")
    .ok_or_else(|| anyhow::anyhow!("--to must be in format github:<username>"))?;

// Load local identity
let id = storage::load_identity()?.context("not initialized — run `shenan init` first")?;

// Resolve "me" alias to the local GitHub username
let to_username = if is_me(to_raw) {
    id.github_username.as_str()
} else {
    to_raw
};
```

3. Delete the `is_self_target` function and its two tests (`is_self_target_matches_case_insensitively`, `is_self_target_rejects_other_users`).

**Step 4: Run tests**

```bash
cargo test -p shenan 'send::tests'
```

Expected: all pass

**Step 5: Commit**

```bash
git add cli/src/commands/send.rs
git commit -m "feat(cli): add github:me alias and allow self-send"
```

---

### Task 4: Add `github:me` alias and skip self-trust check (CLI receive)

**Files:**
- Modify: `cli/src/commands/receive.rs`

**Step 1: Write the failing test**

In `receive.rs`, add a `#[cfg(test)] mod tests` block at the bottom of the file:

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn github_me_resolves_to_own_username() {
        assert!(super::is_me("me"));
        assert!(super::is_me("ME"));
        assert!(!super::is_me("alice"));
    }
}
```

**Step 2: Run test to verify it fails**

```bash
cargo test -p shenan 'receive::tests::github_me_resolves_to_own_username'
```

Expected: FAIL — `is_me` doesn't exist in receive

**Step 3: Implement**

In `receive.rs`:

1. Add this helper function at the bottom of the file (above `#[cfg(test)]`):
```rust
fn is_me(username: &str) -> bool {
    username.eq_ignore_ascii_case("me")
}
```

2. Replace the username extraction and trust check. Find this existing code:
```rust
let from_username = from
    .strip_prefix("github:")
    .ok_or_else(|| anyhow::anyhow!("--from must be in format github:<username>"))?;

// Load local identity
let id = storage::load_identity()?.context("not initialized — run `shenan init` first")?;
let signing_key = identity::load_signing_key(&PathBuf::from(&id.ssh_key_path))?;
let config = storage::load_config()?;

// Verify sender is trusted
let trusted = storage::load_trusted_senders()?;
if !trusted.senders.iter().any(|s| s.github == from_username) {
    anyhow::bail!(
        "{from_username} is not in your trusted senders list.\n\
         Add them with: shenan trust add github:{from_username}"
    );
}
```

Replace with:
```rust
let from_raw = from
    .strip_prefix("github:")
    .ok_or_else(|| anyhow::anyhow!("--from must be in format github:<username>"))?;

// Load local identity
let id = storage::load_identity()?.context("not initialized — run `shenan init` first")?;
let signing_key = identity::load_signing_key(&PathBuf::from(&id.ssh_key_path))?;
let config = storage::load_config()?;

// Resolve "me" alias to the local GitHub username
let from_username = if is_me(from_raw) {
    id.github_username.as_str()
} else {
    from_raw
};

// Verify sender is trusted (self is always trusted)
if from_username != id.github_username.as_str() {
    let trusted = storage::load_trusted_senders()?;
    if !trusted.senders.iter().any(|s| s.github == from_username) {
        anyhow::bail!(
            "{from_username} is not in your trusted senders list.\n\
             Add them with: shenan trust add github:{from_username}"
        );
    }
}
```

**Step 4: Run tests**

```bash
cargo test -p shenan 'receive::tests'
```

Expected: all pass

**Step 5: Commit**

```bash
git add cli/src/commands/receive.rs
git commit -m "feat(cli): add github:me alias to receive; skip trust check for self"
```

---

### Task 5: Update SPEC

**Files:**
- Modify: `SPEC.md`

**Step 1: Update §7.4**

Find the admission check section in SPEC.md. It reads:

```
4. Performs the **admission check**:

```
check_1: pubkey_1 ≠ pubkey_2    // two distinct parties
```

The channel token includes a Diffie-Hellman shared secret...
```

Replace step 4 and the code block with:

```
4. Opens the bidirectional pipe if the proof is valid. Same-pubkey channels are
   permitted — a user may send to themselves across devices using the same SSH key.
   The proof requirement (step 3) is sufficient: only the key owner can produce a
   valid signature over `SHA256(channel_token)`.

The channel token includes a Diffie-Hellman shared secret...
```

Also update the §8.2 reference:

Find:
```
1. The relay verifies the proof and performs the admission check as described in §7.4 (second arrival)
```

Replace with:
```
1. The relay verifies the proof as described in §7.4 (second arrival)
```

**Step 2: Commit**

```bash
git add SPEC.md
git commit -m "spec: allow same-pubkey channels; remove check_1 admission constraint"
```

---

### Task 6: Full workspace build and lint check

**Step 1: Build everything**

```bash
cargo build --workspace
```

Expected: clean build, no errors

**Step 2: Run all tests**

```bash
cargo test --workspace
```

Expected: all tests pass

**Step 3: Lint**

```bash
cargo clippy --all-targets
```

Expected: no warnings

**Step 4: Commit if any clippy fixes were needed, otherwise done**

---

## Verification

After all tasks, the feature is complete when:

1. `cargo test --workspace` passes
2. `cargo clippy --all-targets` is clean
3. `shenan send --to=github:me KEY=val` on machine A connects to the relay and waits
4. `shenan receive --from=github:me` on machine B (same SSH key, same GitHub account) connects and receives the secret
