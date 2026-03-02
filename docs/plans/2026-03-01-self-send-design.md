# Self-Send Design

**Date:** 2026-03-01
**Status:** Approved
**Scope:** Allow a user to send a secret to themselves across devices using the same SSH key.

---

## Problem

Today `shenan send --to=github:<username>` rejects the request if the target username matches the sender's own username. The relay also rejects channels where both sides present the same public key. This prevents cross-device secret transfer for users who share the same SSH key across machines — the primary "dog food" use case.

---

## Approach

Remove both the CLI guard and the relay admission check that reject same-pubkey channels. The existing proof requirement (`channel_proof = Sign(SHA256(token), key)`) is sufficient to ensure only the key owner can form either side of the channel. The old same-pubkey check was belt-and-suspenders, not load-bearing for security.

No protocol version bump is needed. No new wire messages. No new files.

---

## UX

```
# Machine A
shenan send --to=github:me DB_PASSWORD=hunter2

# Machine B
shenan receive --from=github:me
```

`github:me` is a special alias that resolves to the local stored GitHub username at runtime.

---

## Changes

### 1. `cli/src/commands/send.rs`

- Resolve `github:me` to `id.github_username` before processing the recipient
- Delete the `is_self_target()` call and the `is_self_target` helper function

### 2. `cli/src/commands/receive.rs`

- Resolve `github:me` to `id.github_username` for symmetry

### 3. `relay/src/admission.rs`

- Remove the `admission_check` function and its test (`admission_check_rejects_identical_keys`)

### 4. `relay/src/connection.rs`

- Remove the `admission::admission_check` call and the error branch that drops both connections on same-pubkey

### 5. `SPEC.md` §7.4

- Remove `check_1: pubkey_1 ≠ pubkey_2`
- Add note: same-pubkey channels are valid; the proof requirement is sufficient

---

## Crypto notes

Self-DH is mathematically valid. When sender == recipient:

```
my_x_priv  = X25519(ed25519_priv)
my_x_pub   = X25519(ed25519_pub)
shared     = DH(my_x_priv, my_x_pub)   # scalar² · G — deterministic, non-zero
ikm        = shared || my_pubkey || my_pubkey
token      = HKDF(ikm, info="shenan-channel-v1:s2r:<window>")
```

Both machines hold the same private key and compute the same token independently. The relay sees two connections presenting the same token with valid proofs — it opens the pipe as normal.

---

## Tests

| File | Test |
|---|---|
| `proto/src/channel.rs` | `self_dh_produces_valid_token` — same key on both sides, assert token is non-zero and both sides agree |
| `cli/src/commands/send.rs` | `github_me_resolves_to_own_username` |
| `cli/src/commands/receive.rs` | `github_me_resolves_to_own_username` |
| `relay/src/admission.rs` | Remove `admission_check_rejects_identical_keys` |

---

## Security analysis

Removing `check_1` introduces no regression:

- **Channel squatting:** Still prevented. Token derivation requires the DH shared secret, which requires the private key.
- **Proof forgery:** Still prevented. The proof is a signature over `SHA256(token)` — only the key owner can produce it.
- **Replay:** Still prevented. Tokens rotate hourly.
- **Loop-back confusion:** The original motivation for `check_1`. Now intentional and safe for the self-send case.
