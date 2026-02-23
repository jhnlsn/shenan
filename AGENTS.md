# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build --workspace          # Debug build
cargo build --release            # Release build (binaries: target/release/shenan, target/release/shenan-relay)
cargo test --workspace           # Run all tests
cargo test -p shenan-proto       # Test proto crate only
cargo test -p shenan-relay       # Test relay crate only
cargo clippy --all-targets       # Lint
```

## Architecture

Shenan is a protocol for securely sharing secrets between developers using existing SSH Ed25519 keys and GitHub as a key registry. The authoritative reference is **SPEC.md**.

### Three-crate workspace

- **`proto/` (shenan-proto, MIT)** — Shared wire types and cryptography. No network code. Both relay and CLI depend on this.
- **`relay/` (shenan-relay, AGPL-3.0)** — WebSocket relay server. Blind pipe: routes encrypted bytes without knowing identities or contents post-authentication.
- **`cli/` (shenan, MIT)** — CLI client. Handles key discovery, encryption, session lifecycle, trust management.

### Data flow (send/receive)

1. Both parties independently derive the same **channel token** using X25519 DH shared secret + HKDF + current time window (rotates hourly)
2. Each authenticates to relay via Ed25519 challenge-response (relay discards identity immediately after)
3. Both present channel token + proof → relay opens blind pipe, discards all channel state
4. Sender encrypts payload with ephemeral X25519 + ChaCha20-Poly1305, sends binary through pipe
5. Receiver decrypts, sends `{"type":"received"}` ACK, both close

### Relay state model (SPEC §8.4)

The relay holds exactly three maps in memory — nothing else:
- `sessions`: conn_id → {expires_at, sender} (no identity)
- `pending_channels`: token → {proof, pubkey, socket, arrived_at} (max 5 min)
- `active_pipes`: pipe_id → {socket_a, socket_b} (no identity, deleted on close)

### Crypto stack (all in `proto/src/crypto/`)

Ed25519 signing → X25519 DH (via `to_montgomery()` conversion) → HKDF-SHA256 key derivation → ChaCha20-Poly1305 AEAD. Sensitive bytes wrapped in `Zeroizing<T>`.

### Connection lifecycle (relay/src/connection.rs)

State machine: `AwaitingHello` → `AwaitingAuth` → `Authenticated` → piped. The `AuthState` enum tracks this per connection.

## Key Constraints

- **No identity retention in relay**: Post-authentication, no code path may link a connection to a GitHub username. This is structural, not policy.
- **No dependency leakage**: relay and CLI share only `proto`. Never add cross-dependencies between relay and CLI.
- **Exactly one Ed25519 key per GitHub account**: The protocol fails deterministically if zero or multiple Ed25519 keys are found. This is a POC constraint (SPEC §5).
- **Direction string is always `"s2r"`**: Both sender and receiver use the same direction in channel token derivation to produce identical tokens.
- **Session = socket, not token**: The relay identifies sessions by WebSocket connection, not bearer tokens (SPEC §6.6).

## License Structure

Contributions to `relay/` are AGPL-3.0, `cli/` and `proto/` are MIT, `SPEC.md` is CC0. See CONTRIBUTING.MD.
