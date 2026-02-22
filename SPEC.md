# Shenan Protocol Specification

**Version:** 0.1.0-draft
**Status:** Pre-alpha
**License:** CC0 (public domain)

This document is the authoritative specification for the Shenan protocol. Any conforming implementation of this specification is a valid Shenan relay or client. The reference implementation is at `relay/` and `cli/`.

---

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [Threat Model](#2-threat-model)
3. [Transport](#3-transport)
4. [Cryptographic Primitives](#4-cryptographic-primitives)
5. [Identity Model](#5-identity-model)
6. [Authentication](#6-authentication)
7. [Channel Derivation](#7-channel-derivation)
8. [Channel Admission and Piping](#8-channel-admission-and-piping)
9. [Payload Encryption](#9-payload-encryption)
10. [Wire Format](#10-wire-format)
11. [Relay Configuration](#11-relay-configuration)
12. [CLI Specification](#12-cli-specification)
13. [Security Analysis](#13-security-analysis)
14. [Implementation Notes](#14-implementation-notes)
15. [Open Questions](#15-open-questions)

---

## 1. Design Philosophy

**The relay is a blind pipe, not a mailbox.**
**The relay is a blind notary, not an identity provider.**
**The relay routes without storing.**
**The relay verifies without identifying.**

A conforming Shenan relay:

- Routes messages without knowing the identities of the parties
- Stores no secrets, even transiently
- Maintains no logs of transmission events
- Cannot correlate any two sessions to the same pair of parties
- Forgets everything about a transmission immediately upon completion

These are not aspirational goals — they are verifiable architectural constraints. A conforming relay has no code path that stores, logs, or inspects payload content. Security guarantees are **structural**, not operational. They are enforced by what code exists, not by policy. An auditor can verify them by reading the source, not by trusting a document.

---

## 2. Threat Model

### What shenan protects against

- **Harvest now, decrypt later (HNDL)** — No ciphertext is ever stored on any server. There is nothing to harvest.
- **Relay compromise** — Even complete real-time memory access to a running relay reveals no useful information about who is communicating with whom, or what is being transmitted.
- **Relay operator surveillance** — The relay is architecturally incapable of constructing a relationship graph between users.
- **Slot-occupancy attacks** — A malicious party cannot occupy a channel slot to block a legitimate transaction (see §8).
- **Replay attacks** — Channel tokens rotate hourly. Captured tokens are useless after the current window expires.
- **Injection attacks** — The client-side friends list means only trusted senders can deliver secrets to your environment.

### What shenan does not protect against

- **Endpoint compromise** — If Alice's or Bob's machine is compromised, secrets on that machine are exposed. This is true of all cryptographic systems.
- **GitHub compromise** — Identity is anchored to GitHub public keys. A compromised GitHub account can authenticate to the relay as that user. However, key substitution only affects future sessions (there is nothing stored), and the local trust list provides a second layer of defense.
- **Malicious relay disruption** — A malicious relay can drop connections or delay transmission (denial of service), but it cannot read secrets or learn identities.
- **Traffic analysis at scale** — An adversary with access to network-level metadata (timing, packet sizes, connection origins) could potentially correlate sessions. This is a network-layer problem outside shenan's scope.
- **Quantum attacks on stored secrets** — Shenan eliminates stored ciphertext, making harvest-and-decrypt-later attacks impossible. However, secrets stored locally after receipt are only as protected as the user's local storage.

---

## 3. Transport

All relay connections MUST use WebSocket over TLS (WSS). Plaintext WebSocket connections MUST be rejected with HTTP 426 Upgrade Required.

The relay MUST present a valid TLS certificate. Clients MUST verify the certificate.

Required: TLS 1.3. TLS 1.2 MAY be supported for compatibility but is not recommended.

---

## 4. Cryptographic Primitives

| Purpose | Algorithm | Rationale |
|---|---|---|
| Key agreement | X25519 | Fast, well-audited, used by Signal/age |
| Symmetric encryption | ChaCha20-Poly1305 | AEAD, constant-time, no timing side-channels |
| Key derivation | HKDF-SHA256 | Standard KDF, used for channel token derivation |
| Signatures | Ed25519 | Fast, small signatures, compatible with SSH keys |
| Hashing | SHA-256 | Standard |
| Post-quantum (roadmap) | ML-KEM-768 (CRYSTALS-Kyber) | NIST PQC standard, hybrid with X25519 |

### Key format

Shenan uses SSH public keys as the identity primitive. GitHub exposes these at `https://github.com/<username>.keys`. This means:

- No new key infrastructure is required
- Developers already maintain these keys
- The key registry is decentralized from shenan's perspective (GitHub is a pre-existing trust anchor developers already use)

Implementations MUST support Ed25519 and RSA keys. They SHOULD support ECDSA keys. They MAY support other key types. Ed25519 is preferred.

---

## 5. Identity Model

### GitHub as key registry

Each user is identified by their GitHub username. Their public keys are fetched from:

```
https://github.com/<username>.keys
```

This endpoint returns one or more public keys in OpenSSH authorized_keys format (one key per line).

### Key selection

If a user has multiple keys, the CLI selects the Ed25519 key if present, otherwise falls back to ECDSA, then RSA. The user may override key selection explicitly.

### Local identity

On first run, `shenan init` does not generate new keys. It discovers existing SSH keys on the local machine (from `~/.ssh/`) and asks the user which key corresponds to their GitHub identity. The private key never leaves the user's machine.

### No accounts

Shenan has no accounts, no registration, no passwords, no email. Identity is entirely derived from existing GitHub SSH keys.

---

## 6. Authentication

### 6.1 Overview

Authentication establishes that a connecting client controls a GitHub account with at least one registered SSH public key. After authentication, the client's GitHub identity is shed and replaced with an ephemeral session identifier that has no link to the original identity.

### 6.2 Protocol

```
Client                                   Relay
  |                                        |
  |--- {"type":"hello","user":"alice"} --> |
  |                                        | fetch https://github.com/alice.keys
  |                                        | select a key for the challenge
  |<-- {"type":"challenge",                |
  |      "nonce":"<32 bytes hex>",         |
  |      "pubkey_fingerprint":"<fp>"} ---- |
  |                                        |
  | sign(nonce) with matching private key  |
  |--- {"type":"auth",                     |
  |     "signature":"<base64>"}        --> |
  |                                        | verify signature
  |                                        | discard: user, pubkey
  |                                        | generate: ephemeral_id (random 32 bytes)
  |<-- {"type":"authenticated",            |
  |     "ephemeral_id":"<hex>"}        --- |
```

### 6.3 Key fetching

The relay fetches public keys from `https://github.com/{username}.keys`. If the fetch fails or returns no keys, the relay returns `{"type":"error","code":"auth_failed"}` and closes the connection.

### 6.4 Challenge construction

The nonce is 32 cryptographically random bytes encoded as lowercase hex. The challenge MUST be unique per connection attempt.

The relay MAY select one specific key from the user's key list and include its fingerprint in the challenge message, allowing the client to select the correct private key. The relay MUST verify against the indicated key only.

Alternatively, the relay MAY issue a challenge valid for any of the user's keys. In this case, the relay verifies the signature against each key in sequence and accepts if any match.

### 6.5 Signature verification

The client signs `SHA256(nonce_bytes)` with its private key. The relay verifies with the corresponding public key.

For Ed25519: standard EdDSA signature over the digest.
For RSA: RSASSA-PKCS1-v1_5 with SHA-256.
For ECDSA: standard ECDSA over the digest.

### 6.6 Post-authentication state

After successful authentication:

1. The relay MUST discard the GitHub username from memory
2. The relay MUST discard the public key from memory
3. The relay stores only: `{ ephemeral_id -> { socket, expires_at } }`
4. `expires_at` is `now + session_expiry` (default 10 minutes, configurable)
5. The `ephemeral_id` MUST be 32 cryptographically random bytes, independent of the user's identity

The relay MUST NOT log the association between `ephemeral_id` and GitHub username.

On failure: connection dropped, no state retained.

### 6.7 Rate limiting

The relay SHOULD rate-limit authentication attempts per source IP. The recommended default is 10 attempts per IP per minute with exponential backoff.

Failed authentication attempts MUST NOT reveal whether the GitHub user exists or whether the signature was close to valid.

---

## 7. Channel Derivation

### 7.1 Overview

Channel tokens allow two parties to rendezvous on the relay without the relay knowing who they are. Both parties independently compute the same token using only their public keys and the current time. No prior coordination is required beyond knowing each other's GitHub username.

### 7.2 Token computation

```
window        = floor(unix_timestamp_seconds / 3600)
channel_token = HKDF-SHA256(
  ikm    = canonical_pubkey(sender) || canonical_pubkey(recipient),
  salt   = nil,
  info   = "shenan-channel-v1:" || direction || ":" || decimal(window),
  length = 32 bytes
)
```

Where:
- `direction` is the ASCII string `"s2r"` (sender to receiver) or `"r2s"` (receiver to sender)
- `canonical_pubkey(k)` is the SSH wire format encoding of key `k` (the binary blob, not base64)
- `||` denotes concatenation
- `decimal(n)` is the base-10 ASCII representation of the integer

The sender computes the token with `direction="s2r"`. The receiver computes the complementary token with `direction="r2s"`. Both tokens are presented to the relay, which verifies that they are complementary (derived from the same pair of keys in opposite directions for the same window).

### 7.3 Channel proof

Each party generates a proof that they hold the private key corresponding to one of the keys used in the token derivation:

```
channel_proof = Sign(SHA256(channel_token), my_private_key)
```

The signing algorithm matches the key type (Ed25519, RSA-SHA256, ECDSA).

### 7.4 Relay verification

When the relay receives `(channel_token, channel_proof, ephemeral_id)`:

1. Check that `ephemeral_id` corresponds to an authenticated session
2. Check that no channel entry already exists for this `channel_token` (first arrival) or that a pending entry exists (second arrival)
3. Verify that `channel_proof` is a valid signature over `SHA256(channel_token)`

The relay cannot verify *which* public key was used to generate the signature, because the relay does not know the public keys — it only knows the ephemeral IDs. The proof verifies that the presenter has a consistent private key; the relay trusts that the token derivation math ensures only the correct parties can produce matching tokens.

This is a deliberate trade-off: the relay gains zero knowledge about identities in exchange for delegating proof validity to the cryptographic properties of the token derivation.

### 7.5 Properties

| Property | Description |
|---|---|
| Deterministic | Both parties independently produce the same token |
| Ephemeral | Rotates every hour automatically |
| Anonymous | Token reveals nothing about the parties to the relay |
| Unlinkable | Different windows produce uncorrelated tokens |
| Exclusive | Requires knowledge of both exact pubkeys to derive |
| Directional | Sender and receiver compute complementary tokens (s2r/r2s) |

### 7.6 Token rotation and clock skew

Channel tokens rotate every hour (`window` increments). Both parties MUST use the current window when computing tokens. The CLI SHOULD warn if the clock skew between client and relay exceeds 30 seconds.

If a session spans a window boundary (e.g., initiated at 23:59 and received at 00:01), the client SHOULD retry with the adjacent window's token if the relay returns `{"type":"error","code":"channel_expired"}`.

---

## 8. Channel Admission and Piping

### 8.1 First party arrival

When a client presents a channel token:

1. The relay checks for an existing pending channel entry for this token
2. If none exists, the relay creates: `{ channel_token -> { proof, ephemeral_id, arrived_at } }`
3. The `arrived_at` timestamp is set to `now`. The pending channel entry MUST be deleted if no second party arrives within `admission_window` (default 60 seconds)
4. The relay sends `{"type":"waiting","expires_in_seconds":60}` to the first party

### 8.2 Second party arrival

When a second client presents the complementary channel token:

1. The relay looks up the pending entry for this token
2. The relay verifies the complementary relationship between the two tokens
3. If valid: the relay opens a bidirectional pipe between the two sockets and MUST immediately delete the pending channel state
4. If invalid: the relay closes BOTH connections with `{"type":"error","code":"auth_failed"}` and MUST delete the pending channel state

Closing both connections on failure is deliberate: if one proof is invalid, the first party may also be compromised or confused.

The relay MUST NOT retain any state linking the two ephemeral IDs to each other after the pipe is established. The pipe state is `{ pipe_id -> { socket_a, socket_b } }` where `pipe_id` is a new random value with no link to either session or channel.

### 8.3 Piped transmission

Once a pipe is established:

1. The relay streams raw bytes between the two sockets with no inspection, buffering, or transformation
2. The relay MUST NOT log message events, byte counts, or timing information
3. When either socket closes, the relay closes the other socket
4. The relay MUST immediately delete the pipe state

`max_payload_size` (default 1MB) limits the total bytes transferred per pipe. If exceeded, the relay closes both connections.

### 8.4 Relay memory model

At any given moment the relay holds **only** the following in memory:

```
active_sessions: {
  ephemeral_id (random 32 bytes) -> {
    socket:     WebSocket connection,
    expires_at: timestamp
  }
}

pending_channels: {
  channel_token (32 bytes) -> {
    proof:        channel_proof bytes,
    ephemeral_id: ephemeral session ID,
    arrived_at:   timestamp
  }
  // Max lifetime: admission_window (60 seconds)
  // Deleted immediately when pipe opens or times out
}

active_pipes: {
  pipe_id (random) -> {
    socket_a: WebSocket,
    socket_b: WebSocket
  }
  // No identity information whatsoever
  // Deleted immediately when either side closes
}
```

That is the **complete** relay state. Nothing else is stored.

---

## 9. Payload Encryption

### 9.1 Payload format

The payload is a JSON object containing one or more secrets:

```json
{
  "version": 1,
  "secrets": {
    "DATABASE_URL": "postgres://...",
    "API_KEY": "sk-abc123"
  },
  "sender_pubkey_fingerprint": "SHA256:...",
  "timestamp": 1234567890
}
```

### 9.2 Encryption

A fresh ephemeral X25519 keypair is generated for every send operation. This provides forward secrecy — compromise of the recipient's long-term private key does not compromise past sessions.

```
shared_secret  = X25519(sender_ephemeral_private, recipient_public)
encryption_key = HKDF-SHA256(shared_secret, salt=nil, info="shenan-payload-v1", length=32)
ciphertext     = ChaCha20-Poly1305-Encrypt(encryption_key, nonce, plaintext_json)
wire_payload   = sender_ephemeral_pubkey || nonce || ciphertext
```

### 9.3 Decryption

The recipient decrypts by:

```
sender_ephemeral_pubkey, nonce, ciphertext = parse(wire_payload)
shared_secret  = X25519(recipient_private, sender_ephemeral_pubkey)
encryption_key = HKDF-SHA256(shared_secret, salt=nil, info="shenan-payload-v1", length=32)
plaintext_json = ChaCha20-Poly1305-Decrypt(encryption_key, nonce, ciphertext)
```

The wire payload is transmitted as binary WebSocket data through the relay pipe.

---

## 10. Wire Format

All control messages between client and relay are JSON objects, one per WebSocket text message. Payload data is transmitted as binary WebSocket messages (opaque bytes) after the pipe is established.

### 10.1 Client → Relay messages

`hello`: initiates authentication
```json
{"type":"hello","user":"<github-username>"}
```

`auth`: responds to challenge
```json
{"type":"auth","signature":"<base64-encoded-signature>"}
```

`channel`: presents channel token after authentication
```json
{
  "type": "channel",
  "token": "<hex-encoded-32-bytes>",
  "proof": "<base64-encoded-signature>"
}
```

### 10.2 Relay → Client messages

`challenge`: issued after hello
```json
{
  "type": "challenge",
  "nonce": "<hex-encoded-32-bytes>",
  "pubkey_fingerprint": "<SHA256:...>"
}
```

`authenticated`: confirms successful auth
```json
{"type":"authenticated","ephemeral_id":"<hex>"}
```

`waiting`: first party acknowledged, waiting for second
```json
{"type":"waiting","expires_in_seconds":60}
```

`connected`: pipe established, switch to binary frames
```json
{"type":"connected"}
```

`error`: error condition, connection will close
```json
{"type":"error","code":"<code>","message":"<human-readable>"}
```

### 10.3 Error codes

| Code | Meaning |
|------|---------|
| `auth_failed` | Authentication failed or channel proof invalid |
| `channel_expired` | No second party arrived within `admission_window` |
| `rate_limited` | Too many attempts from this IP |
| `payload_too_large` | Transfer exceeded `max_payload_size` |
| `internal_error` | Relay-side error (do not expose details) |

---

## 11. Relay Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `admission_window` | 60s | Time to wait for second party after first arrives |
| `session_expiry` | 10m | Idle authenticated session lifetime |
| `max_payload_size` | 1048576 (1MB) | Maximum bytes per pipe transfer |
| `rate_limit_auth` | 10/min/IP | Auth attempt rate limit |
| `tls_cert` | required | Path to TLS certificate |
| `tls_key` | required | Path to TLS private key |
| `bind` | `:443` | Address to bind |

---

## 12. CLI Specification

### 12.1 Local storage

```
~/.shenan/
  config.toml          # relay URL, key preference
  trusted_senders.toml # friends list — never transmitted
  identity.toml        # which local SSH key to use
```

No secrets are stored in `~/.shenan/`. The private key remains in `~/.ssh/` under the user's control.

### 12.2 Friends list

```toml
# ~/.shenan/trusted_senders.toml
# Payloads from senders not on this list are silently dropped
# This file never leaves the local machine

[[senders]]
github = "alice"

[[senders]]
github = "bob"
```

### 12.3 Commands

```bash
# Initialize — discover local SSH keys, select identity
shenan init

# Trust management
shenan trust add github:<username>
shenan trust remove github:<username>
shenan trust list

# Send a secret (blocks until recipient connects)
shenan send --to github:<username> KEY=value
shenan send --to github:<username> KEY1=value1 KEY2=value2
shenan send --to github:<username> --from-file .env.production
shenan send --to github:<username> < .env.production

# Receive (blocks until sender connects)
shenan receive --from github:<username>
shenan receive --from github:<username> --out .env
shenan receive --from github:<username> --out .env --merge  # append, don't overwrite

# Configuration
shenan config set relay wss://relay.shenan.dev
shenan config set relay wss://my-self-hosted-relay.example.com
shenan config get relay

# Self-hosted relay
shenan relay start --port 443 --tls-cert cert.pem --tls-key key.pem
```

---

## 13. Security Analysis

### 13.1 What a fully compromised relay reveals

Even with complete real-time memory access:

**Can see:**
- Some number of verified GitHub users are currently connected (as anonymous ephemeral IDs)
- Some of those connections are paired on anonymous channels
- Opaque encrypted bytes flowing through those channels
- Approximate timing of transactions

**Cannot determine:**
- Which GitHub user corresponds to which ephemeral ID (shed after auth)
- Which GitHub user is talking to which
- What relationship exists between any two parties
- What the bytes contain
- Whether the same two parties have transacted before
- Anything useful for a harvest-now-decrypt-later attack (there is nothing to harvest)

### 13.2 Forward secrecy

Each send operation generates a fresh ephemeral X25519 keypair. Compromise of the recipient's long-term private key does not expose past transmissions.

### 13.3 Channel token collision resistance

HKDF-SHA256 output is 256 bits. The probability of two different party pairs deriving the same channel token in the same time window is negligible (2^-256).

### 13.4 Abuse prevention

| Attack | Prevention |
|---|---|
| Unauthenticated flood | GitHub auth gate — must prove GitHub identity |
| Slot occupancy | Complementary proof check on channel admission |
| Ciphertext harvest | Structurally impossible — nothing stored |
| Replay | Channel tokens rotate hourly |
| DoS via queue exhaustion | No queue exists |
| GitHub API exhaustion | Rate limiting on auth phase |

### 13.5 Post-quantum roadmap

The current design uses X25519 for key agreement, which is vulnerable to a sufficiently powerful quantum computer via Shor's algorithm. The roadmap includes a hybrid key agreement combining X25519 with ML-KEM-768 (CRYSTALS-Kyber, NIST PQC standard), matching the approach taken by Signal's PQXDH protocol. This upgrade is backward-compatible and planned for a future version.

---

## 14. Implementation Notes

### 14.1 Memory zeroing

Implementations SHOULD zero sensitive bytes (private key material, nonces, channel tokens) immediately after use. In Go, use `crypto/subtle` utilities. In Rust, use `zeroize`.

### 14.2 No-log enforcement

A conforming relay MUST NOT log:
- GitHub usernames presented during authentication
- The association between ephemeral IDs and GitHub usernames
- Channel tokens or proofs
- That a pipe was established between any two parties
- Payload content or byte counts

It MAY log: connection errors, rate limit events (with IP only), and relay startup/shutdown events.

### 14.3 State cleanup

The relay MUST clean up:
- Expired pending channels (after `admission_window`)
- Expired authenticated sessions (after `session_expiry`)
- Stale pipes (on socket close or error)

Cleanup SHOULD run in a background goroutine, not inline with request handling.

---

## 15. Open Questions

These are design questions not yet resolved in the specification.

1. **Multi-recipient sends** — When sending to multiple recipients simultaneously, should each recipient get an independent channel, or should there be a group channel primitive?

2. **Relay federation** — Should multiple relays be able to interoperate, or is each relay fully independent? Independent relays are simpler but require both parties to agree on a relay in advance.

3. **Key rotation** — When a user rotates their GitHub SSH keys, channel tokens derived from old keys become invalid. What is the graceful handling for this?

4. **Offline notification** — The current design requires both parties to be online simultaneously. Is there a way to notify a recipient that someone wants to send them a secret, without storing the payload?

5. **Relay discovery** — How do two parties agree on which relay to use without out-of-band coordination? A default public relay at `relay.shenan.dev` handles the common case, but self-hosters need a discovery mechanism.

---

*This specification is CC0 — public domain. Implement it freely.*
