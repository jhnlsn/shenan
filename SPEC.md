# Shenan Protocol Specification

**Version:** 0.1-draft  
**Status:** Pre-alpha  
**License:** CC0 (public domain)

This document is the authoritative specification for the Shenan protocol. Anyone may implement a compatible relay or CLI client without license restrictions.

---

## Table of Contents

1. [Design Philosophy](#design-philosophy)
2. [Threat Model](#threat-model)
3. [Cryptographic Primitives](#cryptographic-primitives)
4. [Identity Model](#identity-model)
5. [Channel Derivation](#channel-derivation)
6. [Relay Specification](#relay-specification)
7. [CLI Specification](#cli-specification)
8. [Wire Protocol](#wire-protocol)
9. [Security Analysis](#security-analysis)
10. [Open Questions](#open-questions)

---

## Design Philosophy

The relay is a **blind pipe**, not a mailbox.  
The relay is a **blind notary**, not an identity provider.  
The relay **routes without storing**.  
The relay **verifies without identifying**.  
Security guarantees are **structural**, not operational.

They are enforced by what code exists, not by policy. An auditor can verify them by reading the source, not by trusting a document.

---

## Threat Model

### What shenan protects against

- **Harvest now, decrypt later (HNDL)** — No ciphertext is ever stored on any server. There is nothing to harvest.
- **Relay compromise** — Even complete real-time memory access to a running relay reveals no useful information about who is communicating with whom, or what is being transmitted.
- **Relay operator surveillance** — The relay is architecturally incapable of constructing a relationship graph between users.
- **Slot-occupancy attacks** — A malicious party cannot occupy a channel slot to block a legitimate transaction (see Phase 3).
- **Replay attacks** — Channel tokens rotate hourly. Captured tokens are useless after the current window expires.
- **Injection attacks** — The client-side friends list means only trusted senders can deliver secrets to your environment.

### What shenan does not protect against

- **Endpoint compromise** — If Alice's or Bob's machine is compromised, secrets on that machine are exposed. This is true of all cryptographic systems.
- **GitHub compromise** — Identity is anchored to GitHub public keys. A compromised GitHub account can authenticate to the relay as that user.
- **Traffic analysis at scale** — An adversary with access to network-level metadata (timing, packet sizes, connection origins) could potentially correlate sessions. This is a network-layer problem outside shenan's scope.
- **Quantum attacks on stored secrets** — Shenan eliminates stored ciphertext, making harvest-and-decrypt-later attacks impossible. However secrets stored locally after receipt are only as protected as the user's local storage.

---

## Cryptographic Primitives

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

Ed25519 keys are preferred. RSA keys are supported for compatibility. ECDSA keys are supported.

---

## Identity Model

### GitHub as key registry

Each user is identified by their GitHub username. Their public keys are fetched from:

```
https://github.com/<username>.keys
```

This endpoint returns one or more public keys in OpenSSH format.

### Key selection

If a user has multiple keys, the CLI selects the Ed25519 key if present, otherwise falls back to ECDSA, then RSA. The user may override key selection explicitly.

### Local identity

On first run, `shenan init` does not generate new keys. It discovers existing SSH keys on the local machine (from `~/.ssh/`) and asks the user which key corresponds to their GitHub identity. The private key never leaves the user's machine.

### No accounts

Shenan has no accounts, no registration, no passwords, no email. Identity is entirely derived from existing GitHub SSH keys.

---

## Channel Derivation

Channel tokens allow two parties to find each other on the relay without the relay knowing their identities, and without out-of-band coordination.

### Inputs

```
sender_pubkey    — the sender's SSH public key (raw bytes)
recipient_pubkey — the recipient's SSH public key (raw bytes)
direction        — fixed ASCII string "s2r" (sender to receiver)
window           — floor(unix_utc_timestamp / 3600) as big-endian uint64
                   represents the current hour
```

Both parties know their own pubkey and can fetch the other's from GitHub. Both know which direction they are in. Both share the same current time. Therefore both independently derive identical inputs.

### Derivation

```
ikm    = sender_pubkey || recipient_pubkey
info   = "shenan-channel-v1" || direction || window_bytes
salt   = nil (HKDF default)
length = 32 bytes

channel_token = HKDF-SHA256(ikm, salt, info, length)
```

### Channel proof

Each party signs the channel token with their SSH private key to prove they hold the private key corresponding to one of the pubkeys that derived the channel.

```
channel_proof = Sign(channel_token, private_key)
```

The signing algorithm matches the key type (Ed25519Sign, RSASign-SHA256, etc.).

### Properties

| Property | Description |
|---|---|
| Deterministic | Both parties independently produce the same token |
| Ephemeral | Rotates every hour automatically |
| Anonymous | Token reveals nothing about the parties to the relay |
| Unlinkable | Different windows produce uncorrelated tokens |
| Exclusive | Requires knowledge of both exact pubkeys to derive |
| Directional | Sender and receiver compute proofs from their own keys |

### Time window skew tolerance

Clocks may differ by up to 30 seconds. If a channel join times out, the CLI should retry with `window - 1` to account for clock skew near the hour boundary.

---

## Relay Specification

### What the relay never does

```
✗ Never stores any message or payload, even transiently on disk
✗ Never writes anything to disk
✗ Never logs message events (connection events only, no identity)
✗ Never retains a mapping of ephemeral ID to GitHub identity
✗ Never knows the relationship between any two parties
✗ Never holds a channel slot open for an unverified party
✗ Never accumulates ciphertext for any duration
```

### Memory model

At any given moment the relay holds **only** the following in memory:

```
active_sessions: {
  ephemeral_id (random 256-bit) -> {
    socket:    WebSocket connection,
    expiry:    timestamp (session_expiry from now)
  }
}

pending_channels: {
  channel_token (32 bytes) -> {
    proof_1:        channel_proof bytes,
    pubkey_1:       extracted signing pubkey,
    ephemeral_id_1: ephemeral session ID,
    arrived_at:     timestamp
  }
  // Exists only between first and second party arriving
  // Max lifetime: admission_window (60 seconds)
  // Deleted immediately when pipe opens or times out
}

active_pipes: {
  pipe_id (random) -> {
    socket_1: WebSocket,
    socket_2: WebSocket
  }
  // No identity information whatsoever
  // Deleted immediately when transmission completes
}
```

That is the **complete** relay state. Nothing else is stored.

### Configuration

| Parameter | Default | Description |
|---|---|---|
| `admission_window` | 60s | Time to wait for second party on a channel |
| `session_expiry` | 10m | Idle authenticated session lifetime |
| `max_payload_size` | 1MB | Upper bound for a single transmission |
| `rate_limit_auth` | 10/min | Authentication attempts per IP |
| `port` | 8080 | WebSocket listen port |
| `tls` | required | All connections must use WSS |

### Phase 1 — Authentication

**Purpose:** Prove the connecting client is a legitimate GitHub user. Acts as anti-abuse gate only. GitHub identity is shed immediately after this phase.

```
Client → Relay:   CONNECT (WebSocket upgrade)

Relay → Client:   {
                    "type": "auth_challenge",
                    "nonce": "<random 256-bit hex>"
                  }

Client → Relay:   {
                    "type": "auth_response",
                    "github_username": "<username>",
                    "pubkey_fingerprint": "<SHA256 fingerprint>",
                    "signature": "<base64 Ed25519/RSA signature of nonce>"
                  }
```

Relay validation steps:
1. Fetch `https://github.com/<username>.keys`
2. Find the key matching `pubkey_fingerprint`
3. Verify `signature` over `nonce` using that key
4. On success: assign random `ephemeral_id`, **discard** `github_username` and pubkey
5. Store only `{ ephemeral_id -> { socket, expiry } }`

```
Relay → Client:   {
                    "type": "auth_success",
                    "ephemeral_id": "<random 256-bit hex>"
                  }
```

On failure: connection dropped, no state retained.

### Phase 2 — Channel Derivation (client-side only)

This phase occurs entirely on the client. The relay does not participate. See [Channel Derivation](#channel-derivation).

### Phase 3 — Channel Admission

**Purpose:** Relay verifies both parties belong to this channel before opening the pipe. Prevents slot-occupancy attacks. Relay does this without knowing who the parties are.

```
Client → Relay:   {
                    "type": "channel_join",
                    "channel_token": "<32-byte hex>",
                    "channel_proof": "<base64 signature>",
                    "ephemeral_id": "<assigned in phase 1>"
                  }
```

**On first join:**
1. Verify `channel_proof` is a valid signature over `channel_token`
2. Extract the signing pubkey from the proof
3. Store `{ channel_token -> { proof_1, pubkey_1, ephemeral_id_1, arrived_at } }`
4. Notify client: `{ "type": "channel_waiting" }`
5. If second party does not arrive within `admission_window`: drop channel state, notify client

**On second join:**
1. Verify `channel_proof` is a valid signature over `channel_token`
2. Extract the signing pubkey from the proof
3. Perform **complementary proof check**:

```
expected_pubkeys = {pubkey that derived channel as sender,
                    pubkey that derived channel as receiver}

check_1: pubkey_1 ∈ expected_pubkeys  ✓
check_2: pubkey_2 ∈ expected_pubkeys  ✓
check_3: pubkey_1 ≠ pubkey_2          ✓
```

4. If all checks pass:
   - Open bidirectional pipe between the two sockets
   - **Immediately discard ALL channel state**: channel_token, both proofs, both pubkeys
   - Relay now has zero knowledge this channel exists

5. If any check fails:
   - Drop **both** connections (not just the impostor)
   - Discard all channel state
   - No state retained
   - Reason: if check fails, first party may also be compromised or confused

```
Relay → both clients:  { "type": "channel_open" }
```

### Phase 4 — Transmission

**Purpose:** Move encrypted bytes from sender to recipient. Relay is maximally dumb.

```
Sender → Relay:   { "type": "payload", "data": "<base64 ciphertext>" }
Relay → Recipient: { "type": "payload", "data": "<base64 ciphertext>" }

Recipient → Relay: { "type": "ack" }
Relay → Sender:    { "type": "delivered" }

Both connections close.
Pipe entry removed from relay memory.
```

The relay does not buffer, inspect, log, or retain the payload at any point.

### Abuse prevention

| Attack | Prevention |
|---|---|
| Unauthenticated flood | GitHub auth gate — must prove GitHub identity |
| Slot occupancy | Option A relay-side complementary proof check |
| Ciphertext harvest | Structurally impossible — nothing stored |
| Replay | Channel tokens rotate hourly |
| DoS via queue exhaustion | No queue exists |
| GitHub API exhaustion | Rate limiting on auth phase |

---

## CLI Specification

### Local storage

```
~/.shenan/
  config.toml          # relay URL, key preference
  trusted_senders.toml # friends list — never transmitted
  identity.toml        # which local SSH key to use
```

No secrets are stored in `~/.shenan/`. The private key remains in `~/.ssh/` under the user's control.

### Friends list

```toml
# ~/.shenan/trusted_senders.toml
# Payloads from senders not on this list are silently dropped
# This file never leaves the local machine

[[senders]]
github = "alice"

[[senders]]
github = "bob"
```

### Commands

```bash
# Initialize shenan — discover local SSH keys, select identity
shenan init

# Trust management
shenan trust add github:<username>
shenan trust remove github:<username>
shenan trust list

# Send a secret
shenan send --to github:<username> KEY=value
shenan send --to github:<username> KEY1=value1 KEY2=value2
shenan send --to github:<username> --from-file .env.production

# Send to multiple recipients
shenan send --to github:<alice> --to github:<bob> KEY=value

# Receive
shenan receive --from github:<username>
shenan receive --from github:<username> --out .env
shenan receive --from github:<username> --out .env --merge  # append, don't overwrite

# Configuration
shenan config set relay wss://relay.shenan.dev
shenan config set relay wss://my-self-hosted-relay.example.com
shenan config get relay
```

### Payload format

The payload is a JSON object encrypted using the recipient's public key:

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

This JSON is then encrypted:

```
shared_secret  = X25519(sender_ephemeral_private, recipient_public)
encryption_key = HKDF-SHA256(shared_secret, "shenan-payload-v1")
ciphertext     = ChaCha20-Poly1305-Encrypt(encryption_key, plaintext_json)
wire_payload   = sender_ephemeral_pubkey || ciphertext
```

The recipient decrypts by:
```
shared_secret  = X25519(recipient_private, sender_ephemeral_pubkey)
encryption_key = HKDF-SHA256(shared_secret, "shenan-payload-v1")
plaintext_json = ChaCha20-Poly1305-Decrypt(encryption_key, ciphertext)
```

Note: a fresh ephemeral keypair is generated for every send. This provides forward secrecy — compromise of the recipient's long-term private key does not compromise past sessions.

---

## Wire Protocol

All communication between client and relay is over **WebSocket Secure (WSS)**. Plaintext WebSocket is not permitted.

Messages are JSON objects with a `type` field. See Phase 1-4 above for message formats.

### Message types

| Type | Direction | Description |
|---|---|---|
| `auth_challenge` | Relay → Client | Nonce for authentication |
| `auth_response` | Client → Relay | Signed nonce + GitHub username |
| `auth_success` | Relay → Client | Ephemeral ID assigned |
| `auth_failure` | Relay → Client | Authentication failed |
| `channel_join` | Client → Relay | Request to join a channel |
| `channel_waiting` | Relay → Client | First party, waiting for second |
| `channel_open` | Relay → Client | Both parties verified, pipe open |
| `channel_timeout` | Relay → Client | Second party did not arrive |
| `channel_rejected` | Relay → Client | Complementary proof check failed |
| `payload` | Client ↔ Relay ↔ Client | Encrypted payload bytes |
| `ack` | Client → Relay | Payload received |
| `delivered` | Relay → Client | Delivery confirmed to sender |
| `error` | Relay → Client | Generic error |

---

## Security Analysis

### What a fully compromised relay reveals

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

### Forward secrecy

Each send operation generates a fresh ephemeral X25519 keypair. Compromise of the recipient's long-term private key does not expose past transmissions.

### Channel token collision resistance

HKDF-SHA256 output is 256 bits. The probability of two different party pairs deriving the same channel token in the same time window is negligible (2^-256).

### Post-quantum roadmap

The current design uses X25519 for key agreement, which is vulnerable to a sufficiently powerful quantum computer via Shor's algorithm. The roadmap includes a hybrid key agreement combining X25519 with ML-KEM-768 (CRYSTALS-Kyber, NIST PQC standard), matching the approach taken by Signal's PQXDH protocol. This upgrade is backward-compatible and planned for v0.3.

---

## Open Questions

These are design questions not yet resolved in the specification.

1. **Multi-recipient sends** — When sending to multiple recipients simultaneously, should each recipient get an independent channel, or should there be a group channel primitive?

2. **Relay federation** — Should multiple relays be able to interoperate, or is each relay fully independent? Independent relays are simpler but require both parties to agree on a relay in advance.

3. **Key rotation** — When a user rotates their GitHub SSH keys, channel tokens derived from old keys become invalid. What is the graceful handling for this?

4. **Offline notification** — The current design requires both parties to be online simultaneously. Is there a way to notify a recipient that someone wants to send them a secret, without storing the payload?

5. **Relay discovery** — How do two parties agree on which relay to use without out-of-band coordination? A default public relay at `relay.shenan.dev` handles the common case, but self-hosters need a discovery mechanism.

---

*This specification is CC0 — public domain. Implement it freely.*