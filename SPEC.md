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
15. [POC Decisions and Future Work](#15-poc-decisions-and-future-work)

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

These are not aspirational goals — they are verifiable architectural constraints. A conforming relay has no code path that stores, logs, or inspects payload content. Security guarantees are **structural**, not operational — they are enforced by what code exists, not by policy. An auditor can verify them by reading the source, not by trusting a document.

**Caveat:** During authentication (§6), the relay necessarily learns the client's GitHub username and public key in order to verify identity. A conforming relay discards this information immediately after verification. The structural guarantee begins *after* authentication — from that point forward, the relay holds no identity information, only anonymous authenticated connections and bare public keys (during the brief channel admission window) with no username attached.

---

## 2. Threat Model

### POC trust assumptions

The POC assumes a **trusted relay** operated at `wss://relay.shenan.dev`. The relay is trusted to execute the protocol correctly: discard identity data after authentication, not inspect or substitute payloads, and not retain relationship information. Self-hosted relays are supported but the operator is assumed to be trusted by both parties.

A future iteration will add zero-trust relay support (payload signing, relay-blind channel derivation) so that even a fully malicious relay cannot compromise confidentiality, authenticity, or relationship privacy. See §15.

### What shenan protects against

- **Harvest now, decrypt later (HNDL)** — No ciphertext is ever stored on any server. There is nothing to harvest.
- **Third-party eavesdropping** — End-to-end encryption ensures only the intended recipient can read the payload.
- **Channel squatting** — Channel tokens include a Diffie-Hellman shared secret that third parties cannot compute, even if they know both public keys (see §7.2).
- **Replay attacks** — Channel tokens rotate hourly. Captured tokens are useless after the current window expires.
- **Injection attacks** — The client-side friends list means only trusted senders can deliver secrets to your environment.

### What shenan does not protect against

- **Endpoint compromise** — If Alice's or Bob's machine is compromised, secrets on that machine are exposed. This is true of all cryptographic systems.
- **GitHub compromise** — Identity is anchored to GitHub public keys. A compromised GitHub account can authenticate to the relay as that user. The local trust list provides a second layer of defense.
- **Malicious relay (deferred)** — The POC trusts the relay. A malicious relay could theoretically substitute payloads, retain identity mappings, or observe the relationship graph. These attacks will be addressed in a future zero-trust relay iteration.
- **Traffic analysis at scale** — An adversary with access to network-level metadata (timing, packet sizes, connection origins) could potentially correlate sessions. This is a network-layer problem outside shenan's scope.

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

Shenan requires Ed25519 keys. Both parties MUST have an Ed25519 SSH key registered on GitHub. Support for other key types (RSA, ECDSA) may be added in a future version.

---

## 5. Identity Model

### GitHub as key registry

Each user is identified by their GitHub username. Their public keys are fetched from:

```
https://github.com/<username>.keys
```

This endpoint returns one or more public keys in OpenSSH authorized_keys format (one key per line).

### Key selection

The POC requires exactly one Ed25519 key per GitHub account. If no Ed25519 key is found, or if multiple Ed25519 keys are found, the CLI MUST fail with a clear error. This ensures both parties deterministically agree on the same key for channel derivation (§7.2) without ambiguity. See §15 for future multi-key support.

### Local identity

On first run, `shenan init` does not generate new keys. It discovers existing SSH keys on the local machine (from `~/.ssh/`) and asks the user which key corresponds to their GitHub identity. The private key never leaves the user's machine.

### No accounts

Shenan has no accounts, no registration, no passwords, no email. Identity is entirely derived from existing GitHub SSH keys.

---

## 6. Authentication

### 6.1 Overview

Authentication establishes that a connecting client controls a GitHub account with at least one registered SSH public key. After authentication, the client's GitHub identity is shed — the relay marks the WebSocket connection as authenticated but retains no link to the original identity.

### 6.2 Protocol

```
Client                                   Relay
  |                                        |
  |--- {"type":"hello","version":1,   --> |
  |     "user":"alice"}                   |
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
  |                                        | mark connection as authenticated
  |<-- {"type":"authenticated"}        --- |
```

### 6.3 Key fetching

The relay fetches public keys from `https://github.com/{username}.keys`. The relay MUST validate the username against `^[a-zA-Z0-9\-]+$` (GitHub's username rules) before constructing the URL, to prevent SSRF via path traversal. If validation fails, the fetch fails, the response contains no Ed25519 keys, or the response contains more than one Ed25519 key, the relay returns `{"type":"error","code":"auth_failed"}` and closes the connection.

### 6.4 Challenge construction

The nonce is 32 cryptographically random bytes encoded as lowercase hex. The challenge MUST be unique per connection attempt.

The relay uses the user's single Ed25519 key from the fetched key list and includes its fingerprint in the challenge message, allowing the client to select the correct private key.

### 6.5 Signature verification

The client signs `SHA256(nonce_bytes)` with its Ed25519 private key. The relay verifies with the corresponding public key using standard EdDSA verification.

### 6.6 Post-authentication state

After successful authentication:

1. The relay MUST discard the GitHub username from memory
2. The relay MUST discard the public key from memory
3. The relay marks the WebSocket connection as authenticated with an expiry of `now + session_expiry` (default 10 minutes, configurable)
4. The relay identifies sessions by their socket connection, not by a bearer token

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
window         = floor(unix_timestamp_seconds / 3600)
shared_secret  = X25519(my_ed25519_private, other_ed25519_public)
channel_token  = HKDF-SHA256(
  ikm    = shared_secret || canonical_pubkey(sender) || canonical_pubkey(recipient),
  salt   = nil,
  info   = "shenan-channel-v1:s2r:" || decimal(window),
  length = 32 bytes
)
```

Where:
- `shared_secret` is a Diffie-Hellman shared secret computed via X25519 between the two parties' Ed25519 keys. Both parties compute the same value: `X25519(a_private, b_public) == X25519(b_private, a_public)`. This ensures that only someone holding one of the two private keys can derive the channel token — third parties who know both public keys cannot.
- `canonical_pubkey(k)` is the SSH wire format encoding of key `k` (the binary blob, not base64)
- `||` denotes concatenation
- `decimal(n)` is the base-10 ASCII representation of the integer
- The direction string `"s2r"` is fixed — both parties use the same direction, producing an identical token

Both parties know the sender's pubkey and the recipient's pubkey (fetched from GitHub). Both know which role they are in (sender or recipient), so both independently construct the same `ikm` with the same key ordering. The X25519 shared secret is identical regardless of which side computes it. The result is that both parties derive the **same** channel token without any coordination, and no third party can compute or predict the token.

### 7.3 Channel proof

Each party generates a proof that they hold the private key corresponding to one of the keys used in the token derivation:

```
channel_proof = Sign(SHA256(channel_token), my_private_key)
```

The signature uses Ed25519 (EdDSA).

### 7.4 Relay verification

The client includes its public key in the channel join message:

```
Client → Relay: {
  channel_token,    // derived in §7.2
  channel_proof,    // signature over SHA256(channel_token)
  pubkey            // the client's SSH public key (raw bytes)
}
```

The relay identifies the client by its WebSocket connection, not by a bearer token.

**On first arrival**, the relay:

1. Checks that the connection corresponds to an authenticated session
2. Checks that no pending channel entry exists for this `channel_token`
3. Verifies `channel_proof` is a valid signature over `SHA256(channel_token)` using the provided `pubkey`
4. Stores: `{ channel_token -> { proof, pubkey_1, socket, arrived_at } }`

**On second arrival**, the relay:

1. Checks that the connection corresponds to an authenticated session
2. Looks up the pending entry for this `channel_token`
3. Verifies `channel_proof` is a valid signature over `SHA256(channel_token)` using the provided `pubkey`
4. Performs the **admission check**:

```
check_1: pubkey_1 ≠ pubkey_2    // two distinct parties
```

The channel token includes a Diffie-Hellman shared secret (§7.2) that only the two legitimate parties can compute. This makes the token unguessable by third parties, preventing channel squatting at the derivation level. The relay does not need to re-derive the token — the cryptographic properties of the derivation ensure that only the correct parties can produce a matching token and a valid proof over it.

5. If all checks pass: open bidirectional pipe, immediately discard all channel state (token, both proofs, both pubkeys)
6. If any check fails: drop BOTH connections, discard all channel state

**Privacy note:** The relay holds bare public keys (with no GitHub username attached) for at most `admission_window` (default 5 minutes) during the channel admission phase. This is a narrower exposure window than authentication, and the pubkeys carry no identity information without the username mapping that was discarded in §6.6. All pubkey material is discarded the moment the pipe opens or the admission times out.

### 7.5 Properties

| Property | Description |
|---|---|
| Deterministic | Both parties independently produce the same token |
| Ephemeral | Rotates every hour automatically |
| Anonymous | Token reveals nothing about the parties to the relay |
| Unlinkable | Different windows produce uncorrelated tokens |
| Exclusive | Requires knowledge of both exact pubkeys to derive |

### 7.6 Token rotation and clock skew

Channel tokens rotate every hour (`window` increments). Both parties MUST use the current window when computing tokens. The CLI SHOULD warn if the clock skew between client and relay exceeds 30 seconds.

If a channel join times out or the relay returns `{"type":"error","code":"channel_expired"}`, the client SHOULD retry with `window - 1` and then `window + 1` to account for clock skew near the hour boundary. At most one retry in each direction.

---

## 8. Channel Admission and Piping

### 8.1 First party arrival

When a client presents a channel join (see §7.4), and no pending entry exists for this `channel_token`:

1. The relay verifies the proof as described in §7.4 (first arrival)
2. The relay creates: `{ channel_token -> { proof, pubkey_1, socket, arrived_at } }`
3. The `arrived_at` timestamp is set to `now`. The pending channel entry MUST be deleted if no second party arrives within `admission_window` (default 5 minutes)
4. The relay sends `{"type":"waiting","expires_in_seconds":300}` to the first party

### 8.2 Second party arrival

When a second client presents the same `channel_token`:

1. The relay verifies the proof and performs the admission check as described in §7.4 (second arrival)
2. If all checks pass: the relay opens a bidirectional pipe between the two sockets and MUST immediately discard all channel state — channel token, both proofs, both pubkeys
3. If any check fails: the relay closes BOTH connections with `{"type":"error","code":"auth_failed"}` and MUST discard all channel state

Closing both connections on failure is deliberate: if one proof is invalid, the first party may also be compromised or confused.

The relay MUST NOT retain any state linking the two connections to each other after the pipe is established. The pipe state is `{ pipe_id -> { socket_a, socket_b } }` where `pipe_id` is a new random value with no link to either session or channel.

### 8.3 Piped transmission

Once a pipe is established:

1. The sender transmits the wire payload (§9.2) as a single WebSocket binary message. The relay forwards it as-is to the recipient. The recipient processes the first binary message received after `connected` as the complete wire payload
2. After successful decryption, the recipient sends `{"type":"received"}` as a text message through the pipe. The relay forwards this as-is to the sender. The sender waits for this message before considering the delivery complete
3. After sending or receiving the `received` message, both sides close their WebSocket connections cleanly (close code 1000)
4. The relay MUST NOT log message events, byte counts, or timing information
5. When either socket closes, the relay closes the other socket
6. The relay MUST immediately delete the pipe state

If the recipient fails to decrypt the payload (auth tag mismatch), it closes the connection without sending `received`. The sender interprets a connection close without a `received` message as delivery failure.

**Timeout:** The sender SHOULD wait up to 30 seconds for the `received` message after transmitting the payload. If no `received` message arrives, the sender reports delivery as uncertain (the payload may have been received but the ACK lost).

`max_payload_size` (default 1MB) limits the total bytes transferred per pipe. If exceeded, the relay closes both connections.

### 8.4 Relay memory model

At any given moment the relay holds **only** the following in memory:

```
authenticated_connections: {
  socket -> {
    authenticated: true,
    expires_at:    timestamp
  }
}

pending_channels: {
  channel_token (32 bytes) -> {
    proof:        channel_proof bytes,
    pubkey_1:     first party's public key (no username attached),
    socket:       first party's WebSocket connection,
    arrived_at:   timestamp
  }
  // Max lifetime: admission_window (default 5 minutes)
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

Both parties MUST have an Ed25519 SSH key on GitHub (see §4).

A fresh ephemeral X25519 keypair is generated for every send operation. This provides forward secrecy — compromise of the recipient's long-term private key does not compromise past sessions.

```
shared_secret     = X25519(sender_ephemeral_private, recipient_ed25519_public)
encryption_key    = HKDF-SHA256(shared_secret, salt=nil, info="shenan-payload-v1", length=32)
nonce             = random(12 bytes)                                // ChaCha20-Poly1305 uses 96-bit nonce
ciphertext        = ChaCha20-Poly1305-Encrypt(encryption_key, nonce, plaintext_json)
wire_payload      = sender_ephemeral_x25519_pubkey || nonce || ciphertext
```

Wire payload layout:

| Offset | Length | Content |
|--------|--------|---------|
| 0 | 32 bytes | Sender's ephemeral X25519 public key |
| 32 | 12 bytes | Nonce (random) |
| 44 | variable | ChaCha20-Poly1305 ciphertext (includes 16-byte auth tag) |

### 9.3 Decryption

The recipient decrypts by:

```
sender_ephemeral_pubkey = wire_payload[0:32]
nonce                   = wire_payload[32:44]
ciphertext              = wire_payload[44:]

shared_secret            = X25519(recipient_ed25519_private, sender_ephemeral_pubkey)
encryption_key           = HKDF-SHA256(shared_secret, salt=nil, info="shenan-payload-v1", length=32)
plaintext_json           = ChaCha20-Poly1305-Decrypt(encryption_key, nonce, ciphertext)
```

If decryption fails (auth tag mismatch), the payload MUST be silently dropped. No error detail is sent back through the relay.

The wire payload is transmitted as binary WebSocket data through the relay pipe.

---

## 10. Wire Format

All control messages between client and relay are JSON objects, one per WebSocket text message. Payload data is transmitted as binary WebSocket messages (opaque bytes) after the pipe is established.

### 10.1 Client → Relay messages

`hello`: initiates authentication
```json
{"type":"hello","version":1,"user":"<github-username>"}
```

The `version` field is the protocol version. A relay MUST reject connections with an unsupported version with `{"type":"error","code":"unsupported_version"}`.

`auth`: responds to challenge
```json
{"type":"auth","signature":"<base64-encoded-signature>"}
```

`channel`: presents channel token after authentication
```json
{
  "type": "channel",
  "token": "<hex-encoded-32-bytes>",
  "proof": "<base64-encoded-signature>",
  "pubkey": "<base64-encoded-ssh-public-key>"
}
```

`received`: delivery confirmation from recipient (sent through pipe, forwarded by relay)
```json
{"type":"received"}
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
{"type":"authenticated"}
```

`waiting`: first party acknowledged, waiting for second
```json
{"type":"waiting","expires_in_seconds":300}
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
| `unsupported_version` | Protocol version not supported by this relay |
| `auth_failed` | Authentication failed or channel proof invalid |
| `channel_expired` | No second party arrived within `admission_window` |
| `rate_limited` | Too many attempts from this IP |
| `payload_too_large` | Transfer exceeded `max_payload_size` |
| `internal_error` | Relay-side error (do not expose details) |

---

## 11. Relay Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `admission_window` | 5m | Time to wait for second party after first arrives |
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

### 12.4 Input parsing

**Command-line arguments:** `KEY=value` pairs are parsed directly into the payload `secrets` map.

**File input** (`--from-file` or stdin): The CLI parses `.env`-style files with the following rules:
- One `KEY=value` per line
- Lines starting with `#` are comments (ignored)
- Empty lines are ignored
- Values MAY be quoted with single or double quotes; quotes are stripped
- No variable interpolation or shell expansion
- Keys must match `[A-Za-z_][A-Za-z0-9_]*`

Example `.env` file:
```
# Database
DATABASE_URL=postgres://user:pass@host:5432/db
API_KEY="sk-abc123"
REDIS_URL='redis://localhost:6379'
```

Parses into the payload JSON (§9.1):
```json
{
  "version": 1,
  "secrets": {
    "DATABASE_URL": "postgres://user:pass@host:5432/db",
    "API_KEY": "sk-abc123",
    "REDIS_URL": "redis://localhost:6379"
  },
  "sender_pubkey_fingerprint": "SHA256:...",
  "timestamp": 1234567890
}
```

**Output** (`--out`): The CLI writes secrets in `.env` format (unquoted values, one per line). With `--merge`, new keys are appended and existing keys are updated in place.

---

## 13. Security Analysis

### 13.1 What a conforming relay reveals

The POC assumes a trusted, conforming relay. Against such a relay, even with complete real-time memory access:

**Can see:**
- Some number of verified GitHub users are currently connected (as anonymous authenticated connections)
- Some of those connections are paired on anonymous channels
- Opaque encrypted bytes flowing through those channels
- Approximate timing of transactions

**Cannot determine:**
- Which GitHub user corresponds to which connection (shed after auth)
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
| Channel squatting | DH shared secret in token derivation — third parties cannot compute the token |
| Ciphertext harvest | Structurally impossible — nothing stored |
| Replay | Channel tokens rotate hourly |
| DoS via queue exhaustion | No queue exists |
| GitHub API exhaustion | Rate limiting on auth phase |

### 13.5 GitHub key fetch as side channel

During authentication, the relay fetches `https://github.com/<username>.keys`. This creates an observable correlation at GitHub's end: GitHub (or an adversary monitoring GitHub's CDN) can see that a specific relay IP requested a specific user's keys at a specific time. If the adversary also monitors relay connections, they can correlate the key fetch timing with the connecting client's IP to de-anonymize the session.

Mitigations:
- The relay MAY cache GitHub key responses for a short TTL (e.g., 5 minutes) to decorrelate fetch timing from individual connections
- Self-hosted relays reduce exposure to a single organization's traffic
- A future version could support client-provided public keys with out-of-band verification, eliminating the GitHub fetch entirely

This side channel does not affect the relay's post-authentication anonymity guarantees — it is limited to the authentication phase.

### 13.6 Post-quantum roadmap

The current design uses X25519 for key agreement, which is vulnerable to a sufficiently powerful quantum computer via Shor's algorithm. The roadmap includes a hybrid key agreement combining X25519 with ML-KEM-768 (CRYSTALS-Kyber, NIST PQC standard), matching the approach taken by Signal's PQXDH protocol. This upgrade is backward-compatible and planned for a future version.

---

## 14. Implementation Notes

### 14.1 Memory zeroing

Implementations SHOULD zero sensitive bytes (private key material, nonces, channel tokens) immediately after use. In Rust, use the `zeroize` crate with `Zeroizing<T>` wrappers.

### 14.2 One connection per operation

Each `send` or `receive` operation uses a single WebSocket connection through the full lifecycle: authenticate → join channel → transmit/receive → close. Connections MUST NOT be reused across operations. This simplifies relay state management and ensures clean teardown.

### 14.3 No-log enforcement

A conforming relay MUST NOT log:
- GitHub usernames presented during authentication
- The association between authenticated connections and GitHub usernames
- Channel tokens or proofs
- That a pipe was established between any two parties
- Payload content or byte counts

It MAY log: connection errors, rate limit events (with IP only), and relay startup/shutdown events.

### 14.4 State cleanup

The relay MUST clean up:
- Expired pending channels (after `admission_window`)
- Expired authenticated sessions (after `session_expiry`)
- Stale pipes (on socket close or error)

Cleanup SHOULD run in a background task (e.g., `tokio::spawn`), not inline with request handling.

---

## 15. POC Decisions and Future Work

### Resolved for POC

1. **Multi-recipient sends** — Each recipient gets an independent channel. The CLI runs parallel send operations internally. This matches Signal's model (each message is independently encrypted per recipient, even in group contexts). A group channel primitive is unnecessary complexity for the POC.

2. **Relay federation** — No federation. Each relay is fully independent. The default public relay at `wss://relay.shenan.dev` handles the common case. Users may specify an alternative with `--relay` or `shenan config set relay`. Both parties must agree on a relay out of band.

3. **Key rotation** — The client always fetches fresh keys from GitHub at send/receive time (no client-side key cache). The relay uses a short-TTL FIFO cache for GitHub key responses to reduce API load and mitigate the key-fetch side channel (§13.5). If a user rotates their key, new sessions use the new key automatically. In-flight sessions are unaffected (they already have the pipe open).

4. **Relay discovery** — Default relay is `wss://relay.shenan.dev`. Self-hosters configure via `shenan config set relay` or per-command `--relay` flag. No DNS-based discovery for the POC.

### Known Limitations (future work)

5. **Zero-trust relay** — The POC assumes a trusted relay. A future iteration will add:
   - **Payload signing** — The sender signs the ciphertext with their Ed25519 identity key. The recipient verifies before trusting the content. This prevents a malicious relay from substituting payloads.
   - **Relay-blind identity** — Techniques to prevent a malicious relay from correlating auth-phase identity data with admission-phase pubkeys to reconstruct the relationship graph.

6. **Simultaneous online requirement** — Both parties must be online within the `admission_window` (default 5 minutes). This requires out-of-band coordination ("hey, run `shenan receive` now"). A future version may add a lightweight notification mechanism.

7. **Single Ed25519 key requirement** — The POC requires exactly one Ed25519 key per GitHub account and fails if zero or multiple are found. A future version should support multiple Ed25519 keys via a deterministic selection rule (e.g., first Ed25519 key in the GitHub response) or key ID negotiation, so users with multiple keys can participate without restriction.

8. **Additional key types** — Only Ed25519 is supported. RSA and ECDSA support may be added in a future version.

9. **Post-quantum key exchange** — Hybrid X25519 + ML-KEM-768 for payload encryption (see §13.6).

10. **Delivery confirmation robustness** — The POC uses a simple `received` message as delivery confirmation (§8.3). This is best-effort: if the ACK is lost due to a network partition after the payload was received, the sender reports delivery as uncertain even though the recipient has the secrets. A future version may add a more robust delivery receipt mechanism (e.g., signed receipts, retry semantics).

11. **Connection reuse** — The POC uses one WebSocket connection per operation (§14.2). A future version may support connection pooling or multiplexing for efficiency in high-throughput scenarios.

---

*This specification is CC0 — public domain. Implement it freely.*
