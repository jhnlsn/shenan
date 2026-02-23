╔══════════════════════════════════════════════════════════════╗
║           SHROUD RELAY — COMPLETE SPECIFICATION v0.1         ║
╚══════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DESIGN PHILOSOPHY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The relay is a blind pipe, not a mailbox.
The relay is a blind notary, not an identity provider.
The relay routes without storing.
The relay verifies without identifying.
The relay's security guarantees are structural, not operational.
  — They are enforced by what code exists, not by policy.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHAT THE RELAY NEVER DOES (STRUCTURAL GUARANTEES)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  - Never stores any message or payload, even transiently
  - Never writes anything to disk
  - Never logs message events, only connection events
  - Never knows which GitHub identity is routing to which
  - Never retains pubkeys after authentication handshake
  - Never knows the relationship between two parties
  - Never holds a channel slot open for an unverified party
  - Never accumulates ciphertext for future harvest

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 1 — AUTHENTICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Purpose:
  Prove the connecting client is a legitimate GitHub user.
  Acts as an anti-abuse gate only.
  GitHub identity is shed immediately after this phase.

Flow:
  1. Client opens WebSocket connection to relay
  2. Client sends:  { github_username, pubkey_fingerprint }
  3. Relay fetches: https://github.com/<username>.keys
  4. Relay verifies: claimed pubkey exists in fetched keyset
  5. Relay issues:  { nonce: <random_256bit_value> }
  6. Client signs nonce with their SSH private key
  7. Client sends:  { signature }
  8. Relay verifies signature against fetched pubkey
  9. On success:
       - Relay assigns ephemeral_id (random, unrelated to identity)
       - Relay DISCARDS github_username and pubkey from memory
       - Relay stores ONLY: { ephemeral_id -> { socket, expiry } }
  10. On failure:
       - Connection dropped
       - No state retained

Post-authentication relay memory:
  { ephemeral_id -> { socket, expiry } }
  
  Nothing else. GitHub identity is gone.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 2 — CHANNEL DERIVATION (CLIENT SIDE ONLY)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Purpose:
  Both parties independently derive an identical, anonymous,
  ephemeral channel token. No coordination required.
  The relay never participates in this derivation.

Inputs (all publicly available or locally known):
  sender_pubkey    — fetched from github.com/sender.keys
  recipient_pubkey — fetched from github.com/recipient.keys
  direction        — fixed string, "s2r" (sender to receiver)
                     both parties know their role
  window           — floor(unix_utc_timestamp / 3600)
                     current hour as integer
                     provides automatic token rotation

Derivation:
  channel_token = HKDF-SHA256(
    ikm  = sender_pubkey || recipient_pubkey,
    info = direction || window,
    len  = 32 bytes
  )

Properties:
  Deterministic:  both parties independently produce same token
  Ephemeral:      rotates every hour automatically
  Anonymous:      token reveals nothing about the parties to relay
  Unlinkable:     different windows produce uncorrelated tokens
  Exclusive:      requires knowledge of both exact pubkeys

Channel proof (each party independently):
  proof = Sign(channel_token, my_private_key)
  
  This proves "I hold a private key corresponding to one of
  the pubkeys used to derive this channel" without revealing
  which one or linking to a GitHub identity.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 3 — CHANNEL ADMISSION (RELAY VERIFIES, IDENTITY BLIND)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Purpose:
  Relay verifies both parties belong to this channel
  before opening the pipe. Prevents slot occupancy attacks.
  Relay does this WITHOUT knowing who the parties are.

Client sends to relay:
  {
    channel_token,   // derived in phase 2
    channel_proof,   // signature over token with private key
    ephemeral_id     // assigned in phase 1
  }

Relay on receiving first channel join request:
  1. Verify channel_proof is a valid signature over channel_token
  2. Extract the signing pubkey from the proof
  3. Store: {
       channel_token -> {
         proof_1:      channel_proof,
         pubkey_1:     extracted signing pubkey,
         ephemeral_id: ephemeral_id,
         arrived_at:   timestamp
       }
     }
  4. Wait for second party
  5. If second party does not arrive within admission_window
     (suggested: 60 seconds):
       - Drop channel state
       - Notify first party: "timeout, no second party arrived"

Relay on receiving second channel join request:
  1. Verify channel_proof is a valid signature over channel_token
  2. Extract the signing pubkey from the proof
  3. Perform complementary proof check:
  
       expected_pubkeys = derive_pubkeys_from_channel_token(
                            channel_token
                          )
       // channel_token was derived from two pubkeys —
       // we can verify the two proofs correspond to exactly
       // those two pubkeys
       
       check_1: pubkey_1 ∈ expected_pubkeys  ✓ or ✗
       check_2: pubkey_2 ∈ expected_pubkeys  ✓ or ✗
       check_3: pubkey_1 ≠ pubkey_2          ✓ or ✗
       
  4. If all checks pass:
       - Open bidirectional pipe between the two sockets
       - Discard ALL channel state immediately:
           channel_token, both proofs, both pubkeys
       - Relay now has zero knowledge this channel exists
       
  5. If any check fails:
       - Drop BOTH connections (not just the impostor)
       - Discard all channel state
       - No state retained
       - Reason: if check fails, first party may also
                 be compromised or confused

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 4 — TRANSMISSION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Purpose:
  Move encrypted bytes from sender to recipient.
  Relay is maximally dumb during this phase.

Flow:
  1. Pipe is open between two verified anonymous sockets
  2. Sender streams encrypted payload bytes
  3. Relay forwards bytes to recipient socket as they arrive
  4. Relay does not buffer, does not inspect, does not log
  5. Recipient acknowledges receipt
  6. Both connections closed
  7. Pipe entry removed from relay memory
  8. Relay has now forgotten this transaction entirely

Relay during transmission:
  Sees: opaque bytes flowing between two anonymous sockets
  Does not see: plaintext, key material, usernames, metadata

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RELAY MEMORY MODEL — COMPLETE PICTURE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

At any given moment the relay holds in memory:

  active_sessions: {
    ephemeral_id -> { socket, expiry }
    // GitHub identity shed after phase 1
    // No usernames, no pubkeys
  }

  pending_channels: {
    channel_token -> {
      proof_1, pubkey_1, ephemeral_id_1, arrived_at
    }
    // Exists only between first and second party arriving
    // Max lifetime: admission_window (60 seconds)
    // Deleted immediately when pipe opens or times out
  }

  active_pipes: {
    pipe_id -> { socket_1, socket_2 }
    // No identity information at all
    // Deleted immediately when transmission completes
  }

  That is the complete relay state. Nothing else exists.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ABUSE PREVENTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

GitHub authentication gate:
  All connections must prove GitHub identity to connect.
  Bots, scripts without valid GitHub keys are rejected.
  Raises the cost of abuse to: acquire real GitHub accounts.

Slot occupancy attack (prevented by Option A):
  Malicious party cannot occupy a channel slot because
  their proof will fail the complementary check.
  Both connections dropped on failure — no partial state.

Ciphertext harvest (structurally impossible):
  Nothing is stored. Ever. Nothing to harvest.

Replay attacks:
  Channel tokens rotate hourly. A captured token is
  invalid after the current window expires.
  Channel proofs are signatures over ephemeral tokens —
  a captured proof is useless in any other window.

Denial of service:
  No database to corrupt or fill.
  No queue to exhaust.
  Connections are cheap and stateless.
  Rate limiting on authentication phase prevents
  GitHub API exhaustion.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHAT A FULLY COMPROMISED RELAY REVEALS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Even with complete real-time memory access an attacker sees:

  - Some number of verified GitHub users are connected
  - Some of those connections are paired on anonymous pipes
  - Opaque encrypted bytes flowing through those pipes
  - Approximate timing of transactions

An attacker cannot determine:

  - Which GitHub user is talking to which
  - What relationship exists between any two parties
  - What the bytes contain
  - Whether the same two parties have transacted before
  - Anything useful for a harvest-now-decrypt-later attack
    (there is nothing to harvest)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONFIGURATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  admission_window:    60s   (how long to wait for second party)
  session_expiry:      10m   (idle authenticated session lifetime)
  max_payload_size:    1MB   (reasonable upper bound for secrets)
  rate_limit_auth:     10    (auth attempts per IP per minute)
  transport:           WSS   (WebSocket over TLS, mandatory)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SELF-HOSTING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  The relay is designed to be trivially self-hostable.
  Target: single binary, single Docker image, zero config.
  A team can run their own relay on a $5 VPS.
  No database dependency. No external services.
  No state survives a restart — this is a feature.
  Multiple relays can coexist — clients choose which to use.
  No relay federation needed — each relay is independent.