# shenan

> *From Irish/Gaelic — Sionainn, the River Shannon, named for a goddess who sought forbidden knowledge. Also: mischief happening just out of sight.*

Decentralized, ephemeral secret distribution for developers. No servers hold your secrets. No relay knows who you are. No ciphertext is ever stored.

```bash
# Send a secret to a teammate
shenan send --to github:alice DATABASE_URL=postgres://prod:5432/mydb

# Receive a secret from a trusted sender
shenan receive --from github:bob
```

---

## The Problem

Every team has the same moment: someone generates a production secret and now has to get it to the people who need it. The options are all bad.

- Slack or email — plaintext, logged, searchable forever
- A `.env` file committed to git — a breach waiting to happen
- A secrets manager like Doppler or Vault — centralized, proprietary, and someone else holds a key that can decrypt your secrets

The centralized model has a deeper problem: stored ciphertext is harvestable. Even if it can't be decrypted today, a sufficiently motivated adversary stores it and waits. This is the **harvest now, decrypt later** attack, and it's not theoretical — it's happening now.

## The Shenan Approach

Shenan borrows from how Signal and WhatsApp handle secure messaging and applies it to developer secret distribution.

- **End-to-end encrypted** — secrets are encrypted on your machine to the recipient's public key. The relay sees opaque bytes it cannot read.
- **Ephemeral by design** — the relay is a pipe, not a mailbox. Nothing is stored, queued, or logged. A secret exists in transit only — milliseconds, not minutes.
- **Identity-blind routing** — the relay verifies you are a legitimate GitHub user but immediately forgets who you are. It routes anonymous connections, not named ones.
- **Zero harvest surface** — there is no ciphertext to harvest. Ever. The attack doesn't apply.
- **Client-side trust** — your friends list lives on your machine. The relay never knows the relationship between any two parties.
- **Self-hostable relay** — run your own relay on a $5 VPS. Single binary, zero config, no database.
- **Fully open source** — the relay is AGPL v3, the CLI is MIT. The security guarantees are in the code, not in a policy document.

## How It Works

```
┌─────────────────┐                              ┌─────────────────┐
│   Bob's CLI     │                              │   Alice's CLI   │
│                 │                              │                 │
│ 1. Fetch Alice's│                              │ 1. Fetch Bob's  │
│    pubkey from  │                              │    pubkey from  │
│    GitHub       │                              │    GitHub       │
│                 │                              │                 │
│ 2. Derive anon  │◄──── same channel token ────►│ 2. Derive same  │
│    channel from │      (no coordination        │    channel from │
│    both pubkeys │       needed)                │    both pubkeys │
│    + time window│                              │    + time window│
│                 │                              │                 │
│ 3. Encrypt      │                              │                 │
│    payload to   │                              │                 │
│    Alice's key  │                              │                 │
│                 │          Relay               │                 │
│ 4. Connect ─────┼──────── (blind pipe) ────────┼───── Connect    │
│    present proof│  verifies both proofs        │     present     │
│                 │  opens pipe                  │     proof       │
│                 │  forgets immediately         │                 │
│ 5. Send ────────┼─────── bytes flow ──────────►│ 5. Receive      │
│                 │  relay never held them       │                 │
│                 │                              │ 6. Decrypt with │
│                 │                              │    private key  │
│                 │                              │                 │
│                 │                              │ 7. Write to     │
│                 │                              │    .env ✓       │
└─────────────────┘                              └─────────────────┘
```

The channel token is derived independently by both parties from their public keys and the current time window — no coordination, no out-of-band token exchange. The relay verifies cryptographic proofs that both parties belong to the channel before opening the pipe, preventing slot-occupancy attacks.

## Security Properties

| Property | Guarantee |
|---|---|
| Encryption | End-to-end, client-side only |
| Relay knowledge | Anonymous ephemeral IDs only |
| Relationship graph | Never constructed, never stored |
| Ciphertext at rest | Structurally impossible |
| Harvest now / decrypt later | No surface to harvest |
| Post-quantum readiness | Hybrid X25519 + ML-KEM (roadmap) |
| Relay compromise impact | Zero — nothing to learn, nothing to steal |

## What a Fully Compromised Relay Reveals

Even with complete real-time memory access an attacker sees:

- Some number of verified GitHub users are currently connected
- Some of those are paired on anonymous channels
- Opaque encrypted bytes flowing through those channels

An attacker **cannot** determine who is talking to whom, what relationship exists between any two parties, what the bytes contain, or anything useful for a harvest-now-decrypt-later attack.

## Getting Started

```bash
# Install
brew install shenan        # macOS
cargo install shenan       # from source

# Initialize — generates your local keypair
shenan init

# Add trusted senders (stored locally, never leaves your machine)
shenan trust add github:alice
shenan trust add github:bob

# Send a secret
shenan send --to github:alice API_KEY=sk-abc123

# Send multiple secrets
shenan send --to github:alice \
  DATABASE_URL=postgres://... \
  REDIS_URL=redis://... \
  API_KEY=sk-abc123

# Receive (run this when someone tells you they're sending)
shenan receive --from github:bob

# Receive and write directly to .env
shenan receive --from github:bob --out .env

# List your trusted senders
shenan trust list

# Remove a trusted sender
shenan trust remove github:mallory
```

## Self-Hosting the Relay

```bash
# Docker
docker run -p 8080:8080 ghcr.io/jhnlsn/shenan-relay

# Binary
shenan-relay --port 8080

# Point your CLI at it
shenan config set relay wss://your-relay.example.com
```

The relay has no configuration file, no database, no persistent state. Restarting it loses nothing — there was nothing to keep.

## Project Structure

```
shenan/
  cli/      # The shenan CLI (MIT License)
  relay/    # The shenan relay server (AGPL v3)
  spec/     # Protocol specification (CC0)
  docs/     # Documentation
```

## Licenses

- **CLI** (`cli/`) — [MIT](cli/LICENSE) — use it anywhere, embed it in anything
- **Relay** (`relay/`) — [AGPL v3](relay/LICENSE) — modifications to the relay must be open sourced, including when run as a service
- **Spec** (`spec/`) — [CC0](spec/LICENSE) — public domain, implement it freely

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Status

🚧 **Pre-alpha — specification phase**

The protocol is designed. Implementation is beginning. See [SPEC.md](SPEC.md) for the full technical specification.

---

*shenan.dev*