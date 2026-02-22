# shenan

> *From Irish Sionainn (the River Shannon, goddess who sought forbidden knowledge) — a blind pipe for secrets.*

Shenan is a decentralized, ephemeral relay for sharing secrets between developers. It has one job: move an encrypted secret from one machine to another without ever seeing what's inside.

```bash
# Alice sends a secret to Bob
shenan send --to github:bob DATABASE_URL=postgres://prod:5432/mydb

# Bob receives it (must be online simultaneously)
shenan receive --from github:alice
```

No secrets are stored anywhere. Not on the relay, not in a database, not in transit buffers. Both parties must be online at the same time. The relay is a blind pipe, not a mailbox.

---

## Why

Every team has the same moment: someone generates a production secret and now has to get it to the people who need it. The options are all bad.

- Slack or email — plaintext, logged, searchable forever
- A `.env` file committed to git — a breach waiting to happen
- A secrets manager like Doppler or Vault — centralized, proprietary, and someone else holds a key that can decrypt your secrets

The centralized model has a deeper problem: stored ciphertext is harvestable. Even if it can't be decrypted today, a sufficiently motivated adversary stores it and waits. This is the **harvest now, decrypt later** attack, and it's not theoretical — it's happening now.

Shenan is different in one specific way: **the relay is architecturally incapable of reading or retaining your secrets.** There is no database. There are no stored ciphertexts. The relay does not know who is talking to whom. By the time a secret has been transmitted, the relay has already forgotten everything about the transaction.

---

## How it works

### Identity via GitHub

Authentication uses your existing GitHub SSH keys. No new accounts, no new keypairs.

```
you                    relay                    colleague
 |                       |                          |
 |-- connect (WSS) ----> |                          |
 |<- challenge nonce --- |                          |
 |-- sign(nonce) ------> |                          |
 |   relay verifies via github.com/you.keys         |
 |   GitHub username discarded immediately          |
 |<- ephemeral_id ------ |                          |
```

After authentication, the relay knows nothing about your identity. It holds only an ephemeral ID linked to your socket connection.

### Channel derivation (client-side only)

Both parties independently derive the same channel token from their public keys and the current hour. No coordination required — the math produces the same result on both ends.

```
channel_token = HKDF-SHA256(
  ikm  = sender_pubkey || recipient_pubkey,
  info = "shenan-channel-v1:" || direction || ":" || window,
  len  = 32 bytes
)
```

Tokens rotate every hour. A captured token is useless after 60 minutes. The relay sees only the token — it never learns whose keys produced it or what relationship those keys have.

### Transmission

```
+-------------------+                              +-------------------+
|   Bob's CLI       |                              |   Alice's CLI     |
|                   |                              |                   |
| 1. Fetch Alice's  |                              | 1. Fetch Bob's    |
|    pubkey from    |                              |    pubkey from    |
|    GitHub         |                              |    GitHub         |
|                   |                              |                   |
| 2. Derive anon    |<---- same channel token ---->| 2. Derive same    |
|    channel from   |      (no coordination        |    channel from   |
|    both pubkeys   |       needed)                |    both pubkeys   |
|    + time window  |                              |    + time window  |
|                   |                              |                   |
| 3. Encrypt        |                              |                   |
|    payload to     |                              |                   |
|    Alice's key    |                              |                   |
|                   |          Relay               |                   |
| 4. Connect -------+-------- (blind pipe) --------+------- Connect   |
|    present proof  |  verifies both proofs        |     present       |
|                   |  opens pipe                  |     proof         |
|                   |  forgets immediately         |                   |
| 5. Send ----------+--------- bytes flow -------->| 5. Receive        |
|                   |  relay never held them       |                   |
|                   |                              | 6. Decrypt with   |
|                   |                              |    private key    |
|                   |                              |                   |
|                   |                              | 7. Write to       |
|                   |                              |    .env           |
+-------------------+                              +-------------------+
```

The relay admits two connections presenting complementary proofs for the same channel, opens a bidirectional pipe, streams the bytes, and immediately forgets everything.

### End-to-end encryption

Secrets never touch the relay as plaintext. Before sending:

1. Sender fetches recipient's public key from `github.com/recipient.keys`
2. Generates a fresh ephemeral keypair (forward secrecy)
3. Encrypts the payload locally (X25519 + ChaCha20-Poly1305)
4. Transmits ciphertext through the relay pipe

The relay carries encrypted bytes it cannot read.

### Trust model

Shenan maintains a local friends list at `~/.shenan/trusted_senders.toml`. Payloads from unknown senders are dropped silently before decryption. This prevents social engineering attacks even if the relay is compromised.

```bash
shenan trust add github:alice
shenan trust list
```

---

## Security properties

| Property | Guarantee |
|---|---|
| Encryption | End-to-end, client-side only |
| Forward secrecy | Fresh ephemeral keypair per send |
| Relay knowledge | Anonymous ephemeral IDs only |
| Relationship graph | Never constructed, never stored |
| Ciphertext at rest | Structurally impossible |
| Harvest now / decrypt later | No surface to harvest |
| Post-quantum readiness | Hybrid X25519 + ML-KEM (roadmap) |
| Relay compromise impact | Zero — nothing to learn, nothing to steal |

### What a fully compromised relay reveals

Even with complete real-time memory access an attacker sees:

- Some number of verified GitHub users are currently connected
- Some of those are paired on anonymous channels
- Opaque encrypted bytes flowing through those channels

An attacker **cannot** determine who is talking to whom, what relationship exists between any two parties, what the bytes contain, or anything useful for a harvest-now-decrypt-later attack.

---

## Getting started

```bash
# Install
brew install shenan        # macOS
go install github.com/jhnlsn/shenan/cli/cmd/shenan@latest  # from source

# Initialize — discover your local SSH keys, select identity
shenan init

# Add trusted senders (stored locally, never leaves your machine)
shenan trust add github:alice
shenan trust add github:bob

# Send a secret (blocks until recipient connects)
shenan send --to github:alice API_KEY=sk-abc123

# Send multiple secrets
shenan send --to github:alice \
  DATABASE_URL=postgres://... \
  REDIS_URL=redis://... \
  API_KEY=sk-abc123

# Send from a file
shenan send --to github:alice --from-file .env.production
shenan send --to github:alice < .env.production

# Receive (blocks until sender connects)
shenan receive --from github:bob

# Receive and write directly to .env
shenan receive --from github:bob --out .env

# List trusted senders
shenan trust list

# Remove a trusted sender
shenan trust remove github:mallory
```

---

## Self-hosting the relay

```bash
# Docker
docker run -p 443:443 ghcr.io/jhnlsn/shenan-relay

# Binary
shenan relay start --port 443 --tls-cert cert.pem --tls-key key.pem

# Point your CLI at it
shenan config set relay wss://your-relay.example.com

# Or per-command
shenan send --relay wss://relay.yourcompany.com --to github:bob SECRET=value
```

The relay has no configuration file, no database, no persistent state. It is safe to restart at any time — there was nothing to keep. Multiple independent relays can coexist; clients choose which relay to use.

---

## Project structure

```
shenan/
  cli/      # The shenan CLI (Go, MIT License)
  relay/    # The shenan relay server (Go, AGPL v3)
  spec/     # Protocol specification (CC0)
```

The relay and CLI are intentionally separate binaries with separate licenses. The relay is meant to be auditable and forkable under AGPL. The CLI is meant to be embeddable anywhere under MIT.

## Licenses

- **CLI** (`cli/`) — [MIT](cli/LICENSE) — use it anywhere, embed it in anything
- **Relay** (`relay/`) — [AGPL v3](relay/LICENSE) — modifications to the relay must be open sourced, including when run as a service
- **Spec** (`spec/`) — [CC0](spec/LICENSE) — public domain, implement it freely

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Status

Pre-alpha — specification phase. The protocol is designed. Implementation is beginning. See [SPEC.md](SPEC.md) for the full technical specification.

---

*shenan.dev*
