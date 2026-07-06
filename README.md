# @koove/secrets-cli

Zero-knowledge secrets CLI + controller tooling for [Koove](https://koove.io).

The CLI **encrypts secrets on your machine** and uploads only the ciphertext envelope —
the server never sees a plaintext value. It also drives the whole device lifecycle:
add/approve/revoke devices, break-glass recovery, and key rotation.

![License](https://img.shields.io/badge/license-MIT-green)

## Install

```bash
npm install -g @koove/secrets-cli    # requires Node.js >= 22
```

## Configure

```bash
koove-secrets config --api-url=https://koove.io --app-token=YOUR_APP_TOKEN
```

## Two roles

The CLI is both the **writer** (encrypts and stores secrets) and the **controller**
(holds the app's controller identity and drives re-wraps). Private keys live here, in an
encrypted keyfile — never on the server.

## Common commands

```bash
# Initialize the app: creates the controller keyfile and a one-time 24-word
# BIP39 recovery code (shown once, never stored).
koove-secrets app-init

# Store a secret — encrypted locally; only the envelope is uploaded.
koove-secrets set DATABASE_URL "postgres://..." --env prod

# List secrets (metadata only — the writer can't read values back).
koove-secrets list --env prod

# Device lifecycle
koove-secrets devices                    # list devices and their state
koove-secrets device-approve             # re-wrap existing secrets for pending devices
koove-secrets device-revoke <deviceId>   # cryptographic kill: remove from every envelope

# Break-glass recovery (needs the 24-word code)
koove-secrets recover-show DATABASE_URL --env prod
koove-secrets recover-rewrap

# Rotation (zero downtime, idempotent)
koove-secrets controller-rotate
koove-secrets recovery-rotate
```

## How it stays zero-knowledge

Secrets are encrypted with [`@koove/crypto`](https://github.com/kooveio/koove-crypto)
(envelope encryption: X25519 + AES-256-GCM + HKDF) before upload. Adding a device,
revoking one, or rotating keys is a **re-seal** of the data key, authorized by the
controller or recovery identity — the server only stores and gates recipients, it never
re-wraps or reads.

**Honest limit:** revoking removes a device from future versions, but a secret already
downloaded and cached is not un-delivered — for a total kill, rotate the secret's value.

## License

MIT © Koove. See [LICENSE](./LICENSE). Part of Koove — https://koove.io · https://github.com/kooveio
