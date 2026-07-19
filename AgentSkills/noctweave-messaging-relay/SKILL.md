---
name: noctweave-messaging-relay
description: "Operate the public Noctweave 1.0 relationship protocol, headless client, exact modular relay, opaque routes, and federation without relying on proprietary app code."
---

# Noctweave Messaging + Relay

## Scope

Use only:

- `NoctweaveCore/` and `NoctweaveCore/Sources/NoctweaveCLI/`
- `NoctweaveRelayServer/`
- `NoctweaveJS/`
- `NoctweaveDocumentation/`
- `scripts/`

Do not rely on proprietary Apple clients or the macOS relay app.

## Protocol boundary

A persona is a local label and container. It is never a network identity.
Every contact pairing creates fresh relationship authority, one relationship
endpoint binding, and opaque receive routes. Never introduce accounts, global
inboxes, device or installation registries, recovery authorities, self-sync
identity, shared live ratchets, or compatibility adapters for discarded
pre-1.0 state.

Relays accept one exact request envelope on `/relay`. They route ciphertext by
opaque capability and never receive persona, contact, message, or group
plaintext.

## First checks

1. Preserve the supplied endpoint scheme (`http`, `https`, `ws`, `wss`, `tcp`,
   or `tls`). Do not invent a port for a complete URL.
2. Query the modular core operations:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI health --relay http://127.0.0.1:9340
swift run --package-path NoctweaveCore NoctweaveCLI info --relay http://127.0.0.1:9340
```

3. Preserve E2EE and metadata boundaries. Never add plaintext logging,
   server-side decryption, implicit escrow, or identity-addressed routing.

## Messaging tasks

Read `references/messaging-cli.md` for local persona initialization, one-use
contact rendezvous, pairwise send/sync, durable group admission and transport,
prekey renewal, route rollover, explicit continuity, persona burn, and complete
local-state erasure.

## Relay tasks

Read `references/relay-operations.md` for Linux/Docker startup, the exact
modular envelope, opaque-route persistence, TLS proxying, encrypted blobs, and
federation policy.

Federation modes remain explicit trust domains: `solo`, `manual`, `curated`,
and `open` must never be silently bridged.

## Validation

```sh
swift build --package-path NoctweaveCore
swift test --package-path NoctweaveCore
swift build --package-path NoctweaveRelayServer
swift test --package-path NoctweaveRelayServer
scripts/run-tests.sh
```

For relay work, query `health` and `info` through the actual `/relay` endpoint.
For pairwise messaging work, prove one encrypted relationship event is
relay-accepted, synced, durably processed, and cursor-committed. For group work,
also prove the group-only invitation/admission artifacts, signed route
announcement, persisted transport operation, and restart-safe resume path. Do
not call a relay response a peer delivery or read receipt.
