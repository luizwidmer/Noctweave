---
name: noctweave-messaging-relay
description: "Use this skill when an agent needs to operate Noctweave open tooling: run NoctyraCLI headless messaging workflows, diagnose relay endpoints, configure or verify Linux/Docker relays, inspect federation mode, or perform relay/client smoke tests without using proprietary Noctyra app code."
---

# Noctweave Messaging + Relay

## Scope

Use only the public Noctweave surface:

- `NoctweaveCore/` and `NoctweaveCore/Sources/NoctyraCLI/`
- `Noctweave Relay Server/`
- `NoctweaveJS/`
- `Noctweave Documentation/`
- `scripts/`

Do not rely on the proprietary Apple clients or macOS GUI relay app.

## First Checks

1. Confirm the relay endpoint scheme exactly: `http`, `https`, `ws`, `wss`, `tcp`, or `tls`. Do not append a port when the user gave a full URL.
2. Run relay diagnostics before messaging:

```sh
swift run --package-path NoctweaveCore NoctyraCLI health --relay http://127.0.0.1:9340
swift run --package-path NoctweaveCore NoctyraCLI info --relay http://127.0.0.1:9340
```

3. Preserve privacy boundaries: relays store and forward encrypted envelopes and attachment chunks; they must not decrypt payloads, log plaintext, or bypass federation policy.

## Messaging Tasks

For identity creation, inbox registration, contact exchange, direct/group send, fetch/decrypt, attachments, continuity audit, key rotation, and burn workflows, read `references/messaging-cli.md`.

Prefer `NoctyraCLI` for smoke tests because it exercises the same public protocol models and crypto paths used by compatible clients.

## Relay Tasks

For Linux relay startup, Docker, HTTP/WebSocket/TLS proxying, storage, password-protected relays, federation modes, health checks, IPFS offload, and operator hardening, read `references/relay-operations.md`.

When operating relays:

- `solo` never forwards.
- `manual` uses an operator-maintained peer list.
- `curated` uses allow lists and coordinator policy.
- `open` may use DHT/PEX discovery and must retain public endpoint safeguards.

Do not silently bridge curated and open networks.

## Validation

Use the narrowest verification that proves the task:

```sh
swift build --package-path NoctweaveCore
swift test --package-path NoctweaveCore
swift build --package-path "Noctweave Relay Server"
swift test --package-path "Noctweave Relay Server"
scripts/run-tests.sh
```

For relay work, also run `health` and `info` against the actual endpoint. For messaging work, send and fetch at least one encrypted test message between two headless identities when feasible.
