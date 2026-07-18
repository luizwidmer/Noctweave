# NoctweaveCLI relationship reference

NoctweaveCLI exercises the clean Noctweave 1.0 public architecture.

## Baseline

```sh
swift run --package-path NoctweaveCore NoctweaveCLI help
swift run --package-path NoctweaveCore NoctweaveCLI endpoint --relay https://relay.example
swift run --package-path NoctweaveCore NoctweaveCLI health --relay http://127.0.0.1:9340
swift run --package-path NoctweaveCore NoctweaveCLI info --relay http://127.0.0.1:9340
```

The health and info commands are `nw.core@2` operations sent through `/relay`;
they are not separate HTTP compatibility endpoints.

## Local persona state

```sh
swift run --package-path NoctweaveCore NoctweaveCLI init \
  --display-name "local label" --state alice.json
swift run --package-path NoctweaveCore NoctweaveCLI status --state alice.json
```

The display name is local-only. It is not registered or disclosed.

## One-use relationship preparation

Each side independently creates fresh relationship keys and a fresh opaque
receive route:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI prepare-participant \
  --state alice.json --relay https://relay.example \
  --relationship-pseudonym "Night orchid" --out alice-participant.json

swift run --package-path NoctweaveCore NoctweaveCLI pairing-invitation \
  --state alice.json --out alice-offer.json --lifetime 600
```

The invitation is one-use ephemeral rendezvous material. The prepared
participant file contains local secret state and must be protected. Complete
introductions travel only inside the authenticated rendezvous channel.

## Messaging

After the rendezvous result has been durably added to each local persona:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI relationships --state alice.json
swift run --package-path NoctweaveCore NoctweaveCLI send \
  --state alice.json --relationship <uuid> --text "hello"
swift run --package-path NoctweaveCore NoctweaveCLI sync \
  --state bob.json --relationship <uuid> --max 256
```

One logical event, one retry-stable intent, per-route ciphertext packets, and
a route-local cursor are distinct objects. Cursor commit occurs
only after verification, decryption, and durable local application.

## Relationship maintenance

Use `HeadlessMessagingClient` for the full public maintenance surface:

- `renewRelationshipPrekeyIfNeeded`
- `prepareRouteRollover` / `beginRouteRollover`
- targeted route probing and automatic make-before-break promotion
- `finalizeDrainedRoutes`
- explicit `sendContinuityOffer` when local policy permits
- explicit `markRead`; read receipts are never automatic

These operations affect one relationship only.

## Persona burn

```sh
swift run --package-path NoctweaveCore NoctweaveCLI burn-persona \
  --state alice.json --confirm BURN --replacement-name "new local label"
```

Burn deletes the active local persona state and creates an unrelated local
container. No continuity link is emitted.

## Safety

- Never copy live ratchet or route-capability state into another process.
- Never log private participant files, rendezvous secrets, route capabilities,
  decrypted payloads, or state-store keys.
- Prefer `--auth-file`; literal secrets may leak through process listings.
- A relay acceptance is not peer storage. A peer-storage receipt is not read.
