# NoctweaveCLI messaging reference

NoctweaveCLI exercises the clean Noctweave 1.0 pairwise and group architecture.

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
  --display-name "local label" \
  --accept-privacy-policy true \
  --accept-terms-of-use true
swift run --package-path NoctweaveCore NoctweaveCLI status
```

The default state lives under the user's application-support directory and is
encrypted with an independently protected local rollback anchor. The display
name is local-only; it is not registered or disclosed. A custom `--state` path
is allowed, but its parent must be owned by the caller and not group- or
world-writable. `--plaintext true` is only for bounded tests.

## One-use relationship preparation

Each side independently creates fresh relationship keys and a fresh opaque
receive route:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI prepare-participant \
  --state alice.json --relay https://relay.example \
  --relationship-pseudonym "Night orchid" --out alice-participant.json

swift run --package-path NoctweaveCore NoctweaveCLI prepare-participant \
  --state bob.json --relay https://relay.example \
  --relationship-pseudonym "Quiet ember" --out bob-participant.json

swift run --package-path NoctweaveCore NoctweaveCLI pairing-invitation \
  --state alice.json --offer-out alice-offer.json \
  --invitation-out alice-invitation.json --lifetime 600
```

The invitation is one-use ephemeral rendezvous material. The prepared
participant file contains local secret state and must be protected. Complete
introductions travel only inside the authenticated rendezvous channel.

Run both rendezvous pumps while the invitation is live:

```sh
# responder
swift run --package-path NoctweaveCore NoctweaveCLI pair-accept \
  --state bob.json --invitation-file alice-invitation.json \
  --participant-file bob-participant.json --relay https://relay.example

# offerer, concurrently
swift run --package-path NoctweaveCore NoctweaveCLI pair-offer \
  --state alice.json --offer-file alice-offer.json \
  --participant-file alice-participant.json --relay https://relay.example
```

The process-local rendezvous session keys are intentionally not serializable.
If either pump is interrupted, let the short-lived lanes expire and create a
fresh invitation; never export or clone the live pairing state.

## Messaging

After the rendezvous result has been durably added to each local persona:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI relationships --state alice.json
swift run --package-path NoctweaveCore NoctweaveCLI send \
  --state alice.json --relationship <uuid> --text-file message.txt
swift run --package-path NoctweaveCore NoctweaveCLI sync \
  --state bob.json --relationship <uuid> --max 256
```

One logical event, one retry-stable intent, per-route ciphertext packets, and
a route-local cursor are distinct objects. Cursor commit occurs
only after verification, decryption, and durable local application.

Plaintext is accepted only through a bounded regular file so it does not appear
in process arguments. Symlinks, devices, FIFOs, oversized inputs, and path races
are rejected.

## Durable groups

Choose and retain a stable UUID before group creation so a retry resumes the
same durable operation:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI group-create \
  --group <stable-uuid> --relay https://relay.example
swift run --package-path NoctweaveCore NoctweaveCLI group-send \
  --group <uuid> --text-file message.txt
swift run --package-path NoctweaveCore NoctweaveCLI group-sync \
  --group <uuid> --max 256 --pages 8
swift run --package-path NoctweaveCore NoctweaveCLI group-maintain --group <uuid>
```

Admission is an explicit artifact flow:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI group-invite-request \
  --group <uuid> --out invitation.json
swift run --package-path NoctweaveCore NoctweaveCLI group-admission-prepare \
  --invitation-file invitation.json --relay https://relay.example \
  --response-out response.json
swift run --package-path NoctweaveCore NoctweaveCLI group-add-member \
  --group <uuid> --invitation-file invitation.json \
  --response-file response.json --join-out join.json
swift run --package-path NoctweaveCore NoctweaveCLI group-join-accept \
  --admission <uuid> --join-file join.json
```

`group-admission-prepare` prints the saved admission UUID in its JSON result;
use that exact value for `group-join-accept` and admission resume commands. If
the original output is unavailable, `group-admissions` lists the same durable
admission instead of creating another one.

Invitation, response, and join files contain private or bearer material. Move
them only through an independently authenticated encrypted channel. The CLI
installs them as mode `0600`, refuses to clobber different bytes, and accepts an
identical existing file only as an idempotent retry. Each group member has a
fresh group-only credential; no persona or pairwise key becomes group authority.

Group operations always emit their durable operation identifiers. Incomplete
relay effects also return a nonzero status after JSON: `75` retryable, `77`
authorization recovery required, `69` relay rejected, or `76` malformed relay
response. For `77`, inspect `group-status` and the saved operation, repair the
affected local receive route with `group-maintain` when possible, then resume
the exact operation. If its bearer capability is no longer available, explicit
operator recovery is required; the CLI has no hidden credential bypass. For
the other incomplete outcomes, correct the reported relay condition and use
`group-resume --group <uuid> --operation <uuid>`.

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

Complete local erasure uses a token bound to the canonical state path. Run once
with a missing/stale confirmation to obtain the exact token, then repeat with
`--confirm ERASE:<path-hash>`. Group deletion works the same way with
`DELETE-GROUP:<uuid>:<state-hash>`. These tokens prevent a confirmation copied
from authorizing a different target.

## Safety

- Never copy live ratchet or route-capability state into another process.
- Never log private participant files, rendezvous secrets, route capabilities,
  decrypted payloads, or state-store keys.
- Prefer `--auth-file`; literal secrets may leak through process listings.
- Treat nonzero group-operation exits as durable recovery state, not as permission
  to generate a replacement group or artifact.
- A relay acceptance is not peer storage. A peer-storage receipt is not read.
