# NoctweaveCLI

`NoctweaveCLI` is the native diagnostic and headless-client surface for the
Noctweave 1.0 architecture.

```sh
swift run --package-path NoctweaveCore NoctweaveCLI help
```

## Local state

```sh
swift run --package-path NoctweaveCore NoctweaveCLI init \
  --display-name "local mask"

swift run --package-path NoctweaveCore NoctweaveCLI status
swift run --package-path NoctweaveCore NoctweaveCLI relationships
```

The display name is a local persona label. It is never used as a relationship
pseudonym or transmitted automatically.

State is encrypted by default. Without `--state`, the database lives at the
platform's user Application Support location under
`NoctweaveCLI/client-state.json`, not in the current working directory.
`--plaintext true` is for disposable test fixtures only. `--state path`
selects another state file; its parent must be owned by the current user and
must not be group/other writable. The CLI creates a missing final state
directory with mode `0700` but does not change an existing caller-owned
directory's permissions.

Each command rejects options outside its own strict allowlist before loading
state or performing network/file side effects. Sensitive inputs are read once
through a held descriptor, must be bounded regular files, and cannot be final
component symlinks, FIFOs, or growing files. Sensitive outputs are created with
mode `0600`, flushed with their parent directory, and installed without
replacement. An exact existing artifact is accepted as an idempotent retry;
different existing bytes are never clobbered. Output paths may not overlap the
state file, its pending/lock files, or the command's input artifacts.

## Prepare pairwise material

Create a relationship-local endpoint, prekey, and registered opaque receive
route:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI prepare-participant \
  --relay https://relay.example \
  --relationship-pseudonym "night orchid" \
  --out ./participant.private.json
```

The output contains private relationship and route authority. It is written
atomically with mode `0600`; do not publish it as a contact code.

Create a one-use contact-pairing rendezvous invitation:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI pairing-invitation \
  --offer-out ./pairing-offer.private.json \
  --invitation-out ./pairing-invitation.share \
  --lifetime 600
```

The command writes the offerer's pending state and shareable invitation to
separate mode-`0600` files. The invitation is a short-lived bearer rendezvous
capability, but contains no relationship identity or relay route.

Each participant independently prepares its relationship-local material. The
responder receives only the invitation file:

```sh
# responder
swift run --package-path NoctweaveCore NoctweaveCLI pair-accept \
  --invitation-file ./pairing-invitation.share \
  --participant-file ./responder.private.json \
  --relay https://relay.example

# offerer, run concurrently
swift run --package-path NoctweaveCore NoctweaveCLI pair-offer \
  --offer-file ./pairing-offer.private.json \
  --participant-file ./offerer.private.json \
  --relay https://relay.example
```

These are live rendezvous pumps. Their process-local session keys are
deliberately non-serializable. If either command is interrupted, let the
short-lived lanes expire and create a fresh invitation; do not export live
session state. Successful pairing stores only each side's local projection of
the fresh relationship.

## Send and synchronize

```sh
swift run --package-path NoctweaveCore NoctweaveCLI send \
  --relationship 00000000-0000-0000-0000-000000000000 \
  --text-file ./message.private.txt

swift run --package-path NoctweaveCore NoctweaveCLI sync \
  --relationship 00000000-0000-0000-0000-000000000000 \
  --max 128
```

Sending persists one logical event and exact encrypted route packets before
publication. Message text is read from a file so plaintext does not appear in
the process argument list. Sync commits a route cursor only after durable local
processing.

Retry and route maintenance are explicit headless workflows:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI retry-deliveries \
  --relationship 00000000-0000-0000-0000-000000000000

swift run --package-path NoctweaveCore NoctweaveCLI maintain --all true

swift run --package-path NoctweaveCore NoctweaveCLI resume-rollovers \
  --relationship 00000000-0000-0000-0000-000000000000

swift run --package-path NoctweaveCore NoctweaveCLI finalize-routes \
  --relationship 00000000-0000-0000-0000-000000000000
```

`maintain` renews relationship prekeys and performs make-before-break receive
route replacement before expiry. Permanent delivery or rollover failures stay
visible until the operator uses the corresponding `discard-*` command.

## Experimental groups

Create a fresh group-scoped credential and opaque receive route, then send,
sync, and maintain the group runtime:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI group-create \
  --group 00000000-0000-0000-0000-000000000000 \
  --relay https://relay.example

swift run --package-path NoctweaveCore NoctweaveCLI group-send \
  --group 00000000-0000-0000-0000-000000000000 \
  --text-file ./group-message.private.txt

swift run --package-path NoctweaveCore NoctweaveCLI group-sync \
  --group 00000000-0000-0000-0000-000000000000 \
  --max 128 --pages 8

swift run --package-path NoctweaveCore NoctweaveCLI group-maintain --all true
```

`group-create` requires an explicit UUID, so an interrupted creation still has
a known target for `group-status`, maintenance, or exact-operation resume. Do
not rerun creation after the group has been installed locally; resume the
reported operation instead. The CLI never silently substitutes a second group
identity. Group transport commands print their structured result even when
publication is incomplete, then exit nonzero so automation cannot mistake
partial progress for completion:

- exit `75`: exact work remains pending for retry;
- exit `77`: local authorization recovery is required;
- exit `69`: the relay rejected the operation;
- exit `76`: the relay response was invalid.

Use `group-resume --group <uuid> --operation <uuid>` or the relevant admission
resume command after correcting the reported condition. These outcomes retain
the exact prepared group artifacts; retry does not create a replacement
transition, Welcome, ciphertext, or deletion tombstone.

For exit `77`, first inspect `group-status` and the saved operation. Repair the
affected local receive route with `group-maintain` when the route can be
renewed, then resume the exact operation. If the bearer capability itself is no
longer available, recovery requires an explicit operator decision; the CLI has
no implicit credential or authority fallback.

Member admission is deliberately a four-step exchange. Every generated file
must travel through an independently authenticated and encrypted channel; the
CLI does not infer a contact, upload invitations, or create an account/device
service.

```sh
# Existing authorized member creates the one-use request.
swift run --package-path NoctweaveCore NoctweaveCLI group-invite-request \
  --group 00000000-0000-0000-0000-000000000000 \
  --out ./group-invitation.private.json

# Prospective member creates a fresh group-only credential and receive route.
swift run --package-path NoctweaveCore NoctweaveCLI group-admission-prepare \
  --invitation-file ./group-invitation.private.json \
  --relay https://relay.example \
  --response-out ./group-admission.private.json

# Preserve the admissionID printed in the command's JSON result.

# Existing member commits the admission and exports the exact join package.
swift run --package-path NoctweaveCore NoctweaveCLI group-add-member \
  --group 00000000-0000-0000-0000-000000000000 \
  --invitation-file ./group-invitation.private.json \
  --response-file ./group-admission.private.json \
  --join-out ./group-join.private.json \
  --role member

# Prospective member consumes its saved one-use admission.
swift run --package-path NoctweaveCore NoctweaveCLI group-join-accept \
  --admission 00000000-0000-0000-0000-000000000000 \
  --join-file ./group-join.private.json
```

The printed `admissionID` is the durable identifier used by
`group-join-accept` and admission resume commands. If the output was not
retained, `group-admissions` lists the locally saved admission; do not prepare
a replacement.

`group-admission-resume`, `group-admissions`, and `group-resume` recover exact
saved work after relay or process failure. Group deletion requires a
target-bound confirmation token:

```text
DELETE-GROUP:<lowercase-group-uuid>:<first-16-hex-SHA256-of-canonical-current-group-state>
```

Run `group-delete --group <uuid>` without a valid `--confirm` value to have the
CLI print the exact expected token, inspect the target, then repeat the command
with that token. The command creates and durably publishes the signed terminal
tombstone; a partial publication uses the nonzero outcomes above. The
implemented `nw.pq-group.experimental-2` provider remains unaudited and is not
RFC 9420 MLS.

## Relationship-local trust and policy

```sh
swift run --package-path NoctweaveCore NoctweaveCLI safety-number \
  --relationship 00000000-0000-0000-0000-000000000000

swift run --package-path NoctweaveCore NoctweaveCLI relationship-policy \
  --relationship 00000000-0000-0000-0000-000000000000 \
  --consent accepted \
  --read-receipts false

swift run --package-path NoctweaveCore NoctweaveCLI block \
  --relationship 00000000-0000-0000-0000-000000000000
```

The safety number compares only the disposable authorities for this one
relationship. Consent, mute, receipt, and block state remain local. Blocking
clears live relationship work before best-effort route teardown and never
publishes a global block identity.

Selective continuity is off by default. To disclose a fresh invitation only
inside one accepted relationship, opt in locally, create an ordinary pairing
invitation, and send its share file as a signed relationship control:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI continuity-policy \
  --relationship 00000000-0000-0000-0000-000000000000 \
  --mode sendOnly

swift run --package-path NoctweaveCore NoctweaveCLI continuity-offer \
  --relationship 00000000-0000-0000-0000-000000000000 \
  --invitation-file ./pairing-invitation.share
```

The receiving peer must separately enable `receiveOnly` or `bidirectional`,
sync the control event, and export that event's invitation with
`continuity-invitation --event <uuid> --out <share-file>`. The subsequent
pairing creates another independent relationship; it does not rotate a global
identity or prove persona-wide continuity.

## Burn

```sh
swift run --package-path NoctweaveCore NoctweaveCLI burn-persona \
  --confirm BURN \
  --replacement-name "fresh local mask"
```

Burn removes the old persona record from local state and creates an unrelated
empty container. It does not publish continuity or preserve recoverable live
authority.

To intentionally erase the entire encrypted local database, including all
personas and group state, use the distinct destructive command:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI erase-local-state \
  --confirm ERASE:<first-16-hex-SHA256-of-canonical-absolute-state-path>
```

Encrypted mode advances an identity-free local rollback tombstone before the
database is considered erased. Missing files are never interpreted as a fresh
state automatically. The confirmation is bound to the canonical state path so
a token copied from one database cannot authorize another. Invoke the command
without a valid token to print the exact expected value, verify the path, then
repeat it deliberately.

## Relay diagnostics

```sh
swift run --package-path NoctweaveCore NoctweaveCLI endpoint \
  --relay wss://relay.example/relay

swift run --package-path NoctweaveCore NoctweaveCLI health \
  --relay https://relay.example

swift run --package-path NoctweaveCore NoctweaveCLI info \
  --relay https://relay.example
```

Use `--auth-file path` for an operator-supplied bearer token and `--timeout
seconds` to change the request timeout.

An exact modular relay request can be sent for protocol diagnostics:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI raw \
  --relay https://relay.example \
  --request @request.json
```

The JSON must match the current module/version/method/body schema exactly.
