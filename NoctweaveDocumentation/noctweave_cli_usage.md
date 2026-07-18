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

State is encrypted by default. `--plaintext true` is for disposable test
fixtures only. `--state path` selects another state file.

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
