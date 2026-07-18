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
  --out ./pairing-offer.private.json \
  --lifetime 600
```

The command prints the shareable invitation and writes the offerer's private
rendezvous state separately. The invitation contains no relationship identity
or relay route.

The CLI exposes these primitives for integration and diagnostics. The complete
interactive two-party rendezvous is implemented by the Core APIs and reference
JavaScript client.

## Send and synchronize

```sh
swift run --package-path NoctweaveCore NoctweaveCLI send \
  --relationship 00000000-0000-0000-0000-000000000000 \
  --text "hello"

swift run --package-path NoctweaveCore NoctweaveCLI sync \
  --relationship 00000000-0000-0000-0000-000000000000 \
  --max 128
```

Sending persists one logical event and exact encrypted route packets before
publication. Sync commits a route cursor only after durable processing.

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
