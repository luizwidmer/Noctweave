<p align="center">
  <img src="../docs/assets/NoctweaveRelayIcon.svg" alt="Noctweave Relay" width="160">
</p>

# Noctweave Relay Server

Linux/Docker ciphertext relay for the clean Noctweave 1.0 protocol. It has no
global identity service, identity directory, global inbox, endpoint registry,
plaintext message API, or legacy request profile.

## Protocol surface

All raw TCP, HTTP, WebSocket, and federation traffic uses the same exact relay
envelope:

```text
requestID, module, version, method, body, authToken
```

Responses repeat the complete operation tuple and contain exactly one success
or error body. Missing/unknown fields, unsupported tuples, mismatched bodies,
and uncorrelated responses fail closed.

Implemented modules:

| Module | Version | Methods |
| --- | ---: | --- |
| `nw.core` | 2 | `health`, `info` |
| `nw.opaque-route` | 2 | `create`, `renew`, `teardown`, `append`, `sync`, `commit` |
| `nw.rendezvous-transport` | 2 | `register`, `append`, `sync`, `delete` |
| `nw.blobs` | 1 | `upload`, `fetch` |
| `nw.federation` | 1 | `register`, `list` |
| `nw.open-discovery` | 1 | `publish-dht`, `list-dht` (experimental; open discovery only) |

The opaque-route runtime is enabled by default. Rendezvous transport and open
discovery are operator opt-in. A module is omitted from `info` when its exact
runtime is disabled.

## Build and test

```sh
swift build --package-path NoctweaveRelayServer
swift test --package-path NoctweaveRelayServer
```

Release build:

```sh
swift build -c release --package-path NoctweaveRelayServer
```

## Run

```sh
NoctweaveRelayServer/.build/debug/NoctweaveRelayServer \
  --host 0.0.0.0 \
  --port 9339 \
  --http-port 9340 \
  --data-dir /tmp/noctweave-relay
```

Use `--help` for the authoritative option list without opening storage or
binding a listener.

Use `--memory-only` only for disposable development. Normal operation stores
route lifecycle, ordered packets/cursors, rendezvous frames, encrypted blob
metadata, and federation records in `relay_store.sqlite`.

## Docker

```sh
docker build -t noctweave-relay NoctweaveRelayServer

docker run --rm --name noctweave-relay \
  -p 9339:9339 \
  -p 9340:9340 \
  -p 127.0.0.1:9090:9090 \
  -e NOCTWEAVE_ADMIN_TOKEN \
  -v noctweave-relay-data:/data \
  noctweave-relay \
  --host 0.0.0.0 \
  --port 9339 \
  --http-port 9340 \
  --admin-port 9090 \
  --data-dir /data
```

The multi-stage image runs as an unprivileged user and pins the reviewed
liboqs source commit. Mount `/data` persistently.

## Transports

- raw TCP: one newline-delimited request and response per connection;
- HTTP: `POST /relay`;
- WebSocket: connect to `/relay`, then exchange exact JSON frames.

There is no separate GET health or information route. Health and information
are `nw.core@2` requests through the normal relay transport.

Example:

```sh
curl -sS http://127.0.0.1:9340/relay \
  -H 'content-type: application/json' \
  -d '{"requestID":"00000000-0000-0000-0000-000000000001","module":"nw.core","version":2,"method":"health","body":{},"authToken":null}'
```

## Opaque routes

Routes are random capability-authorized ciphertext logs. Append, read,
renewal, and teardown use distinct secrets. Sync is ordered and
non-destructive; commit advances a route-local cursor after client processing.
Expiry, quota, request bounds, monotonic revisions, and idempotency keep relay
state bounded.

The relay never receives a persona, contact name, relationship authority,
direct ratchet, content relation, or plaintext. It can still observe source
network metadata, request timing, route capability reuse, and ciphertext size.

## Rendezvous transport

Enable one-use contact transport explicitly:

```sh
--rendezvous-transport true
```

The transport stores bounded opaque frames under expiring random capabilities.
It does not learn the relationship introduction carried inside the encrypted
rendezvous. It is only for pairwise contact establishment; it does not perform
endpoint enrollment, group invitation, route rollover, or history transfer.

## Encrypted blobs

`nw.blobs` stores only encrypted attachment chunks. Disable it with:

```sh
--attachments-enabled false
```

Inline SQLite is the default. Optional IPFS offload uses
`--attachment-storage ipfs`, `--ipfs-api-endpoint`, and an optional
`--ipfs-gateway-endpoint`. The relay verifies fetched byte count and digest.
IPFS changes storage placement, not anonymity or cryptographic deletion.

Every `nw.blobs@1 upload` body contains an attachment UUID, chunk index,
encrypted payload, explicit nullable TTL, and a required base64-encoded
32-byte `idempotencyKey`. The coordinate `(attachmentId, chunkIndex)` is
immutable while retained:

- the same idempotency key and canonical request body returns the original
  chunk without extending its TTL, rewriting SQLite, or repeating an IPFS put;
- a different key, encrypted payload, or requested TTL returns a non-retryable
  `conflict`;
- replacing content requires a fresh attachment UUID.

The relay persists the key and canonical body digest only to enforce this
retry boundary. It never receives attachment plaintext or its content key.

## Federation

Federation is operator-plane relay discovery and coordination only. Clients
obtain relay endpoints from relationship-encrypted peer route sets and submit
ciphertext directly to the selected opaque route. A relay does not receive a
user message for forwarding to another relay.

Modes are explicit and must not be mixed:

- `solo`: no federation discovery or coordination;
- `manual`: operator-maintained relay descriptors and allow list;
- `curated`: coordinator policy, quorum, freshness, and optional signed
  directory requirements;
- `open`: bounded signed relay discovery records and optional peer hints.

Configure `--advertised-endpoint` with an explicit public scheme and keep
private/loopback federation destinations rejected unless running a deliberately
isolated network. `NOCTWEAVE_COORDINATOR_REGISTRATION_TOKEN` authorizes only
relay registration with a curated coordinator; it is not a message-routing or
client credential.

See
[`federation_protocol_and_operations.md`](../NoctweaveDocumentation/federation_protocol_and_operations.md).

## Operator console

Set `NOCTWEAVE_ADMIN_TOKEN` (at least 32 random bytes recommended) and bind the
admin listener to loopback/private management networking. The console may
change non-secret operator policy; it cannot return relay passwords, admin
tokens, coordinator registration tokens, or signing private keys. Runtime
policy persists in `operator-config.json` with restrictive permissions.

## Optional privacy advertisements

Hidden retrieval, onion packet, mixnet, open-DHT, and wake-related capability
objects are experimental metadata. Enabling a flag is not a claim of global
anonymity, traffic-analysis resistance, or deployment independence. Advertise
only properties the surrounding deployment actually provides.

## Common secrets

Prefer environment variables:

- `NOCTWEAVE_RELAY_PASSWORD`
- `NOCTWEAVE_ADMIN_TOKEN`
- `NOCTWEAVE_COORDINATOR_REGISTRATION_TOKEN`
- `NOCTWEAVE_COORDINATOR_SIGNING_KEY`

Keep each role separate and rotate it independently.

## Security and operations

- terminate public client and federation-directory traffic with HTTPS/WSS or
  TLS;
- keep raw TCP and the bridge behind a reverse proxy/firewall where possible;
- keep the admin listener private;
- back up SQLite and operator policy consistently;
- never log auth tokens, route capabilities, packet bodies, or ciphertext;
- use bounded retention and attachment TTLs appropriate to the threat model;
- validate reverse-proxy body/time limits and WebSocket behavior;
- review the operator hardening guide before public deployment.

See
[`relay_ops_hardening_guide.md`](../NoctweaveDocumentation/relay_ops_hardening_guide.md)
and the exact
[`OpenAPI schema`](../NoctweaveDocumentation/noctweave_relay_openapi.yaml).
