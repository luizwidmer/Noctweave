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
| `nw.federation` | 1 | `register`, `list`, `namespace`, `claim`, `rotate`, `release` |
| `nw.federation-forward` | 1 | `forward`, `deliver`, `get`, `resolve` |
| `nw.open-discovery` | 1 | `publish-dht`, `list-dht` (experimental; open discovery only) |
| `nw.net-passthrough` | 1 | `forward` |
| `nw.net-host` | 1 | `put`, `bind`, `get`, `resolve`, `has`, `release` |

Every process selects one primary current role with `--relay-kind standard`,
`--relay-kind passthrough`, or `--relay-kind host`. A standard relay may also
advertise `nw.net-host@1` with `--net-host-enabled true`; this is capability
co-location, not a fourth topology role. `info` advertises the exact enabled
surface. Legacy federation-era kind strings remain decode-compatible but are
rejected for new server startup.

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

Host-capable relays additionally store exact Noctweave Net object bytes under
`/data/net-host`, a bounded metadata index, and a stable Ed25519 receipt key.
The relay's persistent ML-DSA-65 identity is stored as
`/data/relay_identity_v1.json` with owner-only permissions. Namespace records,
including irreversible suffix tombstones, are stored transactionally in
SQLite. Back up the data directory as one security boundary.

## Noctweave Net relay roles

Standard is the default and retains the existing Noctweave messaging surface.

A passthrough relay requires authentication and at least one explicit public
HTTPS destination:

```sh
export NOCTWEAVE_RELAY_PASSWORD="$(openssl rand -hex 32)"

NoctweaveRelayServer/.build/debug/NoctweaveRelayServer \
  --relay-kind passthrough \
  --passthrough-allow-endpoint https://relay.example \
  --http-port 9340 \
  --memory-only
```

`nw.net-passthrough@1 forward` accepts one bounded opaque request and returns
one bounded opaque response. It does not discover destinations, follow
redirects, retain bodies, create recursive routes, or claim anonymity.

A host relay stores SHA-256-addressed object bytes:

```sh
export NOCTWEAVE_RELAY_PASSWORD="$(openssl rand -hex 32)"

NoctweaveRelayServer/.build/debug/NoctweaveRelayServer \
  --host 127.0.0.1 \
  --relay-kind host \
  --http-port 9340 \
  --data-dir /data
```

The same host service can be co-located on a standard relay. This example is
solo; manual, curated, and open modes are also supported when a suffix and the
corresponding federation policy are configured:

```sh
export NOCTWEAVE_RELAY_PASSWORD="$(openssl rand -hex 32)"

NoctweaveRelayServer/.build/debug/NoctweaveRelayServer \
  --host 127.0.0.1 \
  --relay-kind standard \
  --net-host-enabled true \
  --http-port 9340 \
  --data-dir /data
```

`nw.net-host@1` verifies object IDs before `put`, returns exact bytes and an
Ed25519-signed hosting receipt from `get`, exposes bounded `has`, and requires
an object-scoped 32-byte capability for `release`. Host receipts attest to
storage acknowledgement, not publisher identity, consensus finality, content
safety, or future availability. `get` and `has` are public by object ID so
clients can retrieve a hosted site; `put` and `release` require the relay
password, and private object bytes must already be encrypted by the client.

Passthrough and every host-capable relay require
`NOCTWEAVE_RELAY_PASSWORD` (or `--access-password`). Passthrough remains a solo,
bounded forwarding role. Host and host-capable standard relays may join
`manual`, `curated`, or `open` federation so their Noctweb objects can be
resolved and fetched through authenticated federation routes.

Those examples bind the browser/HTTP surface to loopback. For a public
Publisher, terminate HTTPS at a reverse proxy on the same host, keep the plain
backend listener unreachable from clients, and add both:

```sh
--advertised-endpoint https://relay.example \
--trusted-reverse-proxy-tls true
```

Remote plaintext requests cannot load the Publisher or perform
capability/auth-token-bearing bridge operations.

### Noctweb Publisher

When hosting is enabled and `--http-port` is set, the bridge serves the
same-origin Page Publisher at `/noctweb/` only to direct loopback clients or
through an operator-declared trusted TLS reverse proxy. This secure-context
boundary is required because browser publisher keys use WebCrypto and write
requests carry the relay password. The Publisher provides a focused
Design/Code/Preview workflow, local autosave, sandboxed active-content
preview, browser-held publication signing identity, and direct
`nw.net-host@1` upload/release operations. The relay password is entered only
for a write request and is not embedded in or persisted by the app.
Every hosted revision keeps its independently encrypted release capability in
bounded local history, so **Unhost all copies** can release older revisions as
well as the current one.

Set `--noctweb-relay-suffix .example` (or
`NOCTWEAVE_NOCTWEB_RELAY_SUFFIX`) to choose the human-facing relay namespace
suffix. Every non-solo standard or host relay must set one. A solo host may
omit it and use a local `r-…` Publisher fallback derived from its stable hosting
receipt public key; that fallback is not federation namespace evidence.

The publisher supports ordinary HTML, CSS, and JavaScript, including
browser-ready compiled React bundles. The relay never builds or executes a
site. A visitor retrieves exact hosted bytes, verifies publisher integrity,
and runs active content only in a sandbox without the relay origin.

The UI reports a revision as **Hosted**, not publisher-finalized. Publication
content and head continuity remain signed by the publisher. In a federation,
the displayed `noct://` address is resolved only after the Browser verifies the
configured threshold of byte-identical, relay-signed namespace snapshots.

## Authenticated federation and naming

Each persistent relay advertises a signed ML-DSA identity claim. In a manual
federation, a host-capable deployment can be started with:

```sh
NoctweaveRelayServer/.build/debug/NoctweaveRelayServer \
  --host 0.0.0.0 \
  --http-port 9340 \
  --relay-kind standard \
  --net-host-enabled true \
  --noctweb-relay-suffix .atelier \
  --federation-mode manual \
  --federation-name private-mesh \
  --federation-allow https://relay-b.example \
  --advertised-endpoint https://relay-a.example \
  --trusted-reverse-proxy-tls true \
  --data-dir /data
```

Every peer must use the same mode and federation name. Manual peers are
operator-selected and can be updated at runtime. Curated deployments configure
coordinator endpoints and signing keys. Open deployments may use DHT/PEX to
discover candidates, but clients still require an explicit namespace signer
set and threshold.

The namespace module exposes signed `namespace`, `claim`, `rotate`, and
`release` operations. Accepted mutations are propagated to a bounded peer set.
Offline operation never releases a suffix. Rotation requires a proof signed by
both relay keys. Release is an irreversible tombstone.

`nw.federation-forward@1` lets a standard home relay forward an unchanged
encrypted opaque append to an authenticated destination relay. It also proxies
Noctweb name resolution and object fetches to the namespace-selected host.
Client-side relationship, namespace, destination identity, host receipt,
object digest, and publisher verification remain mandatory.

The operator console shows the persistent relay ID and active suffix as
read-only security state. Initial suffix selection is a startup operation;
rotation and release require signed lifecycle operations and are not treated as
ordinary live form edits.

See
[`federation_protocol_and_operations.md`](../NoctweaveDocumentation/federation_protocol_and_operations.md)
for trust modes, quorum behavior, lifecycle rules, and security boundaries.

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

### Desktop Docker launcher

The source-built Electrobun launcher keeps Docker lifecycle and relay setup in
one desktop surface:

```sh
cd NoctweaveRelayServer
bun install --frozen-lockfile
bun run desktop:dev
```

New launcher profiles enable Noctweb hosting on the solo standard relay by
default. The setup screen exposes this choice explicitly, the overview reports
`nw.net-host@1`, and **Open Publisher / Lab** opens
`http://127.0.0.1:<http-port>/noctweb/`. The launcher creates a dedicated
publisher password separate from its operator-console token; **Copy publisher
password** copies it without displaying or persisting it in the WebView.
Disabling Noctweb hosting removes both the capability and Publisher surface
from the launched container.

For local exposure, the launcher also supplies
`--trusted-local-container-bridge true`. Docker NAT hides the host's literal
loopback source from the relay process, so this explicit deployment assertion
is required for the local Publisher and authenticated bridge operations. It is
safe only while the host publishes the HTTP port to `127.0.0.1`; network
exposure forces the assertion off. Do not set it manually for a publicly bound
container port.

## Transports

- raw TCP: one newline-delimited request and response per connection;
- HTTP: `POST /relay`;
- WebSocket: connect to `/relay`, then exchange exact JSON frames.

There is no separate GET health or information route. Health and information
are `nw.core@2` requests through the normal relay transport.

Opaque-route and rendezvous capability operations require a confidential
transport. Literal loopback, listener TLS, or an explicitly trusted TLS reverse
proxy satisfy that gate. When nginx, Caddy, or another proxy owns HTTPS/WSS,
start the relay with:

```sh
--advertised-endpoint https://relay.example \
--trusted-reverse-proxy-tls true
```

This flag trusts the deployment boundary, not an `X-Forwarded-*` header. The
plain backend listener must therefore be firewalled or bound so clients cannot
bypass the trusted proxy. Leave the flag off for an exposed plaintext listener;
capability-bearing operations then fail closed.

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

In `manual` mode, every allow-listed endpoint is a standard relay peer rather
than a coordinator. The relay probes each peer's validated `info` response,
requires matching manual mode and federation name when configured, and exposes
only healthy peers through `nw.federation/list`. Adding or removing manual
peers through the native app or operator console updates the live directory;
the relay process does not need to restart.

See
[`federation_protocol_and_operations.md`](../NoctweaveDocumentation/federation_protocol_and_operations.md).

## Operator console

Set `NOCTWEAVE_ADMIN_TOKEN` (at least 32 random bytes recommended) and bind the
admin listener to loopback/private management networking. The console may
change non-secret operator policy; it cannot return relay passwords, admin
tokens, coordinator registration tokens, or signing private keys. Runtime
policy persists in `operator-config.json` with restrictive permissions.
Listener addresses, database mode, request ceilings, and secret values remain
process-owned startup configuration. Editable policy is validated and applied
without silently changing those boundaries.

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
