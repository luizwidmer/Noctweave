<p align="center">
  <img src="../docs/assets/NoctweaveRelayIcon.svg" alt="Noctweave Relay" width="160">
</p>

<h1 align="center">Noctweave Relay Server</h1>

A Linux/Docker relay server for the Noctweave Protocol, used by compatible clients and tooling. It supports line-delimited TCP plus optional HTTP/WebSocket bridge support and includes a source-built desktop operator launcher.

## What it does

- Accepts a single JSON request per TCP connection, delimited by `\\n`.
- Optional HTTP/WebSocket bridge endpoint at `POST /relay` and `ws(s)://.../relay`.
- Supports `deliver`, `fetch`, `health`, `info`, and attachment chunk relay by default. Deprecated fingerprint-addressed pairing, prekeys, legacy groups, and inbox-wide destructive acknowledgement require an explicit compatibility profile.
- Supports federation coordinator directory APIs (`registerFederationNode`, `listFederationNodes`).
- Supports explicit open-federation DHT node mode and bounded PEX peer hints when enabled by the operator.
- Persists mailboxes + attachment chunks to `relay_store.sqlite` (unless `--memory-only`).
- Includes an optional authenticated operator Web UI for safe runtime configuration.

## Build (local)

```bash
cd "NoctweaveRelayServer"
swift build
```

Release build:

```bash
swift build -c release
```

## Run (local)

```bash
.build/debug/NoctweaveRelayServer --host 0.0.0.0 --port 9339 --data-dir /tmp/noctweave-relay
```

In-memory only (no disk writes):

```bash
.build/debug/NoctweaveRelayServer --memory-only
```

Inspect options without opening storage or binding a port:

```bash
.build/debug/NoctweaveRelayServer --help
.build/debug/NoctweaveRelayServer --version
```

The host default data directory is `/data`, matching the container image. For
a local persistent run, pass an explicit writable `--data-dir`. Configuration,
storage, and bind failures print a redacted operator error and exit nonzero.

## Docker

The image pins liboqs 0.16.0 to immutable commit
`5a1a854b0dc9f2141bdc771c555ee60c37950183` for reproducible cryptographic builds and runs the
relay as an unprivileged `noctweave` user. Mount `/data` as a writable volume
owned by UID/GID `10001`. Coordinator nodes persist their directory-signing key
inside this volume; back it up with the relay database to preserve client trust
across rebuilds.

For secrets, prefer environment variables over command-line flags so values do
not appear in process listings:

- `NOCTWEAVE_RELAY_PASSWORD`
- `NOCTWEAVE_COORDINATOR_REGISTRATION_TOKEN`
- `NOCTWEAVE_FEDERATION_FORWARDING_TOKEN`
- `NOCTWEAVE_COORDINATOR_SIGNING_KEY` (base64)
- `NOCTWEAVE_ATTACHMENT_STORAGE`
- `NOCTWEAVE_IPFS_API_ENDPOINT`
- `NOCTWEAVE_IPFS_GATEWAY_ENDPOINT`
- `NOCTWEAVE_IPFS_TIMEOUT_SECONDS`
- `NOCTWEAVE_ONION_TRANSPORT`
- `NOCTWEAVE_ONION_MAX_HOPS`
- `NOCTWEAVE_ONION_FIXED_SIZE_PACKETS`
- `NOCTWEAVE_MIXNET_TRANSPORT`
- `NOCTWEAVE_MIXNET_BATCH_INTERVAL_SECONDS`
- `NOCTWEAVE_MIXNET_MIN_BATCH_SIZE`
- `NOCTWEAVE_MIXNET_COVER_PACKETS_PER_BATCH`
- `NOCTWEAVE_MIXNET_MAX_DELAY_SECONDS`
- `NOCTWEAVE_HIDDEN_RETRIEVAL_REPLICAS`
- `NOCTWEAVE_OPEN_FEDERATION_DHT_NODE`
- `NOCTWEAVE_OPEN_FEDERATION_DHT_MAX_RECORDS`
- `NOCTWEAVE_OPEN_FEDERATION_DHT_MAX_RECORDS_PER_HOST`
- `NOCTWEAVE_OPEN_FEDERATION_DHT_MAX_QUERY_RECORDS`
- `NOCTWEAVE_RELAY_PEER_EXCHANGE_LIMIT`
- `NOCTWEAVE_ADMIN_TOKEN`
- `NOCTWEAVE_ADMIN_HOST`
- `NOCTWEAVE_ADMIN_PORT`
Use `--attachments-enabled false` for a text-only relay. Attachment upload and
download routes then fail closed. Set `--temporal-bucket-seconds 0` with no
bucket schedule to disable temporal bucketing.

### IPFS attachment offload

The relay can offload encrypted attachment chunks to an IPFS-compatible HTTP API while keeping only CID, size, digest, and expiry metadata in SQLite. Enable it with:

```bash
.build/debug/NoctweaveRelayServer \
  --attachment-storage ipfs \
  --ipfs-api-endpoint http://127.0.0.1:5001 \
  --ipfs-gateway-endpoint http://127.0.0.1:8080 \
  --ipfs-timeout-seconds 10
```

Equivalent environment configuration:

```bash
NOCTWEAVE_ATTACHMENT_STORAGE=ipfs
NOCTWEAVE_IPFS_API_ENDPOINT=http://127.0.0.1:5001
NOCTWEAVE_IPFS_GATEWAY_ENDPOINT=http://127.0.0.1:8080
NOCTWEAVE_IPFS_TIMEOUT_SECONDS=10
```

Upload uses `/api/v0/add` with pinning enabled. Fetch first tries `/api/v0/cat`, then falls back to `<gateway>/ipfs/<cid>`. Returned bytes must match the stored byte count and SHA-256 digest or the fetch fails closed. TTL cleanup removes relay metadata and performs best-effort IPFS unpinning; it is not cryptographic erasure because other IPFS peers or gateways may retain content. Use a relay-controlled IPFS node or private IPFS cluster.

Use `--hidden-retrieval true` to advertise optional cover-query hidden
retrieval support. This is a metadata-reduction capability for compatible
clients, not full PIR and not a mandatory fetch path.

For replicated XOR-PIR advertisement, use
`--hidden-retrieval-mode replicatedXorPIR` and at least two independent TLS
replicas. Add replicas with repeated `--hidden-retrieval-replica` flags or with
`NOCTWEAVE_HIDDEN_RETRIEVAL_REPLICAS`. Each entry is
`replicaId,operatorId,endpoint`; separate environment entries with `;`.
Example:

```bash
NOCTWEAVE_HIDDEN_RETRIEVAL_REPLICAS='a,operator-a,https://pir-a.example:443;b,operator-b,https://pir-b.example:443'
```

Clients can reject replicated-PIR metadata if replica IDs, operator IDs, or
endpoints are duplicated, if fewer than two replicas are advertised, or if a
replica endpoint is not TLS-protected.

Use `--onion-transport true` to advertise optional PQ onion packet support for
compatible relay paths. This publishes hop-by-hop packet support only; it is not
a full mixnet and does not add global cover traffic or batching.

Use `--mixnet-transport true` to advertise deterministic batching, bounded
release jitter, and cover-packet scheduling. This is a relay capability signal
for compatible clients and federated paths; it is not a claim that the entire
network has global cover traffic.

Use `--wake-mode pullOnly` or `--wake-mode longPoll` to advertise a decentralized wake policy for compatible clients. This does not enable centralized push and does not guarantee closed-app delivery; it only publishes relay-supported polling or long-poll bounds.

Use `--open-federation-dht-node true` with `--federation-mode open` to make the relay act as a bounded open-federation DHT node. The relay then accepts and serves signed short-lived relay records through the relay protocol. Keep `--allow-private-federation-endpoints false` for public networks so records and forwarding do not target loopback or LAN addresses. PEX is separate: `--relay-peer-exchange-limit <count>` controls how many known open relays are advertised in `/info`; set it to `0` to disable peer hints.

```bash
docker build -t noctweave-relay .
docker run --rm -p 9339:9339 -v noctweave-data:/data noctweave-relay
```

The Dockerfile uses the full Swift image only as a build stage. The published
runtime stage is based on Ubuntu 22.04 and contains the stripped relay binary,
the minimal liboqs profile, required Swift shared libraries, certificates,
libcurl, and SQLite. Compiler tools, package caches, static Swift libraries,
tests, and source files are not included in the final image.

### Desktop operator launcher

Noctweave does not publish an official relay desktop binary. The Electrobun
launcher is built locally and uses Docker to provide the same Linux relay on
macOS, Windows, and Linux. It packages the relay source snapshot, builds the
image on your machine, keeps relay data in a named volume, and opens the existing
authenticated operator console. Chromium is not bundled.

Requirements are Git, Bun 1.3.14, and a running Docker Desktop or Docker Engine.
Build on the operating system and architecture where the launcher will run:

```bash
cd NoctweaveRelayServer
bun install --frozen-lockfile
bun run desktop:icons
bun run desktop:test
bun run typecheck:desktop
bun run desktop:build
```

The distributable is written to `NoctweaveRelayServer/artifacts/`. Local builds
are unsigned; sign and notarize redistributed builds with your own platform
identity. Run a development copy with `bun run desktop:dev`.

Inside the launcher, select **Build from source** once, then start the relay.
The first image build compiles Swift and liboqs and may take several minutes;
the launcher keeps the build state visible and Docker caches later builds. If a
native relay already owns port `9339`, choose different launcher ports or stop
the other relay before starting. Startup failures remain visible with bounded
container diagnostics.
The operator console is always mapped to `127.0.0.1`; selecting network exposure
publishes only the messaging ports. The launcher stores its generated operator
token in a user-private local settings file (`0600` permissions on POSIX
systems) and copies it only on explicit request. Closing the launcher does not
stop the relay container.

The launcher invokes the local Docker daemon, which is a privileged capability.
Use only source you have reviewed. For unattended production deployments,
compose files and explicit operator-managed secrets remain preferable to a
desktop launcher.

### Operator Web UI

The container includes a responsive operator console styled consistently with
NoctweaveJS. It runs on a dedicated listener and is disabled unless an admin
token is supplied. Generate a random token and bind the console to localhost:

```bash
export NOCTWEAVE_ADMIN_TOKEN="$(openssl rand -hex 32)"
docker run --rm \
  -p 9339:9339 \
  -p 9340:9340 \
  -p 127.0.0.1:9090:9090 \
  -e NOCTWEAVE_ADMIN_TOKEN \
  -v noctweave-data:/data \
  noctweave-relay \
  --host 0.0.0.0 --port 9339 --http-port 9340 --data-dir /data
```

Open [http://127.0.0.1:9090/admin/](http://127.0.0.1:9090/admin/) and enter the
token. Supplying `NOCTWEAVE_ADMIN_TOKEN` automatically enables port `9090`; use
`NOCTWEAVE_ADMIN_PORT` to choose another port. The Docker image sets the internal
admin bind address to `0.0.0.0`, while the host mapping above keeps it available
only from the relay host.

The console can update and persist:

- relay name, operator message, and advertised public endpoint;
- temporal bucket policy, attachment availability/retention, and group creation;
- inline or IPFS attachment storage, including API/gateway endpoints and timeout;
- group security model, hidden retrieval, onion routing, and mixnet advertisement;
- solo, manual, curated, or open federation settings and peer lists;
- open-federation DHT/PEX bounds, coordinator timing, curated policy, and decentralized wake advertisement.

Changes are validated and written atomically to `/data/operator-config.json`
with mode `0600`. Routing, federation, metadata-reduction, group, and delivery
policy changes apply to new relay requests immediately; existing in-flight
requests retain their starting configuration snapshot. IPFS backend and
endpoint changes display a **Restart required** badge and activate on the next
container start. The file contains no relay password, admin token, coordinator
token, forwarding token, or signing private key.

Listener addresses, ports, SQLite/memory mode, request ceilings, and all secrets
remain bootstrap settings configured through Docker arguments or environment
variables. Attachment backend and IPFS endpoint changes may be staged in the
console, but the running blob store is not replaced until the container
restarts. Never publish the admin port directly to the internet. For remote
administration, use an SSH tunnel, private VPN, or a separately authenticated
HTTPS reverse proxy.

### Docker + Let's Encrypt (automatic TLS)

Use the bundled Caddy stack when you want public TLS certs without manual PKCS#12 handling.

1. Copy env template and set your domain/email:

```bash
cd "NoctweaveRelayServer"
cp .env.letsencrypt.example .env
```

2. Edit `.env`:
- `RELAY_DOMAIN`: public DNS name pointing to this host
- `ACME_EMAIL`: Let's Encrypt contact email

3. Start TLS stack:

```bash
docker compose -f docker-compose.letsencrypt.yml up -d --build
```

The relay listens internally on raw TCP `9339` and HTTP/WebSocket bridge `9340`.
Caddy exposes TLS on `443` with automatic issuance/renewal and forwards `/relay` to the bridge.
Point clients to `https://<RELAY_DOMAIN>:443/relay` or `wss://<RELAY_DOMAIN>:443/relay`.

### Federation quick starts

Use `solo` when the relay should never forward to another relay:

```bash
.build/debug/NoctweaveRelayServer \
  --host 0.0.0.0 \
  --http-port 9340 \
  --transport http \
  --advertised-endpoint https://relay.example.org \
  --federation-mode solo
```

Use `manual` for a small mesh maintained directly by operators. Each relay must
list the other relays by public advertised endpoint:

```bash
.build/debug/NoctweaveRelayServer \
  --host 0.0.0.0 \
  --http-port 9340 \
  --relay-kind standard \
  --transport http \
  --advertised-endpoint https://relay-a.example.org \
  --federation-mode manual \
  --federation-name private-mesh \
  --federation-allow https://relay-b.example.org
```

Use `curated` when membership is governed by an allow-list plus coordinator
health. Start at least one coordinator, then point standard relays at it:

```bash
.build/debug/NoctweaveRelayServer \
  --relay-kind coordinator \
  --transport http \
  --http-port 9340 \
  --advertised-endpoint https://coord.example.org \
  --federation-mode curated \
  --federation-name trusted-net \
  --coordinator-registration-token "$REGISTRATION_TOKEN"
```

```bash
.build/debug/NoctweaveRelayServer \
  --relay-kind standard \
  --transport http \
  --http-port 9340 \
  --advertised-endpoint https://relay-a.example.org \
  --federation-mode curated \
  --federation-name trusted-net \
  --federation-allow https://relay-b.example.org \
  --federation-coordinator https://coord.example.org \
  --coordinator-registration-token "$REGISTRATION_TOKEN"
```

Use `open` only for public federation. DHT and PEX are only meaningful in open
mode:

```bash
.build/debug/NoctweaveRelayServer \
  --relay-kind standard \
  --transport http \
  --http-port 9340 \
  --advertised-endpoint https://relay.example.org \
  --federation-mode open \
  --federation-name public-open-net \
  --open-federation-dht-node true \
  --relay-peer-exchange-limit 12
```

Validate a relay before adding it to a federation:

```bash
curl -s https://relay.example.org/health
curl -s https://relay.example.org/relay \
  -H 'content-type: application/json' \
  -d '{"type":"info"}'
```

For reverse-proxy deployments, advertise the public HTTPS/WSS URL, not the
internal container, Docker bridge, or LAN address. Federation forwarding uses
the advertised endpoint for policy checks and coordinator registration.

### Flags

- `--help`, `-h`: print the common option summary without starting the relay
- `--version`: print the static relay software version

- `--host <ip>`: listen interface (default: `0.0.0.0`)
- `--port <port>`: listen port (default: `9339`)
- `--http-port <port>`: optional HTTP/WebSocket bridge port (disabled by default). Serves `POST /relay` and WebSocket `/relay`.
- `--admin-host <address>`: operator Web UI bind address (default: `127.0.0.1`; Docker image default: `0.0.0.0`)
- `--admin-port <port>`: authenticated operator Web UI port (disabled unless configured; defaults to `9090` when an admin token is supplied)
- `--admin-token <token>`: operator bearer token, 16-4096 UTF-8 bytes. Prefer `NOCTWEAVE_ADMIN_TOKEN` so it does not appear in process listings.
- `--data-dir <path>`: store messages to `relay_store.sqlite` inside this directory (default: `/data`)
- `--memory-only`: disable persistence
- `--max-inbox <count>`: max messages stored per inbox (default: `1000`, `0` disables)
- `--max-message-bytes <bytes>`: reject requests larger than this payload size (default: `524288`; normalized to `1024...8388608`)
- `--max-line-bytes <bytes>`: reject lines larger than this size before decoding (default: `655360`; always at least the message limit plus framing allowance and at most `10485760`)
- `--forwarding-timeout-seconds <seconds>`: timeout for relay-to-relay TCP/HTTP forwarding and federation checks (default: `8`; normalized to `1...300`)
- `--relay-kind <standard|discovery|bridge|archive|privateRelay|coordinator>`: advertise the relay kind (default: `standard`)
- `--transport <tcp|http|websocket>`: advertised transport in relay info when no advertised endpoint is set (default: `tcp`)
- `--federation-mode <solo|manual|curated|open>`: advertise federation mode (default: `solo`)
- `--federation-name <name>`: optional federation name
- `--federation-description <text>`: optional federation description
- `--federation-allow <host:port,host:port>`: manually listed relays for manual federation, or allow-list relays for curated federation (repeat or comma-separated)
- `--allow-private-federation-endpoints <true|false>`: permit open-federation registration/forwarding to loopback, LAN, or private addresses (default: `false`; use only for an isolated development network)
- `--curated-strict-policy <true|false>`: enforce allow-list + coordinator quorum for curated forwarding (default: `true`)
- `--curated-coordinator-quorum <count>`: minimum coordinators that must report destination relay as healthy (default: `1`)
- `--curated-require-signed-directory <true|false>`: require signed coordinator snapshots when validating curated routes (default: `true`)
- `--federation-coordinator <host:port[,host:port]>`: federation coordinator endpoint(s) used for relay directory + heartbeat registration
- `--coordinator-registration-token <token>`: shared secret required by coordinator relays for `registerFederationNode`
- `--federation-forwarding-auth-token <token>`: optional token used only for relay-to-relay `deliver` forwarding authentication
- `--coordinator-heartbeat-seconds <seconds>`: relay heartbeat interval to coordinators (default: `45`, min `15`)
- `--coordinator-directory-max-staleness-seconds <seconds>`: max acceptable heartbeat age for coordinator directory listings (default: `300`)
- `--relay-peer-exchange-limit <count>`: max open-federation peer hints advertised in relay info (default: `12`)
- `--open-federation-dht-node <true|false>`: enable open-federation DHT record publish/list routes on open non-coordinator relays (default: `false`)
- `--open-federation-dht-max-records <count>`: max signed relay records retained in the DHT cache (default: `256`)
- `--open-federation-dht-max-records-per-host <count>`: max accepted DHT records per host to limit flooding (default: `4`)
- `--open-federation-dht-max-query-records <count>`: max records returned by a DHT list request (default: `256`)
- `--coordinator-directory-signing-key <base64>`: optional ML-DSA-65 private key bundle for deterministic coordinator snapshot signing
- `--advertised-endpoint <host:port|https://host:port|wss://host:port>`: endpoint this relay publishes to coordinators
- `--advertise-tls <true|false>`: override TLS status in `relayInfo.tlsEnabled` (defaults to advertised endpoint scheme when set)
- `--temporal-bucket-seconds <seconds>`: advertise temporal bucketing seconds (default: `300`)
- `--temporal-bucket-minutes <minutes>`: convenience flag (overrides seconds)
- `--temporal-bucket-schedule-seconds <csv>`: optional per-message bucket set (e.g. `60,120,300`)
- `--temporal-bucket-schedule-minutes <csv>`: minutes variant (e.g. `1,2,5`)
- `--attachment-default-ttl-seconds <seconds>`: default attachment retention TTL (default: `3600`)
- `--attachment-default-ttl-minutes <minutes>`: default attachment retention TTL in minutes
- `--attachment-max-ttl-seconds <seconds>`: max accepted attachment TTL (default: `21600`)
- `--attachment-max-ttl-minutes <minutes>`: max accepted attachment TTL in minutes
- `--attachments-enabled <true|false>`: enable or disable attachment upload/fetch routes (default: `true`)
- `--attachment-storage <inline|ipfs>`: store encrypted attachment chunks inline in SQLite or offload them to IPFS while retaining verified metadata locally (default: `inline`)
- `--ipfs-api-endpoint <url>`: IPFS HTTP API endpoint used for `/api/v0/add`, `/api/v0/cat`, and `/api/v0/pin/rm` when `--attachment-storage ipfs` is enabled (default: `http://127.0.0.1:5001`)
- `--ipfs-gateway-endpoint <url>`: optional gateway fallback used as `<gateway>/ipfs/<cid>` when API fetch fails
- `--ipfs-timeout-seconds <seconds>`: timeout for IPFS API and gateway requests (default: `10`, min `1`)
- `--hidden-retrieval <true|false>`: advertise optional hidden-retrieval cover-query support (default: `false`)
- `--hidden-retrieval-mode <coverQuery|replicatedXorPIR>`: advertised hidden-retrieval mode
- `--hidden-retrieval-cover-size <count>`: default cover set size advertised to clients (default: `8`)
- `--hidden-retrieval-max-cover-size <count>`: max cover set size advertised to clients (default: `32`)
- `--hidden-retrieval-replica <replicaId,operatorId,endpoint>`: add a replicated XOR-PIR replica endpoint; repeat or separate entries with `;`
- `--onion-transport <true|false>`: advertise optional PQ onion packet support (default: `false`)
- `--onion-max-hops <count>`: max advertised onion hops, clamped to 1-8 (default: `3`)
- `--onion-fixed-size-packets <true|false>`: advertise fixed-size packet requirement (default: `true`)
- `--mixnet-transport <true|false>`: advertise deterministic batching and cover-packet scheduling (default: `false`)
- `--mixnet-batch-interval-seconds <seconds>`: batch interval, clamped to 5-3600 seconds (default: `30`)
- `--mixnet-min-batch-size <count>`: minimum advertised batch size, clamped to 1-256 (default: `8`)
- `--mixnet-cover-packets-per-batch <count>`: cover packets per batch, clamped to 0-256 (default: `2`)
- `--mixnet-max-delay-seconds <seconds>`: max release delay, clamped to 0-3600 seconds (default: `120`)
- `--wake-mode <pullOnly|longPoll>`: advertise decentralized wake support for compatible clients
- `--wake-min-poll-seconds <seconds>`: lower polling interval bound advertised to clients (default: `60`)
- `--wake-max-poll-seconds <seconds>`: upper polling/backoff bound advertised to clients (default: `300`)
- `--wake-jitter-permille <0-1000>`: deterministic jitter range as permille of the active interval (default: `250`)
- `--wake-long-poll-timeout-seconds <seconds>`: bounded long-poll timeout when `--wake-mode longPoll` is used
- `--relay-name <name>`: advertise a relay display name
- `--operator-note <text>`: optional operator note for clients
- `--group-security-model <relayBackedPairwise|mlsDerivedTree>`: advertised group cryptography model (default: `mlsDerivedTree`). Use `relayBackedPairwise` only for a separately implemented compatibility client; the reference group path does not silently downgrade.

`softwareVersion` is generated by the relay binary as
`NoctweaveRelayServer/0.1.0`; operators cannot override it. Use `relayName` and
`operatorNote` for operator-controlled presentation.

Security note:
- Linux relay verifies actor-proof signatures when `liboqs` is available at runtime (included in the Docker image).
- If `liboqs` is not available, actor-proof mutations are fail-closed.
- See `NoctweaveDocumentation/relay_ops_hardening_guide.md` for TLS proxying, firewall, secrets, storage, federation, DHT, and log hygiene guidance.
- See `NoctweaveDocumentation/federation_protocol_and_operations.md` for the full federation protocol, endpoint syntax, coordinator recipes, open-federation DHT/PEX behavior, and failure semantics.

### Manual federation

When `federation.mode=manual`, forwarding is intentionally simple and operator-managed:

1. Destination relay endpoint must be present in `--federation-allow`.
2. Destination relay must advertise `federation.mode=manual`.
3. Destination relay must advertise relay kind `standard`.
4. If federation name is set, destination name must match.

Manual mode does not use coordinator quorum, signed directory snapshots, open-federation DHT records, or peer exchange. It is intended for small meshes where operators directly maintain the node list.

Manual mode can start with an empty node list. Forwarding fails closed until a destination is added to the list. This is useful when the macOS relay app is used to add peers while the relay is already running.

### Curated strict policy

When `federation.mode=curated`, strict policy is enabled by default and forwarding is allowed only if all checks pass:

1. Destination relay endpoint is present in static `--federation-allow`.
2. At least `--curated-coordinator-quorum` coordinators report destination as healthy in the current directory.
3. Directory response signature is valid when `--curated-require-signed-directory=true`.
4. Destination relay advertises `federation.mode=curated` and matching federation name (if set).

## Protocol

The relay supports:
- Raw TCP mode: one JSON object per connection, newline-delimited.
- HTTP mode: `POST /relay` with JSON request body and JSON response body.
- WebSocket mode: connect to `/relay`, send one request JSON frame, receive one response JSON frame.

Raw TCP behavior: one JSON request line and one JSON response line, then close. If `destinationRelay` is provided on deliver, the relay forwards the envelope to the destination server and returns its response.
Inbound client `authToken` is not forwarded; configure `--federation-forwarding-auth-token` when destination relays require auth.

### Deliver

**Request**

The architecture-v2 route shape is capability-only:

```json
{
  "type": "deliver",
  "deliver": {
    "inboxCapability": { "rawValue": "base64-32-byte-bearer-value" },
    "envelope": { "...": "encrypted envelope" },
    "destinationRelay": {
      "host": "relay.example.com",
      "port": 9340,
      "useTLS": true,
      "transport": "websocket"
    }
  }
}
```

It deliberately omits `inboxId` and `routingToken`. A federation entry relay
forwards only the opaque value; the final relay hashes it with the
`org.noctweave.relay.inbox-route-capability/v2` domain and resolves the digest.
Malformed bearer objects fail strict request decoding. Well-formed unknown or
revoked values return `Inbox route capability is unavailable` before mailbox
allocation.

The following inbox-addressed form remains transitional while clients do not
yet have a private per-relationship issuance/exchange flow:

```json
{
  "type": "deliver",
  "deliver": {
    "inboxId": "bob-inbox",
    "routingToken": "optional-bech32-routing-token",
    "envelope": {
      "id": "C8B8F0E0-6C2D-4A2E-8D31-0C31B25C7B7A",
      "conversationId": "base64-conversation-id",
      "sessionId": "base64-session-id",
      "senderFingerprint": "base64-fingerprint",
      "sentAt": "2025-12-27T21:36:12Z",
      "messageCounter": 0,
      "kemCiphertext": "base64-optional",
      "payload": {
        "nonce": "base64",
        "ciphertext": "base64",
        "tag": "base64"
      },
      "signature": "base64"
    },
    "destinationRelay": { "host": "relay.example.com", "port": 9339 }
  }
}
```

**Response**

```json
{
  "type": "delivered",
  "delivered": { "storedCount": 1 }
}
```

The effective destination (`routingToken` when supplied, otherwise `inboxId`)
must already be registered at the final relay. An unknown destination returns
an error response with `Destination inbox is not registered` and allocates no
mailbox state. Federation entry relays may forward without a local registration;
the final relay always performs this admission check. Group delivery has the
same final-relay rule, using the persisted group descriptor as registration for
its generated group inbox.

### Opaque Inbox Route Capabilities

This request family is experimental, disabled by default, and omitted from the
relay capability manifest. The production relay currently exposes no operator
switch to activate it; focused conformance tests enable it only through the
internal configuration model. A client must not infer support from the OpenAPI
schema alone.

`createInboxRouteCapability` and `revokeInboxRouteCapability` carry `inboxId`,
the CSPRNG-minted opaque capability object, the relay-issued scope returned by
authenticated inbox registration, a monotonic inbox-local mutation sequence,
and an `authorityProof` made by that inbox's registered access key. The v3
transcript binds all of those fields. The relay atomically persists the route
change, sequence, and proof-independent logical mutation digest. Exact retries
of an already-applied matching operation remain idempotent even after the proof
freshness window; a first application still needs a fresh proof. Stale,
conflicting, skipped, and cross-relay mutation requests fail closed. Revocation
of an unseen value records a bounded tombstone, while the durable sequence
prevents an older delayed create from winning after tombstone compaction.

Reference limits are 16 active capabilities per inbox, 64 retained revoked
records per inbox, and 100000 total records. These are defensive test bounds,
not a viable one-capability-per-relationship capacity promise. SQLite stores
only the domain-separated capability digest, inbox binding, lifecycle
timestamps, and the inbox registration's relay-local route cursor; never the raw
bearer value. The final relay can nevertheless correlate every digest mapped to
one inbox generation and observe delivery timing and volume. Inbox retirement
atomically purges the scope, cursor, and every mapping.

This relay API is a foundation, not a publication mechanism. No current contact
offer, announcement, discovery path, or headless direct-v4 sender distributes
capabilities. Do not place one reusable value in a public contact code. A bearer
is write authority, so a valid relationship route requires TLS except for
literal same-host loopback development. Client activation additionally waits
for relationship-scoped inboxes or equivalent unlinkability, bounded expiring
route epochs and renewal, realistic rotation capacity, per-capability abuse
controls, and a padding policy.

### Retire Inbox

`retireInbox` is the irreversible cleanup operation for an old inbox generation.
The client signs the domain-separated request with that inbox's ML-DSA access
key and durably journals the exact request before deleting the private key. A
successful request atomically purges the registration, all mailbox consumers
and cursor state, all opaque route-capability mappings, and all queued
envelopes, then stores a compact non-expiring
non-resurrection record. Delivery, consumer registration, and inbox
re-registration remain rejected for the lifetime of that relay namespace.

Retirement proofs intentionally do not expire and do not consume the ordinary
actor-proof replay cache. Replaying the exact journaled request is a safe no-op
that returns `ok`; a request with a changed nonce or signature does not match a
durable retirement record. A valid self-bound request also creates the record
when no registration remains. Retirement is inbox-key-bound, monotonic, and
cannot recreate state.

Retirement records never expire or evict one another. The relay admits at most
100,000 inbox generations over one storage namespace's lifetime; each admitted
live inbox reserves its eventual retirement slot. New first registrations fail
closed at the ceiling, while an already admitted inbox can always be retired.
Operators must preserve `relay_inbox_retirements` in backups, provision a new
relay namespace before exhaustion, and never reuse a retired inbox address for
a new identity generation.

```json
{
  "type": "retireInbox",
  "retireInbox": {
    "inboxId": "noctweave1...",
    "accessProof": {
      "fingerprint": "base64-sha256-access-key",
      "publicSigningKey": "base64-ml-dsa-public-key",
      "signedAt": "2026-07-16T12:34:56Z",
      "nonce": "11111111-1111-4111-8111-111111111111",
      "signature": "base64-ml-dsa-signature"
    }
  }
}
```

### Fetch

**Request**

```json
{
  "type": "fetch",
  "fetch": { "inboxId": "bob-inbox", "routingToken": "optional-bech32-routing-token", "maxCount": 50 }
}
```

**Response**

```json
{
  "type": "messages",
  "messages": [ { "id": "...", "conversationId": "...", "...": "..." } ]
}
```

### Health

**Request**

```json
{ "type": "health" }
```

**Response**

```json
{ "type": "ok" }
```

### Info

```json
{ "type": "info" }
```

```json
{
  "type": "info",
  "relayInfo": {
    "kind": "standard",
    "federation": { "mode": "solo", "name": null, "description": null },
    "tlsEnabled": true,
    "federationCoordinatorEndpoints": [{ "host": "coord.example.org", "port": 9339 }],
    "coordinatorReportedRelayCount": null,
    "curatedStrictPolicyEnabled": true,
    "curatedCoordinatorQuorum": 1,
    "curatedRequireSignedDirectory": true,
    "federationDirectoryPublicKey": "base64-ml-dsa-65-public-key",
    "knownOpenPeers": [{ "host": "relay-open.example.org", "port": 9443, "useTLS": true }],
    "temporalBucketSeconds": 300,
    "temporalBucketScheduleSeconds": [60, 120, 300],
    "attachmentDefaultTTLSeconds": 3600,
    "attachmentMaxTTLSeconds": 21600,
    "operatorNote": "Optional operator message",
    "softwareVersion": "NoctweaveRelayServer/0.1.0",
    "advertisedAt": "2026-02-02T12:00:00Z"
  }
}
```

`federationDirectoryPublicKey` is the coordinator's ML-DSA-65 public key for signed federation directory snapshots. Linux relay signing and verification use runtime `liboqs`; coordinator mode fails closed for signed snapshot generation if the runtime signer is unavailable.

### Open-Federation DHT Gateway

Autonomous BEP5/libp2p public-DHT participation is intentionally not built into
the relay binary. Operators may use the bounded relay-native overlay described
below or connect a separately managed discovery process through the narrow HTTP
gateway. Both paths accept only Noctweave-signed records and retain the same
validation boundary as coordinator discovery.

Gateway contract:

- Publish: `POST /v1/open-federation/dht/records`
- Query: `GET /v1/open-federation/dht/records?namespace=<namespace>&limit=<n>`
- Optional auth: `Authorization: Bearer <token>`
- Publish body:

```json
{
  "namespace": "noctweave-open-v1:<federation-name-hash>",
  "record": { "...": "signed OpenFederationDHTRecord" }
}
```

- Query response:

```json
{ "records": [{ "...": "signed OpenFederationDHTRecord" }] }
```

The gateway may also return a raw JSON array of records. Relay validation still rejects wrong namespaces, invalid ML-DSA signatures, stale records, insecure endpoints, non-public endpoints when public routing is required, per-host floods, and over-large gateway responses.

### Native Open-Federation Overlay

The Linux relay also exposes native relay-protocol DHT routes for open non-coordinator relays:

- `publishOpenFederationDHTRecord`: publish one signed short-lived DHT record into the receiving relay's ephemeral cache.
- `listOpenFederationDHTRecords`: list accepted records for the relay's configured open-federation namespace.

`OpenFederationDHTNativeOverlayTransport` uses those routes plus capped `knownOpenPeers` hints from `info` responses to walk a small PEX-style overlay without a gateway sidecar. It is still a discovery hint path, not membership authority. Records are ephemeral, namespace-bound, signature-checked, lifetime-limited, and revalidated by the same candidate cache used by the gateway path.

### Federation Coordinator APIs

Register/heartbeat relay metadata at a coordinator:

```json
{
  "type": "registerFederationNode",
  "registerFederationNode": {
    "endpoint": { "host": "relay-x.example.org", "port": 9339 },
    "relayInfo": { "...": "..." },
    "ttlSeconds": 120
  }
}
```

List currently healthy federation relays from a coordinator:

```json
{
  "type": "listFederationNodes",
  "listFederationNodes": {
    "mode": "curated",
    "federationName": "MyFederation",
    "onlyHealthy": true,
    "maxStalenessSeconds": 300,
    "requireSignedSnapshot": true
  }
}
```

Coordinator responses now include `federationSnapshot` (signed directory snapshot with `issuedAt` / `validUntil` / `signature`), when available.

### Attachments

Attachments are uploaded as encrypted chunks and fetched by attachment ID + chunk index.

Upload chunk:

```json
{
  "type": "uploadAttachment",
  "uploadAttachment": {
    "attachmentId": "C8B8F0E0-6C2D-4A2E-8D31-0C31B25C7B7A",
    "chunkIndex": 0,
    "payload": { "nonce": "base64", "ciphertext": "base64", "tag": "base64" },
    "ttlSeconds": 1800
  }
}
```

Fetch chunk:

```json
{
  "type": "fetchAttachment",
  "fetchAttachment": {
    "attachmentId": "C8B8F0E0-6C2D-4A2E-8D31-0C31B25C7B7A",
    "chunkIndex": 0
  }
}
```

### Error

```json
{ "type": "error", "error": "Human-readable message" }
```

## Storage

- File path: `<data-dir>/relay_store.sqlite`
- Format: normalized, transactional SQLite tables for relay-domain records
- Message removal: `fetch` is non-destructive; authenticated acknowledgement removes successfully processed envelopes
- Attachment removal: chunks expire after their TTL

## Compatibility

- Compatible with the SwiftUI client in this repository.
- The client uses a pure ML‑KEM‑768 session bootstrap; the first message includes `kemCiphertext`.
