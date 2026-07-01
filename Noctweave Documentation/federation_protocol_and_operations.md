# Noctweave Federation Protocol And Operations

This guide describes how Noctweave relays discover each other, advertise capabilities, and forward traffic across relay boundaries. Federation is relay-to-relay routing only. Relays never decrypt message payloads.

## Federation Modes

Noctweave separates federation modes into different trust domains. A relay must not silently bridge one mode into another.

| Mode | Purpose | Forwarding Rule |
| --- | --- | --- |
| `solo` | Single standalone relay | Rejects all requests with `destinationRelay` |
| `manual` | Small operator-managed mesh | Destination must be in the local node list, report `manual`, and be `standard` kind |
| `curated` | Allow-listed federation with coordinators | Destination must satisfy allow-list, coordinator quorum, and optional signed-directory checks |
| `open` | Public open federation | Destination must report `open`, match federation name, and use public TLS unless private endpoints are explicitly allowed |

`manual`, `curated`, and `open` are intentionally incompatible. A curated relay cannot forward into open federation, and an open relay cannot use a curated allow-list.

## Endpoint Syntax

Relay endpoints may be written as:

- `relay.example.org:9339`: raw TCP, no TLS flag
- `tcp://relay.example.org:9339`: raw TCP
- `tls://relay.example.org:9339`: TLS-wrapped raw TCP
- `http://relay.example.org`: HTTP bridge, default port `80`
- `https://relay.example.org`: HTTPS bridge, default port `443`
- `ws://relay.example.org`: WebSocket bridge, default port `80`
- `wss://relay.example.org`: secure WebSocket bridge, default port `443`

Use `https://...` or `wss://...` when a relay is behind a reverse proxy such as Caddy, nginx, Nginx Proxy Manager, or Cloudflare.

## Relay Advertisement

Clients and other relays use the `info` request to inspect a relay before selecting it or forwarding through it.

```json
{ "type": "info" }
```

Important fields in `relayInfo`:

- `kind`: `standard`, `coordinator`, `bridge`, etc.
- `federation.mode`: `solo`, `manual`, `curated`, or `open`
- `federation.name`: optional federation namespace
- `tlsEnabled` and `transport`: advertised transport posture
- `federationCoordinatorEndpoints`: coordinator roots, if configured
- `knownOpenPeers`: bounded open-federation peer hints
- `openFederationDiscovery`: DHT/PEX capability advertisement
- `temporalBucketSeconds` and `temporalBucketScheduleSeconds`: timing policy
- `attachmentsEnabled` and attachment TTL fields
- `relayName`, `operatorNote`, and `softwareVersion`

Operators should set an advertised endpoint when the public endpoint differs from the listen socket:

```bash
--advertised-endpoint https://relay.example.org
```

## Manual Federation

Manual federation is the simplest operator-controlled mesh. It does not use coordinators, DHT records, peer exchange, quorum, or signed directory snapshots.

Start relay A:

```bash
NoctweaveRelayServer \
  --host 0.0.0.0 \
  --port 9339 \
  --http-port 9340 \
  --relay-kind standard \
  --federation-mode manual \
  --federation-name private-mesh \
  --federation-allow https://relay-b.example.org
```

Start relay B with A in its node list:

```bash
NoctweaveRelayServer \
  --host 0.0.0.0 \
  --port 9339 \
  --http-port 9340 \
  --relay-kind standard \
  --federation-mode manual \
  --federation-name private-mesh \
  --federation-allow https://relay-a.example.org
```

The Noctyra Relay macOS app can start a manual relay with an empty node list and add or remove peers while running. Until a peer is added, federation forwarding fails closed with `Manual federation: destination relay is not in the node list.`

## Curated Federation

Curated federation is for operator-managed universes where membership is explicit and auditable.

Strict curated policy requires:

1. Destination relay appears in the static allow-list.
2. Destination relay appears healthy in coordinator directory responses.
3. Coordinator quorum is met.
4. Directory snapshots are signed when `curatedRequireSignedDirectory` is enabled.
5. Destination relay reports `curated` mode and matching federation name.

Coordinator:

```bash
NoctweaveRelayServer \
  --relay-kind coordinator \
  --federation-mode curated \
  --federation-name trusted-net \
  --coordinator-registration-token "$REGISTRATION_TOKEN" \
  --data-dir /var/lib/noctweave-coordinator
```

Curated relay:

```bash
NoctweaveRelayServer \
  --relay-kind standard \
  --federation-mode curated \
  --federation-name trusted-net \
  --advertised-endpoint https://relay-a.example.org \
  --federation-coordinator https://coord.example.org \
  --coordinator-registration-token "$REGISTRATION_TOKEN" \
  --federation-allow https://relay-b.example.org \
  --curated-strict-policy true \
  --curated-coordinator-quorum 1 \
  --curated-require-signed-directory true
```

Relays heartbeat to coordinators with `registerFederationNode`; coordinators return currently healthy nodes with `listFederationNodes`.

## Open Federation

Open federation is for public relay networks. It does not use allow-lists. DHT and PEX features are available only in open mode.

Recommended open relay:

```bash
NoctweaveRelayServer \
  --relay-kind standard \
  --federation-mode open \
  --federation-name public-open-net \
  --advertised-endpoint https://relay.example.org \
  --open-federation-dht-node true \
  --relay-peer-exchange-limit 12
```

Public open federation requires TLS HTTPS/WSS endpoints by default. For isolated local testing only:

```bash
--allow-private-federation-endpoints true
```

Open federation discovery records are signed short-lived advertisements. They are discovery hints, not authority.

## Protocol Requests

### Forwarded Delivery

A client or relay forwards direct delivery by setting `destinationRelay`:

```json
{
  "type": "deliver",
  "deliver": {
    "inboxId": "recipient-routing-token",
    "routingToken": "recipient-routing-token",
    "destinationRelay": { "host": "relay-b.example.org", "port": 443, "useTLS": true, "transport": "http" },
    "envelope": { "...": "encrypted envelope" }
  }
}
```

Group delivery uses the same pattern with `deliverGroupMessage`.

### Coordinator Registration

```json
{
  "type": "registerFederationNode",
  "authToken": "registration-token-if-required",
  "registerFederationNode": {
    "endpoint": { "host": "relay-a.example.org", "port": 443, "useTLS": true, "transport": "http" },
    "ttlSeconds": 120,
    "relayInfo": { "...": "relayInfo from info" }
  }
}
```

### Coordinator Directory Listing

```json
{
  "type": "listFederationNodes",
  "listFederationNodes": {
    "mode": "curated",
    "federationName": "trusted-net",
    "onlyHealthy": true,
    "maxStalenessSeconds": 300,
    "requireSignedSnapshot": true
  }
}
```

Coordinator responses include `federationNodes` and, when signing is available, `federationSnapshot`.

### Open-Federation DHT

Open non-coordinator relays may expose:

```json
{
  "type": "publishOpenFederationDHTRecord",
  "publishOpenFederationDHTRecord": {
    "namespace": "noctyra-open-v1:<sha256-federation-name>",
    "record": { "...": "signed OpenFederationDHTRecord" }
  }
}
```

```json
{
  "type": "listOpenFederationDHTRecords",
  "listOpenFederationDHTRecords": {
    "namespace": "noctyra-open-v1:<sha256-federation-name>",
    "limit": 50
  }
}
```

DHT records are accepted only when the namespace, federation name, relay identity digest, ML-DSA signature, lifetime, endpoint transport, and public endpoint policy all validate.

## HTTPS Federation Source Files

The macOS relay app can fetch federation configuration from an HTTPS JSON file.

```json
{
  "mode": "curated",
  "name": "trusted-net",
  "description": "Operator-selected relays",
  "allowlist": [
    "https://relay-a.example.org",
    "https://relay-b.example.org"
  ],
  "coordinatorEntries": [
    {
      "endpoint": "https://coord.example.org",
      "directorySigningPublicKey": "base64-ml-dsa-public-key"
    }
  ],
  "coordinatorHeartbeatSeconds": 45,
  "coordinatorDirectoryMaxStalenessSeconds": 300,
  "curatedStrictPolicyEnabled": true,
  "curatedCoordinatorQuorum": 1,
  "curatedRequireSignedDirectory": true
}
```

Use source files for curated or manual deployments where operators want a reviewable configuration artifact. Do not use a public open-federation source file as an allow-list substitute.

## Operational Checks

Before adding a relay to any federation:

1. Send `health`; expect `{ "type": "ok" }`.
2. Send `info`; verify mode, name, kind, transport, TLS flag, relay name, and software version.
3. For curated mode, verify coordinator signatures and quorum.
4. For open mode, verify the endpoint is public HTTPS/WSS and the signed DHT record validates.
5. Send a test envelope with a controlled destination inbox.

## Failure Behavior

- Wrong federation mode: forwarding rejected.
- Name mismatch: forwarding rejected.
- Manual destination not listed: forwarding rejected.
- Curated quorum not met: forwarding rejected.
- Unsigned curated directory when signatures are required: forwarding rejected.
- Open destination without public TLS: forwarding rejected unless private endpoints are explicitly enabled.
- DHT record expired, tampered, flood-limited, or wrong namespace: record rejected.

These failures are intentional. Federation should fail closed rather than silently downgrade trust.
