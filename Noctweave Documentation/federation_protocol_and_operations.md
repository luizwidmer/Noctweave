# Noctweave Federation Protocol And Operations

This document defines the deployed Noctweave federation model and the operator procedures for configuring it. Federation is relay-to-relay routing only: relays route sealed envelopes, group registry mutations, prekey state, pairing requests, and capability metadata, but they never receive plaintext message bodies or attachment plaintext.

## Design Goals

Federation has three practical goals:

- Let users on different relays exchange direct and group messages without moving identities to the same relay.
- Let operators choose their trust domain: standalone, manual mesh, curated network, or open network.
- Fail closed when a relay cannot prove that a destination belongs to the same federation mode and namespace.

Noctweave deliberately does not bridge curated and open networks. A curated universe is an operator-reviewed allow-listed network. An open universe is a public discovery network. Mixing them would weaken both models.

## Federation Modes

| Mode | Use Case | Discovery | Forwarding Gate |
| --- | --- | --- | --- |
| `solo` | One private relay | None | Reject every request with `destinationRelay` |
| `manual` | Small private mesh | Local peer list | Destination must be explicitly listed, `manual`, same federation name, and `standard` kind |
| `curated` | Reviewed multi-operator network | Allow-list plus coordinators | Destination must pass allow-list, coordinator quorum, health freshness, optional signed directory, and same federation name |
| `open` | Public open relay network | Coordinators, relay-native DHT, and PEX hints | Destination must report `open`, same federation name, public secure endpoint unless test mode permits private addresses |

Use `manual` for the simplest real deployment. Use `curated` when membership needs governance. Use `open` only when the operator accepts public federation semantics and public endpoint requirements.

## Endpoint Syntax

Relays and clients normalize endpoint strings before use:

- `relay.example.org:9339`: raw TCP, explicit port
- `tcp://relay.example.org:9339`: raw TCP
- `tls://relay.example.org:9339`: TLS-wrapped raw TCP
- `http://relay.example.org`: HTTP relay bridge, default port `80`
- `https://relay.example.org`: HTTPS relay bridge, default port `443`
- `ws://relay.example.org`: WebSocket relay bridge, default port `80`
- `wss://relay.example.org`: secure WebSocket relay bridge, default port `443`

For reverse-proxy deployments, prefer `https://relay.example.org` or `wss://relay.example.org` as the advertised endpoint. The relay can listen on an internal HTTP port while nginx, Caddy, Nginx Proxy Manager, or Cloudflare terminates TLS.

## Advertisement And Capability Discovery

Every relay should answer:

```json
{ "type": "info" }
```

The response advertises:

- relay identity: `relayName`, `kind`, `softwareVersion`, and `operatorNote`
- federation: `federation.mode`, `federation.name`, `federation.description`
- transports: `transport`, `tlsEnabled`, and advertised endpoint-derived TLS posture
- timing policy: `temporalBucketSeconds` or `temporalBucketScheduleSeconds`
- attachment policy: enabled state, TTLs, and storage backend
- group policy: group creation and advertised group security model
- coordinator state: configured coordinator endpoints and reported relay count
- open discovery: DHT node state, PEX limit, endpoint policy, and cache limits

Clients should display this data before a user selects a relay. Relays should set `--advertised-endpoint` whenever the public URL differs from the local listen socket.

## Forwarding Protocol

Forwarding is triggered by a request that contains `destinationRelay`.

```json
{
  "type": "deliver",
  "deliver": {
    "inboxId": "recipient-routing-token",
    "routingToken": "recipient-routing-token",
    "destinationRelay": {
      "host": "relay-b.example.org",
      "port": 443,
      "useTLS": true,
      "transport": "http"
    },
    "envelope": { "ciphertext": "..." }
  }
}
```

The same routing rule is used by `deliverGroupMessage`. The first relay evaluates local federation policy, probes or uses directory state for the destination, then forwards the original sealed payload to the destination relay. Client relay passwords are never forwarded. If `federationForwardingAuthToken` is configured, relay-to-relay forwarding uses that dedicated token.

Forwarding fails closed when:

- the local mode is `solo`
- the destination endpoint is malformed
- the destination mode differs from the local federation mode
- the federation names do not match when a name is configured
- the destination kind is not acceptable for the mode
- manual allow-list, curated allow-list, coordinator quorum, signed snapshot, or open public-endpoint checks fail

## Runtime Configuration

The macOS relay app can add or remove manual federation peers while the relay is running. The core relay server also supports locked runtime updates for federation allow-lists, coordinator endpoints, curated policy, open DHT settings, private endpoint policy, and PEX limits.

Runtime updates are applied to future requests. In-flight requests keep their already-captured routing decision. This avoids half-mutated forwarding behavior while still allowing operators to change peer lists without restarting the relay.

## Manual Federation

Manual federation is an explicit node list. It does not use coordinators, signed directories, DHT records, or PEX.

Relay A:

```bash
NoctweaveRelayServer \
  --host 0.0.0.0 \
  --port 9339 \
  --http-port 9340 \
  --relay-kind standard \
  --transport http \
  --advertised-endpoint https://relay-a.example.org \
  --federation-mode manual \
  --federation-name private-mesh \
  --federation-allow https://relay-b.example.org
```

Relay B:

```bash
NoctweaveRelayServer \
  --host 0.0.0.0 \
  --port 9339 \
  --http-port 9340 \
  --relay-kind standard \
  --transport http \
  --advertised-endpoint https://relay-b.example.org \
  --federation-mode manual \
  --federation-name private-mesh \
  --federation-allow https://relay-a.example.org
```

Operational rules:

- Add the public advertised endpoint, not the internal LAN address behind a proxy.
- Keep the same `federation-name` on every node.
- Use `standard` relay kind for message-carrying peers.
- Start with an empty list if needed; forwarding will fail closed until peers are added.

## Curated Federation

Curated federation is a governed network. It combines static membership with coordinator health state.

Coordinator:

```bash
NoctweaveRelayServer \
  --host 0.0.0.0 \
  --port 9339 \
  --http-port 9340 \
  --relay-kind coordinator \
  --transport http \
  --advertised-endpoint https://coord.example.org \
  --federation-mode curated \
  --federation-name trusted-net \
  --coordinator-registration-token "$REGISTRATION_TOKEN" \
  --data-dir /var/lib/noctweave-coordinator
```

Standard relay:

```bash
NoctweaveRelayServer \
  --host 0.0.0.0 \
  --port 9339 \
  --http-port 9340 \
  --relay-kind standard \
  --transport http \
  --advertised-endpoint https://relay-a.example.org \
  --federation-mode curated \
  --federation-name trusted-net \
  --federation-allow https://relay-b.example.org \
  --federation-coordinator https://coord.example.org \
  --coordinator-registration-token "$REGISTRATION_TOKEN" \
  --curated-strict-policy true \
  --curated-coordinator-quorum 1 \
  --curated-require-signed-directory true
```

Strict policy requires:

1. Destination endpoint is in the allow-list.
2. Enough coordinators report the destination as healthy.
3. Directory data is not older than `coordinatorDirectoryMaxStalenessSeconds`.
4. Signed directory snapshots verify when signing is required.
5. Destination relay reports `curated`, matching federation name, and compatible relay kind.

Coordinator nodes organize relay membership and health. They do not need to carry user messages.

## Federation Source Files

The macOS relay app can fetch federation configuration from HTTPS JSON. Source files are useful when an operator wants a reviewable artifact.

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

Use HTTPS. Keep signing keys and registration tokens out of public source files. Put secrets in app settings, environment variables, a secrets manager, or deployment orchestration.

## Open Federation

Open federation is public discovery. It has no allow-list. DHT and PEX are valid only in `open` mode.

Recommended open relay:

```bash
NoctweaveRelayServer \
  --host 0.0.0.0 \
  --port 9339 \
  --http-port 9340 \
  --relay-kind standard \
  --transport http \
  --advertised-endpoint https://relay.example.org \
  --federation-mode open \
  --federation-name public-open-net \
  --open-federation-dht-node true \
  --relay-peer-exchange-limit 12
```

Open discovery uses short-lived ML-DSA-signed relay advertisements. Records are accepted only when namespace, federation name, relay identity digest, signature, lifetime, endpoint transport, public endpoint policy, and cache limits all validate.

For local test networks only:

```bash
--allow-private-federation-endpoints true
```

Do not enable private endpoints on public open relays. It can turn open federation traffic into a probe against localhost or private networks.

## Open DHT And PEX

Relay-native DHT routes:

```json
{
  "type": "publishOpenFederationDHTRecord",
  "publishOpenFederationDHTRecord": {
    "namespace": "noctyra-open-v1:<sha256-federation-name>",
    "record": { "..." : "signed OpenFederationDHTRecord" }
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

PEX is a bounded list of known open peers returned through `info`. PEX is a hint, not authority. Clients and relays must still validate the destination relay's `info` response before forwarding.

## Coordinator Requests

Relays register with coordinators using:

```json
{
  "type": "registerFederationNode",
  "authToken": "registration-token-if-required",
  "registerFederationNode": {
    "endpoint": { "host": "relay-a.example.org", "port": 443, "useTLS": true, "transport": "http" },
    "ttlSeconds": 120,
    "relayInfo": { "..." : "relayInfo from info" }
  }
}
```

Clients or relays query coordinator directories with:

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

Responses include `federationNodes` and may include `federationSnapshot`. Signed snapshots use ML-DSA-65. Consumers should reject a required snapshot when the signature key is absent or verification fails.

## Client Behavior

A client should:

- fetch `info` before adding a relay
- show relay name, TLS state, transport, mode, federation name, bucket policy, and attachment policy
- reject or warn about non-TLS public endpoints
- preserve the user-selected relay per identity
- use `destinationRelay` only when the contact or group is homed on another relay
- retry normal network failures, but not policy failures

For setup UX, manual and curated federation should be presented as operator-managed networks. Open federation should be presented as public discovery with metadata and trust tradeoffs.

## Troubleshooting

Use these checks before debugging client crypto:

1. Health:

```bash
curl -s https://relay.example.org/health
```

2. Relay info:

```bash
curl -s https://relay.example.org/relay \
  -H 'content-type: application/json' \
  -d '{"type":"info"}'
```

3. Verify both relays advertise the same `federation.mode` and `federation.name`.
4. In manual mode, verify each relay lists the other's public advertised endpoint.
5. In curated mode, verify coordinator directory freshness and quorum.
6. In open mode, verify DHT/PEX is enabled only on open relays and endpoints are public TLS endpoints.
7. Confirm the relay behind a reverse proxy advertises the external URL, not `127.0.0.1` or a Docker bridge address.

Common failures:

- `Solo federation disabled`: local relay is `solo`.
- `destination relay is not in the node list`: manual peer is missing.
- `coordinator quorum`: curated coordinator did not report enough healthy nodes.
- `signed directory`: coordinator snapshot key is missing or invalid.
- `non-public endpoint`: open federation endpoint is loopback, LAN, or otherwise private.
- `mode mismatch`: one side is manual/curated/open and the other reports a different mode.

## Security Rules

- Do not forward client passwords to another relay.
- Use a dedicated inter-relay forwarding token when relay authentication is required.
- Keep coordinator registration tokens secret.
- Keep coordinator signing keys stable and backed up.
- Do not publish private endpoints in open federation.
- Use TLS or a trusted reverse proxy for public endpoints.
- Prefer short coordinator heartbeat intervals for active networks and stricter staleness windows for curated networks.
- Treat DHT and PEX records as discovery hints only; always validate the destination relay before forwarding.
