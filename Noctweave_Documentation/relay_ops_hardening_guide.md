# Noctweave Relay Operator Hardening Guide

Last updated: June 24, 2026

This guide is for operators running a Noctweave relay on Linux or Docker. It focuses on reducing operational metadata, limiting abuse paths, and avoiding configuration drift. It does not make the relay anonymous: relays still observe source IPs, request timing, chosen inboxes, ciphertext sizes, and federation topology hints.

## Baseline Deployment

Run the relay behind a TLS reverse proxy unless you are testing on an isolated LAN. Prefer HTTPS/WSS for client traffic and relay-to-relay federation.

Recommended public layout:

```bash
Client -> https://relay.example.org/relay -> reverse proxy -> relay HTTP bridge
```

Expose only the public proxy ports (`443`, optionally `80` for ACME). Keep the raw relay TCP port and HTTP bridge port firewalled to localhost or the reverse proxy network.

Use the Docker image as the default Linux deployment path. It runs as an unprivileged user and includes runtime `liboqs` for ML-DSA actor-proof and coordinator-signature verification.

## TLS And Reverse Proxy

Use one of these patterns:

- Caddy/Let's Encrypt stack from `Noctweave_Relay_Server/docker-compose.letsencrypt.yml`.
- Nginx Proxy Manager or Cloudflare Tunnel terminating TLS and forwarding to `POST /relay`.
- Internal-only TCP for development only.

When TLS is terminated by a proxy, advertise the public URL:

```bash
--http-port 9340 \
--advertised-endpoint https://relay.example.org:443 \
--advertise-tls true \
--transport http
```

Do not advertise `http://`, private IPs, loopback, or LAN addresses for open federation unless the relay is intentionally private and `--allow-private-federation-endpoints true` is set for an isolated test network.

## Firewall Rules

Minimum public exposure:

- Allow inbound `443/tcp` to the reverse proxy.
- Allow inbound `80/tcp` only if ACME HTTP-01 challenges need it.
- Block direct inbound access to relay raw TCP (`9339`) and bridge (`9340`) from the public internet.
- Allow outbound HTTPS/WSS to federation peers and coordinators.

For curated federation, restrict outbound relay-to-relay traffic to allow-listed relays where possible.

## Secrets

Prefer environment variables over command-line flags:

- `NOCTYRA_RELAY_PASSWORD`
- `NOCTYRA_COORDINATOR_REGISTRATION_TOKEN`
- `NOCTYRA_FEDERATION_FORWARDING_TOKEN`
- `NOCTYRA_COORDINATOR_SIGNING_KEY`

Keep relay passwords and federation forwarding tokens distinct. The relay already avoids forwarding inbound client auth tokens to other relays; keep that isolation operationally true by not reusing the same secret everywhere.

Coordinator signing keys are trust roots. Back them up offline. If a coordinator key is lost or rotated unexpectedly, clients and relays that pinned the previous public key should treat the directory as a new trust root.

## Storage

Use a dedicated data volume with restrictive permissions:

```bash
docker run --rm \
  -p 127.0.0.1:9340:9340 \
  -v noctyra-relay-data:/data \
  noctyra-relay
```

Persist `/data` for normal operation. Use `--memory-only` only for throwaway relays or development because queued messages, attachments, and coordinator keys disappear on restart.

Set attachment retention low enough for your budget and threat model:

```bash
--attachment-default-ttl-seconds 1800 \
--attachment-max-ttl-seconds 7200
```

Use `--attachments-enabled false` for text-only relays.

For storage offload, the Linux relay can store encrypted attachment chunks in an IPFS-compatible backend while keeping only chunk metadata, CIDs, byte counts, digests, and expiry data in SQLite:

```bash
--attachment-storage ipfs \
--ipfs-api-endpoint http://127.0.0.1:5001 \
--ipfs-gateway-endpoint http://127.0.0.1:8080 \
--ipfs-timeout-seconds 10
```

This does not make attachment delivery anonymous. Clients still use the normal relay upload/fetch API, and the relay performs IPFS pin, fetch, digest verification, and best-effort unpin after TTL. Use a relay-controlled IPFS node or private IPFS cluster; public gateways and public DHT lookups can leak CID interest and should not be the privacy default.

## Federation Mode

Solo mode is safest operationally because it does not forward across other relays.

Curated federation should use:

```bash
--federation-mode curated \
--federation-allow relay-a.example.org:443,relay-b.example.org:443 \
--curated-strict-policy true \
--curated-require-signed-directory true \
--curated-coordinator-quorum 1
```

Manual federation should use `--federation-mode manual` with a short, explicit `--federation-allow` node list. Use it for small standard-relay meshes where operators directly exchange endpoint lists and do not want coordinator quorum, signed directory snapshots, DHT records, or peer exchange.

Open federation is more exposed. Keep `--allow-private-federation-endpoints false`, require TLS, use public advertised endpoints, and monitor peer churn.

## Open Federation And DHT

Open-federation DHT records are discovery hints, not authority. Enable DHT node mode only for open-federation relays that should participate in relay discovery. A relay should accept records only after signed-record validation, namespace matching, lifetime checks, TLS/public-routability checks, and host/total caps.

The current relay supports:

- HTTP gateway sidecar integration for BEP5/libp2p/custom discovery processes.
- Native relay-protocol DHT publish/list routes when DHT node mode is enabled.
- Bounded PEX-style traversal from `knownOpenPeers`.

Do not publish user identifiers, contact codes, inbox addresses, or message metadata to any public DHT. Only relay endpoint records belong in this path.

## Logs

Treat logs as sensitive metadata. Avoid logging:

- Inbox IDs
- contact codes
- full relay endpoints of clients
- message counters
- attachment IDs
- auth tokens

Keep logs short-lived. In Docker, prefer host log rotation:

```bash
docker run --log-opt max-size=10m --log-opt max-file=3 ...
```

If exposing logs to a monitoring system, scrub request bodies and authorization headers before export.

## Rate Limits And Capacity

Keep default bounds unless you have measured need:

```bash
--max-inbox 1000 \
--max-message-bytes 524288 \
--max-line-bytes 655360 \
--forwarding-timeout-seconds 8
```

Lower `--relay-peer-exchange-limit` if open-federation peer churn is high. Set it to `0` to disable peer hints.

## Upgrade Checklist

Before upgrading:

1. Back up `/data`, including coordinator signing keys.
2. Record the relay public endpoint and federation mode.
3. Verify the new image still includes `liboqs`.
4. Start the upgraded relay behind the proxy.
5. Run health checks on `/health` and client relay test connection.
6. For federation, verify `/info` advertises the expected relay name, mode, transport, TLS state, and coordinator metadata.

For release dependency review, use `dependency_sbom_and_release_policy.md`.

## Incident Response

If a relay token leaks:

1. Rotate `NOCTYRA_RELAY_PASSWORD`.
2. Rotate `NOCTYRA_FEDERATION_FORWARDING_TOKEN`.
3. Restart the relay and proxy.
4. Review logs for unexpected forwarding attempts.
5. Notify federation peers if a curated or coordinator token was involved.

If a coordinator signing key leaks, retire that coordinator identity and publish a new trust root through an out-of-band operator channel. Do not silently reuse the compromised key.
