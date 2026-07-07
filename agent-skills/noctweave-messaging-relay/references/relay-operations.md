# Noctweave Relay Operations Reference

Use this reference when an agent must run, configure, verify, or troubleshoot a Noctweave relay.

## Build + Run

```sh
swift build --package-path "Noctweave_Relay_Server"
"Noctweave_Relay_Server/.build/debug/NoctweaveRelayServer" \
  --host 0.0.0.0 \
  --port 9339 \
  --http-port 9340 \
  --data-dir /tmp/noctyra-relay
```

Docker:

```sh
docker build -t noctyra-relay "Noctweave_Relay_Server"
docker run --rm -p 9339:9339 -p 9340:9340 -v noctyra-data:/data noctyra-relay
```

## Endpoint Modes

- Raw TCP: one JSON request line, one response line.
- HTTP: `POST /relay`.
- WebSocket: connect to `/relay`, send one JSON frame, receive one JSON frame.
- HTTPS/WSS usually come from a reverse proxy such as Caddy, nginx, or Cloudflare Tunnel.

For reverse proxy deployments, point clients at the public URL, for example `https://relay.example.org/relay` or `wss://relay.example.org/relay`. Do not add a port unless the public URL requires it.

## Diagnostics

```sh
curl -s http://127.0.0.1:9340/health
swift run --package-path NoctweaveCore NoctyraCLI health --relay http://127.0.0.1:9340
swift run --package-path NoctweaveCore NoctyraCLI info --relay http://127.0.0.1:9340
```

Relay `info` should advertise relay name, software version, transport, TLS status, federation mode, temporal bucket policy, attachment TTLs, attachment storage backend, group creation policy, wake policy, and optional federation capabilities.

## Storage + Attachments

Default persistent relay storage is SQLite under the configured data directory. `--memory-only` is for ephemeral testing. Attachment chunks are encrypted by clients before upload and may expire by relay TTL. IPFS offload is for relay storage pressure, not anonymity or cryptographic deletion.

## Federation

- `solo`: local-only relay, no forwarding.
- `manual`: operator-managed peer list.
- `curated`: allow-listed federation with coordinator policy and health.
- `open`: public discovery mode; DHT/PEX belongs here only.

Manual and curated relays should fail closed when the destination relay is not listed or policy-compatible. Never mix curated and open networks implicitly.

## Security Hygiene

- Run as an unprivileged user.
- Put public deployments behind TLS or a TLS reverse proxy.
- Keep relay passwords and federation tokens out of logs.
- Do not log plaintext payloads, decrypted keys, auth tokens, or contact payload secrets.
- Back up the SQLite database only when operator policy requires preserving queued encrypted data.
