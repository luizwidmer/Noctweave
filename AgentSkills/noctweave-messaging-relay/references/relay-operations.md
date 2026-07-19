# Noctweave relay operations reference

## Build and run

```sh
swift build --package-path NoctweaveRelayServer
"NoctweaveRelayServer/.build/debug/NoctweaveRelayServer" \
  --host 0.0.0.0 --port 9339 --http-port 9340 \
  --data-dir /tmp/noctweave-relay
```

```sh
docker build -t noctweave-relay NoctweaveRelayServer
docker run --rm -p 9339:9339 -p 9340:9340 \
  -v noctweave-data:/data noctweave-relay
```

## Transport

- Raw TCP: one exact JSON request line and one correlated response line.
- HTTP: `POST /relay`.
- WebSocket: connect to `/relay`, send one JSON request frame, receive one
  correlated response frame.
- HTTPS/WSS normally terminate at an operator-controlled reverse proxy.

The supported protocol modules are `nw.core@2`, `nw.opaque-route@2`,
`nw.rendezvous-transport@2`, `nw.blobs@1`, and `nw.federation@1`. There are no
identity, inbox, account, group-plaintext, or legacy endpoints.

When explicitly enabled in open mode, the relay also advertises experimental
`nw.open-discovery@1`; its discovery records never authorize message routes.

## Diagnostics

```sh
swift run --package-path NoctweaveCore NoctweaveCLI health --relay http://127.0.0.1:9340
swift run --package-path NoctweaveCore NoctweaveCLI info --relay http://127.0.0.1:9340
```

Both commands use `POST /relay`. Relay info reports the exact modules, limits,
transport, storage posture, and federation mode; it does not claim message
delivery, group authority, or user identity services.

## Opaque-route storage

SQLite is the default durable store. `--memory-only` is for ephemeral tests.
Route records are ordered and digest-chained. The receiver commits an opaque
cursor only after durable processing. Retention, quota, and padding are coarse
route policy buckets. Send, read, renew, and teardown capabilities are distinct.
Pairwise and group ciphertext use the same opaque-route module; the relay never
learns which application protocol produced a packet.

Encrypted blob storage and optional IPFS offload reduce relay disk pressure;
they do not provide anonymity or cryptographic deletion.

## Federation

- `solo`: no federation discovery or coordination.
- `manual`: explicit operator-reviewed relay descriptors.
- `curated`: allow-listed coordinator policy and directory evidence.
- `open`: bounded signed relay discovery and public-endpoint safeguards.

Federation is an operator-plane directory and coordination mechanism, not a
message-forwarding path. A client reads the destination relay from its peer's
relationship-encrypted route set and appends ciphertext directly to that opaque
route. Never infer or silently cross a federation trust domain.

## Security hygiene

- Run unprivileged and put public endpoints behind TLS.
- Keep relay auth and coordinator-registration tokens out of logs.
- Never log plaintext payloads, route secrets, contact material, or state keys.
- Treat backups as copies of queued ciphertext and capability-protected state.
