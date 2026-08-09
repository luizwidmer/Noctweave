# Coturn Call Traversal

Noctweave uses [coturn](https://github.com/coturn/coturn) as an optional,
standards-compliant STUN/TURN service for call connectivity. The Noctweave
relay remains the authenticated control plane: it advertises canonical ICE
URLs and issues short-lived TURN REST credentials through
`nw.ice-service@1`. coturn carries encrypted media packets but never receives
Noctweave relationship keys, call roots, or plaintext.

## Components

```text
client -- nw.core info / nw.ice-service acquire --> Noctweave relay
client -- STUN binding or TURN allocation ----------> coturn
client == application-encrypted media frames ======> peer or coturn
```

The relay and coturn share one operator secret. That secret is never
advertised. HMAC-SHA1 is used only for coturn's time-limited REST credential
convention; Noctweave identity, session, signaling, and media cryptography do
not use SHA-1.

## Docker deployment

```sh
cd NoctweaveRelayServer
cp .env.coturn.example .env
# Set TURN_DOMAIN, TURN_EXTERNAL_IP, NOCTWEAVE_ADMIN_TOKEN, and a random
# NOCTWEAVE_TURN_SHARED_SECRET in .env.
docker compose --env-file .env -f docker-compose.coturn.yml up -d --build
```

Publish TCP and UDP port 3478 plus the configured UDP allocation range
(49160-49200 by default). Set `TURN_EXTERNAL_IP` to the host's public address
when coturn runs behind NAT. A normal HTTP reverse proxy cannot forward TURN;
use direct ports or a TURN-aware layer-4 proxy. The supplied profile disables
coturn TLS/DTLS because Noctweave media already has mandatory application-layer
encryption. Operators may deploy `turns:` separately when transport-policy or
censorship-resistance requirements justify it.

## External coturn

Configure coturn with `use-auth-secret`, `static-auth-secret`, and the same
realm and secret supplied to the relay:

```sh
export NOCTWEAVE_ICE_URLS='stun:turn.example.org:3478,turn:turn.example.org:3478?transport=udp,turn:turn.example.org:3478?transport=tcp'
export NOCTWEAVE_TURN_REALM='turn.example.org'
export NOCTWEAVE_TURN_SHARED_SECRET="$(openssl rand -hex 32)"
export NOCTWEAVE_TURN_CREDENTIAL_TTL_SECONDS=600
```

The macOS relay app advertises and authorizes an externally managed coturn
instance; it does not run coturn inside the application process.

## Client behavior

1. Fetch authenticated relay info.
2. Reject an invalid or unsupported ICE descriptor as a whole.
3. Use credential-free STUN URLs directly.
4. For `turn-rest`, request credentials over TLS, trusted-proxy TLS, or literal
   loopback. Supply the relay access password when required.
5. Keep credentials in memory and refresh only when expiry approaches.
6. If discovery or allocation fails, continue messaging and report that calls
   are limited to directly reachable peers. Never downgrade media encryption.

TURN improves reachability and hides each peer's address from the other peer,
but the coturn operator sees both network addresses, allocation timing, and
traffic volume. It does not provide anonymity or traffic-flow confidentiality.

## Rotation and operations

Rotate the shared secret by briefly accepting both old and new secrets at the
TURN layer, switching the relay issuer, waiting longer than the maximum
credential lifetime, then removing the old secret. Keep the relay credential
lifetime between 60 and 3600 seconds. Apply allocation quotas and monitor port
range exhaustion; never log issued credentials or packet payloads.
