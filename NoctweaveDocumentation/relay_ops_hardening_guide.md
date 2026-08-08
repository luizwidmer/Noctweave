# Noctweave Relay Operator Hardening Guide

Updated July 18, 2026 for the clean 1.0 relay.

The relay stores capability-protected ciphertext for direct client submission
and receiver synchronization. It is not anonymous infrastructure: an operator
or network observer can still see source addresses, timing, request frequency,
selected route capabilities, ciphertext sizes, retention, and federation
topology.

## Network boundary

Recommended public layout:

```text
client -> HTTPS/WSS reverse proxy -> POST or WebSocket /relay -> relay bridge
```

- expose `443/tcp` at the reverse proxy;
- expose `80/tcp` only when ACME HTTP-01 needs it;
- firewall raw TCP `9339` and bridge `9340` from direct public access where
  possible;
- bind operator port `9090` to loopback or a private management network;
- allow outbound federation directory and coordination calls only to the
  endpoints required by the selected trust mode.

Advertise the public explicit endpoint and TLS state. Do not publish loopback,
private, link-local, or ambiguous endpoints into public federation.

## Relay roles

Run exactly one current role per process:

- `standard`: expose only the messaging and operator surfaces actually used;
- `passthrough`: require relay authentication, an explicit public HTTPS allow
  list, strict request/response/time limits, and outbound firewall policy;
- `host`: require write authentication, persist `/data/net-host` with
  restrictive permissions, back up its signing key with its index and object
  files, and monitor object count, bytes, expiry, and disk pressure.

Passthrough and host roles require federation mode `solo`. Their `info`
manifests must not advertise opaque routes, rendezvous, blobs, federation,
open discovery, or experimental privacy modules.

A passthrough relay is not an open proxy or anonymity service. A host relay is
not a publisher, consensus participant, code executor, or plaintext processor.

## Exact protocol path

Only the exact modular relay envelope is accepted. Health and information are
`nw.core@2` requests through `/relay`; there is no GET compatibility endpoint.
Configure reverse proxies to reject oversized/slow bodies and preserve
WebSocket frame boundaries.

After deployment, verify:

1. `nw.core@2 health` through HTTPS;
2. `nw.core@2 info` advertises only enabled modules;
3. malformed/unknown fields are rejected;
4. request/response correlation survives HTTP and WebSocket proxying;
5. TLS validation and any configured pins work from a real client network.

## Secrets

Use separate random values for relay access, operator access, coordinator
registration, and coordinator signing. Prefer secret files or environment
injection over shell history.

Never log:

- relay/admin/coordinator-registration tokens;
- opaque route IDs or capability material;
- rendezvous capabilities or frame bodies;
- encrypted packet or attachment bytes;
- request bodies containing user-supplied ciphertext.

If a bearer route capability leaks, treat only that route as compromised:
create a fresh route, move the relationship through its signed rollover, and
tear down the old route. Do not invent a user/account revocation record.

## Storage

Run as an unprivileged user and mount `/data` with restrictive permissions.
Back up `relay_store.sqlite` and `operator-config.json` as one consistency unit.
Use `--memory-only` only for disposable testing.

Validate restart behavior for:

- route revision/idempotency state;
- ordered packet sequences and committed cursors;
- route expiry/teardown tombstones;
- rendezvous expiry and replay state;
- attachment metadata and optional external blobs;
- federation directory/DHT bounds.

Recovery must never resurrect an expired or torn-down route or report an
in-memory mutation that did not reach durable SQLite.

## Bounds and retention

Keep configured message/line limits, route quota buckets, attachment TTLs,
rendezvous expiry, federation record limits, and request timeouts as small as
the product permits. Validate integer conversion and disk-pressure behavior.

For the app-neutral modules, enforce the advertised capability registry at
the edge: 512 KiB record/chunk ceilings, 256-record pages, 86,400-second
realtime-route lifetimes, 100,000 shared-log records, 16 KiB presence payloads,
5-to-120-second presence leases, and 32 MiB media blobs with 256 chunks and
60-second-to-seven-day retention. Realtime routes and shared logs are not
temporal-bucketed; do not silently apply the normal attachment bucket policy
to them. Treat their timing as an explicit metadata tradeoff.

Route sync is non-destructive but not permanent: expiry and bounded quota are
the retention controls. The relay is not a history archive.

## Attachments and IPFS

Attachment plaintext and content keys must be encrypted client-side. If IPFS
offload is enabled:

- use an operator-controlled node or private cluster;
- restrict the API listener;
- verify returned size and digest;
- understand that unpinning is best effort, not cryptographic erasure;
- keep gateway/API timeouts and maximum fetch bytes bounded.

Disable `nw.blobs` when attachments are not needed.

`nw.media-blobs@1` is separate from `nw.blobs@1`. Enable it only when the
application needs its create/upload/fetch/release lifecycle, keep the 32-byte
blob capability confidential, and ensure every chunk is encrypted before it
reaches the relay. Its metadata and chunks are durable under SQLite-backed
operation and expire or release independently; it is not an IPFS anonymity
feature. Presence leases are the exception: they are process-local and never
enter the durable snapshot.

## Federation

Federation discovers and authenticates relay operators. Senders may append
directly to the destination endpoint from a relationship-encrypted route set,
or a standard home relay may make one authenticated
`nw.federation-forward@1` hop. The forwarded object is the unchanged opaque
append; relays do not receive relationship keys or message plaintext.

- `solo`: safest default; no federation discovery or coordination.
- `manual`: maintain explicit operator-reviewed relay descriptors and an allow
  list.
- `curated`: require matching trust domain, fresh coordinator evidence,
  configured quorum, and valid signatures where enabled.
- `open`: retain signed-record TTL, host quotas, query bounds, public endpoint
  validation, and peer-hint ceilings.

Federation requests may register or discover relays, validate endpoint
reachability, distribute signed namespace state, and carry bounded opaque
forwarding envelopes. Do not reuse client auth or route capabilities for
coordinator registration. There is no reusable federation-wide forwarding
token: each forwarded append retains its destination-scoped authorization.
Do not silently fall from curated/manual into open behavior. Treat coordinator
key replacement as a new trust-root decision.

## Operator console

Generate at least 32 random bytes for `NOCTWEAVE_ADMIN_TOKEN`. Keep the admin
listener private and protect remote access with SSH, VPN, or a separately
authenticated management proxy. Review persisted policy before restart.

The console must not expose secrets or edit listener/authentication primitives.
Close/lock the session when not in use.

## Optional privacy modules

Hidden retrieval, replicated XOR-PIR metadata, onion packets, mixnet schedules,
open DHT, and wake advertisements are experimental. Enable them only when the
deployment satisfies their assumptions. None alone establishes global
anonymity, cover traffic, independent PIR operators, or safe public discovery.

## Incident response

1. isolate the affected listener/storage role;
2. preserve bounded logs that contain no capability or ciphertext bodies;
3. rotate only the compromised operator/coordinator-registration secret or
   opaque route;
4. validate SQLite and external blob consistency;
5. re-run exact protocol and persistence tests;
6. publish changes to advertised federation trust only after verification.

There is no global Noctweave account to suspend. Abuse controls are route,
request, storage, network, and operator-policy controls.

## Release checklist

- clean Swift relay build and test suite;
- exact OpenAPI/schema drift check;
- immutable liboqs and Swift dependency pins;
- current native and CycloneDX SBOMs;
- non-root container and restrictive volume permissions;
- TLS/reverse-proxy integration test;
- backup/restore and disk-pressure exercise;
- attachment/IPFS failure exercise if enabled;
- federation-mode-specific directory/coordination test if federation is
  enabled;
- no unsupported module advertised.
