# Noctweave App-Neutral Relay Modules v1

Status: provisional and implemented in the shared Swift relay core and the
Linux relay package. These modules are application-neutral relay primitives;
they do not define chat, group, voice, or UI semantics.

## Common rules

The modules use the exact Noctweave relay envelope:
`requestID`, `module`, `version`, `method`, `body`, and optional `authToken`.
The module identifiers and versions are:

| Module | Version | Relay role | Operations |
| --- | ---: | --- | --- |
| `nw.realtime-route` | 1 | standard | `create`, `append`, `subscribe`, `sync`, `unsubscribe` |
| `nw.shared-log` | 1 | standard | `create`, `append`, `sync` |
| `nw.ephemeral-presence` | 1 | standard | `acquire`, `renew-lease`, `release`, `list` |
| `nw.media-blobs` | 1 | standard, with attachments enabled | `create`, `upload`, `fetch`, `release` |

Same-relay contact discovery is intentionally specified separately as the
default-off experimental `nw.pairing-lobby@1` module. It depends on realtime
routes but is not a fifth general collaboration store. See
[`pairing_lobby_v1.md`](pairing_lobby_v1.md).

All four modules require the relay's confidential-transport gate. They are
not available on `passthrough` or `host` topology roles. The relay validates
capability proofs, structural bounds, cursors, idempotency, and expiry; it
does not decrypt application payloads. Payload bytes are opaque ciphertext by
protocol contract. Operators can still observe transport metadata such as
source metadata, operation timing, record sizes, UUIDs, and request frequency.

Capabilities are 32-byte non-zero bearer values. They must be generated with
cryptographic randomness, conveyed only through the authenticated application
flow that needs them, and never logged, published in discovery, or placed in
operator diagnostics. Route, shared-log, presence, and media authorities are
domain-separated when reduced to relay state. A capability is not an identity,
account, authorization directory entry, or federation-wide token.

All persisted bearer authorities, including realtime subscription
capabilities, are reduced to domain-separated SHA-256 digests before they are
used as runtime or snapshot keys. The relay returns the generated subscription
capability once and accepts it for `sync` or `unsubscribe`, but does not retain
the raw bearer value in durable state.

The configured legacy temporal-bucket schedule does not apply to these
modules. Realtime records, shared-log records, presence leases, and media blob
chunks are accepted immediately; their own retention and expiry rules apply.
This is intentional for low-latency application features and exposes timing
metadata. It does not change the bucketed behavior of `nw.blobs@1`.

## `nw.realtime-route@1`

Realtime routes are short-lived ordered opaque logs for low-latency signaling
or application events. A route is created with:

```text
routeCapability, appendCapability, readCapability, expiresAt
```

`append` accepts `routeCapability`, `appendCapability`, `recordID`, and opaque
`payload`. `subscribe` accepts the route and read capabilities plus an
`afterSequence` cursor. `sync` accepts the route and subscription capabilities,
an `afterSequence`, and `maxRecords`. `unsubscribe` accepts the route and
subscription capabilities. Sync returns ordered opaque records with
`nextSequence`, `highWatermark`, `retentionFloor`, and `hasMore`.
`create` returns the three route capabilities and `expiresAt`; `append`
returns `sequence` and `recordID`; and `subscribe` returns a generated
`subscriptionCapability`, the route capability, `nextSequence`, and
`expiresAt`.

The implementation bounds a payload at 512 KiB, a sync page at 256 records,
and a route lifetime at 86,400 seconds. A route retains at most 4,096 records.
The capability registry reports `maxRecordBytes`, `maxPage`, `maxRecords`,
`maxLifetimeSeconds`, and `immediate: 1`.

Routes and their ordered records are included in the durable relay snapshot
when disk persistence is enabled. `--memory-only` makes them process-local.
Expiry removes them; no temporal bucket is inserted into the append or sync
path. Sync is cursor-based and does not acknowledge or delete records.

## `nw.shared-log@1`

Shared logs are durable, ordered opaque logs for application history that is
not a pairwise inbox. `create` accepts `logCapability`, `appendCapability`,
`readCapability`, `retentionSeconds`, and `maxRecords`. `append` accepts the
log and append capabilities, a UUID `recordID`, and opaque `payload`. `sync`
accepts the log and read capabilities, `afterSequence`, and `maxRecords`.
`create` returns the three log capabilities and `retentionSeconds`; `append`
returns `sequence` and `recordID`; and `sync` returns the common opaque sync
batch.

The default retention is 2,592,000 seconds (30 days); accepted retention is
60 through 2,592,000 seconds. Payloads are limited to 512 KiB, sync pages to
256 records, and a log to 100,000 records. The capability registry reports
`maxRecordBytes`, `maxPage`, `maxRecords`, and `maxRetentionSeconds`.

Records are pruned by the configured per-log retention interval and bounded
record count. Logs and records are included in the durable relay snapshot;
memory-only operation loses them at process exit. There is no delete operation
in v1.

## `nw.ephemeral-presence@1`

Presence is a lease table, not a history log. `acquire` and `renew-lease`
accept `scope`, `scopeCapability`, `leaseID`, `leaseCapability`, opaque
`payload`, and `ttlSeconds`. `release` accepts the scope and lease authority;
`list` accepts the scope and scope capability. The response contains only the
lease ID, opaque payload, and expiry time.

The scope is at most 64 bytes, the lease ID is 16 non-zero bytes, payloads are
at most 16 KiB, and a lease lasts from 5 to 120 seconds. The capability
registry reports `maxPayloadBytes`, `minLeaseSeconds`, and `maxLeaseSeconds`.
Expired leases are pruned. Presence is intentionally process-local and is not
written to the durable relay snapshot, including when other modules use disk
persistence.

The relay does not know whether a presence payload represents a user, member,
voice participant, or any other application object. Applications that require
confidential presence must encrypt the payload before `acquire` or `renew`.

## `nw.media-blobs@1`

Media blobs provide a bounded, capability-authorized encrypted-chunk store.
They are separate from the legacy `nw.blobs@1` attachment API. `create`
accepts a UUID `blobID`, `blobCapability`, `chunkCount`, and `ttlSeconds`.
`upload` accepts the blob authority, `chunkIndex`, opaque `payload`, and a
32-byte `idempotencyKey`. `fetch` accepts the blob authority and chunk index.
`release` accepts the blob authority and returns an empty success body.
The default `ttlSeconds` is 86,400 (one day). `create` returns the blob ID,
capability, chunk count, and `expiresAt`; `upload` and `fetch` return the blob
ID, chunk index, and opaque payload.

The implementation limits each chunk to 512 KiB, a blob to 256 chunks and
32 MiB total, and retention to 60 through 604,800 seconds (seven days).
`chunkCount` must be at least one; each upload index must be below it. Exact
retries with the same idempotency key and payload return the original chunk;
conflicting reuse is rejected. The capability registry reports
`maxChunkBytes`, `maxChunks`, `maxBlobBytes`, `minRetentionSeconds`,
`maxRetentionSeconds`, and `requiresCapability: 1`.

Blob metadata and encrypted chunks are included in the durable relay snapshot
when persistence is enabled. Expiry and explicit `release` remove the blob;
memory-only operation loses it at process exit. The relay never receives the
plaintext, content key, filename, or media metadata unless an application
chooses to put such data into opaque ciphertext incorrectly.

## Legacy `nw.blobs@1`

`nw.blobs@1` remains a separate provisional module with `upload` and `fetch`.
It is the existing attachment pipeline, with its own attachment UUID/chunk
coordinates, configured attachment TTL, optional SQLite/IPFS backend, and
temporal-bucket handling. It must not be treated as an alias for
`nw.media-blobs@1`, and capability negotiation must select the exact module
and version requested by the application.

## Platform parity and verification

The module models, envelope dispatch, capability registry, and store APIs are
implemented in the shared `NoctweaveCore` path used by the public Swift relay
stack. The Linux relay package build passed and its relay suite reported 104
passing tests; the shared core build and focused realtime suite also passed.
This verifies protocol/core and Linux package parity. A separate macOS GUI
relay archive or runtime interoperability run was not part of this
documentation update, so macOS GUI parity is not claimed beyond its shared
core dependency.
