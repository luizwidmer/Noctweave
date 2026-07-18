# Optional Wake and Opaque-Route Prefetch

Status: implemented experimental `nw.wake@1` profile; never required for
Noctweave Core conformance or message availability.

Noctweave wake is optional background synchronization over independently
authorized opaque receive routes. It is not a notification service and is not
part of contact discovery. The relay sees only a random route identifier,
bounded synchronization requests, and fixed-bucket encrypted packets.

## Scheduling

A relay may advertise `wakeSupport` with one of two modes:

- `pullOnly` schedules bounded authenticated route synchronization.
- `longPoll` permits a bounded wait inside the same synchronization operation.

The advertisement also supplies minimum and maximum intervals, a jitter bound,
and an optional long-poll timeout. Values are normalized when constructed and
the current wire decoder rejects unknown fields or noncanonical values.

Each local receive route has a freshly random 32-byte `routeJitterSeed`. The
seed never leaves local storage. `DecentralizedWakePlanner` combines that seed
with the opaque `routeID`, relay identifier, minute bucket, and bounded failure
step to produce deterministic local jitter. Separate routes therefore do not
share scheduling material. A failure on one route does not delay a healthy
route, and duplicate scheduling entries for the same route are collapsed.

`DecentralizedPrefetchExecutionPlanner` bounds routes per cycle, packets per
route, and total packets per cycle. Long-poll operation remains subject to the
same aggregate work limit.

## Prefetch Flow

1. Synchronize one opaque route after its last durably committed cursor.
2. Accept only packets whose embedded route matches the requested `routeID`.
3. Canonically encode each `OpaqueRouteReceivedPacketV2` without opening its
   encrypted frame.
4. Store the page as one `DecentralizedPrefetchBatch`, protected by a separate
   32-byte local storage key.
5. In foreground processing, verify each canonical packet envelope, validate
   the route revision, reassemble packet fragments, decrypt the route payload,
   and durably apply the resulting events.
6. Commit `deferredCommitCursor` only after every packet in the staged page has
   completed that processing sequence.
7. Remove the encrypted local batch after the cursor commit succeeds.

A crash before step 6 leaves the relay cursor unchanged, so the page remains
recoverable. Repeated packets are handled by the opaque-route packet and event
idempotency layers. Prefetch never copies a live ratchet or route payload key
into the staged records.

## Current Stored Schema

`DecentralizedPrefetchRecord` contains exactly:

```text
version
envelopeID
routeID
routeRevision
stagedAt
sealedPacketEnvelope
```

`DecentralizedPrefetchBatch` contains exactly:

```text
version
routeID
relayIdentifier
records
fetchedAfter
deferredCommitCursor
highWatermark
retentionFloor
hasMore
stagedAt
```

Both decoders reject missing, extra, malformed, noncanonical, cross-route, or
duplicate packet state. The stored file is an authenticated encrypted envelope;
the route identifier, relay label, cursors, packet metadata, and ciphertext are
not visible in the file's outer JSON.

## Security Boundary

- Wake policy is scheduling metadata only. It grants no cryptographic power.
- The route-local jitter seed stays local and is unrelated across routes.
- Relays never receive plaintext through wake or prefetch.
- Prefetch stages ciphertext only and does not need route decryption material.
- Cursor advancement is deferred until verified durable processing.
- Local staging uses authenticated encryption, atomic file replacement,
  restrictive filesystem permissions, size limits, and best-effort overwrite
  before removal.
- Missing relay policy falls back to bounded pull-only scheduling.

## Platform Limits

Operating systems may suspend background work. Closed-app instant delivery is
therefore not guaranteed. Long polling consumes relay connections and remains
operator-configurable. No external push provider is required for protocol
correctness.

## Verification

Focused tests cover strict policy decoding, deterministic route-scoped jitter,
route deduplication, independent failure backoff, execution limits, real
opaque-route synchronization, ciphertext-only staging, deferred cursor state,
cross-route rejection, corrupt envelope rejection, encrypted local persistence,
wrong-key failure, and relay-info round trips.
