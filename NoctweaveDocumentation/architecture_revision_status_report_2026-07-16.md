# Architecture Revision Status Report

**Date:** July 16, 2026

**Branch:** `architecture-revision`

**Base:** `main` at `35be68e`

**Implementation commit:** `9ebece0`

**Status:** substantial implementation complete; integration and production
gates remain

This report is the durable handoff for the pre-1.0 architecture revision. It
summarizes what changed, which earlier assumptions were replaced, how the
active paths now behave, and what remains before Noctweave can call the
revision complete or production-audited.

The detailed target and status matrix remain in
[`noctweave_architecture_revision_v2.md`](noctweave_architecture_revision_v2.md).
The normative filter is
[`noctweave_identity_philosophy.md`](noctweave_identity_philosophy.md).
Raw comparison research remains in the ignored `OtherResources/` working
folder and is not part of the repository.

## Executive Summary

The revision keeps the useful engineering lessons from XMTP, Signal/Sesame,
Matrix, XMPP, SimpleX, Waku, Nostr, MLS, AT Protocol, and Briar without adopting
their account or identity assumptions.

Noctweave is now designed around **disposable identity generations**. A local
endpoint is an independently keyed protocol participant whose authority exists
only inside one generation. It is not a permanent device record attached to an
account. There is no global account identifier, recovery authority, provider
registry, or public endpoint graph. Identity continuity remains pairwise and
optional, while a true burn destroys old-generation reachability and state.

The largest functional changes are:

- a certified post-quantum direct-v4 path for one preferred endpoint;
- ordered mailbox synchronization with independent consumer cursors;
- typed immutable application events separated from security controls;
- crash-safe exact-ciphertext outboxes and protocol intent journals;
- authenticated, durable identity burn and inbox retirement;
- strict capability and ciphersuite negotiation bound into the direct
  transcript;
- bounded replay, dead-letter, compaction, and persistence semantics;
- a signed endpoint-aware group foundation, inert encrypted history transfer,
  and self-sync models that do not clone live authority; and
- capability honesty: unfinished or misleading paths are disabled or omitted
  from advertisements.

The branch is **not yet proven fully green**. JavaScript tests, desktop
type-checking, Swift syntax parsing, schema/vector parsing, SVG validation, and
diff hygiene pass. Full SwiftPM builds and test suites could not run in the
current sandbox because SwiftPM manifest evaluation invokes `sandbox-exec`,
which is denied. Those commands remain the first verification gate in a normal
development environment.

## Philosophy Correction

The architecture originally borrowed an `Inbox -> Identity -> Installation`
shape too literally. That suggested a stable account with authorizable and
revocable devices. Such a design conflicts with Noctweave's disposable,
ephemeral identities.

The corrected model is:

```text
Identity generation
├── generation-bounded identity authority
├── one or more independently keyed local endpoints
├── generation-bounded inboxes and route authority
├── generation-bounded self-sync state
└── pairwise relationships with optional continuity
```

The invariants are now explicit:

- An endpoint is not an account device and has no cross-generation identity.
- No provider or recovery key can resurrect or globally link a generation.
- Endpoint handles, certificate references, and future routes are
  relationship-scoped where practical.
- A completed burn retires all known old inbox routes and discards old private
  state; creating a new generation without remote teardown is accurately
  called abandonment, not burn completion.
- Continuity is disclosed only to selected relationships.
- Relays remain bounded ciphertext routers and must not learn plaintext social
  graphs.
- Opaque labels do not erase metadata. Relay-visible correlation and timing
  limits are documented rather than hidden behind naming.

Some source types still use the pre-correction word `Installation`. Those are
compatibility names for generation-scoped local endpoints. They do not create a
stable installation registry or device-recovery model.

## What Was Implemented

### 1. Identity generations and certified endpoints

Legacy profiles migrate idempotently to a generation record with one freshly
keyed local endpoint, a signed bounded endpoint-set manifest, relationship
shells, route-local mailbox state, and local self-sync state. The endpoint has
independent ML-DSA signing, ML-KEM agreement, and rotating signed-prekey
material.

Fresh contact offers expose a compact identity-signed manifest checkpoint and
one preferred certified endpoint, not the sender's full endpoint graph.
Direct-v4 derives relationship-scoped endpoint handles and certificate
references so the same endpoint does not expose one reusable public handle to
every contact.

Current active support remains deliberately limited to one preferred endpoint.
The manifest model can represent more entries, but default endpoint
capabilities truthfully advertise `maxActiveEndpoints: 1` until admission,
self-sync, fan-out, removal, and receipt aggregation are connected end to end.

### 2. Direct-v4 cryptographic profile

The Swift and JavaScript reference paths implement the exact profile:

```text
nw.direct-v4.ml-kem-768.ml-dsa-65.hkdf-sha256.hmac-sha256.aes-256-gcm
```

The pairwise relationship, endpoint certificates, endpoint signed prekeys,
required module versions and limits, suite identifier, logical event ID,
authenticated context, and envelope ID are transcript-bound. Missing modules,
version gaps, altered limits, suite tampering, expired bootstrap prekeys, and
legacy fallback fail closed. The signature now authenticates the delivery
envelope ID; there is no compatibility verifier that accepts an unsigned ID.

Signed-prekey expiry prevents new bootstrap sessions but does not silently kill
an already established endpoint-bound ratchet. Rotation republishes a fresh
endpoint-signed package while retaining only a small expiry-bounded set of old
private prekeys for in-flight offers.

### 3. Typed events and separate controls

The old closed message body mixed visible content with identity, session, and
resend controls. The new direct-v4 plaintext carries either a versioned typed
application event or a separately enumerated authenticated control frame.

Application events support bounded namespaced types, versions, parameters,
payloads, fallback text, visibility disposition, and encrypted relations.
Unknown visible application content can be retained and rendered through a
bounded fallback. Silent unknown content is retained without producing a chat
bubble. Unknown controls never mutate security state and enter a bounded
quarantine; malformed known controls fail before ratchet state commits.

Relationship history compacts old immutable events into a chained checkpoint
instead of silently evicting records or wedging permanently at capacity.

### 4. Ordered mailbox synchronization

The relay mailbox is now a bounded append-only ciphertext log with monotonic
relay-local sequence numbers. Each authorized route consumer has its own opaque
cursor. Synchronization returns ordered events, a next cursor, high watermark,
retention floor, and `hasMore` state.

A client commits a cursor only after verification, decryption, event storage,
ratchet storage, and receive metadata are durably committed. One consumer's
progress does not destructively consume another consumer's delivery state.
Long polling and streaming do not implicitly advance durable state.

Consumers use fresh route-local ML-DSA credentials. The first v2 consumer
binding permanently disables legacy inbox-authority fetch/ack access. Later
bindings require an active bound consumer sponsor, so an inbox authority alone
cannot silently add readers. The relay enforces bounded active and historical
consumer records, cursor retention, gap detection, and restart persistence.

Permanently hostile but structurally valid envelopes are recorded in a bounded
metadata-only dead-letter journal and skipped atomically, preventing one poison
envelope from causing permanent head-of-line denial of service. Local storage,
state corruption, or unavailable cryptography remain retryable and do not
advance the cursor.

### 5. Exact retry, intents, and identifiers

The architecture now distinguishes:

| Identifier | Meaning |
| --- | --- |
| `clientTransactionId` | One endpoint's local operation and retry identity. |
| `eventId` | One logical immutable event in an authenticated relationship scope. |
| `envelopeId` | One encrypted delivery copy to one route. |
| `relaySequence` | One position in a relay-local mailbox log. |

Direct send clones the ratchet, constructs the logical event, signs and
encrypts the exact envelope, then atomically persists the candidate ratchet,
event/local echo, ciphertext outbox, and intent before network submission.
Retry sends the same signed ciphertext and IDs; it does not re-encrypt or
advance the ratchet again.

Pending ciphertext and live intent records are capacity-bound together. They
receive backpressure rather than truncation. Exhausted or permanently rejected
delivery remains in an explicit action-required state, and manual rearming
changes retry bookkeeping only.

On receive, a bounded durable receipt binds relationship scope, logical event
ID, envelope ID, and canonical signed-envelope digest. A reused ID with
different bytes fails closed instead of being treated as a duplicate.

### 6. Burn, rotation, and retirement

Authority rotation and identity burn now have distinct semantics.

Rotation preserves the identity generation and selectively announces a new
continuity authority through an authenticated event. Burn creates an unrelated
generation, stages exact reset ciphertext only for selected contacts, registers
the new route, cuts over locally, retires every known old inbox route, and
removes old private state.

Each old-route retirement is pre-signed before key deletion and stored in a
bounded durable journal. The relay persists a non-resurrection tombstone,
rejects new delivery and consumer registration for the retired inbox, clears
mailbox/consumer/route-capability state, and treats exact retirement retry as
idempotent. Cleanup does not require retaining the old private key after
cutover.

The new local profile contains no general old-to-new link. Only explicitly
selected contacts receive the old-key-authenticated reset envelope, and each
relationship stays send-blocked until that exact staged envelope reaches the
contact's relay.

### 7. Relay durability and admission

In-process and Linux relay storage now share mailbox-v2 semantic tests and
normalized persistence behavior. Security-relevant updates use snapshot or
transaction rollback so failed persistence does not leave mutated memory ahead
of durable state.

The final relay rejects delivery to an unregistered inbox before allocating
mailbox storage. Group retries bind an immutable original-recipient set so an
exact retry remains a no-op after partial acknowledgement, while a payload,
kind, or recipient-set conflict fails closed.

Legacy fingerprint-based pairing, relay prekeys, groups, and destructive
acknowledgements are disabled by default behind the explicit deprecated
`nw.compat.legacy-fingerprint` operator profile. Direct-v4 never negotiates
that profile.

### 8. Opaque route-capability foundation

Both relays contain a hardened but deliberately inactive route-capability
foundation. Registration establishes a random relay-local scope. Route
mutation v3 binds that scope, a monotonic sequence, previous digest, mutation
digest, time, and actor proof. State, sequence, digest, and capability mapping
commit atomically. Stale, skipped, conflicting, and cross-relay mutation
requests fail closed, while an already-applied exact mutation remains
idempotently replayable.

Relays store only a digest of each 32-byte bearer and never log or expose the
raw capability through description/reflection. Strict decoding rejects
malformed bearers. Delivery by an unknown or revoked capability fails before
mailbox allocation, and inbox retirement purges the scope, cursor, and every
mapping.

This feature is default-off, inaccessible when disabled, and omitted from
capability advertisements. It is not used by contact offers or direct-v4. That
gate is intentional because the current design still lets a final relay
correlate every capability terminating at one inbox, has only test-scale route
capacity, lacks expiring route epochs and per-capability abuse policy, and has
no final padding/cover design. A bearer route requires confidential transport
except for literal loopback development.

### 9. Self-sync, history, and endpoint admission foundations

The profile persists a generation-scoped self-sync secret and progress model,
with bounded encrypted event seal/open and deterministic merge rules. The
endpoint-removal model rotates self-sync authority and journals unfinished
remote teardown. No transport currently publishes self-sync records.

The live profile-vault export was removed from JavaScript. A live
`IdentityProfile` remains an unsafe transfer object because it contains
generation/inbox authority, ratchets, routes, cursors, and revocation power.
No active API clones that state into another endpoint.

The endpoint-admission model is purpose-bound to one generation and requires
identity-authority authorization plus possession proofs for the new endpoint's
ML-DSA and ML-KEM keys. Its transport and complete lifecycle remain inactive.

Read-only history transfer is implemented as a local Swift packaging API. It
exports only inert application/receipt projections and safe metadata, encrypts
them under a fresh content key, wraps that key to the recipient endpoint with
ML-KEM, signs the authorization, and hides the metadata-bearing inner package
inside fixed-size outer padding buckets. Import is bounded, expiring,
transactional, and replay-protected. It grants no inbox access, endpoint
admission, future ratchet, group leaf, route authority, or continuity. No
managed service or default transport is introduced.

### 10. Groups and policy

The new signed-state foundation distinguishes contact-level group users,
endpoint-level group clients, and versioned crypto providers. It adds externally
pinned genesis trust, full key-package possession proofs, signed complete-state
commits, hierarchy-bounded roles and permissions, bounded Welcomes, and a
128-active-leaf cap for the current O(n) provider.

The current construction is explicitly named
`noctweave-pq-group-experimental-2`; it is not claimed to be RFC 9420 MLS. The
active relay-backed group workflow still uses the deprecated opt-in fingerprint
compatibility path. The endpoint-aware objects are not yet negotiated,
persisted, delivered, or resumed by active clients.

The legacy path was nevertheless hardened with authenticated envelope digests,
durable acknowledgement retry, invitation authorization, idempotent invite and
accept flows, deletion cleanup, and matching Core/Linux capacity policy.

### 11. Documentation, schemas, and conformance

The protocol spec, Core API guide, CLI guide, relay README, OpenAPI schema,
whitepaper, security requirements, roadmap, wire-format guide, architecture
diagrams, and group design now describe the revised boundaries. Shared
Swift/JavaScript vectors cover direct-v4 negotiation and envelope behavior;
mailbox/OpenAPI/vector fixtures exercise the new wire shapes and negative
cases.

Module catalogs no longer imply support. Default endpoints advertise only the
four modules wired into direct-v4, and relay `info` advertises only concrete
relay-terminated behavior. Experimental privacy features remain separately
gated and cannot be inferred from the existence of model types.

## What Was Replaced

| Earlier assumption or mechanism | Revision behavior |
| --- | --- |
| Stable inbox/account with authorizable devices | Disposable identity generation with generation-scoped independently keyed endpoints; no account or recovery registry. |
| Copying/exporting a live profile to another device | Forbidden; live JavaScript profile vault removed. Endpoint admission transfers only endpoint-local state after purpose-bound authorization. |
| One identity key/prekey/ratchet participant | Certified endpoint keys and endpoint-local prekeys/ratchets, currently one active preferred endpoint. |
| Globally reusable endpoint identity | Relationship-scoped endpoint handles and certificate references. |
| Destructive mailbox fetch plus message-ID acknowledgement | Ordered relay log plus independent route-consumer cursors committed after durable processing. |
| One envelope UUID representing send, event, copy, and ordering | Separate transaction, logical event, delivery envelope, and relay-sequence identifiers. |
| Closed `MessageBody` mixing chat content and security controls | Versioned typed application events plus separate fail-closed control frames. |
| Ad hoc pending deliveries | Bounded durable intents and exact-ciphertext outbox with explicit action-required state. |
| Duplicate skip based on ID alone | Authenticated receipt binding scope, logical event, envelope, and canonical bytes. |
| Key replacement described as identity burn | Rotation preserves a generation; burn requires new generation, remote retirement, key deletion, and selective continuity. |
| Inbox deletion or local abandonment as sufficient burn | Pre-signed multi-route retirement journal and relay non-resurrection tombstone. |
| Unscoped bearer mutations | Relay-local scope plus monotonic, digest-chained route mutation v3; feature remains inactive pending privacy completion. |
| Feature model existence treated as support | Explicit capability negotiation and honest default advertisements. |
| Fingerprint-scoped relay APIs enabled by default | Disabled opt-in deprecated compatibility profile. |
| Group members identified only by user fingerprint | Signed endpoint-client foundation with provider boundary, roles, and policy; active migration still pending. |
| History backup carrying live authority | Inert, recipient-encrypted, replay-protected read-only projection only. |
| Silent bounded-history eviction | Chained event checkpoint compaction. |

## How the Active Direct Path Works Now

### Create a generation

1. Generate fresh identity authority, generation ID, inbox/access authority,
   local endpoint signing/agreement keys, route-consumer key, self-sync secret,
   and endpoint signed-prekey package.
2. Register the inbox with privacy-minimized registration v2.
3. Bind the first route consumer and persist the one-way mailbox-v2 migration.
4. Publish a contact offer containing only a compact generation checkpoint and
   one certified preferred endpoint.

### Establish a contact

1. Validate the contact offer, authority signature, endpoint-possession proof,
   signed-prekey signature/lifetime, capability bounds, and exact suite.
2. Derive a pairwise relationship ID from the authenticated random generation
   IDs.
3. Derive relationship-scoped endpoint handles and blinded certificate
   references.
4. Initialize an endpoint-keyed direct-v4 ratchet; never probe or fall back to
   the legacy wire.

### Send

1. Create one typed immutable event with distinct transaction and event IDs.
2. Clone the conversation ratchet and create one signed delivery envelope.
3. Atomically persist the event/local echo, candidate ratchet, exact ciphertext,
   envelope ID, and send intent.
4. Submit to the recipient's registered inbox and record `relayAccepted` only
   after the durable relay response.
5. On retry, resubmit the exact envelope. Do not re-encrypt or advance state.

### Receive

1. Synchronize an ordered batch with the route-consumer credential.
2. Reject any sequence/cursor gap before processing.
3. For each envelope, validate certified attribution, relationship context,
   signature, ciphertext, event semantics, and replay bindings using a cloned
   ratchet.
4. Atomically persist the decoded event, candidate ratchet, bounded receipt,
   and cursor progress.
5. Quarantine unknown controls or journal permanently hostile envelopes without
   exposing plaintext; do not advance past retryable local failures.
6. Commit the opaque relay cursor only after local persistence succeeds.

### Burn

1. Build a fresh unrelated generation and register its route.
2. Persist exact reset envelopes only for selected relationships.
3. Pre-sign retirement requests for every known old relay route.
4. Cut over locally and delete old private authority after the durable journal
   contains everything required for retry.
5. Retry resets and retirements idempotently until cleanup completes.
6. Keep unselected relationships and local state free of a general old-to-new
   link.

## Current Feature Status

| Area | Status | Important boundary |
| --- | --- | --- |
| Certified direct-v4 | Active | One preferred endpoint; no peer fan-out. |
| Ordered mailbox v2 | Active | Route-consumer scoped; legacy access becomes permanently unavailable after binding. |
| Typed direct events and controls | Active | Generic application events; control mutations are a closed authenticated set. |
| Direct outbox/intents | Active | Send and exact retry are wired; other intent kinds are models or partial journals. |
| Identity burn/retirement | Active | Completed burn requires access to every old route's staged retirement. |
| Prekey renewal | Active | Single-endpoint proactive publication path. |
| Read-only history package | Local API active | No transfer adapter, attachment bytes, or authorization side effect. |
| Self-sync | Foundation only | Persisted cryptographic/state model; no publication or rendezvous path. |
| Multi-endpoint participation | Inactive | No complete admission, self-sync membership, fan-out, teardown, or group mapping. |
| Relationship route sets | Foundation only | State transitions exist; exchange and migration are not wired. |
| Opaque route capabilities | Disabled experimental foundation | Not advertised or used until metadata, scale, expiry, abuse, and padding issues are solved. |
| Endpoint-aware groups | Foundation only | Signed model exists; active workflow remains deprecated fingerprint compatibility. |
| Custom PQ group provider | Experimental | Not RFC 9420 MLS and not independently audited. |
| PIR/onion/mixnet/open discovery | Optional experimental modules | Not part of the stable direct-message core or a production anonymity claim. |

## Remaining Work

### P0: architecture completion gates

1. **Run and repair the full public compatibility suite.** In an unrestricted
   build environment run:

   ```sh
   swift build --package-path NoctweaveCore
   swift test --package-path NoctweaveCore
   swift build --package-path NoctweaveRelayServer
   swift test --package-path NoctweaveRelayServer
   scripts/run-tests.sh
   ```

   The current environment proved syntax, JS behavior, and schema integrity,
   but not Swift type checking, linking, runtime tests, or the aggregate release
   harness.

2. **Finish same-generation multi-endpoint participation without inventing an
   account.** Connect a short-lived purpose-bound rendezvous, endpoint
   possession proof, encrypted admission intent, independent route credential,
   endpoint-set publication, self-sync membership/rekey, direct fan-out,
   per-endpoint cursor state, aggregated receipts, group-client leaves, and
   complete endpoint removal. Never transfer generation authority, inbox-access
   authority, active ratchets, or existing cursors.

3. **Finish self-sync as an independent encrypted protocol.** Define the
   transport, sequence/cursor behavior, snapshot compaction, conflict rules,
   burn/reset behavior, endpoint-add/remove rekey, retry journal, and offline
   recovery. Keep the stream hidden from ordinary conversations and free of
   shared live ratchet/prekey authority.

4. **Replace reusable contact codes with private rendezvous.** Pairing offers
   should be short-lived, purpose-bound, expiring, replay-safe, and contain only
   an ephemeral key, opaque temporary route/token, and supported versions. Full
   PQ contact and relationship-scoped route material should travel inside the
   resulting encrypted channel. Until then, document that reuse can link the
   same generation to multiple recipients.

5. **Complete private relationship routing before activating route
   capabilities.** Prefer relationship-scoped inboxes/queues or an equivalent
   unlinkable design; add expiring route epochs, make-before-break renewal,
   realistic relationship and overlap capacity, per-capability quotas/rate
   limits, padding/cover policy, private issuance, and confidential transport.
   Then wire route-set exchange, testing, overlap, drain, and revocation into
   both clients. Do not advertise `nw.routes` before this gate passes.

6. **Replace the active compatibility group path.** Connect authenticated
   endpoint key-package distribution, trusted manifest freshness, group-client
   admission, Welcome delivery, per-endpoint delivery cursors, persistence,
   restart recovery, fan-out, sibling-preserving removal, and signed policy to
   the active Core, JS, and relay workflows.

7. **Choose and review the production group cryptography boundary.** Either
   obtain an independent cryptographic review of the current PQ provider or
   introduce a separately versioned conforming MLS provider. Do not market the
   custom provider as MLS, and do not silently replace the PQ profile with a
   classical-only suite.

8. **Publish independent security evidence.** Complete cryptographic,
   side-channel, identity/burn, storage-atomicity, and metadata-analysis review.
   Add a third-party or independently implemented client/conformance runner.
   Until then, mark the revision and experimental group construction unaudited.

9. **Resolve compatibility naming and migration policy.** Rename remaining
   public `Installation*` symbols to endpoint terminology where source breakage
   is acceptable, or publish an explicit deprecation/alias schedule. Specify
   the supported migration window for legacy profile, mailbox, direct, and
   group data; define rollback limits and recovery for interrupted migration.

### P1: product and interoperability completion

1. Add resumable direct/user-selected history transports, expiry/deletion UX,
   and explicitly authorized attachment-byte migration. Keep imported history
   inert and never bundle live authority.
2. Generate Swift and TypeScript wire models from one normative schema, or
   adopt one strictly specified deterministic signing representation. Expand
   differential positive/negative vectors for unknown fields, canonical bytes,
   migrations, and all security controls.
3. Complete client projections and UX for replies, reactions, replacements,
   retractions, delivery/read events, unsupported content, consent, blocks,
   mutes, and message requests.
4. Define JavaScript parity for the closed security-control set where browser
   products need rotation, burn/reset, or session recovery. Keep those controls
   explicitly enumerated and authenticated; do not expose a generic custom
   control-state mutation API.
5. Add optional opaque wake/helper-mailbox adapters without making vendor push
   or a central helper service mandatory.
6. Add operator migration tooling, backup/restore tests, mailbox/consumer/route
   observability that does not log secrets, and explicit quota/retention
   guidance for the new storage model.
7. Add active route migration and redundant-route UX with an honest warning
   that redundancy increases traffic and metadata exposure.

### P1: release engineering gates

1. Run Core and Linux relay CI on supported macOS and Ubuntu toolchains.
2. Publish code-coverage reports for both Swift packages.
3. Add container build and vulnerability-scan evidence.
4. Publish relay/core latency, throughput, encryption, and decryption
   benchmarks with reproducible methodology.
5. Document and exercise signed relay-binary and container release artifacts.
6. Publish a fresh audit report or explicitly label the release unaudited.

### P2: optional research, not 1.0 core blockers

- Production PIR only with independent non-collusion and availability evidence.
- Production mixnet only with sustainable cover traffic and shared routing
  policy.
- Wider mesh, Bluetooth, LAN, offline-file, and helper-device transports as
  replaceable adapters.
- Future PQ MLS profiles only after relevant standards and implementations are
  stable enough for independent interoperability testing.
- Formal proofs for continuity, group epochs, burn/retirement, and recovery
  state machines.

## Known Limitations and Residual Risks

- Full Swift compilation and runtime tests have not run in this sandbox.
- The active direct path supports one preferred endpoint only.
- Internal compatibility naming can still suggest an account/device model if
  read without the philosophy specification.
- The transitional inbox-addressed delivery path lets the final relay observe
  generation-level timing and volume.
- Opaque capability labels alone do not prevent the final relay from linking
  capabilities that terminate at one inbox; that feature remains disabled.
- Reusable contact offers can be correlated by recipients until rendezvous
  pairing replaces them.
- The self-sync, route migration, endpoint-aware group, and full endpoint
  lifecycle models are not complete active workflows.
- The custom PQ group protocol and direct/group cryptographic state machines
  have not received a fresh independent audit or side-channel review.
- The current `IdentityProfile` remains a local aggregate containing powerful
  generation authority and must never become a portable live endpoint backup.
- A lost sole endpoint can locally abandon a generation but cannot prove a
  completed remote burn without previously staged route-retirement authority.

## Verification Recorded for This Revision

The following checks passed after the architecture and final route-gating
changes:

- `npm test` in `NoctweaveJS`: **80/80 tests passed**.
- `npm run typecheck:desktop` in `NoctweaveJS`: passed.
- `xcrun swiftc -parse` over all Swift Core/CLI sources and Core tests: passed.
- `xcrun swiftc -parse` over all Linux relay sources and tests: passed.
- OpenAPI YAML parse: passed.
- JSON test-vector parse: passed.
- Both revised SVG architecture assets parsed with `xmllint`: passed.
- `git diff --check`: passed.

Not completed in this environment:

- SwiftPM build and tests for `NoctweaveCore`.
- SwiftPM build and tests for `NoctweaveRelayServer`.
- The aggregate `scripts/run-tests.sh` release harness.

The attempted SwiftPM run failed during manifest evaluation with
`sandbox-exec: Operation not permitted`; this is an environment restriction,
not a passing or failing product test result.

## Recommended Next Milestone

Call the next milestone **Architecture Revision Stabilization** and keep it
strictly ordered:

1. Obtain a normal Swift build/test result and fix any compile/runtime failures.
2. Freeze endpoint terminology and the migration contract.
3. Replace reusable pairing with purpose-bound rendezvous.
4. Complete self-sync and same-generation endpoint lifecycle.
5. Complete private routing and only then activate route capabilities.
6. Replace the fingerprint compatibility group workflow.
7. Run independent interoperability and security review.
8. Finish CI, coverage, benchmarks, container scans, and signed-release
   evidence.

That sequence finishes the reusable product substrate first while keeping PIR,
mixnet, wider mesh, and future PQ MLS work outside the core release path.
