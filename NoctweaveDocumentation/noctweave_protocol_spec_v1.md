# Noctweave Protocol 1.0

Status: normative 1.0 candidate; implemented core modules remain provisional.

## 1. Scope

Noctweave 1.0 defines:

- one-use post-quantum contact rendezvous;
- unlinkable pairwise relationships;
- typed encrypted direct events and controls;
- opaque relay routes with ordered cursor synchronization;
- encrypted attachments;
- an experimental group profile;
- explicit relay federation modules;
- experimental route-scoped wake and privacy research extensions.

A local persona is outside the protocol. There are no accounts, global inboxes,
device registries, recovery authorities, or self-sync identities.

Normative security requirements are in
[`security_requirements.md`](security_requirements.md). The identity boundary is
defined by [`noctweave_identity_philosophy.md`](noctweave_identity_philosophy.md).

## 2. Encoding rules

JSON transport objects use BOM-free UTF-8, canonical padded Base64 for `Data`, UTC
ISO-8601 whole-second dates, and lexicographically sorted object keys for
authenticated payloads. Security-sensitive decoded objects require the exact
current field set and canonical nested bytes. Unknown, missing, duplicate,
malformed, non-finite, out-of-range, or structurally inconsistent values fail
closed. Objects and arrays nested beyond 128 containers are rejected before
native decoding.

Sorted JSON is the implemented 1.0 signing profile, not a claim that arbitrary
JSON encoders produce the same bytes. Every implementation must reproduce the
repository vectors exactly. Moving to a separately specified deterministic
binary representation remains a release-hardening gate.

Every signature, KDF, MAC, and AEAD context uses a purpose-specific domain.

## 3. Contact rendezvous

`RendezvousPurposeV2` has one value: `contactPairing`.

A public invitation contains:

- protocol version;
- opaque temporary transport capability;
- one-time token digest and separately conveyed redemption secret;
- ephemeral ML-KEM public material;
- canonical creation and expiry times;
- bounded frame limits.

The invitation must not contain a persona label or ID, relationship ID,
relationship authority, endpoint binding, prekey, route ID, relay address, or
group handle.

The responder proves the redemption secret and contributes fresh ephemeral KEM
material. Both roles derive transcript-bound directional keys. Frames are
ordered per direction, padded, AEAD-protected, and limited by count and size.
Successful redemption is recorded and cannot be replayed.

When a relay carries the rendezvous, it exposes two unlabeled ciphertext lanes.
Each lane has independent publish, read, and delete capabilities; the relay
stores only bearer digests and terminal tombstones. TLS is mandatory except for
an explicitly allowed loopback development endpoint.

Inside the session each party sends fresh, independently generated:

- relationship pseudonym;
- ML-DSA relationship-authority public key;
- ML-KEM relationship-agreement public key;
- one authority-signed endpoint binding and endpoint-signed prekey;
- one signed opaque receive route set.

## 4. Relationship identity

Relationship material is valid only for the rendezvous transcript that created
it. A peer must verify the authority signature, endpoint key-possession proof,
prekey signature and expiry, route-set signature, route expiry, and transcript
binding before creating local relationship state.

Local clients that construct a relationship across a suspension boundary must
mint a non-serializable, process-local scope token before construction and
require the same token when inserting the result into a persona. The token is
local race protection only: it is never encoded, transmitted, signed, or used
as cryptographic authority. Persona burn or process restart invalidates it.

The endpoint binding is singular. There is no endpoint set, installation list,
authorization challenge, sibling endpoint, recovery key, or cross-relationship
certificate.

`RelationshipSafetyNumberV2` derives a human-comparable value from only the two
fresh relationship-authority signing keys. It is not reusable outside that
relationship. Consent, pending-request state, mute, receipt preferences, and
block are likewise local relationship policy and produce no global identity.

## 5. Direct profile

The direct profile uses ML-KEM-768, ML-DSA-65, HKDF/HMAC-SHA-256, and
AES-256-GCM. Its authenticated session context binds:

- relationship ID and conversation ID;
- sender and recipient relationship endpoint handles;
- both endpoint-binding digests;
- negotiated `nw.core` and `nw.direct` versions;
- the exact shared content-type major versions and bounded limits;
- cipher suite and payload format;
- session, event, envelope, counter, and ratchet state.

Initial delivery consumes a valid signed ML-KEM prekey and derives one root plus
independent symmetric send and receive chains. Direct-v4 has no periodic PQ root
refresh and makes no in-session post-compromise-healing claim. Replays, counter
gaps beyond policy, expired prekeys, and mismatched binding digests fail closed.

Protocol processing uses throwing PQ verification so algorithm unavailability
and local ML-DSA/ML-KEM runtime failure remain distinguishable from invalid peer
signatures. The former is retryable and cannot authorize receive-cursor
advancement; the latter is a deterministic peer-controlled failure.

Direct sessions and both chain states are persisted inside exactly one
relationship. A bounded retirement window may evict an old session, but a
validly signed envelope from that evicted session is authenticated and
quarantined rather than allowed to block ordered route synchronization. A
session reset remains reset until a fresh signed-prekey bootstrap creates a new
session.

`ProtocolCapabilityManifest` negotiation requires every implemented direct
module and a shared text content type. `ContentTypeCapabilityV2` negotiates by
type ID and major version, selecting the lower shared bounds. Unsupported
outbound content fails before a ratchet advances.

## 6. Events and controls

An application event contains:

- event and client-transaction IDs;
- conversation ID and author relationship handle;
- creation time;
- event kind;
- namespaced content type and version;
- bounded parameters and payload;
- optional encrypted relation;
- optional fallback and visible/silent disposition.

Standard families include text, attachment, reply, replacement, reaction,
retraction, delivery receipt, and read receipt.

For one author relationship handle, `clientTransactionID` is unique within the
bounded retained event log. Repeating it while retained cannot create a second
event. `eventID` identifies the immutable logical event, `envelopeID` identifies
its direct-session ciphertext projection,
packet/bundle IDs identify exact route copies, and the relay assigns the
route-local sequence.

Security controls are separately authenticated and relationship-bound. Defined
controls include session reset, resend request, route-set update, targeted
route probe, endpoint-prekey update, and optional selective continuity. Unknown
controls are retained as quarantined audit events and never executed.

## 7. Opaque routes

A receive route is an unguessable relay-local capability with separate:

- append capability for peers;
- read capability and cursor for the receiver;
- renewal capability;
- teardown capability;
- payload-encryption key;
- revision and bounded expiry.

Peers receive only the send-side route projection: append capability plus the
outer route-wrapping key required to create fixed opaque packets. They never
receive read, renewal, or teardown authority. The direct envelope remains
independently end-to-end encrypted inside that outer packet.

Append stores bounded opaque packets under a monotonically increasing route
sequence. Sync is non-destructive and returns packets after an authenticated
cursor. The client durably saves verified events, replay receipts, and its next
local cursor before submitting relay commit. Commit then authorizes garbage
collection for that route consumer. A crash before commit resumes from the
newer local cursor while the relay retains the older prefix. Expired or
torn-down routes cannot be resurrected by stale requests.

Relay commit and any generated delivery receipt, route probe, or route-set
publication happen after the local save and are best-effort. Their failure does
not undo the locally committed page. Each receive route is an independent
availability path: a failure on one route does not stop the same synchronization
pass from attempting later routes, and the aggregate call fails only if none
succeeds.

Teardown is terminal but effect-idempotent across the final crash window. A
fresh request authenticated by the last valid teardown authority against an
already-torn-down route returns its tombstone. Create, renew, append, and sync
remain rejected.

## 8. Route sets and rollover

A route set is signed by the current relationship endpoint and includes a
revision, previous digest, active/testing/draining state, validity times, and a
bounded route list.

Clients register a new route, advertise it as `testing` through the old working
path, receive a targeted probe on the new route, then promote it while the old
route drains through a bounded overlap. Messages may be duplicated during
overlap; event and envelope replay rules make this idempotent. The drained route
is then torn down.

Only one rollover may be unfinished for a relationship. The client persists a
bounded rollover intent, exact create request, replacement local route, and each
accepted route-set transition before proceeding. Restart resumes that record;
accepted testing/probe state reconciles a crash before promotion. A terminal
failure stays explicit until discarded and is never reused as a successful
route-set event.

## 9. Durable intents and delivery state

Multi-step local mutations use bounded `ProtocolIntentV2` records containing an
idempotency key, exact payload digest/bytes, dependencies, expected state, retry
classification, and explicit terminal state.

The client serializes mutations within one relationship and uses a process-wide
encrypted-state save gate for the aggregate. Each save must merge against the
latest state so independent awaited relationship operations cannot overwrite
one another.

`prepareSend` performs no relay I/O. Before returning local echo it atomically
persists the logical event, unique transaction binding, advanced ratchet,
direct envelope, exact route packet bundles, delivery projections, and one
intent per route. Publication and restart recovery use only those saved bytes.
For one destination route and direct session, counter N+1 cannot publish while
N remains unresolved.

Retryable intents record bounded attempts and the next eligible retry time.
Permanent failures are excluded from pending counts but retained with their
artifacts until explicit discard. Discarding an unresolved direct counter marks
later dependent artifacts terminal and resets that session so a later message
must bootstrap fresh. Route rollover and encrypted blob upload use the same
prepare, persist, publish, resume, and explicit-discard discipline.

Delivery projections distinguish local persistence, relay acceptance, peer
storage, and peer read. A relay response proves only the operation it performed.

## 10. Relay wire envelope

Every relay request contains exactly:

```text
requestID
module
version
method
body
optional authToken
```

Every response repeats the same request ID, module, version, and method and has
exactly one success body or one structured error. A response that does not match
the outstanding request is invalid.

Current bindings are:

| Module | Version | Status | Methods |
| --- | ---: | --- | --- |
| `nw.core` | 2 | provisional | `health`, `info` |
| `nw.opaque-route` | 2 | provisional | `create`, `renew`, `teardown`, `append`, `sync`, `commit` |
| `nw.rendezvous-transport` | 2 | provisional | `register`, `append`, `sync`, `delete` |
| `nw.blobs` | 1 | provisional | `upload`, `fetch` |
| `nw.federation` | 1 | provisional | `register`, `list` |
| `nw.open-discovery` | 1 | experimental | `publish-dht`, `list-dht` (advertised only when enabled) |

Both relay implementations advertise the exact same canonical
`nw.opaque-route@2` limit registry:

| Key | Value |
| --- | ---: |
| `cursorBytes` | 68 |
| `maxPage` | 256 |
| `maxPacketBytes` | 65,536 |
| `maxPacketsPerRoute` | 1,024 |
| `maxRetentionSeconds` | 604,800 |
| `maxRoutes` | 100,000 |

Attachment upload TTL is bounded by the default and maximum policy reported in
relay info and an absolute 2,592,000-second (30-day) store ceiling. The normal
configuration may choose a lower maximum. A value accepted above six hours is
retained for that bounded duration; the store does not silently shorten it to
six hours.

The direct client profile advertises provisional `nw.core` version 2 and
`nw.direct` version 4 modules.

The OpenAPI document defines HTTP transport details. TCP and WebSocket carry
the same protocol objects.

## 11. Attachments

Attachments are encrypted client-side under a random content key. Relays store
bounded ciphertext chunks and a ciphertext manifest. The event carries the
descriptor and wrapped content key inside the direct or group ciphertext.

Every chunk upload includes a 32-byte idempotency key. The client persists the
exact upload request and its domain-separated canonical body digest before
relay I/O. While `(attachmentId, chunkIndex)` is retained, an exact retry
returns the original result without extending expiry or rewriting local/IPFS
storage. A different key, ciphertext, or requested expiry is a non-retryable
conflict; replacement requires a fresh attachment ID.

Storage offload, including optional IPFS, changes storage placement only. It is
not an anonymity feature.

## 12. Groups

The experimental group profile uses fresh group-scoped member handles and one
active credential per member. Signed state includes epoch, previous transcript,
members, roles, permission policy, and metadata digest. Commits add/remove
members, replace a credential, update role/policy/metadata, or delete the group.

Credential replacement requires authorization by the old active credential and
proof of possession by the new credential. Forked or conflicting commits are
quarantined. Application ciphertext binds group ID, profile, suite, epoch,
sender, counter, envelope ID, transcript, and visible metadata.

An epoch transition is one complete authenticated object containing the signed
commit, signed next state, and exact provider commit bytes. Every active
destination that continues into the next epoch receives a destination-specific
signed Welcome. A receiver verifies the transition against its current signed
state and processes the matching Welcome before atomically replacing signed
state, provider state, and the epoch replay journal. Exact replay is
idempotent. A different transition for an already accepted base epoch retains
bounded digest-only fork evidence and does not replace state.

A runtime that does not yet exist may be created only from a caller-pinned
`GroupJoinAnchorV2` supplied through an already encrypted group-only invitation.
The anchor binds the base state and intended member, credential, and admission
digest; a Welcome cannot authorize its own recipient. Accepted removal of the
local credential is terminal and clears sendable work. A local deletion first
persists its exact signed tombstone outbox and clears application/epoch work in
one atomic replacement; an inbound deletion is likewise terminal. Exact
deletion replay is accepted, while conflicting deletion and post-deletion
transition/commit resurrection attempts retain bounded digest-only evidence.
The canonical group runtime aggregate is limited to 32 MiB. Group signing,
verification, key validation, and provider processing use throwing PQ paths so
local algorithm/runtime failure is not reclassified as invalid peer input.

`GroupOpaqueRouteFanoutPlanV2` and
`HeadlessMessagingClient.publishGroupFanoutPlan` are low-level stateless
experimental helpers. They do not durably own recipient/route authorization
snapshots, packet-attempt state, transition-plus-Welcome staging, group receive
cursors/reassembly/quarantine, group route lifecycle, or Headless group
dispatch. They are not an end-to-end crash-safe group transport.

This profile is not RFC 9420 MLS.

## 13. Wake, federation, and experimental privacy

Experimental optional wake uses route-scoped opaque identifiers, local jitter,
encrypted staging, and normal cursor sync. It supplies no delivery or read
semantics and is not required for message availability.

Federation modes are explicit trust domains. Experimental open discovery uses
its own `nw.open-discovery` module. Hidden retrieval, open discovery, onion, and
mixnet extensions are advertised only when their exact policy and runtime are
active. They do not alter end-to-end relationship authentication.

## 14. Resource and error rules

Every implementation must enforce the repository constants for payload sizes,
array counts, route pages, frame counts, attachment chunks, retry attempts,
retention, expiry, and arithmetic conversion.

Opaque-route receive errors are classified as follows:

1. A cursor/sequence/digest-chain gap, retention-floor loss, or persisted-state
   corruption is route-fatal. The disputed page does not advance.
2. A deterministic peer-controlled malformed packet, invalid ciphertext or
   attribution, replay conflict, incompatible envelope, or invalid known
   control is durably quarantined by packet/stream coordinates. The page may
   advance so later independent traffic is not wedged.
3. Storage, network, local-state, or PQ algorithm/runtime failure is retryable.
   Neither the local page cursor nor relay garbage-collection authorization
   advances.

A page need not contain a complete bundle. A verified fragment may advance
only after its bounded partial-reassembly state and the next local cursor are
persisted atomically. At deterministic reassembly pressure, the oldest partial
bundle is retired with a replay tombstone and quarantine record; it is not
reported `peerStored` and has no implicit reconstruction or resend guarantee.

Freshness decisions use receiver-observed time and the specified clock-skew
bound. Peer-authored timestamps are authenticated metadata, not a sole state-
transition clock.
