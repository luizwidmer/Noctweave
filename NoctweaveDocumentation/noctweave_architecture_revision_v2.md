# Noctweave 1.0 Architecture

Status: normative architecture baseline.

## Outcome

Noctweave is a post-quantum, pairwise-private event protocol with replaceable
relays and optional federation. It borrows robust delivery and state-machine
ideas from public messaging protocols without importing their accounts, global
identities, device graphs, managed services, or public social metadata.

> A local persona never becomes a protocol identity. Every relationship and
> group is a fresh, unlinkable cryptographic context.

## State model

```text
ClientState
├── local relay and UI preferences
└── personas[]                         local-only containers
    ├── pairwise relationships[]
    │   ├── fresh relationship authority
    │   ├── one relationship endpoint binding and rotating prekeys
    │   ├── local opaque receive routes and committed cursors
    │   ├── peer send-only route set
    │   ├── immutable conversation events
    │   ├── delivery projections and replay receipts
    │   └── bounded protocol intents
    └── group runtimes[]
        ├── group-scoped member handle and credential
        ├── signed roles and permissions
        ├── complete signed epoch transitions and welcomes
        ├── anchored joins, replay/fork journals, and terminal removal
        └── exact application and deletion outboxes
```

There is no account object, global inbox, device or installation registry,
recovery authority, persona public key, or shared self-sync channel.

## Contact pairing

1. The offerer creates a short-lived one-use rendezvous invitation.
2. The invitation exposes only random rendezvous capability material and a
   redemption secret.
3. Each side generates a relationship authority, endpoint binding, signed
   prekey, opaque receive route, and relationship pseudonym.
4. Those values are exchanged inside the encrypted rendezvous session.
5. Both sides derive the same relationship identifier from the transcript.
6. The redemption is recorded so replay cannot create another relationship.

Before an application starts construction that may suspend outside the client,
it mints a non-serializable process-local persona-scope token. The completed
relationship is inserted only if that token still names the active local
persona and the same client process. The token is not protocol authority and
contains no reusable identity; burn or restart invalidates it.

The encoded invitation is tested to exclude persona labels, relationship IDs,
relationship-authority keys, endpoint IDs, relay URLs, and route capabilities.

## Direct messaging

The direct profile binds the relationship transcript, each side's
relationship-scoped endpoint handle and binding digest, the exact PQ cipher
profile, negotiated `nw.core` and `nw.direct` versions, the exact shared
content-type major versions and limits, and the event/session context into
authenticated bytes. A sender rejects unsupported content before advancing a
ratchet.

One endpoint-signed ML-KEM prekey bootstrap derives the direct-v4 root and its
independent symmetric send and receive chains. There is no periodic PQ root
refresh and no in-session post-compromise-healing claim. Reset is terminal for
that session; communication resumes only through a fresh bootstrap and distinct
session state.

Application content and security controls are separate wire families. Content
is namespaced and versioned; replies, replacements, reactions, retractions,
delivery receipts, and read receipts are immutable related events. Unknown
application content can be retained with a safe fallback. Unknown or malformed
controls cannot mutate protocol state.

Live authentication paths use throwing PQ verification. Invalid peer material
is a deterministic peer failure, while unavailable ML-DSA/ML-KEM support or a
local PQ runtime failure propagates as retryable local unavailability. It is
never collapsed into an invalid-signature result that could authorize cursor
advancement.

Consent, pending-request state, mute, receipt preferences, and block are local
policy for one relationship. They expose no global block list or persona
identifier. A relationship safety number is derived only from the two fresh
relationship-authority signing keys.

Every send distinguishes:

```text
clientTransactionID  one local user action and its retry reconciliation
eventID               one immutable logical event
envelopeID            one direct-session ciphertext projection of that event
packet or bundle ID   one exact delivery copy for one opaque route
route sequence        one relay-local ordered position
```

`prepareSend` performs no relay I/O. It atomically persists the event, unique
author/transaction binding, advanced relationship ratchet, direct envelope,
fixed ciphertext packet bundles, local delivery projection, and one bounded
intent per destination route. That durable event is the immediate local echo.

Mutations are serialized per relationship, while one process-wide encrypted-
state save gate merges independent relationship changes against the latest
state. This permits unrelated conversations to make progress concurrently
without allowing either save to overwrite the other's newer state.

Publication uses only those saved bytes. While the bounded event/outbox record
is retained, a restart can resume by event ID or client transaction ID without
creating another event or advancing the ratchet again. One route never
publishes direct-session counter N+1 while N is still
unresolved. Retryable failures retain an explicit next-attempt time; permanent
failures remain visible and retain their authenticated artifacts until an
explicit discard. Discarding a terminal counter gap fails later dependent
artifacts and forces the next send onto a fresh direct session instead of
silently skipping ratchet state.

## Delivery and synchronization

Relays expose opaque route capabilities rather than identity-addressed
mailboxes. A route has separate append, read, renewal, and teardown authority,
an expiry, a revision, and bounded storage.

Synchronization returns ordered packets, an opaque next cursor, a high-water
position, and `hasMore`. Fetching is non-destructive. Every packet in a page is
terminally classified before the page cursor advances. A verified fragment may
advance before its bundle is complete only when the partial reassembler state
and next cursor are saved atomically; the completed bundle is then decrypted
and applied on a later page.

Failures have three exact classes:

- route-chain, cursor, retention-gap, or persisted-state corruption is
  route-fatal and does not advance the disputed page;
- deterministic peer-controlled packet, envelope, replay, or known-control
  failure is recorded in bounded plaintext-free quarantine and advances so one
  hostile item cannot wedge later traffic;
- storage, network, local-state, or PQ-runtime failure is retryable and does
  not advance the page cursor.

When the bounded partial-reassembly budget is exhausted, the receiver
deterministically retires and tombstones the oldest incomplete bundle, records
reassembly-pressure quarantine, and continues. That abandoned logical message
is not silently reconstructed or automatically acknowledged as stored; a
sender sees no `peerStored` receipt and may issue a new logical send.

The durable mutation order is local first: verified events, replay receipts,
and the next local cursor are saved before the relay is authorized to garbage
collect the consumed prefix. A crash between those steps resumes safely from
the newer local cursor while the relay still retains the older packets.

Relay cursor commit and generated delivery receipts, route probes, and
route-set publications run only after that local commit. They are best-effort:
their failure cannot roll back or hide the successful local sync result, and a
later pass can retry them. Receive routes are independent availability paths;
one failed or gapped route does not prevent the same sync pass from processing
a later healthy route, and the call fails only when no route succeeds.

Receiver-observed time governs freshness windows and local state chronology.
Peer timestamps remain authenticated display/audit metadata and cannot alone
advance expiry, retention, epoch, route, or prekey state into the future.

A torn-down route is terminal. To close the crash window after the relay
applies teardown but before the client removes its capability, a fresh valid
teardown request against that terminal state returns the existing tombstone.
Create, renew, append, and sync remain rejected after teardown.

Delivery UI state has four meanings:

1. `locallyPersisted` — the outbox intent is durable;
2. `relayAccepted` — the relay accepted encrypted packets;
3. `peerStored` — the peer voluntarily reported durable processing;
4. `peerRead` — the peer voluntarily reported a read action.

Transport responses and cursor commits are not read receipts.

## Route rollover

Route location is independent of relationship identity. Rollover is
make-before-break: register a replacement route, advertise it as `testing`
through the old working path, receive a targeted probe on the replacement,
promote it while the old route drains through a bounded overlap, then tear down
the old route.

Route sets are encrypted relationship material. Relays receive neither a
contact graph nor a public relay list.

The client journals rollover before network work and persists each accepted
boundary: replacement-route creation, testing advertisement, probe receipt,
promotion, overlap, drain, and teardown. Restart resumes the one unfinished
rollover from its saved intent and exact request. If a crash follows probe
acceptance, the accepted testing snapshot can reconcile promotion. A terminal
rollover failure is retained until explicitly discarded; it is never mistaken
for a completed route change.

## Burn and selective continuity

Burn removes the old persona record and its relationships, groups, sessions,
route capabilities, and pending operations from local state, then creates an
unrelated empty persona. Old relay packets may remain until route expiry; they
contain no link to the replacement.

Construction that suspends outside the client is guarded by a non-serializable,
process-local persona-scope token minted before work begins. A burn or client
restart invalidates the token, so an old relationship or group result cannot be
inserted into the replacement persona after the fact.

Continuity is an optional one-relationship control carrying a successor
one-use invitation. Local policy independently gates sending and accepting it.
No global old-to-new event is created.

## Groups

Group membership is unrelated to direct relationships. Each member has one
group-scoped handle and one active credential. Roles and permission policy are
signed group state. Credential replacement is an explicit two-proof commit:
the old credential authorizes the change and the new credential proves key
possession in the same accepted epoch.

An epoch publication contains the signed commit, the authoritative signed next
state, exact provider commit bytes, and destination-specific signed welcomes.
The receiver validates that complete transition against its current state,
processes the matching Welcome for its current or explicitly pending group-only
credential, and atomically persists the accepted signed state, provider state,
and replay journal. Exact replay returns the retained outcome; a different
artifact for the same base epoch retains bounded digest-only fork evidence.

A new runtime can be joined only through an explicit `GroupJoinAnchorV2`
pinned by an already encrypted group invitation. A self-consistent Welcome is
epoch-secret delivery, not a trust root. Removal of the local credential is a
terminal group-local state that clears sendable epoch/application work. Group
deletion similarly persists the exact signed tombstone as an outbox or inbound
terminal state, clears sendable work atomically, accepts exact replay, and
rejects conflicting deletion or later resurrection while retaining only
bounded digest evidence. The aggregate runtime record is capped at 32 MiB.
Live group signing, verification, and provider operations propagate PQ
algorithm/runtime failure through throwing APIs.

The runtime also persists exact pending group application envelopes and
processed-envelope replay receipts. `GroupOpaqueRouteFanoutPlanV2` and
`publishGroupFanoutPlan` are low-level, stateless experimental transport
primitives: a caller supplies routes, creates a plan, and publishes its sealed
packets. They do not yet provide durable recipient/route authorization
snapshots, exact packet-attempt persistence, transition-plus-Welcome staging,
group receive cursors/reassembly/quarantine, group route lifecycle, or Headless
group-envelope dispatch. The implemented group state machine therefore must not
be described as end-to-end crash-safe opaque-route group transport.

The supplied PQ group provider is experimental, Noctweave-specific, and not
RFC 9420 MLS. MLS contributes useful vocabulary and discipline, not a
compatibility claim.

## Encrypted blobs

Attachment bytes are encrypted before upload. The client persists one exact
upload request and bounded intent before relay I/O, then retries that request
unchanged. Every upload carries a 32-byte idempotency key and a domain-separated
canonical body digest.

While `(attachmentId, chunkIndex)` remains retained, the relay treats it as an
immutable coordinate. The same key and body returns the original result without
refreshing expiry or rewriting SQLite/IPFS storage. Any changed key, ciphertext,
or requested expiry is a non-retryable conflict. A failed upload remains
explicitly retryable or terminal and can be discarded without granting the
relay plaintext or a content key.

## Relay protocol modules

Every request and response uses an exact envelope containing request ID,
module, version, method, and one typed body. A response is bound to the same
tuple. Unknown fields, mismatched methods, and invented error correlation fail
closed.

Provisional 1.0-candidate relay modules are deliberately small:

- `nw.core` — health, info, and exact capability discovery;
- `nw.opaque-route` — route lifecycle, append, sync, and cursor commit;
- `nw.rendezvous-transport` — bounded one-use pairing transport over two
  encrypted directional lanes with separate capabilities;
- `nw.blobs` — encrypted attachment chunks;
- `nw.federation` — operator-selected registration and listing.

Experimental relay modules are separately advertised only when their runtime
is explicitly enabled:

- `nw.open-discovery` — experimental signed open-relay discovery, advertised
  only when its runtime is enabled.

`nw.direct` is a provisional client-to-client capability, not relay plaintext
logic. A module is not advertised until its exact runtime exists.

Both relay implementations advertise the same exact `nw.opaque-route@2`
registry: `cursorBytes=68`, `maxPage=256`, `maxPacketBytes=65536`,
`maxPacketsPerRoute=1024`, `maxRetentionSeconds=604800`, and
`maxRoutes=100000`. Blob default and maximum TTL are reported separately in
relay info and remain operator-configurable between 60 seconds and an absolute
2,592,000-second (30-day) storage ceiling.

## Wake and transport independence

Experimental optional wake/prefetch uses route IDs, route-local jitter seeds,
opaque packet records, encrypted staging, and deferred cursor commit. It
carries no persona, identity, contact label, message count, or plaintext.
Pull-only synchronization remains complete.

Conversation events are independent of delivery adapters, allowing relay, LAN,
offline file, onion, or other transports to be evaluated without changing
application semantics. Experimental adapters are not 1.0-candidate core
requirements.

## Federation and privacy extensions

`solo`, `manual`, `curated`, and `open` are separate trust domains. Federation
never grants plaintext access or changes relationship authentication.

Hidden retrieval, onion, mixnet, and `nw.open-discovery` remain modular and
experimental. Their presence does not justify anonymity claims for the
provisional 1.0-candidate direct path.

## Ideas adopted

- ordered cursors, local echo, transaction IDs, and immutable relations;
- explicit acknowledgement layers and durable mutation intents;
- pairwise opaque routes and make-before-break rotation;
- namespaced content types and capability discovery;
- signed group roles, policies, commits, welcomes, and epochs;
- transport decomposition, experimental optional opaque wake, and extension
  lifecycle;
- exact bounded decoders and a growing shared cross-language vector set.

## Ideas deliberately excluded

- stable inbox accounts and global user identifiers;
- device or installation authorization and revocation;
- multi-device self-sync and shared live ratchets;
- recovery authorities and portable live-profile imports;
- permanent managed history or push services;
- public topics, public relay lists, or broadcast DM routing;
- wallet, phone-number, DID, or provider identity as a default trust anchor;
- server-readable relations or plaintext moderation;
- claims that the experimental PQ group protocol is MLS.

## Assurance boundary

Builds, unit tests, vectors, strict-decoding tests, and model checks are required
gates. A profile cannot become stable without independently demonstrated
normative wire and failure-semantics conformance through a genuinely
independent implementation or independently built conformance harness. Stable
still does not mean audited. Production claims additionally require external
cryptographic, side-channel, zeroization, fuzzing, and operational review.
