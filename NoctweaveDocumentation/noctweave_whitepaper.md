# Noctweave

## A pairwise-private post-quantum messaging architecture

### Abstract

Noctweave is a self-hostable encrypted messaging protocol in which a local
persona never becomes a network identity. Each pairwise relationship and group
is a fresh cryptographic context. Direct relationships use ML-DSA-65 for
authentication, ML-KEM-768 for one asynchronous signed-prekey bootstrap,
padded authenticated encryption for content, and opaque capability routes for
relay delivery. Relays store ciphertext and ordered route state without
receiving a global user identifier or plaintext social graph.

Noctweave combines this identity model with durable event semantics, exact
idempotent retries, non-destructive cursor synchronization, make-before-break
route rollover, explicit federation trust domains, and modular experimental
privacy transports. The supplied post-quantum group provider is experimental
and is not presented as RFC 9420 MLS.

## 1. Motivation

Many messaging systems attach cryptographic devices, mailboxes, archives, and
service location to a stable account. That is useful for conventional product
continuity, but it also creates durable correlation and recovery structures.

Noctweave begins from a different objective: communicating contexts should be
unlinkable unless a user deliberately links them. The protocol therefore does
not define a user account. Local software may organize chats under a persona,
but the persona has no wire identifier or authority.

## 2. Contextual identity

For each contact, both sides generate new:

- relationship pseudonym;
- ML-DSA authority key;
- ML-KEM agreement key;
- singular relationship endpoint binding and signed prekey;
- opaque route handles and capabilities.

Nothing in this set is reused for another contact. Group membership similarly
uses a fresh handle and credential per group.

This does not make a relationship anonymous to its peer or relay. The peer
knows the relationship it participates in, and a relay observes network
addresses, timing, route access, and ciphertext sizes. It prevents the protocol
itself from supplying one stable cross-context identifier.

## 3. One-use pairing

Pairing uses a short-lived post-quantum rendezvous. The public invitation is a
random, one-use transport capability plus redemption material. Relationship
keys, pseudonyms, prekeys, and routes are exchanged only after the participants
derive an encrypted transcript-bound session.

Relay-assisted pairing uses two unlabeled encrypted directional lanes with
separate publish, read, and delete capabilities. The relay persists only
capability digests and tombstones, not reusable participant identity.

Replaying an invitation cannot create another accepted relationship. The same
rendezvous state machine is not overloaded for device linking, history import,
route rollover, or group membership.

## 4. Direct cryptography

The direct profile authenticates both singular endpoint bindings and the exact
negotiated protocol, cipher, content-type-major-version, and bounds context.
Unsupported content is rejected before ratchet mutation. Initial asynchronous
messages consume a valid endpoint-signed ML-KEM prekey. Symmetric send and
receive chains then derive message keys. Direct-v4 does not periodically refresh
its root with ML-KEM and therefore makes no in-session post-compromise-healing
claim. Reset retires the session; resumption requires a fresh signed-prekey
bootstrap and a distinct session. Bounded skipped-key state supports ordinary
reordering without unbounded allocation.

Live authentication uses throwing PQ operations. An unavailable algorithm or
local PQ runtime is therefore retryable local failure, not an invalid peer
signature that could be quarantined and skipped.

Application events are padded and encrypted. Security controls carry their own
relationship, event, sender, time, nonce, and signature binding. Unknown
application formats can be retained safely; unknown controls do not execute.
Consent, message-request state, mute, receipt preferences, and block are local
to one relationship. A safety number compares only its two disposable
relationship-authority keys.

## 5. Event semantics

Messages are immutable events. Replies, edits, reactions, retractions, and
receipts refer to an earlier event inside ciphertext. A unique local transaction
ID reconciles one user action and its retries; an event ID names the logical
action, an envelope ID names its direct-session ciphertext projection, and
packet/bundle IDs name exact per-route delivery copies.

Preparing a send performs no relay I/O. The client atomically persists the
event, advanced per-relationship ratchet, direct envelope, mutation intents,
exact encrypted route packets, and local delivery projection before returning
local echo. A restart resumes by event or transaction ID without re-encrypting.
Within one route/session, later counters wait for earlier counters. Retryable
and terminal failures remain distinct; terminal artifacts require explicit
discard, and discarding a ratchet gap forces a fresh session instead of silently
skipping state.

Mutations are serialized per relationship. A process-wide encrypted-state save
gate merges independent relationship changes against the latest aggregate so
awaited operations cannot overwrite another relationship's newer state.

## 6. Opaque route delivery

An opaque route is a relay-local random capability with separated append,
read, renew, and teardown powers. The peer receives append authority plus the
outer route-wrapping key required to construct fixed opaque packets. The owner
keeps read and lifecycle authority. Direct ciphertext remains independently
protected inside the packet.

Relay storage is an ordered bounded log. Synchronization fetches packets after
an opaque cursor without deleting them. A cursor is committed only after local
durable processing. Retention and route expiry keep the relay from becoming a
permanent archive.

Verified fragments may span pages and restarts because partial reassembly state
and the next local cursor are saved atomically. Route-chain or persisted-state
corruption is route-fatal without page advancement; deterministic peer poison
is durably quarantined and advances; transient local, storage, network, or PQ
failure does not advance. When the bounded reassembly budget fills, the oldest
incomplete bundle is deterministically tombstoned and recorded as lost rather
than falsely reported stored.

The receiver persists verified events, replay state, and its next local cursor
before committing that cursor to the relay. A crash in between leaves the relay
with the older retained prefix and allows safe resumption from local state.
Relay commit and generated receipts or route-control followups are best-effort
after that local transition. A failed route does not prevent the same pass from
processing another healthy receive route.

Authentication at rest does not by itself make local state monotonic. The
reference client therefore commits each encrypted generation against separate
host-local rollback authority. Ciphertext and authority advance through a
recoverable transaction; replay, unexplained file loss, and stale writers fail
closed. Every replacement compares the caller's exact prior aggregate with the
committed aggregate under the store lock, so one stale client cannot resurrect
state after another burns it. Explicit destruction leaves an identity-free
erased tombstone. The anchor is local storage authority only and never becomes
a network identity or portable recovery key.

Terminal route teardown is effect-idempotent: a fresh authenticated repeat
returns the existing tombstone, while all non-teardown operations stay rejected.

Freshness and local chronology use receiver-observed time. A peer timestamp is
authenticated metadata, never the sole authority for future expiry or state
advancement.

Routes can move independently of relationship identity. A replacement route is
registered, advertised as `testing` through the old path, targeted by a probe,
then promoted while the old route drains through bounded overlap before
teardown. The client journals the exact create request and every accepted
rollover boundary so restart can resume or explicitly discard a terminal
failure without inventing a completed transition.

Encrypted attachment chunks use the same durability discipline. Each upload
has a 32-byte idempotency key and canonical body digest. While a chunk coordinate
is retained, an exact retry returns the original result without extending
expiry or rewriting storage; changed ciphertext, key, or expiry conflicts.
Relay info reports the configured default and maximum TTL, and storage enforces
an absolute 2,592,000-second (30-day) ceiling.

## 7. Delivery meanings

Noctweave distinguishes local persistence, relay acceptance, peer storage, and
peer read. Network or WebSocket acknowledgement is below those layers. A relay
cannot truthfully assert that a peer read end-to-end encrypted content.

## 8. Groups

Group state uses group-scoped handles, one active credential per member,
signed roles and permissions, linear epochs, commits, and welcomes. Credential
replacement is approved by the old key and proven by the new key in one commit.
An epoch publication binds the signed commit, authoritative signed next state,
exact provider commit bytes, and destination-specific signed welcomes. Peer
processing atomically stores verified signed/provider state and a replay
journal. Exact replay is idempotent; a conflicting same-base transition retains
bounded digest-only fork evidence.

Joining requires a group-only anchor delivered through an already encrypted
invitation; a Welcome cannot authenticate its own destination. Accepted removal
of the local credential is terminal and clears sendable work. Group deletion
first persists an exact signed tombstone as local outbox or inbound terminal
state, clears pending application/epoch work atomically, and rejects later
resurrection. Runtime state is bounded to 32 MiB, and group cryptographic
operations propagate PQ runtime/algorithm failures rather than treating them as
peer authentication failures.

Typed immutable group events use negotiated content capabilities. Exact sealed
application envelopes remain in a durable runtime outbox; retries reuse that
ciphertext and inbound replay receipts prevent a second ratchet advance.

The group runtime now persists credential-signed peer route announcements,
recipient authorization snapshots, exact fixed-size packets and attempts, and
complete application/route-announcement/transition/Welcome/deletion work before
relay I/O. A direct route revision must hash-chain to its predecessor; a
strictly newer credential-signed monotonic checkpoint is accepted only after
missed revisions and cannot move issue time backwards. Each local group route
independently persists its ordered cursor,
digest chain, partial reassembly, processed effects, and quarantine before
authorizing relay garbage collection. Headless APIs orchestrate creation, text
send, bounded sync, maintenance, admission/add/join, exact-operation resume,
and deletion.

The admission artifacts remain transport-neutral and must cross a
caller-selected authenticated encrypted channel. They create only one
group-scoped credential; they do not create an account, contact, device, or
cross-group continuity link.

This design learns state-machine discipline from MLS, but the current PQ
provider has custom wire and cryptography. Complete transport orchestration is
implementation evidence, not a cryptographic audit. The provider still needs
independent review, cross-implementation vectors, fuzzing, and live
process-termination testing and must remain labeled experimental.

## 9. Federation and deployment

Noctweave is a protocol and toolkit, not a mandatory hosted service. A single
self-hosted relay in `solo` mode is complete. `manual`, `curated`, and `open`
federation are explicit operator decisions with different trust and discovery
rules. They are never silently combined.

Relay requests use exact module/version/method envelopes. A relay advertises
only modules it actually implements. The provisional 1.0-candidate surface
covers health/info, opaque routes, rendezvous transport, encrypted blobs, and
federation. Both relay implementations publish the same exact
`nw.opaque-route@2` registry: 68-byte cursors, 256-packet pages, 65,536-byte
packets, 1,024 packets per route, 604,800-second retention, and 100,000 routes.

## 10. Wake and privacy research

Experimental optional wake/prefetch is route-scoped and carries no identity,
label, message count, or plaintext. It wakes the client to perform normal
authenticated sync and is not required for message availability.

PIR, onion, mixnet, and open discovery work is modular and experimental.
Encryption, opaque routes, or a mix transport do not by themselves prove
anonymity. Each deployment must state its observer model and residual metadata.

## 11. Burn and continuity

Burn deletes the old local persona record and its live authority, then creates
an unrelated empty container. No recoverable archived identity remains. Relay
packets may survive until route expiry, and remote parties may retain data they
already received.

An asynchronous relationship or group construction is guarded by a
non-serializable process-local persona-scope token minted before it starts.
Burn or restart invalidates the token, preventing the late result from entering
the replacement persona without creating a protocol account or recovery link.

Continuity is a separate opt-in relationship control: one chosen contact may
receive a successor one-use pairing invitation. Other contacts receive no
protocol link.

## 12. Security and assurance

The repository enforces deterministic encodings, strict field sets, bounded
resources, replay controls, persistence checks, negative tests, and
cross-language vectors. These controls reduce implementation ambiguity; they
do not constitute a formal proof or independent security audit.

Production assurance requires external analysis of direct and group
cryptography, side channels, secret zeroization, parser fuzzing, relay abuse and
load behavior, federation operations, and the metadata of every optional
privacy profile.

## 13. Non-goals

Noctweave 1.0 does not provide accounts, device authorization, multi-device
self-sync, account recovery, permanent managed history, public social
discovery, guaranteed OS-background delivery, global anonymity, or MLS
interoperability.
