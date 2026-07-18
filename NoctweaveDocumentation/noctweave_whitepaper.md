# Noctweave

## A pairwise-private post-quantum messaging architecture

### Abstract

Noctweave is a self-hostable encrypted messaging protocol in which a local
persona never becomes a network identity. Each pairwise relationship and group
is a fresh cryptographic context. Direct relationships use ML-DSA-65 for
authentication, ML-KEM-768 for asynchronous establishment and PQ root refresh,
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
messages consume a valid endpoint-signed ML-KEM prekey. A symmetric chain
ratchet derives message keys; periodic ML-KEM operations refresh the root.
Bounded skipped-key state supports ordinary reordering without unbounded
allocation.

Application events are padded and encrypted. Security controls carry their own
relationship, event, sender, time, nonce, and signature binding. Unknown
application formats can be retained safely; unknown controls do not execute.
Consent, message-request state, mute, receipt preferences, and block are local
to one relationship. A safety number compares only its two disposable
relationship-authority keys.

## 5. Event semantics

Messages are immutable events. Replies, edits, reactions, retractions, and
receipts refer to an earlier event inside ciphertext. A local transaction ID
survives retries, while an event ID names the logical action and packet IDs name
individual relay delivery copies.

The client persists the event, mutation intent, and exact encrypted packets
before publication. This provides local echo and makes retries idempotent even
after a crash.

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

Routes can move independently of relationship identity. A replacement route is
registered, advertised as `testing` through the old path, targeted by a probe,
then promoted while the old route drains through bounded overlap before
teardown.

## 7. Delivery meanings

Noctweave distinguishes local persistence, relay acceptance, peer storage, and
peer read. Network or WebSocket acknowledgement is below those layers. A relay
cannot truthfully assert that a peer read end-to-end encrypted content.

## 8. Groups

Group state uses group-scoped handles, one active credential per member,
signed roles and permissions, linear epochs, commits, and welcomes. Credential
replacement is approved by the old key and proven by the new key in one commit.
Crash-safe intents preserve dependent work, and conflicting forks are
quarantined.

Typed immutable group events use negotiated content capabilities. Exact sealed
envelopes remain in a durable outbox until opaque-route fanout accepts them;
retries reuse ciphertext and inbound replay receipts prevent ratchet advance.

This design learns state-machine discipline from MLS, but the current PQ
provider has custom wire and cryptography. It needs independent review and must
remain labeled experimental.

## 9. Federation and deployment

Noctweave is a protocol and toolkit, not a mandatory hosted service. A single
self-hosted relay in `solo` mode is complete. `manual`, `curated`, and `open`
federation are explicit operator decisions with different trust and discovery
rules. They are never silently combined.

Relay requests use exact module/version/method envelopes. A relay advertises
only modules it actually implements. The stable surface covers health/info,
opaque routes, rendezvous transport, encrypted blobs, and federation.

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
