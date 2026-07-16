# Noctweave Identity Philosophy

**Status:** normative design filter for all pre-1.0 architecture work

Noctweave is not an account system with privacy features added around it. It is
a private messaging protocol built from disposable identity generations,
pairwise relationships, ciphertext-only delivery, and user-controlled
infrastructure.

This document decides whether an idea belongs in Noctweave before that idea is
allowed into the protocol.

## Core Invariants

1. **No permanent account.** The protocol has no global account identifier,
   recovery authority, device registry, or provider-controlled user record.
2. **Identity generations are disposable.** One generation owns its own
   identity keys, endpoint keys, prekeys, inboxes, route authority, endpoint
   set, and self-sync state. None of those objects silently survives a burn.
3. **Continuity is pairwise and optional.** A user may disclose a transition to
   selected relationships. No global continuity record or public directory is
   required, and unselected relationships receive no cryptographic link.
4. **Endpoints do not become identities.** A phone, desktop, or browser may be
   an independently keyed endpoint inside one generation. Its authorization is
   bounded by that generation and must prove possession of its own keys.
5. **A burn destroys reachability.** Completion requires retiring every known
   old inbox route, removing old endpoint and self-sync authority, discarding
   old private state, clearing local cross-generation audit links, and sending
   continuity only to explicitly selected contacts.
6. **Relationships reveal the minimum.** Endpoint handles, certificate
   references, and routes are relationship-scoped wherever practical. Relays
   are never given identity fingerprints, explicit contact or endpoint graphs,
   or plaintext social metadata. Unavoidable inference at a final relay must
   be stated precisely: if several opaque routes terminate at one inbox, that
   relay can correlate them to the inbox generation and observe their traffic.
   A feature is not privacy-preserving merely because its labels are opaque.
7. **Infrastructure remains replaceable.** Relays store and route bounded
   ciphertext. Self-hosting and explicit federation trust domains remain
   first-class; no vendor account, history service, push service, or recovery
   service becomes mandatory.
8. **Features fail closed and stay bounded.** Unknown security controls cannot
   mutate state. Logs, queues, endpoint sets, replay records, archives, and
   retries all have explicit limits and deterministic recovery behavior.

## Terminology

| Term | Meaning |
| --- | --- |
| Identity generation | A deliberately bounded cryptographic lifetime, not a stable account or persona. |
| Local endpoint | One independently keyed protocol participant within one identity generation. |
| Endpoint set | The bounded endpoints authorized only for the current generation. |
| Relationship | Pairwise local state and optional continuity between two parties. |
| Identity burn | Creation of an unrelated generation plus complete old-generation teardown. |
| Authority rotation | A continuity-preserving key transition inside the same generation; it is not a privacy burn. |

Some pre-1.0 source types still contain the compatibility word
`Installation`. In protocol design and user-facing documentation, read that as
**generation-scoped local endpoint**, never as a durable device attached to an
account. Compatibility naming must not weaken the invariants above.

## The Borrowing Filter

An external protocol feature may be adopted only when all of these answers are
acceptable:

1. Does it work without creating a stable global user, account, recovery key,
   public device ID, or permanent inbox?
2. Is every new identifier bounded to a generation, relationship, route, or
   local database?
3. Can a user burn an identity without an old provider, old endpoint, or
   recovery authority linking the replacement?
4. Can relays implement it while remaining plaintext-blind and without learning
   the contact or endpoint graph?
5. Is authorization proven cryptographically, purpose-bound, expiring where
   appropriate, replay-safe, and resource-bounded?
6. Does failure preserve the previous durable state or leave a resumable,
   idempotent journal?
7. Can self-hosted and federated deployments use it without a privileged vendor
   service?

If any answer is no, the feature is redesigned, isolated as an explicitly
experimental extension, or left out.

## Good Lessons We Keep

- Independently keyed endpoints, because shared ratchet and prekey state is
  unsafe, but endpoint authorization ends with its identity generation.
- Ordered encrypted event streams, opaque per-endpoint cursors, idempotent
  transaction IDs, local echo, and distinct relay-accepted/delivered/read
  states.
- Typed immutable application events, separate authenticated control frames,
  and explicit capability/ciphersuite negotiation bound into transcripts.
- Durable mutation intents for crash-safe sends, route changes, endpoint-set
  changes, group commits, and burns.
- Pairwise opaque routes with make-before-break migration, bounded overlap, and
  authenticated retirement.
- Explicit group roles and policies inside signed group state, with each local
  endpoint represented independently.
- Read-only encrypted history projections that contain no live keys, ratchets,
  route authority, cursors, or implicit authorization.
- Modular relay capabilities and a small stable core with separately named
  experimental privacy extensions.

## Ideas We Leave Out

- Stable inbox accounts, global device graphs, permanent recovery authorities,
  provider-managed identity, and phone-number or wallet account assumptions.
- Exporting or importing a live profile containing private identity keys,
  ratchets, prekeys, routes, cursor state, or self-sync authority.
- Public user IDs, public relay lists, public contact graphs, server-readable
  event relations, or globally reusable endpoint identifiers.
- Destructive single-consumer queues as the synchronization model, permanent
  relay history, or a required centralized history server.
- Gossip-based broadcast delivery as the default direct-message transport.
- Shared live ratchet state across endpoints or silent fallback to legacy
  ciphersuites and wire formats.
- Calling a manifest-only endpoint removal "revocation" when routes, self-sync,
  group state, and delivery authority have not also been removed.

## Required Burn Postconditions

After a completed burn:

- the new identity, generation ID, endpoint keys, prekeys, inbox ID, inbox
  access key, route credentials, and self-sync secret are freshly generated;
- every known old inbox has an authenticated, durably retryable retirement;
- old relays reject new delivery and consumer registration for retired inboxes;
- no old private key remains solely to finish cleanup;
- no old conversation ratchet, group state, route set, cursor, endpoint
  manifest, or self-sync event is active in the new generation;
- the local profile contains no general old-to-new continuity record;
- only selected contacts receive an old-key-authenticated reset message; and
- those reset messages are exact durable ciphertexts retried idempotently.

A key swap that does not satisfy these postconditions is an authority rotation,
not an identity burn.

If the only endpoint holding an old inbox authority is lost, creating a fresh
generation is local abandonment, not a completed burn. Noctweave must say so
plainly; it must not disguise the missing remote teardown with a recovery
account or by copying authority keys across endpoints. Multi-endpoint support
stays inactive until each admitted endpoint can participate and be removed
without weakening these postconditions.

## Conformance Rule

Every new architecture proposal must state:

- its identifier and authority scopes;
- what survives identity burn and why;
- relay-visible metadata;
- unlinkability limits, including colluding contacts or relays;
- bounded-resource limits;
- downgrade behavior;
- crash and retry semantics; and
- deterministic tests for its security-relevant invariants.

Passing ordinary functional tests is necessary but insufficient. A change that
violates this philosophy is a failed change even when its test suite is green.
