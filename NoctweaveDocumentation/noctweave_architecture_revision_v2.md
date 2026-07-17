# Noctweave Architecture Revision v2

**Status:** implementation draft for the pre-1.0 `architecture-revision` branch
**Scope:** public Swift core, Linux relay, JavaScript client, wire protocol, state
format, groups, and interoperability tests

This revision introduces a durable endpoint-aware event substrate without
changing Noctweave into a global account service. The controlling properties
remain post-quantum identity and bootstrap, pairwise selective continuity,
full identity burn, ciphertext-only self-hostable relays, explicit federation
trust domains, bounded metadata reduction, and fail-closed parsing. The
[Noctweave Identity Philosophy](noctweave_identity_philosophy.md) is the
normative filter for every design in this document.

## Implementation Status

The sections below specify the target architecture. This matrix governs what
the current branch actually claims:

| Area | Current status |
| --- | --- |
| Clean 1.0 state and endpoint records | Active. New profiles originate with one independently keyed local endpoint, signed generation-scoped endpoint set, per-contact relationship shells, and local signed self-sync state. Reusable contact-offer pairing is not the 1.0 rendezvous flow; full peer sets and multi-endpoint fan-out are not published. |
| Certified direct endpoint | Active for one preferred endpoint in the Swift headless and JavaScript browser/Node reference paths. Direct-v4 envelopes use endpoint signing/prekeys, pairwise opaque sender/recipient handles, relationship-blinded certificate references, endpoint-keyed sessions, logical event IDs, and typed application content. Both paths strictly project text and attachments and preserve bounded unknown-content fallback/disposition; Swift additionally applies the closed rotation and burn/reset control set. Uncertified contacts and pre-v4 direct frames are rejected; neither implementation performs multi-endpoint fan-out yet. |
| Direct mailbox synchronization | Active in the Swift headless client, in-process relay, and Linux relay. Consumers use fresh ML-DSA credentials per relay/inbox route; sequences, opaque cursors, commit/remove, persistence, long polling, retention gating, and durable dead-letter progress are implemented. |
| Durable intents | Active for direct send and exact-envelope retry. Other intent kinds are bounded model surface only. |
| Envelope identifier authentication | Active and wire-breaking. The direct envelope signature includes `id`; there is no alternate fallback verifier. |
| Capabilities and typed event models | Relay `info` advertises bounded relay-terminated v2 modules. Swift and JavaScript direct-v4 deterministically negotiate required `nw.core`, `nw.endpoints`, `nw.events`, and `nw.prekeys` v2 capabilities. The exact PQ suite and canonical negotiated digest are bound into pairwise identifiers, root/session derivation, authenticated context, signatures, and shared vectors; missing modules, version gaps, reduced limits, and alternate formats fail closed. |
| Removed identity-bearing relay surfaces | Fingerprint-addressed pairing, relay prekey lookup, relay-backed groups, and destructive inbox-wide acknowledgement are outside the 1.0 relay surface. Git history, not production branches, retains their pre-1.0 record. |
| Route sets | Per-contact v2 relationship containers are persisted, and verified route snapshots have a bounded state-transition model. Relationship exchange and end-to-end route rotation are not wired. |
| Self-sync and rendezvous | Endpoint-signed, source-ordered, epoch-sealed self-sync records and one-use purpose-bound PQ rendezvous are implemented as bounded foundations. The identity-blind relay rendezvous transport is available when explicitly enabled. Client pairing publication, full projection integration, and multi-endpoint participation remain unfinished. |
| Read-only history transfer | Active as a local Swift export/import and cryptographic-packaging API. The metadata-bearing signed inner archive is wrapped in a recipient-KEM outer transport seal with fixed size buckets; import is bounded, authorized, and replay-protected. Same-generation transfer is the default; cross-generation transfer requires a distinct expiring approval and remains inert. No default transfer adapter, managed history service, attachment-byte transfer, or endpoint admission is implied. |
| Endpoint-aware groups | Additive signed-state foundation: externally pinned one-owner genesis trust, group-scoped client handles, generation-authority/endpoint/client-possession admission projections, full-state commits, roles/policies, bounded Welcomes, and a 128-active-leaf limit for the current O(n) PQ provider. Trusted-state distribution, private relay delivery, persistence, and restart integration remain unfinished. No fingerprint-addressed relay group path is retained. |

This matrix distinguishes active paths from foundations without claiming that a
public data type is already negotiated or transported by every client.

## 1. Identity Generations And Local Endpoints

An identity generation is the bounded lifetime of one Noctweave identity,
inbox, endpoint set, self-sync stream, and route authority. It is not a
permanent public persona.

Each local endpoint is a cryptographic participant scoped to that generation.
It is not a durable device attached to an account. Each endpoint has:

- an opaque, generation-bounded local endpoint identifier;
- independent ML-DSA signing and ML-KEM agreement keys;
- independent prekey state;
- an authorization epoch and optional revocation epoch;
- bounded protocol and content capabilities;
- independent mailbox cursor state;
- relationship-scoped peer handles where disclosure is necessary.

An identity burn creates a new identity generation. The previous inbox,
endpoint-set manifest, self-sync stream, outstanding pairing offers, and route
authority do not silently carry forward. Continuity is disclosed only through
the existing contact-scoped reset mechanism.

An endpoint-set manifest is signed by the current identity-generation
authority and advances monotonically. A removed endpoint cannot create new
actor proofs, receive new route material, or count toward mailbox retention.

Fresh contact offers do not expose the full endpoint graph. They carry a
compact identity-signed manifest checkpoint and one independently verifiable
preferred endpoint authorization with identity-authority and endpoint-
possession signatures. The active direct path deliberately selects only that
endpoint. Encrypted endpoint-set updates and multi-endpoint fan-out remain
follow-up work.

After two offers are imported, each side independently derives the same
pairwise relationship identifier from the two authenticated random identity-
generation identifiers. Imported endpoint certificates authenticate those
generations, while later continuity-key rotation does not rename the
relationship. Endpoint handles and certificate references are
then derived under that relationship. They are stable for the pinned endpoint
session but differ across contacts. This deliberately trades pairwise stability
within an identity generation for unlinkability at the relay boundary. A
relay-visible direct context contains only the constant typed-payload format,
logical event ID, pairwise
handles, relationship-blinded certificate references, and manifest epochs; it
does not contain public keys, prekeys, manifests, global endpoint UUIDs, or
identity fingerprints. Inbox registration is separately privacy-minimized and
does not upload a contact offer. Its explicit `registrationVersion = 2` proof
binds only the inbox address, inbox-access public key, version, time, and nonce.
The relay verifies address derivation and key possession, then persists no
identity, contact, endpoint-set, endpoint-certificate, or prekey material. A
missing or altered discriminator fails validation.

Authority rotation retains the generation-scoped endpoint keys and the already
pinned endpoint session; the encrypted continuity event authorizes the new
identity authority key inside the same generation. It does not silently replace
certificate references on an old ratchet and is not a privacy burn.
Identity burn first durably stages the exact reset ciphertext through the old
endpoint session, then cuts over locally to a fresh generation and endpoint
after its fresh inbox and consumer are registered. It does not
wait for any contact relay to accept a reset. Each retained relationship
remains send-blocked until its staged reset reaches that contact's relay;
unselected relationships receive no continuity disclosure. A compact
identity-signed endpoint-key rejection record can be delivered as an encrypted
control and fails closed once applied. That signal blocks the peer endpoint but
does not by itself complete local endpoint removal; route, self-sync, group, and
delivery cleanup must also finish. The endpoint certificate stays pinned to its
issuing authority, while a later rejection record is verified with the
contact's current continuity key so a verified authority rotation does not
strand removal authority on a discarded secret.

Signed-prekey freshness is a bootstrap rule, not an established-session kill
switch. Persisted endpoint certificates are revalidated against the signed
prekey package's publication time when a client reopens local state; creating
a new inbound or outbound
direct-v4 session still requires the selected signed prekey to be current.
Established endpoint-bound ratchets continue after that publication lifetime
until rotation, revocation, or another authenticated control transition.

The preferred endpoint authorization and its signed-prekey publication have
separate lifetimes. The generation authority and endpoint-possession proof bind
the stable endpoint keys, manifest checkpoint, and capabilities. A separate
endpoint-signed package binds the current signed prekey to that authorization.
The endpoint renews the package before expiry without invoking an account,
recovery, inbox, or identity-copying authority. It retains at most four prior
private signed-prekey records, and only until each authenticated expiry, so a
delayed bootstrap created from an earlier offer can finish without making old
keys permanent. Package renewal leaves pairwise authorization references and
established ratchets unchanged; expired or tampered packages fail closed for
new sessions.

## 2. Identifier Semantics

The protocol separates four identifiers:

| Identifier | Scope |
| --- | --- |
| `clientTransactionId` | One local endpoint's logical operation and retry identity. |
| `eventId` | One immutable application or control event within its authenticated relationship/source scope; not a global user namespace. |
| `envelopeId` | One encrypted delivery copy to one route. |
| `relaySequence` | One relay-local mailbox position. |

Identifiers are never silently substituted for one another. Event and envelope
identifiers are authenticated. Relay sequences are local ordering metadata, not
global timestamps or cross-relay consensus.

## 3. Events And Control Frames

An application event contains a namespaced content type, major and minor
version, bounded parameters, bounded payload bytes, optional encrypted fallback
text, optional encrypted relation, and a visible or silent disposition.

Initial event families are text, attachment, reply, reaction, replacement,
retraction, delivery receipt, and optional read receipt.

Security control frames are separate from custom application content. They
cover identity continuity, endpoint admission, endpoint removal,
route updates, session recovery, group proposals, and group commits.

Unknown application events are authenticated, retained within resource bounds,
and rendered using a bounded fallback or unsupported placeholder. Unknown
control frames never mutate security state and are retained only in a bounded
quarantine.

Relationship event history preserves a bounded recent window. When that window
reaches its limit, the oldest canonical event prefix is committed into a
domain-separated `RelationshipEventCheckpointV2` digest chain with an explicit
cumulative event count and boundary event ID before removal. Compaction keeps
the newest events, is relationship-bound, and must succeed before any event is
removed; a round-tripped checkpoint can therefore continue accepting events
without a silent history drop or a permanent capacity wedge.

The active Swift and JavaScript certified direct-v4 paths bind the constant
`nw.wire-payload.v2` and logical event ID into their authenticated context. The
NPAD-v2 plaintext carries the complete event/content type/version/fallback or
the separately enumerated control payload. Envelope signatures cover the
authenticated context and ciphertext. Visible unknown application events use
fallback projection; silent unknown events and receipts are retained without a
UI message. Unknown controls are quarantined without a synthetic chat message,
and malformed known controls fail before receive-chain state is committed.
The JavaScript reference emits generic application events and strictly projects
the standard text and attachment types. It preserves unknown visible events
with their encrypted fallback and processes silent unknown events without a UI
message; it intentionally exposes no generic control-state mutation API.

## 4. Delivery And Synchronization

Mailbox delivery is an append-only bounded encrypted event log with a monotonic
relay-local sequence. Each authorized local endpoint owns an opaque cursor.

Synchronization returns:

- a bounded ordered batch;
- an opaque next cursor;
- a relay-local numeric high watermark;
- a retention floor;
- a `hasMore` flag.

Committing a cursor means that one endpoint durably verified, decrypted, and
stored all events through that position. It does not delete another endpoint's
delivery state.

Relay retention is bounded by configured mailbox quotas, the retention floor,
active endpoint cursors, and removal epochs. A missing or permanently offline
endpoint can delay garbage collection, but cannot force unbounded storage.

Streaming and long polling reduce latency but do not advance durable cursor
state implicitly. Consumers persist the numeric committed sequence beside the
opaque cursor and reject a first-event, internal, empty-batch, or final-sequence
gap before processing or committing a batch.

Direct delivery uses the envelope ID as the relay idempotency key. Exact retries
are no-ops only when the complete stored material matches; conflicting reuse
fails closed.

The Swift headless client and JavaScript reference client do not treat a bare
historical envelope ID as sufficient proof that a newly fetched item is an
exact duplicate. A bounded persisted receipt binds the authenticated
relationship scope, logical event ID, delivery envelope ID, and digest of the
canonical signed envelope. Logical IDs are not a global namespace across
unrelated contacts. Exact
matches may be skipped after prior durable processing; an ID-to-different-bytes
or envelope-to-different-event conflict is verified and rejected before the
mailbox cursor advances. Once an old receipt is compacted, a replay must pass
the normal signature and ratchet checks instead of being skipped by ID alone.

A structurally valid relay event can still be permanently unusable—for example,
because it names an unknown sender, attempts a certified-profile downgrade,
has invalid attribution, conflicts with a processed event, or fails ciphertext
authentication. The Swift client records only its sequence, canonical envelope
digest, route digest, and bounded reason in a durable local dead-letter journal,
then advances past it in the same atomic cursor workflow. Plaintext and sender
key material are not copied into that journal. Local-state corruption, storage
failure, or unavailable cryptographic primitives remain retryable errors and
do not advance the cursor. This prevents one hostile envelope from causing
head-of-line denial of service without weakening fail-closed control handling.

Delivery state names have exact meanings:

- `locallyPersisted`: sender durably stored the event or ciphertext outbox;
- `relayAccepted`: relay durably accepted the delivery envelope;
- `peerEndpointStored`: at least one intended peer endpoint committed
  the corresponding event;
- `peerRead`: a peer voluntarily emitted an encrypted read event.

Transport acknowledgements do not imply any of these states except the
explicit durable relay response that establishes `relayAccepted`.

## 5. Relationship Route Sets

Relay location is mutable relationship state, not a permanent identity anchor.
A signed encrypted route set contains a version, previous digest, bounded route
entries, validity time, overlap deadline, and signature.

Routes contain an opaque route identifier, endpoint, inbox capability,
relationship-scoped endpoint handle, priority, and state: testing, active,
draining, or revoked.

Both reference relays implement an experimental storage and wire foundation for
the opaque `InboxRouteCapabilityV2`. An inbox authority can create or revoke a
nonzero 32-byte bearer using an ML-DSA actor proof. Authenticated inbox
registration returns a random relay-local scope and the next monotonic
route-mutation sequence. Mutation v3 binds both values; route state, cursor, and
proof-independent digest commit atomically. An already-applied matching
mutation remains an idempotent signed replay after the ordinary proof-freshness
window; a first application still requires a fresh proof. Stale, conflicting,
skipped, and cross-relay mutation requests fail closed.

The relay stores the domain-separated SHA-256 capability digest and inbox
binding, never the raw bearer or a plaintext relationship label.
Capability-addressed `deliver` omits `inboxId` and `routingToken` during
federation forwarding. Malformed bearer objects fail strict request decoding;
well-formed unknown or revoked bearers return an unavailable-route error before
mailbox allocation. Inbox retirement purges the relay scope, cursor, and every
mapping.

This foundation is intentionally disabled by default, omitted from relay
capability advertisements, and not activated by contact offers, discovery, or
the headless direct-v4 sender. The current model still has unresolved privacy
and product constraints:

- the final relay can correlate every capability digest mapped to one inbox
  generation and observe delivery timing and volume;
- 16 active mappings are only bounded test headroom, not a viable
  one-capability-per-relationship scale or rotation budget;
- the registry does not yet enforce short route epochs, renewal, or expiry;
- per-capability quotas and a padding/cover policy are not yet specified; and
- a bearer is write authority, so a valid `RelationshipRouteV2` requires TLS
  except for literal same-host loopback development.

Activation therefore waits for relationship-scoped inboxes or an equivalently
unlinkable queue design, bounded expiring route epochs with make-before-break
renewal, realistic relationship/rotation limits, per-capability abuse controls,
and a documented padding policy. A reusable delivery token must never be placed
in a contact directory.

Route rotation is make-before-break:

1. Register the new route and publish endpoint-signed prekeys.
2. Send the route-set update through the existing authenticated relationship.
3. Test the new route.
4. Use bounded overlap when policy permits.
5. Commit the new route set.
6. Drain and revoke the previous route.

Route sets are not public directories. Redundant routes are optional because
they increase both availability and observable traffic.

## 6. Durable Intents

Multi-stage client operations use an encrypted persistent intent journal.
Intent states are prepared, published, committed, finalized, and permanent
failure. Retryable failures remain in a nonterminal state.

Each intent has an immutable ID, kind, target, idempotency key, expected epoch,
payload digest, bounded dependency list, retry count, error class, timestamps,
and terminal result.

The journal covers message fan-out, attachment finalization, endpoint-set
changes, prekey rotation, route rotation, group changes, and continuity
events. Dependency cycles, unbounded retry, and ambiguous terminal states fail
closed.

The direct ciphertext outbox and its send intents are bounded together. Every
pending ciphertext must retain one exact, unfinalized intent with the same ID,
target, and envelope digest. At capacity, a new send receives backpressure;
pending ciphertext and live intents are never truncated or evicted.
Only terminal records unreferenced by pending delivery, mutation journals, or
live dependencies may be pruned to make room.

The browser reference applies the same boundary to local echo: it clones the
relationship ratchet, assigns distinct client-transaction, logical-event, and
delivery-envelope IDs, then durably stores the candidate chain and exact signed
envelope before network submission. Receive processing likewise clones the
ratchet and persists the decoded event before cursor progress. Storage failure
restores the prior in-memory state; relay retry never causes re-encryption.

A retryable delivery stops automatically at its bounded attempt limit, while a
relay rejection classified as permanent also requires explicit action. In
either case the exact ciphertext and idempotency identity remain persisted and
the client reports `directDeliveryRequiresAction`. An application may call
`rearmPendingDirectDelivery(envelopeId:)` to reset only the retry bookkeeping;
it does not re-encrypt, advance the ratchet, or replace the signed envelope.

## 7. Encrypted Self-Sync And History Transfer

Each 1.0 profile maintains local secret/progress state for one hidden encrypted
self-sync stream. Endpoint-signed, source-ordered records can carry immutable outbound event
copies, endpoint-set and route manifests, selected relationship changes, group
updates,
consent, block and mute state, optional read markers, and user preferences.

No default relay or peer transport publishes these records yet. The stream never
copies shared active ratchet chains, reusable one-time prekeys,
hardware-backed private keys, app-lock credentials, or device-local secrets.

The target new-endpoint flow uses a purpose-bound short-lived rendezvous containing an
ephemeral key, opaque temporary route, one-time token, expiry, and supported
versions. Full PQ material is transferred inside the resulting encrypted
channel.

The current `IdentityProfile` still owns the identity-generation and inbox-
authority private keys. It therefore is not a safe endpoint-transfer shape:
copying it would clone generation, route, ratchet, cursor, and revocation
authority. Live profile export is forbidden. Same-generation endpoint admission
must remain inactive until a purpose-bound rendezvous proves possession of the
new endpoint keys and transfers only a separate participant-endpoint state:
generation public checkpoint, endpoint-local keys and prekeys, one route-local
credential, and the current self-sync secret. It must never transfer identity-
generation authority, inbox-access authority, ratchets, or cursors. Admission
must also be a durable encrypted intent, and the endpoint must sign its own
short-lived rotating prekey packages under a stable generation authorization.

No recovery authority is introduced. Losing the sole generation/inbox-authority
endpoint means creating a fresh generation and selectively disclosing
continuity, but that is abandonment—not a completed burn—unless every old route
can still be cryptographically retired. Multi-endpoint participation remains
inactive until route-local teardown authority or per-endpoint inbox routes make
that distinction enforceable without copying an inbox private key.

History transfer is separately approved, bounded, encrypted to the receiving
endpoint, transactional, replay-protected, and transported directly or
through user-selected infrastructure. No managed history service or key escrow
is required. The signed inner archive, including endpoint IDs,
public keys, timestamps, counts, and signatures, is itself hidden inside a
second recipient-KEM transport seal. Its clear wrapper contains only a version,
KEM ciphertext, AES-GCM nonce, fixed-bucket padded ciphertext, and tag. The
64-KiB through 64-MiB padding classes hide the exact inner size while retaining
explicit memory and wire bounds. Importing history does not authorize future
participation. Applications must atomically persist the inert projection and
updated replay ledger; successful in-memory validation is not a durable commit.

## 8. Group Clients And Crypto Providers

Group state separates:

- a contact-level `GroupUser`;
- an endpoint-level cryptographic `GroupClient`;
- a versioned `GroupCryptoProvider`.

One user can have multiple group clients. Removing one endpoint removes only
that client. Signed roles and permissions are included in the group
transcript and independently checked by clients; relay checks are defense in
depth.

Genesis does not trust keys contained only in the proposed group state. It
requires externally pinned creator trust: one owner user, one creator leaf, a
current identity-signed endpoint-set manifest, and a full identity-authority,
endpoint-possession, and client-possession signed key package. Post-genesis commits
then advance from that independently authenticated root.

The existing group construction remains the experimental Noctweave PQ group
profile and does not claim RFC 9420 conformance. Its active wire identifier
is `noctweave-pq-group-experimental-2`, while the v2 provider model names it
`nw.pq-group.experimental-2`. Any conforming MLS or future PQ MLS profile is
negotiated under a distinct identifier and requires independent
interoperability evidence.

The Core currently includes an isolated signed-state foundation for this
future endpoint-aware path. It authenticates complete membership, role,
policy, metadata-digest, epoch, transcript, author, provider-commit, and
Welcome state. No relay-backed group path is exposed by the 1.0 relay surface.
The current O(n)
experimental PQ provider is capped at 128 active endpoint leaves; the larger 4,096-leaf model bound
is reserved for future providers with separately reviewed scaling behavior.

Before creating an `addClient` or `addUser` commit, the caller verifies a full
`GroupClientKeyPackageV2` against an authenticated identity authority and
current trusted `EndpointSetManifest`. The shared commit then carries one
`GroupClientAdmissionProjectionV2`, not identity fingerprints, endpoint IDs,
endpoint certificates, manifests, or contact evidence. The commit signature
covers that projection, and the added leaf must exactly match it. Sibling
endpoint admission additionally requires `GroupSiblingClientConsentV2` from an
active group client belonging to that user. Trusted-state distribution and
freshness tracking remain part of connecting this foundation to an active
client workflow; they are not delegated to a relay.

Role policy is also bounded by hierarchy rather than treated as unrestricted
permission delegation. For a non-self role change, the actor must outrank the
target before the change and cannot grant a role above the actor's own role.
A self-role change is permitted only as an explicit strict demotion. Even when
`updatePolicy` is configured as `admin` or `everyone`, members and admins cannot
rewrite equal or higher-privileged users or promote themselves, and every
accepted state must retain at least one active owner.

## 9. Protocol Modules And Capabilities

The protocol keeps a descriptive catalog of versioned capability modules:

- `nw.core`
- `nw.mailbox`
- `nw.prekeys`
- `nw.events`
- `nw.endpoints`
- `nw.routes`
- `nw.blobs`
- `nw.groups`
- `nw.wake`
- `nw.federation`
- optional `nw.privacy.*` modules

Catalog membership is not a support claim. A default endpoint manifest
advertises only the active direct-v4 path: `nw.core:2`, `nw.endpoints:2`,
`nw.events:2`, and `nw.prekeys:2`. `nw.endpoints` advertises
`maxActiveEndpoints: 1` until peer fan-out is implemented; the larger endpoint
manifest storage bound must not be mistaken for delivery support. All other
modules require explicit opt-in by a caller that has wired them.

This decomposition does not require separate processes. One relay binary can
implement every selected module. Relay `info` separately advertises the
relay-terminated modules and concrete limits it actually supports. Direct-v4
endpoint negotiation selects the four required shared v2 modules under fixed
profile ceilings, authenticates the exact
`nw.direct-v4.ml-kem-768.ml-dsa-65.hkdf-sha256.hmac-sha256.aes-256-gcm`
suite plus a canonical 32-byte capability digest, and rejects missing modules,
version gaps, altered limits, suite tampering, and alternate-format downgrade before
ratchet state commits. Optional module declarations never enter that direct-v4
digest.

Extension status is experimental, provisional, stable, or deprecated. Stable
extensions require a normative specification, errors, examples, limits,
state-transition behavior, and cross-language conformance vectors.

## 10. Clean 1.0 Baseline

Noctweave 1.0 starts with current state. A new profile creates one disposable
identity generation, one independently keyed local endpoint, fresh prekeys, a
separate route credential, and signed generation-scoped self-sync state.
Research-era profiles, wire messages, and relay records are unsupported input;
they are not upgraded or retained behind runtime flags.

Certified direct-v4 now requires `WirePayloadV2` in an NPAD-v2 frame. Text and
attachment sends create distinct client-transaction and event identifiers and
persist the immutable event before delivery; exact-envelope retry reuses both.
`MessageBody` wire encoding is not available to direct sessions. The current
experimental group profile uses its own `NWGP-v1` frame, which a direct-v4
decoder rejects. Direct-v4 negotiates only within its exact authenticated
profile and has no fallback path. Security
control messages never downgrade to custom application content.

Mailbox-v2 cursor synchronization is the only 1.0 mailbox state model. The
first consumer registration binds a fresh
route-scoped signing key with independent inbox-authority and possession
proofs. It never publishes the endpoint signing key for a newly created
route. Every later fresh binding also requires an active bound consumer's
sponsor proof over the full registration; authority alone cannot add a
consumer. Existing same-ID/same-key registration remains idempotent. If all
consumers are revoked, continuing requires a new inbox and identity generation.
Only the bound route credential may sync or commit, while the inbox authority
retains revoke power.
Relays cap active consumers at 16, not lifetime registrations. They retain a
bounded history of 64 active/revoked records and compact the oldest revoked
tombstones during endpoint churn.

The final relay rejects delivery to an unregistered destination, so a sender
cannot allocate persistent mailboxes by guessing syntactically valid inbox
addresses. Registered inboxes still require relay-side quota and rate policy;
future pairwise delivery capabilities can tighten admission without exposing
sender identity to the relay.

Old or security-ambiguous state fails closed as unsupported. Git history is the
record of pre-1.0 research state.

## 11. Acceptance Gates

The revision is complete only when:

- Swift and JavaScript share positive and negative vectors;
- endpoint removal and identity burn fail closed;
- one endpoint cannot consume another's delivery state;
- cursor expiry and retention floors have deterministic recovery;
- logical retries create one event and bounded delivery copies;
- route rotation never leaves both old and new routes invalid;
- group-client removal preserves sibling endpoints;
- unknown application and control events follow their distinct rules;
- all remote and persisted structures enforce fixed bounds;
- `solo`, `manual`, `curated`, and `open` remain separate;
- all public build, test, vector, and documentation checks pass;
- security claims and remaining external review needs are documented honestly.
