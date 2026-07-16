# Noctweave Protocol v1 Compatibility Specification

This document records the compatibility surface that predates the pre-1.0
architecture revision. It remains relevant because the current relay request
envelope and explicit pre-v4/group compatibility payloads are still present, but it is no longer
the architectural direction for new integrations. New work starts with
[Noctweave Architecture Revision v2](noctweave_architecture_revision_v2.md),
then uses this document only where the v2 status matrix identifies an active
compatibility path.

Noctweave is still pre-1.0. The revision deliberately changes wire and state
formats rather than preserving unsafe single-endpoint assumptions. A v1
label here is not a claim that the protocol has reached a stable 1.0 release.

## Cryptographic Profile

- Identity signatures: ML-DSA-65 through liboqs.
- Session establishment: ML-KEM-768 prekey bundles and one-time prekeys.
- Message encryption: AES-256-GCM over padded plaintext envelopes.
- Key derivation: HKDF-SHA256 and HMAC-SHA256.
- Identity continuity: signed rotation statements, selective contact disclosure, and full identity burn semantics.

## Identity And Inboxes

Each identity owns a signing key, prekey state, contact book, relay list, and one or more inbox routing addresses. Inbox addresses are routing identifiers, not human identifiers. A relay must not treat an inbox address as proof of identity; protected routes require actor proofs bound to the relevant inbox or group state.

New inbox registration uses the privacy-minimized
`RegisterInboxRequest.registrationVersion = 2` profile. Its canonical access-key
proof binds only `inboxId`, `accessPublicKey`, `registrationVersion`, `signedAt`,
and a replay-protected `nonce`. The relay verifies that the address is derived
from the supplied key and that the registrant possesses that key. A v2 request
must not contain a `ContactOffer`, endpoint-set manifest, endpoint certificate,
prekey, display name, or identity signing/agreement key. The relay persists only
the inbox address, access public key, registration time, and mailbox stream
state. Identity and contact establishment remain end-to-end client operations.

For pre-1.0 compatibility, a decoded registration with no
`registrationVersion` follows the legacy contact-offer-bound verifier. The
absence of the discriminator is not a negotiable downgrade: unknown versions,
v2 requests containing a contact offer, and v2 proofs replayed after removing
the discriminator fail closed. New integrations must emit v2.

Architecture-v2 state migration additionally creates an identity-generation
identifier, independently keyed local endpoint, signed endpoint-set manifest,
and relay-route-scoped mailbox consumer. Fresh direct-v4 contact
offers publish a compact signed manifest checkpoint and one certified preferred
endpoint. Full-manifest publication, encrypted endpoint-set updates,
multi-endpoint fan-out, same-generation endpoint admission, encrypted self-sync transport,
and relationship route-set exchange remain additive work rather than active
wire behavior.

The reference relays contain a bounded experimental opaque-route foundation,
but it is disabled by default and omitted from capability advertisements.
`createInboxRouteCapability` and `revokeInboxRouteCapability` bind a nonzero
32-byte bearer to the registered inbox authority. Registration returns a random
scope local to that inbox generation and relay. Mutation v3 signs the scope and
a monotonic sequence; route state, sequence, and proof-independent digest commit
atomically. Matching already-applied mutations remain signed idempotent replays;
new mutations require fresh proofs. Stale, conflicting, skipped, and cross-relay
mutation requests fail closed. Malformed bearer objects fail request decoding;
well-formed unknown or revoked values fail before mailbox allocation. Raw
bearers are never persisted, and inbox retirement purges the scope, cursor, and
all mappings.

The final relay does learn that all registered capability digests resolve to
one inbox generation and can observe their delivery timing and volume. The
current limit of 16 active mappings is bounded test headroom, not a realistic
one-token-per-relationship design. The current registry also lacks enforced
route expiry/renewal, per-capability abuse quotas, and a complete padding
policy. Accordingly, no client, contact offer, discovery service, or global
directory publishes these values. Capability routes require confidential
transport except literal loopback, and activation remains blocked until a
relationship-scoped inbox/queue design plus bounded expiring rotation and abuse
controls exist. Direct-v4 must never publish one reusable global delivery token.

Authority rotation (named `rotateIdentity` by the compatibility API) preserves
continuity only for contacts selected by the user.
The initiating API takes an explicit bounded set of local contact UUIDs,
including an explicit empty set. It produces one relationship-private,
old-key-authenticated rotation statement per selected contact and no rotation
statement for any unselected contact. Unknown identifiers fail closed, and a
retry may not widen or otherwise change the durably journaled recipient set.
Because rotation stays inside the same identity generation, an empty selection
is not an unlinkability guarantee and does not retire routes or endpoints;
identity burn is the severance operation.
Identity burn intentionally severs continuity for unselected contacts. A burn
first persists each selected contact's exact reset ciphertext under the old
endpoint session, registers the new local inbox and mailbox consumer, and
then cuts local state over to the fresh identity generation. It does not wait
for a contact's remote relay to accept that reset. Each selected relationship
remains send-blocked until its staged reset is accepted by that contact's
relay; unselected contacts receive no continuity disclosure.

Before deleting the old inbox-access private key, the burn journal also creates
and durably stores the exact signed `RetireInboxRequest`. Retirement is bound to
the old route-level inbox and access key; it carries no identity, contact, or
endpoint-set metadata. A successful relay mutation atomically removes the
registration, mailbox consumers and stream state, plus every queued direct or
group envelope at that inbox, then writes a compact, non-expiring
non-resurrection record. Delivery, consumer registration, and inbox
re-registration fail permanently for that relay storage namespace. The exact
signed request may be retried indefinitely and returns success after completion,
while a changed request does not match the durable record. A valid self-bound
request for an inbox with no live registration creates the same record, so a
pre-signed burn remains effective after partial relay-state recovery.

Exact non-resurrection has an information-storage lower bound. The reference
relay therefore admits at most 100,000 inbox generations over one storage
namespace's lifetime. A live registration reserves its eventual retirement
slot; retirement of an admitted generation cannot be displaced by newer burns.
At the lifetime ceiling, new first registrations and previously unseen
unregistered retirement requests fail closed. Records are never expired or
evicted. Operators must preserve this table in backups and provision a new relay
namespace before exhausting the lifetime ceiling.

This operation deliberately differs from ordinary actor proofs: it has no
timestamp freshness expiry and does not consume the general proof-nonce replay
cache. Retirement is monotonic and irreversible, so replay can only repeat the
authorized deletion. Its inbox/key binding plus the live durable exact-request
digest are the replay boundary. This permits a client to delete every old
private key immediately after cutover without making relay cleanup depend on a
short online window. A later identity generation must always use a new inbox
address; an old inbox ID is never recycled.

The relay-backed group compatibility path is scoped to an identity fingerprint
and is disabled unless the relay operator explicitly enables the deprecated
`nw.compat.legacy-fingerprint` profile.
The headless client therefore rejects a new identity rotation while any active
non-invitation legacy group remains. Rotating would otherwise strand membership,
fetch authorization, and pending acknowledgements under the old fingerprint.
Users must leave those groups or migrate them after the signed
endpoint-aware group path becomes active. Resuming an identity-rotation
journal that was already durably created remains allowed.

## Direct Message Flow

The currently implemented signed contact offer is reusable compatibility
pairing material. Reusing it exposes the same identity generation, preferred
endpoint authorization, inbox, and relay details to each recipient, so it must
not be described as a one-time or unlinkable rendezvous. A future
purpose-bound, expiring rendezvous flow is tracked separately.

1. A client obtains or imports a contact offer containing identity material, inbox routing data, and prekey material.
2. The sender derives a session using the PQ prekey flow.
3. The message body is encoded into a supported fixed-size padding bucket,
   encrypted with AEAD, and wrapped in an `Envelope`. Decoders reject malformed,
   non-canonical, or legacy unpadded plaintext.
4. The sender persists the sealed envelope in a local ciphertext outbox, then submits `RelayRequest.type = deliver`. Retries reuse the original envelope identifier and ratchet counter.
5. The current headless recipient synchronizes ordered sealed envelopes with
   a fresh ML-DSA credential bound only to that relay/inbox route. The inbox
   authority is used only to register or revoke that consumer. The client
   verifies, decrypts, and durably saves the advanced state before committing
   the returned cursor. A pending cursor commit is itself persisted so restart
   can safely complete it. Permanently invalid remote envelopes are recorded
   as bounded, plaintext-free dead letters before the same cursor workflow
   advances; local storage or crypto-runtime failures remain retryable.

Certified direct-v4 uses the `NPAD` v2 frame and `WirePayloadV2`, identified by
the authenticated context constant `nw.wire-payload.v2`. Application payloads
contain an immutable `ConversationEvent` and versioned `EncodedContent`;
security-sensitive identity rotation/reset and session recovery values use the
separate `AuthenticatedControlPayloadV2` family. The logical `eventId`, the
endpoint-local `clientTransactionId`, and the delivery `envelope.id` are
distinct. The event/type/version/fallback bytes are inside the AEAD plaintext,
the event ID and payload-format discriminator are in authenticated direct-v4
context, and the envelope signature covers that context plus the ciphertext.

Unknown application content is retained in the bounded relationship event log.
Visible content uses its encrypted fallback or an unsupported placeholder;
silent unknown content and receipts are retained without creating a chat
bubble. A structurally valid unknown control is retained in the bounded control
quarantine, advances delivery state, and never mutates contact/session security
state. A malformed payload for a known control fails transactionally without
advancing the receive chain.

`NPAD` v1 `MessageBody` decoding is explicit compatibility behavior for
pre-direct-v4 sessions and the current experimental group profile. A direct-v4
decoder accepts only the v2 typed frame, while a legacy/group decoder accepts
only v1; neither format is probed as a fallback for the other.
Once a contact is pinned to a certified local endpoint, the headless
receiver also rejects identity-fingerprint/non-v4 envelopes for that contact;
direct-v4 context from an unresolved relationship is rejected before session
or legacy contact lookup.

Relays store ciphertext only. Direct mailbox delivery is idempotent for an
`(inboxId, envelope.id)` pair so a client may safely retry after an ambiguous
network failure. The envelope ID is included in the sender's signature
transcript. Receiving clients persist a bounded receipt that additionally binds
the authenticated relationship scope, logical event ID, and digest of the
complete canonical signed envelope. Unrelated contacts do not share a logical
event-ID namespace.
Only an exact receipt match may skip repeat processing; conflicting reuse fails
before cursor advancement, and an old replay whose receipt was compacted must
pass ordinary signature and ratchet validation. Relays may bucket visible
timestamps and reject oversized payloads.

The final destination relay accepts a direct envelope only when its effective
routing address has already completed inbox registration. An unknown but
syntactically valid address returns `Destination inbox is not registered`
without allocating a mailbox, stream sequence, or durable record. Federation
does not weaken this rule: an intermediate relay may forward an opaque request,
but the destination relay performs admission against its own registrations.

The non-destructive legacy `fetch` request is available only before an inbox
registers its first v2 consumer. The destructive inbox-wide
`acknowledgeMessages` request additionally requires the disabled-by-default
deprecated `nw.compat.legacy-fingerprint` relay profile. Once a v2 consumer has
ever been registered, both legacy inbox-wide operations remain rejected even
if every consumer is later revoked. New direct integrations use
`registerMailboxConsumer`, `syncMailbox`, `commitMailboxCursor`, and
`revokeMailboxConsumer`. A cursor commit records one consumer's durable local
progress; it does not consume another endpoint's delivery state.

The same explicit compatibility profile gates relay announcement/pair-request
pairing, fingerprint-keyed prekey upload/fetch, and every fingerprint-scoped
legacy group operation. Relays advertise it only when enabled and mark it
`deprecated`. Direct-v4 capability negotiation always excludes it.

The first consumer registration is a joint bootstrap authorized by the inbox
authority and proved by the new consumer key. After that transition, adding a
fresh consumer also requires `sponsorConsumerId` and a `register-sponsor` proof
from an active bound consumer over the complete registration. Inbox authority
alone cannot add another endpoint consumer. Existing same-ID/same-key registration
remains idempotent; a legacy keyless record can be rebound without sponsorship
only while no active bound consumer exists. If every bound consumer has been
revoked, registration fails closed and the user must create a new inbox and
identity generation rather than resurrecting the old mailbox with authority
alone.

The signed-envelope change is wire-breaking: envelopes signed before the ID
was added to the transcript do not verify under the current rules. Matching
senders and receivers must be deployed together, and old sealed outboxes must
be drained or explicitly discarded before cutover. See
[Wire Format And Test Vectors](wire_format_and_test_vectors.md) for the exact
transcript and migration boundary.

## Ratchet And Recovery

Direct sessions use symmetric-chain ratcheting plus periodic ML-KEM root ratchets. Implementations keep bounded skipped-message state for out-of-order delivery and use explicit recovery requests when a session mismatch is recoverable. Replay and stale actor-proof nonces must fail closed.

Separately authorized read-only history transfer is available as a local Swift
API. The exported projection cannot contain live ratchets, reusable prekeys,
inbox authority, route capabilities, group leaves, or other future-participation
secrets. The signed metadata-bearing inner archive is encrypted and then hidden
inside a second recipient-ML-KEM transport seal with fixed public size buckets.
Import validates the outer seal before decoding the inner archive, checks the
trusted sender authority and endpoint key, recipient and identity binding,
expiry, digests, signatures, and a bounded replay ledger, and yields only an
inert local projection. Applications must atomically persist that projection
with the updated ledger. No default rendezvous, storage adapter, managed history
service, attachment-byte migration, or endpoint admission is provided.
See [Read-only History Transfer v2](history_transfer_v2.md).

## Groups

Groups are relay-backed entities with group inboxes, signed membership commits,
retained epoch history, and group-ratchet envelopes. Relays enforce actor
authorization for group mutation, join, leave, delivery, fetch, and
acknowledgement. The implemented profile identifies itself as
`noctweave-pq-group-experimental-2`; it is a Noctweave-specific post-quantum
construction, not RFC 9420 MLS and not a formally proven MLS implementation.
The source retains some `MLS*` type names as migration-era implementation
vocabulary only. See [Noctweave PQ Group Design](group_mls_design.md).

Creating a group persists its generated inbox as part of the group descriptor;
that descriptor is the relay-side registration for group delivery. The final
relay rejects storage unless the request's group ID resolves to that descriptor
and its inbox matches, so arbitrary group-shaped addresses cannot allocate
mailboxes. A forwarding relay preserves the opaque destination and leaves this
decision to the final relay.

The in-process and Linux reference relays implement the same compatibility
group-invitation request/response surface: invitations remain distinct from
membership, only the authorized creator may add invitations, an invitee lists
with its actor proof and accepts into its signed group-scoped member profile,
and persisted invitations are removed after acceptance or group deletion.
This parity does not change the fingerprint-scoped security boundary.

Architecture-v2 includes additive models for endpoint-level group leaves,
signed role/permission policy, and a crypto-provider boundary. The active
relay-backed group path still addresses membership and acknowledgement by
identity fingerprint, so endpoint-scoped group removal is not yet claimed.

Legacy group receive state uses a bounded two-phase destructive-acknowledgement
journal. Before acknowledging the relay, the client durably stores the advanced
ratchet, the decrypted message, and an envelope-ID plus canonical-envelope-digest
receipt. An exact refetch while that receipt is pending is skipped and re-acked
without replaying the ratchet or duplicating the message. Reuse of the same ID
for different envelope bytes fails closed. The pending window is capped at 512;
it applies backpressure instead of evicting unacknowledged receipts. Only a
successful idempotent relay acknowledgement permits the client to clear the
corresponding receipts in a subsequent durable save.

Group delivery retries are idempotent for an `(inboxId, envelope.id)` pair only
when both the encrypted envelope and the normalized original recipient set are
identical. Relays persist that bounded original set separately from the mutable
pending-acknowledgement set; acknowledging one recipient therefore cannot make
an exact retry look like a conflicting delivery. The reference stores accept at
most 256 recipient entries of at most 128 UTF-8 bytes each. A changed payload,
direct-versus-group kind, or recipient set fails closed. Normalized SQLite
records from before this field existed derive the original set from the pending
set present at migration time. If such a record was already partially
acknowledged before upgrade, the removed recipients cannot be reconstructed and
a retry naming them is rejected rather than broadening the migrated set.

## Attachments And Voice

Attachments and voice messages are encrypted before relay upload. Large payloads are chunked, bounded, and TTL-controlled. Linux relays may store encrypted chunks inline in SQLite or offload encrypted chunks to an IPFS-compatible blob backend while keeping digest, size, CID, and expiry metadata in SQLite.

## Relay Transports

Supported relay transports are:

- TCP: one line-delimited JSON request per connection.
- HTTP: `POST /relay` with a JSON `RelayRequest`; `GET /health` for simple health probes.
- WebSocket: binary or text JSON messages on `/relay`.

TLS may be terminated by the relay or by an upstream reverse proxy. Clients record TLS mode in relay endpoint configuration and relay metadata. TLS never replaces end-to-end message encryption. For an opaque capability route, however, the bearer itself is write authority, so confidential authenticated transport is mandatory except for literal same-host loopback development. The reference client additionally supports SHA-256 leaf-certificate pinning for TCP-TLS, HTTPS, and WSS. When no manual pin is supplied, it records the certificate only after a system-trusted TLS handshake and a successful Noctweave relay response, then fails closed on later certificate changes. This trust-on-first-use step does not protect the first connection from an attacker able to present a platform-trusted certificate, and legitimate certificate renewal requires explicit re-pinning.

## Federation

Relays operate in exactly one federation mode: `solo`, `manual`, `curated`, or `open`. Modes are separate trust domains. A relay must not forward between curated and open networks or silently reinterpret one mode as another.

Forwarding is requested by setting `destinationRelay` on a direct or group delivery request. The receiving relay evaluates the destination before forwarding:

1. `solo` rejects every destination relay.
2. `manual` requires the destination endpoint to appear in the local operator-maintained node list, requires destination `info` to report `manual`, requires matching federation name when set, and requires relay kind `standard`.
3. `curated` requires static allow-list membership, coordinator health state, configured coordinator quorum, fresh directory data, signed directory verification when required, matching federation name, and curated destination mode.
4. `open` requires open destination mode, matching federation name, public secure endpoints unless local test mode explicitly allows private endpoints, and signed short-lived discovery records when DHT discovery is used.

Client relay passwords are not forwarded. When a relay requires relay-to-relay authentication, it uses a dedicated federation forwarding token. Coordinator registration uses a separate coordinator registration token.

Coordinator nodes organize relay directories and health state. They do not need to carry user messages. Relays register with coordinators using `registerFederationNode`; consumers query healthy directory state with `listFederationNodes`. Signed directory snapshots use ML-DSA-65.

Open federation may advertise relay-native DHT node support and capped peer exchange hints. DHT records use the `noctweave-open-v1` namespace and are signed short-lived relay advertisements validated by protocol version, namespace, federation name, relay identity digest, signature, lifetime, endpoint transport, public endpoint policy, total-record limits, per-host limits, and query-size limits. Peer exchange is only a discovery hint; consumers must still validate the destination relay through `info` before forwarding.

Reference relays bound request bodies, response bodies, mailboxes, groups,
prekeys, attachment records, DHT caches, and operator-supplied timing/count
configuration before allocation or arithmetic. Values outside a supported
range are rejected or normalized at the documented configuration boundary.

Runtime federation updates are allowed for future requests. Implementations must synchronize mutable relay configuration, coordinator heartbeat tasks, and coordinator directory caches so UI or operator changes do not race with active request handling. In-flight requests keep the routing decision already taken for that request.

## Metadata Reduction

Implemented metadata controls include temporal bucketing, fixed-size message buckets, cover-query hidden retrieval, replicated XOR-PIR primitives under a non-collusion assumption, onion packet primitives, mixnet scheduling machinery, and decentralized wake planning. These are metadata-reduction features, not a claim of full network anonymity.

## Security Boundary

The relay is not trusted with plaintext. The client endpoint and operating system remain trusted execution boundaries. UI protections for screenshots, secure typing, secure camera capture, and local encrypted storage reduce exposure but do not defeat a hostile OS.
