# NoctweaveCore Public API

`NoctweaveCore` is the Swift implementation of the Noctweave 1.0 protocol. It
contains protocol models, cryptographic flows, opaque-route relay primitives,
the headless client, group runtime, federation policy, and experimental route-
scoped wake and privacy research modules.

## Add the package

Use `NoctweaveCore/Package.swift` as a local Swift package or point a package
dependency at this repository's `NoctweaveCore` directory.

```swift
import NoctweaveCore
```

Production applications must use the throwing PQ generation APIs and handle
entropy, algorithm, decoding, persistence, and network failures explicitly.

## Local application state

```swift
let state = try ClientState(displayName: "local mask")
let store = ClientStateStore(fileURL: stateURL) // encrypted by default
let client = try HeadlessMessagingClient(
    stateStore: store,
    initialState: state
)
```

`ClientState` stores local preferences and `PersonaProfileV1` containers. A
persona has no protocol key or network identity. Live authority exists only in
`PairwiseRelationshipV2` and group runtime records.

Encrypted state is generation-bound to a separate local rollback anchor. On
Apple hosts the default anchor is a non-synchronizing Keychain item scoped to
the resolved state path. Other hosts must supply a
`ClientStateRollbackAnchorStore` whose compare-and-swap is atomic, durable, and
independently protected; encrypted mode fails closed when none is available.
The anchor is local storage authority only and never enters a persona,
relationship, group, route, relay request, or wire object.

The Apple Keychain backend is an OS-protected last-value authority, not a
hardware monotonic counter. It detects rollback or deletion of the companion
state file; rollback of the whole Keychain or host is outside this guarantee.

`save` advances the pending encrypted file and anchor through a two-phase,
crash-recoverable commit. Missing or replayed state with a newer anchor is an
error, not a reset. Replacement is an exact compare-and-replace operation:

```swift
try await store.save(candidate, replacing: prior)
```

The expected prior aggregate is checked under the store lock, so a second stale
client cannot overwrite a newer burn or relationship mutation. A brand-new
store uses `replacing: nil`. After an anchored erasure, only an explicitly
fresh save with `replacing: nil` may advance beyond the tombstone; a retained
pre-erasure aggregate cannot. Intentional whole-database destruction is
explicit:

```swift
try await store.eraseAllLocalState()
```

Erasure advances an identity-free anchor tombstone, removes state, and prevents
an older file from resurrecting. A later unrelated database advances from the
next local generation. `.insecurePlaintextForTesting` and
`VolatileClientStateRollbackAnchorStore` are bounded test facilities, not
production rollback protection.

Relationship mutations are serialized per relationship. A process-wide
encrypted-state save gate merges each successful mutation against the latest
aggregate so awaited work on independent relationships cannot overwrite newer
state.

## Relay endpoints

Parse explicit schemes rather than guessing transport from a URL:

```swift
let endpoint = try RelayEndpointParser.parse("wss://relay.example/relay")
let relay = RelayClient(endpoint: endpoint)
let health = try await relay.send(.health())
```

`RelayClient` verifies that every response repeats the outstanding request ID,
module, version, and method.

Before pairing, verify the exact relay surface that the selected path needs:

```swift
let relayClient = RelayClient(endpoint: endpoint, authToken: relayPassword)
let relayPairing = try await RelayPairingPreflight.check(
    client: relayClient,
    requirement: .rendezvous
)

let directPairing = try await RelayPairingPreflight.check(
    client: relayClient,
    requirement: .opaqueRouteOnly
)
```

The functional check creates and removes a temporary opaque route. Rendezvous
mode additionally registers and removes temporary one-use lanes. A successful
health response alone is not considered pairing readiness.

## Prepare one pairing participant

```swift
// Mint immediately before work that may suspend outside the client actor.
let personaScope = await client.mintActivePersonaScopeToken()

let pending = try await client.prepareContactParticipant(
    relay: endpoint,
    relationshipPseudonym: "night orchid"
)
let participant = try await client.activateContactParticipant(pending)
```

Preparation generates a fresh `LocalPairwiseIdentityV2`, singular
`RelationshipEndpointBindingV4`, signed prekey, `RelationshipEndpointHandle`,
and `LocalOpaqueReceiveRouteV2`. Activation registers the route before it can be
advertised.

The relationship pseudonym is explicit. The API does not substitute the local
persona label.

## Create a one-use invitation

```swift
let now = Date()
let offer = try await client.makeContactPairingInvitation(
    createdAt: now,
    expiresAt: now.addingTimeInterval(600)
)
let shareable = try offer.invitation.encoded()
```

`ContactPairingInvitationV2` contains rendezvous material only.
Production integrations drive `ContactPairingOffererFlowV2` and
`ContactPairingResponderFlowV2` independently. Each flow verifies redemption,
holds only its own private state, and produces one local
`PairwiseRelationshipV2` projection after mutual encrypted confirmation. The
live Swift flows are intentionally non-`Codable`; an interrupted exchange is
abandoned and restarted with fresh one-use material rather than exporting live
session keys. The JavaScript browser state machine separately provides exact
outbox persistence and restart resumption.

When the local flow returns its relationship, insert it with the token minted
before construction:

```swift
try await client.addRelationship(
    relationship,
    consent: .accepted,
    personaScope: personaScope
)
```

`LocalPersonaScopeToken` is non-`Codable`, process-local, and carries no
protocol identity or authority. `addRelationship` rejects it after persona
burn or client restart, preventing an old asynchronous pairing result from
entering a replacement persona. The same rule applies to `addGroupRuntime` for
externally constructed group state.

### Relay and direct/offline carriers

Relay Pairing moves the initial one-use invitation out of band, then transports
the encrypted transcript through `nw.rendezvous-transport@2`. Direct / Offline
Pairing instead transports each existing authenticated flow stage by QR,
AirDrop, removable storage, or another direct path. It uses
`DirectPairingTransferV2` stages in this order:

1. `invitation`
2. `response`
3. `offer`
4. `confirmation`
5. `finalConfirmation`

Each stage is bounded, strictly decoded, and prefixed with
`noctweave-direct-pair-v2:`. The live offerer/responder flow remains in memory;
an interrupted exchange is restarted rather than serializing session keys.

Files and system shares should wrap either a relay invitation or one direct
stage with `PasswordProtectedPairingPackageV1`, which applies
PBKDF2-HMAC-SHA256 with a fresh salt and AES-256-GCM authentication:

```swift
let package = try PasswordProtectedPairingPackageV1.seal(
    invitation: shareable,
    password: separatelySharedPassword
)

let recovered = try PasswordProtectedPairingPackageV1.open(
    package: package,
    password: separatelySharedPassword
)
```

In Relay Pairing both devices must reach the invitation's rendezvous relay
before expiry. In Direct Pairing no relay stores the handshake frames, and the
devices need not share a relay; each device must still reach its own relay to
provision the relationship-scoped receive route advertised inside the encrypted
introduction. The password must travel through a different channel from the
protected package.

The combined `ContactPairingHandshakeV2.establish` orchestration is internal to
tests and conformance work; it is not a public integration API.

## Send and synchronize

```swift
let prepared = try await client.prepareSend(
    body: .text("hello"),
    relationshipID: relationshipID
)

// Render local echo from the durable logical event immediately.
render(prepared.event)

let publication = try await client.publishPreparedSend(prepared)

let batches = try await client.sync(
    relationshipID: relationshipID,
    maximumPackets: 128
)
```

`prepareSend` performs no relay I/O. It atomically persists the
`ConversationEvent`, advanced direct ratchet, immutable `DirectEnvelopeV4`,
fixed ciphertext packets, local-persisted delivery state, and one bounded
`ProtocolIntentV2` per destination route. The returned event ID and client
transaction ID are the local-echo reconciliation keys.

`Conversation.messages` is only a bounded local display projection. Appending a
received projection increments the unread suffix of the received-projection
subsequence; appending a sent projection does not. Trimming decrements the count
only when an unread received projection leaves the retained window.
`Conversation.markAllRead()` clears that local count and does not emit a read
receipt. A reset `Conversation` is retired and must be replaced by a fresh
ML-KEM-bootstrap session; it is never healed in place.

`publishPreparedSend` verifies the supplied envelope against that durable
outbox and publishes the saved packets without re-encrypting. While the bounded
event/outbox record is retained, call
`publishPreparedEvent(eventID:relationshipID:)` after a restart; it resumes from
persisted state and does not require the in-memory `HeadlessPreparedSend` value. The
`sendText` and `sendAttachment` methods remain prepare-and-publish convenience
wrappers.

Publication results have deliberately narrow meanings:

- `acceptedDeliveryCount`: destination routes accepted during this call;
- `pendingDeliveryCount`: retained nonterminal route intents;
- `failedDeliveryCount`: retained permanent failures;
- `nextRetryNotBefore`: earliest durable retry deadline, when one exists.

Transient failures retain the exact packet bundle and use bounded exponential
backoff through `retryPendingDeliveries`. Permanent failures also retain their
authenticated bytes until `discardFailedDelivery` is called explicitly. For
one destination route and direct session, publication is counter-ordered: a
later ciphertext waits for every earlier counter to be accepted or explicitly
discarded. Discarding the only viable copy resets that direct session and marks
dependent later artifacts failed rather than skipping a ratchet position.

Sync independently verifies, decrypts, and stores inbound events before
committing each `OpaqueRouteCursorV2`. Partial packet reassembly is part of the
durable route state: a page containing only verified fragments may advance once
the partial bundle and next cursor are saved atomically, and completion can
continue after another page or process restart.

Receive failures have three behaviors:

- route-chain, cursor, retention-gap, or persisted-state corruption is
  route-fatal and leaves the disputed page unadvanced;
- deterministic peer-controlled malformed, invalid, conflicting, or known-
  control input is recorded in bounded plaintext-free quarantine and advances;
- storage, local-state, network, or PQ-runtime unavailability is retryable and
  leaves the page unadvanced.

At the bounded reassembly budget, the oldest incomplete bundle is
deterministically retired and tombstoned, and a reassembly-pressure quarantine
record is persisted. The abandoned logical message is not reported
`peerStored` and is not silently reconstructed.

Relay cursor commit and generated receipts/probes/route-set updates are
best-effort after the local state commit. Their failure does not erase the
successful local result. Routes are independent availability paths: one failed
route does not starve a healthy later route in the same `sync` call; an error is
thrown only when no route succeeds.

Freshness and local chronology use receiver-observed time. Peer timestamps are
authenticated display/audit metadata, not a sole clock for expiry or protocol
state. Live processing uses throwing PQ verification so local algorithm/runtime
unavailability remains retryable instead of being mistaken for invalid peer
material.

Use `sendRelationshipControl` for authenticated relationship controls.

## Selective continuity

Continuity is disabled by default and configured locally per relationship:

```swift
try await client.setContinuityPolicy(
    .sendOnly,
    relationshipID: relationshipID
)

try await client.sendContinuityOffer(
    relationshipID: relationshipID,
    invitation: successorInvitation
)
```

Receiving applications use `.receiveOnly` or `.bidirectional` and retrieve an
accepted invitation through `continuityInvitation`. No persona-wide continuity
record exists.

## Burn

```swift
let replacement = try await client.burnActivePersona(
    replacementDisplayName: "fresh local mask"
)
```

The old persona record is removed rather than archived. Active sessions and
packet reassembly state are cleared. Remote ciphertext may remain until opaque
route expiry. Any `LocalPersonaScopeToken` minted before burn is rejected if an
older asynchronous relationship or group construction later completes.

## Typed content

`ConversationEvent` separates the logical event from delivery. Its
`EncodedContent` uses a namespaced `ContentTypeId`, bounded parameters and
payload, optional fallback text, and visible/silent disposition.

`WirePayloadV2` carries either an application event or an independently
authenticated `AuthenticatedRelationshipControlV2`. Known controls are session
reset, resend request, route-set update, targeted route probe, endpoint-prekey
update, and selective continuity. Unknown controls are quarantined and never
executed.

`ProtocolCapabilityManifest` and `ContentTypeCapabilityV2` negotiate exact
module, cipher, content-type-major-version, and bound intersections. Use the
manifest from each verified endpoint binding; unsupported outbound content is
rejected before ratchet mutation.

## Relationship-local safety and policy

```swift
let number = try RelationshipSafetyNumberV2.make(
    localAuthoritySigningPublicKey: localKey,
    peerAuthoritySigningPublicKey: peerKey
)

try await client.setRelationshipLocalPolicy(
    RelationshipLocalPolicyV2(
        consent: .accepted,
        mutedUntil: nil,
        deliveryReceiptsEnabled: true,
        readReceiptsEnabled: false
    ),
    relationshipID: relationshipID
)
```

The safety number is symmetric and valid only for one relationship. Local
policy carries pending-request/accepted/blocked consent, mute, and receipt
preferences without emitting protocol metadata. `blockRelationship` commits
the local block before best-effort route teardown.

## Route rollover

`prepareRouteRollover` creates fresh capability material and durably journals
the exact route-create request before network I/O. `beginRouteRollover` is the
convenience continuation for that returned value. The restart-safe entry points
are `resumeRouteRollover(routeID:relationshipID:)` and
`resumePendingRouteRollovers(relationshipID:)`.

Resume retries the same route-create idempotency material, activates the new
local receive route, and advertises it as `testing` through the old working
route. `HeadlessRouteRolloverResult.state` reports the durable intent stage;
`routeSetPublication` reports the per-route control publication when one was
attempted. The peer's targeted probe promotes the new route and marks the old
route draining for bounded overlap. Applications should run the maintenance
entry point on startup, foreground activation, and a bounded periodic timer:

```swift
let reports = try await client.maintainAllRelationships()
for report in reports where report.requiresFollowUp {
    presentRouteRecovery(for: report.relationshipID)
}
```

`maintainRelationship` resumes the exact unfinished rollover, rotates only the
relationship endpoint's expiring signed prekey, starts a fresh replacement
opaque route thirty minutes before its six-hour lease expires, and finalizes
elapsed drain windows. It does not renew a stable route, authorize a device, or
create persona-wide routing state. `routeExpired`, `noLocalRoute`, and
`rolloverFailed` require explicit product recovery rather than invented global
identity. A terminal failed rollover retains its recovery artifact until
`discardFailedRouteRollover` explicitly removes or revokes it.

## Encrypted attachment publication

For normal direct messaging, prefer the atomic sanitized-byte entry point:

```swift
let result = try await client.sendAttachment(
    bytes: sanitizedBytes,
    canonicalMIME: "image/jpeg",
    relay: endpoint,
    relationshipID: relationshipID
)
```

It persists the local descriptor event, one direct-ratchet advance, exact route
ciphertext, and all encrypted chunk-upload journals as one state replacement
before network I/O. It omits the source filename and rejects a relay unless the
peer has a usable advertised route on that same relay. Upload retries therefore
cannot create a second event, consume another message key, or strand a
descriptor that points to an undiscoverable blob location.

Low-level integrations that already own an equivalent transaction may keep
blob upload and descriptor publication separate. First encrypt each chunk end
to end, then journal and publish the already encrypted request:

```swift
let request = UploadAttachmentRequest(
    attachmentId: attachmentID,
    chunkIndex: chunkIndex,
    payload: encryptedPayload,
    ttlSeconds: 3_600,
    idempotencyKey: idempotencyKey // exactly 32 random bytes
)

let pending = try await client.prepareAttachmentUpload(
    request,
    relay: endpoint,
    relationshipID: relationshipID
)
let result = try await client.publishAttachmentUpload(
    uploadID: pending.id,
    relationshipID: relationshipID
)
```

`prepareAttachmentUpload` persists only ciphertext, relay coordinates, and the
exact bounded request; plaintext and attachment encryption keys remain
outside the journal. It performs no relay I/O. `HeadlessBlobUploadResult`
returns the durable intent `state` and sets `accepted` only after the correlated
relay response is committed locally. Use `retryPendingAttachmentUploads` after
restart or a transient failure. A permanent failure remains available for
inspection until `discardFailedAttachmentUpload` is called.

The 32-byte upload idempotency key is mandatory. While a relay retains an
`(attachmentId, chunkIndex)` coordinate, an exact retry with the same key and
canonical body returns the original chunk without extending TTL or rewriting
blob storage. A different key, payload, or requested TTL is a non-retryable
conflict; replacement content requires a fresh attachment ID. Only after all
required chunks are available should the application send the corresponding
`AttachmentDescriptor` with `sendAttachment`.

Receive integrations use `prepareAttachmentDownload`,
`fetchAttachmentDownload`, and `retryPendingAttachmentDownloads`. The exact
relay, descriptor, next index, and accepted ciphertext chunks are encrypted and
saved after every fetch. Completed plaintext is returned to the caller for
bounded use and is not retained in Core state.

Read `attachmentDefaultTTLSeconds` and `attachmentMaxTTLSeconds` from relay
info rather than assuming the default example above. Both values are bounded
to at least 60 seconds and at most the absolute 2,592,000-second (30-day) store
ceiling; an operator may advertise a lower maximum.

## Opaque-route primitives

Low-level integrations can use:

- `OpaqueRouteClientCapabilityMaterialV2` and `OpaqueSendRouteV2`;
- route create, renew, teardown, append, sync, and commit requests;
- `OpaqueRoutePacketizerV2` and `OpaqueRoutePacketReassemblerV2`;
- `PairwiseRouteSetV2` for testing, overlap, promotion, draining, and
  revocation;
- `NoctweaveOpaqueRouteRelayStoreV2` as the in-process reference store.

The peer projection contains append capability and the outer route-wrapping key
required to form fixed opaque packets. It never contains read, renewal, or
teardown authority. Direct event ciphertext remains independently protected
inside the packet.

The canonical `nw.opaque-route@2` capability registry is exact in both relay
implementations: `cursorBytes=68`, `maxPage=256`,
`maxPacketBytes=65536`, `maxPacketsPerRoute=1024`,
`maxRetentionSeconds=604800`, and `maxRoutes=100000`. Integrations should reject
drift rather than infer different limits from relay defaults.

## Exact relay wire

`RelayRequest` and `RelayResponse` are strict modular envelopes. Current
modules are represented by `RelayModuleID`, methods by `RelayMethodID`, and the
valid tuple by `RelayOperationBinding`.

Use the typed factories rather than constructing unbound JSON:

```swift
let request = RelayRequest.info()
let response = try await RelayClient(endpoint: endpoint).send(request)
guard response.isResponse(to: request) else { throw IntegrationError() }
```

## Experimental groups

`NoctweavePQGroupExperimentalProviderV2` implements the
`nw.pq-group.experimental-2` profile behind the group runtime. Group
members use `GroupScopedMemberHandleV2` and one active credential. Signed group
state defines roles, policy, epochs, commits, welcomes, deletion, credential
replacement, and fork quarantine.

The runtime exposes `prepareApplicationEvent`, `markApplicationPublished`, and
`processApplicationEnvelope` over durable
`PendingGroupApplicationPublicationV2` records and processed-envelope replay
receipts. Epoch publication carries one complete
`GroupEpochTransitionEnvelopeV2` plus destination-specific signed welcomes.
`processPeerEpoch` validates and atomically stores the signed next state,
provider state, and replay outcome; exact replay is idempotent and a conflicting
same-base artifact produces digest-only fork evidence. `join` additionally
requires a caller-pinned `GroupJoinAnchorV2`; an unsolicited self-consistent
Welcome is insufficient.

Accepted local-credential removal is terminal and clears sendable work.
`prepareDeletion`, `pendingDeletionPublication`, `markDeletionPublished`, and
`processDeletionTombstone` retain an exact signed terminal tombstone, clear
application/epoch work atomically, accept exact replay, and reject later
resurrection. Runtime records enforce a 32 MiB aggregate encoded-state bound,
and live group PQ operations use throwing error propagation.

`SignedGroupRouteSetAnnouncementV2` and `GroupPeerRouteSetCacheV2` bind current
opaque routes to one active group credential. The runtime verifies and persists
an exact replay, a valid direct hash-chained successor, or a strictly newer
credential-signed monotonic checkpoint when intermediate revisions were
missed. A checkpoint cannot move the issue time backwards, and a direct
successor cannot bypass its predecessor digest. Ordinary sends resolve routes
only from that authenticated cache. Explicit route sets are accepted solely
for a newly admitted credential that has no cached announcement yet.

`prepareApplicationTransport` and the equivalent epoch/control preparation
methods persist the exact recipient snapshot, sealed packets, and attempt state
before relay I/O. `resumeGroupTransport` retries those bytes without rebuilding
the cryptographic operation. Inbound sync stores each route's cursor, digest
chain, partial reassembly, processed effects, and quarantine before committing
the relay cursor.

Most applications should use the high-level `HeadlessMessagingClient` entry
points:

```swift
let created = try await client.createGroup(relay: relay)
let send = try await client.sendGroupText(
    groupID: created.groupID,
    text: "hello"
)
let pages = try await client.syncGroup(groupID: created.groupID)
let maintenance = try await client.maintainGroup(groupID: created.groupID)
```

The client also exposes `prepareGroupAdmission`,
`resumeGroupAdmissionRoute`, `prepareGroupMemberAddition`, join acceptance,
exact-operation resume, and deletion. The returned admission and Welcome
artifacts are deliberately transport-neutral and must cross an independently
authenticated encrypted channel selected by the caller. The API does not infer
a contact, authorize a device, or create a global invitation service.

This provider is not RFC 9420 MLS and requires independent review before a
production security claim.

## Federation and optional privacy

The package includes explicit relay-operator federation-mode policy.
Route-scoped wake/prefetch models, signed open-discovery records, hidden-
retrieval primitives, onion packets, and mixnet policy are experimental
research modules with no production anonymity claim. None changes direct
relationship authentication, and ordinary messaging clients learn destination
relays only from relationship-encrypted peer route sets.

## Required verification

Before claiming conformance with the repository:

```sh
swift build --package-path NoctweaveCore
swift test --package-path NoctweaveCore
swift build --package-path NoctweaveRelayServer
swift test --package-path NoctweaveRelayServer
scripts/run-tests.sh
```

Also run the JavaScript type-check and any application-specific persistence,
transport, and UI tests. Repository success is not an external security audit.
