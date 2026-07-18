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

## Relay endpoints

Parse explicit schemes rather than guessing transport from a URL:

```swift
let endpoint = try RelayEndpointParser.parse("wss://relay.example/relay")
let relay = RelayClient(endpoint: endpoint)
let health = try await relay.send(.health())
```

`RelayClient` verifies that every response repeats the outstanding request ID,
module, version, and method.

## Prepare one pairing participant

```swift
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
The combined `ContactPairingHandshakeV2.establish` orchestration is internal to
tests and conformance work; it is not a public integration API.

## Send and synchronize

```swift
let result = try await client.sendText(
    "hello",
    relationshipID: relationshipID
)

let batches = try await client.sync(
    relationshipID: relationshipID,
    maximumPackets: 128
)
```

Sending persists a `ConversationEvent`, `ProtocolIntentV2`, and exact
`OpaqueRoutePacketV2` bytes before publication. Sync verifies, decrypts, stores,
and then commits each `OpaqueRouteCursorV2`.

Use `sendAttachment`, `sendRelationshipControl`, and
`retryPendingDeliveries` for the corresponding flows.

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
route expiry.

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

`prepareRouteRollover` creates fresh local capability material.
`beginRouteRollover` registers it, advertises it as `testing` through the old
working route, and journals the operation. The peer sends a targeted probe over
the new route; inbound processing promotes it and marks the old route draining
for bounded overlap. Drained-route teardown remains explicit and retryable.

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
receipts. `GroupOpaqueRouteFanoutPlanV2` creates member-route copies, and
`HeadlessMessagingClient.publishGroupFanoutPlan` publishes their already sealed
exact bytes rather than re-encrypting.

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
