import CryptoKit
import Foundation

public enum ContactPairingV2Error: Error, Equatable {
    case invalidInvitation
    case invalidParticipant
    case invalidConfirmation
    case invalidState
}

/// The complete one-use out-of-band invitation. It contains only ephemeral
/// rendezvous material; no identity, endpoint, route, relay account, or stable
/// persona identifier is disclosed before the encrypted session exists.
public struct ContactPairingInvitationV2: Codable, Equatable {
    public static let version = 2
    public static let maximumEncodedCharacters = 32 * 1_024

    public let version: Int
    public let offer: RendezvousOfferV2
    public let redemptionSecret: RendezvousRedemptionSecretV2

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case offer
        case redemptionSecret
    }

    public init(
        offer: RendezvousOfferV2,
        redemptionSecret: RendezvousRedemptionSecretV2
    ) throws {
        self.version = Self.version
        self.offer = offer
        self.redemptionSecret = redemptionSecret
        guard isStructurallyValid else { throw ContactPairingV2Error.invalidInvitation }
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: ContactPairingCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Pairing invitation fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        offer = try container.decode(RendezvousOfferV2.self, forKey: .offer)
        redemptionSecret = try container.decode(
            RendezvousRedemptionSecretV2.self,
            forKey: .redemptionSecret
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .offer,
                in: container,
                debugDescription: "Pairing invitation is structurally invalid"
            )
        }
    }

    public var isStructurallyValid: Bool {
        version == Self.version
            && offer.purpose == .contactPairing
            && offer.isStructurallyValid
            && redemptionSecret.matches(offer)
    }

    public func encoded() throws -> String {
        guard isStructurallyValid else { throw ContactPairingV2Error.invalidInvitation }
        let value = try NoctweaveCoder.encode(self).base64EncodedString()
        guard value.count <= Self.maximumEncodedCharacters else {
            throw ContactPairingV2Error.invalidInvitation
        }
        return value
    }

    public static func decode(_ value: String) throws -> ContactPairingInvitationV2 {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty,
              normalized.count <= Self.maximumEncodedCharacters,
              let data = Data(base64Encoded: normalized) else {
            throw ContactPairingV2Error.invalidInvitation
        }
        return try NoctweaveCoder.decode(ContactPairingInvitationV2.self, from: data)
    }
}

/// Local secret material waiting for the relay to durably create its opaque
/// receive route. It cannot produce a peer introduction: a client must first
/// validate the relay-returned route projection with `activate(createdRoute:)`.
public struct PendingContactParticipantV2: Codable, Equatable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let version = 2

    public let version: Int
    public let localIdentity: LocalPairwiseIdentityV2
    public let relay: RelayEndpoint
    public let clientCapabilities: OpaqueRouteClientCapabilityMaterialV2
    public let payloadKey: OpaqueRoutePayloadKeyV2
    public let routeCreateRequest: OpaqueRouteCreateRequestV2
    public let createdAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case localIdentity
        case relay
        case clientCapabilities
        case payloadKey
        case routeCreateRequest
        case createdAt
    }

    private init(
        version: Int,
        localIdentity: LocalPairwiseIdentityV2,
        relay: RelayEndpoint,
        clientCapabilities: OpaqueRouteClientCapabilityMaterialV2,
        payloadKey: OpaqueRoutePayloadKeyV2,
        routeCreateRequest: OpaqueRouteCreateRequestV2,
        createdAt: Date
    ) {
        self.version = version
        self.localIdentity = localIdentity
        self.relay = relay
        self.clientCapabilities = clientCapabilities
        self.payloadKey = payloadKey
        self.routeCreateRequest = routeCreateRequest
        self.createdAt = createdAt
    }

    public static func prepare(
        relationshipPseudonym: String,
        relay: RelayEndpoint,
        policy: OpaqueRoutePolicyV2 = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .sixHours,
            quotaBucket: .packets256
        ),
        createdAt: Date = Date()
    ) throws -> PendingContactParticipantV2 {
        let identity = try LocalPairwiseIdentityV2.generate(
            relationshipPseudonym: relationshipPseudonym,
            createdAt: createdAt
        )
        let capabilities = try OpaqueRouteClientCapabilityMaterialV2()
        let lease = try OpaqueRouteLeaseV2(
            issuedAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(6 * 60 * 60),
            policy: policy
        )
        let participant = PendingContactParticipantV2(
            version: Self.version,
            localIdentity: identity,
            relay: relay,
            clientCapabilities: capabilities,
            payloadKey: .generate(),
            routeCreateRequest: try capabilities.makeCreateRequest(
                lease: lease,
                idempotencyKey: .generate()
            ),
            createdAt: createdAt
        )
        guard participant.isStructurallyValid else {
            throw ContactPairingV2Error.invalidParticipant
        }
        return participant
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: ContactPairingCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Pending pairing participant fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try container.decode(Int.self, forKey: .version),
            localIdentity: try container.decode(LocalPairwiseIdentityV2.self, forKey: .localIdentity),
            relay: try container.decode(RelayEndpoint.self, forKey: .relay),
            clientCapabilities: try container.decode(
                OpaqueRouteClientCapabilityMaterialV2.self,
                forKey: .clientCapabilities
            ),
            payloadKey: try container.decode(OpaqueRoutePayloadKeyV2.self, forKey: .payloadKey),
            routeCreateRequest: try container.decode(
                OpaqueRouteCreateRequestV2.self,
                forKey: .routeCreateRequest
            ),
            createdAt: try container.decode(Date.self, forKey: .createdAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .routeCreateRequest,
                in: container,
                debugDescription: "Pending pairing participant is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Pending pairing participant is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(localIdentity, forKey: .localIdentity)
        try container.encode(relay, forKey: .relay)
        try container.encode(clientCapabilities, forKey: .clientCapabilities)
        try container.encode(payloadKey, forKey: .payloadKey)
        try container.encode(routeCreateRequest, forKey: .routeCreateRequest)
        try container.encode(createdAt, forKey: .createdAt)
    }

    public var isStructurallyValid: Bool {
        version == Self.version
            && localIdentity.isStructurallyValid
            && relay.isStructurallyValidRelationshipRouteEndpointV2
            && relay.isConfidentialCapabilityTransportV2
            && clientCapabilities.isStructurallyValid
            && payloadKey.isStructurallyValid
            && routeCreateRequest.isStructurallyValid
            && routeCreateRequest.routeID == clientCapabilities.routeID
            && routeCreateRequest.lease.issuedAt == createdAt
            && localIdentity.createdAt == createdAt
    }

    public func activate(
        createdRoute: OpaqueReceiveRouteV2
    ) throws -> PreparedContactParticipantV2 {
        guard isStructurallyValid,
              let transitionDigest = routeCreateRequest.transitionDigest,
              createdRoute.status == .active,
              createdRoute.routeID == routeCreateRequest.routeID,
              createdRoute.creationIdempotencyKey == routeCreateRequest.idempotencyKey,
              createdRoute.creationDigest == transitionDigest,
              createdRoute.matches(clientCapabilities: clientCapabilities) else {
            throw ContactPairingV2Error.invalidParticipant
        }
        return try PreparedContactParticipantV2(
            localIdentity: localIdentity,
            localReceiveRoute: LocalOpaqueReceiveRouteV2(
                relay: relay,
                route: createdRoute,
                clientCapabilities: clientCapabilities,
                payloadKey: payloadKey
            ),
            routeCreateRequest: routeCreateRequest,
            createdAt: createdAt
        )
    }

    public var description: String { "PendingContactParticipantV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

/// Pairing material whose opaque receive route has been confirmed by its
/// relay. Read, renewal, teardown, private identity, and persona material stay
/// local when the encrypted introduction is produced.
public struct PreparedContactParticipantV2: Codable, Equatable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let version = 2

    public let version: Int
    public let localIdentity: LocalPairwiseIdentityV2
    public let localReceiveRoute: LocalOpaqueReceiveRouteV2
    public let routeCreateRequest: OpaqueRouteCreateRequestV2
    public let createdAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case localIdentity
        case localReceiveRoute
        case routeCreateRequest
        case createdAt
    }

    fileprivate init(
        version: Int = Self.version,
        localIdentity: LocalPairwiseIdentityV2,
        localReceiveRoute: LocalOpaqueReceiveRouteV2,
        routeCreateRequest: OpaqueRouteCreateRequestV2,
        createdAt: Date
    ) {
        self.version = version
        self.localIdentity = localIdentity
        self.localReceiveRoute = localReceiveRoute
        self.routeCreateRequest = routeCreateRequest
        self.createdAt = createdAt
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: ContactPairingCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Prepared pairing participant fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try container.decode(Int.self, forKey: .version),
            localIdentity: try container.decode(LocalPairwiseIdentityV2.self, forKey: .localIdentity),
            localReceiveRoute: try container.decode(
                LocalOpaqueReceiveRouteV2.self,
                forKey: .localReceiveRoute
            ),
            routeCreateRequest: try container.decode(
                OpaqueRouteCreateRequestV2.self,
                forKey: .routeCreateRequest
            ),
            createdAt: try container.decode(Date.self, forKey: .createdAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .localIdentity,
                in: container,
                debugDescription: "Prepared pairing participant is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Prepared pairing participant is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(localIdentity, forKey: .localIdentity)
        try container.encode(localReceiveRoute, forKey: .localReceiveRoute)
        try container.encode(routeCreateRequest, forKey: .routeCreateRequest)
        try container.encode(createdAt, forKey: .createdAt)
    }

    public var isStructurallyValid: Bool {
        version == Self.version
            && localIdentity.isStructurallyValid
            && localReceiveRoute.isStructurallyValid
            && routeCreateRequest.isStructurallyValid
            && routeCreateRequest.routeID == localReceiveRoute.route.routeID
            && localReceiveRoute.route.matches(
                clientCapabilities: localReceiveRoute.clientCapabilities
            )
            && createdAt.timeIntervalSince1970.isFinite
            && localIdentity.createdAt == createdAt
    }

    fileprivate func introductionBundle(
        rendezvousTranscriptDigest: Data,
        issuedAt: Date,
        expiresAt: Date
    ) throws -> PairingIntroductionBundleV2 {
        guard isStructurallyValid else { throw ContactPairingV2Error.invalidParticipant }
        let relationshipID = try PairwiseRelationshipIDV2.derive(
            from: rendezvousTranscriptDigest
        )
        let endpointHandle = RelationshipEndpointHandle.generate(
            relationshipId: relationshipID
        )
        let routeSet = try localIdentity.makeInitialRouteSet(
            relationshipID: relationshipID,
            ownerEndpointHandle: endpointHandle,
            receiveRoute: localReceiveRoute.peerSendRoute(),
            issuedAt: issuedAt
        )
        let introduction = try localIdentity.makeIntroduction(
            receiveRoutes: routeSet,
            rendezvousTranscriptDigest: rendezvousTranscriptDigest,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
        return PairingIntroductionBundleV2(
            endpointHandle: endpointHandle,
            routeSet: routeSet,
            introduction: introduction
        )
    }

    public var description: String { "PreparedContactParticipantV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

public struct ContactPairingResultV2 {
    public let offererRelationship: PairwiseRelationshipV2
    public let responderRelationship: PairwiseRelationshipV2
    public let relationshipID: UUID
}

/// Live responder-side pairing state. It is intentionally non-Codable because
/// it contains short-lived rendezvous session keys. Applications persist the
/// invitation and prepared relationship participant, but restart an interrupted
/// pairing exchange instead of cloning or exporting live cryptographic state.
public struct ContactPairingResponderFlowV2 {
    private var session: RendezvousSessionV2
    private let participant: PreparedContactParticipantV2
    private let localBundle: PairingIntroductionBundleV2
    private var peerIntroduction: ContactIntroductionV2?
    private var expectedConfirmation: PairingConfirmationV2?
    private var completed: Bool

    private init(
        session: RendezvousSessionV2,
        participant: PreparedContactParticipantV2,
        localBundle: PairingIntroductionBundleV2
    ) {
        self.session = session
        self.participant = participant
        self.localBundle = localBundle
        peerIntroduction = nil
        expectedConfirmation = nil
        completed = false
    }

    public static func begin(
        invitation: ContactPairingInvitationV2,
        participant: PreparedContactParticipantV2,
        at date: Date
    ) throws -> (
        openRequest: RendezvousOpenV2,
        acceptanceFrame: RendezvousFrameV2,
        flow: ContactPairingResponderFlowV2
    ) {
        guard invitation.isStructurallyValid,
              participant.isStructurallyValid else {
            throw ContactPairingV2Error.invalidInvitation
        }
        let opened = try RendezvousResponderV2.createOpen(
            for: invitation.offer,
            redemptionSecret: invitation.redemptionSecret,
            at: date
        )
        var session = opened.session
        let localBundle = try participant.introductionBundle(
            rendezvousTranscriptDigest: session.transcriptDigest,
            issuedAt: date,
            expiresAt: pairingIntroductionExpiry(invitation: invitation, at: date)
        )
        let acceptance = try session.seal(
            NoctweaveCoder.encode(localBundle.introduction),
            kind: .contactAcceptance,
            at: date
        )
        return (
            opened.request,
            acceptance,
            ContactPairingResponderFlowV2(
                session: session,
                participant: participant,
                localBundle: localBundle
            )
        )
    }

    public mutating func receiveOffer(
        _ frame: RendezvousFrameV2,
        at date: Date
    ) throws -> RendezvousFrameV2 {
        guard peerIntroduction == nil,
              expectedConfirmation == nil,
              !completed else {
            throw ContactPairingV2Error.invalidState
        }
        let peer = try NoctweaveCoder.decode(
            ContactIntroductionV2.self,
            from: session.open(frame, at: date)
        )
        let relationshipID = try PairwiseRelationshipIDV2.derive(
            from: session.transcriptDigest
        )
        let confirmation = PairingConfirmationV2(
            relationshipID: relationshipID,
            offererIntroductionDigest: pairingIntroductionDigest(peer),
            responderIntroductionDigest: pairingIntroductionDigest(localBundle.introduction)
        )
        guard confirmation.isStructurallyValid else {
            throw ContactPairingV2Error.invalidConfirmation
        }
        peerIntroduction = peer
        expectedConfirmation = confirmation
        return try session.seal(
            NoctweaveCoder.encode(confirmation),
            kind: .confirmation,
            at: date
        )
    }

    public mutating func receiveConfirmation(
        _ frame: RendezvousFrameV2,
        at date: Date
    ) throws -> PairwiseRelationshipV2 {
        guard let peerIntroduction,
              let expectedConfirmation,
              !completed else {
            throw ContactPairingV2Error.invalidState
        }
        let received = try NoctweaveCoder.decode(
            PairingConfirmationV2.self,
            from: session.open(frame, at: date)
        )
        guard received == expectedConfirmation else {
            throw ContactPairingV2Error.invalidConfirmation
        }
        let relationship = try PairwiseRelationshipV2(
            localIdentity: participant.localIdentity,
            localEndpointHandle: localBundle.endpointHandle,
            localReceiveRoutes: [participant.localReceiveRoute],
            localAdvertisedRoutes: localBundle.routeSet,
            peerIntroduction: peerIntroduction,
            rendezvousTranscriptDigest: session.transcriptDigest,
            acceptedAt: date
        )
        guard relationship.id == expectedConfirmation.relationshipID else {
            throw ContactPairingV2Error.invalidConfirmation
        }
        completed = true
        return relationship
    }
}

/// Live offerer-side pairing state. The public methods mirror the network
/// exchange, allowing each participant to run in a different process while the
/// relay adapter transports only opaque fixed-bucket ciphertext.
public struct ContactPairingOffererFlowV2 {
    private var session: RendezvousSessionV2
    private let participant: PreparedContactParticipantV2
    private let localBundle: PairingIntroductionBundleV2
    private let peerIntroduction: ContactIntroductionV2
    private let expectedConfirmation: PairingConfirmationV2
    private var completed: Bool

    private init(
        session: RendezvousSessionV2,
        participant: PreparedContactParticipantV2,
        localBundle: PairingIntroductionBundleV2,
        peerIntroduction: ContactIntroductionV2,
        expectedConfirmation: PairingConfirmationV2
    ) {
        self.session = session
        self.participant = participant
        self.localBundle = localBundle
        self.peerIntroduction = peerIntroduction
        self.expectedConfirmation = expectedConfirmation
        completed = false
    }

    public static func begin(
        pendingOffer: inout PendingRendezvousOfferV2,
        invitation: ContactPairingInvitationV2,
        participant: PreparedContactParticipantV2,
        openRequest: RendezvousOpenV2,
        acceptanceFrame: RendezvousFrameV2,
        ledger: inout RendezvousRedemptionLedgerV2,
        at date: Date
    ) throws -> (
        offerFrame: RendezvousFrameV2,
        flow: ContactPairingOffererFlowV2
    ) {
        guard invitation.offer == pendingOffer.offer,
              invitation.isStructurallyValid,
              participant.isStructurallyValid else {
            throw ContactPairingV2Error.invalidInvitation
        }
        var session = try pendingOffer.accept(openRequest, ledger: &ledger, at: date)
        let peer = try NoctweaveCoder.decode(
            ContactIntroductionV2.self,
            from: session.open(acceptanceFrame, at: date)
        )
        let localBundle = try participant.introductionBundle(
            rendezvousTranscriptDigest: session.transcriptDigest,
            issuedAt: date,
            expiresAt: pairingIntroductionExpiry(invitation: invitation, at: date)
        )
        let offerFrame = try session.seal(
            NoctweaveCoder.encode(localBundle.introduction),
            kind: .contactOffer,
            at: date
        )
        let relationshipID = try PairwiseRelationshipIDV2.derive(
            from: session.transcriptDigest
        )
        let confirmation = PairingConfirmationV2(
            relationshipID: relationshipID,
            offererIntroductionDigest: pairingIntroductionDigest(localBundle.introduction),
            responderIntroductionDigest: pairingIntroductionDigest(peer)
        )
        guard confirmation.isStructurallyValid else {
            throw ContactPairingV2Error.invalidConfirmation
        }
        return (
            offerFrame,
            ContactPairingOffererFlowV2(
                session: session,
                participant: participant,
                localBundle: localBundle,
                peerIntroduction: peer,
                expectedConfirmation: confirmation
            )
        )
    }

    public mutating func receiveConfirmation(
        _ frame: RendezvousFrameV2,
        at date: Date
    ) throws -> (
        confirmationFrame: RendezvousFrameV2,
        relationship: PairwiseRelationshipV2
    ) {
        guard !completed else { throw ContactPairingV2Error.invalidState }
        let received = try NoctweaveCoder.decode(
            PairingConfirmationV2.self,
            from: session.open(frame, at: date)
        )
        guard received == expectedConfirmation else {
            throw ContactPairingV2Error.invalidConfirmation
        }
        let confirmationFrame = try session.seal(
            NoctweaveCoder.encode(expectedConfirmation),
            kind: .confirmation,
            at: date
        )
        let relationship = try PairwiseRelationshipV2(
            localIdentity: participant.localIdentity,
            localEndpointHandle: localBundle.endpointHandle,
            localReceiveRoutes: [participant.localReceiveRoute],
            localAdvertisedRoutes: localBundle.routeSet,
            peerIntroduction: peerIntroduction,
            rendezvousTranscriptDigest: session.transcriptDigest,
            acceptedAt: date
        )
        guard relationship.id == expectedConfirmation.relationshipID else {
            throw ContactPairingV2Error.invalidConfirmation
        }
        completed = true
        return (confirmationFrame, relationship)
    }
}

public enum ContactPairingHandshakeV2 {
    public static func makeOffer(
        createdAt: Date,
        expiresAt: Date
    ) throws -> (
        pending: PendingRendezvousOfferV2,
        invitation: ContactPairingInvitationV2
    ) {
        let capability = try RendezvousTransportCapabilityV2.generate(expiresAt: expiresAt)
        let pending = try PendingRendezvousOfferV2.create(
            transportCapability: capability,
            createdAt: createdAt
        )
        let invitation = try ContactPairingInvitationV2(
            offer: pending.offer,
            redemptionSecret: pending.redemptionSecret()
        )
        return (pending, invitation)
    }

    /// Executes the typed handshake state machine. Network adapters transport
    /// the returned rendezvous frames in the same order; this helper proves the
    /// cryptographic and persistence objects without assigning trust to a relay.
    public static func establish(
        pendingOffer: inout PendingRendezvousOfferV2,
        invitation: ContactPairingInvitationV2,
        offerer: PreparedContactParticipantV2,
        responder: PreparedContactParticipantV2,
        ledger: inout RendezvousRedemptionLedgerV2,
        at date: Date
    ) throws -> ContactPairingResultV2 {
        let responderStart = try ContactPairingResponderFlowV2.begin(
            invitation: invitation,
            participant: responder,
            at: date
        )
        var responderFlow = responderStart.flow
        let offererStart = try ContactPairingOffererFlowV2.begin(
            pendingOffer: &pendingOffer,
            invitation: invitation,
            participant: offerer,
            openRequest: responderStart.openRequest,
            acceptanceFrame: responderStart.acceptanceFrame,
            ledger: &ledger,
            at: date
        )
        var offererFlow = offererStart.flow
        let responderConfirmation = try responderFlow.receiveOffer(
            offererStart.offerFrame,
            at: date
        )
        let offererCompletion = try offererFlow.receiveConfirmation(
            responderConfirmation,
            at: date
        )
        let responderRelationship = try responderFlow.receiveConfirmation(
            offererCompletion.confirmationFrame,
            at: date
        )
        let offererRelationship = offererCompletion.relationship
        let relationshipID = offererRelationship.id
        guard responderRelationship.id == relationshipID else {
            throw ContactPairingV2Error.invalidConfirmation
        }
        return ContactPairingResultV2(
            offererRelationship: offererRelationship,
            responderRelationship: responderRelationship,
            relationshipID: relationshipID
        )
    }

}

private func pairingIntroductionExpiry(
    invitation: ContactPairingInvitationV2,
    at date: Date
) -> Date {
    min(
        invitation.offer.expiresAt,
        NoctweaveRendezvousV2.canonicalTimestamp(date)
            .addingTimeInterval(NoctweaveRendezvousV2.maximumLifetime)
    )
}

private func pairingIntroductionDigest(_ introduction: ContactIntroductionV2) -> Data {
    guard let encoded = try? NoctweaveCoder.encode(introduction, sortedKeys: true) else {
        return Data()
    }
    return Data(SHA256.hash(data: encoded))
}

private struct PairingIntroductionBundleV2 {
    let endpointHandle: RelationshipEndpointHandle
    let routeSet: PairwiseRouteSetV2
    let introduction: ContactIntroductionV2
}

private struct PairingConfirmationV2: Codable, Equatable {
    let version: Int
    let relationshipID: UUID
    let offererIntroductionDigest: Data
    let responderIntroductionDigest: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case relationshipID
        case offererIntroductionDigest
        case responderIntroductionDigest
    }

    init(
        relationshipID: UUID,
        offererIntroductionDigest: Data,
        responderIntroductionDigest: Data
    ) {
        self.version = ContactPairingInvitationV2.version
        self.relationshipID = relationshipID
        self.offererIntroductionDigest = offererIntroductionDigest
        self.responderIntroductionDigest = responderIntroductionDigest
    }

    init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: ContactPairingCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Pairing confirmation fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        relationshipID = try container.decode(UUID.self, forKey: .relationshipID)
        offererIntroductionDigest = try container.decode(
            Data.self,
            forKey: .offererIntroductionDigest
        )
        responderIntroductionDigest = try container.decode(
            Data.self,
            forKey: .responderIntroductionDigest
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: container,
                debugDescription: "Pairing confirmation is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Pairing confirmation is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(relationshipID, forKey: .relationshipID)
        try container.encode(offererIntroductionDigest, forKey: .offererIntroductionDigest)
        try container.encode(responderIntroductionDigest, forKey: .responderIntroductionDigest)
    }

    var isStructurallyValid: Bool {
        version == ContactPairingInvitationV2.version
            && offererIntroductionDigest.count == SHA256.byteCount
            && responderIntroductionDigest.count == SHA256.byteCount
    }
}

private struct ContactPairingCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}
