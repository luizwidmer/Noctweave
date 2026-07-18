import CryptoKit
import Foundation

public enum GroupOpaqueRouteTransportV2Error: Error, Equatable {
    case invalidRouteSet
    case invalidSuccessor
    case invalidDestinationSnapshot
    case invalidOperation
    case operationNotFound
    case publicationNotFound
    case publicationNotEligible
    case attemptRequired
    case conflictingAcceptance
    case incompleteOperation
    case capacityReached
}

private struct StrictGroupOpaqueTransportCodingKey: CodingKey {
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

private func requireExactGroupOpaqueTransportKeys<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ keyType: Key.Type
) throws where Key.AllCases: Collection {
    let strict = try decoder.container(keyedBy: StrictGroupOpaqueTransportCodingKey.self)
    guard Set(strict.allKeys.map(\.stringValue))
            == Set(keyType.allCases.map(\.stringValue)) else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "Group opaque transport fields must match exactly"
            )
        )
    }
}

/// Group-credential-signed routes. This is group-scoped authority: it contains
/// no persona, account, identity, inbox, device, or installation identifier.
public struct SignedGroupOpaqueRouteSetV2: Codable, Equatable {
    public static let version = 2

    public let version: Int
    public let groupID: UUID
    public let ownerCredentialHandle: GroupScopedCredentialHandleV2
    public let ownerAdmissionDigest: Data
    public let revision: UInt64
    public let previousDigest: Data?
    public let routes: [OpaqueSendRouteV2]
    public let issuedAt: Date
    public let expiresAt: Date
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case groupID
        case ownerCredentialHandle
        case ownerAdmissionDigest
        case revision
        case previousDigest
        case routes
        case issuedAt
        case expiresAt
        case signature
    }

    private init(
        version: Int = Self.version,
        groupID: UUID,
        ownerCredentialHandle: GroupScopedCredentialHandleV2,
        ownerAdmissionDigest: Data,
        revision: UInt64,
        previousDigest: Data?,
        routes: [OpaqueSendRouteV2],
        issuedAt: Date,
        expiresAt: Date,
        signature: Data
    ) {
        self.version = version
        self.groupID = groupID
        self.ownerCredentialHandle = ownerCredentialHandle
        self.ownerAdmissionDigest = ownerAdmissionDigest
        self.revision = revision
        self.previousDigest = previousDigest
        self.routes = routes.sorted(by: Self.routeOrdering)
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.signature = signature
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupOpaqueTransportKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let decodedRoutes = try values.decode([OpaqueSendRouteV2].self, forKey: .routes)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            groupID: try values.decode(UUID.self, forKey: .groupID),
            ownerCredentialHandle: try values.decode(
                GroupScopedCredentialHandleV2.self,
                forKey: .ownerCredentialHandle
            ),
            ownerAdmissionDigest: try values.decode(Data.self, forKey: .ownerAdmissionDigest),
            revision: try values.decode(UInt64.self, forKey: .revision),
            previousDigest: try values.decodeIfPresent(Data.self, forKey: .previousDigest),
            routes: decodedRoutes,
            issuedAt: try values.decode(Date.self, forKey: .issuedAt),
            expiresAt: try values.decode(Date.self, forKey: .expiresAt),
            signature: try values.decode(Data.self, forKey: .signature)
        )
        guard routes == decodedRoutes, try isStructurallyValidThrowing else {
            throw DecodingError.dataCorruptedError(
                forKey: .signature,
                in: values,
                debugDescription: "Invalid signed group route set"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid group route set")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(groupID, forKey: .groupID)
        try values.encode(ownerCredentialHandle, forKey: .ownerCredentialHandle)
        try values.encode(ownerAdmissionDigest, forKey: .ownerAdmissionDigest)
        try values.encode(revision, forKey: .revision)
        try values.encode(previousDigest, forKey: .previousDigest)
        try values.encode(routes, forKey: .routes)
        try values.encode(issuedAt, forKey: .issuedAt)
        try values.encode(expiresAt, forKey: .expiresAt)
        try values.encode(signature, forKey: .signature)
    }

    public static func create(
        groupID: UUID,
        ownerCredentialHandle: GroupScopedCredentialHandleV2,
        ownerAdmissionDigest: Data,
        routes: [OpaqueSendRouteV2],
        issuedAt: Date,
        expiresAt: Date,
        signingKey: SigningKeyPair
    ) throws -> SignedGroupOpaqueRouteSetV2 {
        try signed(
            groupID: groupID,
            ownerCredentialHandle: ownerCredentialHandle,
            ownerAdmissionDigest: ownerAdmissionDigest,
            revision: 0,
            previousDigest: nil,
            routes: routes,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            signingKey: signingKey
        )
    }

    public func successor(
        routes: [OpaqueSendRouteV2],
        issuedAt: Date,
        expiresAt: Date,
        signingKey: SigningKeyPair
    ) throws -> SignedGroupOpaqueRouteSetV2 {
        guard revision < UInt64.max,
              let digest,
              try verifyThrowing(ownerSigningPublicKey: signingKey.publicKeyData),
              issuedAt >= self.issuedAt else {
            throw GroupOpaqueRouteTransportV2Error.invalidSuccessor
        }
        return try Self.signed(
            groupID: groupID,
            ownerCredentialHandle: ownerCredentialHandle,
            ownerAdmissionDigest: ownerAdmissionDigest,
            revision: revision + 1,
            previousDigest: digest,
            routes: routes,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            signingKey: signingKey
        )
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard version == Self.version,
                  ownerCredentialHandle.isStructurallyValid,
                  ownerAdmissionDigest.count == SHA256.byteCount,
                  previousDigest.map({ $0.count == SHA256.byteCount }) ?? true,
                  (revision == 0) == (previousDigest == nil),
                  !routes.isEmpty,
                  routes.count <= NoctweaveArchitectureV2.maximumRoutes,
                  routes == routes.sorted(by: Self.routeOrdering),
                  Set(routes.map(\.routeID)).count == routes.count,
                  routes.allSatisfy({ $0.state == .active || $0.state == .draining }),
                  issuedAt.timeIntervalSince1970.isFinite,
                  expiresAt.timeIntervalSince1970.isFinite,
                  issuedAt < expiresAt,
                  routes.allSatisfy({ $0.validFrom <= issuedAt && expiresAt <= $0.expiresAt }),
                  !signature.isEmpty,
                  signature.count <= 8 * 1_024 else {
                return false
            }
            for route in routes where try !route.isStructurallyValidThrowing {
                return false
            }
            return true
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    public func verifyThrowing(ownerSigningPublicKey: Data) throws -> Bool {
        guard try isStructurallyValidThrowing else { return false }
        return try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: signaturePayloadData(),
            publicKeyData: ownerSigningPublicKey
        )
    }

    public func verify(ownerSigningPublicKey: Data) -> Bool {
        (try? verifyThrowing(ownerSigningPublicKey: ownerSigningPublicKey)) == true
    }

    public func isValidSuccessor(
        of previous: SignedGroupOpaqueRouteSetV2,
        ownerSigningPublicKey: Data
    ) -> Bool {
        guard previous.revision < UInt64.max,
              groupID == previous.groupID,
              ownerCredentialHandle == previous.ownerCredentialHandle,
              ownerAdmissionDigest == previous.ownerAdmissionDigest,
              revision == previous.revision + 1,
              previousDigest == previous.digest,
              issuedAt >= previous.issuedAt else {
            return false
        }
        return verify(ownerSigningPublicKey: ownerSigningPublicKey)
    }

    public func usableRoutes(at date: Date) -> [OpaqueSendRouteV2] {
        guard date.timeIntervalSince1970.isFinite,
              issuedAt <= date.addingTimeInterval(
                  NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew
              ),
              date < expiresAt else {
            return []
        }
        return routes.filter { $0.isUsable(at: date) }.sorted {
            if $0.priority != $1.priority { return $0.priority < $1.priority }
            return Self.routeOrdering($0, $1)
        }
    }

    public var digest: Data? {
        guard isStructurallyValid,
              let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else {
            return nil
        }
        return Data(SHA256.hash(data: encoded))
    }

    private static func signed(
        groupID: UUID,
        ownerCredentialHandle: GroupScopedCredentialHandleV2,
        ownerAdmissionDigest: Data,
        revision: UInt64,
        previousDigest: Data?,
        routes: [OpaqueSendRouteV2],
        issuedAt: Date,
        expiresAt: Date,
        signingKey: SigningKeyPair
    ) throws -> SignedGroupOpaqueRouteSetV2 {
        let ordered = routes.sorted(by: routeOrdering)
        let unsigned = GroupOpaqueRouteSetSignaturePayloadV2(
            version: Self.version,
            groupID: groupID,
            ownerCredentialHandle: ownerCredentialHandle,
            ownerAdmissionDigest: ownerAdmissionDigest,
            revision: revision,
            previousDigest: previousDigest,
            routes: ordered,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
        let signature = try signingKey.sign(NoctweaveCoder.encode(unsigned, sortedKeys: true))
        let result = SignedGroupOpaqueRouteSetV2(
            groupID: groupID,
            ownerCredentialHandle: ownerCredentialHandle,
            ownerAdmissionDigest: ownerAdmissionDigest,
            revision: revision,
            previousDigest: previousDigest,
            routes: ordered,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            signature: signature
        )
        guard try result.isStructurallyValidThrowing else {
            throw GroupOpaqueRouteTransportV2Error.invalidRouteSet
        }
        return result
    }

    private func signaturePayloadData() throws -> Data {
        try NoctweaveCoder.encode(
            GroupOpaqueRouteSetSignaturePayloadV2(
                version: version,
                groupID: groupID,
                ownerCredentialHandle: ownerCredentialHandle,
                ownerAdmissionDigest: ownerAdmissionDigest,
                revision: revision,
                previousDigest: previousDigest,
                routes: routes,
                issuedAt: issuedAt,
                expiresAt: expiresAt
            ),
            sortedKeys: true
        )
    }

    private static func routeOrdering(_ lhs: OpaqueSendRouteV2, _ rhs: OpaqueSendRouteV2) -> Bool {
        lhs.routeID.rawValue.lexicographicallyPrecedes(rhs.routeID.rawValue)
    }
}

private struct GroupOpaqueRouteSetSignaturePayloadV2: Codable {
    let version: Int
    let groupID: UUID
    let ownerCredentialHandle: GroupScopedCredentialHandleV2
    let ownerAdmissionDigest: Data
    let revision: UInt64
    let previousDigest: Data?
    let routes: [OpaqueSendRouteV2]
    let issuedAt: Date
    let expiresAt: Date
}

/// Immutable, verified transport destination retained with an outbox operation.
public struct GroupOpaqueRouteDestinationSnapshotV2: Codable, Equatable {
    public let credential: GroupMemberCredentialV2
    public let routeSet: SignedGroupOpaqueRouteSetV2
    public let routeSetDigest: Data
    public let selectedRoutes: [OpaqueSendRouteV2]
    public let capturedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case credential
        case routeSet
        case routeSetDigest
        case selectedRoutes
        case capturedAt
    }

    public init(
        credential: GroupMemberCredentialV2,
        routeSet: SignedGroupOpaqueRouteSetV2,
        capturedAt: Date
    ) throws {
        guard credential.credentialHandle == routeSet.ownerCredentialHandle,
              credential.admissionDigest == routeSet.ownerAdmissionDigest,
              try routeSet.verifyThrowing(
                ownerSigningPublicKey: credential.signingPublicKey
              ),
              let digest = routeSet.digest else {
            throw GroupOpaqueRouteTransportV2Error.invalidDestinationSnapshot
        }
        let usable = routeSet.usableRoutes(at: capturedAt)
        guard !usable.isEmpty else {
            throw GroupOpaqueRouteTransportV2Error.invalidDestinationSnapshot
        }
        self.credential = credential
        self.routeSet = routeSet
        routeSetDigest = digest
        selectedRoutes = usable
        self.capturedAt = capturedAt
        guard try isStructurallyValidThrowing else {
            throw GroupOpaqueRouteTransportV2Error.invalidDestinationSnapshot
        }
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupOpaqueTransportKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        credential = try values.decode(GroupMemberCredentialV2.self, forKey: .credential)
        routeSet = try values.decode(SignedGroupOpaqueRouteSetV2.self, forKey: .routeSet)
        routeSetDigest = try values.decode(Data.self, forKey: .routeSetDigest)
        selectedRoutes = try values.decode([OpaqueSendRouteV2].self, forKey: .selectedRoutes)
        capturedAt = try values.decode(Date.self, forKey: .capturedAt)
        guard try isStructurallyValidThrowing else {
            throw DecodingError.dataCorruptedError(
                forKey: .routeSetDigest,
                in: values,
                debugDescription: "Invalid group destination snapshot"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid destination snapshot")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(credential, forKey: .credential)
        try values.encode(routeSet, forKey: .routeSet)
        try values.encode(routeSetDigest, forKey: .routeSetDigest)
        try values.encode(selectedRoutes, forKey: .selectedRoutes)
        try values.encode(capturedAt, forKey: .capturedAt)
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard credential.isStructurallyValid,
                  credential.credentialHandle == routeSet.ownerCredentialHandle,
                  credential.admissionDigest == routeSet.ownerAdmissionDigest,
                  routeSetDigest.count == SHA256.byteCount,
                  routeSet.digest == routeSetDigest,
                  !selectedRoutes.isEmpty,
                  selectedRoutes == routeSet.usableRoutes(at: capturedAt),
                  capturedAt.timeIntervalSince1970.isFinite else {
                return false
            }
            return try routeSet.verifyThrowing(
                ownerSigningPublicKey: credential.signingPublicKey
            )
        }
    }

    fileprivate var fanoutDestination: GroupOpaqueRouteDestinationV2 {
        GroupOpaqueRouteDestinationV2(
            credentialHandle: credential.credentialHandle,
            routes: selectedRoutes
        )
    }
}

public enum GroupOpaqueRouteOutboundOperationKindV2: String, Codable, Equatable {
    case application
    case epoch
    case deletion
}

public enum GroupOpaqueRouteArtifactKindV2: String, Codable, Equatable {
    case application
    case epochTransition
    case epochWelcome
    case deletion
}

public struct GroupOpaqueRoutePublicationAcceptanceV2: Codable, Equatable {
    public let receipts: [OpaqueRouteAppendReceiptV2]
    public let acceptedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case receipts
        case acceptedAt
    }

    fileprivate init(receipts: [OpaqueRouteAppendReceiptV2], acceptedAt: Date) {
        self.receipts = receipts
        self.acceptedAt = acceptedAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupOpaqueTransportKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        receipts = try values.decode([OpaqueRouteAppendReceiptV2].self, forKey: .receipts)
        acceptedAt = try values.decode(Date.self, forKey: .acceptedAt)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .receipts,
                in: values,
                debugDescription: "Invalid group publication acceptance"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid acceptance")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(receipts, forKey: .receipts)
        try values.encode(acceptedAt, forKey: .acceptedAt)
    }

    public var isStructurallyValid: Bool {
        !receipts.isEmpty
            && Set(receipts.map(\.packetID)).count == receipts.count
            && receipts.allSatisfy(\.isStructurallyValid)
            && acceptedAt.timeIntervalSince1970.isFinite
    }
}

/// Per-route state. The exact publication never changes; only durable attempt
/// and append-receipt evidence advances.
public struct GroupOpaqueRoutePublicationAttemptV2: Codable, Equatable, Identifiable {
    public var id: UUID { publication.id }
    public let publication: GroupOpaqueRoutePublicationV2
    public let predecessorPublicationID: UUID?
    public let attemptCount: UInt32
    public let lastAttemptAt: Date?
    public let acceptance: GroupOpaqueRoutePublicationAcceptanceV2?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case publication
        case predecessorPublicationID
        case attemptCount
        case lastAttemptAt
        case acceptance
    }

    fileprivate init(
        publication: GroupOpaqueRoutePublicationV2,
        predecessorPublicationID: UUID?,
        attemptCount: UInt32 = 0,
        lastAttemptAt: Date? = nil,
        acceptance: GroupOpaqueRoutePublicationAcceptanceV2? = nil
    ) {
        self.publication = publication
        self.predecessorPublicationID = predecessorPublicationID
        self.attemptCount = attemptCount
        self.lastAttemptAt = lastAttemptAt
        self.acceptance = acceptance
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupOpaqueTransportKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            publication: try values.decode(
                GroupOpaqueRoutePublicationV2.self,
                forKey: .publication
            ),
            predecessorPublicationID: try values.decodeIfPresent(
                UUID.self,
                forKey: .predecessorPublicationID
            ),
            attemptCount: try values.decode(UInt32.self, forKey: .attemptCount),
            lastAttemptAt: try values.decodeIfPresent(Date.self, forKey: .lastAttemptAt),
            acceptance: try values.decodeIfPresent(
                GroupOpaqueRoutePublicationAcceptanceV2.self,
                forKey: .acceptance
            )
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .attemptCount,
                in: values,
                debugDescription: "Invalid group route attempt"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid route attempt")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(publication, forKey: .publication)
        try values.encode(predecessorPublicationID, forKey: .predecessorPublicationID)
        try values.encode(attemptCount, forKey: .attemptCount)
        try values.encode(lastAttemptAt, forKey: .lastAttemptAt)
        try values.encode(acceptance, forKey: .acceptance)
    }

    public var isStructurallyValid: Bool {
        publication.isStructurallyValid
            && (attemptCount == 0) == (lastAttemptAt == nil)
            && lastAttemptAt.map { $0.timeIntervalSince1970.isFinite } ?? true
            && acceptance.map { accepted in
                guard attemptCount > 0,
                      let lastAttemptAt,
                      accepted.isStructurallyValid,
                      accepted.acceptedAt >= lastAttemptAt,
                      accepted.receipts.count == publication.packets.count else {
                    return false
                }
                return zip(accepted.receipts, publication.packets).allSatisfy {
                    $0.packetID == $1.packetID
                }
            } ?? true
    }

    fileprivate func recordingAttempt(at date: Date) throws -> Self {
        if acceptance != nil { return self }
        guard attemptCount < UInt32.max,
              date.timeIntervalSince1970.isFinite,
              date >= publication.createdAt,
              lastAttemptAt.map({ date >= $0 }) ?? true else {
            throw GroupOpaqueRouteTransportV2Error.capacityReached
        }
        return Self(
            publication: publication,
            predecessorPublicationID: predecessorPublicationID,
            attemptCount: attemptCount + 1,
            lastAttemptAt: date
        )
    }

    fileprivate func recordingAcceptance(
        receipts: [OpaqueRouteAppendReceiptV2],
        at date: Date
    ) throws -> Self {
        guard attemptCount > 0, let lastAttemptAt else {
            throw GroupOpaqueRouteTransportV2Error.attemptRequired
        }
        let byPacket = Dictionary(uniqueKeysWithValues: receipts.map { ($0.packetID, $0) })
        guard byPacket.count == receipts.count,
              byPacket.count == publication.packets.count else {
            throw GroupOpaqueRouteTransportV2Error.conflictingAcceptance
        }
        let ordered = try publication.packets.map { packet -> OpaqueRouteAppendReceiptV2 in
            guard let receipt = byPacket[packet.packetID], receipt.isStructurallyValid else {
                throw GroupOpaqueRouteTransportV2Error.conflictingAcceptance
            }
            return receipt
        }
        if let acceptance {
            guard acceptance.receipts == ordered,
                  date.timeIntervalSince1970.isFinite,
                  date >= acceptance.acceptedAt else {
                throw GroupOpaqueRouteTransportV2Error.conflictingAcceptance
            }
            return self
        }
        let accepted = GroupOpaqueRoutePublicationAcceptanceV2(
            receipts: ordered,
            acceptedAt: date
        )
        guard date >= lastAttemptAt, accepted.isStructurallyValid else {
            throw GroupOpaqueRouteTransportV2Error.conflictingAcceptance
        }
        return Self(
            publication: publication,
            predecessorPublicationID: predecessorPublicationID,
            attemptCount: attemptCount,
            lastAttemptAt: lastAttemptAt,
            acceptance: accepted
        )
    }

    fileprivate func replacingPublication(
        _ publication: GroupOpaqueRoutePublicationV2
    ) throws -> Self {
        guard publication.id == self.publication.id,
              acceptance == nil else {
            throw GroupOpaqueRouteTransportV2Error.invalidOperation
        }
        let result = Self(
            publication: publication,
            predecessorPublicationID: predecessorPublicationID,
            attemptCount: attemptCount,
            lastAttemptAt: lastAttemptAt,
            acceptance: nil
        )
        guard result.isStructurallyValid else {
            throw GroupOpaqueRouteTransportV2Error.invalidOperation
        }
        return result
    }
}

public struct GroupOpaqueRouteTransportDeliveryV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let artifactKind: GroupOpaqueRouteArtifactKindV2
    public let requiredCredentialHandles: [GroupScopedCredentialHandleV2]
    public let plan: GroupOpaqueRouteFanoutPlanV2
    public let attempts: [GroupOpaqueRoutePublicationAttemptV2]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case artifactKind
        case requiredCredentialHandles
        case plan
        case attempts
    }

    fileprivate init(
        id: UUID = UUID(),
        artifactKind: GroupOpaqueRouteArtifactKindV2,
        requiredCredentialHandles: [GroupScopedCredentialHandleV2],
        plan: GroupOpaqueRouteFanoutPlanV2,
        predecessorByPublicationID: [UUID: UUID] = [:]
    ) {
        self.id = id
        self.artifactKind = artifactKind
        self.requiredCredentialHandles = requiredCredentialHandles.sorted {
            $0.rawValue < $1.rawValue
        }
        self.plan = plan
        attempts = plan.publications.map {
            GroupOpaqueRoutePublicationAttemptV2(
                publication: $0,
                predecessorPublicationID: predecessorByPublicationID[$0.id]
            )
        }
    }

    private init(
        id: UUID,
        artifactKind: GroupOpaqueRouteArtifactKindV2,
        requiredCredentialHandles: [GroupScopedCredentialHandleV2],
        plan: GroupOpaqueRouteFanoutPlanV2,
        attempts: [GroupOpaqueRoutePublicationAttemptV2]
    ) {
        self.id = id
        self.artifactKind = artifactKind
        self.requiredCredentialHandles = requiredCredentialHandles
        self.plan = plan
        self.attempts = attempts
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupOpaqueTransportKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try values.decode(UUID.self, forKey: .id),
            artifactKind: try values.decode(
                GroupOpaqueRouteArtifactKindV2.self,
                forKey: .artifactKind
            ),
            requiredCredentialHandles: try values.decode(
                [GroupScopedCredentialHandleV2].self,
                forKey: .requiredCredentialHandles
            ),
            plan: try values.decode(GroupOpaqueRouteFanoutPlanV2.self, forKey: .plan),
            attempts: try values.decode(
                [GroupOpaqueRoutePublicationAttemptV2].self,
                forKey: .attempts
            )
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .attempts,
                in: values,
                debugDescription: "Invalid group transport delivery"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid delivery")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(id, forKey: .id)
        try values.encode(artifactKind, forKey: .artifactKind)
        try values.encode(requiredCredentialHandles, forKey: .requiredCredentialHandles)
        try values.encode(plan, forKey: .plan)
        try values.encode(attempts, forKey: .attempts)
    }

    public var isStructurallyValid: Bool {
        let required = Set(requiredCredentialHandles)
        return !required.isEmpty
            && required.count == requiredCredentialHandles.count
            && requiredCredentialHandles == requiredCredentialHandles.sorted {
                $0.rawValue < $1.rawValue
            }
            && plan.isStructurallyValid
            && Set(plan.publications.map(\.destinationCredentialHandle)) == required
            && attempts.count == plan.publications.count
            && zip(attempts, plan.publications).allSatisfy {
                $0.publication == $1 && $0.isStructurallyValid
            }
    }

    public var isComplete: Bool {
        requiredCredentialHandles.allSatisfy { credentialHandle in
            attempts.contains {
                $0.publication.destinationCredentialHandle == credentialHandle
                    && $0.acceptance != nil
            }
        }
    }

    fileprivate func replacingAttempt(
        _ updated: GroupOpaqueRoutePublicationAttemptV2
    ) throws -> Self {
        guard let index = attempts.firstIndex(where: { $0.id == updated.id }) else {
            throw GroupOpaqueRouteTransportV2Error.publicationNotFound
        }
        var next = attempts
        next[index] = updated
        let result = Self(
            id: id,
            artifactKind: artifactKind,
            requiredCredentialHandles: requiredCredentialHandles,
            plan: plan,
            attempts: next
        )
        guard result.isStructurallyValid else {
            throw GroupOpaqueRouteTransportV2Error.invalidOperation
        }
        return result
    }

    fileprivate func refreshingPublicationAuthorization(
        publicationID: UUID,
        at date: Date
    ) throws -> Self {
        guard let index = attempts.firstIndex(where: { $0.id == publicationID }) else {
            throw GroupOpaqueRouteTransportV2Error.publicationNotFound
        }
        let refreshed = try attempts[index].publication.refreshingExpiredAuthorizations(at: date)
        if refreshed == attempts[index].publication { return self }
        var nextAttempts = attempts
        nextAttempts[index] = try nextAttempts[index].replacingPublication(refreshed)
        let result = Self(
            id: id,
            artifactKind: artifactKind,
            requiredCredentialHandles: requiredCredentialHandles,
            plan: try plan.replacingPublication(refreshed),
            attempts: nextAttempts
        )
        guard result.isStructurallyValid else {
            throw GroupOpaqueRouteTransportV2Error.invalidOperation
        }
        return result
    }
}

public struct GroupOpaqueRouteOutboundOperationV2: Codable, Equatable, Identifiable {
    public static let version = 2
    public static let maximumJournalEntries = 128
    public static let recentCompletedWindow = 64

    public let version: Int
    public let id: UUID
    public let groupID: UUID
    public let kind: GroupOpaqueRouteOutboundOperationKindV2
    public let logicalID: UUID
    public let destinationSnapshots: [GroupOpaqueRouteDestinationSnapshotV2]
    public let deliveries: [GroupOpaqueRouteTransportDeliveryV2]
    public let createdAt: Date
    public let updatedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case groupID
        case kind
        case logicalID
        case destinationSnapshots
        case deliveries
        case createdAt
        case updatedAt
    }

    private init(
        version: Int = Self.version,
        id: UUID = UUID(),
        groupID: UUID,
        kind: GroupOpaqueRouteOutboundOperationKindV2,
        logicalID: UUID,
        destinationSnapshots: [GroupOpaqueRouteDestinationSnapshotV2],
        deliveries: [GroupOpaqueRouteTransportDeliveryV2],
        createdAt: Date,
        updatedAt: Date
    ) {
        self.version = version
        self.id = id
        self.groupID = groupID
        self.kind = kind
        self.logicalID = logicalID
        self.destinationSnapshots = destinationSnapshots.sorted {
            $0.credential.credentialHandle.rawValue < $1.credential.credentialHandle.rawValue
        }
        self.deliveries = deliveries
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupOpaqueTransportKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let decodedSnapshots = try values.decode(
            [GroupOpaqueRouteDestinationSnapshotV2].self,
            forKey: .destinationSnapshots
        )
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            id: try values.decode(UUID.self, forKey: .id),
            groupID: try values.decode(UUID.self, forKey: .groupID),
            kind: try values.decode(
                GroupOpaqueRouteOutboundOperationKindV2.self,
                forKey: .kind
            ),
            logicalID: try values.decode(UUID.self, forKey: .logicalID),
            destinationSnapshots: decodedSnapshots,
            deliveries: try values.decode(
                [GroupOpaqueRouteTransportDeliveryV2].self,
                forKey: .deliveries
            ),
            createdAt: try values.decode(Date.self, forKey: .createdAt),
            updatedAt: try values.decode(Date.self, forKey: .updatedAt)
        )
        guard destinationSnapshots == decodedSnapshots, isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .deliveries,
                in: values,
                debugDescription: "Invalid group outbound transport operation"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid transport operation")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(id, forKey: .id)
        try values.encode(groupID, forKey: .groupID)
        try values.encode(kind, forKey: .kind)
        try values.encode(logicalID, forKey: .logicalID)
        try values.encode(destinationSnapshots, forKey: .destinationSnapshots)
        try values.encode(deliveries, forKey: .deliveries)
        try values.encode(createdAt, forKey: .createdAt)
        try values.encode(updatedAt, forKey: .updatedAt)
    }

    public var isStructurallyValid: Bool {
        let snapshotHandles = Set(destinationSnapshots.map {
            $0.credential.credentialHandle
        })
        let requiredHandles = Set(deliveries.flatMap(\.requiredCredentialHandles))
        guard version == Self.version,
              !destinationSnapshots.isEmpty,
              snapshotHandles.count == destinationSnapshots.count,
              destinationSnapshots.allSatisfy({
                  $0.routeSet.groupID == groupID && $0.isStructurallyValid
              }),
              !deliveries.isEmpty,
              Set(deliveries.map(\.id)).count == deliveries.count,
              deliveries.allSatisfy({
                  $0.plan.groupID == groupID && $0.isStructurallyValid
              }),
              requiredHandles == snapshotHandles,
              createdAt.timeIntervalSince1970.isFinite,
              updatedAt.timeIntervalSince1970.isFinite,
              updatedAt >= createdAt else {
            return false
        }
        let allAttempts = deliveries.flatMap(\.attempts)
        guard Set(allAttempts.map(\.id)).count == allAttempts.count else { return false }
        let acceptedIDs = Set(allAttempts.compactMap { $0.acceptance == nil ? nil : $0.id })
        guard allAttempts.allSatisfy({ attempt in
            attempt.predecessorPublicationID.map { predecessor in
                allAttempts.contains(where: { $0.id == predecessor })
                    && (attempt.acceptance == nil || acceptedIDs.contains(predecessor))
            } ?? true
        }) else {
            return false
        }
        switch kind {
        case .application:
            return deliveries.count == 1 && deliveries[0].artifactKind == .application
                && deliveries[0].plan.protocolEnvelopeID == logicalID
                && deliveries[0].attempts.allSatisfy {
                    $0.predecessorPublicationID == nil
                }
        case .epoch:
            let transitions = deliveries.filter { $0.artifactKind == .epochTransition }
            let welcomes = deliveries.filter { $0.artifactKind == .epochWelcome }
            guard transitions.count == 1,
                  welcomes.count == deliveries.count - 1,
                  Set(welcomes.flatMap(\.requiredCredentialHandles)).count
                    == welcomes.count else {
                return false
            }
            let transitionByDestinationRoute = Dictionary(uniqueKeysWithValues:
                transitions[0].attempts.map {
                    (GroupDestinationRouteKeyV2(
                        credentialHandle: $0.publication.destinationCredentialHandle,
                        routeID: $0.publication.destinationRouteID
                    ), $0.id)
                }
            )
            return transitions[0].attempts.allSatisfy {
                    $0.predecessorPublicationID == nil
                }
                && welcomes.allSatisfy { delivery in
                    delivery.requiredCredentialHandles.count == 1
                        && delivery.attempts.allSatisfy { attempt in
                            let key = GroupDestinationRouteKeyV2(
                                credentialHandle: attempt.publication
                                    .destinationCredentialHandle,
                                routeID: attempt.publication.destinationRouteID
                            )
                            return attempt.predecessorPublicationID
                                == transitionByDestinationRoute[key]
                        }
                }
        case .deletion:
            return deliveries.count == 1
                && deliveries[0].artifactKind == .deletion
                && deliveries[0].plan.protocolEnvelopeID == logicalID
                && deliveries[0].attempts.allSatisfy {
                    $0.predecessorPublicationID == nil
                }
        }
    }

    public var isComplete: Bool {
        deliveries.allSatisfy(\.isComplete)
    }

    public var eligiblePublications: [GroupOpaqueRoutePublicationV2] {
        guard !isComplete else { return [] }
        let acceptedIDs = Set(deliveries.flatMap(\.attempts).compactMap {
            $0.acceptance == nil ? nil : $0.id
        })
        return deliveries.flatMap(\.attempts).filter { attempt in
            attempt.acceptance == nil
                && (attempt.predecessorPublicationID.map(acceptedIDs.contains) ?? true)
        }.map(\.publication)
    }

    public func acceptedCredentialHandles(
        for artifactKind: GroupOpaqueRouteArtifactKindV2
    ) -> Set<GroupScopedCredentialHandleV2> {
        Set(deliveries.filter { $0.artifactKind == artifactKind }.flatMap { delivery in
            delivery.requiredCredentialHandles.filter { credentialHandle in
                delivery.attempts.contains {
                    $0.publication.destinationCredentialHandle == credentialHandle
                        && $0.acceptance != nil
                }
            }
        })
    }

    fileprivate func recordingAttempt(
        publicationID: UUID,
        at date: Date
    ) throws -> (Self, GroupOpaqueRoutePublicationV2) {
        guard date >= updatedAt,
              eligiblePublications.contains(where: { $0.id == publicationID }) else {
            throw GroupOpaqueRouteTransportV2Error.publicationNotEligible
        }
        guard let deliveryIndex = deliveries.firstIndex(where: {
            $0.attempts.contains(where: { $0.id == publicationID })
        }),
              let attempt = deliveries[deliveryIndex].attempts.first(where: {
                  $0.id == publicationID
              }) else {
            throw GroupOpaqueRouteTransportV2Error.publicationNotFound
        }
        let updatedAttempt = try attempt.recordingAttempt(at: date)
        var updatedDeliveries = deliveries
        updatedDeliveries[deliveryIndex] = try updatedDeliveries[deliveryIndex]
            .replacingAttempt(updatedAttempt)
        let result = Self(
            id: id,
            groupID: groupID,
            kind: kind,
            logicalID: logicalID,
            destinationSnapshots: destinationSnapshots,
            deliveries: updatedDeliveries,
            createdAt: createdAt,
            updatedAt: date
        )
        guard result.isStructurallyValid else {
            throw GroupOpaqueRouteTransportV2Error.invalidOperation
        }
        return (result, attempt.publication)
    }

    fileprivate func refreshingPublicationAuthorization(
        publicationID: UUID,
        at date: Date
    ) throws -> Self {
        guard let index = deliveries.firstIndex(where: {
            $0.attempts.contains(where: { $0.id == publicationID })
        }) else {
            throw GroupOpaqueRouteTransportV2Error.publicationNotFound
        }
        var updatedDeliveries = deliveries
        updatedDeliveries[index] = try updatedDeliveries[index]
            .refreshingPublicationAuthorization(publicationID: publicationID, at: date)
        if updatedDeliveries == deliveries { return self }
        let result = Self(
            id: id,
            groupID: groupID,
            kind: kind,
            logicalID: logicalID,
            destinationSnapshots: destinationSnapshots,
            deliveries: updatedDeliveries,
            createdAt: createdAt,
            updatedAt: max(updatedAt, date)
        )
        guard result.isStructurallyValid else {
            throw GroupOpaqueRouteTransportV2Error.invalidOperation
        }
        return result
    }

    fileprivate func recordingAcceptance(
        publicationID: UUID,
        receipts: [OpaqueRouteAppendReceiptV2],
        at date: Date
    ) throws -> Self {
        guard date >= updatedAt else {
            throw GroupOpaqueRouteTransportV2Error.conflictingAcceptance
        }
        guard let deliveryIndex = deliveries.firstIndex(where: {
            $0.attempts.contains(where: { $0.id == publicationID })
        }),
              let attempt = deliveries[deliveryIndex].attempts.first(where: {
                  $0.id == publicationID
              }) else {
            throw GroupOpaqueRouteTransportV2Error.publicationNotFound
        }
        if let predecessor = attempt.predecessorPublicationID {
            let predecessorAccepted = deliveries.flatMap(\.attempts).contains {
                $0.id == predecessor && $0.acceptance != nil
            }
            guard predecessorAccepted else {
                throw GroupOpaqueRouteTransportV2Error.publicationNotEligible
            }
        }
        let updatedAttempt = try attempt.recordingAcceptance(receipts: receipts, at: date)
        var updatedDeliveries = deliveries
        updatedDeliveries[deliveryIndex] = try updatedDeliveries[deliveryIndex]
            .replacingAttempt(updatedAttempt)
        let result = Self(
            id: id,
            groupID: groupID,
            kind: kind,
            logicalID: logicalID,
            destinationSnapshots: destinationSnapshots,
            deliveries: updatedDeliveries,
            createdAt: createdAt,
            updatedAt: date
        )
        guard result.isStructurallyValid else {
            throw GroupOpaqueRouteTransportV2Error.invalidOperation
        }
        return result
    }

    fileprivate static func application(
        eventID: UUID,
        envelope: GroupApplicationEnvelopeV2,
        groupID: UUID,
        snapshots: [GroupOpaqueRouteDestinationSnapshotV2],
        at date: Date
    ) throws -> Self {
        let destinations = snapshots.map(\.fanoutDestination)
        let plan = try GroupOpaqueRouteFanoutPlanV2.create(
            envelope: .groupApplicationV2(envelope),
            groupID: groupID,
            destinations: destinations,
            at: date
        )
        let delivery = GroupOpaqueRouteTransportDeliveryV2(
            artifactKind: .application,
            requiredCredentialHandles: snapshots.map { $0.credential.credentialHandle },
            plan: plan
        )
        let result = Self(
            groupID: groupID,
            kind: .application,
            logicalID: eventID,
            destinationSnapshots: snapshots,
            deliveries: [delivery],
            createdAt: date,
            updatedAt: date
        )
        guard result.isStructurallyValid else {
            throw GroupOpaqueRouteTransportV2Error.invalidOperation
        }
        return result
    }

    fileprivate static func deletion(
        tombstone: SignedGroupDeletionTombstoneV2,
        groupID: UUID,
        snapshots: [GroupOpaqueRouteDestinationSnapshotV2],
        at date: Date
    ) throws -> Self {
        let plan = try GroupOpaqueRouteFanoutPlanV2.create(
            envelope: .groupDeletionV2(tombstone),
            groupID: groupID,
            destinations: snapshots.map(\.fanoutDestination),
            at: date
        )
        let delivery = GroupOpaqueRouteTransportDeliveryV2(
            artifactKind: .deletion,
            requiredCredentialHandles: snapshots.map { $0.credential.credentialHandle },
            plan: plan
        )
        let result = Self(
            groupID: groupID,
            kind: .deletion,
            logicalID: tombstone.id,
            destinationSnapshots: snapshots,
            deliveries: [delivery],
            createdAt: date,
            updatedAt: date
        )
        guard result.isStructurallyValid else {
            throw GroupOpaqueRouteTransportV2Error.invalidOperation
        }
        return result
    }

    fileprivate static func epoch(
        intent: GroupEpochIntent,
        groupID: UUID,
        transitionSnapshots: [GroupOpaqueRouteDestinationSnapshotV2],
        welcomeCredentialHandles: Set<GroupScopedCredentialHandleV2>,
        at date: Date
    ) throws -> Self {
        let transitionPlan = try GroupOpaqueRouteFanoutPlanV2.create(
            envelope: .groupCommitV2(intent.publication.transition),
            groupID: groupID,
            destinations: transitionSnapshots.map(\.fanoutDestination),
            at: date
        )
        let transitionDelivery = GroupOpaqueRouteTransportDeliveryV2(
            artifactKind: .epochTransition,
            requiredCredentialHandles: transitionSnapshots.map {
                $0.credential.credentialHandle
            },
            plan: transitionPlan
        )
        var deliveries = [transitionDelivery]
        let snapshotsByHandle = Dictionary(uniqueKeysWithValues: transitionSnapshots.map {
            ($0.credential.credentialHandle, $0)
        })
        let transitionByDestinationRoute = Dictionary(uniqueKeysWithValues:
            transitionPlan.publications.map {
                (GroupDestinationRouteKeyV2(
                    credentialHandle: $0.destinationCredentialHandle,
                    routeID: $0.destinationRouteID
                ), $0.id)
            }
        )
        for welcome in intent.signedWelcomes where
            welcomeCredentialHandles.contains(welcome.destinationCredentialHandle) {
            guard let snapshot = snapshotsByHandle[welcome.destinationCredentialHandle] else {
                throw GroupOpaqueRouteTransportV2Error.invalidDestinationSnapshot
            }
            let plan = try GroupOpaqueRouteFanoutPlanV2.create(
                envelope: .groupWelcomeV2(welcome),
                groupID: groupID,
                destinations: [snapshot.fanoutDestination],
                at: date
            )
            var predecessors: [UUID: UUID] = [:]
            for publication in plan.publications {
                let key = GroupDestinationRouteKeyV2(
                    credentialHandle: publication.destinationCredentialHandle,
                    routeID: publication.destinationRouteID
                )
                guard let predecessor = transitionByDestinationRoute[key] else {
                    throw GroupOpaqueRouteTransportV2Error.invalidOperation
                }
                predecessors[publication.id] = predecessor
            }
            deliveries.append(GroupOpaqueRouteTransportDeliveryV2(
                artifactKind: .epochWelcome,
                requiredCredentialHandles: [welcome.destinationCredentialHandle],
                plan: plan,
                predecessorByPublicationID: predecessors
            ))
        }
        let result = Self(
            groupID: groupID,
            kind: .epoch,
            logicalID: intent.id,
            destinationSnapshots: transitionSnapshots,
            deliveries: deliveries,
            createdAt: date,
            updatedAt: date
        )
        guard result.isStructurallyValid else {
            throw GroupOpaqueRouteTransportV2Error.invalidOperation
        }
        return result
    }
}

private struct GroupDestinationRouteKeyV2: Hashable {
    let credentialHandle: GroupScopedCredentialHandleV2
    let routeID: OpaqueReceiveRouteIDV2
}

extension NoctweavePQGroupRuntimeV2 {
    public func outboundTransportOperations() -> [GroupOpaqueRouteOutboundOperationV2] {
        record.outboundTransportOperations
    }

    /// Persists exact application packets before any relay append can occur.
    /// A nil result means the group has no remote credential to address.
    public func prepareApplicationTransport(
        eventID: UUID,
        routeSets: [SignedGroupOpaqueRouteSetV2],
        at date: Date = Date()
    ) async throws -> GroupOpaqueRouteOutboundOperationV2? {
        try requireActiveRuntime()
        if let existing = record.outboundTransportOperations.first(where: {
            $0.kind == .application && $0.logicalID == eventID
        }) {
            return existing
        }
        guard let pending = record.pendingApplicationPublications.first(where: {
            $0.event.id == eventID
        }), date >= pending.preparedAt else {
            throw GroupRuntimeError.publicationNotFound
        }
        let recipients = record.signedState.activeCredentials.filter {
            $0.memberHandle != record.localCredential.memberHandle
        }
        guard !recipients.isEmpty else {
            guard routeSets.isEmpty else {
                throw GroupOpaqueRouteTransportV2Error.invalidRouteSet
            }
            return nil
        }
        let snapshots = try makeDestinationSnapshots(
            credentials: recipients,
            routeSets: routeSets,
            at: date
        )
        let operation = try GroupOpaqueRouteOutboundOperationV2.application(
            eventID: eventID,
            envelope: pending.envelope,
            groupID: record.groupId,
            snapshots: snapshots,
            at: date
        )
        guard record.outboundTransportOperations.count
                < GroupOpaqueRouteOutboundOperationV2.maximumJournalEntries else {
            throw GroupOpaqueRouteTransportV2Error.capacityReached
        }
        try await persist(record.replacing(
            outboundTransportOperations: record.outboundTransportOperations + [operation]
        ))
        return operation
    }

    /// Persists the transition for the old/new credential union and a Welcome
    /// for every next-epoch remote credential. Per-route predecessor links
    /// force transition acceptance before the corresponding Welcome append.
    public func prepareEpochTransport(
        intentID: UUID,
        routeSets: [SignedGroupOpaqueRouteSetV2],
        at date: Date = Date()
    ) async throws -> GroupOpaqueRouteOutboundOperationV2? {
        try requireActiveRuntime()
        if let existing = record.outboundTransportOperations.first(where: {
            $0.kind == .epoch && $0.logicalID == intentID
        }) {
            return existing
        }
        guard let intent = record.epochIntents.first(where: { $0.id == intentID }),
              intent.phase == .stateCommitted || intent.phase == .fanoutInProgress,
              date >= intent.updatedAt else {
            throw GroupRuntimeError.invalidIntent
        }
        let transitionRecipients = intent.transportRecipientCredentials.filter {
            $0.memberHandle != intent.localCredentialAfterCommit.memberHandle
        }
        guard !transitionRecipients.isEmpty else {
            guard routeSets.isEmpty else {
                throw GroupOpaqueRouteTransportV2Error.invalidRouteSet
            }
            return nil
        }
        let snapshots = try makeDestinationSnapshots(
            credentials: transitionRecipients,
            routeSets: routeSets,
            at: date
        )
        let welcomeHandles = Set(intent.nextSignedState.activeCredentials.filter {
            $0.memberHandle != intent.localCredentialAfterCommit.memberHandle
        }.map(\.credentialHandle))
        let operation = try GroupOpaqueRouteOutboundOperationV2.epoch(
            intent: intent,
            groupID: record.groupId,
            transitionSnapshots: snapshots,
            welcomeCredentialHandles: welcomeHandles,
            at: date
        )
        guard record.outboundTransportOperations.count
                < GroupOpaqueRouteOutboundOperationV2.maximumJournalEntries else {
            throw GroupOpaqueRouteTransportV2Error.capacityReached
        }
        try await persist(record.replacing(
            outboundTransportOperations: record.outboundTransportOperations + [operation]
        ))
        return operation
    }

    /// Persists the exact deletion tombstone packets for every current remote
    /// group credential before relay I/O. A terminal local group remains able
    /// to finish only this retained transport operation.
    public func prepareDeletionTransport(
        tombstoneID: UUID,
        routeSets: [SignedGroupOpaqueRouteSetV2],
        at date: Date = Date()
    ) async throws -> GroupOpaqueRouteOutboundOperationV2? {
        if let existing = record.outboundTransportOperations.first(where: {
            $0.kind == .deletion && $0.logicalID == tombstoneID
        }) {
            return existing
        }
        guard let deletion = record.deletionState,
              deletion.origin == .local,
              deletion.publicationState == .pending,
              deletion.deletedState.tombstone.id == tombstoneID else {
            throw GroupRuntimeError.publicationNotFound
        }
        let recipients = record.signedState.activeCredentials.filter {
            $0.memberHandle != record.localCredential.memberHandle
        }
        guard !recipients.isEmpty else {
            guard routeSets.isEmpty else {
                throw GroupOpaqueRouteTransportV2Error.invalidRouteSet
            }
            return nil
        }
        let snapshots = try makeDestinationSnapshots(
            credentials: recipients,
            routeSets: routeSets,
            at: date
        )
        let operation = try GroupOpaqueRouteOutboundOperationV2.deletion(
            tombstone: deletion.deletedState.tombstone,
            groupID: record.groupId,
            snapshots: snapshots,
            at: date
        )
        guard record.outboundTransportOperations.count
                < GroupOpaqueRouteOutboundOperationV2.maximumJournalEntries else {
            throw GroupOpaqueRouteTransportV2Error.capacityReached
        }
        try await persist(record.replacing(
            outboundTransportOperations: record.outboundTransportOperations + [operation]
        ))
        return operation
    }

    public func eligibleOutboundTransportPublications(
        operationID: UUID
    ) throws -> [GroupOpaqueRoutePublicationV2] {
        guard let operation = record.outboundTransportOperations.first(where: {
            $0.id == operationID
        }) else {
            throw GroupOpaqueRouteTransportV2Error.operationNotFound
        }
        return operation.eligiblePublications
    }

    /// Must be saved before network I/O. Reopening the runtime returns the
    /// same publication bytes and records another attempt without resealing.
    @discardableResult
    internal func recordOutboundTransportAttempt(
        operationID: UUID,
        publicationID: UUID,
        at date: Date = Date()
    ) async throws -> GroupOpaqueRoutePublicationV2 {
        guard let index = record.outboundTransportOperations.firstIndex(where: {
            $0.id == operationID
        }) else {
            throw GroupOpaqueRouteTransportV2Error.operationNotFound
        }
        if record.outboundTransportOperations[index].kind == .deletion {
            guard record.deletionState?.deletedState.tombstone.id
                    == record.outboundTransportOperations[index].logicalID else {
                throw GroupOpaqueRouteTransportV2Error.invalidOperation
            }
        } else {
            try requireActiveRuntime()
        }
        let refreshed = try record.outboundTransportOperations[index]
            .refreshingPublicationAuthorization(
                publicationID: publicationID,
                at: date
            )
        let (updated, publication) = try refreshed.recordingAttempt(
            publicationID: publicationID,
            at: date
        )
        var operations = record.outboundTransportOperations
        operations[index] = updated
        try await persist(record.replacing(outboundTransportOperations: operations))
        return publication
    }

    /// Persists exact relay append receipts for every packet in one route
    /// publication. A bool, message ID, or destination assertion is not
    /// sufficient completion evidence.
    internal func recordOutboundTransportAcceptance(
        operationID: UUID,
        publicationID: UUID,
        receipts: [OpaqueRouteAppendReceiptV2],
        at date: Date = Date()
    ) async throws {
        guard let operationIndex = record.outboundTransportOperations.firstIndex(where: {
            $0.id == operationID
        }) else {
            throw GroupOpaqueRouteTransportV2Error.operationNotFound
        }
        if record.outboundTransportOperations[operationIndex].kind == .deletion {
            guard record.deletionState?.deletedState.tombstone.id
                    == record.outboundTransportOperations[operationIndex].logicalID else {
                throw GroupOpaqueRouteTransportV2Error.invalidOperation
            }
        } else {
            try requireActiveRuntime()
        }
        let updatedOperation = try record.outboundTransportOperations[operationIndex]
            .recordingAcceptance(
                publicationID: publicationID,
                receipts: receipts,
                at: date
            )
        var operations = record.outboundTransportOperations
        operations[operationIndex] = updatedOperation
        var intents = record.epochIntents
        if updatedOperation.kind == .epoch,
           let intentIndex = intents.firstIndex(where: {
               $0.id == updatedOperation.logicalID
           }) {
            let intent = intents[intentIndex]
            let accepted = updatedOperation.acceptedCredentialHandles(for: .epochWelcome)
            let merged = Set(intent.deliveredCredentialHandles).union(accepted)
            if !merged.isEmpty && merged != Set(intent.deliveredCredentialHandles) {
                intents[intentIndex] = try intent.advancing(
                    to: .fanoutInProgress,
                    deliveredCredentialHandles: Array(merged),
                    at: date
                )
            }
        }
        try await persist(record.replacing(
            epochIntents: intents,
            outboundTransportOperations: operations
        ))
    }

    internal func hasCompletedApplicationTransport(eventID: UUID) -> Bool {
        let remoteCredentials = record.signedState.activeCredentials.filter {
            $0.memberHandle != record.localCredential.memberHandle
        }
        if remoteCredentials.isEmpty { return true }
        return record.outboundTransportOperations.contains {
            $0.kind == .application && $0.logicalID == eventID && $0.isComplete
        }
    }

    internal func hasAcceptedEpochWelcome(
        intentID: UUID,
        credentialHandle: GroupScopedCredentialHandleV2
    ) -> Bool {
        if credentialHandle == record.localCredential.credentialHandle { return true }
        return record.outboundTransportOperations.first(where: {
            $0.kind == .epoch && $0.logicalID == intentID
        })?.acceptedCredentialHandles(for: .epochWelcome).contains(credentialHandle) == true
    }

    internal func hasCompletedEpochTransport(intent: GroupEpochIntent) -> Bool {
        let remoteCredentials = intent.transportRecipientCredentials.filter {
            $0.memberHandle != intent.localCredentialAfterCommit.memberHandle
        }
        if remoteCredentials.isEmpty { return true }
        return record.outboundTransportOperations.contains {
            $0.kind == .epoch && $0.logicalID == intent.id && $0.isComplete
        }
    }

    internal func hasCompletedDeletionTransport(tombstoneID: UUID) -> Bool {
        let remoteCredentials = record.signedState.activeCredentials.filter {
            $0.memberHandle != record.localCredential.memberHandle
        }
        if remoteCredentials.isEmpty { return true }
        return record.outboundTransportOperations.contains {
            $0.kind == .deletion && $0.logicalID == tombstoneID && $0.isComplete
        }
    }

    private func makeDestinationSnapshots(
        credentials: [GroupMemberCredentialV2],
        routeSets: [SignedGroupOpaqueRouteSetV2],
        at date: Date
    ) throws -> [GroupOpaqueRouteDestinationSnapshotV2] {
        guard date.timeIntervalSince1970.isFinite,
              Set(credentials.map(\.credentialHandle)).count == credentials.count,
              Set(routeSets.map(\.ownerCredentialHandle)).count == routeSets.count,
              Set(credentials.map(\.credentialHandle))
                == Set(routeSets.map(\.ownerCredentialHandle)) else {
            throw GroupOpaqueRouteTransportV2Error.invalidRouteSet
        }
        let routeSetsByHandle = Dictionary(uniqueKeysWithValues: routeSets.map {
            ($0.ownerCredentialHandle, $0)
        })
        return try credentials.map { credential in
            guard let routeSet = routeSetsByHandle[credential.credentialHandle],
                  routeSet.groupID == record.groupId,
                  routeSet.ownerAdmissionDigest == credential.admissionDigest else {
                throw GroupOpaqueRouteTransportV2Error.invalidRouteSet
            }
            return try GroupOpaqueRouteDestinationSnapshotV2(
                credential: credential,
                routeSet: routeSet,
                capturedAt: date
            )
        }
    }
}
