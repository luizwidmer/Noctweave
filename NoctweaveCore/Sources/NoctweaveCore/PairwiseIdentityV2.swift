import CryptoKit
import Foundation

public enum PairwiseIdentityV2Error: Error, Equatable {
    case invalidState
    case wrongIntroduction
}

public enum PairwiseRelationshipIDV2 {
    /// Both rendezvous participants derive the same relationship identifier
    /// without publishing it or carrying any profile identifier into it.
    public static func derive(from rendezvousTranscriptDigest: Data) throws -> UUID {
        guard rendezvousTranscriptDigest.count == SHA256.byteCount else {
            throw PairwiseIdentityV2Error.invalidState
        }
        var material = Data("Noctweave/pairwise-relationship-id/v2".utf8)
        material.append(0)
        material.append(rendezvousTranscriptDigest)
        var bytes = Array(SHA256.hash(data: material).prefix(16))
        bytes[6] = (bytes[6] & 0x0F) | 0x40
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        let value = "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12).prefix(4))-\(hex.dropFirst(16).prefix(4))-\(hex.dropFirst(20))"
        guard let uuid = UUID(uuidString: value) else {
            throw PairwiseIdentityV2Error.invalidState
        }
        return uuid
    }
}

/// Secret local identity material minted independently for exactly one
/// relationship. It is never certified by a profile-wide key, so two contacts
/// cannot correlate one another by comparing Noctweave identity or endpoint
/// keys. The containing persona is a local UI concept only.
public struct LocalPairwiseIdentityV2: Codable, Identifiable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let version = 2

    public let version: Int
    public let id: UUID
    public let generationID: UUID
    public var relationshipIdentity: Identity
    public var localEndpoint: LocalEndpointState
    public var endpointSetManifest: EndpointSetManifest
    public var certifiedEndpoint: CertifiedGenerationEndpoint
    public let createdAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case generationID
        case relationshipIdentity
        case localEndpoint
        case endpointSetManifest
        case certifiedEndpoint
        case createdAt
    }

    private init(
        version: Int = Self.version,
        id: UUID,
        generationID: UUID,
        relationshipIdentity: Identity,
        localEndpoint: LocalEndpointState,
        endpointSetManifest: EndpointSetManifest,
        certifiedEndpoint: CertifiedGenerationEndpoint,
        createdAt: Date
    ) {
        self.version = version
        self.id = id
        self.generationID = generationID
        self.relationshipIdentity = relationshipIdentity
        self.localEndpoint = localEndpoint
        self.endpointSetManifest = endpointSetManifest
        self.certifiedEndpoint = certifiedEndpoint
        self.createdAt = createdAt
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PairwiseIdentityCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Local pairwise identity fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try container.decode(Int.self, forKey: .version),
            id: try container.decode(UUID.self, forKey: .id),
            generationID: try container.decode(UUID.self, forKey: .generationID),
            relationshipIdentity: try container.decode(Identity.self, forKey: .relationshipIdentity),
            localEndpoint: try container.decode(LocalEndpointState.self, forKey: .localEndpoint),
            endpointSetManifest: try container.decode(EndpointSetManifest.self, forKey: .endpointSetManifest),
            certifiedEndpoint: try container.decode(CertifiedGenerationEndpoint.self, forKey: .certifiedEndpoint),
            createdAt: try container.decode(Date.self, forKey: .createdAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .relationshipIdentity,
                in: container,
                debugDescription: "Local pairwise identity is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Local pairwise identity is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(id, forKey: .id)
        try container.encode(generationID, forKey: .generationID)
        try container.encode(relationshipIdentity, forKey: .relationshipIdentity)
        try container.encode(localEndpoint, forKey: .localEndpoint)
        try container.encode(endpointSetManifest, forKey: .endpointSetManifest)
        try container.encode(certifiedEndpoint, forKey: .certifiedEndpoint)
        try container.encode(createdAt, forKey: .createdAt)
    }

    public static func generate(
        displayName: String,
        id: UUID = UUID(),
        generationID: UUID = UUID(),
        createdAt: Date = Date()
    ) throws -> LocalPairwiseIdentityV2 {
        let relationshipIdentity = try Identity(
            displayName: displayName,
            signingKey: SigningKeyPair.generate(),
            agreementKey: AgreementKeyPair.generate(),
            createdAt: createdAt
        )
        let endpoint = try LocalEndpointState.generate(
            identityGenerationId: generationID,
            createdAt: createdAt
        )
        let manifest = try EndpointSetManifest.create(
            identityGenerationId: generationID,
            epoch: 0,
            endpoints: [endpoint.publicRecord(addedEpoch: 0)],
            identity: relationshipIdentity,
            issuedAt: createdAt
        )
        let certificate = try CertifiedGenerationEndpoint.create(
            identity: relationshipIdentity,
            endpoint: endpoint,
            manifest: manifest,
            issuedAt: createdAt
        )
        let result = LocalPairwiseIdentityV2(
            id: id,
            generationID: generationID,
            relationshipIdentity: relationshipIdentity,
            localEndpoint: endpoint,
            endpointSetManifest: manifest,
            certifiedEndpoint: certificate,
            createdAt: createdAt
        )
        guard result.isStructurallyValid else { throw PairwiseIdentityV2Error.invalidState }
        return result
    }

    public var isStructurallyValid: Bool {
        version == Self.version
            && !relationshipIdentity.displayName.isEmpty
            && relationshipIdentity.displayName.utf8.count <= 512
            && relationshipIdentity.createdAt == createdAt
            && localEndpoint.identityGenerationId == generationID
            && localEndpoint.createdAt == createdAt
            && endpointSetManifest.identityGenerationId == generationID
            && endpointSetManifest.endpoints.contains(where: { $0.id == localEndpoint.id })
            && endpointSetManifest.verify(
                identityPublicKey: relationshipIdentity.signingKey.publicKeyData
            )
            && certifiedEndpoint.identityGenerationId == generationID
            && certifiedEndpoint.endpointId == localEndpoint.id
            && (try? certifiedEndpoint.verified(
                identityPublicKey: relationshipIdentity.signingKey.publicKeyData,
                manifest: endpointSetManifest
            )) != nil
            && createdAt.timeIntervalSince1970.isFinite
    }

    public func makeInitialRouteSet(
        relationshipID: UUID,
        ownerEndpointHandle: RelationshipEndpointHandle,
        receiveRoute: PairwiseSendRouteV2,
        issuedAt: Date
    ) throws -> PairwiseRouteSetV2 {
        try PairwiseRouteSetV2.create(
            relationshipID: relationshipID,
            ownerEndpointHandle: ownerEndpointHandle,
            activeRoutes: [receiveRoute],
            issuedAt: issuedAt,
            signingKey: localEndpoint.signingKey
        )
    }

    public func makeIntroduction(
        receiveRoutes: PairwiseRouteSetV2,
        rendezvousTranscriptDigest: Data,
        issuedAt: Date,
        expiresAt: Date
    ) throws -> ContactIntroductionV2 {
        try ContactIntroductionV2.create(
            relationshipIdentity: relationshipIdentity,
            relationshipGenerationID: generationID,
            endpointSetManifest: endpointSetManifest,
            preferredEndpoint: certifiedEndpoint,
            receiveRoutes: receiveRoutes,
            rendezvousTranscriptDigest: rendezvousTranscriptDigest,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
    }

    public var description: String { "LocalPairwiseIdentityV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

/// Public relationship state learned from one verified rendezvous
/// introduction. The identifier is local-only; no field can be used to locate
/// a profile, account, or another relationship.
public struct PeerPairwiseIdentityV2: Codable, Equatable, Identifiable {
    public static let version = 2

    public let version: Int
    public let id: UUID
    public let relationshipID: UUID
    public var displayName: String
    public var generationID: UUID
    public var signingPublicKey: Data
    public var agreementPublicKey: Data
    public var endpointSetCheckpoint: EndpointSetCheckpointV4
    public var preferredEndpoint: CertifiedGenerationEndpoint
    public var sendRoutes: PairwiseRouteSetV2
    public var allowContinuity: Bool
    public let createdAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case relationshipID
        case displayName
        case generationID
        case signingPublicKey
        case agreementPublicKey
        case endpointSetCheckpoint
        case preferredEndpoint
        case sendRoutes
        case allowContinuity
        case createdAt
    }

    public init(
        id: UUID = UUID(),
        introduction: ContactIntroductionV2,
        rendezvousTranscriptDigest: Data,
        allowContinuity: Bool = false,
        acceptedAt: Date
    ) throws {
        let verified = try introduction.verified(
            for: rendezvousTranscriptDigest,
            at: acceptedAt
        )
        self.version = Self.version
        self.id = id
        self.relationshipID = try PairwiseRelationshipIDV2.derive(
            from: rendezvousTranscriptDigest
        )
        self.displayName = verified.displayName
        self.generationID = verified.relationshipGenerationID
        self.signingPublicKey = verified.relationshipSigningPublicKey
        self.agreementPublicKey = verified.relationshipAgreementPublicKey
        self.endpointSetCheckpoint = verified.endpointSetCheckpoint
        self.preferredEndpoint = verified.preferredEndpoint
        guard verified.receiveRoutes.verify(
            ownerSigningPublicKey: verified.preferredEndpoint.signingPublicKey
        ), verified.receiveRoutes.relationshipID == relationshipID else {
            throw PairwiseIdentityV2Error.wrongIntroduction
        }
        self.sendRoutes = verified.receiveRoutes
        self.allowContinuity = allowContinuity
        self.createdAt = acceptedAt
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PairwiseIdentityCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Peer pairwise identity fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        id = try container.decode(UUID.self, forKey: .id)
        relationshipID = try container.decode(UUID.self, forKey: .relationshipID)
        displayName = try container.decode(String.self, forKey: .displayName)
        generationID = try container.decode(UUID.self, forKey: .generationID)
        signingPublicKey = try container.decode(Data.self, forKey: .signingPublicKey)
        agreementPublicKey = try container.decode(Data.self, forKey: .agreementPublicKey)
        endpointSetCheckpoint = try container.decode(
            EndpointSetCheckpointV4.self,
            forKey: .endpointSetCheckpoint
        )
        preferredEndpoint = try container.decode(
            CertifiedGenerationEndpoint.self,
            forKey: .preferredEndpoint
        )
        sendRoutes = try container.decode(PairwiseRouteSetV2.self, forKey: .sendRoutes)
        allowContinuity = try container.decode(Bool.self, forKey: .allowContinuity)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .sendRoutes,
                in: container,
                debugDescription: "Peer pairwise identity is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Peer pairwise identity is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(id, forKey: .id)
        try container.encode(relationshipID, forKey: .relationshipID)
        try container.encode(displayName, forKey: .displayName)
        try container.encode(generationID, forKey: .generationID)
        try container.encode(signingPublicKey, forKey: .signingPublicKey)
        try container.encode(agreementPublicKey, forKey: .agreementPublicKey)
        try container.encode(endpointSetCheckpoint, forKey: .endpointSetCheckpoint)
        try container.encode(preferredEndpoint, forKey: .preferredEndpoint)
        try container.encode(sendRoutes, forKey: .sendRoutes)
        try container.encode(allowContinuity, forKey: .allowContinuity)
        try container.encode(createdAt, forKey: .createdAt)
    }

    public var isStructurallyValid: Bool {
        version == Self.version
            && !displayName.isEmpty
            && displayName.utf8.count <= 512
            && SigningKeyPair.isValidPublicKey(signingPublicKey)
            && AgreementKeyPair.isValidPublicKey(agreementPublicKey)
            && sendRoutes.relationshipID == relationshipID
            && endpointSetCheckpoint.identityGenerationId == generationID
            && preferredEndpoint.identityGenerationId == generationID
            && (try? preferredEndpoint.verified(
                identityPublicKey: signingPublicKey,
                checkpoint: endpointSetCheckpoint,
                now: preferredEndpoint.prekeyBundle.createdAt
            )) != nil
            && sendRoutes.isStructurallyValid
            && sendRoutes.verify(ownerSigningPublicKey: preferredEndpoint.signingPublicKey)
            && createdAt.timeIntervalSince1970.isFinite
    }
}

private struct PairwiseIdentityCodingKey: CodingKey {
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
