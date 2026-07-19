import CryptoKit
import Foundation

public enum PairwiseIdentityV2Error: Error, Equatable {
    case invalidState
    case wrongIntroduction
}

public enum PairwiseRelationshipIDV2 {
    /// Both rendezvous participants derive the same relationship identifier
    /// without publishing it or carrying any persona identifier into it.
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

/// Secret authority and endpoint material minted independently for exactly one
/// relationship. No account, persona, generation, or device identifier is
/// disclosed in the pairwise introduction or direct wire.
public struct LocalPairwiseIdentityV2: Codable, Equatable, Identifiable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let version = 2

    public let version: Int
    public let id: UUID
    public var relationshipAuthority: RelationshipAuthorityV2
    public var localEndpoint: LocalRelationshipEndpointV2
    public var endpointBinding: RelationshipEndpointBindingV4
    public let createdAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case relationshipAuthority
        case localEndpoint
        case endpointBinding
        case createdAt
    }

    private init(
        version: Int = Self.version,
        id: UUID,
        relationshipAuthority: RelationshipAuthorityV2,
        localEndpoint: LocalRelationshipEndpointV2,
        endpointBinding: RelationshipEndpointBindingV4,
        createdAt: Date
    ) {
        self.version = version
        self.id = id
        self.relationshipAuthority = relationshipAuthority
        self.localEndpoint = localEndpoint
        self.endpointBinding = endpointBinding
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
            relationshipAuthority: try container.decode(
                RelationshipAuthorityV2.self,
                forKey: .relationshipAuthority
            ),
            localEndpoint: try container.decode(LocalRelationshipEndpointV2.self, forKey: .localEndpoint),
            endpointBinding: try container.decode(RelationshipEndpointBindingV4.self, forKey: .endpointBinding),
            createdAt: try container.decode(Date.self, forKey: .createdAt)
        )
        guard try isStructurallyValidThrowing else {
            throw DecodingError.dataCorruptedError(
                forKey: .relationshipAuthority,
                in: container,
                debugDescription: "Local pairwise identity is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
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
        try container.encode(relationshipAuthority, forKey: .relationshipAuthority)
        try container.encode(localEndpoint, forKey: .localEndpoint)
        try container.encode(endpointBinding, forKey: .endpointBinding)
        try container.encode(createdAt, forKey: .createdAt)
    }

    public static func generate(
        relationshipPseudonym: String,
        id: UUID = UUID(),
        createdAt: Date = Date()
    ) throws -> LocalPairwiseIdentityV2 {
        let pseudonym = relationshipPseudonym.trimmingCharacters(in: .whitespacesAndNewlines)
        guard pseudonym == relationshipPseudonym,
              !pseudonym.isEmpty,
              pseudonym.utf8.count <= 512 else {
            throw PairwiseIdentityV2Error.invalidState
        }
        let authority = try RelationshipAuthorityV2(
            relationshipPseudonym: pseudonym,
            signingKey: SigningKeyPair.generate(),
            agreementKey: AgreementKeyPair.generate(),
            createdAt: createdAt
        )
        let endpoint = try LocalRelationshipEndpointV2.generate(createdAt: createdAt)
        let binding = try RelationshipEndpointBindingV4.create(
            authority: authority,
            endpoint: endpoint,
            issuedAt: createdAt
        )
        let result = LocalPairwiseIdentityV2(
            id: id,
            relationshipAuthority: authority,
            localEndpoint: endpoint,
            endpointBinding: binding,
            createdAt: createdAt
        )
        guard try result.isStructurallyValidThrowing else {
            throw PairwiseIdentityV2Error.invalidState
        }
        return result
    }

    public var relationshipPseudonym: String {
        relationshipAuthority.relationshipPseudonym
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard version == Self.version,
                  !relationshipPseudonym.isEmpty,
                  relationshipPseudonym.utf8.count <= 512,
                  relationshipAuthority.createdAt == createdAt,
                  localEndpoint.createdAt == createdAt,
                  endpointBinding.signingPublicKey == localEndpoint.signingKey.publicKeyData,
                  endpointBinding.agreementPublicKey == localEndpoint.agreementKey.publicKeyData,
                  createdAt.timeIntervalSince1970.isFinite,
                  try relationshipAuthority.isStructurallyValidThrowing else {
                return false
            }
            do {
                _ = try endpointBinding.verified(
                    authoritySigningPublicKey: relationshipAuthority.signingKey.publicKeyData,
                    now: endpointBinding.prekeyBundle.createdAt
                )
                return true
            } catch let error as CryptoError {
                throw error
            } catch {
                return false
            }
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    /// Atomically renews the one relationship endpoint's advertised prekey.
    /// The relationship-scoped authority binding and established direct sessions do not
    /// change, and a failure cannot leave local key state ahead of disclosure.
    @discardableResult
    public mutating func renewEndpointPrekeyIfNeeded(at date: Date = Date()) throws -> Bool {
        var endpoint = localEndpoint
        guard try endpoint.renewSignedPrekeyIfNeeded(at: date) else { return false }
        let binding = try endpointBinding.refreshingPrekeyPackage(
            using: endpoint,
            at: date
        )
        localEndpoint = endpoint
        endpointBinding = binding
        return true
    }

    public func makeInitialRouteSet(
        relationshipID: UUID,
        ownerEndpointHandle: RelationshipEndpointHandle,
        receiveRoute: OpaqueSendRouteV2,
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
            relationshipPseudonym: relationshipPseudonym,
            relationshipAuthority: relationshipAuthority,
            endpointBinding: endpointBinding,
            receiveRoutes: receiveRoutes,
            rendezvousTranscriptDigest: rendezvousTranscriptDigest,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
    }

    public var description: String { "LocalPairwiseIdentityV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }

    public static func == (
        lhs: LocalPairwiseIdentityV2,
        rhs: LocalPairwiseIdentityV2
    ) -> Bool {
        lhs.version == rhs.version
            && lhs.id == rhs.id
            && lhs.relationshipAuthority.relationshipPseudonym
                == rhs.relationshipAuthority.relationshipPseudonym
            && lhs.relationshipAuthority.signingKey.privateKeyData
                == rhs.relationshipAuthority.signingKey.privateKeyData
            && lhs.relationshipAuthority.agreementKey.privateKeyData
                == rhs.relationshipAuthority.agreementKey.privateKeyData
            && lhs.relationshipAuthority.createdAt == rhs.relationshipAuthority.createdAt
            && lhs.localEndpoint == rhs.localEndpoint
            && lhs.endpointBinding == rhs.endpointBinding
            && lhs.createdAt == rhs.createdAt
    }
}

/// Public state learned from one verified rendezvous introduction. It contains
/// one relationship pseudonym, one disposable authority, one endpoint binding,
/// and its pairwise routes. Continuity preference is local relationship policy,
/// not peer identity state.
public struct PeerPairwiseIdentityV2: Codable, Equatable, Identifiable {
    public static let version = 2

    public let version: Int
    public let id: UUID
    public let relationshipID: UUID
    public var relationshipPseudonym: String
    public var signingPublicKey: Data
    public var agreementPublicKey: Data
    public var endpointBinding: RelationshipEndpointBindingV4
    public var sendRoutes: PairwiseRouteSetV2
    public let createdAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case relationshipID
        case relationshipPseudonym
        case signingPublicKey
        case agreementPublicKey
        case endpointBinding
        case sendRoutes
        case createdAt
    }

    public init(
        id: UUID = UUID(),
        introduction: ContactIntroductionV2,
        rendezvousTranscriptDigest: Data,
        acceptedAt: Date
    ) throws {
        let verified = try introduction.verified(
            for: rendezvousTranscriptDigest,
            at: acceptedAt
        )
        version = Self.version
        self.id = id
        relationshipID = try PairwiseRelationshipIDV2.derive(from: rendezvousTranscriptDigest)
        relationshipPseudonym = verified.relationshipPseudonym
        signingPublicKey = verified.relationshipSigningPublicKey
        agreementPublicKey = verified.relationshipAgreementPublicKey
        endpointBinding = verified.endpointBinding
        guard try verified.receiveRoutes.verifyThrowing(
            ownerSigningPublicKey: verified.endpointBinding.signingPublicKey
        ), verified.receiveRoutes.relationshipID == relationshipID else {
            throw PairwiseIdentityV2Error.wrongIntroduction
        }
        sendRoutes = verified.receiveRoutes
        createdAt = acceptedAt
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
        relationshipPseudonym = try container.decode(String.self, forKey: .relationshipPseudonym)
        signingPublicKey = try container.decode(Data.self, forKey: .signingPublicKey)
        agreementPublicKey = try container.decode(Data.self, forKey: .agreementPublicKey)
        endpointBinding = try container.decode(
            RelationshipEndpointBindingV4.self,
            forKey: .endpointBinding
        )
        sendRoutes = try container.decode(PairwiseRouteSetV2.self, forKey: .sendRoutes)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        guard try isStructurallyValidThrowing else {
            throw DecodingError.dataCorruptedError(
                forKey: .sendRoutes,
                in: container,
                debugDescription: "Peer pairwise identity is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
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
        try container.encode(relationshipPseudonym, forKey: .relationshipPseudonym)
        try container.encode(signingPublicKey, forKey: .signingPublicKey)
        try container.encode(agreementPublicKey, forKey: .agreementPublicKey)
        try container.encode(endpointBinding, forKey: .endpointBinding)
        try container.encode(sendRoutes, forKey: .sendRoutes)
        try container.encode(createdAt, forKey: .createdAt)
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
        let pseudonym = relationshipPseudonym.trimmingCharacters(in: .whitespacesAndNewlines)
        guard version == Self.version,
              pseudonym == relationshipPseudonym,
              !pseudonym.isEmpty,
              pseudonym.utf8.count <= 512,
              sendRoutes.relationshipID == relationshipID,
              createdAt.timeIntervalSince1970.isFinite,
              try SigningKeyPair.isValidPublicKeyThrowing(signingPublicKey),
              try AgreementKeyPair.isValidPublicKeyThrowing(agreementPublicKey),
              try sendRoutes.isStructurallyValidThrowing,
              try sendRoutes.verifyThrowing(
                  ownerSigningPublicKey: endpointBinding.signingPublicKey
              ) else {
            return false
        }
        do {
            _ = try endpointBinding.verified(
                authoritySigningPublicKey: signingPublicKey,
                now: endpointBinding.prekeyBundle.createdAt
            )
            return true
        } catch let error as CryptoError {
            throw error
        } catch {
            return false
        }
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
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
