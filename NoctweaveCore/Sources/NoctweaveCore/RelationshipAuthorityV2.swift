import Foundation

/// Disposable cryptographic authority minted for exactly one relationship.
/// It carries only a relationship-local pseudonym and must never be reused as
/// an account, persona, installation, device, or cross-relationship identity.
public struct RelationshipAuthorityV2: Codable {
    public var relationshipPseudonym: String
    public var signingKey: SigningKeyPair
    public var agreementKey: AgreementKeyPair
    public let createdAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case relationshipPseudonym
        case signingKey
        case agreementKey
        case createdAt
    }

    public static func generate(
        relationshipPseudonym: String,
        createdAt: Date = Date()
    ) throws -> RelationshipAuthorityV2 {
        try RelationshipAuthorityV2(
            relationshipPseudonym: relationshipPseudonym,
            signingKey: SigningKeyPair.generate(),
            agreementKey: AgreementKeyPair.generate(),
            createdAt: createdAt
        )
    }

    public init(
        relationshipPseudonym: String,
        signingKey: SigningKeyPair,
        agreementKey: AgreementKeyPair,
        createdAt: Date = Date()
    ) throws {
        guard SigningKeyPair.isValidPublicKey(signingKey.publicKeyData),
              AgreementKeyPair.isValidPublicKey(agreementKey.publicKeyData) else {
            throw CryptoError.invalidPublicKey
        }
        self.relationshipPseudonym = relationshipPseudonym
        self.signingKey = signingKey
        self.agreementKey = agreementKey
        self.createdAt = createdAt
    }

    public var fingerprint: String {
        CryptoBox.fingerprint(for: signingKey.publicKeyData)
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: RelationshipAuthorityCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Pairwise authority fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            relationshipPseudonym: container.decode(
                String.self,
                forKey: .relationshipPseudonym
            ),
            signingKey: container.decode(SigningKeyPair.self, forKey: .signingKey),
            agreementKey: container.decode(AgreementKeyPair.self, forKey: .agreementKey),
            createdAt: container.decode(Date.self, forKey: .createdAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .signingKey,
                in: container,
                debugDescription: "Pairwise authority is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Pairwise authority is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(relationshipPseudonym, forKey: .relationshipPseudonym)
        try container.encode(signingKey, forKey: .signingKey)
        try container.encode(agreementKey, forKey: .agreementKey)
        try container.encode(createdAt, forKey: .createdAt)
    }

    public var isStructurallyValid: Bool {
        let normalized = relationshipPseudonym.trimmingCharacters(
            in: .whitespacesAndNewlines
        )
        return !normalized.isEmpty
            && normalized == relationshipPseudonym
            && normalized.utf8.count <= 512
            && SigningKeyPair.isValidPublicKey(signingKey.publicKeyData)
            && AgreementKeyPair.isValidPublicKey(agreementKey.publicKeyData)
            && createdAt.timeIntervalSince1970.isFinite
    }
}

private struct RelationshipAuthorityCodingKey: CodingKey {
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
