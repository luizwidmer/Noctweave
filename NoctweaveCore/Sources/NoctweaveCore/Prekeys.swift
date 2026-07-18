import Foundation

/// Protocol timestamps are encoded as ISO-8601 whole seconds. Canonicalizing
/// before signing keeps the authenticated bytes and persisted value identical
/// across a wire round trip.
private func canonicalPrekeyDate(_ date: Date) -> Date {
    Date(timeIntervalSince1970: floor(date.timeIntervalSince1970))
}

public enum PrekeyError: Error, Equatable {
    case invalidCount
    case invalidState
    case rotationCapacityExceeded
}

public struct OneTimePrekey: Codable, Equatable {
    public let id: UUID
    public let publicKey: Data
    public let signature: Data

    public init(id: UUID = UUID(), publicKey: Data, signature: Data) {
        self.id = id
        self.publicKey = publicKey
        self.signature = signature
    }

    public static func create(
        id: UUID = UUID(),
        agreementPublicKey: Data,
        signingKey: SigningKeyPair
    ) throws -> OneTimePrekey {
        let payload = OneTimePrekeyPayload(id: id, publicKey: agreementPublicKey)
        let data = try NoctweaveCoder.encode(payload, sortedKeys: true)
        return OneTimePrekey(
            id: id,
            publicKey: agreementPublicKey,
            signature: try signingKey.sign(data)
        )
    }

    public func verifyThrowing(using publicSigningKey: Data) throws -> Bool {
        guard signature.count == 3_309,
              try AgreementKeyPair.isValidPublicKeyThrowing(publicKey) else {
            return false
        }
        let payload = OneTimePrekeyPayload(id: id, publicKey: publicKey)
        return try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: NoctweaveCoder.encode(payload, sortedKeys: true),
            publicKeyData: publicSigningKey
        )
    }

    public func verify(using publicSigningKey: Data) -> Bool {
        (try? verifyThrowing(using: publicSigningKey)) == true
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard signature.count == 3_309 else { return false }
            return try AgreementKeyPair.isValidPublicKeyThrowing(publicKey)
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }
}

public enum PrekeyKind: String, Codable, Equatable {
    case signed
    case oneTime
}

public struct PrekeyReference: Codable, Equatable {
    public let kind: PrekeyKind
    public let id: UUID

    public init(kind: PrekeyKind, id: UUID) {
        self.kind = kind
        self.id = id
    }
}

public struct SignedPrekey: Codable, Equatable {
    public let id: UUID
    public let publicKey: Data
    public let issuedAt: Date
    public let expiresAt: Date
    public let signature: Data

    public init(
        id: UUID,
        publicKey: Data,
        issuedAt: Date,
        expiresAt: Date? = nil,
        signature: Data
    ) {
        self.id = id
        self.publicKey = publicKey
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt ?? issuedAt.addingTimeInterval(PrekeyBundle.maximumAge)
        self.signature = signature
    }

    public static func create(
        id: UUID = UUID(),
        agreementPublicKey: Data,
        signingKey: SigningKeyPair,
        issuedAt: Date = Date(),
        expiresAt: Date? = nil
    ) throws -> SignedPrekey {
        guard issuedAt.timeIntervalSince1970.isFinite,
              expiresAt?.timeIntervalSince1970.isFinite ?? true else {
            throw PrekeyError.invalidState
        }
        let canonicalIssuedAt = canonicalPrekeyDate(issuedAt)
        let resolvedExpiry = canonicalPrekeyDate(
            expiresAt ?? canonicalIssuedAt.addingTimeInterval(PrekeyBundle.maximumAge)
        )
        let payload = SignedPrekeyPayload(
            id: id,
            publicKey: agreementPublicKey,
            issuedAt: canonicalIssuedAt,
            expiresAt: resolvedExpiry
        )
        let data = try NoctweaveCoder.encode(payload, sortedKeys: true)
        let signature = try signingKey.sign(data)
        return SignedPrekey(
            id: id,
            publicKey: agreementPublicKey,
            issuedAt: canonicalIssuedAt,
            expiresAt: resolvedExpiry,
            signature: signature
        )
    }

    public func verifyThrowing(using publicSigningKey: Data) throws -> Bool {
        guard issuedAt.timeIntervalSince1970.isFinite,
              expiresAt.timeIntervalSince1970.isFinite,
              expiresAt > issuedAt,
              expiresAt.timeIntervalSince(issuedAt) <= PrekeyBundle.maximumAge,
              signature.count == 3_309,
              try AgreementKeyPair.isValidPublicKeyThrowing(publicKey) else {
            return false
        }
        let payload = SignedPrekeyPayload(
            id: id,
            publicKey: publicKey,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
        return try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: NoctweaveCoder.encode(payload, sortedKeys: true),
            publicKeyData: publicSigningKey
        )
    }

    public func verify(using publicSigningKey: Data) -> Bool {
        (try? verifyThrowing(using: publicSigningKey)) == true
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard issuedAt.timeIntervalSince1970.isFinite,
                  expiresAt.timeIntervalSince1970.isFinite,
                  expiresAt > issuedAt,
                  expiresAt.timeIntervalSince(issuedAt) <= PrekeyBundle.maximumAge,
                  signature.count == 3_309 else {
                return false
            }
            return try AgreementKeyPair.isValidPublicKeyThrowing(publicKey)
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    public func isFreshThrowing(at now: Date = Date()) throws -> Bool {
        guard try isStructurallyValidThrowing,
              now.timeIntervalSince1970.isFinite else {
            return false
        }
        return issuedAt <= now.addingTimeInterval(PrekeyBundle.maximumFutureClockSkew)
            && now < expiresAt
    }

    public func isFresh(at now: Date = Date()) -> Bool {
        (try? isFreshThrowing(at: now)) == true
    }
}

public struct PrekeyBundle: Codable, Equatable {
    public static let currentVersion = 2
    public static let maximumOneTimePrekeys = 64
    public static let maximumAge: TimeInterval = 8 * 86_400
    public static let maximumFutureClockSkew: TimeInterval = 5 * 60
    public let version: Int
    public let relationshipSigningKeyDigest: String
    public let signedPrekey: SignedPrekey
    public let oneTimePrekeys: [OneTimePrekey]
    public let createdAt: Date

    public init(
        version: Int = PrekeyBundle.currentVersion,
        relationshipSigningKeyDigest: String,
        signedPrekey: SignedPrekey,
        oneTimePrekeys: [OneTimePrekey],
        createdAt: Date = Date()
    ) {
        self.version = version
        self.relationshipSigningKeyDigest = relationshipSigningKeyDigest
        self.signedPrekey = signedPrekey
        self.oneTimePrekeys = oneTimePrekeys
        self.createdAt = createdAt
    }

    public func isStructurallyValidThrowing(now: Date = Date()) throws -> Bool {
        guard version == Self.currentVersion,
              let signingKeyDigest = Data(base64Encoded: relationshipSigningKeyDigest),
              signingKeyDigest.count == 32,
              signingKeyDigest.base64EncodedString() == relationshipSigningKeyDigest,
              oneTimePrekeys.count <= Self.maximumOneTimePrekeys,
              Set(oneTimePrekeys.map(\.id)).count == oneTimePrekeys.count,
              !oneTimePrekeys.contains(where: { $0.id == signedPrekey.id }),
              createdAt.timeIntervalSince1970.isFinite else {
            return false
        }
        guard try signedPrekey.isStructurallyValidThrowing else { return false }
        for prekey in oneTimePrekeys {
            guard try prekey.isStructurallyValidThrowing else { return false }
        }
        let newestAllowed = now.addingTimeInterval(Self.maximumFutureClockSkew)
        return try signedPrekey.isFreshThrowing(at: now)
            && createdAt <= newestAllowed
            && createdAt >= signedPrekey.issuedAt
            && createdAt <= signedPrekey.expiresAt
    }

    public func isStructurallyValid(now: Date = Date()) -> Bool {
        (try? isStructurallyValidThrowing(now: now)) == true
    }
}

public struct PrekeyPrivateRecord: Codable, Equatable {
    public let id: UUID
    public let publicKey: Data
    public let privateKey: Data
    public let createdAt: Date

    public init(id: UUID, publicKey: Data, privateKey: Data, createdAt: Date = Date()) {
        self.id = id
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.createdAt = createdAt
    }
}

/// A previously advertised signed prekey retained only for delayed bootstrap
/// ciphertexts. Records are endpoint-local, bounded, and become unusable at
/// the exact expiry authenticated in the public signed prekey.
public struct RetiredSignedPrekeyPrivateRecord: Codable, Equatable {
    public let id: UUID
    public let publicKey: Data
    public var privateKey: Data
    public let signature: Data
    public let issuedAt: Date
    public let expiresAt: Date

    public init(
        id: UUID,
        publicKey: Data,
        privateKey: Data,
        signature: Data,
        issuedAt: Date,
        expiresAt: Date
    ) {
        self.id = id
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.signature = signature
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }

    public var signedPrekey: SignedPrekey {
        SignedPrekey(
            id: id,
            publicKey: publicKey,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            signature: signature
        )
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard try signedPrekey.isStructurallyValidThrowing else { return false }
            do {
                _ = try AgreementKeyPair(
                    privateKeyData: privateKey,
                    publicKeyData: publicKey
                )
                return true
            } catch CryptoError.invalidPrivateKey {
                return false
            }
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }
}

public struct PrekeyState: Codable, Equatable {
    public static let defaultOneTimeCount = 8
    public static let signedPrekeyRenewalLeadTime: TimeInterval = 2 * 86_400
    public static let maximumRetiredSignedPrekeys = 4

    public var signedPrekeyId: UUID
    public var signedPrekeyPublicKey: Data
    public var signedPrekeyPrivateKey: Data
    public var signedPrekeySignature: Data
    public var signedPrekeyIssuedAt: Date
    public var signedPrekeyExpiresAt: Date
    public var retiredSignedPrekeys: [RetiredSignedPrekeyPrivateRecord]
    public var oneTimePrekeys: [PrekeyPrivateRecord]

    public init(
        signedPrekeyId: UUID,
        signedPrekeyPublicKey: Data,
        signedPrekeyPrivateKey: Data,
        signedPrekeySignature: Data,
        signedPrekeyIssuedAt: Date,
        signedPrekeyExpiresAt: Date? = nil,
        retiredSignedPrekeys: [RetiredSignedPrekeyPrivateRecord] = [],
        oneTimePrekeys: [PrekeyPrivateRecord]
    ) {
        self.signedPrekeyId = signedPrekeyId
        self.signedPrekeyPublicKey = signedPrekeyPublicKey
        self.signedPrekeyPrivateKey = signedPrekeyPrivateKey
        self.signedPrekeySignature = signedPrekeySignature
        self.signedPrekeyIssuedAt = signedPrekeyIssuedAt
        self.signedPrekeyExpiresAt = signedPrekeyExpiresAt
            ?? signedPrekeyIssuedAt.addingTimeInterval(PrekeyBundle.maximumAge)
        self.retiredSignedPrekeys = retiredSignedPrekeys
        self.oneTimePrekeys = oneTimePrekeys
    }

    public static func generate(
        authority: RelationshipAuthorityV2,
        oneTimeCount: Int = defaultOneTimeCount,
        issuedAt: Date = Date()
    ) throws -> PrekeyState {
        guard (0...PrekeyBundle.maximumOneTimePrekeys).contains(oneTimeCount) else {
            throw PrekeyError.invalidCount
        }
        guard issuedAt.timeIntervalSince1970.isFinite else {
            throw PrekeyError.invalidState
        }
        let signedKeyPair = try AgreementKeyPair.generate()
        let signedPrekey = try SignedPrekey.create(
            agreementPublicKey: signedKeyPair.publicKeyData,
            signingKey: authority.signingKey,
            issuedAt: issuedAt
        )
        let canonicalIssuedAt = signedPrekey.issuedAt
        var oneTime: [PrekeyPrivateRecord] = []
        for _ in 0..<oneTimeCount {
            let keyPair = try AgreementKeyPair.generate()
            let id = UUID()
            oneTime.append(
                PrekeyPrivateRecord(
                    id: id,
                    publicKey: keyPair.publicKeyData,
                    privateKey: keyPair.privateKeyData,
                    createdAt: canonicalIssuedAt
                )
            )
        }
        return PrekeyState(
            signedPrekeyId: signedPrekey.id,
            signedPrekeyPublicKey: signedKeyPair.publicKeyData,
            signedPrekeyPrivateKey: signedKeyPair.privateKeyData,
            signedPrekeySignature: signedPrekey.signature,
            signedPrekeyIssuedAt: signedPrekey.issuedAt,
            signedPrekeyExpiresAt: signedPrekey.expiresAt,
            oneTimePrekeys: oneTime
        )
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
        let allIDs = [signedPrekeyId]
            + retiredSignedPrekeys.map(\.id)
            + oneTimePrekeys.map(\.id)
        let allPublicKeys = [signedPrekeyPublicKey]
            + retiredSignedPrekeys.map(\.publicKey)
            + oneTimePrekeys.map(\.publicKey)
        guard signedPrekeyIssuedAt.timeIntervalSince1970.isFinite,
              signedPrekeyExpiresAt.timeIntervalSince1970.isFinite,
              signedPrekeyExpiresAt > signedPrekeyIssuedAt,
              signedPrekeyExpiresAt.timeIntervalSince(signedPrekeyIssuedAt)
                <= PrekeyBundle.maximumAge,
              signedPrekeySignature.count == 3_309,
              retiredSignedPrekeys.count <= Self.maximumRetiredSignedPrekeys,
              oneTimePrekeys.count <= PrekeyBundle.maximumOneTimePrekeys,
              Set(allIDs).count == allIDs.count,
              Set(allPublicKeys).count == allPublicKeys.count else {
            return false
        }
        guard try Self.agreementKeyPairIsValid(
            privateKey: signedPrekeyPrivateKey,
            publicKey: signedPrekeyPublicKey
        ) else {
            return false
        }
        for retired in retiredSignedPrekeys {
            guard try retired.isStructurallyValidThrowing else { return false }
        }
        for prekey in oneTimePrekeys {
            guard prekey.createdAt.timeIntervalSince1970.isFinite,
                  prekey.createdAt >= signedPrekeyIssuedAt,
                  prekey.createdAt <= signedPrekeyExpiresAt,
                  try Self.agreementKeyPairIsValid(
                      privateKey: prekey.privateKey,
                      publicKey: prekey.publicKey
                  ) else {
                return false
            }
        }
        return true
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    public func bundle(
        authority: RelationshipAuthorityV2,
        createdAt: Date = Date()
    ) throws -> PrekeyBundle {
        guard oneTimePrekeys.count <= PrekeyBundle.maximumOneTimePrekeys,
              signedPrekeySignature.count == 3_309,
              try Self.agreementKeyPairIsValid(
                  privateKey: signedPrekeyPrivateKey,
                  publicKey: signedPrekeyPublicKey
              ) else {
            throw PrekeyError.invalidState
        }
        for prekey in oneTimePrekeys {
            guard try Self.agreementKeyPairIsValid(
                privateKey: prekey.privateKey,
                publicKey: prekey.publicKey
            ) else {
                throw PrekeyError.invalidState
            }
        }
        let signed = SignedPrekey(
            id: signedPrekeyId,
            publicKey: signedPrekeyPublicKey,
            issuedAt: signedPrekeyIssuedAt,
            expiresAt: signedPrekeyExpiresAt,
            signature: signedPrekeySignature
        )
        guard try signed.verifyThrowing(using: authority.signingKey.publicKeyData),
              createdAt.timeIntervalSince1970.isFinite,
              createdAt >= signed.issuedAt,
              createdAt <= signed.expiresAt else {
            throw PrekeyError.invalidState
        }
        let oneTime = try oneTimePrekeys.map {
            try OneTimePrekey.create(
                id: $0.id,
                agreementPublicKey: $0.publicKey,
                signingKey: authority.signingKey
            )
        }
        return PrekeyBundle(
            version: PrekeyBundle.currentVersion,
            relationshipSigningKeyDigest: authority.fingerprint,
            signedPrekey: signed,
            oneTimePrekeys: oneTime,
            createdAt: createdAt
        )
    }

    /// Renews only the endpoint's short-lived signed prekey. The endpoint
    /// signing key authorizes the replacement; no identity-generation,
    /// recovery, inbox, or account authority participates.
    @discardableResult
    public mutating func rotateSignedPrekeyIfNeeded(
        endpointSigningKey: SigningKeyPair,
        now: Date = Date()
    ) throws -> Bool {
        guard now.timeIntervalSince1970.isFinite else {
            throw PrekeyError.invalidState
        }
        var candidate = self
        candidate.pruneExpiredSignedPrekeys(now: now)
        guard try candidate.retainedSignedPrekeysAreStructurallyValidThrowing(
            using: endpointSigningKey.publicKeyData,
            now: now
        ) else {
            throw PrekeyError.invalidState
        }
        guard candidate.signedPrekeyExpiresAt
                <= now.addingTimeInterval(Self.signedPrekeyRenewalLeadTime) else {
            return false
        }
        if now < candidate.signedPrekeyExpiresAt {
            guard candidate.retiredSignedPrekeys.count < Self.maximumRetiredSignedPrekeys else {
                throw PrekeyError.rotationCapacityExceeded
            }
            candidate.retiredSignedPrekeys.append(candidate.currentRetiredRecord)
        }
        let keyPair = try AgreementKeyPair.generate()
        let signed = try SignedPrekey.create(
            agreementPublicKey: keyPair.publicKeyData,
            signingKey: endpointSigningKey,
            issuedAt: now
        )
        candidate.signedPrekeyId = signed.id
        candidate.signedPrekeyPublicKey = keyPair.publicKeyData
        candidate.signedPrekeyPrivateKey = keyPair.privateKeyData
        candidate.signedPrekeySignature = signed.signature
        candidate.signedPrekeyIssuedAt = signed.issuedAt
        candidate.signedPrekeyExpiresAt = signed.expiresAt
        self = candidate
        return true
    }

    public mutating func pruneExpiredSignedPrekeys(now: Date = Date()) {
        for index in retiredSignedPrekeys.indices.reversed()
            where retiredSignedPrekeys[index].expiresAt <= now {
            retiredSignedPrekeys[index].privateKey.secureWipe()
            retiredSignedPrekeys.remove(at: index)
        }
    }

    public func retainedSignedPrekeysAreStructurallyValid(
        using signingPublicKey: Data,
        now: Date = Date()
    ) -> Bool {
        (try? retainedSignedPrekeysAreStructurallyValidThrowing(
            using: signingPublicKey,
            now: now
        )) == true
    }

    public func retainedSignedPrekeysAreStructurallyValidThrowing(
        using signingPublicKey: Data,
        now: Date = Date()
    ) throws -> Bool {
        guard try signedPrekeyRenewalStateIsValidThrowing(using: signingPublicKey) else {
            return false
        }
        return retiredSignedPrekeys.allSatisfy { $0.expiresAt > now }
    }

    public mutating func consumeOneTimePrekey(id: UUID) -> AgreementKeyPair? {
        try? consumeOneTimePrekeyThrowing(id: id)
    }

    public mutating func consumeOneTimePrekeyThrowing(
        id: UUID
    ) throws -> AgreementKeyPair? {
        guard let index = oneTimePrekeys.firstIndex(where: { $0.id == id }) else {
            return nil
        }
        let record = oneTimePrekeys[index]
        let keyPair = try AgreementKeyPair(
            privateKeyData: record.privateKey,
            publicKeyData: record.publicKey
        )
        oneTimePrekeys.remove(at: index)
        return keyPair
    }

    public func signedPrekey(id: UUID) -> SignedPrekey? {
        if id == signedPrekeyId {
            return SignedPrekey(
                id: signedPrekeyId,
                publicKey: signedPrekeyPublicKey,
                issuedAt: signedPrekeyIssuedAt,
                expiresAt: signedPrekeyExpiresAt,
                signature: signedPrekeySignature
            )
        }
        return retiredSignedPrekeys.first(where: { $0.id == id })?.signedPrekey
    }

    public func signedPrekeyKeyPairThrowing(
        id: UUID,
        now: Date = Date()
    ) throws -> AgreementKeyPair? {
        if id == signedPrekeyId, now < signedPrekeyExpiresAt {
            return try AgreementKeyPair(
                privateKeyData: signedPrekeyPrivateKey,
                publicKeyData: signedPrekeyPublicKey
            )
        }
        guard let record = retiredSignedPrekeys.first(where: {
            $0.id == id && now < $0.expiresAt
        }) else {
            return nil
        }
        return try AgreementKeyPair(
            privateKeyData: record.privateKey,
            publicKeyData: record.publicKey
        )
    }

    private var currentRetiredRecord: RetiredSignedPrekeyPrivateRecord {
        RetiredSignedPrekeyPrivateRecord(
            id: signedPrekeyId,
            publicKey: signedPrekeyPublicKey,
            privateKey: signedPrekeyPrivateKey,
            signature: signedPrekeySignature,
            issuedAt: signedPrekeyIssuedAt,
            expiresAt: signedPrekeyExpiresAt
        )
    }

    private func signedPrekeyRenewalStateIsValidThrowing(
        using signingPublicKey: Data
    ) throws -> Bool {
        let current = currentRetiredRecord
        guard retiredSignedPrekeys.count <= Self.maximumRetiredSignedPrekeys,
              Set(retiredSignedPrekeys.map(\.id)).count == retiredSignedPrekeys.count,
              !retiredSignedPrekeys.contains(where: { $0.id == signedPrekeyId }),
              try current.isStructurallyValidThrowing,
              try current.signedPrekey.verifyThrowing(using: signingPublicKey) else {
            return false
        }
        for retired in retiredSignedPrekeys {
            guard try retired.isStructurallyValidThrowing,
                  try retired.signedPrekey.verifyThrowing(using: signingPublicKey) else {
                return false
            }
        }
        return true
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case signedPrekeyId
        case signedPrekeyPublicKey
        case signedPrekeyPrivateKey
        case signedPrekeySignature
        case signedPrekeyIssuedAt
        case signedPrekeyExpiresAt
        case retiredSignedPrekeys
        case oneTimePrekeys
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PrekeyStateCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Prekey-state fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        signedPrekeyId = try container.decode(UUID.self, forKey: .signedPrekeyId)
        signedPrekeyPublicKey = try container.decode(Data.self, forKey: .signedPrekeyPublicKey)
        signedPrekeyPrivateKey = try container.decode(Data.self, forKey: .signedPrekeyPrivateKey)
        signedPrekeySignature = try container.decode(Data.self, forKey: .signedPrekeySignature)
        signedPrekeyIssuedAt = try container.decode(Date.self, forKey: .signedPrekeyIssuedAt)
        signedPrekeyExpiresAt = try container.decode(
            Date.self,
            forKey: .signedPrekeyExpiresAt
        )
        retiredSignedPrekeys = try container.decode(
            [RetiredSignedPrekeyPrivateRecord].self,
            forKey: .retiredSignedPrekeys
        )
        oneTimePrekeys = try container.decode(
            [PrekeyPrivateRecord].self,
            forKey: .oneTimePrekeys
        )
        guard try isStructurallyValidThrowing else {
            throw DecodingError.dataCorruptedError(
                forKey: .signedPrekeyId,
                in: container,
                debugDescription: "Prekey-state cryptographic material is invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(signedPrekeyId, forKey: .signedPrekeyId)
        try container.encode(signedPrekeyPublicKey, forKey: .signedPrekeyPublicKey)
        try container.encode(signedPrekeyPrivateKey, forKey: .signedPrekeyPrivateKey)
        try container.encode(signedPrekeySignature, forKey: .signedPrekeySignature)
        try container.encode(signedPrekeyIssuedAt, forKey: .signedPrekeyIssuedAt)
        try container.encode(signedPrekeyExpiresAt, forKey: .signedPrekeyExpiresAt)
        try container.encode(retiredSignedPrekeys, forKey: .retiredSignedPrekeys)
        try container.encode(oneTimePrekeys, forKey: .oneTimePrekeys)
    }

    private static func agreementKeyPairIsValid(
        privateKey: Data,
        publicKey: Data
    ) throws -> Bool {
        do {
            _ = try AgreementKeyPair(
                privateKeyData: privateKey,
                publicKeyData: publicKey
            )
            return true
        } catch CryptoError.invalidPrivateKey {
            return false
        }
    }
}

private struct PrekeyStateCodingKey: CodingKey {
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

private struct SignedPrekeyPayload: Codable {
    let id: UUID
    let publicKey: Data
    let issuedAt: Date
    let expiresAt: Date
}

private struct OneTimePrekeyPayload: Codable {
    let id: UUID
    let publicKey: Data
}
