import Foundation

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

    public func verify(using publicSigningKey: Data) -> Bool {
        guard isStructurallyValid else { return false }
        let payload = OneTimePrekeyPayload(id: id, publicKey: publicKey)
        guard let data = try? NoctweaveCoder.encode(payload, sortedKeys: true) else {
            return false
        }
        return SigningKeyPair.verify(
            signature: signature,
            data: data,
            publicKeyData: publicSigningKey
        )
    }

    public var isStructurallyValid: Bool {
        AgreementKeyPair.isValidPublicKey(publicKey) && signature.count == 3_309
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
        let resolvedExpiry = expiresAt ?? issuedAt.addingTimeInterval(PrekeyBundle.maximumAge)
        let payload = SignedPrekeyPayload(
            id: id,
            publicKey: agreementPublicKey,
            issuedAt: issuedAt,
            expiresAt: resolvedExpiry
        )
        let data = try NoctweaveCoder.encode(payload, sortedKeys: true)
        let signature = try signingKey.sign(data)
        return SignedPrekey(
            id: id,
            publicKey: agreementPublicKey,
            issuedAt: issuedAt,
            expiresAt: resolvedExpiry,
            signature: signature
        )
    }

    public func verify(using publicSigningKey: Data) -> Bool {
        guard isStructurallyValid else { return false }
        let payload = SignedPrekeyPayload(
            id: id,
            publicKey: publicKey,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
        guard let data = try? NoctweaveCoder.encode(payload, sortedKeys: true) else {
            return false
        }
        return SigningKeyPair.verify(signature: signature, data: data, publicKeyData: publicSigningKey)
    }

    public var isStructurallyValid: Bool {
        issuedAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && expiresAt > issuedAt
            && expiresAt.timeIntervalSince(issuedAt) <= PrekeyBundle.maximumAge
            && AgreementKeyPair.isValidPublicKey(publicKey)
            && signature.count == 3_309
    }

    public func isFresh(at now: Date = Date()) -> Bool {
        guard isStructurallyValid, now.timeIntervalSince1970.isFinite else { return false }
        return issuedAt <= now.addingTimeInterval(PrekeyBundle.maximumFutureClockSkew)
            && now < expiresAt
    }
}

public struct PrekeyBundle: Codable, Equatable {
    public static let currentVersion = 2
    public static let maximumOneTimePrekeys = 64
    public static let maximumAge: TimeInterval = 8 * 86_400
    public static let maximumFutureClockSkew: TimeInterval = 5 * 60
    public let version: Int
    public let identityFingerprint: String
    public let signedPrekey: SignedPrekey
    public let oneTimePrekeys: [OneTimePrekey]
    public let createdAt: Date

    public init(
        version: Int = PrekeyBundle.currentVersion,
        identityFingerprint: String,
        signedPrekey: SignedPrekey,
        oneTimePrekeys: [OneTimePrekey],
        createdAt: Date = Date()
    ) {
        self.version = version
        self.identityFingerprint = identityFingerprint
        self.signedPrekey = signedPrekey
        self.oneTimePrekeys = oneTimePrekeys
        self.createdAt = createdAt
    }

    public func isStructurallyValid(now: Date = Date()) -> Bool {
        guard version == Self.currentVersion,
              let fingerprintData = Data(base64Encoded: identityFingerprint),
              fingerprintData.count == 32,
              fingerprintData.base64EncodedString() == identityFingerprint,
              signedPrekey.isStructurallyValid,
              oneTimePrekeys.count <= Self.maximumOneTimePrekeys,
              oneTimePrekeys.allSatisfy(\.isStructurallyValid),
              Set(oneTimePrekeys.map(\.id)).count == oneTimePrekeys.count,
              !oneTimePrekeys.contains(where: { $0.id == signedPrekey.id }),
              createdAt.timeIntervalSince1970.isFinite else {
            return false
        }
        let newestAllowed = now.addingTimeInterval(Self.maximumFutureClockSkew)
        return signedPrekey.isFresh(at: now)
            && createdAt <= newestAllowed
            && createdAt >= signedPrekey.issuedAt
            && createdAt <= signedPrekey.expiresAt
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

    public var isStructurallyValid: Bool {
        signedPrekey.isStructurallyValid
            && (try? AgreementKeyPair(privateKeyData: privateKey, publicKeyData: publicKey)) != nil
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

    public static func generate(identity: Identity, oneTimeCount: Int = defaultOneTimeCount) throws -> PrekeyState {
        guard (0...PrekeyBundle.maximumOneTimePrekeys).contains(oneTimeCount) else {
            throw PrekeyError.invalidCount
        }
        let signedKeyPair = try AgreementKeyPair.generate()
        let signedPrekey = try SignedPrekey.create(
            agreementPublicKey: signedKeyPair.publicKeyData,
            signingKey: identity.signingKey
        )
        var oneTime: [PrekeyPrivateRecord] = []
        for _ in 0..<oneTimeCount {
            let keyPair = try AgreementKeyPair.generate()
            let id = UUID()
            oneTime.append(
                PrekeyPrivateRecord(
                    id: id,
                    publicKey: keyPair.publicKeyData,
                    privateKey: keyPair.privateKeyData
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

    public func bundle(identity: Identity, createdAt: Date = Date()) throws -> PrekeyBundle {
        guard oneTimePrekeys.count <= PrekeyBundle.maximumOneTimePrekeys,
              (try? AgreementKeyPair(
                  privateKeyData: signedPrekeyPrivateKey,
                  publicKeyData: signedPrekeyPublicKey
              )) != nil,
              signedPrekeySignature.count == 3_309,
              oneTimePrekeys.allSatisfy({
                  (try? AgreementKeyPair(
                      privateKeyData: $0.privateKey,
                      publicKeyData: $0.publicKey
                  )) != nil
              }) else {
            throw PrekeyError.invalidState
        }
        let signed = SignedPrekey(
            id: signedPrekeyId,
            publicKey: signedPrekeyPublicKey,
            issuedAt: signedPrekeyIssuedAt,
            expiresAt: signedPrekeyExpiresAt,
            signature: signedPrekeySignature
        )
        guard signed.verify(using: identity.signingKey.publicKeyData),
              createdAt.timeIntervalSince1970.isFinite,
              createdAt >= signed.issuedAt,
              createdAt <= signed.expiresAt else {
            throw PrekeyError.invalidState
        }
        let oneTime = try oneTimePrekeys.map {
            try OneTimePrekey.create(
                id: $0.id,
                agreementPublicKey: $0.publicKey,
                signingKey: identity.signingKey
            )
        }
        return PrekeyBundle(
            version: PrekeyBundle.currentVersion,
            identityFingerprint: identity.fingerprint,
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
        pruneExpiredSignedPrekeys(now: now)
        guard retainedSignedPrekeysAreStructurallyValid(
            using: endpointSigningKey.publicKeyData,
            now: now
        ) else {
            throw PrekeyError.invalidState
        }
        guard signedPrekeyExpiresAt <= now.addingTimeInterval(Self.signedPrekeyRenewalLeadTime) else {
            return false
        }
        if now < signedPrekeyExpiresAt {
            guard retiredSignedPrekeys.count < Self.maximumRetiredSignedPrekeys else {
                throw PrekeyError.rotationCapacityExceeded
            }
            retiredSignedPrekeys.append(currentRetiredRecord)
        }
        let keyPair = try AgreementKeyPair.generate()
        let signed = try SignedPrekey.create(
            agreementPublicKey: keyPair.publicKeyData,
            signingKey: endpointSigningKey,
            issuedAt: now
        )
        signedPrekeyId = signed.id
        signedPrekeyPublicKey = keyPair.publicKeyData
        signedPrekeyPrivateKey = keyPair.privateKeyData
        signedPrekeySignature = signed.signature
        signedPrekeyIssuedAt = signed.issuedAt
        signedPrekeyExpiresAt = signed.expiresAt
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
        signedPrekeyRenewalStateIsValid(using: signingPublicKey)
            && retiredSignedPrekeys.allSatisfy { $0.expiresAt > now }
    }

    public mutating func consumeOneTimePrekey(id: UUID) -> AgreementKeyPair? {
        guard let index = oneTimePrekeys.firstIndex(where: { $0.id == id }) else {
            return nil
        }
        let record = oneTimePrekeys.remove(at: index)
        return try? AgreementKeyPair(privateKeyData: record.privateKey, publicKeyData: record.publicKey)
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

    public func signedPrekeyKeyPair(id: UUID, now: Date = Date()) -> AgreementKeyPair? {
        if id == signedPrekeyId, now < signedPrekeyExpiresAt {
            return try? AgreementKeyPair(
                privateKeyData: signedPrekeyPrivateKey,
                publicKeyData: signedPrekeyPublicKey
            )
        }
        guard let record = retiredSignedPrekeys.first(where: {
            $0.id == id && now < $0.expiresAt
        }) else {
            return nil
        }
        return try? AgreementKeyPair(
            privateKeyData: record.privateKey,
            publicKeyData: record.publicKey
        )
    }

    /// Compatibility accessor for code that explicitly wants the current key.
    public func signedPrekeyKeyPair(now: Date = Date()) -> AgreementKeyPair? {
        signedPrekeyKeyPair(id: signedPrekeyId, now: now)
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

    private func signedPrekeyRenewalStateIsValid(using signingPublicKey: Data) -> Bool {
        let current = currentRetiredRecord
        return current.isStructurallyValid
            && current.signedPrekey.verify(using: signingPublicKey)
            && retiredSignedPrekeys.count <= Self.maximumRetiredSignedPrekeys
            && Set(retiredSignedPrekeys.map(\.id)).count == retiredSignedPrekeys.count
            && !retiredSignedPrekeys.contains(where: { $0.id == signedPrekeyId })
            && retiredSignedPrekeys.allSatisfy {
                $0.isStructurallyValid && $0.signedPrekey.verify(using: signingPublicKey)
            }
    }

    private enum CodingKeys: String, CodingKey {
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
        let container = try decoder.container(keyedBy: CodingKeys.self)
        signedPrekeyId = try container.decode(UUID.self, forKey: .signedPrekeyId)
        signedPrekeyPublicKey = try container.decode(Data.self, forKey: .signedPrekeyPublicKey)
        signedPrekeyPrivateKey = try container.decode(Data.self, forKey: .signedPrekeyPrivateKey)
        signedPrekeySignature = try container.decode(Data.self, forKey: .signedPrekeySignature)
        signedPrekeyIssuedAt = try container.decode(Date.self, forKey: .signedPrekeyIssuedAt)
        signedPrekeyExpiresAt = try container.decodeIfPresent(
            Date.self,
            forKey: .signedPrekeyExpiresAt
        ) ?? signedPrekeyIssuedAt.addingTimeInterval(PrekeyBundle.maximumAge)
        retiredSignedPrekeys = try container.decodeIfPresent(
            [RetiredSignedPrekeyPrivateRecord].self,
            forKey: .retiredSignedPrekeys
        ) ?? []
        oneTimePrekeys = try container.decode(
            [PrekeyPrivateRecord].self,
            forKey: .oneTimePrekeys
        )
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
