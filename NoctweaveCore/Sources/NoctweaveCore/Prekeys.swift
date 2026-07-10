import Foundation

public enum PrekeyError: Error, Equatable {
    case invalidCount
    case invalidState
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
    public let signature: Data

    public init(id: UUID, publicKey: Data, issuedAt: Date, signature: Data) {
        self.id = id
        self.publicKey = publicKey
        self.issuedAt = issuedAt
        self.signature = signature
    }

    public static func create(
        id: UUID = UUID(),
        agreementPublicKey: Data,
        signingKey: SigningKeyPair,
        issuedAt: Date = Date()
    ) throws -> SignedPrekey {
        let payload = SignedPrekeyPayload(id: id, publicKey: agreementPublicKey, issuedAt: issuedAt)
        let data = try NoctweaveCoder.encode(payload, sortedKeys: true)
        let signature = try signingKey.sign(data)
        return SignedPrekey(id: id, publicKey: agreementPublicKey, issuedAt: issuedAt, signature: signature)
    }

    public func verify(using publicSigningKey: Data) -> Bool {
        guard isStructurallyValid else { return false }
        let payload = SignedPrekeyPayload(id: id, publicKey: publicKey, issuedAt: issuedAt)
        guard let data = try? NoctweaveCoder.encode(payload, sortedKeys: true) else {
            return false
        }
        return SigningKeyPair.verify(signature: signature, data: data, publicKeyData: publicSigningKey)
    }

    public var isStructurallyValid: Bool {
        issuedAt.timeIntervalSince1970.isFinite
            && AgreementKeyPair.isValidPublicKey(publicKey)
            && signature.count == 3_309
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
        let oldestAllowed = now.addingTimeInterval(-Self.maximumAge)
        let newestAllowed = now.addingTimeInterval(Self.maximumFutureClockSkew)
        return (oldestAllowed...newestAllowed).contains(signedPrekey.issuedAt)
            && (oldestAllowed...newestAllowed).contains(createdAt)
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

public struct PrekeyState: Codable, Equatable {
    public static let defaultOneTimeCount = 8

    public var signedPrekeyId: UUID
    public var signedPrekeyPublicKey: Data
    public var signedPrekeyPrivateKey: Data
    public var signedPrekeySignature: Data
    public var signedPrekeyIssuedAt: Date
    public var oneTimePrekeys: [PrekeyPrivateRecord]

    public init(
        signedPrekeyId: UUID,
        signedPrekeyPublicKey: Data,
        signedPrekeyPrivateKey: Data,
        signedPrekeySignature: Data,
        signedPrekeyIssuedAt: Date,
        oneTimePrekeys: [PrekeyPrivateRecord]
    ) {
        self.signedPrekeyId = signedPrekeyId
        self.signedPrekeyPublicKey = signedPrekeyPublicKey
        self.signedPrekeyPrivateKey = signedPrekeyPrivateKey
        self.signedPrekeySignature = signedPrekeySignature
        self.signedPrekeyIssuedAt = signedPrekeyIssuedAt
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
            oneTimePrekeys: oneTime
        )
    }

    public func bundle(identity: Identity) throws -> PrekeyBundle {
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
            signature: signedPrekeySignature
        )
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
            oneTimePrekeys: oneTime
        )
    }

    public mutating func consumeOneTimePrekey(id: UUID) -> AgreementKeyPair? {
        guard let index = oneTimePrekeys.firstIndex(where: { $0.id == id }) else {
            return nil
        }
        let record = oneTimePrekeys.remove(at: index)
        return try? AgreementKeyPair(privateKeyData: record.privateKey, publicKeyData: record.publicKey)
    }

    public func signedPrekeyKeyPair() -> AgreementKeyPair? {
        try? AgreementKeyPair(privateKeyData: signedPrekeyPrivateKey, publicKeyData: signedPrekeyPublicKey)
    }
}

private struct SignedPrekeyPayload: Codable {
    let id: UUID
    let publicKey: Data
    let issuedAt: Date
}

private struct OneTimePrekeyPayload: Codable {
    let id: UUID
    let publicKey: Data
}
