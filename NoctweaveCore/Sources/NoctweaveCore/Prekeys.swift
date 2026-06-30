import Foundation

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
        let payload = SignedPrekeyPayload(id: id, publicKey: publicKey, issuedAt: issuedAt)
        guard let data = try? NoctweaveCoder.encode(payload, sortedKeys: true) else {
            return false
        }
        return SigningKeyPair.verify(signature: signature, data: data, publicKeyData: publicSigningKey)
    }
}

public struct PrekeyBundle: Codable, Equatable {
    public let version: Int
    public let identityFingerprint: String
    public let signedPrekey: SignedPrekey
    public let oneTimePrekeys: [OneTimePrekey]
    public let createdAt: Date

    public init(
        version: Int = 1,
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
        let signedKeyPair = AgreementKeyPair()
        let signedPrekey = try SignedPrekey.create(
            agreementPublicKey: signedKeyPair.publicKeyData,
            signingKey: identity.signingKey
        )
        var oneTime: [PrekeyPrivateRecord] = []
        for _ in 0..<max(0, oneTimeCount) {
            let keyPair = AgreementKeyPair()
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
            version: 2,
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
