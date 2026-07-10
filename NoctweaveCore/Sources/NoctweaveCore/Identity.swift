import Foundation

public struct Identity: Codable {
    public var displayName: String
    public var signingKey: SigningKeyPair
    public var agreementKey: AgreementKeyPair
    public var rotationCounter: UInt64
    public let createdAt: Date

    public init(displayName: String) {
        self.displayName = displayName
        self.signingKey = SigningKeyPair()
        self.agreementKey = AgreementKeyPair()
        self.rotationCounter = 0
        self.createdAt = Date()
    }

    public static func generate(displayName: String) throws -> Identity {
        try Identity(
            displayName: displayName,
            signingKey: SigningKeyPair.generate(),
            agreementKey: AgreementKeyPair.generate()
        )
    }

    public init(
        displayName: String,
        signingKey: SigningKeyPair,
        agreementKey: AgreementKeyPair,
        rotationCounter: UInt64 = 0,
        createdAt: Date = Date()
    ) throws {
        guard SigningKeyPair.isValidPublicKey(signingKey.publicKeyData),
              AgreementKeyPair.isValidPublicKey(agreementKey.publicKeyData) else {
            throw CryptoError.invalidPublicKey
        }
        self.displayName = displayName
        self.signingKey = signingKey
        self.agreementKey = agreementKey
        self.rotationCounter = rotationCounter
        self.createdAt = createdAt
    }

    public var fingerprint: String {
        CryptoBox.fingerprint(for: signingKey.publicKeyData)
    }

    public mutating func rotateKeys() throws -> IdentityRotationContext {
        guard rotationCounter < UInt64.max else {
            throw CryptoError.counterOutOfOrder
        }
        let oldSigningKey = signingKey
        let oldAgreementKey = agreementKey
        let oldFingerprint = fingerprint

        let newSigningKey = try SigningKeyPair.generate()
        let newAgreementKey = try AgreementKeyPair.generate()
        let nextCounter = rotationCounter + 1

        let rotation = try IdentityRotation.create(
            newSigningPublicKey: newSigningKey.publicKeyData,
            newAgreementPublicKey: newAgreementKey.publicKeyData,
            counter: nextCounter,
            signingKey: oldSigningKey
        )

        signingKey = newSigningKey
        agreementKey = newAgreementKey
        rotationCounter = nextCounter

        return IdentityRotationContext(
            rotation: rotation,
            oldSigningKey: oldSigningKey,
            oldAgreementKey: oldAgreementKey,
            oldFingerprint: oldFingerprint
        )
    }
}

public struct IdentityRotationContext {
    public let rotation: IdentityRotation
    public let oldSigningKey: SigningKeyPair
    public let oldAgreementKey: AgreementKeyPair
    public let oldFingerprint: String
}

public struct IdentityRotation: Codable, Equatable {
    public let newSigningPublicKey: Data
    public let newAgreementPublicKey: Data
    public let rotationCounter: UInt64
    public let signature: Data

    public static func create(
        newSigningPublicKey: Data,
        newAgreementPublicKey: Data,
        counter: UInt64,
        signingKey: SigningKeyPair
    ) throws -> IdentityRotation {
        let payload = IdentityRotationPayload(
            newSigningPublicKey: newSigningPublicKey,
            newAgreementPublicKey: newAgreementPublicKey,
            rotationCounter: counter
        )
        let data = try NoctweaveCoder.encode(payload, sortedKeys: true)
        let signature = try signingKey.sign(data)
        return IdentityRotation(
            newSigningPublicKey: newSigningPublicKey,
            newAgreementPublicKey: newAgreementPublicKey,
            rotationCounter: counter,
            signature: signature
        )
    }

    public func verify(using publicSigningKey: Data) -> Bool {
        guard SigningKeyPair.isValidPublicKey(newSigningPublicKey),
              AgreementKeyPair.isValidPublicKey(newAgreementPublicKey) else {
            return false
        }
        let payload = IdentityRotationPayload(
            newSigningPublicKey: newSigningPublicKey,
            newAgreementPublicKey: newAgreementPublicKey,
            rotationCounter: rotationCounter
        )
        guard let data = try? NoctweaveCoder.encode(payload, sortedKeys: true) else {
            return false
        }
        return SigningKeyPair.verify(signature: signature, data: data, publicKeyData: publicSigningKey)
    }
}

private struct IdentityRotationPayload: Codable {
    let newSigningPublicKey: Data
    let newAgreementPublicKey: Data
    let rotationCounter: UInt64
}
