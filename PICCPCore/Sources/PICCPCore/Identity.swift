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

    public var fingerprint: String {
        CryptoBox.fingerprint(for: signingKey.publicKeyData)
    }

    public mutating func rotateKeys() throws -> IdentityRotationContext {
        let oldSigningKey = signingKey
        let oldAgreementKey = agreementKey
        let oldFingerprint = fingerprint

        signingKey = SigningKeyPair()
        agreementKey = AgreementKeyPair()
        rotationCounter += 1

        let rotation = try IdentityRotation.create(
            newSigningPublicKey: signingKey.publicKeyData,
            newAgreementPublicKey: agreementKey.publicKeyData,
            counter: rotationCounter,
            signingKey: oldSigningKey
        )

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
        let data = try PICCPCoder.encode(payload, sortedKeys: true)
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
        guard let data = try? PICCPCoder.encode(payload, sortedKeys: true) else {
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
