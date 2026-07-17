import Foundation

/// Short-lived proof used to authorize relay mutations.
public struct RelayActorProof: Codable, Equatable {
    public static let maximumAgeSeconds: TimeInterval = 300

    public let fingerprint: String
    public let publicSigningKey: Data
    public let signedAt: Date
    public let nonce: UUID
    public let signature: Data

    public init(
        fingerprint: String,
        publicSigningKey: Data,
        signedAt: Date = Date(),
        nonce: UUID = UUID(),
        signature: Data
    ) {
        self.fingerprint = fingerprint
        self.publicSigningKey = publicSigningKey
        self.signedAt = signedAt
        self.nonce = nonce
        self.signature = signature
    }

    public static func make(
        identity: Identity,
        signableData: Data,
        signedAt: Date = Date(),
        nonce: UUID = UUID()
    ) throws -> RelayActorProof {
        try make(
            signingKey: identity.signingKey,
            signableData: signableData,
            signedAt: signedAt,
            nonce: nonce
        )
    }

    public static func make(
        signingKey: SigningKeyPair,
        signableData: Data,
        signedAt: Date = Date(),
        nonce: UUID = UUID()
    ) throws -> RelayActorProof {
        RelayActorProof(
            fingerprint: CryptoBox.fingerprint(for: signingKey.publicKeyData),
            publicSigningKey: signingKey.publicKeyData,
            signedAt: signedAt,
            nonce: nonce,
            signature: try signingKey.sign(signableData)
        )
    }

    public func isConsistentFingerprint() -> Bool {
        !publicSigningKey.isEmpty
            && fingerprint == CryptoBox.fingerprint(for: publicSigningKey)
    }

    public func verify(signableData: Data) -> Bool {
        isConsistentFingerprint()
            && SigningKeyPair.verify(
                signature: signature,
                data: signableData,
                publicKeyData: publicSigningKey
            )
    }
}
