import Foundation

public enum ContactOfferError: Error, Equatable {
    case invalidSignature
    case invalidFingerprint
    case invalidKeyMaterial
}

public struct ContactOffer: Codable, Equatable {
    public let version: Int
    public let displayName: String
    public let inboxId: String
    public let relay: RelayEndpoint
    public let signingPublicKey: Data
    public let agreementPublicKey: Data
    public let inboxAccessPublicKey: Data?
    public let fingerprint: String
    public let signature: Data

    public init(
        version: Int = 1,
        displayName: String,
        inboxId: String,
        relay: RelayEndpoint,
        signingPublicKey: Data,
        agreementPublicKey: Data,
        inboxAccessPublicKey: Data? = nil,
        fingerprint: String,
        signature: Data
    ) {
        self.version = version
        self.displayName = displayName
        self.inboxId = inboxId
        self.relay = relay
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
        self.inboxAccessPublicKey = inboxAccessPublicKey
        self.fingerprint = fingerprint
        self.signature = signature
    }

    public static func create(
        displayName: String,
        inboxId: String,
        relay: RelayEndpoint,
        signingKey: SigningKeyPair,
        agreementPublicKey: Data,
        inboxAccessPublicKey: Data? = nil
    ) throws -> ContactOffer {
        let fingerprint = CryptoBox.fingerprint(for: signingKey.publicKeyData)
        let unsigned = UnsignedContactOffer(
            version: inboxAccessPublicKey == nil ? 2 : 3,
            displayName: displayName,
            inboxId: inboxId,
            relay: relay,
            signingPublicKey: signingKey.publicKeyData,
            agreementPublicKey: agreementPublicKey,
            inboxAccessPublicKey: inboxAccessPublicKey,
            fingerprint: fingerprint
        )
        let signature = try signingKey.sign(unsigned.signableData())
        return ContactOffer(
            version: unsigned.version,
            displayName: unsigned.displayName,
            inboxId: unsigned.inboxId,
            relay: unsigned.relay,
            signingPublicKey: unsigned.signingPublicKey,
            agreementPublicKey: unsigned.agreementPublicKey,
            inboxAccessPublicKey: unsigned.inboxAccessPublicKey,
            fingerprint: unsigned.fingerprint,
            signature: signature
        )
    }

    public func verified() throws -> ContactOffer {
        guard isConsistentFingerprint() else {
            throw ContactOfferError.invalidFingerprint
        }
        guard SigningKeyPair.isValidPublicKey(signingPublicKey),
              AgreementKeyPair.isValidPublicKey(agreementPublicKey),
              inboxAccessPublicKey.map(SigningKeyPair.isValidPublicKey) ?? true else {
            throw ContactOfferError.invalidKeyMaterial
        }
        guard verifySignature() else {
            throw ContactOfferError.invalidSignature
        }
        return self
    }

    public func isConsistentFingerprint() -> Bool {
        fingerprint == CryptoBox.fingerprint(for: signingPublicKey)
    }

    public func verifySignature() -> Bool {
        guard let data = try? unsignedRepresentation.signableData() else {
            return false
        }
        return SigningKeyPair.verify(signature: signature, data: data, publicKeyData: signingPublicKey)
    }

    private var unsignedRepresentation: UnsignedContactOffer {
        UnsignedContactOffer(
            version: version,
            displayName: displayName,
            inboxId: inboxId,
            relay: relay,
            signingPublicKey: signingPublicKey,
            agreementPublicKey: agreementPublicKey,
            inboxAccessPublicKey: inboxAccessPublicKey,
            fingerprint: fingerprint
        )
    }
}

public enum ContactOfferCode {
    public static func encode(_ offer: ContactOffer) throws -> String {
        let data = try NoctweaveCoder.encode(offer)
        return data.base64EncodedString()
    }

    public static func decode(_ code: String) throws -> ContactOffer {
        let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = Data(base64Encoded: trimmed) else {
            throw CryptoError.invalidPayload
        }
        let offer = try NoctweaveCoder.decode(ContactOffer.self, from: data)
        return try offer.verified()
    }
}

private struct UnsignedContactOffer: Codable {
    let version: Int
    let displayName: String
    let inboxId: String
    let relay: RelayEndpoint
    let signingPublicKey: Data
    let agreementPublicKey: Data
    let inboxAccessPublicKey: Data?
    let fingerprint: String

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}
