import Foundation

public enum ContactOfferError: Error, Equatable {
    case invalidSignature
    case invalidFingerprint
    case invalidKeyMaterial
    case invalidStructure
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
        guard isStructurallyValid else {
            throw ContactOfferError.invalidStructure
        }
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
        guard isStructurallyValid,
              let data = try? unsignedRepresentation.signableData() else {
            return false
        }
        return SigningKeyPair.verify(signature: signature, data: data, publicKeyData: signingPublicKey)
    }

    public var isStructurallyValid: Bool {
        let normalizedDisplayName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedHost = relay.host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (version == 2 && inboxAccessPublicKey == nil) || (version == 3 && inboxAccessPublicKey != nil),
              !normalizedDisplayName.isEmpty,
              normalizedDisplayName.utf8.count <= 512,
              !inboxId.isEmpty,
              inboxId.utf8.count <= 128,
              !normalizedHost.isEmpty,
              normalizedHost == relay.host,
              normalizedHost.utf8.count <= 253,
              relay.port > 0,
              fingerprint.utf8.count <= 128,
              signature.count <= 8 * 1024 else {
            return false
        }
        if let inboxAccessPublicKey {
            guard InboxAddress.isValid(inboxId),
                  InboxAddress.isBound(inboxId, to: inboxAccessPublicKey) else {
                return false
            }
        }
        return true
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
    public static let maximumCodeCharacters = 64 * 1024

    public static func encode(_ offer: ContactOffer) throws -> String {
        _ = try offer.verified()
        let data = try NoctweaveCoder.encode(offer)
        let code = data.base64EncodedString()
        guard code.count <= maximumCodeCharacters else {
            throw CryptoError.invalidPayload
        }
        return code
    }

    public static func decode(_ code: String) throws -> ContactOffer {
        let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= maximumCodeCharacters else {
            throw CryptoError.invalidPayload
        }
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
