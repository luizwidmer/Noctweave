import Foundation

public struct Contact: Codable, Identifiable, Equatable {
    public let id: UUID
    public var displayName: String
    public var inboxId: String
    public var relay: RelayEndpoint
    public var signingPublicKey: Data
    public var agreementPublicKey: Data
    public var rotationCounter: UInt64
    public var allowIdentityReset: Bool
    public var trustAssertions: [ContactTrustAssertion]

    public init(
        id: UUID = UUID(),
        displayName: String,
        inboxId: String,
        relay: RelayEndpoint,
        signingPublicKey: Data,
        agreementPublicKey: Data,
        rotationCounter: UInt64 = 0,
        allowIdentityReset: Bool = false,
        trustAssertions: [ContactTrustAssertion] = []
    ) {
        self.id = id
        self.displayName = displayName
        self.inboxId = inboxId
        self.relay = relay
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
        self.rotationCounter = rotationCounter
        self.allowIdentityReset = allowIdentityReset
        self.trustAssertions = trustAssertions
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case displayName
        case inboxId
        case relay
        case signingPublicKey
        case agreementPublicKey
        case rotationCounter
        case allowIdentityReset
        case trustAssertions
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        displayName = try container.decode(String.self, forKey: .displayName)
        inboxId = try container.decode(String.self, forKey: .inboxId)
        relay = try container.decode(RelayEndpoint.self, forKey: .relay)
        signingPublicKey = try container.decode(Data.self, forKey: .signingPublicKey)
        agreementPublicKey = try container.decode(Data.self, forKey: .agreementPublicKey)
        rotationCounter = try container.decodeIfPresent(UInt64.self, forKey: .rotationCounter) ?? 0
        allowIdentityReset = try container.decodeIfPresent(Bool.self, forKey: .allowIdentityReset) ?? false
        trustAssertions = try container.decodeIfPresent([ContactTrustAssertion].self, forKey: .trustAssertions) ?? []
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(displayName, forKey: .displayName)
        try container.encode(inboxId, forKey: .inboxId)
        try container.encode(relay, forKey: .relay)
        try container.encode(signingPublicKey, forKey: .signingPublicKey)
        try container.encode(agreementPublicKey, forKey: .agreementPublicKey)
        try container.encode(rotationCounter, forKey: .rotationCounter)
        try container.encode(allowIdentityReset, forKey: .allowIdentityReset)
        try container.encode(trustAssertions, forKey: .trustAssertions)
    }

    public var fingerprint: String {
        CryptoBox.fingerprint(for: signingPublicKey)
    }

    public mutating func apply(rotation: IdentityRotation) -> Bool {
        guard rotation.rotationCounter > rotationCounter else {
            return false
        }
        guard rotation.verify(using: signingPublicKey) else {
            return false
        }
        signingPublicKey = rotation.newSigningPublicKey
        agreementPublicKey = rotation.newAgreementPublicKey
        rotationCounter = rotation.rotationCounter
        return true
    }

    public mutating func apply(reset: IdentityReset) -> Bool {
        guard reset.verify(using: signingPublicKey) else {
            return false
        }
        guard let offer = try? reset.newOffer.verified() else {
            return false
        }
        displayName = offer.displayName
        inboxId = offer.inboxId
        relay = offer.relay
        signingPublicKey = offer.signingPublicKey
        agreementPublicKey = offer.agreementPublicKey
        rotationCounter = 0
        return true
    }
}
