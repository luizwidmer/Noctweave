import Foundation

public struct Contact: Codable, Identifiable, Equatable {
    public let id: UUID
    public var displayName: String
    public var inboxId: String
    public var relay: RelayEndpoint
    public var signingPublicKey: Data
    public var agreementPublicKey: Data
    public var identityGenerationId: UUID?
    public var installationCheckpoint: InstallationManifestCheckpointV4?
    public var preferredInstallationEndpoint: CertifiedInstallationEndpoint?
    public var endpointAuthoritySigningPublicKey: Data?
    public var preferredEndpointRevocation: InstallationEndpointRevocationV4?
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
        identityGenerationId: UUID? = nil,
        installationCheckpoint: InstallationManifestCheckpointV4? = nil,
        preferredInstallationEndpoint: CertifiedInstallationEndpoint? = nil,
        endpointAuthoritySigningPublicKey: Data? = nil,
        preferredEndpointRevocation: InstallationEndpointRevocationV4? = nil,
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
        self.identityGenerationId = identityGenerationId
        self.installationCheckpoint = installationCheckpoint
        self.preferredInstallationEndpoint = preferredInstallationEndpoint
        self.endpointAuthoritySigningPublicKey = endpointAuthoritySigningPublicKey
        self.preferredEndpointRevocation = preferredEndpointRevocation
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
        case identityGenerationId
        case installationCheckpoint
        case preferredInstallationEndpoint
        case endpointAuthoritySigningPublicKey
        case preferredEndpointRevocation
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
        identityGenerationId = try container.decodeIfPresent(UUID.self, forKey: .identityGenerationId)
        installationCheckpoint = try container.decodeIfPresent(
            InstallationManifestCheckpointV4.self,
            forKey: .installationCheckpoint
        )
        preferredInstallationEndpoint = try container.decodeIfPresent(
            CertifiedInstallationEndpoint.self,
            forKey: .preferredInstallationEndpoint
        )
        endpointAuthoritySigningPublicKey = try container.decodeIfPresent(
            Data.self,
            forKey: .endpointAuthoritySigningPublicKey
        )
        preferredEndpointRevocation = try container.decodeIfPresent(
            InstallationEndpointRevocationV4.self,
            forKey: .preferredEndpointRevocation
        )
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
        try container.encodeIfPresent(identityGenerationId, forKey: .identityGenerationId)
        try container.encodeIfPresent(installationCheckpoint, forKey: .installationCheckpoint)
        try container.encodeIfPresent(preferredInstallationEndpoint, forKey: .preferredInstallationEndpoint)
        try container.encodeIfPresent(endpointAuthoritySigningPublicKey, forKey: .endpointAuthoritySigningPublicKey)
        try container.encodeIfPresent(preferredEndpointRevocation, forKey: .preferredEndpointRevocation)
        try container.encode(rotationCounter, forKey: .rotationCounter)
        try container.encode(allowIdentityReset, forKey: .allowIdentityReset)
        try container.encode(trustAssertions, forKey: .trustAssertions)
    }

    public var fingerprint: String {
        CryptoBox.fingerprint(for: signingPublicKey)
    }

    public var usesCertifiedInstallationEndpoint: Bool {
        identityGenerationId != nil
            && installationCheckpoint != nil
            && preferredInstallationEndpoint != nil
            && endpointAuthoritySigningPublicKey != nil
    }

    /// Verifies the immutable endpoint authorization without applying the
    /// signed-prekey freshness window. Prekey age is a bootstrap concern; an
    /// already established endpoint session must remain usable until revoked.
    public func certifiedInstallationEndpoint() throws -> CertifiedInstallationEndpoint {
        guard let identityGenerationId,
              let installationCheckpoint,
              let preferredInstallationEndpoint,
              let endpointAuthoritySigningPublicKey,
              preferredInstallationEndpoint.identityGenerationId == identityGenerationId else {
            throw CertifiedInstallationEndpointError.invalidStructure
        }
        if preferredEndpointRevocation?.verify(
            endpoint: preferredInstallationEndpoint,
            identityPublicKey: signingPublicKey
        ) == true {
            throw CertifiedInstallationEndpointError.installationNotAuthorized
        }
        return try preferredInstallationEndpoint.verified(
            identityPublicKey: endpointAuthoritySigningPublicKey,
            checkpoint: installationCheckpoint,
            now: preferredInstallationEndpoint.prekeyBundle.createdAt
        )
    }

    public mutating func apply(endpointRevocation: InstallationEndpointRevocationV4) -> Bool {
        guard let endpoint = preferredInstallationEndpoint,
              endpointAuthoritySigningPublicKey != nil,
              // The endpoint certificate remains pinned to the authority that
              // issued it, while revocation follows the contact's current
              // continuity key. This preserves revocation after a verified
              // identity rotation without retaining the superseded secret key.
              endpointRevocation.verify(endpoint: endpoint, identityPublicKey: signingPublicKey) else {
            return false
        }
        if let existing = preferredEndpointRevocation,
           existing.manifestEpoch >= endpointRevocation.manifestEpoch {
            return existing == endpointRevocation
        }
        preferredEndpointRevocation = endpointRevocation
        return true
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
        identityGenerationId = offer.identityGenerationId
        installationCheckpoint = offer.installationCheckpoint
        preferredInstallationEndpoint = offer.preferredInstallationEndpoint
        endpointAuthoritySigningPublicKey = offer.preferredInstallationEndpoint == nil
            ? nil
            : offer.signingPublicKey
        preferredEndpointRevocation = nil
        rotationCounter = 0
        return true
    }
}
