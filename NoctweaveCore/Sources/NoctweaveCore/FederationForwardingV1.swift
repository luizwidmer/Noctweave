import Foundation

public enum FederationForwardingV1 {
    public static let version = 1
    public static let maximumDeliveryLifetime: TimeInterval = 60
    public static let maximumClockSkew: TimeInterval = 30
    public static let signatureAlgorithm = RelayIdentityV1.signatureAlgorithm
}

/// A client asks only its home relay to deliver this already encrypted opaque
/// route packet to one authenticated federation member.
public struct FederatedOpaqueRouteForwardRequestV1: Codable, Equatable {
    public let destinationRelayID: RelayIdentityIDV1
    public let destination: RelayEndpoint
    public let append: AppendOpaqueRouteRelayRequestV2

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case destinationRelayID
        case destination
        case append
    }

    public init(
        destinationRelayID: RelayIdentityIDV1,
        destination: RelayEndpoint,
        append: AppendOpaqueRouteRelayRequestV2
    ) {
        self.destinationRelayID = destinationRelayID
        self.destination = destination
        self.append = append
    }

    public var isStructurallyValid: Bool {
        destinationRelayID.isStructurallyValid
            && destination.isStructurallyValid
            && append.isStructurallyValid
    }

    public init(from decoder: Decoder) throws {
        try federationForwardRequireExactFields(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            destinationRelayID: try values.decode(
                RelayIdentityIDV1.self,
                forKey: .destinationRelayID
            ),
            destination: try values.decode(RelayEndpoint.self, forKey: .destination),
            append: try values.decode(
                AppendOpaqueRouteRelayRequestV2.self,
                forKey: .append
            )
        )
        guard isStructurallyValid else {
            throw federationForwardDecodingError(
                decoder,
                "Federated opaque-route forwarding request is invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw federationForwardEncodingError(
                encoder,
                "Federated opaque-route forwarding request is invalid"
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(destinationRelayID, forKey: .destinationRelayID)
        try values.encode(destination, forKey: .destination)
        try values.encode(append, forKey: .append)
    }
}

/// One-hop relay-to-relay delivery. The destination handles the embedded
/// append locally; this body can never be forwarded recursively.
public struct FederatedOpaqueRouteDeliveryV1: Codable, Equatable {
    public let version: Int
    public let deliveryID: UUID
    public let sourceIdentity: SignedRelayIdentityClaimV1
    public let destinationRelayID: RelayIdentityIDV1
    public let append: AppendOpaqueRouteRelayRequestV2
    public let issuedAt: Date
    public let expiresAt: Date
    public let signatureAlgorithm: String
    public let signature: Data

    private struct Unsigned: Codable {
        let version: Int
        let deliveryID: UUID
        let sourceIdentity: SignedRelayIdentityClaimV1
        let destinationRelayID: RelayIdentityIDV1
        let append: AppendOpaqueRouteRelayRequestV2
        let issuedAt: Date
        let expiresAt: Date
        let signatureAlgorithm: String
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case deliveryID
        case sourceIdentity
        case destinationRelayID
        case append
        case issuedAt
        case expiresAt
        case signatureAlgorithm
        case signature
    }

    private init(
        version: Int,
        deliveryID: UUID,
        sourceIdentity: SignedRelayIdentityClaimV1,
        destinationRelayID: RelayIdentityIDV1,
        append: AppendOpaqueRouteRelayRequestV2,
        issuedAt: Date,
        expiresAt: Date,
        signatureAlgorithm: String,
        signature: Data
    ) {
        self.version = version
        self.deliveryID = deliveryID
        self.sourceIdentity = sourceIdentity
        self.destinationRelayID = destinationRelayID
        self.append = append
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }

    public static func signed(
        deliveryID: UUID = UUID(),
        sourceIdentity: SignedRelayIdentityClaimV1,
        sourceKey: RelayIdentityKeyMaterialV1,
        destinationRelayID: RelayIdentityIDV1,
        append: AppendOpaqueRouteRelayRequestV2,
        issuedAt: Date = Date(),
        lifetime: TimeInterval = 30
    ) throws -> FederatedOpaqueRouteDeliveryV1 {
        guard sourceIdentity.claim.relayID == sourceKey.relayID,
              sourceIdentity.claim.signingPublicKey == sourceKey.signingPublicKey,
              lifetime.isFinite,
              lifetime > 0,
              lifetime <= FederationForwardingV1.maximumDeliveryLifetime else {
            throw CryptoError.invalidPayload
        }
        let canonicalIssuedAt = federationForwardCanonicalDate(issuedAt)
        let unsigned = Unsigned(
            version: FederationForwardingV1.version,
            deliveryID: deliveryID,
            sourceIdentity: sourceIdentity,
            destinationRelayID: destinationRelayID,
            append: append,
            issuedAt: canonicalIssuedAt,
            expiresAt: federationForwardCanonicalDate(
                canonicalIssuedAt.addingTimeInterval(lifetime)
            ),
            signatureAlgorithm: FederationForwardingV1.signatureAlgorithm
        )
        return FederatedOpaqueRouteDeliveryV1(
            version: unsigned.version,
            deliveryID: unsigned.deliveryID,
            sourceIdentity: unsigned.sourceIdentity,
            destinationRelayID: unsigned.destinationRelayID,
            append: unsigned.append,
            issuedAt: unsigned.issuedAt,
            expiresAt: unsigned.expiresAt,
            signatureAlgorithm: unsigned.signatureAlgorithm,
            signature: try sourceKey.signingKeyPair.sign(try Self.transcript(unsigned))
        )
    }

    public func verifyThrowing(
        expectedDestinationRelayID: RelayIdentityIDV1,
        federation: FederationDescriptor,
        at now: Date = Date()
    ) throws -> Bool {
        guard version == FederationForwardingV1.version,
              destinationRelayID == expectedDestinationRelayID,
              append.isStructurallyValid,
              namespaceFederationMatches(sourceIdentity.claim, federation: federation),
              try sourceIdentity.verifyThrowing(at: now),
              federationForwardIsCanonicalDate(issuedAt),
              federationForwardIsCanonicalDate(expiresAt),
              expiresAt > issuedAt,
              expiresAt.timeIntervalSince(issuedAt)
                <= FederationForwardingV1.maximumDeliveryLifetime,
              issuedAt <= now.addingTimeInterval(FederationForwardingV1.maximumClockSkew),
              expiresAt >= now.addingTimeInterval(-FederationForwardingV1.maximumClockSkew),
              signatureAlgorithm == FederationForwardingV1.signatureAlgorithm else {
            return false
        }
        return try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: Self.transcript(unsigned),
            publicKeyData: sourceIdentity.claim.signingPublicKey
        )
    }

    private var unsigned: Unsigned {
        Unsigned(
            version: version,
            deliveryID: deliveryID,
            sourceIdentity: sourceIdentity,
            destinationRelayID: destinationRelayID,
            append: append,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            signatureAlgorithm: signatureAlgorithm
        )
    }

    private static func transcript(_ unsigned: Unsigned) throws -> Data {
        var transcript = Data("Noctweave/FederatedOpaqueRouteDelivery/v1\u{0}".utf8)
        transcript.append(try NoctweaveCanonicalJSON.encode(unsigned))
        return transcript
    }

    public init(from decoder: Decoder) throws {
        try federationForwardRequireExactFields(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        version = try values.decode(Int.self, forKey: .version)
        deliveryID = try values.decode(UUID.self, forKey: .deliveryID)
        sourceIdentity = try values.decode(
            SignedRelayIdentityClaimV1.self,
            forKey: .sourceIdentity
        )
        destinationRelayID = try values.decode(
            RelayIdentityIDV1.self,
            forKey: .destinationRelayID
        )
        append = try values.decode(
            AppendOpaqueRouteRelayRequestV2.self,
            forKey: .append
        )
        issuedAt = try values.decode(Date.self, forKey: .issuedAt)
        expiresAt = try values.decode(Date.self, forKey: .expiresAt)
        signatureAlgorithm = try values.decode(String.self, forKey: .signatureAlgorithm)
        signature = try values.decode(Data.self, forKey: .signature)
        guard version == FederationForwardingV1.version,
              destinationRelayID.isStructurallyValid,
              append.isStructurallyValid,
              federationForwardIsCanonicalDate(issuedAt),
              federationForwardIsCanonicalDate(expiresAt),
              expiresAt > issuedAt,
              expiresAt.timeIntervalSince(issuedAt)
                <= FederationForwardingV1.maximumDeliveryLifetime,
              signatureAlgorithm == FederationForwardingV1.signatureAlgorithm else {
            throw federationForwardDecodingError(
                decoder,
                "Federated opaque-route delivery is invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard version == FederationForwardingV1.version,
              destinationRelayID.isStructurallyValid,
              append.isStructurallyValid,
              federationForwardIsCanonicalDate(issuedAt),
              federationForwardIsCanonicalDate(expiresAt),
              expiresAt > issuedAt,
              expiresAt.timeIntervalSince(issuedAt)
                <= FederationForwardingV1.maximumDeliveryLifetime,
              signatureAlgorithm == FederationForwardingV1.signatureAlgorithm else {
            throw federationForwardEncodingError(
                encoder,
                "Federated opaque-route delivery is invalid"
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(deliveryID, forKey: .deliveryID)
        try values.encode(sourceIdentity, forKey: .sourceIdentity)
        try values.encode(destinationRelayID, forKey: .destinationRelayID)
        try values.encode(append, forKey: .append)
        try values.encode(issuedAt, forKey: .issuedAt)
        try values.encode(expiresAt, forKey: .expiresAt)
        try values.encode(signatureAlgorithm, forKey: .signatureAlgorithm)
        try values.encode(signature, forKey: .signature)
    }
}

public struct FederatedNetHostReadRequestV1: Codable, Equatable {
    public let destinationRelayID: RelayIdentityIDV1
    public let destination: RelayEndpoint
    public let request: NoctweaveNetHostObjectRequest

    public init(
        destinationRelayID: RelayIdentityIDV1,
        destination: RelayEndpoint,
        request: NoctweaveNetHostObjectRequest
    ) {
        self.destinationRelayID = destinationRelayID
        self.destination = destination
        self.request = request
    }

    public var isStructurallyValid: Bool {
        destinationRelayID.isStructurallyValid
            && destination.isStructurallyValid
            && request.isStructurallyValid
    }
}

public struct FederatedNetHostObjectResponseV1: Codable, Equatable {
    public let destinationIdentity: SignedRelayIdentityClaimV1
    public let object: NoctweaveNetHostFetchResponse

    public init(
        destinationIdentity: SignedRelayIdentityClaimV1,
        object: NoctweaveNetHostFetchResponse
    ) {
        self.destinationIdentity = destinationIdentity
        self.object = object
    }

    public func verifyThrowing(
        expectedRelayID: RelayIdentityIDV1,
        at now: Date = Date()
    ) throws -> Bool {
        try destinationIdentity.verifyThrowing(at: now)
            && destinationIdentity.claim.relayID == expectedRelayID
            && destinationIdentity.claim.hostSigningPublicKey
                == object.receipt.signingPublicKey
            && object.isStructurallyValid
    }
}

public struct FederatedNetHostNameReadRequestV1: Codable, Equatable {
    public let destinationRelayID: RelayIdentityIDV1
    public let destination: RelayEndpoint
    public let request: NoctweaveNetHostNameRequestV1

    public init(
        destinationRelayID: RelayIdentityIDV1,
        destination: RelayEndpoint,
        request: NoctweaveNetHostNameRequestV1
    ) {
        self.destinationRelayID = destinationRelayID
        self.destination = destination
        self.request = request
    }

    public var isStructurallyValid: Bool {
        destinationRelayID.isStructurallyValid
            && destination.isStructurallyValid
            && request.isStructurallyValid
    }
}

public struct FederatedNetHostNameResponseV1: Codable, Equatable {
    public let destinationIdentity: SignedRelayIdentityClaimV1
    public let resolution: NoctweaveNetHostNameResolutionV1

    public init(
        destinationIdentity: SignedRelayIdentityClaimV1,
        resolution: NoctweaveNetHostNameResolutionV1
    ) {
        self.destinationIdentity = destinationIdentity
        self.resolution = resolution
    }

    public func verifyThrowing(
        expectedRelayID: RelayIdentityIDV1,
        at now: Date = Date()
    ) throws -> Bool {
        guard destinationIdentity.claim.relayID == expectedRelayID else {
            return false
        }
        return try resolution.verifyThrowing(
            expectedRelayIdentity: destinationIdentity,
            at: now
        )
    }
}

private func namespaceFederationMatches(
    _ claim: RelayIdentityClaimV1,
    federation: FederationDescriptor
) -> Bool {
    claim.federationMode == federation.mode
        && claim.federationName == federation.name
}

private func federationForwardCanonicalDate(_ value: Date) -> Date {
    Date(timeIntervalSince1970: floor(value.timeIntervalSince1970))
}

private func federationForwardIsCanonicalDate(_ value: Date) -> Bool {
    let seconds = value.timeIntervalSince1970
    return seconds.isFinite
        && seconds >= 0
        && seconds <= 4_102_444_800
        && floor(seconds) == seconds
}

private func federationForwardRequireExactFields<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ keyType: Key.Type
) throws where Key.AllCases: Collection, Key.AllCases.Element == Key {
    let expected = Set(Key.allCases.map(\.stringValue))
    let values = try decoder.container(keyedBy: FederationForwardDynamicCodingKey.self)
    guard Set(values.allKeys.map(\.stringValue)) == expected else {
        throw federationForwardDecodingError(
            decoder,
            "Federation forwarding fields must match the current protocol exactly"
        )
    }
}

private struct FederationForwardDynamicCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private func federationForwardDecodingError(
    _ decoder: Decoder,
    _ message: String
) -> DecodingError {
    DecodingError.dataCorrupted(
        .init(codingPath: decoder.codingPath, debugDescription: message)
    )
}

private func federationForwardEncodingError(
    _ encoder: Encoder,
    _ message: String
) -> EncodingError {
    EncodingError.invalidValue(
        message,
        .init(codingPath: encoder.codingPath, debugDescription: message)
    )
}
