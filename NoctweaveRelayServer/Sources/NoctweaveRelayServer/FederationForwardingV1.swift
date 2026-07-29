import Foundation

enum FederationForwardingV1 {
    static let version = 1
    static let maximumDeliveryLifetime: TimeInterval = 60
    static let maximumClockSkew: TimeInterval = 30
    static let signatureAlgorithm = RelayIdentityV1.signatureAlgorithm
}

struct FederatedOpaqueRouteForwardRequestV1: Codable, Equatable {
    let destinationRelayID: RelayIdentityIDV1
    let destination: RelayEndpoint
    let append: OpaqueRouteAppendSubmissionV2

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case destinationRelayID
        case destination
        case append
    }

    init(
        destinationRelayID: RelayIdentityIDV1,
        destination: RelayEndpoint,
        append: OpaqueRouteAppendSubmissionV2
    ) {
        self.destinationRelayID = destinationRelayID
        self.destination = destination
        self.append = append
    }

    var isStructurallyValid: Bool {
        destinationRelayID.isStructurallyValid
            && destination.isStructurallyValid
            && append.isStructurallyValid
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(
            decoder,
            CodingKeys.self,
            context: "Federation forwarding request"
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            destinationRelayID: try values.decode(
                RelayIdentityIDV1.self,
                forKey: .destinationRelayID
            ),
            destination: try values.decode(RelayEndpoint.self, forKey: .destination),
            append: try values.decode(
                OpaqueRouteAppendSubmissionV2.self,
                forKey: .append
            )
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .destination,
                in: values,
                debugDescription: "Federation forwarding request is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Federation forwarding request")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(destinationRelayID, forKey: .destinationRelayID)
        try values.encode(destination, forKey: .destination)
        try values.encode(append, forKey: .append)
    }
}

struct FederatedOpaqueRouteDeliveryV1: Codable, Equatable {
    let version: Int
    let deliveryID: UUID
    let sourceIdentity: SignedRelayIdentityClaimV1
    let destinationRelayID: RelayIdentityIDV1
    let append: OpaqueRouteAppendSubmissionV2
    let issuedAt: Date
    let expiresAt: Date
    let signatureAlgorithm: String
    let signature: Data

    private struct Unsigned: Codable {
        let version: Int
        let deliveryID: UUID
        let sourceIdentity: SignedRelayIdentityClaimV1
        let destinationRelayID: RelayIdentityIDV1
        let append: OpaqueRouteAppendSubmissionV2
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
        append: OpaqueRouteAppendSubmissionV2,
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

    static func signed(
        deliveryID: UUID = UUID(),
        sourceIdentity: SignedRelayIdentityClaimV1,
        sourceKey: RelayIdentityKeyMaterialV1,
        destinationRelayID: RelayIdentityIDV1,
        append: OpaqueRouteAppendSubmissionV2,
        issuedAt: Date = Date(),
        lifetime: TimeInterval = 30
    ) throws -> FederatedOpaqueRouteDeliveryV1 {
        guard sourceIdentity.claim.relayID == sourceKey.relayID,
              sourceIdentity.claim.signingPublicKey == sourceKey.signingPublicKey,
              lifetime.isFinite,
              lifetime > 0,
              lifetime <= FederationForwardingV1.maximumDeliveryLifetime else {
            throw RelayIdentityError.invalidPayload
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
            signature: try OQSSignatureVerifier.shared.signThrowing(
                data: try Self.transcript(unsigned),
                privateKey: sourceKey.signingPrivateKey,
                publicKey: sourceKey.signingPublicKey
            )
        )
    }

    func verifyThrowing(
        expectedDestinationRelayID: RelayIdentityIDV1,
        federation: FederationDescriptor,
        at now: Date = Date()
    ) throws -> Bool {
        guard version == FederationForwardingV1.version,
              destinationRelayID == expectedDestinationRelayID,
              append.isStructurallyValid,
              federationForwardFederationMatches(sourceIdentity.claim, federation: federation),
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
        return try OQSSignatureVerifier.shared.verifyThrowing(
            signature: signature,
            data: Self.transcript(unsigned),
            publicKey: sourceIdentity.claim.signingPublicKey
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
        var result = Data("Noctweave/FederatedOpaqueRouteDelivery/v1\u{0}".utf8)
        result.append(try RelayCanonicalJSON.encode(unsigned))
        return result
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(
            decoder,
            CodingKeys.self,
            context: "Federated opaque route delivery"
        )
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
            OpaqueRouteAppendSubmissionV2.self,
            forKey: .append
        )
        issuedAt = try values.decode(Date.self, forKey: .issuedAt)
        expiresAt = try values.decode(Date.self, forKey: .expiresAt)
        signatureAlgorithm = try values.decode(String.self, forKey: .signatureAlgorithm)
        signature = try values.decode(Data.self, forKey: .signature)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: values,
                debugDescription: "Federated opaque route delivery is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Federated opaque route delivery")
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

    private var isStructurallyValid: Bool {
        version == FederationForwardingV1.version
            && destinationRelayID.isStructurallyValid
            && append.isStructurallyValid
            && federationForwardIsCanonicalDate(issuedAt)
            && federationForwardIsCanonicalDate(expiresAt)
            && expiresAt > issuedAt
            && expiresAt.timeIntervalSince(issuedAt)
                <= FederationForwardingV1.maximumDeliveryLifetime
            && signatureAlgorithm == FederationForwardingV1.signatureAlgorithm
            && signature.count == OQSSignatureVerifier.mlDSA65SignatureBytes
    }
}

struct FederatedNetHostReadRequestV1: Codable, Equatable {
    let destinationRelayID: RelayIdentityIDV1
    let destination: RelayEndpoint
    let request: NoctweaveNetHostObjectRequest

    var isStructurallyValid: Bool {
        destinationRelayID.isStructurallyValid
            && destination.isStructurallyValid
            && request.isStructurallyValid
    }
}

struct FederatedNetHostObjectResponseV1: Codable, Equatable {
    let destinationIdentity: SignedRelayIdentityClaimV1
    let object: NoctweaveNetHostFetchResponse

    func verifyThrowing(
        expectedRelayID: RelayIdentityIDV1,
        at now: Date = Date()
    ) throws -> Bool {
        guard try destinationIdentity.verifyThrowing(at: now),
              destinationIdentity.claim.relayID == expectedRelayID,
              destinationIdentity.claim.hostSigningPublicKey
                == object.receipt.signingPublicKey else {
            return false
        }
        return object.isStructurallyValid
    }
}

struct FederatedNetHostNameReadRequestV1: Codable, Equatable {
    let destinationRelayID: RelayIdentityIDV1
    let destination: RelayEndpoint
    let request: NoctweaveNetHostNameRequestV1

    var isStructurallyValid: Bool {
        destinationRelayID.isStructurallyValid
            && destination.isStructurallyValid
            && request.isStructurallyValid
    }
}

struct FederatedNetHostNameResponseV1: Codable, Equatable {
    let destinationIdentity: SignedRelayIdentityClaimV1
    let resolution: NoctweaveNetHostNameResolutionV1

    func verifyThrowing(
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

private func federationForwardFederationMatches(
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
