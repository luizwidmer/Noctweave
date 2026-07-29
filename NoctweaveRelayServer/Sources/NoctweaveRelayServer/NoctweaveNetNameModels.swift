import Foundation

struct NoctweaveNetHostNameBindingRequestV1: Codable, Equatable {
    let version: Int
    let relaySuffix: NoctwebRelaySuffixV1
    let siteLabel: String
    let objectID: String
    let publisherID: String
    let headID: String?
    let revision: UInt64
    let previousObjectID: String?
    let idempotencyKey: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case relaySuffix
        case siteLabel
        case objectID
        case publisherID
        case headID
        case revision
        case previousObjectID
        case idempotencyKey
    }

    init(
        relaySuffix: NoctwebRelaySuffixV1,
        siteLabel: String,
        objectID: String,
        publisherID: String,
        headID: String?,
        revision: UInt64,
        previousObjectID: String?,
        idempotencyKey: Data
    ) {
        version = 1
        self.relaySuffix = relaySuffix
        self.siteLabel = siteLabel
        self.objectID = objectID
        self.publisherID = publisherID
        self.headID = headID
        self.revision = revision
        self.previousObjectID = previousObjectID
        self.idempotencyKey = idempotencyKey
    }

    var isStructurallyValid: Bool {
        version == 1
            && relaySuffix.isStructurallyValid
            && netSiteLabelIsValid(siteLabel)
            && netObjectIDIsValid(objectID)
            && netPublisherIDIsValid(publisherID)
            && (headID == nil || netDigestIDIsValid(headID!))
            && revision > 0
            && revision <= UInt64(RelayIdentityV1.maximumSequence)
            && (previousObjectID == nil
                || netObjectIDIsValid(previousObjectID!))
            && idempotencyKey.count
                == NoctweaveNetLimits.idempotencyKeyBytes
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(
            decoder,
            CodingKeys.self,
            context: "Noctweave Net host name binding request"
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            relaySuffix: try values.decode(
                NoctwebRelaySuffixV1.self,
                forKey: .relaySuffix
            ),
            siteLabel: try values.decode(String.self, forKey: .siteLabel),
            objectID: try values.decode(String.self, forKey: .objectID),
            publisherID: try values.decode(
                String.self,
                forKey: .publisherID
            ),
            headID: try values.decodeIfPresent(
                String.self,
                forKey: .headID
            ),
            revision: try values.decode(UInt64.self, forKey: .revision),
            previousObjectID: try values.decodeIfPresent(
                String.self,
                forKey: .previousObjectID
            ),
            idempotencyKey: try values.decode(
                Data.self,
                forKey: .idempotencyKey
            )
        )
        guard try values.decode(Int.self, forKey: .version) == version,
              isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: values,
                debugDescription:
                    "Noctweave Net host name binding request is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(
                self,
                encoder,
                context: "Noctweave Net host name binding request"
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(relaySuffix, forKey: .relaySuffix)
        try values.encode(siteLabel, forKey: .siteLabel)
        try values.encode(objectID, forKey: .objectID)
        try values.encode(publisherID, forKey: .publisherID)
        try values.encode(headID, forKey: .headID)
        try values.encode(revision, forKey: .revision)
        try values.encode(previousObjectID, forKey: .previousObjectID)
        try values.encode(idempotencyKey, forKey: .idempotencyKey)
    }
}

struct NoctweaveNetHostNameRequestV1: Codable, Equatable {
    let version: Int
    let relaySuffix: NoctwebRelaySuffixV1
    let siteLabel: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case relaySuffix
        case siteLabel
    }

    init(relaySuffix: NoctwebRelaySuffixV1, siteLabel: String) {
        version = 1
        self.relaySuffix = relaySuffix
        self.siteLabel = siteLabel
    }

    var isStructurallyValid: Bool {
        version == 1
            && relaySuffix.isStructurallyValid
            && netSiteLabelIsValid(siteLabel)
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(
            decoder,
            CodingKeys.self,
            context: "Noctweave Net host name request"
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            relaySuffix: try values.decode(
                NoctwebRelaySuffixV1.self,
                forKey: .relaySuffix
            ),
            siteLabel: try values.decode(String.self, forKey: .siteLabel)
        )
        guard try values.decode(Int.self, forKey: .version) == version,
              isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: values,
                debugDescription:
                    "Noctweave Net host name request is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(
                self,
                encoder,
                context: "Noctweave Net host name request"
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(relaySuffix, forKey: .relaySuffix)
        try values.encode(siteLabel, forKey: .siteLabel)
    }
}

struct NoctweaveNetHostNameResolutionV1: Codable, Equatable {
    static let signatureAlgorithm = RelayIdentityV1.signatureAlgorithm

    let version: Int
    let relayID: RelayIdentityIDV1
    let relaySuffix: NoctwebRelaySuffixV1
    let siteLabel: String
    let objectID: String
    let publisherID: String
    let headID: String?
    let revision: UInt64
    let updatedAt: Date
    let expiresAt: Date
    let signatureAlgorithm: String
    let signature: Data

    private struct Unsigned: Codable {
        let version: Int
        let relayID: RelayIdentityIDV1
        let relaySuffix: NoctwebRelaySuffixV1
        let siteLabel: String
        let objectID: String
        let publisherID: String
        let headID: String?
        let revision: UInt64
        let updatedAt: Date
        let expiresAt: Date
        let signatureAlgorithm: String
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case relayID
        case relaySuffix
        case siteLabel
        case objectID
        case publisherID
        case headID
        case revision
        case updatedAt
        case expiresAt
        case signatureAlgorithm
        case signature
    }

    static func signed(
        binding: NoctweaveNetHostNameBindingRequestV1,
        updatedAt: Date,
        signer: RelayIdentityKeyMaterialV1,
        at now: Date = Date()
    ) throws -> NoctweaveNetHostNameResolutionV1 {
        let unsigned = Unsigned(
            version: 1,
            relayID: signer.relayID,
            relaySuffix: binding.relaySuffix,
            siteLabel: binding.siteLabel,
            objectID: binding.objectID,
            publisherID: binding.publisherID,
            headID: binding.headID,
            revision: binding.revision,
            updatedAt: netCanonicalDate(updatedAt),
            expiresAt: netCanonicalDate(
                now.addingTimeInterval(
                    NoctweaveNetLimits.maximumNameResolutionLifetime
                )
            ),
            signatureAlgorithm: signatureAlgorithm
        )
        return NoctweaveNetHostNameResolutionV1(
            unsigned: unsigned,
            signature: try OQSSignatureVerifier.shared.signThrowing(
                data: transcript(for: unsigned),
                privateKey: signer.signingPrivateKey,
                publicKey: signer.signingPublicKey
            )
        )
    }

    private init(unsigned: Unsigned, signature: Data) {
        version = unsigned.version
        relayID = unsigned.relayID
        relaySuffix = unsigned.relaySuffix
        siteLabel = unsigned.siteLabel
        objectID = unsigned.objectID
        publisherID = unsigned.publisherID
        headID = unsigned.headID
        revision = unsigned.revision
        updatedAt = unsigned.updatedAt
        expiresAt = unsigned.expiresAt
        signatureAlgorithm = unsigned.signatureAlgorithm
        self.signature = signature
    }

    var isStructurallyValid: Bool {
        version == 1
            && relayID.isStructurallyValid
            && relaySuffix.isStructurallyValid
            && netSiteLabelIsValid(siteLabel)
            && netObjectIDIsValid(objectID)
            && netPublisherIDIsValid(publisherID)
            && (headID == nil || netDigestIDIsValid(headID!))
            && revision > 0
            && revision <= UInt64(RelayIdentityV1.maximumSequence)
            && netIsCanonicalDate(updatedAt)
            && netIsCanonicalDate(expiresAt)
            && expiresAt > updatedAt
            && expiresAt.timeIntervalSince(updatedAt)
                <= TimeInterval(
                    NoctweaveNetLimits.maximumNameResolutionLifetime
                )
            && signatureAlgorithm == Self.signatureAlgorithm
            && !signature.isEmpty
    }

    func verifyThrowing(
        expectedRelayIdentity: SignedRelayIdentityClaimV1,
        at now: Date = Date()
    ) throws -> Bool {
        guard isStructurallyValid,
              try expectedRelayIdentity.verifyThrowing(at: now),
              relayID == expectedRelayIdentity.claim.relayID,
              relaySuffix == expectedRelayIdentity.claim.noctwebSuffix,
              expiresAt >= now.addingTimeInterval(
                -RelayIdentityV1.maximumClockSkew
              ) else {
            return false
        }
        return try OQSSignatureVerifier.shared.verifyThrowing(
            signature: signature,
            data: Self.transcript(for: unsigned),
            publicKey: expectedRelayIdentity.claim.signingPublicKey
        )
    }

    private var unsigned: Unsigned {
        Unsigned(
            version: version,
            relayID: relayID,
            relaySuffix: relaySuffix,
            siteLabel: siteLabel,
            objectID: objectID,
            publisherID: publisherID,
            headID: headID,
            revision: revision,
            updatedAt: updatedAt,
            expiresAt: expiresAt,
            signatureAlgorithm: signatureAlgorithm
        )
    }

    private static func transcript(for value: Unsigned) throws -> Data {
        var transcript = Data(
            "Noctweave/NoctwebHostNameResolution/v1\u{0}".utf8
        )
        transcript.append(try RelayCanonicalJSON.encode(value))
        return transcript
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(
            decoder,
            CodingKeys.self,
            context: "Noctweave Net host name resolution"
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let unsigned = Unsigned(
            version: try values.decode(Int.self, forKey: .version),
            relayID: try values.decode(
                RelayIdentityIDV1.self,
                forKey: .relayID
            ),
            relaySuffix: try values.decode(
                NoctwebRelaySuffixV1.self,
                forKey: .relaySuffix
            ),
            siteLabel: try values.decode(String.self, forKey: .siteLabel),
            objectID: try values.decode(String.self, forKey: .objectID),
            publisherID: try values.decode(
                String.self,
                forKey: .publisherID
            ),
            headID: try values.decodeIfPresent(
                String.self,
                forKey: .headID
            ),
            revision: try values.decode(UInt64.self, forKey: .revision),
            updatedAt: try values.decode(Date.self, forKey: .updatedAt),
            expiresAt: try values.decode(Date.self, forKey: .expiresAt),
            signatureAlgorithm: try values.decode(
                String.self,
                forKey: .signatureAlgorithm
            )
        )
        self.init(
            unsigned: unsigned,
            signature: try values.decode(Data.self, forKey: .signature)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .signature,
                in: values,
                debugDescription:
                    "Noctweave Net host name resolution is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(
                self,
                encoder,
                context: "Noctweave Net host name resolution"
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(relayID, forKey: .relayID)
        try values.encode(relaySuffix, forKey: .relaySuffix)
        try values.encode(siteLabel, forKey: .siteLabel)
        try values.encode(objectID, forKey: .objectID)
        try values.encode(publisherID, forKey: .publisherID)
        try values.encode(headID, forKey: .headID)
        try values.encode(revision, forKey: .revision)
        try values.encode(updatedAt, forKey: .updatedAt)
        try values.encode(expiresAt, forKey: .expiresAt)
        try values.encode(signatureAlgorithm, forKey: .signatureAlgorithm)
        try values.encode(signature, forKey: .signature)
    }
}

private func netSiteLabelIsValid(_ value: String) -> Bool {
    guard value == value.lowercased(),
          !value.isEmpty,
          value.utf8.count <= NoctweaveNetLimits.maximumSiteLabelBytes,
          value.first != "-",
          value.last != "-" else {
        return false
    }
    return value.utf8.allSatisfy {
        (48...57).contains($0)
            || (97...122).contains($0)
            || $0 == 45
    }
}

private func netPublisherIDIsValid(_ value: String) -> Bool {
    guard value.hasPrefix("nwpub1_"),
          value.utf8.count == "nwpub1_".utf8.count + 64,
          value.utf8.count
            <= NoctweaveNetLimits.maximumPublisherIDBytes else {
        return false
    }
    return value.dropFirst("nwpub1_".count).utf8.allSatisfy {
        (48...57).contains($0) || (97...102).contains($0)
    }
}

private func netDigestIDIsValid(_ value: String) -> Bool {
    guard value.hasPrefix("sha256:"),
          value.utf8.count == NoctweaveNetLimits.maximumHeadIDBytes else {
        return false
    }
    return value.dropFirst("sha256:".count).utf8.allSatisfy {
        (48...57).contains($0) || (97...102).contains($0)
    }
}
