import CryptoKit
import Foundation

public enum RelayIdentityV1 {
    public static let version = 1
    public static let relayIDPrefix = "nwr1"
    public static let relayIDDigestBytes = 32
    public static let capabilityDigestBytes = 32
    public static let maximumEndpoints = 16
    public static let maximumClaimLifetime: TimeInterval = 7 * 24 * 60 * 60
    public static let maximumClockSkew: TimeInterval = 5 * 60
    public static let maximumSequence = 9_007_199_254_740_991
    public static let signatureAlgorithm = "ML-DSA-65"
}

public struct RelayIdentityIDV1: RawRepresentable, Codable, Equatable, Hashable, Comparable {
    public let rawValue: String

    public init?(rawValue: String) {
        guard Self.isCanonical(rawValue) else {
            return nil
        }
        self.rawValue = rawValue
    }

    public static func derived(from signingPublicKey: Data) -> RelayIdentityIDV1 {
        let digest = Data(SHA256.hash(data: signingPublicKey))
        let value = RelayIdentityV1.relayIDPrefix + digest.map {
            String(format: "%02x", $0)
        }.joined()
        return RelayIdentityIDV1(rawValue: value)!
    }

    public static func < (lhs: RelayIdentityIDV1, rhs: RelayIdentityIDV1) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var isStructurallyValid: Bool {
        Self.isCanonical(rawValue)
    }

    private static func isCanonical(_ value: String) -> Bool {
        let expectedCount = RelayIdentityV1.relayIDPrefix.utf8.count
            + RelayIdentityV1.relayIDDigestBytes * 2
        guard value.utf8.count == expectedCount,
              value.hasPrefix(RelayIdentityV1.relayIDPrefix) else {
            return false
        }
        return value.dropFirst(RelayIdentityV1.relayIDPrefix.count).allSatisfy {
            $0.isNumber || ("a"..."f").contains($0)
        }
    }
}

/// A federation-local, relay-owned Noctweb suffix. The restricted ASCII form
/// deliberately excludes Unicode and case folding ambiguity.
public struct NoctwebRelaySuffixV1: RawRepresentable, Codable, Equatable, Hashable, Comparable {
    public let rawValue: String

    public init?(rawValue: String) {
        guard Self.isCanonical(rawValue) else {
            return nil
        }
        self.rawValue = rawValue
    }

    public static func < (lhs: NoctwebRelaySuffixV1, rhs: NoctwebRelaySuffixV1) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var isStructurallyValid: Bool {
        Self.isCanonical(rawValue)
    }

    private static func isCanonical(_ value: String) -> Bool {
        guard value == value.lowercased(),
              value.hasPrefix("."),
              value.utf8.count >= 3,
              value.utf8.count <= 64 else {
            return false
        }
        let label = value.dropFirst()
        guard label.first != "-", label.last != "-" else {
            return false
        }
        return label.allSatisfy {
            $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-")
        }
    }
}

public struct RelayIdentityClaimV1: Codable, Equatable {
    public let version: Int
    public let relayID: RelayIdentityIDV1
    public let signingPublicKey: Data
    public let sequence: Int
    public let relayKind: RelayKind
    public let federationMode: FederationMode
    public let federationName: String?
    public let advertisedEndpoints: [RelayEndpoint]
    public let noctwebSuffix: NoctwebRelaySuffixV1?
    public let hostSigningPublicKey: Data?
    public let capabilityDigest: Data
    public let issuedAt: Date
    public let expiresAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case relayID
        case signingPublicKey
        case sequence
        case relayKind
        case federationMode
        case federationName
        case advertisedEndpoints
        case noctwebSuffix
        case hostSigningPublicKey
        case capabilityDigest
        case issuedAt
        case expiresAt
    }

    public init(
        relayID: RelayIdentityIDV1,
        signingPublicKey: Data,
        sequence: Int,
        relayKind: RelayKind,
        federationMode: FederationMode,
        federationName: String?,
        advertisedEndpoints: [RelayEndpoint],
        noctwebSuffix: NoctwebRelaySuffixV1?,
        hostSigningPublicKey: Data? = nil,
        capabilityDigest: Data,
        issuedAt: Date,
        expiresAt: Date
    ) {
        version = RelayIdentityV1.version
        self.relayID = relayID
        self.signingPublicKey = signingPublicKey
        self.sequence = sequence
        self.relayKind = relayKind
        self.federationMode = federationMode
        self.federationName = federationName
        self.advertisedEndpoints = Self.canonicalEndpoints(advertisedEndpoints)
        self.noctwebSuffix = noctwebSuffix
        self.hostSigningPublicKey = hostSigningPublicKey
        self.capabilityDigest = capabilityDigest
        self.issuedAt = Self.canonicalDate(issuedAt)
        self.expiresAt = Self.canonicalDate(expiresAt)
    }

    public init(from decoder: Decoder) throws {
        try relayIdentityRequireExactFields(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            relayID: try values.decode(RelayIdentityIDV1.self, forKey: .relayID),
            signingPublicKey: try values.decode(Data.self, forKey: .signingPublicKey),
            sequence: try values.decode(Int.self, forKey: .sequence),
            relayKind: try values.decode(RelayKind.self, forKey: .relayKind),
            federationMode: try values.decode(FederationMode.self, forKey: .federationMode),
            federationName: try values.decodeIfPresent(String.self, forKey: .federationName),
            advertisedEndpoints: try values.decode([RelayEndpoint].self, forKey: .advertisedEndpoints),
            noctwebSuffix: try values.decodeIfPresent(NoctwebRelaySuffixV1.self, forKey: .noctwebSuffix),
            hostSigningPublicKey: try values.decodeIfPresent(Data.self, forKey: .hostSigningPublicKey),
            capabilityDigest: try values.decode(Data.self, forKey: .capabilityDigest),
            issuedAt: try values.decode(Date.self, forKey: .issuedAt),
            expiresAt: try values.decode(Date.self, forKey: .expiresAt)
        )
        guard try isStructurallyValidThrowing,
              try values.decode(Int.self, forKey: .version) == RelayIdentityV1.version else {
            throw relayIdentityDecodingError(decoder, "Relay identity claim is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw relayIdentityEncodingError(encoder, "Relay identity claim is invalid")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(relayID, forKey: .relayID)
        try values.encode(signingPublicKey, forKey: .signingPublicKey)
        try values.encode(sequence, forKey: .sequence)
        try values.encode(relayKind, forKey: .relayKind)
        try values.encode(federationMode, forKey: .federationMode)
        try values.encode(federationName, forKey: .federationName)
        try values.encode(advertisedEndpoints, forKey: .advertisedEndpoints)
        try values.encode(noctwebSuffix, forKey: .noctwebSuffix)
        try values.encode(hostSigningPublicKey, forKey: .hostSigningPublicKey)
        try values.encode(capabilityDigest, forKey: .capabilityDigest)
        try values.encode(issuedAt, forKey: .issuedAt)
        try values.encode(expiresAt, forKey: .expiresAt)
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard version == RelayIdentityV1.version,
                  relayID == RelayIdentityIDV1.derived(from: signingPublicKey),
                  try SigningKeyPair.isValidPublicKeyThrowing(signingPublicKey),
                  (0...RelayIdentityV1.maximumSequence).contains(sequence),
                  [.standard, .passthrough, .host, .coordinator].contains(relayKind),
                  federationName.map(Self.isCanonicalFederationName) ?? true,
                  !advertisedEndpoints.isEmpty,
                  advertisedEndpoints.count <= RelayIdentityV1.maximumEndpoints,
                  advertisedEndpoints == Self.canonicalEndpoints(advertisedEndpoints),
                  Set(advertisedEndpoints.map(Self.endpointKey)).count == advertisedEndpoints.count,
                  advertisedEndpoints.allSatisfy(\.isStructurallyValid),
                  noctwebSuffix?.isStructurallyValid != false,
                  hostSigningPublicKey?.count == 32 || hostSigningPublicKey == nil,
                  capabilityDigest.count == RelayIdentityV1.capabilityDigestBytes,
                  Self.isCanonicalDate(issuedAt),
                  Self.isCanonicalDate(expiresAt),
                  expiresAt > issuedAt,
                  expiresAt.timeIntervalSince(issuedAt) <= RelayIdentityV1.maximumClaimLifetime else {
                return false
            }
            return true
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    public func transcript() throws -> Data {
        guard try isStructurallyValidThrowing else {
            throw CryptoError.invalidPayload
        }
        var transcript = Data("Noctweave/RelayIdentityClaim/v1\u{0}".utf8)
        transcript.append(try NoctweaveCanonicalJSON.encode(self))
        return transcript
    }

    public static func capabilityDigest(
        for manifest: RelayCapabilityManifestV2
    ) throws -> Data {
        Data(SHA256.hash(data: try NoctweaveCanonicalJSON.encode(manifest)))
    }

    private static func canonicalDate(_ date: Date) -> Date {
        Date(timeIntervalSince1970: floor(date.timeIntervalSince1970))
    }

    private static func isCanonicalDate(_ date: Date) -> Bool {
        let value = date.timeIntervalSince1970
        return value.isFinite
            && value >= 0
            && value <= 4_102_444_800
            && floor(value) == value
    }

    private static func isCanonicalFederationName(_ value: String) -> Bool {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return !normalized.isEmpty
            && normalized == value
            && value.utf8.count <= 1_024
            && !value.unicodeScalars.contains {
                CharacterSet.controlCharacters.contains($0)
            }
    }

    private static func canonicalEndpoints(_ endpoints: [RelayEndpoint]) -> [RelayEndpoint] {
        endpoints.sorted { endpointKey($0) < endpointKey($1) }
    }

    private static func endpointKey(_ endpoint: RelayEndpoint) -> String {
        [
            endpoint.transport.rawValue,
            endpoint.host.lowercased(),
            String(endpoint.port),
            endpoint.useTLS ? "1" : "0",
            endpoint.tlsCertificateFingerprintSHA256?.base64EncodedString() ?? "",
            endpoint.directorySigningPublicKey?.base64EncodedString() ?? ""
        ].joined(separator: "\u{0}")
    }
}

public struct SignedRelayIdentityClaimV1: Codable, Equatable {
    public let claim: RelayIdentityClaimV1
    public let signatureAlgorithm: String
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case claim
        case signatureAlgorithm
        case signature
    }

    public init(
        claim: RelayIdentityClaimV1,
        signatureAlgorithm: String = RelayIdentityV1.signatureAlgorithm,
        signature: Data
    ) {
        self.claim = claim
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }

    public static func signed(
        claim: RelayIdentityClaimV1,
        by keyMaterial: RelayIdentityKeyMaterialV1
    ) throws -> SignedRelayIdentityClaimV1 {
        guard claim.relayID == keyMaterial.relayID,
              claim.signingPublicKey == keyMaterial.signingPublicKey else {
            throw CryptoError.invalidPrivateKey
        }
        return SignedRelayIdentityClaimV1(
            claim: claim,
            signature: try keyMaterial.signingKeyPair.sign(claim.transcript())
        )
    }

    public func verifyThrowing(
        at now: Date? = nil,
        maximumClockSkew: TimeInterval = RelayIdentityV1.maximumClockSkew
    ) throws -> Bool {
        guard signatureAlgorithm == RelayIdentityV1.signatureAlgorithm,
              try claim.isStructurallyValidThrowing,
              maximumClockSkew.isFinite,
              maximumClockSkew >= 0,
              try SigningKeyPair.verifyThrowing(
                  signature: signature,
                  data: claim.transcript(),
                  publicKeyData: claim.signingPublicKey
              ) else {
            return false
        }
        guard let now else {
            return true
        }
        return claim.issuedAt <= now.addingTimeInterval(maximumClockSkew)
            && claim.expiresAt >= now.addingTimeInterval(-maximumClockSkew)
    }

    public var isStructurallyValid: Bool {
        (try? verifyThrowing()) == true
    }

    public init(from decoder: Decoder) throws {
        try relayIdentityRequireExactFields(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            claim: try values.decode(RelayIdentityClaimV1.self, forKey: .claim),
            signatureAlgorithm: try values.decode(String.self, forKey: .signatureAlgorithm),
            signature: try values.decode(Data.self, forKey: .signature)
        )
        guard try verifyThrowing() else {
            throw relayIdentityDecodingError(decoder, "Signed relay identity claim is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try verifyThrowing() else {
            throw relayIdentityEncodingError(encoder, "Signed relay identity claim is invalid")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(claim, forKey: .claim)
        try values.encode(signatureAlgorithm, forKey: .signatureAlgorithm)
        try values.encode(signature, forKey: .signature)
    }
}

public struct RelayIdentityKeyMaterialV1: Codable {
    public let signingPrivateKey: Data
    public let signingPublicKey: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case signingPrivateKey
        case signingPublicKey
    }

    public static func generate() throws -> RelayIdentityKeyMaterialV1 {
        let pair = try SigningKeyPair.generate()
        return try RelayIdentityKeyMaterialV1(
            signingPrivateKey: pair.privateKeyData,
            signingPublicKey: pair.publicKeyData
        )
    }

    public init(signingPrivateKey: Data, signingPublicKey: Data) throws {
        _ = try SigningKeyPair(
            privateKeyData: signingPrivateKey,
            publicKeyData: signingPublicKey
        )
        self.signingPrivateKey = signingPrivateKey
        self.signingPublicKey = signingPublicKey
    }

    public var relayID: RelayIdentityIDV1 {
        RelayIdentityIDV1.derived(from: signingPublicKey)
    }

    public var signingKeyPair: SigningKeyPair {
        get throws {
            try SigningKeyPair(
                privateKeyData: signingPrivateKey,
                publicKeyData: signingPublicKey
            )
        }
    }

    public func makeSignedClaim(
        sequence: Int,
        relayKind: RelayKind,
        federation: FederationDescriptor,
        advertisedEndpoints: [RelayEndpoint],
        noctwebSuffix: NoctwebRelaySuffixV1?,
        hostSigningPublicKey: Data? = nil,
        capabilities: RelayCapabilityManifestV2,
        issuedAt: Date = Date(),
        lifetime: TimeInterval = 24 * 60 * 60
    ) throws -> SignedRelayIdentityClaimV1 {
        guard lifetime.isFinite,
              lifetime > 0,
              lifetime <= RelayIdentityV1.maximumClaimLifetime else {
            throw CryptoError.invalidPayload
        }
        let claim = RelayIdentityClaimV1(
            relayID: relayID,
            signingPublicKey: signingPublicKey,
            sequence: sequence,
            relayKind: relayKind,
            federationMode: federation.mode,
            federationName: federation.name,
            advertisedEndpoints: advertisedEndpoints,
            noctwebSuffix: noctwebSuffix,
            hostSigningPublicKey: hostSigningPublicKey,
            capabilityDigest: try RelayIdentityClaimV1.capabilityDigest(for: capabilities),
            issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(lifetime)
        )
        return try SignedRelayIdentityClaimV1.signed(claim: claim, by: self)
    }

    public init(from decoder: Decoder) throws {
        try relayIdentityRequireExactFields(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            signingPrivateKey: try values.decode(Data.self, forKey: .signingPrivateKey),
            signingPublicKey: try values.decode(Data.self, forKey: .signingPublicKey)
        )
    }

    public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(signingPrivateKey, forKey: .signingPrivateKey)
        try values.encode(signingPublicKey, forKey: .signingPublicKey)
    }
}

public struct RelayIdentityRotationV1: Codable, Equatable {
    public let version: Int
    public let oldRelayID: RelayIdentityIDV1
    public let newRelayID: RelayIdentityIDV1
    public let oldSigningPublicKey: Data
    public let newSigningPublicKey: Data
    public let sequence: Int
    public let issuedAt: Date
    public let oldKeySignature: Data
    public let newKeySignature: Data

    private struct Unsigned: Codable {
        let version: Int
        let oldRelayID: RelayIdentityIDV1
        let newRelayID: RelayIdentityIDV1
        let oldSigningPublicKey: Data
        let newSigningPublicKey: Data
        let sequence: Int
        let issuedAt: Date
    }

    public static func signed(
        from oldKey: RelayIdentityKeyMaterialV1,
        to newKey: RelayIdentityKeyMaterialV1,
        sequence: Int,
        issuedAt: Date = Date()
    ) throws -> RelayIdentityRotationV1 {
        let canonicalIssuedAt = Date(
            timeIntervalSince1970: floor(issuedAt.timeIntervalSince1970)
        )
        let unsigned = Unsigned(
            version: RelayIdentityV1.version,
            oldRelayID: oldKey.relayID,
            newRelayID: newKey.relayID,
            oldSigningPublicKey: oldKey.signingPublicKey,
            newSigningPublicKey: newKey.signingPublicKey,
            sequence: sequence,
            issuedAt: canonicalIssuedAt
        )
        let transcript = try Self.transcript(unsigned)
        return RelayIdentityRotationV1(
            version: RelayIdentityV1.version,
            oldRelayID: oldKey.relayID,
            newRelayID: newKey.relayID,
            oldSigningPublicKey: oldKey.signingPublicKey,
            newSigningPublicKey: newKey.signingPublicKey,
            sequence: sequence,
            issuedAt: canonicalIssuedAt,
            oldKeySignature: try oldKey.signingKeyPair.sign(transcript),
            newKeySignature: try newKey.signingKeyPair.sign(transcript)
        )
    }

    public func verifyThrowing() throws -> Bool {
        guard version == RelayIdentityV1.version,
              oldRelayID != newRelayID,
              oldRelayID == RelayIdentityIDV1.derived(from: oldSigningPublicKey),
              newRelayID == RelayIdentityIDV1.derived(from: newSigningPublicKey),
              (1...RelayIdentityV1.maximumSequence).contains(sequence),
              issuedAt.timeIntervalSince1970.isFinite,
              floor(issuedAt.timeIntervalSince1970) == issuedAt.timeIntervalSince1970 else {
            return false
        }
        let transcript = try Self.transcript(Unsigned(
            version: version,
            oldRelayID: oldRelayID,
            newRelayID: newRelayID,
            oldSigningPublicKey: oldSigningPublicKey,
            newSigningPublicKey: newSigningPublicKey,
            sequence: sequence,
            issuedAt: issuedAt
        ))
        return try SigningKeyPair.verifyThrowing(
            signature: oldKeySignature,
            data: transcript,
            publicKeyData: oldSigningPublicKey
        ) && SigningKeyPair.verifyThrowing(
            signature: newKeySignature,
            data: transcript,
            publicKeyData: newSigningPublicKey
        )
    }

    public var isStructurallyValid: Bool {
        (try? verifyThrowing()) == true
    }

    private static func transcript(_ unsigned: Unsigned) throws -> Data {
        var data = Data("Noctweave/RelayIdentityRotation/v1\u{0}".utf8)
        data.append(try NoctweaveCanonicalJSON.encode(unsigned))
        return data
    }
}

private func relayIdentityRequireExactFields<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ keyType: Key.Type
) throws where Key.AllCases: Collection, Key.AllCases.Element == Key {
    let expected = Set(Key.allCases.map(\.stringValue))
    let values = try decoder.container(keyedBy: RelayIdentityDynamicCodingKey.self)
    guard Set(values.allKeys.map(\.stringValue)) == expected else {
        throw relayIdentityDecodingError(
            decoder,
            "Relay identity fields must match the current protocol exactly"
        )
    }
}

private struct RelayIdentityDynamicCodingKey: CodingKey {
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

private func relayIdentityDecodingError(
    _ decoder: Decoder,
    _ message: String
) -> DecodingError {
    DecodingError.dataCorrupted(
        .init(codingPath: decoder.codingPath, debugDescription: message)
    )
}

private func relayIdentityEncodingError(
    _ encoder: Encoder,
    _ message: String
) -> EncodingError {
    EncodingError.invalidValue(
        message,
        .init(codingPath: encoder.codingPath, debugDescription: message)
    )
}
