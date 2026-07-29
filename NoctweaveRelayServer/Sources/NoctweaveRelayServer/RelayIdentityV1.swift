import Crypto
import Foundation

enum RelayIdentityV1 {
    static let version = 1
    static let relayIDPrefix = "nwr1"
    static let relayIDDigestBytes = 32
    static let capabilityDigestBytes = 32
    static let maximumEndpoints = 16
    static let maximumClaimLifetime: TimeInterval = 7 * 24 * 60 * 60
    static let maximumClockSkew: TimeInterval = 5 * 60
    static let maximumSequence = 9_007_199_254_740_991
    static let signatureAlgorithm = "ML-DSA-65"
}

enum RelayIdentityError: Error, Equatable {
    case invalidKeyMaterial
    case invalidPayload
}

struct RelayIdentityIDV1: RawRepresentable, Codable, Equatable, Hashable, Comparable {
    let rawValue: String

    init?(rawValue: String) {
        guard Self.isCanonical(rawValue) else { return nil }
        self.rawValue = rawValue
    }

    static func derived(from signingPublicKey: Data) -> RelayIdentityIDV1 {
        let digest = Data(SHA256.hash(data: signingPublicKey))
        let value = RelayIdentityV1.relayIDPrefix + digest.map {
            String(format: "%02x", $0)
        }.joined()
        return RelayIdentityIDV1(rawValue: value)!
    }

    static func < (lhs: RelayIdentityIDV1, rhs: RelayIdentityIDV1) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var isStructurallyValid: Bool { Self.isCanonical(rawValue) }

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

struct NoctwebRelaySuffixV1: RawRepresentable, Codable, Equatable, Hashable, Comparable {
    let rawValue: String

    init?(rawValue: String) {
        guard Self.isCanonical(rawValue) else { return nil }
        self.rawValue = rawValue
    }

    static func < (lhs: NoctwebRelaySuffixV1, rhs: NoctwebRelaySuffixV1) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var isStructurallyValid: Bool { Self.isCanonical(rawValue) }

    private static func isCanonical(_ value: String) -> Bool {
        guard value == value.lowercased(),
              value.hasPrefix("."),
              value.utf8.count >= 3,
              value.utf8.count <= 64 else {
            return false
        }
        let label = value.dropFirst()
        guard label.first != "-", label.last != "-" else { return false }
        return label.allSatisfy {
            $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-")
        }
    }
}

struct RelayIdentityClaimV1: Codable, Equatable {
    let version: Int
    let relayID: RelayIdentityIDV1
    let signingPublicKey: Data
    let sequence: Int
    let relayKind: RelayKind
    let federationMode: FederationMode
    let federationName: String?
    let advertisedEndpoints: [RelayEndpoint]
    let noctwebSuffix: NoctwebRelaySuffixV1?
    let hostSigningPublicKey: Data?
    let capabilityDigest: Data
    let issuedAt: Date
    let expiresAt: Date

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

    init(
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

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Relay identity claim")
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
        guard try values.decode(Int.self, forKey: .version) == RelayIdentityV1.version,
              isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: values,
                debugDescription: "Relay identity claim is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Relay identity claim")
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

    var isStructurallyValid: Bool {
        version == RelayIdentityV1.version
            && relayID == RelayIdentityIDV1.derived(from: signingPublicKey)
            && signingPublicKey.count == OQSSignatureVerifier.mlDSA65PublicKeyBytes
            && (0...RelayIdentityV1.maximumSequence).contains(sequence)
            && [.standard, .passthrough, .host, .coordinator].contains(relayKind)
            && (federationName.map(Self.isCanonicalFederationName) ?? true)
            && !advertisedEndpoints.isEmpty
            && advertisedEndpoints.count <= RelayIdentityV1.maximumEndpoints
            && advertisedEndpoints == Self.canonicalEndpoints(advertisedEndpoints)
            && Set(advertisedEndpoints.map(Self.endpointKey)).count
                == advertisedEndpoints.count
            && advertisedEndpoints.allSatisfy(\.isStructurallyValid)
            && noctwebSuffix?.isStructurallyValid != false
            && (hostSigningPublicKey == nil || hostSigningPublicKey?.count == 32)
            && capabilityDigest.count == RelayIdentityV1.capabilityDigestBytes
            && Self.isCanonicalDate(issuedAt)
            && Self.isCanonicalDate(expiresAt)
            && expiresAt > issuedAt
            && expiresAt.timeIntervalSince(issuedAt)
                <= RelayIdentityV1.maximumClaimLifetime
    }

    func transcript() throws -> Data {
        guard isStructurallyValid else { throw RelayIdentityError.invalidPayload }
        var result = Data("Noctweave/RelayIdentityClaim/v1\u{0}".utf8)
        result.append(try RelayCanonicalJSON.encode(self))
        return result
    }

    static func capabilityDigest(for manifest: RelayCapabilityManifestV2) throws -> Data {
        Data(SHA256.hash(data: try RelayCanonicalJSON.encode(manifest)))
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

struct SignedRelayIdentityClaimV1: Codable, Equatable {
    let claim: RelayIdentityClaimV1
    let signatureAlgorithm: String
    let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case claim
        case signatureAlgorithm
        case signature
    }

    init(
        claim: RelayIdentityClaimV1,
        signatureAlgorithm: String = RelayIdentityV1.signatureAlgorithm,
        signature: Data
    ) {
        self.claim = claim
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }

    static func signed(
        claim: RelayIdentityClaimV1,
        by keyMaterial: RelayIdentityKeyMaterialV1
    ) throws -> SignedRelayIdentityClaimV1 {
        guard claim.relayID == keyMaterial.relayID,
              claim.signingPublicKey == keyMaterial.signingPublicKey else {
            throw RelayIdentityError.invalidKeyMaterial
        }
        return SignedRelayIdentityClaimV1(
            claim: claim,
            signature: try OQSSignatureVerifier.shared.signThrowing(
                data: claim.transcript(),
                privateKey: keyMaterial.signingPrivateKey,
                publicKey: keyMaterial.signingPublicKey
            )
        )
    }

    func verifyThrowing(
        at now: Date? = nil,
        maximumClockSkew: TimeInterval = RelayIdentityV1.maximumClockSkew
    ) throws -> Bool {
        guard signatureAlgorithm == RelayIdentityV1.signatureAlgorithm,
              claim.isStructurallyValid,
              maximumClockSkew.isFinite,
              maximumClockSkew >= 0,
              try OQSSignatureVerifier.shared.verifyThrowing(
                  signature: signature,
                  data: claim.transcript(),
                  publicKey: claim.signingPublicKey
              ) else {
            return false
        }
        guard let now else { return true }
        return claim.issuedAt <= now.addingTimeInterval(maximumClockSkew)
            && claim.expiresAt >= now.addingTimeInterval(-maximumClockSkew)
    }

    var isStructurallyValid: Bool {
        (try? verifyThrowing()) == true
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Signed relay identity")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            claim: try values.decode(RelayIdentityClaimV1.self, forKey: .claim),
            signatureAlgorithm: try values.decode(String.self, forKey: .signatureAlgorithm),
            signature: try values.decode(Data.self, forKey: .signature)
        )
        guard try verifyThrowing() else {
            throw DecodingError.dataCorruptedError(
                forKey: .signature,
                in: values,
                debugDescription: "Signed relay identity is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard try verifyThrowing() else {
            throw invalidModelEncoding(self, encoder, context: "Signed relay identity")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(claim, forKey: .claim)
        try values.encode(signatureAlgorithm, forKey: .signatureAlgorithm)
        try values.encode(signature, forKey: .signature)
    }
}

struct RelayIdentityKeyMaterialV1: Codable, Equatable {
    let signingPrivateKey: Data
    let signingPublicKey: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case signingPrivateKey
        case signingPublicKey
    }

    static func generate() throws -> RelayIdentityKeyMaterialV1 {
        let pair = try OQSSignatureVerifier.shared.generateKeyPairThrowing()
        return try RelayIdentityKeyMaterialV1(
            signingPrivateKey: pair.privateKey,
            signingPublicKey: pair.publicKey
        )
    }

    init(signingPrivateKey: Data, signingPublicKey: Data) throws {
        guard signingPrivateKey.count == OQSSignatureVerifier.mlDSA65PrivateKeyBytes,
              signingPublicKey.count == OQSSignatureVerifier.mlDSA65PublicKeyBytes else {
            throw RelayIdentityError.invalidKeyMaterial
        }
        self.signingPrivateKey = signingPrivateKey
        self.signingPublicKey = signingPublicKey
    }

    var relayID: RelayIdentityIDV1 {
        RelayIdentityIDV1.derived(from: signingPublicKey)
    }

    func makeSignedClaim(
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
            throw RelayIdentityError.invalidPayload
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

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Relay identity key material")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            signingPrivateKey: try values.decode(Data.self, forKey: .signingPrivateKey),
            signingPublicKey: try values.decode(Data.self, forKey: .signingPublicKey)
        )
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(signingPrivateKey, forKey: .signingPrivateKey)
        try values.encode(signingPublicKey, forKey: .signingPublicKey)
    }
}

struct RelayIdentityRotationV1: Codable, Equatable {
    let version: Int
    let oldRelayID: RelayIdentityIDV1
    let newRelayID: RelayIdentityIDV1
    let oldSigningPublicKey: Data
    let newSigningPublicKey: Data
    let sequence: Int
    let issuedAt: Date
    let oldKeySignature: Data
    let newKeySignature: Data

    private struct Unsigned: Codable {
        let version: Int
        let oldRelayID: RelayIdentityIDV1
        let newRelayID: RelayIdentityIDV1
        let oldSigningPublicKey: Data
        let newSigningPublicKey: Data
        let sequence: Int
        let issuedAt: Date
    }

    static func signed(
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
            oldKeySignature: try OQSSignatureVerifier.shared.signThrowing(
                data: transcript,
                privateKey: oldKey.signingPrivateKey,
                publicKey: oldKey.signingPublicKey
            ),
            newKeySignature: try OQSSignatureVerifier.shared.signThrowing(
                data: transcript,
                privateKey: newKey.signingPrivateKey,
                publicKey: newKey.signingPublicKey
            )
        )
    }

    func verifyThrowing() throws -> Bool {
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
        return try OQSSignatureVerifier.shared.verifyThrowing(
            signature: oldKeySignature,
            data: transcript,
            publicKey: oldSigningPublicKey
        ) && OQSSignatureVerifier.shared.verifyThrowing(
            signature: newKeySignature,
            data: transcript,
            publicKey: newSigningPublicKey
        )
    }

    var isStructurallyValid: Bool {
        (try? verifyThrowing()) == true
    }

    private static func transcript(_ unsigned: Unsigned) throws -> Data {
        var data = Data("Noctweave/RelayIdentityRotation/v1\u{0}".utf8)
        data.append(try RelayCanonicalJSON.encode(unsigned))
        return data
    }
}

final class RelayIdentityRuntime: @unchecked Sendable {
    private struct CacheDescriptor: Codable {
        let relayKind: RelayKind
        let federation: FederationDescriptor
        let advertisedEndpoints: [RelayEndpoint]
        let noctwebSuffix: NoctwebRelaySuffixV1?
        let hostSigningPublicKey: Data?
        let capabilityDigest: Data
    }

    let keyMaterial: RelayIdentityKeyMaterialV1
    private let lock = NSLock()
    private var sequence = 0
    private var cachedDescriptor: Data?
    private var cachedIdentity: SignedRelayIdentityClaimV1?

    init(keyMaterial: RelayIdentityKeyMaterialV1) {
        self.keyMaterial = keyMaterial
    }

    var relayID: RelayIdentityIDV1 { keyMaterial.relayID }

    func signedIdentity(
        configuration: RelayConfiguration,
        advertisedEndpoints: [RelayEndpoint],
        hostSigningPublicKey: Data?,
        at date: Date = Date()
    ) throws -> SignedRelayIdentityClaimV1 {
        guard let capabilities = configuration.makeInfo(now: date).protocolCapabilities else {
            throw RelayIdentityError.invalidPayload
        }
        let descriptor = try RelayCanonicalJSON.encode(
            CacheDescriptor(
                relayKind: configuration.kind,
                federation: configuration.federation,
                advertisedEndpoints: advertisedEndpoints,
                noctwebSuffix: configuration.noctwebRelaySuffix,
                hostSigningPublicKey: hostSigningPublicKey,
                capabilityDigest:
                    RelayIdentityClaimV1.capabilityDigest(
                        for: capabilities
                    )
            )
        )
        lock.lock()
        defer { lock.unlock() }
        if cachedDescriptor == descriptor,
           let cachedIdentity,
           cachedIdentity.claim.expiresAt
            > date.addingTimeInterval(
                RelayIdentityV1.maximumClockSkew
            ) {
            return cachedIdentity
        }
        let wallClock = max(0, Int(floor(date.timeIntervalSince1970)))
        sequence = max(
            wallClock,
            min(sequence + 1, RelayIdentityV1.maximumSequence)
        )
        let identity = try keyMaterial.makeSignedClaim(
            sequence: sequence,
            relayKind: configuration.kind,
            federation: configuration.federation,
            advertisedEndpoints: advertisedEndpoints,
            noctwebSuffix: configuration.noctwebRelaySuffix,
            hostSigningPublicKey: hostSigningPublicKey,
            capabilities: capabilities,
            issuedAt: date
        )
        cachedDescriptor = descriptor
        cachedIdentity = identity
        return identity
    }

    func authenticatedInfo(
        _ info: RelayInfo,
        configuration: RelayConfiguration,
        advertisedEndpoints: [RelayEndpoint],
        hostSigningPublicKey: Data?
    ) throws -> RelayInfo {
        let identity = try signedIdentity(
            configuration: configuration,
            advertisedEndpoints: advertisedEndpoints,
            hostSigningPublicKey: hostSigningPublicKey,
            at: info.advertisedAt
        )
        return try info.authenticated(
            by: keyMaterial,
            sequence: identity.claim.sequence,
            advertisedEndpoints: advertisedEndpoints,
            noctwebSuffix: configuration.noctwebRelaySuffix,
            hostSigningPublicKey: hostSigningPublicKey,
            precomputedIdentity: identity
        )
    }
}
