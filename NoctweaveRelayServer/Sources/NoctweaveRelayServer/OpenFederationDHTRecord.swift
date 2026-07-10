import Foundation
import Crypto

enum OpenFederationDHTRecordError: Error, Equatable {
    case namespaceMismatch
    case relayIdentityMismatch
    case expired
    case notYetValid
    case invalidLifetime
    case invalidSignature
    case insecureEndpoint
    case nonPublicEndpoint
    case unsupportedVersion
    case federationNameMismatch
    case invalidStructure
}

struct OpenFederationDHTRecord: Codable, Equatable {
    static let version = 1
    static let signatureAlgorithm = "ML-DSA-65"
    static let namespacePrefix = "noctweave-open-v1"
    static let maxLifetimeSeconds: TimeInterval = 600
    static let maxClockSkewSeconds: TimeInterval = 120

    let version: Int
    let namespace: String
    let relayIdentityDigest: String
    let endpoint: RelayEndpoint
    let federationName: String?
    let issuedAt: Date
    let expiresAt: Date
    let relaySigningPublicKey: Data
    let signatureAlgorithm: String
    let signature: Data

    init(
        version: Int = OpenFederationDHTRecord.version,
        namespace: String,
        relayIdentityDigest: String,
        endpoint: RelayEndpoint,
        federationName: String?,
        issuedAt: Date,
        expiresAt: Date,
        relaySigningPublicKey: Data,
        signatureAlgorithm: String = OpenFederationDHTRecord.signatureAlgorithm,
        signature: Data
    ) {
        self.version = version
        self.namespace = namespace
        self.relayIdentityDigest = relayIdentityDigest
        self.endpoint = endpoint
        self.federationName = federationName
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.relaySigningPublicKey = relaySigningPublicKey
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }

    static func namespace(federationName: String?) -> String {
        let normalized = normalizedFederationName(federationName)
        let digest = SHA256.hash(data: Data(normalized.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
        return "\(namespacePrefix):\(digest)"
    }

    static func relayIdentityDigest(publicKey: Data) -> String {
        SHA256.hash(data: publicKey)
            .map { String(format: "%02x", $0) }
            .joined()
    }

    static func signed(
        endpoint: RelayEndpoint,
        federationName: String?,
        privateKey: Data,
        publicKey: Data,
        issuedAt: Date = Date(),
        lifetimeSeconds: TimeInterval = maxLifetimeSeconds
    ) throws -> OpenFederationDHTRecord {
        guard lifetimeSeconds.isFinite,
              issuedAt.timeIntervalSince1970.isFinite,
              isStructurallyValidEndpoint(endpoint),
              normalizedFederationName(federationName).utf8.count <= 128 else {
            throw OpenFederationDHTRecordError.invalidStructure
        }
        let boundedLifetime = max(60, min(lifetimeSeconds, maxLifetimeSeconds))
        let unsigned = OpenFederationDHTRecord(
            namespace: namespace(federationName: federationName),
            relayIdentityDigest: relayIdentityDigest(publicKey: publicKey),
            endpoint: endpoint,
            federationName: normalizedFederationName(federationName),
            issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(boundedLifetime),
            relaySigningPublicKey: publicKey,
            signature: Data()
        )
        guard let signature = OQSSignatureVerifier.shared.sign(
            data: try unsigned.signingPayloadData(),
            privateKey: privateKey,
            publicKey: publicKey
        ) else {
            throw OpenFederationDHTRecordError.invalidSignature
        }
        return OpenFederationDHTRecord(
            namespace: unsigned.namespace,
            relayIdentityDigest: unsigned.relayIdentityDigest,
            endpoint: unsigned.endpoint,
            federationName: unsigned.federationName,
            issuedAt: unsigned.issuedAt,
            expiresAt: unsigned.expiresAt,
            relaySigningPublicKey: unsigned.relaySigningPublicKey,
            signature: signature
        )
    }

    func validate(
        expectedFederationName: String?,
        now: Date = Date(),
        requirePublicEndpoint: Bool = true
    ) throws {
        guard version == Self.version else {
            throw OpenFederationDHTRecordError.unsupportedVersion
        }
        guard Self.isStructurallyValidEndpoint(endpoint),
              namespace.utf8.count <= 128,
              relayIdentityDigest.utf8.count == 64,
              relaySigningPublicKey.count == OQSSignatureVerifier.mlDSA65PublicKeyBytes,
              signature.count == OQSSignatureVerifier.mlDSA65SignatureBytes,
              issuedAt.timeIntervalSince1970.isFinite,
              expiresAt.timeIntervalSince1970.isFinite else {
            throw OpenFederationDHTRecordError.invalidStructure
        }
        guard namespace == Self.namespace(federationName: expectedFederationName) else {
            throw OpenFederationDHTRecordError.namespaceMismatch
        }
        guard federationName == Self.normalizedFederationName(expectedFederationName) else {
            throw OpenFederationDHTRecordError.federationNameMismatch
        }
        guard relayIdentityDigest == Self.relayIdentityDigest(publicKey: relaySigningPublicKey) else {
            throw OpenFederationDHTRecordError.relayIdentityMismatch
        }
        guard issuedAt <= now.addingTimeInterval(Self.maxClockSkewSeconds) else {
            throw OpenFederationDHTRecordError.notYetValid
        }
        guard expiresAt > now else {
            throw OpenFederationDHTRecordError.expired
        }
        guard expiresAt.timeIntervalSince(issuedAt) <= Self.maxLifetimeSeconds else {
            throw OpenFederationDHTRecordError.invalidLifetime
        }
        guard signatureAlgorithm == Self.signatureAlgorithm,
              OQSSignatureVerifier.shared.verify(
                signature: signature,
                data: try signingPayloadData(),
                publicKey: relaySigningPublicKey
              ) else {
            throw OpenFederationDHTRecordError.invalidSignature
        }
        guard endpoint.useTLS,
              endpoint.transport == .http || endpoint.transport == .websocket else {
            throw OpenFederationDHTRecordError.insecureEndpoint
        }
        if requirePublicEndpoint, !PublicRelayEndpointPolicy.permits(endpoint) {
            throw OpenFederationDHTRecordError.nonPublicEndpoint
        }
    }

    private struct SigningPayload: Codable {
        let version: Int
        let namespace: String
        let relayIdentityDigest: String
        let endpoint: RelayEndpoint
        let federationName: String?
        let issuedAt: Date
        let expiresAt: Date
        let relaySigningPublicKey: Data
        let signatureAlgorithm: String
    }

    private func signingPayloadData() throws -> Data {
        try RelayCodec.encoder(sortedKeys: true).encode(
            SigningPayload(
                version: version,
                namespace: namespace,
                relayIdentityDigest: relayIdentityDigest,
                endpoint: endpoint,
                federationName: federationName,
                issuedAt: issuedAt,
                expiresAt: expiresAt,
                relaySigningPublicKey: relaySigningPublicKey,
                signatureAlgorithm: signatureAlgorithm
            )
        )
    }

    private static func normalizedFederationName(_ value: String?) -> String {
        value?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            ?? ""
    }

    private static func isStructurallyValidEndpoint(_ endpoint: RelayEndpoint) -> Bool {
        let host = endpoint.host
        return !host.isEmpty
            && host == host.trimmingCharacters(in: .whitespacesAndNewlines)
            && host.utf8.count <= 253
            && host.rangeOfCharacter(from: .whitespacesAndNewlines) == nil
            && host.rangeOfCharacter(from: CharacterSet(charactersIn: "/?#@")) == nil
    }
}
