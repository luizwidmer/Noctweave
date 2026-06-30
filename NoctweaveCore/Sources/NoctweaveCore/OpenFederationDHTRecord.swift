import CryptoKit
import Foundation

public enum OpenFederationDHTRecordError: Error, Equatable {
    case wrongMode
    case namespaceMismatch
    case relayIdentityMismatch
    case expired
    case notYetValid
    case invalidLifetime
    case invalidSignature
    case insecureEndpoint
    case nonPublicEndpoint
}

public struct OpenFederationDHTRecord: Codable, Equatable {
    public static let version = 1
    public static let signatureAlgorithm = "ML-DSA-65"
    public static let namespacePrefix = "noctyra-open-v1"
    public static let maxLifetimeSeconds: TimeInterval = 600
    public static let maxClockSkewSeconds: TimeInterval = 120

    public let version: Int
    public let namespace: String
    public let relayIdentityDigest: String
    public let endpoint: RelayEndpoint
    public let federationName: String?
    public let issuedAt: Date
    public let expiresAt: Date
    public let relaySigningPublicKey: Data
    public let signatureAlgorithm: String
    public let signature: Data

    public init(
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

    public static func namespace(federationName: String?) -> String {
        let normalized = normalizedFederationName(federationName)
        let digest = SHA256.hash(data: Data(normalized.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
        return "\(namespacePrefix):\(digest)"
    }

    public static func relayIdentityDigest(publicKey: Data) -> String {
        SHA256.hash(data: publicKey)
            .map { String(format: "%02x", $0) }
            .joined()
    }

    public static func signed(
        endpoint: RelayEndpoint,
        federationName: String?,
        signingKey: SigningKeyPair,
        issuedAt: Date = Date(),
        lifetimeSeconds: TimeInterval = maxLifetimeSeconds
    ) throws -> OpenFederationDHTRecord {
        let boundedLifetime = max(60, min(lifetimeSeconds, maxLifetimeSeconds))
        let unsigned = OpenFederationDHTRecord(
            namespace: namespace(federationName: federationName),
            relayIdentityDigest: relayIdentityDigest(publicKey: signingKey.publicKeyData),
            endpoint: endpoint,
            federationName: normalizedFederationName(federationName),
            issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(boundedLifetime),
            relaySigningPublicKey: signingKey.publicKeyData,
            signature: Data()
        )
        let signature = try signingKey.sign(unsigned.signingPayloadData())
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

    public func validate(
        expectedFederationName: String?,
        now: Date = Date(),
        requirePublicEndpoint: Bool = true
    ) throws {
        guard namespace == Self.namespace(federationName: expectedFederationName) else {
            throw OpenFederationDHTRecordError.namespaceMismatch
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
        guard let payload = try? signingPayloadData(),
              signatureAlgorithm == Self.signatureAlgorithm,
              SigningKeyPair.verify(
                signature: signature,
                data: payload,
                publicKeyData: relaySigningPublicKey
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
        try NoctweaveCoder.encode(
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
            ),
            sortedKeys: true
        )
    }

    private static func normalizedFederationName(_ value: String?) -> String {
        value?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            ?? ""
    }
}
