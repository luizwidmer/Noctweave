import Foundation

public enum FederationDirectorySignature {
    public static let algorithm = "ML-DSA-65"

    public static func privateKeyData(from raw: Data?) -> Data {
        if let raw,
           let bundle = try? PICCPCoder.decode(DirectorySigningKeyBundle.self, from: raw),
           bundle.algorithm == algorithm,
           SigningKeyPair.isValidPublicKey(bundle.publicKeyData),
           (try? SigningKeyPair(privateKeyData: bundle.privateKeyData, publicKeyData: bundle.publicKeyData)) != nil {
            return raw
        }
        let keyPair = SigningKeyPair()
        let bundle = DirectorySigningKeyBundle(
            algorithm: algorithm,
            privateKeyData: keyPair.privateKeyData,
            publicKeyData: keyPair.publicKeyData
        )
        return (try? PICCPCoder.encode(bundle, sortedKeys: true)) ?? Data()
    }

    public static func publicKeyData(from privateKeyData: Data) -> Data? {
        guard let bundle = try? PICCPCoder.decode(DirectorySigningKeyBundle.self, from: privateKeyData),
              bundle.algorithm == algorithm,
              SigningKeyPair.isValidPublicKey(bundle.publicKeyData) else {
            return nil
        }
        return bundle.publicKeyData
    }

    public static func signedSnapshot(
        from unsigned: FederationDirectorySnapshot,
        privateKeyData: Data
    ) throws -> FederationDirectorySnapshot {
        let bundle = try PICCPCoder.decode(DirectorySigningKeyBundle.self, from: privateKeyData)
        guard bundle.algorithm == algorithm else {
            throw CryptoError.invalidPrivateKey
        }
        let key = try SigningKeyPair(
            privateKeyData: bundle.privateKeyData,
            publicKeyData: bundle.publicKeyData
        )
        let payload = try signingPayloadData(from: unsigned)
        let signature = try key.sign(payload)
        return FederationDirectorySnapshot(
            version: unsigned.version,
            mode: unsigned.mode,
            federationName: unsigned.federationName,
            issuedAt: unsigned.issuedAt,
            validUntil: unsigned.validUntil,
            maxStalenessSeconds: unsigned.maxStalenessSeconds,
            nodes: unsigned.nodes,
            signatureAlgorithm: algorithm,
            signature: signature
        )
    }

    public static func verify(
        snapshot: FederationDirectorySnapshot,
        trustedPublicKey: Data
    ) -> Bool {
        guard snapshot.signatureAlgorithm == algorithm,
              let signature = snapshot.signature,
              let payload = try? signingPayloadData(from: snapshot) else {
            return false
        }
        return SigningKeyPair.verify(signature: signature, data: payload, publicKeyData: trustedPublicKey)
    }

    private struct DirectorySigningKeyBundle: Codable {
        let algorithm: String
        let privateKeyData: Data
        let publicKeyData: Data
    }

    private struct SnapshotSigningPayload: Codable {
        let version: Int
        let mode: FederationMode
        let federationName: String?
        let issuedAt: Date
        let validUntil: Date
        let maxStalenessSeconds: Int
        let nodes: [FederationNodeRecord]
    }

    private static func signingPayloadData(from snapshot: FederationDirectorySnapshot) throws -> Data {
        let payload = SnapshotSigningPayload(
            version: snapshot.version,
            mode: snapshot.mode,
            federationName: snapshot.federationName,
            issuedAt: snapshot.issuedAt,
            validUntil: snapshot.validUntil,
            maxStalenessSeconds: snapshot.maxStalenessSeconds,
            nodes: snapshot.nodes
        )
        return try PICCPCoder.encode(payload, sortedKeys: true)
    }
}
