import Foundation

public enum FederationDirectorySignature {
    public static let algorithm = "ML-DSA-65"

    public static func privateKeyDataThrowing(from raw: Data?) throws -> Data {
        if let raw {
            guard raw.count <= 16_384 else {
                throw CryptoError.invalidPrivateKey
            }
            let bundle: DirectorySigningKeyBundle
            do {
                bundle = try NoctweaveCoder.decode(DirectorySigningKeyBundle.self, from: raw)
            } catch {
                throw CryptoError.invalidPrivateKey
            }
            guard bundle.algorithm == algorithm else {
                throw CryptoError.invalidPrivateKey
            }
            _ = try SigningKeyPair(
                privateKeyData: bundle.privateKeyData,
                publicKeyData: bundle.publicKeyData
            )
            return raw
        }
        let keyPair = try SigningKeyPair.generate()
        let bundle = DirectorySigningKeyBundle(
            algorithm: algorithm,
            privateKeyData: keyPair.privateKeyData,
            publicKeyData: keyPair.publicKeyData
        )
        return try NoctweaveCoder.encode(bundle, sortedKeys: true)
    }

    public static func publicKeyDataThrowing(from privateKeyData: Data) throws -> Data {
        guard privateKeyData.count <= 16_384 else {
            throw CryptoError.invalidPrivateKey
        }
        let bundle: DirectorySigningKeyBundle
        do {
            bundle = try NoctweaveCoder.decode(
                DirectorySigningKeyBundle.self,
                from: privateKeyData
            )
        } catch {
            throw CryptoError.invalidPrivateKey
        }
        guard bundle.algorithm == algorithm else {
            throw CryptoError.invalidPrivateKey
        }
        _ = try SigningKeyPair(
            privateKeyData: bundle.privateKeyData,
            publicKeyData: bundle.publicKeyData
        )
        return bundle.publicKeyData
    }

    public static func signedSnapshot(
        from unsigned: FederationDirectorySnapshot,
        privateKeyData: Data
    ) throws -> FederationDirectorySnapshot {
        let bundle = try NoctweaveCoder.decode(DirectorySigningKeyBundle.self, from: privateKeyData)
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

    /// Keeps local ML-DSA availability failures distinct from a deterministic
    /// invalid coordinator signature.
    public static func verifyThrowing(
        snapshot: FederationDirectorySnapshot,
        trustedPublicKey: Data
    ) throws -> Bool {
        guard snapshot.signatureAlgorithm == algorithm,
              let signature = snapshot.signature else {
            return false
        }
        let payload = try signingPayloadData(from: snapshot)
        return try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: payload,
            publicKeyData: trustedPublicKey
        )
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
        return try NoctweaveCoder.encode(payload, sortedKeys: true)
    }
}
