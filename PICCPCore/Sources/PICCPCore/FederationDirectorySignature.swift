import CryptoKit
import Foundation

public enum FederationDirectorySignature {
    public static let algorithm = "ed25519"

    public static func privateKeyData(from raw: Data?) -> Data {
        if let raw, let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: raw) {
            return key.rawRepresentation
        }
        return Curve25519.Signing.PrivateKey().rawRepresentation
    }

    public static func publicKeyData(from privateKeyData: Data) -> Data? {
        guard let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData) else {
            return nil
        }
        return key.publicKey.rawRepresentation
    }

    public static func signedSnapshot(
        from unsigned: FederationDirectorySnapshot,
        privateKeyData: Data
    ) throws -> FederationDirectorySnapshot {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        let payload = try signingPayloadData(from: unsigned)
        let signature = try key.signature(for: payload)
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
        guard snapshot.signatureAlgorithm?.lowercased() == algorithm,
              let signature = snapshot.signature,
              let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: trustedPublicKey),
              let payload = try? signingPayloadData(from: snapshot) else {
            return false
        }
        return publicKey.isValidSignature(signature, for: payload)
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
