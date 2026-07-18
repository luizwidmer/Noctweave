import Foundation

enum FederationDirectorySignature {
    static let algorithm = "ML-DSA-65"

    static func privateKeyData(from raw: Data?) -> Data {
        if let raw {
            guard raw.count <= 16_384,
                  let bundle = try? RelayCodec.decoder().decode(DirectorySigningKeyBundle.self, from: raw),
                  bundle.algorithm == algorithm,
                  let probeSignature = OQSSignatureVerifier.shared.sign(
                data: Self.keyProbeDomain,
                privateKey: bundle.privateKeyData,
                publicKey: bundle.publicKeyData
                  ),
                  OQSSignatureVerifier.shared.verify(
                signature: probeSignature,
                data: Self.keyProbeDomain,
                publicKey: bundle.publicKeyData
                  ) else {
                return Data()
            }
            return raw
        }
        guard let keyPair = OQSSignatureVerifier.shared.generateKeyPair() else {
            return Data()
        }
        let bundle = DirectorySigningKeyBundle(
            algorithm: algorithm,
            privateKeyData: keyPair.privateKey,
            publicKeyData: keyPair.publicKey
        )
        return (try? RelayCodec.encoder(sortedKeys: true).encode(bundle)) ?? Data()
    }

    static func publicKeyData(from privateKeyData: Data) -> Data? {
        guard privateKeyData.count <= 16_384,
              let bundle = try? RelayCodec.decoder().decode(DirectorySigningKeyBundle.self, from: privateKeyData),
              bundle.algorithm == algorithm,
              let probeSignature = OQSSignatureVerifier.shared.sign(
                data: Self.keyProbeDomain,
                privateKey: bundle.privateKeyData,
                publicKey: bundle.publicKeyData
              ),
              OQSSignatureVerifier.shared.verify(
                signature: probeSignature,
                data: Self.keyProbeDomain,
                publicKey: bundle.publicKeyData
              ) else {
            return nil
        }
        return bundle.publicKeyData
    }

    static func signedSnapshot(
        from unsigned: FederationDirectorySnapshot,
        privateKeyData: Data
    ) throws -> FederationDirectorySnapshot {
        let bundle = try RelayCodec.decoder().decode(DirectorySigningKeyBundle.self, from: privateKeyData)
        let payload = try signingPayloadData(from: unsigned)
        guard bundle.algorithm == algorithm,
              let signature = OQSSignatureVerifier.shared.sign(
                data: payload,
                privateKey: bundle.privateKeyData,
                publicKey: bundle.publicKeyData
              ) else {
            throw DirectorySigningError.signingUnavailable
        }
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

    static func verify(snapshot: FederationDirectorySnapshot, trustedPublicKey: Data) -> Bool {
        guard snapshot.signatureAlgorithm == algorithm,
              let signature = snapshot.signature,
              let payload = try? signingPayloadData(from: snapshot) else {
            return false
        }
        return OQSSignatureVerifier.shared.verify(
            signature: signature,
            data: payload,
            publicKey: trustedPublicKey
        )
    }

    static let keyProbeDomain = Data("org.noctweave.federation.directory-key-probe/v1".utf8)

    private enum DirectorySigningError: Error {
        case signingUnavailable
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
        return try RelayCodec.encoder(sortedKeys: true).encode(payload)
    }
}
