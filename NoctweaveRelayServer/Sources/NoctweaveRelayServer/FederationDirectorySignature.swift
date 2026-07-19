import Foundation

enum FederationDirectorySignature {
    static let algorithm = "ML-DSA-65"

    static func privateKeyDataThrowing(from raw: Data?) throws -> Data {
        if let raw {
            guard raw.count <= 16_384,
                  let bundle = try? RelayCodec.decoder().decode(
                    DirectorySigningKeyBundle.self,
                    from: raw
                  ),
                  bundle.algorithm == algorithm else {
                throw DirectorySigningError.invalidKeyBundle
            }
            let probeSignature = try OQSSignatureVerifier.shared.signThrowing(
                data: Self.keyProbeDomain,
                privateKey: bundle.privateKeyData,
                publicKey: bundle.publicKeyData
            )
            guard try OQSSignatureVerifier.shared.verifyThrowing(
                signature: probeSignature,
                data: Self.keyProbeDomain,
                publicKey: bundle.publicKeyData
            ) else {
                throw DirectorySigningError.invalidKeyBundle
            }
            return raw
        }
        let keyPair = try OQSSignatureVerifier.shared.generateKeyPairThrowing()
        let bundle = DirectorySigningKeyBundle(
            algorithm: algorithm,
            privateKeyData: keyPair.privateKey,
            publicKeyData: keyPair.publicKey
        )
        return try RelayCodec.encoder(sortedKeys: true).encode(bundle)
    }

    static func publicKeyDataThrowing(from privateKeyData: Data) throws -> Data {
        guard privateKeyData.count <= 16_384,
              let bundle = try? RelayCodec.decoder().decode(
                DirectorySigningKeyBundle.self,
                from: privateKeyData
              ),
              bundle.algorithm == algorithm else {
            throw DirectorySigningError.invalidKeyBundle
        }
        let probeSignature = try OQSSignatureVerifier.shared.signThrowing(
                data: Self.keyProbeDomain,
                privateKey: bundle.privateKeyData,
                publicKey: bundle.publicKeyData
        )
        guard try OQSSignatureVerifier.shared.verifyThrowing(
                signature: probeSignature,
                data: Self.keyProbeDomain,
                publicKey: bundle.publicKeyData
        ) else {
            throw DirectorySigningError.invalidKeyBundle
        }
        return bundle.publicKeyData
    }

    static func signedSnapshot(
        from unsigned: FederationDirectorySnapshot,
        privateKeyData: Data
    ) throws -> FederationDirectorySnapshot {
        let bundle = try RelayCodec.decoder().decode(DirectorySigningKeyBundle.self, from: privateKeyData)
        let payload = try signingPayloadData(from: unsigned)
        guard bundle.algorithm == algorithm else {
            throw DirectorySigningError.signingUnavailable
        }
        let signature = try OQSSignatureVerifier.shared.signThrowing(
            data: payload,
            privateKey: bundle.privateKeyData,
            publicKey: bundle.publicKeyData
        )
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

    static func verifyThrowing(
        snapshot: FederationDirectorySnapshot,
        trustedPublicKey: Data
    ) throws -> Bool {
        guard snapshot.signatureAlgorithm == algorithm,
              let signature = snapshot.signature,
              !signature.isEmpty else {
            return false
        }
        return try OQSSignatureVerifier.shared.verifyThrowing(
            signature: signature,
            data: try signingPayloadData(from: snapshot),
            publicKey: trustedPublicKey
        )
    }

    static let keyProbeDomain = Data("org.noctweave.federation.directory-key-probe/v1".utf8)

    private enum DirectorySigningError: Error {
        case invalidKeyBundle
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
