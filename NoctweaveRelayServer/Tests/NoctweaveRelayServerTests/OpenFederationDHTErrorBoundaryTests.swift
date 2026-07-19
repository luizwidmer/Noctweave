import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class OpenFederationDHTErrorBoundaryTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_900_000_000)

    func testDeterministicallyMalformedRecordIsRejectedWithoutCryptoRuntime() throws {
        var cache = makeCache()
        let record = makeRecord(signature: Data([0x01]))

        let result = try cache.ingest([record], now: now)

        XCTAssertTrue(result.accepted.isEmpty)
        guard case .validationFailed(.invalidStructure)? = result.rejected.first?.reason else {
            return XCTFail("Expected deterministic structural rejection")
        }
    }

    func testSignatureRuntimeFailureEscapesCacheInsteadOfBecomingPeerRejection() throws {
        var cache = makeCache()
        let record = makeRecord(
            signature: Data(repeating: 0, count: OQSSignatureVerifier.mlDSA65SignatureBytes)
        )

        if OQSSignatureVerifier.shared.isAvailable {
            let result = try cache.ingest([record], now: now)
            XCTAssertTrue(result.accepted.isEmpty)
            guard case .validationFailed(.invalidSignature)? = result.rejected.first?.reason else {
                return XCTFail("Expected invalid signature rejection with an available runtime")
            }
        } else {
            XCTAssertThrowsError(try cache.ingest([record], now: now)) { error in
                XCTAssertEqual(
                    error as? OQSSignatureVerifierError,
                    .runtimeUnavailable
                )
            }
        }
    }

    private func makeCache() -> OpenFederationDHTCandidateCache {
        OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "test",
                requirePublicEndpoint: false
            )
        )
    }

    private func makeRecord(signature: Data) -> OpenFederationDHTRecord {
        let publicKey = Data(
            repeating: 0x42,
            count: OQSSignatureVerifier.mlDSA65PublicKeyBytes
        )
        return OpenFederationDHTRecord(
            namespace: OpenFederationDHTRecord.namespace(federationName: "test"),
            relayIdentityDigest: OpenFederationDHTRecord.relayIdentityDigest(
                publicKey: publicKey
            ),
            endpoint: RelayEndpoint(
                host: "relay.example.org",
                port: 443,
                useTLS: true,
                transport: .http
            ),
            federationName: "test",
            issuedAt: now,
            expiresAt: now.addingTimeInterval(300),
            relaySigningPublicKey: publicKey,
            signature: signature
        )
    }
}
