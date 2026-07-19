import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2SharedVectorConformanceTests: XCTestCase {
    func testDirectV4RootSessionMatchesSharedCanonicalVector() throws {
        let vector = try loadDirectV4RootSessionVector()
        let relationshipID = try XCTUnwrap(UUID(uuidString: vector.relationshipId))
        let derivation = MessageEngine.directV4RootSessionDerivation(
            sharedSecret: try Data(hex: vector.sharedSecretHex),
            relationshipID: relationshipID,
            cipherSuite: vector.cipherSuite,
            negotiatedCapabilitiesDigest: try Data(
                hex: vector.negotiatedCapabilitiesDigestHex
            )
        )

        XCTAssertEqual(derivation.rootInfo.count, vector.expectedRootInfoBytes)
        XCTAssertEqual(derivation.rootInfo.hexString, vector.expectedRootInfoHex)
        XCTAssertEqual(derivation.rootKey.hexString, vector.expectedRootKeyHex)
        XCTAssertEqual(
            derivation.sessionTranscript.count,
            vector.expectedSessionTranscriptBytes
        )
        XCTAssertEqual(
            derivation.sessionTranscript.hexString,
            vector.expectedSessionTranscriptHex
        )
        XCTAssertEqual(
            derivation.sessionDigest.hexString,
            vector.expectedSessionDigestHex
        )
        XCTAssertEqual(derivation.sessionID, vector.expectedSessionIdBase64)
    }

    func testRendezvousOfferMatchesSharedCanonicalVector() throws {
        let vector = try loadVectors().rendezvousOffer
        let createdAt = try parseDate(vector.createdAt)
        let expiresAt = try parseDate(vector.expiresAt)
        let offer = try RendezvousOfferV2(
            version: vector.version,
            purpose: try XCTUnwrap(RendezvousPurposeV2(rawValue: vector.purpose)),
            transportCapability: RendezvousTransportCapabilityV2(
                opaqueValue: try Data(hex: vector.transportCapabilityBytesHex),
                expiresAt: expiresAt
            ),
            oneTimeTokenDigest: Data(
                repeating: vector.oneTimeTokenDigestRepeatedByte,
                count: NoctweaveRendezvousV2.tokenDigestBytes
            ),
            ephemeralAgreementPublicKey: Data(
                repeating: vector.ephemeralAgreementPublicKeyRepeatedByte,
                count: vector.ephemeralAgreementPublicKeyBytes
            ),
            createdAt: createdAt,
            expiresAt: expiresAt,
            limits: try RendezvousLimitsV2(
                maximumFrames: vector.maximumFrames,
                maximumFramePlaintextBytes: vector.maximumFramePlaintextBytes
            )
        )

        let transcript = canonicalRendezvousOfferTranscript(offer)
        XCTAssertEqual(transcript.count, vector.expectedTranscriptBytes)
        XCTAssertEqual(transcript.prefix(4).hexString, "00000024")
        XCTAssertEqual(
            Data(SHA256.hash(data: transcript)).hexString,
            vector.expectedTranscriptDigestHex
        )
        XCTAssertEqual(offer.transcriptDigest.hexString, vector.expectedTranscriptDigestHex)
    }

    func testOpaqueRouteCreateMatchesSharedCanonicalVector() throws {
        let vector = try loadVectors().opaqueRouteCreate
        let issuedAt = try parseDate(vector.issuedAt)
        let expiresAt = try parseDate(vector.expiresAt)
        let material = try OpaqueRouteClientCapabilityMaterialV2(
            routeID: OpaqueReceiveRouteIDV2(
                rawValue: Data(repeating: vector.routeIdRepeatedByte, count: 32)
            ),
            sendCapability: RouteSendCapabilityV2(
                rawValue: Data(repeating: vector.sendCapabilityRepeatedByte, count: 32)
            ),
            readCredential: RouteReadCredentialV2(
                rawValue: Data(repeating: vector.readCredentialRepeatedByte, count: 32)
            ),
            renewCapability: RouteRenewCapabilityV2(
                rawValue: Data(repeating: vector.renewCapabilityRepeatedByte, count: 32)
            ),
            teardownCapability: RouteTeardownCapabilityV2(
                rawValue: Data(repeating: vector.teardownCapabilityRepeatedByte, count: 32)
            )
        )
        let policy = OpaqueRoutePolicyV2(
            paddingBucket: try XCTUnwrap(OpaqueRoutePaddingBucketV2(rawValue: vector.paddingBucket)),
            retentionBucket: try XCTUnwrap(OpaqueRouteRetentionBucketV2(rawValue: vector.retentionBucket)),
            quotaBucket: try XCTUnwrap(OpaqueRouteQuotaBucketV2(rawValue: vector.quotaBucket))
        )
        let request = try material.makeCreateRequest(
            lease: OpaqueRouteLeaseV2(
                issuedAt: issuedAt,
                expiresAt: expiresAt,
                policy: policy
            ),
            idempotencyKey: OpaqueRouteIdempotencyKeyV2(
                rawValue: Data(repeating: vector.idempotencyKeyRepeatedByte, count: 32)
            ),
            nonce: OpaqueRouteProofNonceV2(
                rawValue: Data(repeating: vector.proofNonceRepeatedByte, count: 32)
            )
        )

        XCTAssertEqual(request.transitionDigest?.hexString, vector.expectedTransitionDigestHex)
        XCTAssertEqual(request.authorization.mac.hexString, vector.expectedAuthorizationMACHex)
    }

    private func loadVectors() throws -> SharedVectors {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let vectorURL = repositoryRoot
            .appendingPathComponent("NoctweaveDocumentation/test_vectors/rendezvous_opaque_v2.json")
        return try JSONDecoder().decode(
            SharedVectors.self,
            from: Data(contentsOf: vectorURL)
        )
    }

    private func loadDirectV4RootSessionVector() throws -> DirectV4RootSessionVector {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let vectorURL = repositoryRoot.appendingPathComponent(
            "NoctweaveDocumentation/test_vectors/direct_v4_root_session_v1.json"
        )
        return try JSONDecoder().decode(
            DirectV4RootSessionVector.self,
            from: Data(contentsOf: vectorURL)
        )
    }

    private func parseDate(_ value: String) throws -> Date {
        try XCTUnwrap(ISO8601DateFormatter().date(from: value))
    }

    private func canonicalRendezvousOfferTranscript(_ offer: RendezvousOfferV2) -> Data {
        var data = Data()
        append("Noctweave/rendezvous-v2/public-offer", to: &data)
        append(UInt16(offer.version), to: &data)
        append(offer.purpose.rawValue, to: &data)
        append(offer.transportCapability.opaqueValue, to: &data)
        append(timestamp: offer.transportCapability.expiresAt, to: &data)
        append(offer.oneTimeTokenDigest, to: &data)
        append(offer.ephemeralAgreementPublicKey, to: &data)
        append(timestamp: offer.createdAt, to: &data)
        append(timestamp: offer.expiresAt, to: &data)
        append(offer.limits.maximumFrames, to: &data)
        append(offer.limits.maximumFramePlaintextBytes, to: &data)
        return data
    }

    private func append(_ value: String, to data: inout Data) {
        append(Data(value.utf8), to: &data)
    }

    private func append(_ value: Data, to data: inout Data) {
        append(UInt32(value.count), to: &data)
        data.append(value)
    }

    private func append(timestamp: Date, to data: inout Data) {
        append(UInt64(timestamp.timeIntervalSince1970), to: &data)
    }

    private func append(_ value: UInt16, to data: inout Data) {
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    private func append(_ value: UInt32, to data: inout Data) {
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    private func append(_ value: UInt64, to data: inout Data) {
        data.append(UInt8((value >> 56) & 0xff))
        data.append(UInt8((value >> 48) & 0xff))
        data.append(UInt8((value >> 40) & 0xff))
        data.append(UInt8((value >> 32) & 0xff))
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }
}

private struct DirectV4RootSessionVector: Decodable {
    let sharedSecretHex: String
    let relationshipId: String
    let cipherSuite: String
    let negotiatedCapabilitiesDigestHex: String
    let expectedRootInfoBytes: Int
    let expectedRootInfoHex: String
    let expectedRootKeyHex: String
    let expectedSessionTranscriptBytes: Int
    let expectedSessionTranscriptHex: String
    let expectedSessionDigestHex: String
    let expectedSessionIdBase64: String
}

private struct SharedVectors: Decodable {
    let rendezvousOffer: RendezvousOfferVector
    let opaqueRouteCreate: OpaqueRouteCreateVector
}

private struct RendezvousOfferVector: Decodable {
    let version: Int
    let purpose: String
    let transportCapabilityBytesHex: String
    let oneTimeTokenDigestRepeatedByte: UInt8
    let ephemeralAgreementPublicKeyRepeatedByte: UInt8
    let ephemeralAgreementPublicKeyBytes: Int
    let createdAt: String
    let expiresAt: String
    let maximumFrames: UInt16
    let maximumFramePlaintextBytes: UInt32
    let expectedTranscriptBytes: Int
    let expectedTranscriptDigestHex: String
}

private struct OpaqueRouteCreateVector: Decodable {
    let routeIdRepeatedByte: UInt8
    let sendCapabilityRepeatedByte: UInt8
    let readCredentialRepeatedByte: UInt8
    let renewCapabilityRepeatedByte: UInt8
    let teardownCapabilityRepeatedByte: UInt8
    let idempotencyKeyRepeatedByte: UInt8
    let proofNonceRepeatedByte: UInt8
    let issuedAt: String
    let expiresAt: String
    let paddingBucket: UInt32
    let retentionBucket: UInt32
    let quotaBucket: UInt32
    let expectedTransitionDigestHex: String
    let expectedAuthorizationMACHex: String
}

private extension Data {
    init(hex: String) throws {
        guard hex.count.isMultiple(of: 2) else { throw SharedVectorError.invalidHex }
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else {
                throw SharedVectorError.invalidHex
            }
            bytes.append(byte)
            index = next
        }
        self = Data(bytes)
    }

    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}

private enum SharedVectorError: Error {
    case invalidHex
}
