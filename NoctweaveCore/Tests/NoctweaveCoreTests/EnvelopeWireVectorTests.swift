import Foundation
import XCTest
@testable import NoctweaveCore

final class EnvelopeWireVectorTests: XCTestCase {
    func testStrictDirectEnvelopeRoundTripsThroughExactOneUnion() throws {
        let direct = makeTestDirectEnvelope(
            id: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
            eventId: UUID(uuidString: "22222222-2222-4222-8222-222222222222")!,
            conversationId: "strict-direct-v4",
            sessionId: "strict-session-v4",
            counter: 42,
            sentAt: Date(timeIntervalSince1970: 1_800_000_000)
        )
        let envelope = ProtocolEnvelopeV1.directV4(direct)
        let encoded = try NoctweaveCoder.encode(envelope, sortedKeys: true)
        let decoded = try NoctweaveCoder.decode(ProtocolEnvelopeV1.self, from: encoded)

        XCTAssertEqual(decoded, envelope)
        XCTAssertTrue(decoded.isStructurallyValid)
        XCTAssertEqual(
            try jsonObject(encoded).allKeys.compactMap { $0 as? String }.sorted(),
            ["directV4", "version"]
        )
    }

    func testProtocolEnvelopeRejectsUnknownMissingAndMultipleCases() throws {
        let direct = ProtocolEnvelopeV1.directV4(makeTestDirectEnvelope())
        let encoded = try NoctweaveCoder.encode(direct)
        let base = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )

        var unknown = base
        unknown["futureCase"] = [:]
        XCTAssertThrowsError(try decode(unknown))

        XCTAssertThrowsError(try decode(["version": ProtocolEnvelopeV1.version]))

        var multiple = base
        multiple["groupApplicationV2"] = try jsonObject(
            NoctweaveCoder.encode(makeGroupApplicationEnvelope())
        )
        XCTAssertThrowsError(try decode(multiple))
    }

    func testNestedDirectAndGroupApplicationRejectUnknownFields() throws {
        let direct = ProtocolEnvelopeV1.directV4(makeTestDirectEnvelope())
        var directObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: NoctweaveCoder.encode(direct))
                as? [String: Any]
        )
        var nestedDirect = try XCTUnwrap(directObject["directV4"] as? [String: Any])
        nestedDirect["futureHeader"] = true
        directObject["directV4"] = nestedDirect
        XCTAssertThrowsError(try decode(directObject))

        let group = ProtocolEnvelopeV1.groupApplicationV2(makeGroupApplicationEnvelope())
        var groupObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: NoctweaveCoder.encode(group))
                as? [String: Any]
        )
        var nestedGroup = try XCTUnwrap(
            groupObject["groupApplicationV2"] as? [String: Any]
        )
        nestedGroup["relationshipId"] = UUID().uuidString
        groupObject["groupApplicationV2"] = nestedGroup
        XCTAssertThrowsError(try decode(groupObject))
    }

    func testGroupApplicationSignatureTranscriptAndTimestampBucket() throws {
        let signingKey = try SigningKeyPair.generate()
        let requested = Date(timeIntervalSince1970: 1_800_000_123)
        let envelope = try GroupApplicationEnvelopeV2.create(
            groupId: UUID(),
            epoch: 7,
            transcriptHash: Data(repeating: 0x21, count: 32),
            senderCredentialHandle: GroupScopedCredentialHandleV2.generate(),
            messageCounter: 9,
            sentAt: requested,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x31, count: 12),
                ciphertext: Data(repeating: 0x32, count: 512),
                tag: Data(repeating: 0x33, count: 16)
            ),
            signingKey: signingKey
        )

        XCTAssertTrue(envelope.isStructurallyValid)
        XCTAssertEqual(
            envelope.sentAt.timeIntervalSince1970
                .truncatingRemainder(dividingBy: GroupApplicationEnvelopeV2.timestampBucketSeconds),
            0
        )
        XCTAssertTrue(envelope.verifySignature(
            groupClientSigningPublicKey: signingKey.publicKeyData
        ))
    }

    private func makeGroupApplicationEnvelope() -> GroupApplicationEnvelopeV2 {
        GroupApplicationEnvelopeV2(
            profile: NoctweaveSignedGroupV2.experimentalProfile,
            cipherSuite: NoctweaveSignedGroupV2.experimentalCipherSuite,
            groupId: UUID(uuidString: "33333333-3333-4333-8333-333333333333")!,
            epoch: 1,
            transcriptHash: Data(repeating: 0x41, count: 32),
            senderCredentialHandle: GroupScopedCredentialHandleV2(
                rawValue: Data(repeating: 0x42, count: 32).base64EncodedString()
            ),
            eventId: UUID(uuidString: "44444444-4444-4444-8444-444444444444")!,
            messageCounter: 0,
            sentAt: Date(timeIntervalSince1970: 1_800_000_000),
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x43, count: 12),
                ciphertext: Data(repeating: 0x44, count: 512),
                tag: Data(repeating: 0x45, count: 16)
            ),
            signature: Data(repeating: 0x46, count: 3_309)
        )
    }

    private func decode(_ object: [String: Any]) throws -> ProtocolEnvelopeV1 {
        try NoctweaveCoder.decode(
            ProtocolEnvelopeV1.self,
            from: JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        )
    }

    private func jsonObject(_ data: Data) throws -> NSDictionary {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: data, options: []) as? NSDictionary
        )
    }
}
