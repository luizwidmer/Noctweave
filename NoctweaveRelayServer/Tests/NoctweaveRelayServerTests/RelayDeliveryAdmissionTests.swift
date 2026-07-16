import XCTest
@testable import NoctweaveRelayServer

final class RelayDeliveryAdmissionTests: XCTestCase {
    func testDirectDeliveryRequiresRegisteredDestinationBeforeAllocatingStorage() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        let envelope = makeAdmissionEnvelope(counter: 1)

        XCTAssertThrowsError(try store.deliver(envelope, to: inboxId)) { error in
            XCTAssertEqual(error as? RelayStoreError, .destinationInboxNotRegistered)
        }
        XCTAssertTrue(store.fetch(inboxId: inboxId, maxCount: nil).isEmpty)

        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA1]))
        XCTAssertEqual(try store.deliver(envelope, to: inboxId), 1)
        XCTAssertEqual(store.fetch(inboxId: inboxId, maxCount: nil).map(\.id), [envelope.id])
    }

    func testGroupDeliveryRequiresRegisteredDestinationAndAcceptsGroupDescriptorInbox() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let syntheticInboxId = InboxAddress.generate()
        let envelope = makeAdmissionEnvelope(counter: 2)

        XCTAssertThrowsError(
            try store.deliverGroupEnvelope(
                envelope,
                to: syntheticInboxId,
                recipientFingerprints: ["member-b"]
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .destinationInboxNotRegistered)
        }
        XCTAssertTrue(store.fetch(inboxId: syntheticInboxId, maxCount: nil).isEmpty)

        let group = try store.createGroup(
            title: "Registered group",
            creatorFingerprint: "member-a",
            memberFingerprints: ["member-a", "member-b"]
        )
        XCTAssertEqual(
            try store.deliverGroupEnvelope(
                envelope,
                to: group.inboxId,
                recipientFingerprints: ["member-b"]
            ),
            1
        )
        XCTAssertEqual(store.fetch(inboxId: group.inboxId, maxCount: nil).map(\.id), [envelope.id])
    }

    private func makeAdmissionEnvelope(counter: UInt64) -> Envelope {
        Envelope(
            conversationId: "relay-delivery-admission",
            sessionId: "session-v2",
            senderFingerprint: Data(repeating: 0x44, count: 32).base64EncodedString(),
            sentAt: Date(timeIntervalSince1970: TimeInterval(9_000 + counter)),
            messageCounter: counter,
            kemCiphertext: nil,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: 12),
                ciphertext: Data(repeating: UInt8(truncatingIfNeeded: counter), count: 512),
                tag: Data(repeating: 0x22, count: 16)
            ),
            signature: Data(
                repeating: 0x33,
                count: OQSSignatureVerifier.mlDSA65SignatureBytes
            )
        )
    }
}
