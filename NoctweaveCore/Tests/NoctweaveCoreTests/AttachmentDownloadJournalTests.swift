import Foundation
import XCTest
@testable import NoctweaveCore

final class AttachmentDownloadJournalTests: XCTestCase {
    func testDownloadJournalRoundTripsCiphertextOnlyAndRejectsUnknownFields() throws {
        let relationshipID = UUID(uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")!
        let attachmentID = UUID(uuidString: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")!
        let descriptor = AttachmentDescriptor(
            id: attachmentID,
            fileName: nil,
            mimeType: "application/octet-stream",
            byteCount: 16,
            sha256: Data(repeating: 0x11, count: 32),
            chunkCount: 1,
            chunkSize: 16,
            relayTTLSeconds: 600
        )
        let chunk = AttachmentChunk(
            attachmentId: attachmentID,
            chunkIndex: 0,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x22, count: 12),
                ciphertext: Data(repeating: 0x33, count: 16),
                tag: Data(repeating: 0x44, count: 16)
            )
        )
        let pending = try PendingAttachmentDownloadV2(
            relationshipID: relationshipID,
            relay: RelayEndpoint(host: "relay.example", port: 443, useTLS: true),
            descriptor: descriptor,
            receivedChunks: [chunk],
            queuedAt: Date(timeIntervalSince1970: 2_000)
        )
        XCTAssertTrue(pending.isComplete)
        let encoded = try NoctweaveCoder.encode(pending, sortedKeys: true)
        XCTAssertFalse(String(data: encoded, encoding: .utf8)?.contains("plaintext") == true)
        XCTAssertEqual(try NoctweaveCoder.decode(PendingAttachmentDownloadV2.self, from: encoded), pending)

        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        object["unexpected"] = true
        let foreign = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        XCTAssertThrowsError(try NoctweaveCoder.decode(PendingAttachmentDownloadV2.self, from: foreign))
    }

    func testDownloadJournalRequiresExactChunkOrderAndCiphertextLength() throws {
        let attachmentID = UUID(uuidString: "cccccccc-cccc-4ccc-8ccc-cccccccccccc")!
        let descriptor = AttachmentDescriptor(
            id: attachmentID,
            fileName: nil,
            mimeType: "application/octet-stream",
            byteCount: 16,
            sha256: Data(repeating: 0x55, count: 32),
            chunkCount: 1,
            chunkSize: 16
        )
        let invalidChunk = AttachmentChunk(
            attachmentId: attachmentID,
            chunkIndex: 0,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x66, count: 12),
                ciphertext: Data(repeating: 0x77, count: 15),
                tag: Data(repeating: 0x88, count: 16)
            )
        )
        XCTAssertThrowsError(
            try PendingAttachmentDownloadV2(
                relationshipID: UUID(uuidString: "dddddddd-dddd-4ddd-8ddd-dddddddddddd")!,
                relay: RelayEndpoint(host: "relay.example", port: 443, useTLS: true),
                descriptor: descriptor,
                receivedChunks: [invalidChunk],
                queuedAt: Date(timeIntervalSince1970: 2_000)
            )
        )
    }
}
