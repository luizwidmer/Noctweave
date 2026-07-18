import Foundation
import XCTest
@testable import NoctweaveCore

final class MessageProjectionStrictTests: XCTestCase {
    func testMessageRoundTripsOnlyWithExactCurrentFields() throws {
        let message = makeMessage()
        let encoded = try NoctweaveCoder.encode(message, sortedKeys: true)

        XCTAssertEqual(
            try NoctweaveCoder.decode(Message.self, from: encoded),
            message
        )

        var missing = try jsonObject(encoded)
        missing.removeValue(forKey: "attachment")
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(Message.self, from: try jsonData(missing))
        )

        var obsolete = try jsonObject(encoded)
        obsolete["senderDisplayName"] = "linkable-name"
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(Message.self, from: try jsonData(obsolete))
        )

        var foreign = try jsonObject(encoded)
        foreign["futureField"] = true
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(Message.self, from: try jsonData(foreign))
        )
    }

    func testMessageRejectsInvalidProjectionState() {
        let oversized = Message(
            direction: .received,
            body: String(
                repeating: "a",
                count: NoctweaveArchitectureV2.maximumContentPayloadBytes + 1
            ),
            timestamp: Date(),
            counter: 1
        )

        XCTAssertFalse(oversized.isStructurallyValid)
        XCTAssertThrowsError(try NoctweaveCoder.encode(oversized))
    }

    func testAttachmentStateRoundTripsOnlyWithExactCurrentFields() throws {
        let attachment = AttachmentInfo(
            descriptor: makeDescriptor(),
            localFileName: "attachment.bin",
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            cryptoContext: AttachmentCryptoContext(
                conversationId: UUID().uuidString.lowercased(),
                sessionId: "session-v1",
                messageCounter: 7
            ),
            messageKeyData: Data(repeating: 0x44, count: 32)
        )
        let encoded = try NoctweaveCoder.encode(attachment, sortedKeys: true)

        XCTAssertEqual(
            try NoctweaveCoder.decode(AttachmentInfo.self, from: encoded),
            attachment
        )

        var missing = try jsonObject(encoded)
        missing.removeValue(forKey: "messageKeyData")
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(AttachmentInfo.self, from: try jsonData(missing))
        )

        var foreign = try jsonObject(encoded)
        foreign["displayName"] = "leak.txt"
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(AttachmentInfo.self, from: try jsonData(foreign))
        )

        var nested = try jsonObject(encoded)
        var descriptor = try XCTUnwrap(nested["descriptor"] as? [String: Any])
        descriptor["futureField"] = true
        nested["descriptor"] = descriptor
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(AttachmentInfo.self, from: try jsonData(nested))
        )

        var incompleteDescriptor = try jsonObject(encoded)
        var descriptorWithoutNull = try XCTUnwrap(
            incompleteDescriptor["descriptor"] as? [String: Any]
        )
        descriptorWithoutNull.removeValue(forKey: "fileName")
        incompleteDescriptor["descriptor"] = descriptorWithoutNull
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                AttachmentInfo.self,
                from: try jsonData(incompleteDescriptor)
            )
        )

        var incompleteContext = try jsonObject(encoded)
        var context = try XCTUnwrap(
            incompleteContext["cryptoContext"] as? [String: Any]
        )
        context.removeValue(forKey: "messageCounter")
        incompleteContext["cryptoContext"] = context
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                AttachmentInfo.self,
                from: try jsonData(incompleteContext)
            )
        )

        let unsafe = AttachmentInfo(
            descriptor: makeDescriptor(),
            localFileName: "../attachment.bin"
        )
        XCTAssertFalse(unsafe.isStructurallyValid)
        XCTAssertThrowsError(try NoctweaveCoder.encode(unsafe))

        let invalidKey = AttachmentInfo(
            descriptor: makeDescriptor(),
            messageKeyData: Data(repeating: 0x44, count: 31)
        )
        XCTAssertFalse(invalidKey.isStructurallyValid)
        XCTAssertThrowsError(try NoctweaveCoder.encode(invalidKey))
    }

    func testConversationRejectsDuplicateInvalidAndOversizedMessageProjections() throws {
        let message = makeMessage()
        let valid = makeConversation(messages: [message])
        XCTAssertTrue(valid.isStructurallyValid)
        let encoded = try NoctweaveCoder.encode(valid, sortedKeys: true)
        XCTAssertEqual(
            try NoctweaveCoder.decode(
                Conversation.self,
                from: encoded
            ),
            valid
        )
        XCTAssertEqual(
            Set(try jsonObject(encoded).keys),
            Set([
                "id",
                "relationshipID",
                "endpointSession",
                "sessionId",
                "rootKey",
                "sendChain",
                "receiveChain",
                "messages",
                "unreadCount",
                "ratchetState",
            ])
        )

        var obsoleteRootCounter = try jsonObject(encoded)
        obsoleteRootCounter["rootCounter"] = 0
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                Conversation.self,
                from: try jsonData(obsoleteRootCounter)
            )
        )

        let duplicate = makeConversation(messages: [message, message])
        XCTAssertFalse(duplicate.isStructurallyValid)
        XCTAssertThrowsError(try NoctweaveCoder.encode(duplicate))

        let oversizedBody = Message(
            direction: .sent,
            body: String(
                repeating: "a",
                count: NoctweaveArchitectureV2.maximumContentPayloadBytes + 1
            ),
            timestamp: Date(),
            counter: 2
        )
        XCTAssertFalse(
            makeConversation(messages: [oversizedBody]).isStructurallyValid
        )

        let tooMany = (0...NoctweaveArchitectureV2.maximumRelationshipEvents).map {
            Message(
                id: UUID(),
                direction: .received,
                body: "message-\($0)",
                timestamp: Date(timeIntervalSince1970: TimeInterval($0)),
                counter: UInt64($0)
            )
        }
        XCTAssertFalse(makeConversation(messages: tooMany).isStructurallyValid)
    }

    func testConversationUnreadProjectionIsLocalBoundedState() {
        var conversation = makeConversation(messages: [])
        let received = Message(
            direction: .received,
            body: "received",
            timestamp: Date(timeIntervalSince1970: 1_771_200_001),
            counter: 1
        )
        let sent = Message(
            direction: .sent,
            body: "sent",
            timestamp: Date(timeIntervalSince1970: 1_771_200_002),
            counter: 2
        )

        conversation.appendProjectedMessage(received)
        XCTAssertEqual(conversation.unreadCount, 1)
        conversation.appendProjectedMessage(sent)
        XCTAssertEqual(conversation.unreadCount, 1)
        conversation.markAllRead()
        XCTAssertEqual(conversation.unreadCount, 0)
        XCTAssertTrue(conversation.isStructurallyValid)
    }

    func testConversationTrimmingDropsOnlyUnreadReceivedProjectionsThatLeaveWindow() {
        let maximum = NoctweaveArchitectureV2.maximumRelationshipEvents
        var projections = [Message(
            direction: .received,
            body: "oldest unread",
            timestamp: Date(timeIntervalSince1970: 1_771_200_000),
            counter: 0
        )]
        projections.append(contentsOf: (1..<maximum).map { index in
            Message(
                direction: .sent,
                body: "sent-\(index)",
                timestamp: Date(timeIntervalSince1970: 1_771_200_000 + Double(index)),
                counter: UInt64(index)
            )
        })
        var conversation = makeConversation(messages: projections)
        conversation.unreadCount = 1
        XCTAssertTrue(conversation.isStructurallyValid)

        conversation.appendProjectedMessage(
            Message(
                direction: .sent,
                body: "newest sent",
                timestamp: Date(timeIntervalSince1970: 1_771_300_000),
                counter: UInt64(maximum)
            )
        )

        XCTAssertEqual(conversation.messages.count, maximum)
        XCTAssertEqual(conversation.unreadCount, 0)
        XCTAssertTrue(conversation.isStructurallyValid)
    }

    private func makeMessage() -> Message {
        Message(
            id: UUID(uuidString: "E5C22757-5D8E-4F67-A2C1-73092E5B5E8E")!,
            direction: .received,
            body: "hello",
            timestamp: Date(timeIntervalSince1970: 1_771_200_000),
            counter: 1
        )
    }

    private func makeDescriptor() -> AttachmentDescriptor {
        AttachmentDescriptor(
            id: UUID(uuidString: "18C75395-8864-4246-A20C-B36575D54254")!,
            fileName: nil,
            mimeType: "application/octet-stream",
            byteCount: 1,
            sha256: Data(repeating: 0x22, count: 32),
            chunkCount: 1,
            chunkSize: 1,
            relayTTLSeconds: nil
        )
    }

    private func makeConversation(messages: [Message]) -> Conversation {
        let relationshipID = UUID()
        return Conversation(
            id: relationshipID.uuidString.lowercased(),
            relationshipID: relationshipID,
            endpointSession: DirectEndpointSessionIdentity(
                relationshipID: relationshipID,
                localEndpointHandle: .generate(relationshipId: relationshipID),
                localBindingReferenceDigest: Data(repeating: 0x11, count: 32),
                peerEndpointHandle: .generate(relationshipId: relationshipID),
                peerBindingReferenceDigest: Data(repeating: 0x22, count: 32)
            ),
            sessionId: "session-v1",
            rootKey: Data(repeating: 0x33, count: 32),
            sendChain: ChainKeyState(keyData: Data(repeating: 0x44, count: 32)),
            receiveChain: ChainKeyState(keyData: Data(repeating: 0x55, count: 32)),
            messages: messages,
            unreadCount: 0,
            ratchetState: .active
        )
    }

    private func jsonObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
    }

    private func jsonData(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
}
