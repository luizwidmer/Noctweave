import CryptoKit
import XCTest
@testable import NoctweaveCore

final class WirePayloadV2Tests: XCTestCase {
    private let relationshipID = UUID(uuidString: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")!
    private let eventID = UUID(uuidString: "11111111-2222-4333-8444-555555555555")!
    private let transactionID = UUID(uuidString: "99999999-8888-4777-8666-555555555555")!
    private let timestamp = Date(timeIntervalSince1970: 1_800_000_000)

    func testApplicationPayloadRoundTripsOnlyImmutableTypedEvent() throws {
        let handle = endpointHandle(marker: 0x11)
        let payload = try WirePayloadV2.projectingMessageBody(
            .text("pairwise message"),
            eventId: eventID,
            clientTransactionId: transactionID,
            conversationId: relationshipID.uuidString.lowercased(),
            authorEndpointHandle: handle,
            createdAt: timestamp
        )

        XCTAssertEqual(payload.kind, .application)
        XCTAssertNil(payload.control)
        XCTAssertEqual(payload.application?.id, eventID)
        XCTAssertNotEqual(payload.application?.id, payload.application?.clientTransactionId)
        XCTAssertEqual(try payload.applicationProjection(), .text("pairwise message"))
        try payload.validateDirectV4(
            eventId: eventID,
            senderEndpointHandle: handle,
            conversationId: relationshipID.uuidString.lowercased(),
            sentAt: timestamp
        )

        let encoded = try NoctweaveCoder.encode(payload, sortedKeys: true)
        XCTAssertEqual(try NoctweaveCoder.decode(WirePayloadV2.self, from: encoded), payload)
        var object = try jsonObject(encoded)
        object["identityRotation"] = true
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            WirePayloadV2.self,
            from: try JSONSerialization.data(withJSONObject: object)
        ))
    }

    func testMessageBodyIsOnlyLocalTextOrAttachmentProjection() throws {
        let descriptor = AttachmentDescriptor(
            fileName: nil,
            mimeType: "application/octet-stream",
            byteCount: 3,
            sha256: Data(SHA256.hash(data: Data([1, 2, 3]))),
            chunkCount: 1,
            chunkSize: 3
        )
        for body in [MessageBody.text("hello"), .attachment(descriptor)] {
            let encoded = try NoctweaveCoder.encode(body, sortedKeys: true)
            XCTAssertEqual(try NoctweaveCoder.decode(MessageBody.self, from: encoded), body)
        }

        var foreign = try jsonObject(NoctweaveCoder.encode(MessageBody.text("hello")))
        foreign["identityReset"] = true
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            MessageBody.self,
            from: try JSONSerialization.data(withJSONObject: foreign)
        ))
    }

    func testRelationshipControlHasIndependentSignatureAndCannotCrossRelationships() throws {
        let signingKey = try SigningKeyPair.generate()
        let sender = endpointHandle(marker: 0x22)
        let control = try AuthenticatedRelationshipControlV2.create(
            kind: .sessionReset,
            payload: SessionReset(initiatedAt: timestamp),
            relationshipID: relationshipID,
            eventID: eventID,
            senderEndpointHandle: sender,
            issuedAt: timestamp,
            signingKey: signingKey,
            nonce: transactionID
        )
        XCTAssertTrue(control.verify(
            relationshipID: relationshipID,
            senderEndpointHandle: sender,
            eventID: eventID,
            signingPublicKey: signingKey.publicKeyData
        ))
        XCTAssertTrue(try control.verifyThrowing(
            relationshipID: relationshipID,
            senderEndpointHandle: sender,
            eventID: eventID,
            signingPublicKey: signingKey.publicKeyData
        ))
        XCTAssertFalse(control.verify(
            relationshipID: UUID(),
            senderEndpointHandle: sender,
            eventID: eventID,
            signingPublicKey: signingKey.publicKeyData
        ))
        XCTAssertFalse(try control.verifyThrowing(
            relationshipID: UUID(),
            senderEndpointHandle: sender,
            eventID: eventID,
            signingPublicKey: signingKey.publicKeyData
        ))
        XCTAssertFalse(try control.verifyThrowing(
            relationshipID: relationshipID,
            senderEndpointHandle: sender,
            eventID: eventID,
            signingPublicKey: Data([0x01])
        ))
        XCTAssertFalse(control.verify(
            relationshipID: relationshipID,
            senderEndpointHandle: endpointHandle(marker: 0x23),
            eventID: eventID,
            signingPublicKey: signingKey.publicKeyData
        ))

        let payload = try WirePayloadV2.control(control)
        try payload.validateDirectV4(
            eventId: eventID,
            senderEndpointHandle: sender,
            conversationId: relationshipID.uuidString.lowercased(),
            sentAt: timestamp,
            signingPublicKey: signingKey.publicKeyData
        )
        guard case .control(.sessionReset(let reset), let audit) = try payload.controlDisposition(
            conversationId: relationshipID.uuidString.lowercased(),
            eventId: eventID,
            senderEndpointHandle: sender,
            sentAt: timestamp,
            receivedAt: timestamp,
            signingPublicKey: signingKey.publicKeyData
        ) else {
            return XCTFail("Expected authenticated relationship reset")
        }
        XCTAssertEqual(reset.initiatedAt, timestamp)
        XCTAssertEqual(audit.kind, .control)
        XCTAssertEqual(audit.id, eventID)
    }

    func testContinuityOfferIsExplicitlyScopedToOneRelationship() throws {
        let invitation = try ContactPairingHandshakeV2.makeOffer(
            createdAt: timestamp,
            expiresAt: timestamp.addingTimeInterval(300)
        ).invitation
        let signingKey = try SigningKeyPair.generate()
        let sender = endpointHandle(marker: 0x31)
        let scoped = RelationshipContinuityOfferV2(
            relationshipID: relationshipID,
            invitation: invitation,
            expiresAt: invitation.offer.expiresAt
        )
        let control = try AuthenticatedRelationshipControlV2.create(
            kind: .continuityOffer,
            payload: scoped,
            relationshipID: relationshipID,
            eventID: eventID,
            senderEndpointHandle: sender,
            issuedAt: timestamp,
            signingKey: signingKey
        )
        XCTAssertEqual(try control.decodeKnown(), .continuityOffer(scoped))

        let wrongScope = RelationshipContinuityOfferV2(
            relationshipID: UUID(),
            invitation: invitation,
            expiresAt: invitation.offer.expiresAt
        )
        let rejected = try AuthenticatedRelationshipControlV2.create(
            kind: .continuityOffer,
            payload: wrongScope,
            relationshipID: relationshipID,
            eventID: UUID(),
            senderEndpointHandle: sender,
            issuedAt: timestamp,
            signingKey: signingKey
        )
        XCTAssertThrowsError(try rejected.decodeKnown()) { error in
            XCTAssertEqual(error as? WirePayloadV2Error, .invalidKnownControl)
        }
    }

    func testRouteProbeAndPrekeyUpdateStayRelationshipScoped() throws {
        let signingKey = try SigningKeyPair.generate()
        let sender = endpointHandle(marker: 0x35)
        let routeMaterial = try OpaqueRouteClientCapabilityMaterialV2()
        let probe = RelationshipRouteProbeV2(
            relationshipID: relationshipID,
            routeID: routeMaterial.routeID,
            routeSetRevision: 1,
            nonce: transactionID
        )
        let probeControl = try AuthenticatedRelationshipControlV2.create(
            kind: .routeProbe,
            payload: probe,
            relationshipID: relationshipID,
            eventID: eventID,
            senderEndpointHandle: sender,
            issuedAt: timestamp,
            signingKey: signingKey
        )
        XCTAssertEqual(try probeControl.decodeKnown(), .routeProbe(probe))

        let local = try LocalPairwiseIdentityV2.generate(
            relationshipPseudonym: "one relationship",
            createdAt: timestamp
        )
        let prekey = RelationshipEndpointPrekeyUpdateV2(
            relationshipID: relationshipID,
            endpointBinding: local.endpointBinding
        )
        let prekeyControl = try AuthenticatedRelationshipControlV2.create(
            kind: .endpointPrekeyUpdate,
            payload: prekey,
            relationshipID: relationshipID,
            eventID: UUID(),
            senderEndpointHandle: sender,
            issuedAt: timestamp,
            signingKey: signingKey
        )
        XCTAssertEqual(
            try prekeyControl.decodeKnown(),
            .endpointPrekeyUpdate(prekey)
        )

        let wrongScope = RelationshipRouteProbeV2(
            relationshipID: UUID(),
            routeID: routeMaterial.routeID,
            routeSetRevision: 1
        )
        let rejected = try AuthenticatedRelationshipControlV2.create(
            kind: .routeProbe,
            payload: wrongScope,
            relationshipID: relationshipID,
            eventID: UUID(),
            senderEndpointHandle: sender,
            issuedAt: timestamp,
            signingKey: signingKey
        )
        XCTAssertThrowsError(try rejected.decodeKnown())
    }

    func testUnknownApplicationContentIsPreservedWithoutProtocolAuthority() throws {
        let handle = endpointHandle(marker: 0x41)
        let visible = ConversationEvent(
            id: eventID,
            clientTransactionId: transactionID,
            conversationId: relationshipID.uuidString.lowercased(),
            authorEndpointHandle: handle,
            createdAt: timestamp,
            kind: .application,
            content: EncodedContent(
                type: ContentTypeId(
                    authority: "example.private",
                    name: "poll",
                    major: 1
                ),
                payload: Data([0x01]),
                fallbackText: "Unsupported poll",
                disposition: .visible
            )
        )
        guard case .unsupported(let unsupported) = try WirePayloadV2
            .application(visible)
            .applicationProjection() else {
            return XCTFail("Expected unsupported application projection")
        }
        XCTAssertEqual(unsupported.eventId, eventID)
        XCTAssertEqual(unsupported.fallbackText, "Unsupported poll")
        XCTAssertEqual(ApplicationContentProjectionV2.unsupported(unsupported).body, .text("Unsupported poll"))

        let silent = ConversationEvent(
            id: UUID(),
            clientTransactionId: UUID(),
            conversationId: relationshipID.uuidString.lowercased(),
            authorEndpointHandle: handle,
            createdAt: timestamp,
            kind: .application,
            content: EncodedContent(
                type: ContentTypeId(
                    authority: "example.private",
                    name: "typing",
                    major: 1
                ),
                payload: Data([0x02]),
                disposition: .silent
            )
        )
        guard case .unsupported(let silentUnsupported) = try WirePayloadV2
            .application(silent)
            .applicationProjection() else {
            return XCTFail("Expected silent unsupported application projection")
        }
        XCTAssertNil(ApplicationContentProjectionV2.unsupported(silentUnsupported).body)
    }

    func testDirectValidationRequiresRelationshipUUIDAsConversationID() throws {
        let handle = endpointHandle(marker: 0x51)
        let event = ConversationEvent(
            id: eventID,
            clientTransactionId: transactionID,
            conversationId: "global-profile-conversation",
            authorEndpointHandle: handle,
            createdAt: timestamp,
            kind: .application,
            content: try XCTUnwrap(EncodedContent.text("rejected"))
        )
        let payload = try WirePayloadV2.application(event)
        XCTAssertThrowsError(try payload.validateDirectV4(
            eventId: eventID,
            senderEndpointHandle: handle,
            conversationId: event.conversationId,
            sentAt: timestamp
        )) { error in
            XCTAssertEqual(error as? WirePayloadV2Error, .invalidPayload)
        }
    }

    private func endpointHandle(marker: UInt8) -> RelationshipEndpointHandle {
        RelationshipEndpointHandle(
            rawValue: Data(repeating: marker, count: 32).base64EncodedString()
        )
    }

    private func jsonObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }
}
