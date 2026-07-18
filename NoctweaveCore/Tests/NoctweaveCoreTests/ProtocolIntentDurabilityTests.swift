import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class ProtocolIntentDurabilityTests: XCTestCase {
    private let origin = Date(timeIntervalSince1970: 1_900_100_000)

    func testAttemptSixtyFourExhaustsAndAttemptSixtyFiveNeverStarts() throws {
        var intent = ProtocolIntentV2.prepare(
            id: UUID(uuidString: "00000000-0000-4000-8000-000000000001")!,
            kind: .sendEvent,
            payloadDigest: Data(repeating: 0xA1, count: 32),
            createdAt: origin
        )

        for attemptNumber in 1...NoctweaveArchitectureV2.maximumIntentAttempts {
            let attemptID = UUID(
                uuidString: String(
                    format: "00000000-0000-4000-8000-%012d",
                    attemptNumber + 1
                )
            )!
            let attemptedAt = origin.addingTimeInterval(TimeInterval(attemptNumber * 10))
            intent = try XCTUnwrap(intent.beginningAttempt(
                id: attemptID,
                completedIntentIds: [],
                at: attemptedAt
            ))
            XCTAssertEqual(intent.attemptCount, UInt32(attemptNumber))

            if attemptNumber < NoctweaveArchitectureV2.maximumIntentAttempts {
                intent = try XCTUnwrap(intent.recordingTransientFailure(
                    attemptId: attemptID,
                    errorClass: .networkUnavailable,
                    retryNotBefore: attemptedAt.addingTimeInterval(2),
                    at: attemptedAt.addingTimeInterval(1)
                ))
            }
        }

        let sixtyFifthID = UUID(uuidString: "00000000-0000-4000-8000-000000000066")!
        XCTAssertNil(intent.beginningAttempt(
            id: sixtyFifthID,
            completedIntentIds: [],
            at: origin.addingTimeInterval(1_000)
        ))

        let exhausted = try XCTUnwrap(
            intent.exhaustingAttempts(at: origin.addingTimeInterval(1_000))
        )
        XCTAssertEqual(exhausted.state, .permanentFailure)
        XCTAssertEqual(exhausted.lastErrorClass, .attemptLimitExceeded)
        XCTAssertEqual(
            exhausted.attemptCount,
            UInt32(NoctweaveArchitectureV2.maximumIntentAttempts)
        )
        XCTAssertNil(exhausted.beginningAttempt(
            id: sixtyFifthID,
            completedIntentIds: [],
            at: origin.addingTimeInterval(1_001)
        ))
    }

    func testDurableBackoffAndExpiryGateFutureAttempts() throws {
        let attemptID = UUID(uuidString: "10000000-0000-4000-8000-000000000001")!
        let expiresAt = origin.addingTimeInterval(30)
        var intent = ProtocolIntentV2.prepare(
            kind: .rolloverRoute,
            payloadDigest: Data(repeating: 0xB2, count: 32),
            createdAt: origin,
            expiresAt: expiresAt
        )
        intent = try XCTUnwrap(intent.beginningAttempt(
            id: attemptID,
            completedIntentIds: [],
            at: origin.addingTimeInterval(1)
        ))
        intent = try XCTUnwrap(intent.recordingTransientFailure(
            attemptId: attemptID,
            errorClass: .relayUnavailable,
            retryNotBefore: origin.addingTimeInterval(10),
            at: origin.addingTimeInterval(2)
        ))

        XCTAssertFalse(intent.isReady(
            completedIntentIds: [],
            at: origin.addingTimeInterval(9.999)
        ))
        XCTAssertTrue(intent.isReady(
            completedIntentIds: [],
            at: origin.addingTimeInterval(10)
        ))
        XCTAssertNil(intent.beginningAttempt(
            id: UUID(),
            completedIntentIds: [],
            at: origin.addingTimeInterval(9.999)
        ))

        let expired = try XCTUnwrap(intent.expiring(at: expiresAt))
        XCTAssertEqual(expired.state, .permanentFailure)
        XCTAssertEqual(expired.lastErrorClass, .expired)
        XCTAssertNil(expired.nextAttemptNotBefore)
        XCTAssertFalse(expired.isReady(
            completedIntentIds: [],
            at: expiresAt.addingTimeInterval(1)
        ))
    }

    func testPerRouteIntentLinkageSurvivesStrictRoundTrip() throws {
        var relationship = try makeRelationship()
        let eventID = UUID(uuidString: "20000000-0000-4000-8000-000000000001")!
        let event = ConversationEvent(
            id: eventID,
            conversationId: relationship.conversationID,
            authorEndpointHandle: relationship.localEndpointHandle,
            createdAt: origin.addingTimeInterval(2),
            kind: .application,
            content: try XCTUnwrap(.text("intent linkage"))
        )
        _ = try relationship.appendEvent(event)
        let created = try MessageEngine.createOutboundEndpointSession(
            relationship: relationship,
            now: origin.addingTimeInterval(2)
        )
        var conversation = created.conversation
        let envelope = try MessageEngine.encryptDirectV4(
            wirePayload: .application(event),
            eventID: eventID,
            relationship: relationship,
            conversation: &conversation,
            bootstrap: .signedPrekey(
                kemCiphertext: created.kemCiphertext,
                prekey: created.prekey
            ),
            sentAt: origin.addingTimeInterval(2)
        )
        let payload = try NoctweaveCoder.encode(envelope, sortedKeys: true)
        let deliveries = try relationship.enqueue(
            logicalEventID: eventID,
            payload: payload,
            expiresAt: origin.addingTimeInterval(3_600),
            at: origin.addingTimeInterval(2)
        )

        XCTAssertFalse(deliveries.isEmpty)
        for delivery in deliveries {
            XCTAssertEqual(delivery.id, delivery.intentID)
            let intent = try XCTUnwrap(relationship.protocolIntents.first {
                $0.id == delivery.intentID
            })
            XCTAssertEqual(intent.kind, .sendEvent)
            XCTAssertEqual(
                intent.targetIdentifier,
                Data(eventID.uuidString.lowercased().utf8)
            )
            XCTAssertEqual(intent.payloadDigest, delivery.payloadDigest)
        }

        let encoded = try NoctweaveCoder.encode(relationship, sortedKeys: true)
        let decoded = try NoctweaveCoder.decode(
            PairwiseRelationshipV2.self,
            from: encoded
        )
        XCTAssertEqual(decoded, relationship)
        XCTAssertEqual(decoded.pendingDeliveries, deliveries)

        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        var pending = try XCTUnwrap(object["pendingDeliveries"] as? [[String: Any]])
        pending[0]["intentID"] = UUID().uuidString.lowercased()
        object["pendingDeliveries"] = pending
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            PairwiseRelationshipV2.self,
            from: JSONSerialization.data(withJSONObject: object)
        ))
    }

    func testStrictDecodeRejectsPendingRolloverBeyondCombinedRouteCapacity() throws {
        let relationship = try makeRelationshipWithMaximumLocalRoutes()
        XCTAssertEqual(
            relationship.localReceiveRoutes.count,
            PairwiseRelationshipV2.maximumReceiveRoutes
        )
        XCTAssertTrue(relationship.pendingRouteRollovers.isEmpty)

        let pending = try PendingLocalOpaqueReceiveRouteV2.prepare(
            relay: offlineRelay(host: "overflow.offline.invalid"),
            createdAt: origin.addingTimeInterval(3)
        )
        let requestBytes = try NoctweaveCoder.encode(
            pending.createRequest,
            sortedKeys: true
        )
        let intent = ProtocolIntentV2.prepare(
            kind: .rolloverRoute,
            targetIdentifier: pending.clientCapabilities.routeID.rawValue,
            expectedEpoch: relationship.localAdvertisedRoutes.revision + 1,
            idempotencyKey: ProtocolIntentIdempotencyKeyV2(
                rawValue: pending.createRequest.idempotencyKey.rawValue
            ),
            payloadDigest: Data(SHA256.hash(data: requestBytes)),
            createdAt: origin.addingTimeInterval(3),
            expiresAt: pending.createRequest.lease.expiresAt
        )

        var object = try jsonObject(relationship)
        object["pendingRouteRollovers"] = [try jsonObject(pending)]
        object["protocolIntents"] = [try jsonObject(intent)]
        assertRelationshipDecodeRejected(object)
    }

    func testStrictDecodeRejectsUnrelatedRouteAndBlobPayloadDigests() throws {
        let fixture = try makeArtifactLinkageFixture()
        let wrongRoute = replacing(
            fixture.routeIntent,
            payloadDigest: Data(repeating: 0xD1, count: 32),
            expectedEpoch: fixture.routeIntent.expectedEpoch,
            expiresAt: fixture.routeIntent.expiresAt
        )
        assertRelationshipDecodeRejected(try object(
            fixture.relationship,
            replacing: wrongRoute
        ))

        let wrongBlob = replacing(
            fixture.blobIntent,
            payloadDigest: Data(repeating: 0xD2, count: 32),
            expectedEpoch: fixture.blobIntent.expectedEpoch,
            expiresAt: fixture.blobIntent.expiresAt
        )
        assertRelationshipDecodeRejected(try object(
            fixture.relationship,
            replacing: wrongBlob
        ))
    }

    func testStrictDecodeRejectsDuplicateMatchingArtifactIntents() throws {
        let fixture = try makeArtifactLinkageFixture()
        let duplicateRoute = ProtocolIntentV2.prepare(
            kind: .rolloverRoute,
            targetIdentifier: fixture.routeIntent.targetIdentifier,
            expectedEpoch: fixture.routeIntent.expectedEpoch,
            payloadDigest: fixture.routeIntent.payloadDigest,
            createdAt: fixture.routeIntent.createdAt,
            expiresAt: fixture.routeIntent.expiresAt
        )
        assertRelationshipDecodeRejected(try object(
            fixture.relationship,
            appending: duplicateRoute
        ))

        let duplicateBlob = ProtocolIntentV2.prepare(
            kind: .uploadBlob,
            targetIdentifier: fixture.blobIntent.targetIdentifier,
            payloadDigest: fixture.blobIntent.payloadDigest,
            createdAt: fixture.blobIntent.createdAt,
            expiresAt: fixture.blobIntent.expiresAt
        )
        assertRelationshipDecodeRejected(try object(
            fixture.relationship,
            appending: duplicateBlob
        ))
    }

    func testStrictDecodeRejectsWrongRolloverEpochAndExpiryLinkage() throws {
        let fixture = try makeArtifactLinkageFixture()
        let wrongEpoch = replacing(
            fixture.routeIntent,
            payloadDigest: fixture.routeIntent.payloadDigest,
            expectedEpoch: try XCTUnwrap(fixture.routeIntent.expectedEpoch) + 1,
            expiresAt: fixture.routeIntent.expiresAt
        )
        assertRelationshipDecodeRejected(try object(
            fixture.relationship,
            replacing: wrongEpoch
        ))

        let wrongExpiry = replacing(
            fixture.routeIntent,
            payloadDigest: fixture.routeIntent.payloadDigest,
            expectedEpoch: fixture.routeIntent.expectedEpoch,
            expiresAt: try XCTUnwrap(fixture.routeIntent.expiresAt)
                .addingTimeInterval(-1)
        )
        assertRelationshipDecodeRejected(try object(
            fixture.relationship,
            replacing: wrongExpiry
        ))
    }

    func testStrictDecodeRejectsMissingCyclicAndFailedDependencies() throws {
        let fixture = try makeArtifactLinkageFixture()

        let missing = replacingDependencies(
            fixture.blobIntent,
            dependencies: [UUID()]
        )
        assertRelationshipDecodeRejected(try object(
            fixture.relationship,
            replacing: [missing]
        ))

        let cyclicRoute = replacingDependencies(
            fixture.routeIntent,
            dependencies: [fixture.blobIntent.id]
        )
        let cyclicBlob = replacingDependencies(
            fixture.blobIntent,
            dependencies: [fixture.routeIntent.id]
        )
        assertRelationshipDecodeRejected(try object(
            fixture.relationship,
            replacing: [cyclicRoute, cyclicBlob]
        ))

        let failedRoute = try XCTUnwrap(
            fixture.routeIntent.failingPermanently(
                errorClass: .invalidPayload,
                at: fixture.routeIntent.updatedAt
            )
        )
        let dependentBlob = replacingDependencies(
            fixture.blobIntent,
            dependencies: [failedRoute.id]
        )
        assertRelationshipDecodeRejected(try object(
            fixture.relationship,
            replacing: [failedRoute, dependentBlob]
        ))
    }

    private struct ArtifactLinkageFixture {
        let relationship: PairwiseRelationshipV2
        let routeIntent: ProtocolIntentV2
        let blobIntent: ProtocolIntentV2
    }

    private func makeArtifactLinkageFixture() throws -> ArtifactLinkageFixture {
        var relationship = try makeRelationship()
        let routeQueuedAt = origin.addingTimeInterval(4)
        let pendingRoute = try PendingLocalOpaqueReceiveRouteV2.prepare(
            relay: offlineRelay(host: "linked-route.offline.invalid"),
            createdAt: routeQueuedAt
        )
        let routeIntent = ProtocolIntentV2.prepare(
            kind: .rolloverRoute,
            targetIdentifier: pendingRoute.clientCapabilities.routeID.rawValue,
            expectedEpoch: relationship.localAdvertisedRoutes.revision + 1,
            idempotencyKey: ProtocolIntentIdempotencyKeyV2(
                rawValue: pendingRoute.createRequest.idempotencyKey.rawValue
            ),
            payloadDigest: Data(SHA256.hash(data: try NoctweaveCoder.encode(
                pendingRoute.createRequest,
                sortedKeys: true
            ))),
            createdAt: routeQueuedAt,
            expiresAt: pendingRoute.createRequest.lease.expiresAt
        )
        relationship.pendingRouteRollovers.append(pendingRoute)
        _ = try relationship.appendProtocolIntent(routeIntent)

        let blobQueuedAt = origin.addingTimeInterval(5)
        let request = UploadAttachmentRequest(
            attachmentId: UUID(uuidString: "40000000-0000-4000-8000-000000000001")!,
            chunkIndex: 2,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x51, count: EncryptedPayload.nonceByteCount),
                ciphertext: Data(repeating: 0x52, count: 64),
                tag: Data(repeating: 0x53, count: EncryptedPayload.tagByteCount)
            ),
            ttlSeconds: 600,
            idempotencyKey: Data(
                repeating: 0x54,
                count: UploadAttachmentRequest.idempotencyKeyBytes
            )
        )
        let pendingBlob = try PendingAttachmentUploadV2(
            relationshipID: relationship.id,
            relay: offlineRelay(host: "linked-blob.offline.invalid"),
            request: request,
            queuedAt: blobQueuedAt
        )
        let blobIntent = ProtocolIntentV2.prepare(
            kind: .uploadBlob,
            targetIdentifier: Data(pendingBlob.id.uuidString.lowercased().utf8),
            idempotencyKey: ProtocolIntentIdempotencyKeyV2(
                rawValue: request.idempotencyKey
            ),
            payloadDigest: Data(SHA256.hash(data: try NoctweaveCoder.encode(
                request,
                sortedKeys: true
            ))),
            createdAt: blobQueuedAt,
            expiresAt: blobQueuedAt.addingTimeInterval(600)
        )
        relationship.pendingAttachmentUploads.append(pendingBlob)
        _ = try relationship.appendProtocolIntent(blobIntent)
        XCTAssertTrue(relationship.isStructurallyValid)
        return ArtifactLinkageFixture(
            relationship: relationship,
            routeIntent: routeIntent,
            blobIntent: blobIntent
        )
    }

    private func makeRelationshipWithMaximumLocalRoutes() throws
        -> PairwiseRelationshipV2 {
        var relationship = try makeRelationship()
        var routes = relationship.localReceiveRoutes
        while routes.count < PairwiseRelationshipV2.maximumReceiveRoutes {
            let pending = try PendingLocalOpaqueReceiveRouteV2.prepare(
                relay: offlineRelay(
                    host: "local-\(routes.count).offline.invalid"
                ),
                createdAt: origin
            )
            let created = try OpaqueReceiveRouteV2.creating(
                from: pending.createRequest,
                presentedRenewCapability: pending.clientCapabilities.renewCapability,
                existing: nil,
                confidentialTransport: true,
                receivedAt: origin
            )
            routes.append(try pending.activate(createdRoute: created))
        }
        relationship.localReceiveRoutes = routes
        relationship.localAdvertisedRoutes = try PairwiseRouteSetV2.create(
            relationshipID: relationship.id,
            ownerEndpointHandle: relationship.localEndpointHandle,
            activeRoutes: try routes.map { try $0.peerSendRoute() },
            issuedAt: origin.addingTimeInterval(1),
            signingKey: relationship.localIdentity.localEndpoint.signingKey
        )
        XCTAssertTrue(relationship.isStructurallyValid)
        return relationship
    }

    private func replacing(
        _ intent: ProtocolIntentV2,
        payloadDigest: Data,
        expectedEpoch: UInt64?,
        expiresAt: Date?
    ) -> ProtocolIntentV2 {
        ProtocolIntentV2(
            id: intent.id,
            kind: intent.kind,
            targetIdentifier: intent.targetIdentifier,
            expectedEpoch: expectedEpoch,
            idempotencyKey: intent.idempotencyKey,
            payloadDigest: payloadDigest,
            dependencies: intent.dependencies,
            state: intent.state,
            attemptCount: intent.attemptCount,
            lastAttemptId: intent.lastAttemptId,
            lastAttemptAt: intent.lastAttemptAt,
            lastErrorClass: intent.lastErrorClass,
            nextAttemptNotBefore: intent.nextAttemptNotBefore,
            createdAt: intent.createdAt,
            updatedAt: intent.updatedAt,
            expiresAt: expiresAt
        )
    }

    private func replacingDependencies(
        _ intent: ProtocolIntentV2,
        dependencies: [UUID]
    ) -> ProtocolIntentV2 {
        ProtocolIntentV2(
            id: intent.id,
            kind: intent.kind,
            targetIdentifier: intent.targetIdentifier,
            expectedEpoch: intent.expectedEpoch,
            idempotencyKey: intent.idempotencyKey,
            payloadDigest: intent.payloadDigest,
            dependencies: dependencies,
            state: intent.state,
            attemptCount: intent.attemptCount,
            lastAttemptId: intent.lastAttemptId,
            lastAttemptAt: intent.lastAttemptAt,
            lastErrorClass: intent.lastErrorClass,
            nextAttemptNotBefore: intent.nextAttemptNotBefore,
            createdAt: intent.createdAt,
            updatedAt: intent.updatedAt,
            expiresAt: intent.expiresAt
        )
    }

    private func object(
        _ relationship: PairwiseRelationshipV2,
        replacing replacement: ProtocolIntentV2
    ) throws -> [String: Any] {
        var object = try jsonObject(relationship)
        var intents = try XCTUnwrap(object["protocolIntents"] as? [[String: Any]])
        let index = try XCTUnwrap(intents.firstIndex {
            ($0["id"] as? String)?.lowercased()
                == replacement.id.uuidString.lowercased()
        })
        intents[index] = try jsonObject(replacement)
        object["protocolIntents"] = intents
        return object
    }

    private func object(
        _ relationship: PairwiseRelationshipV2,
        appending intent: ProtocolIntentV2
    ) throws -> [String: Any] {
        var object = try jsonObject(relationship)
        var intents = try XCTUnwrap(object["protocolIntents"] as? [[String: Any]])
        intents.append(try jsonObject(intent))
        object["protocolIntents"] = intents
        return object
    }

    private func object(
        _ relationship: PairwiseRelationshipV2,
        replacing replacements: [ProtocolIntentV2]
    ) throws -> [String: Any] {
        var object = try jsonObject(relationship)
        var intents = try XCTUnwrap(object["protocolIntents"] as? [[String: Any]])
        for replacement in replacements {
            let index = try XCTUnwrap(intents.firstIndex {
                ($0["id"] as? String)?.lowercased()
                    == replacement.id.uuidString.lowercased()
            })
            intents[index] = try jsonObject(replacement)
        }
        object["protocolIntents"] = intents
        return object
    }

    private func assertRelationshipDecodeRejected(
        _ object: [String: Any],
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                PairwiseRelationshipV2.self,
                from: JSONSerialization.data(withJSONObject: object)
            ),
            file: file,
            line: line
        )
    }

    private func jsonObject<T: Encodable>(_ value: T) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: NoctweaveCoder.encode(value, sortedKeys: true)
            ) as? [String: Any]
        )
    }

    private func makeRelationship() throws -> PairwiseRelationshipV2 {
        let offer = try ContactPairingHandshakeV2.makeOffer(
            createdAt: origin,
            expiresAt: origin.addingTimeInterval(300)
        )
        var pendingOffer = offer.pending
        var ledger = RendezvousRedemptionLedgerV2()
        let result = try ContactPairingHandshakeV2.establish(
            pendingOffer: &pendingOffer,
            invitation: offer.invitation,
            offerer: try makeParticipant(name: "A", host: "a.offline.invalid"),
            responder: try makeParticipant(name: "B", host: "b.offline.invalid"),
            ledger: &ledger,
            at: origin.addingTimeInterval(1)
        )
        return result.offererRelationship
    }

    private func makeParticipant(
        name: String,
        host: String
    ) throws -> PreparedContactParticipantV2 {
        let pending = try PendingContactParticipantV2.prepare(
            relationshipPseudonym: name,
            relay: RelayEndpoint(
                host: host,
                port: 443,
                useTLS: true,
                transport: .websocket
            ),
            createdAt: origin
        )
        let route = try OpaqueReceiveRouteV2.creating(
            from: pending.routeCreateRequest,
            presentedRenewCapability: pending.clientCapabilities.renewCapability,
            existing: nil,
            confidentialTransport: true,
            receivedAt: origin
        )
        return try pending.activate(createdRoute: route)
    }

    private func offlineRelay(host: String) -> RelayEndpoint {
        RelayEndpoint(
            host: host,
            port: 443,
            useTLS: true,
            transport: .websocket
        )
    }
}
