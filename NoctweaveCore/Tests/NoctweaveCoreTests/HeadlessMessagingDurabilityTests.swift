import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class HeadlessMessagingDurabilityTests: XCTestCase {
    private let origin = Date(timeIntervalSince1970: 1_900_200_000)

    func testPrepareSendPersistsChosenLocalEchoWithoutRelayIO() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let eventID = UUID(uuidString: "30000000-0000-4000-8000-000000000001")!
        let transactionID = UUID(uuidString: "30000000-0000-4000-8000-000000000002")!

        let prepared = try await harness.client.prepareSend(
            body: .text("durable local echo"),
            relationshipID: harness.relationshipID,
            eventID: eventID,
            clientTransactionID: transactionID,
            sentAt: origin.addingTimeInterval(2)
        )

        XCTAssertEqual(prepared.relationshipID, harness.relationshipID)
        XCTAssertEqual(prepared.event.id, eventID)
        XCTAssertEqual(prepared.event.clientTransactionId, transactionID)
        XCTAssertFalse(prepared.deliveryIDs.isEmpty)

        let current = try await harness.client.relationship(harness.relationshipID)
        XCTAssertTrue(current.events.contains(prepared.event))
        XCTAssertEqual(
            Set(current.pendingDeliveries.map(\.id)),
            Set(prepared.deliveryIDs)
        )
        XCTAssertTrue(prepared.deliveryIDs.allSatisfy { deliveryID in
            current.pendingDeliveries.contains {
                $0.id == deliveryID && $0.intentID == deliveryID
            } && current.protocolIntents.contains {
                $0.id == deliveryID && $0.state == .prepared
            }
        })

        let loaded = try await harness.store.load()
        let stored = try XCTUnwrap(loaded)
        let storedRelationship = try XCTUnwrap(
            stored.activePersona.relationships.first { $0.id == harness.relationshipID }
        )
        XCTAssertTrue(storedRelationship.events.contains(prepared.event))
        XCTAssertEqual(
            Set(storedRelationship.pendingDeliveries.map(\.id)),
            Set(prepared.deliveryIDs)
        )
    }

    func testReopenRetainsExactEventPacketsAndIntentLinkage() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let eventID = UUID(uuidString: "31000000-0000-4000-8000-000000000001")!
        let transactionID = UUID(uuidString: "31000000-0000-4000-8000-000000000002")!
        let prepared = try await harness.client.prepareSend(
            body: .text("restart-safe ciphertext"),
            relationshipID: harness.relationshipID,
            eventID: eventID,
            clientTransactionID: transactionID,
            sentAt: origin.addingTimeInterval(2)
        )
        let before = try await harness.client.relationship(harness.relationshipID)
        let beforeDeliveries = before.pendingDeliveries.filter {
            $0.logicalEventID == eventID
        }
        let beforeIntentIDs = beforeDeliveries.map(\.intentID)
        let beforePacketIDs = beforeDeliveries.flatMap { $0.packets.map(\.packetID) }

        let reopened = try await HeadlessMessagingClient.open(
            stateStore: harness.store,
            displayName: "ignored on reopen"
        )
        let after = try await reopened.relationship(harness.relationshipID)
        let afterDeliveries = after.pendingDeliveries.filter {
            $0.logicalEventID == eventID
        }

        XCTAssertEqual(after.events.first { $0.id == eventID }, prepared.event)
        XCTAssertEqual(afterDeliveries, beforeDeliveries)
        XCTAssertEqual(afterDeliveries.map(\.intentID), beforeIntentIDs)
        XCTAssertEqual(
            afterDeliveries.flatMap { $0.packets.map(\.packetID) },
            beforePacketIDs
        )
        XCTAssertTrue(afterDeliveries.allSatisfy { delivery in
            after.protocolIntents.contains {
                $0.id == delivery.intentID
                    && $0.payloadDigest == delivery.payloadDigest
                    && $0.state == .prepared
            }
        })
    }

    func testPreparedPublicationRejectsForgedEnvelopeAndDeliveryIDsBeforeIO() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let first = try await harness.client.prepareSend(
            body: .text("first"),
            relationshipID: harness.relationshipID,
            sentAt: origin.addingTimeInterval(2)
        )
        let second = try await harness.client.prepareSend(
            body: .text("second"),
            relationshipID: harness.relationshipID,
            sentAt: origin.addingTimeInterval(3)
        )

        let forgedDelivery = HeadlessPreparedSend(
            relationshipID: first.relationshipID,
            event: first.event,
            envelope: first.envelope,
            deliveryIDs: [UUID()]
        )
        await assertPreparedPublicationRejected(
            forgedDelivery,
            by: harness.client,
            at: origin.addingTimeInterval(4)
        )

        let forgedEnvelope = HeadlessPreparedSend(
            relationshipID: first.relationshipID,
            event: first.event,
            envelope: second.envelope,
            deliveryIDs: first.deliveryIDs
        )
        await assertPreparedPublicationRejected(
            forgedEnvelope,
            by: harness.client,
            at: origin.addingTimeInterval(4)
        )

        let current = try await harness.client.relationship(harness.relationshipID)
        XCTAssertEqual(
            Set(current.pendingDeliveries.map(\.id)),
            Set(first.deliveryIDs + second.deliveryIDs)
        )
        XCTAssertTrue(current.protocolIntents.allSatisfy { $0.attemptCount == 0 })
    }

    func testRouteRolloverPreparationPersistsExactRequestAndIntentBeforeIO() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let preparedAt = origin.addingTimeInterval(10)
        let pending = try await harness.client.prepareRouteRollover(
            relationshipID: harness.relationshipID,
            relay: offlineRelay(host: "rollover.offline.invalid"),
            createdAt: preparedAt
        )

        let loaded = try await harness.store.load()
        let stored = try XCTUnwrap(loaded)
        let relationship = try XCTUnwrap(
            stored.activePersona.relationships.first { $0.id == harness.relationshipID }
        )
        XCTAssertEqual(relationship.pendingRouteRollovers, [pending])
        let intent = try XCTUnwrap(relationship.protocolIntents.first {
            $0.kind == .rolloverRoute
                && $0.targetIdentifier == pending.clientCapabilities.routeID.rawValue
        })
        XCTAssertEqual(intent.state, .prepared)
        XCTAssertEqual(intent.attemptCount, 0)
        XCTAssertEqual(intent.expiresAt, pending.createRequest.lease.expiresAt)
        XCTAssertEqual(
            intent.payloadDigest,
            Data(SHA256.hash(data: try NoctweaveCoder.encode(
                pending.createRequest,
                sortedKeys: true
            )))
        )

        let roundTrip = try NoctweaveCoder.decode(
            PendingLocalOpaqueReceiveRouteV2.self,
            from: NoctweaveCoder.encode(pending, sortedKeys: true)
        )
        XCTAssertEqual(roundTrip.createRequest, pending.createRequest)
        XCTAssertEqual(roundTrip, pending)
    }

    func testEncryptedBlobUploadPreparationPersistsExactRequestAndIntent() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let request = UploadAttachmentRequest(
            attachmentId: UUID(uuidString: "32000000-0000-4000-8000-000000000001")!,
            chunkIndex: 7,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: EncryptedPayload.nonceByteCount),
                ciphertext: Data(repeating: 0x22, count: 96),
                tag: Data(repeating: 0x33, count: EncryptedPayload.tagByteCount)
            ),
            ttlSeconds: 600,
            idempotencyKey: Data(
                repeating: 0x44,
                count: UploadAttachmentRequest.idempotencyKeyBytes
            )
        )
        let queuedAt = origin.addingTimeInterval(20)
        let pending = try await harness.client.prepareAttachmentUpload(
            request,
            relay: offlineRelay(host: "blob.offline.invalid"),
            relationshipID: harness.relationshipID,
            at: queuedAt
        )

        let loaded = try await harness.store.load()
        let stored = try XCTUnwrap(loaded)
        let relationship = try XCTUnwrap(
            stored.activePersona.relationships.first { $0.id == harness.relationshipID }
        )
        XCTAssertEqual(relationship.pendingAttachmentUploads, [pending])
        XCTAssertEqual(pending.request, request)
        let intent = try XCTUnwrap(relationship.protocolIntents.first {
            $0.kind == .uploadBlob
                && $0.targetIdentifier
                    == Data(pending.id.uuidString.lowercased().utf8)
        })
        XCTAssertEqual(intent.state, .prepared)
        XCTAssertEqual(intent.attemptCount, 0)
        XCTAssertEqual(intent.expiresAt, queuedAt.addingTimeInterval(600))
        XCTAssertEqual(
            intent.payloadDigest,
            Data(SHA256.hash(data: try NoctweaveCoder.encode(request, sortedKeys: true)))
        )
    }

    func testConcurrentPrepareSendOnOneRelationshipRetainsBothAndRatchetState() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let firstEventID = UUID(uuidString: "33000000-0000-4000-8000-000000000001")!
        let secondEventID = UUID(uuidString: "33000000-0000-4000-8000-000000000002")!
        let firstTransactionID = UUID(uuidString: "33000000-0000-4000-8000-000000000003")!
        let secondTransactionID = UUID(uuidString: "33000000-0000-4000-8000-000000000004")!

        async let first = harness.client.prepareSend(
            body: .text("concurrent first"),
            relationshipID: harness.relationshipID,
            eventID: firstEventID,
            clientTransactionID: firstTransactionID,
            sentAt: origin.addingTimeInterval(30)
        )
        async let second = harness.client.prepareSend(
            body: .text("concurrent second"),
            relationshipID: harness.relationshipID,
            eventID: secondEventID,
            clientTransactionID: secondTransactionID,
            sentAt: origin.addingTimeInterval(30)
        )
        let (firstPrepared, secondPrepared) = try await (first, second)

        let current = try await harness.client.relationship(harness.relationshipID)
        XCTAssertEqual(
            Set(current.events.map(\.id)),
            Set([firstEventID, secondEventID])
        )
        XCTAssertEqual(
            Set(current.pendingDeliveries.map(\.id)),
            Set(firstPrepared.deliveryIDs + secondPrepared.deliveryIDs)
        )
        XCTAssertEqual(current.directSessions.count, 1)
        XCTAssertEqual(current.directSessions[0].sendChain.counter, 2)
        XCTAssertTrue(current.isStructurallyValid)

        let reopened = try await HeadlessMessagingClient.open(
            stateStore: harness.store,
            displayName: "ignored on reopen"
        )
        let restored = try await reopened.relationship(harness.relationshipID)
        XCTAssertEqual(restored.events, current.events)
        XCTAssertEqual(restored.pendingDeliveries, current.pendingDeliveries)
        XCTAssertEqual(restored.protocolIntents, current.protocolIntents)
        XCTAssertEqual(restored.directSessions, current.directSessions)
        XCTAssertEqual(restored.directSessions[0].sendChain.counter, 2)
    }

    func testConcurrentPrepareSendAcrossRelationshipsCannotClobberEither() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let secondRelationship = try makeRelationship()
        let personaScope = await harness.client.mintActivePersonaScopeToken()
        try await harness.client.addRelationship(
            secondRelationship,
            personaScope: personaScope
        )
        let firstEventID = UUID(uuidString: "34000000-0000-4000-8000-000000000001")!
        let secondEventID = UUID(uuidString: "34000000-0000-4000-8000-000000000002")!

        async let first = harness.client.prepareSend(
            body: .text("relationship one"),
            relationshipID: harness.relationshipID,
            eventID: firstEventID,
            sentAt: origin.addingTimeInterval(40)
        )
        async let second = harness.client.prepareSend(
            body: .text("relationship two"),
            relationshipID: secondRelationship.id,
            eventID: secondEventID,
            sentAt: origin.addingTimeInterval(40)
        )
        let (firstPrepared, secondPrepared) = try await (first, second)

        let firstRelationship = try await harness.client.relationship(harness.relationshipID)
        let persistedSecond = try await harness.client.relationship(secondRelationship.id)
        XCTAssertEqual(firstRelationship.events.map(\.id), [firstEventID])
        XCTAssertEqual(persistedSecond.events.map(\.id), [secondEventID])
        XCTAssertEqual(
            Set(firstRelationship.pendingDeliveries.map(\.id)),
            Set(firstPrepared.deliveryIDs)
        )
        XCTAssertEqual(
            Set(persistedSecond.pendingDeliveries.map(\.id)),
            Set(secondPrepared.deliveryIDs)
        )
        XCTAssertEqual(firstRelationship.directSessions.count, 1)
        XCTAssertEqual(persistedSecond.directSessions.count, 1)

        let reopened = try await HeadlessMessagingClient.open(
            stateStore: harness.store,
            displayName: "ignored on reopen"
        )
        let reopenedFirst = try await reopened.relationship(harness.relationshipID)
        let reopenedSecond = try await reopened.relationship(secondRelationship.id)
        XCTAssertEqual(reopenedFirst, firstRelationship)
        XCTAssertEqual(reopenedSecond, persistedSecond)
    }

    func testSecondUnfinishedRouteRolloverIsRejected() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let first = try await harness.client.prepareRouteRollover(
            relationshipID: harness.relationshipID,
            relay: offlineRelay(host: "first-rollover.offline.invalid"),
            createdAt: origin.addingTimeInterval(50)
        )

        do {
            _ = try await harness.client.prepareRouteRollover(
                relationshipID: harness.relationshipID,
                relay: offlineRelay(host: "second-rollover.offline.invalid"),
                createdAt: origin.addingTimeInterval(51)
            )
            XCTFail("A second unfinished rollover was accepted")
        } catch let error as HeadlessMessagingClientError {
            XCTAssertEqual(error, .invalidState)
        }

        let current = try await harness.client.relationship(harness.relationshipID)
        XCTAssertEqual(current.pendingRouteRollovers, [first])
        XCTAssertEqual(
            current.protocolIntents.filter {
                $0.kind == .rolloverRoute && !$0.state.isTerminal
            }.count,
            1
        )
    }

    func testStaleGroupRuntimeCannotPersistAfterPersonaBurn() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let record = try makeGroupRuntimeRecord(at: origin.addingTimeInterval(60))
        let personaScope = await harness.client.mintActivePersonaScopeToken()
        try await harness.client.addGroupRuntime(
            record,
            personaScope: personaScope
        )
        let staleRuntime = try await harness.client.openGroupRuntime(groupID: record.groupId)
        let replacement = try await harness.client.burnActivePersona(
            replacementDisplayName: "Unrelated replacement",
            at: origin.addingTimeInterval(70)
        )
        let event = GroupConversationEventV2(
            groupID: record.groupId,
            authorMemberHandle: record.localCredential.memberHandle,
            authorCredentialHandle: record.localCredential.credentialHandle,
            createdAt: origin.addingTimeInterval(71),
            kind: .application,
            content: try XCTUnwrap(.text("must not cross persona burn"))
        )

        do {
            _ = try await staleRuntime.prepareApplicationEvent(
                event,
                at: origin.addingTimeInterval(71)
            )
            XCTFail("A stale runtime wrote into the replacement persona")
        } catch {
            // The persistence capability is persona-bound and must be stale.
        }

        let snapshot = await harness.client.snapshot()
        XCTAssertEqual(snapshot.activePersonaID, replacement.id)
        XCTAssertTrue(snapshot.activePersona.groupRuntimes.isEmpty)
        let loaded = try await harness.store.load()
        XCTAssertTrue(try XCTUnwrap(loaded).activePersona.groupRuntimes.isEmpty)
    }

    func testTwoOpenGroupRuntimesUseCompareAndSwapInsteadOfOverwriting() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let record = try makeGroupRuntimeRecord(at: origin.addingTimeInterval(72))
        let personaScope = await harness.client.mintActivePersonaScopeToken()
        try await harness.client.addGroupRuntime(record, personaScope: personaScope)
        let first = try await harness.client.openGroupRuntime(groupID: record.groupId)
        let stale = try await harness.client.openGroupRuntime(groupID: record.groupId)

        let firstEvent = GroupConversationEventV2(
            groupID: record.groupId,
            authorMemberHandle: record.localCredential.memberHandle,
            authorCredentialHandle: record.localCredential.credentialHandle,
            createdAt: origin.addingTimeInterval(73),
            kind: .application,
            content: try XCTUnwrap(.text("first CAS winner"))
        )
        _ = try await first.prepareApplicationEvent(
            firstEvent,
            at: origin.addingTimeInterval(73)
        )
        let committed = await first.snapshot()

        let staleEvent = GroupConversationEventV2(
            groupID: record.groupId,
            authorMemberHandle: record.localCredential.memberHandle,
            authorCredentialHandle: record.localCredential.credentialHandle,
            createdAt: origin.addingTimeInterval(74),
            kind: .application,
            content: try XCTUnwrap(.text("must not overwrite winner"))
        )
        do {
            _ = try await stale.prepareApplicationEvent(
                staleEvent,
                at: origin.addingTimeInterval(74)
            )
            XCTFail("A stale group runtime overwrote newer durable state")
        } catch let error as HeadlessMessagingClientError {
            XCTAssertEqual(error, .staleGroupRuntime)
        }
        let staleSnapshot = await stale.snapshot()
        XCTAssertEqual(staleSnapshot, record)
        let clientSnapshot = await harness.client.snapshot()
        XCTAssertEqual(
            clientSnapshot.activePersona.groupRuntimes.first(where: {
                $0.groupId == record.groupId
            }),
            committed
        )

        let reopened = try await harness.client.openGroupRuntime(groupID: record.groupId)
        _ = try await reopened.prepareApplicationEvent(
            staleEvent,
            at: origin.addingTimeInterval(74)
        )
        let resumed = await reopened.snapshot()
        XCTAssertTrue(resumed.events.contains(firstEvent))
        XCTAssertTrue(resumed.events.contains(staleEvent))
    }

    func testPersonaScopeRejectsPreBurnInsertionsAndAcceptsCurrentScope() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let preBurnScope = await harness.client.mintActivePersonaScopeToken()
        let staleRelationship = try makeRelationship()
        let staleGroup = try makeGroupRuntimeRecord(at: origin.addingTimeInterval(75))
        let replacement = try await harness.client.burnActivePersona(
            replacementDisplayName: "Unrelated replacement",
            at: origin.addingTimeInterval(76)
        )

        do {
            try await harness.client.addRelationship(
                staleRelationship,
                consent: .accepted,
                personaScope: preBurnScope
            )
            XCTFail("A pre-burn relationship insertion resumed into the replacement persona")
        } catch let error as HeadlessMessagingClientError {
            XCTAssertEqual(error, .invalidState)
        }
        do {
            try await harness.client.addGroupRuntime(
                staleGroup,
                personaScope: preBurnScope
            )
            XCTFail("A pre-burn group insertion resumed into the replacement persona")
        } catch let error as HeadlessMessagingClientError {
            XCTAssertEqual(error, .invalidState)
        }

        var snapshot = await harness.client.snapshot()
        XCTAssertEqual(snapshot.activePersonaID, replacement.id)
        XCTAssertTrue(snapshot.activePersona.relationships.isEmpty)
        XCTAssertTrue(snapshot.activePersona.groupRuntimes.isEmpty)

        let currentScope = await harness.client.mintActivePersonaScopeToken()
        try await harness.client.addRelationship(
            staleRelationship,
            personaScope: currentScope
        )
        try await harness.client.addGroupRuntime(
            staleGroup,
            personaScope: currentScope
        )

        snapshot = await harness.client.snapshot()
        XCTAssertEqual(snapshot.activePersona.relationships, [staleRelationship])
        XCTAssertEqual(snapshot.activePersona.groupRuntimes, [staleGroup])
        let loadedState = try await harness.store.load()
        let loaded = try XCTUnwrap(loadedState)
        XCTAssertEqual(loaded.activePersonaID, replacement.id)
        XCTAssertEqual(loaded.activePersona.relationships, [staleRelationship])
        XCTAssertEqual(loaded.activePersona.groupRuntimes, [staleGroup])
    }

    func testConversationRejectsInvalidChainKeysAndDeliveryOrderingRoundTrips() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let first = try await harness.client.prepareSend(
            body: .text("counter zero"),
            relationshipID: harness.relationshipID,
            sentAt: origin.addingTimeInterval(80)
        )
        let second = try await harness.client.prepareSend(
            body: .text("counter one"),
            relationshipID: harness.relationshipID,
            sentAt: origin.addingTimeInterval(81)
        )
        let relationship = try await harness.client.relationship(harness.relationshipID)
        let session = try XCTUnwrap(relationship.directSessions.first)
        let deliveries = relationship.pendingDeliveries.sorted {
            $0.messageCounter < $1.messageCounter
        }

        XCTAssertEqual(deliveries.map(\.messageCounter), [0, 1])
        XCTAssertEqual(Set(deliveries.map(\.directSessionID)), [session.sessionId])
        XCTAssertEqual(
            deliveries.first { $0.logicalEventID == first.event.id }?.directSessionID,
            first.envelope.sessionId
        )
        XCTAssertEqual(
            deliveries.first { $0.logicalEventID == second.event.id }?.messageCounter,
            second.envelope.messageCounter
        )
        let decoded = try NoctweaveCoder.decode(
            PairwiseRelationshipV2.self,
            from: NoctweaveCoder.encode(relationship, sortedKeys: true)
        )
        XCTAssertEqual(decoded.pendingDeliveries, relationship.pendingDeliveries)
        XCTAssertEqual(decoded.directSessions, relationship.directSessions)

        for chainName in ["sendChain", "receiveChain"] {
            var object = try jsonObject(session)
            var chain = try XCTUnwrap(object[chainName] as? [String: Any])
            chain["keyData"] = Data(repeating: 0xA5, count: 31).base64EncodedString()
            object[chainName] = chain
            XCTAssertThrowsError(try NoctweaveCoder.decode(
                Conversation.self,
                from: JSONSerialization.data(withJSONObject: object)
            ))
        }
    }

    func testLaterCounterWaitsAndPublicationSeparatesPendingFromFailure() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let firstSentAt = origin.addingTimeInterval(90)
        let first = try await harness.client.prepareSend(
            body: .text("must publish first"),
            relationshipID: harness.relationshipID,
            sentAt: firstSentAt
        )
        let second = try await harness.client.prepareSend(
            body: .text("must wait"),
            relationshipID: harness.relationshipID,
            sentAt: firstSentAt.addingTimeInterval(1)
        )

        let waiting = try await harness.client.publishPreparedSend(
            second,
            at: firstSentAt.addingTimeInterval(2)
        )
        XCTAssertEqual(waiting.acceptedDeliveryCount, 0)
        XCTAssertEqual(waiting.pendingDeliveryCount, 1)
        XCTAssertEqual(waiting.failedDeliveryCount, 0)
        XCTAssertNil(waiting.nextRetryNotBefore)
        var current = try await harness.client.relationship(harness.relationshipID)
        XCTAssertEqual(
            Set(current.pendingDeliveries.map(\.id)),
            Set(first.deliveryIDs + second.deliveryIDs)
        )
        XCTAssertTrue(current.protocolIntents.allSatisfy { $0.attemptCount == 0 })

        let expired = try await harness.client.publishPreparedSend(
            first,
            at: firstSentAt.addingTimeInterval(24 * 60 * 60)
        )
        XCTAssertEqual(expired.acceptedDeliveryCount, 0)
        XCTAssertEqual(expired.pendingDeliveryCount, 0)
        XCTAssertEqual(expired.failedDeliveryCount, 1)
        XCTAssertNil(expired.nextRetryNotBefore)
        current = try await harness.client.relationship(harness.relationshipID)
        XCTAssertEqual(
            current.protocolIntents.first { $0.id == first.deliveryIDs[0] }?.state,
            .permanentFailure
        )
        XCTAssertEqual(
            current.protocolIntents.first { $0.id == second.deliveryIDs[0] }?.state,
            .prepared
        )
    }

    func testDiscardingFailedCounterResetsSessionAndFreshSendBootstraps() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let first = try await harness.client.prepareSend(
            body: .text("failed counter"),
            relationshipID: harness.relationshipID,
            sentAt: origin.addingTimeInterval(100)
        )
        let second = try await harness.client.prepareSend(
            body: .text("dependent counter"),
            relationshipID: harness.relationshipID,
            sentAt: origin.addingTimeInterval(101)
        )
        let oldSessionID = first.envelope.sessionId
        XCTAssertEqual(second.envelope.sessionId, oldSessionID)
        XCTAssertEqual(first.envelope.messageCounter, 0)
        XCTAssertEqual(second.envelope.messageCounter, 1)

        var failedRelationship = try await harness.client.relationship(
            harness.relationshipID
        )
        let failedIndex = try XCTUnwrap(failedRelationship.protocolIntents.firstIndex {
            $0.id == first.deliveryIDs[0]
        })
        failedRelationship.protocolIntents[failedIndex] = try XCTUnwrap(
            failedRelationship.protocolIntents[failedIndex].failingPermanently(
                errorClass: .invalidPayload,
                at: origin.addingTimeInterval(102)
            )
        )
        XCTAssertTrue(failedRelationship.isStructurallyValid)
        var failedState = await harness.client.snapshot()
        try failedState.updateActivePersona {
            try $0.upsert(relationship: failedRelationship)
        }
        try await harness.store.save(failedState)
        let resumed = try HeadlessMessagingClient(
            stateStore: harness.store,
            initialState: failedState
        )

        try await resumed.discardFailedDelivery(
            intentID: first.deliveryIDs[0],
            relationshipID: harness.relationshipID,
            at: origin.addingTimeInterval(103)
        )
        var current = try await resumed.relationship(harness.relationshipID)
        XCTAssertFalse(current.pendingDeliveries.contains {
            $0.intentID == first.deliveryIDs[0]
        })
        XCTAssertEqual(
            current.directSessions.first { $0.sessionId == oldSessionID }?.ratchetState,
            .reset
        )
        let laterIntent = try XCTUnwrap(current.protocolIntents.first {
            $0.id == second.deliveryIDs[0]
        })
        XCTAssertEqual(laterIntent.state, .permanentFailure)
        XCTAssertEqual(laterIntent.lastErrorClass?.isRetryable, false)
        XCTAssertTrue(current.isStructurallyValid)

        let fresh = try await resumed.prepareSend(
            body: .text("fresh bootstrap"),
            relationshipID: harness.relationshipID,
            sentAt: origin.addingTimeInterval(104)
        )
        XCTAssertNotEqual(fresh.envelope.sessionId, oldSessionID)
        XCTAssertEqual(fresh.envelope.messageCounter, 0)
        guard case .signedPrekey = fresh.envelope.bootstrap else {
            return XCTFail("A reset session was reused without a fresh bootstrap")
        }
        current = try await resumed.relationship(harness.relationshipID)
        XCTAssertTrue(current.directSessions.contains {
            $0.sessionId == oldSessionID && $0.ratchetState == .reset
        })
        XCTAssertTrue(current.directSessions.contains {
            $0.sessionId == fresh.envelope.sessionId
        })
        XCTAssertTrue(current.isStructurallyValid)
    }

    func testBlockAndExplicitFailedDiscardRemainStructurallyValid() async throws {
        let blockedHarness = try makeHarness(label: "\(#function)-blocked")
        defer { try? FileManager.default.removeItem(at: blockedHarness.directory) }
        let blockedPrepared = try await blockedHarness.client.prepareSend(
            body: .text("pending before block"),
            relationshipID: blockedHarness.relationshipID,
            sentAt: origin.addingTimeInterval(110)
        )
        var policy = try await blockedHarness.client.relationship(
            blockedHarness.relationshipID
        ).localPolicy
        policy.consent = .blocked
        try await blockedHarness.client.setRelationshipLocalPolicy(
            policy,
            relationshipID: blockedHarness.relationshipID,
            at: origin.addingTimeInterval(111)
        )
        let blocked = try await blockedHarness.client.relationship(
            blockedHarness.relationshipID
        )
        XCTAssertTrue(blocked.isStructurallyValid)
        XCTAssertTrue(blocked.pendingDeliveries.isEmpty)
        XCTAssertTrue(blocked.directSessions.isEmpty)
        XCTAssertFalse(blocked.deliveryStates.contains {
            $0.eventId == blockedPrepared.event.id && $0.state == .locallyPersisted
        })
        XCTAssertTrue(blocked.protocolIntents.contains {
            blockedPrepared.deliveryIDs.contains($0.id)
                && $0.state == .permanentFailure
        })
        XCTAssertEqual(
            try NoctweaveCoder.decode(
                PairwiseRelationshipV2.self,
                from: NoctweaveCoder.encode(blocked, sortedKeys: true)
            ),
            blocked
        )

        let discardHarness = try makeHarness(label: "\(#function)-discard")
        defer { try? FileManager.default.removeItem(at: discardHarness.directory) }
        let prepared = try await discardHarness.client.prepareSend(
            body: .text("explicit discard"),
            relationshipID: discardHarness.relationshipID,
            sentAt: origin.addingTimeInterval(120)
        )
        var relationship = try await discardHarness.client.relationship(
            discardHarness.relationshipID
        )
        let index = try XCTUnwrap(relationship.protocolIntents.firstIndex {
            $0.id == prepared.deliveryIDs[0]
        })
        relationship.protocolIntents[index] = try XCTUnwrap(
            relationship.protocolIntents[index].failingPermanently(
                errorClass: .invalidPayload,
                at: origin.addingTimeInterval(121)
            )
        )
        var state = await discardHarness.client.snapshot()
        try state.updateActivePersona { try $0.upsert(relationship: relationship) }
        try await discardHarness.store.save(state)
        let resumed = try HeadlessMessagingClient(
            stateStore: discardHarness.store,
            initialState: state
        )
        try await resumed.discardFailedDelivery(
            intentID: prepared.deliveryIDs[0],
            relationshipID: discardHarness.relationshipID,
            at: origin.addingTimeInterval(122)
        )
        let discarded = try await resumed.relationship(discardHarness.relationshipID)
        XCTAssertTrue(discarded.isStructurallyValid)
        XCTAssertTrue(discarded.pendingDeliveries.isEmpty)
        let retainedFailure = try await resumed.publishPreparedEvent(
            eventID: prepared.event.id,
            relationshipID: discardHarness.relationshipID,
            at: origin.addingTimeInterval(123)
        )
        XCTAssertEqual(retainedFailure.failedDeliveryCount, 1)
        XCTAssertEqual(retainedFailure.pendingDeliveryCount, 0)
        XCTAssertEqual(
            try NoctweaveCoder.decode(
                PairwiseRelationshipV2.self,
                from: NoctweaveCoder.encode(discarded, sortedKeys: true)
            ),
            discarded
        )
    }

    func testDiscardingTerminalPreparedRolloverPermitsReplacement() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let first = try await harness.client.prepareRouteRollover(
            relationshipID: harness.relationshipID,
            relay: offlineRelay(host: "terminal-rollover.offline.invalid"),
            createdAt: origin.addingTimeInterval(130)
        )
        let expired = try await harness.client.resumeRouteRollover(
            routeID: first.clientCapabilities.routeID,
            relationshipID: harness.relationshipID,
            at: first.createRequest.lease.expiresAt
        )
        XCTAssertEqual(expired.state, .permanentFailure)
        let publication = try await harness.client.discardFailedRouteRollover(
            routeID: first.clientCapabilities.routeID,
            relationshipID: harness.relationshipID,
            at: first.createRequest.lease.expiresAt.addingTimeInterval(1)
        )
        XCTAssertNil(publication)

        let second = try await harness.client.prepareRouteRollover(
            relationshipID: harness.relationshipID,
            relay: offlineRelay(host: "replacement-rollover.offline.invalid"),
            createdAt: first.createRequest.lease.expiresAt.addingTimeInterval(2)
        )
        XCTAssertNotEqual(
            second.clientCapabilities.routeID,
            first.clientCapabilities.routeID
        )
        let current = try await harness.client.relationship(harness.relationshipID)
        XCTAssertEqual(current.pendingRouteRollovers, [second])
        XCTAssertEqual(
            current.protocolIntents.filter {
                $0.kind == .rolloverRoute && !$0.state.isTerminal
            }.count,
            1
        )
        XCTAssertTrue(current.isStructurallyValid)
    }

    func testClientTransactionIsUniqueAcrossPrepareAndReopen() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let transactionID = UUID(
            uuidString: "35000000-0000-4000-8000-000000000001"
        )!
        let originalEventID = UUID(
            uuidString: "35000000-0000-4000-8000-000000000002"
        )!
        let prepared = try await harness.client.prepareSend(
            body: .text("one local action"),
            relationshipID: harness.relationshipID,
            eventID: originalEventID,
            clientTransactionID: transactionID,
            sentAt: origin.addingTimeInterval(140)
        )
        let beforeDuplicate = try await harness.client.relationship(
            harness.relationshipID
        )

        await assertDuplicatePrepareRejected(
            by: harness.client,
            relationshipID: harness.relationshipID,
            transactionID: transactionID,
            at: origin.addingTimeInterval(141)
        )
        let afterFirstDuplicate = try await harness.client.relationship(
            harness.relationshipID
        )
        XCTAssertEqual(afterFirstDuplicate, beforeDuplicate)

        let reopened = try await HeadlessMessagingClient.open(
            stateStore: harness.store,
            displayName: "ignored on reopen"
        )
        await assertDuplicatePrepareRejected(
            by: reopened,
            relationshipID: harness.relationshipID,
            transactionID: transactionID,
            at: origin.addingTimeInterval(142)
        )
        let afterReopenDuplicate = try await reopened.relationship(
            harness.relationshipID
        )
        XCTAssertEqual(afterReopenDuplicate, beforeDuplicate)

        let publication = try await reopened.publishPreparedTransaction(
            clientTransactionID: transactionID,
            relationshipID: harness.relationshipID,
            at: origin.addingTimeInterval(143)
        )
        XCTAssertEqual(publication.eventID, prepared.event.id)
        XCTAssertEqual(publication.eventID, originalEventID)
        let afterPublication = try await reopened.relationship(harness.relationshipID)
        XCTAssertEqual(afterPublication.events.count, beforeDuplicate.events.count)
        XCTAssertEqual(
            afterPublication.pendingDeliveries.count,
            beforeDuplicate.pendingDeliveries.count
        )
        XCTAssertEqual(afterPublication.directSessions, beforeDuplicate.directSessions)
    }

    func testTransactionUniquenessIsScopedPerAuthorAtAppendAndStrictDecode() throws {
        var relationship = try makeRelationship()
        let transactionID = UUID(
            uuidString: "36000000-0000-4000-8000-000000000001"
        )!
        let local = ConversationEvent(
            id: UUID(uuidString: "36000000-0000-4000-8000-000000000002")!,
            clientTransactionId: transactionID,
            conversationId: relationship.conversationID,
            authorEndpointHandle: relationship.localEndpointHandle,
            createdAt: origin.addingTimeInterval(150),
            kind: .application,
            content: try XCTUnwrap(.text("local"))
        )
        _ = try relationship.appendEvent(local)
        let duplicateLocal = ConversationEvent(
            id: UUID(uuidString: "36000000-0000-4000-8000-000000000003")!,
            clientTransactionId: transactionID,
            conversationId: relationship.conversationID,
            authorEndpointHandle: relationship.localEndpointHandle,
            createdAt: origin.addingTimeInterval(151),
            kind: .application,
            content: try XCTUnwrap(.text("duplicate local"))
        )
        let beforeDuplicate = relationship
        XCTAssertThrowsError(try relationship.appendEvent(duplicateLocal)) { error in
            XCTAssertEqual(error as? PairwiseRelationshipV2Error, .conflictingEvent)
        }
        XCTAssertEqual(relationship, beforeDuplicate)

        var duplicateObject = try jsonObject(relationship)
        var duplicateEvents = try XCTUnwrap(
            duplicateObject["events"] as? [[String: Any]]
        )
        duplicateEvents.append(try jsonObject(duplicateLocal))
        duplicateObject["events"] = duplicateEvents
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            PairwiseRelationshipV2.self,
            from: JSONSerialization.data(withJSONObject: duplicateObject)
        ))

        let peer = ConversationEvent(
            id: UUID(uuidString: "36000000-0000-4000-8000-000000000004")!,
            clientTransactionId: transactionID,
            conversationId: relationship.conversationID,
            authorEndpointHandle: relationship.peerIdentity.sendRoutes.ownerEndpointHandle,
            createdAt: origin.addingTimeInterval(152),
            kind: .application,
            content: try XCTUnwrap(.text("peer may reuse transaction UUID"))
        )
        _ = try relationship.appendEvent(peer)
        XCTAssertTrue(relationship.isStructurallyValid)
        XCTAssertEqual(
            try NoctweaveCoder.decode(
                PairwiseRelationshipV2.self,
                from: NoctweaveCoder.encode(relationship, sortedKeys: true)
            ),
            relationship
        )
    }

    func testResetSessionCannotBeReactivatedByProcessedMessage() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        _ = try await harness.client.prepareSend(
            body: .text("create session"),
            relationshipID: harness.relationshipID,
            sentAt: origin.addingTimeInterval(160)
        )
        let relationship = try await harness.client.relationship(
            harness.relationshipID
        )
        var session = try XCTUnwrap(relationship.directSessions.first)
        session.markReset()
        XCTAssertEqual(session.ratchetState, .reset)
        session.markMessageProcessed()
        XCTAssertEqual(session.ratchetState, .reset)
    }

    func testRetainedFailedReceiptSuppressesDuplicateUntilExplicitDiscard() async throws {
        var relationship = try makeRelationship()
        let peerEvent = ConversationEvent(
            id: UUID(uuidString: "37000000-0000-4000-8000-000000000001")!,
            clientTransactionId: UUID(
                uuidString: "37000000-0000-4000-8000-000000000002"
            )!,
            conversationId: relationship.conversationID,
            authorEndpointHandle: relationship.peerIdentity.sendRoutes.ownerEndpointHandle,
            createdAt: origin.addingTimeInterval(170),
            kind: .application,
            content: try XCTUnwrap(.text("peer event"))
        )
        _ = try relationship.appendEvent(peerEvent)
        let harness = try makeHarness(label: #function, relationship: relationship)
        defer { try? FileManager.default.removeItem(at: harness.directory) }

        let firstReceipt = try await harness.client.markRead(
            eventID: peerEvent.id,
            relationshipID: harness.relationshipID,
            sentAt: origin.addingTimeInterval(171)
        )
        XCTAssertEqual(firstReceipt.acceptedDeliveryCount, 0)
        XCTAssertEqual(firstReceipt.pendingDeliveryCount, 1)
        let retained = try await harness.client.relationship(harness.relationshipID)
        let retainedDelivery = try XCTUnwrap(retained.pendingDeliveries.first {
            $0.logicalEventID == firstReceipt.event.id
        })

        do {
            _ = try await harness.client.markRead(
                eventID: peerEvent.id,
                relationshipID: harness.relationshipID,
                sentAt: origin.addingTimeInterval(172)
            )
            XCTFail("Retained failed receipt did not suppress a duplicate")
        } catch let error as HeadlessMessagingClientError {
            XCTAssertEqual(error, .invalidState)
        }

        var failedRelationship = retained
        let intentIndex = try XCTUnwrap(
            failedRelationship.protocolIntents.firstIndex {
                $0.id == retainedDelivery.intentID
            }
        )
        failedRelationship.protocolIntents[intentIndex] = try XCTUnwrap(
            failedRelationship.protocolIntents[intentIndex].failingPermanently(
                errorClass: .invalidPayload,
                at: origin.addingTimeInterval(173)
            )
        )
        var failedState = await harness.client.snapshot()
        try failedState.updateActivePersona {
            try $0.upsert(relationship: failedRelationship)
        }
        try await harness.store.save(failedState)
        let resumed = try HeadlessMessagingClient(
            stateStore: harness.store,
            initialState: failedState
        )
        try await resumed.discardFailedDelivery(
            intentID: retainedDelivery.intentID,
            relationshipID: harness.relationshipID,
            at: origin.addingTimeInterval(174)
        )

        let replacementReceipt = try await resumed.markRead(
            eventID: peerEvent.id,
            relationshipID: harness.relationshipID,
            sentAt: origin.addingTimeInterval(175)
        )
        XCTAssertNotEqual(replacementReceipt.event.id, firstReceipt.event.id)
        XCTAssertNotEqual(
            replacementReceipt.envelope.sessionId,
            firstReceipt.envelope.sessionId
        )
        XCTAssertEqual(replacementReceipt.envelope.messageCounter, 0)
        guard case .signedPrekey = replacementReceipt.envelope.bootstrap else {
            return XCTFail("Discarded receipt did not force a fresh direct bootstrap")
        }
        let current = try await resumed.relationship(harness.relationshipID)
        XCTAssertTrue(current.pendingDeliveries.contains {
            $0.logicalEventID == replacementReceipt.event.id
        })
        XCTAssertFalse(current.pendingDeliveries.contains {
            $0.logicalEventID == firstReceipt.event.id
        })
        XCTAssertTrue(current.isStructurallyValid)
    }

    func testDiscardFailedDeliveryRejectsBlobIntentWithoutRemovingArtifact() async throws {
        let harness = try makeHarness(label: #function)
        defer { try? FileManager.default.removeItem(at: harness.directory) }
        let request = UploadAttachmentRequest(
            attachmentId: UUID(),
            chunkIndex: 0,
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
        let pending = try await harness.client.prepareAttachmentUpload(
            request,
            relay: offlineRelay(host: "wrong-discard.offline.invalid"),
            relationshipID: harness.relationshipID,
            at: origin.addingTimeInterval(180)
        )
        var relationship = try await harness.client.relationship(harness.relationshipID)
        let intentIndex = try XCTUnwrap(relationship.protocolIntents.firstIndex {
            $0.kind == .uploadBlob
                && $0.targetIdentifier
                    == Data(pending.id.uuidString.lowercased().utf8)
        })
        relationship.protocolIntents[intentIndex] = try XCTUnwrap(
            relationship.protocolIntents[intentIndex].failingPermanently(
                errorClass: .invalidPayload,
                at: origin.addingTimeInterval(181)
            )
        )
        var failedState = await harness.client.snapshot()
        try failedState.updateActivePersona {
            try $0.upsert(relationship: relationship)
        }
        try await harness.store.save(failedState)
        let resumed = try HeadlessMessagingClient(
            stateStore: harness.store,
            initialState: failedState
        )

        do {
            try await resumed.discardFailedDelivery(
                intentID: relationship.protocolIntents[intentIndex].id,
                relationshipID: harness.relationshipID,
                at: origin.addingTimeInterval(182)
            )
            XCTFail("Blob intent was accepted by direct-delivery discard")
        } catch let error as HeadlessMessagingClientError {
            XCTAssertEqual(error, .invalidState)
        }
        let current = try await resumed.relationship(harness.relationshipID)
        XCTAssertEqual(current.pendingAttachmentUploads, [pending])
        XCTAssertTrue(current.isStructurallyValid)
    }

    func testMessageProjectionTrimsAtBoundAndKeepsUnreadCountValid() throws {
        let relationship = try makeRelationship()
        var conversation = try MessageEngine.createOutboundEndpointSession(
            relationship: relationship,
            now: origin.addingTimeInterval(190)
        ).conversation
        let maximum = NoctweaveArchitectureV2.maximumRelationshipEvents
        let firstID = UUID()
        for index in 0..<maximum {
            _ = MessageEngine.appendMessage(
                id: index == 0 ? firstID : UUID(),
                body: .text("projection \(index)"),
                direction: .received,
                counter: UInt64(index),
                timestamp: origin.addingTimeInterval(TimeInterval(190 + index)),
                conversation: &conversation
            )
        }
        let newestID = UUID()
        _ = MessageEngine.appendMessage(
            id: newestID,
            body: .text("projection overflow"),
            direction: .received,
            counter: UInt64(maximum),
            timestamp: origin.addingTimeInterval(TimeInterval(190 + maximum)),
            conversation: &conversation
        )

        XCTAssertEqual(conversation.messages.count, maximum)
        XCTAssertFalse(conversation.messages.contains { $0.id == firstID })
        XCTAssertEqual(conversation.messages.last?.id, newestID)
        XCTAssertEqual(conversation.unreadCount, maximum)
        XCTAssertTrue(conversation.isStructurallyValid)
    }

    func testRelayAcceptedHistoryCompactsWithoutPeerReceipts() throws {
        var relationship = try makeRelationship()
        let maximum = NoctweaveArchitectureV2.maximumRelationshipEvents
        var events: [ConversationEvent] = []
        var deliveryStates: [DeliveryStateRecord] = []
        events.reserveCapacity(maximum)
        deliveryStates.reserveCapacity(maximum)
        for index in 0..<maximum {
            let event = ConversationEvent(
                id: UUID(),
                clientTransactionId: UUID(),
                conversationId: relationship.conversationID,
                authorEndpointHandle: relationship.localEndpointHandle,
                createdAt: origin.addingTimeInterval(TimeInterval(200 + index)),
                kind: .application,
                content: try XCTUnwrap(.text("accepted \(index)"))
            )
            events.append(event)
            deliveryStates.append(DeliveryStateRecord(
                eventId: event.id,
                destinationEndpoint: relationship.peerIdentity.sendRoutes.ownerEndpointHandle,
                state: .relayAccepted,
                updatedAt: event.createdAt
            ))
        }
        let oldestEventID = try XCTUnwrap(events.first?.id)
        relationship.events = events
        relationship.deliveryStates = deliveryStates
        XCTAssertTrue(relationship.isStructurallyValid)

        let next = ConversationEvent(
            id: UUID(),
            clientTransactionId: UUID(),
            conversationId: relationship.conversationID,
            authorEndpointHandle: relationship.localEndpointHandle,
            createdAt: origin.addingTimeInterval(TimeInterval(200 + maximum)),
            kind: .application,
            content: try XCTUnwrap(.text("accepted after compaction"))
        )
        XCTAssertTrue(try relationship.appendEvent(next))

        XCTAssertEqual(
            relationship.events.count,
            NoctweaveArchitectureV2.relationshipEventRecentWindow + 1
        )
        XCTAssertTrue(relationship.events.contains(next))
        XCTAssertFalse(relationship.events.contains { $0.id == oldestEventID })
        XCTAssertLessThan(relationship.deliveryStates.count, maximum)
        XCTAssertTrue(relationship.isStructurallyValid)
    }

    func testExpiredBootstrapUsesReceiverObservedTimeNotHistoricalSentAt() async throws {
        let offer = try ContactPairingHandshakeV2.makeOffer(
            createdAt: origin,
            expiresAt: origin.addingTimeInterval(300)
        )
        var pendingOffer = offer.pending
        var ledger = RendezvousRedemptionLedgerV2()
        let paired = try ContactPairingHandshakeV2.establish(
            pendingOffer: &pendingOffer,
            invitation: offer.invitation,
            offerer: try makeParticipant(name: "Bootstrap sender", host: "bootstrap-sender.invalid"),
            responder: try makeParticipant(
                name: "Bootstrap receiver",
                host: "bootstrap-receiver.invalid"
            ),
            ledger: &ledger,
            at: origin.addingTimeInterval(1)
        )
        let senderHarness = try makeHarness(
            label: "\(#function)-sender",
            relationship: paired.offererRelationship
        )
        let receiverHarness = try makeHarness(
            label: "\(#function)-receiver",
            relationship: paired.responderRelationship
        )
        defer {
            try? FileManager.default.removeItem(at: senderHarness.directory)
            try? FileManager.default.removeItem(at: receiverHarness.directory)
        }
        let historicalSentAt = origin.addingTimeInterval(2)
        let prepared = try await senderHarness.client.prepareSend(
            body: .text("historically valid bootstrap"),
            relationshipID: paired.relationshipID,
            sentAt: historicalSentAt
        )
        guard case .signedPrekey = prepared.envelope.bootstrap else {
            return XCTFail("First outbound event did not carry a signed-prekey bootstrap")
        }
        let receiverPrekey = paired.responderRelationship.localIdentity.endpointBinding
            .prekeyBundle.signedPrekey
        XCTAssertLessThan(historicalSentAt, receiverPrekey.expiresAt)
        let receiverObservedAt = receiverPrekey.expiresAt.addingTimeInterval(1)
        let payload = try NoctweaveCoder.encode(prepared.envelope, sortedKeys: true)
        let sourceRoute = try XCTUnwrap(
            paired.responderRelationship.localReceiveRoutes.first
        )
        let bundle = OpaqueRouteReassembledBundleV2(
            routeID: sourceRoute.route.routeID,
            routeRevision: sourceRoute.route.lease.renewalSequence,
            bundleID: .generate(),
            bundleDigest: Data(SHA256.hash(data: payload)),
            payload: payload
        )
        var receiverRelationship = paired.responderRelationship

        do {
            _ = try await receiverHarness.client.processInboundBundle(
                bundle,
                sourceRouteID: sourceRoute.route.routeID,
                receivedAt: receiverObservedAt,
                relationship: &receiverRelationship
            )
            XCTFail("Expired bootstrap was accepted using the historical sender timestamp")
        } catch let error as CryptoError {
            XCTAssertEqual(error, .invalidPayload)
        }
        XCTAssertTrue(receiverRelationship.directSessions.isEmpty)
        XCTAssertTrue(receiverRelationship.events.isEmpty)
        XCTAssertTrue(receiverRelationship.inboundReceipts.isEmpty)
    }

    func testProbeSchedulingSkipsTestingRouteOutsideObservedValidityWindow() async throws {
        let offer = try ContactPairingHandshakeV2.makeOffer(
            createdAt: origin,
            expiresAt: origin.addingTimeInterval(300)
        )
        var pendingOffer = offer.pending
        var ledger = RendezvousRedemptionLedgerV2()
        let paired = try ContactPairingHandshakeV2.establish(
            pendingOffer: &pendingOffer,
            invitation: offer.invitation,
            offerer: try makeParticipant(name: "Probe local", host: "probe-local.invalid"),
            responder: try makeParticipant(name: "Probe peer", host: "probe-peer.invalid"),
            ledger: &ledger,
            at: origin.addingTimeInterval(1)
        )
        let candidateAt = origin.addingTimeInterval(30)
        let pendingRoute = try PendingLocalOpaqueReceiveRouteV2.prepare(
            relay: offlineRelay(host: "probe-candidate.offline.invalid"),
            createdAt: candidateAt
        )
        let createdRoute = try OpaqueReceiveRouteV2.creating(
            from: pendingRoute.createRequest,
            presentedRenewCapability: pendingRoute.clientCapabilities.renewCapability,
            existing: nil,
            confidentialTransport: true,
            receivedAt: candidateAt
        )
        let localTestingRoute = try pendingRoute.activate(createdRoute: createdRoute)
        let testingSendRoute = try localTestingRoute.peerSendRoute(state: .testing)
        let peerRouteSet = try paired.responderRelationship.localAdvertisedRoutes
            .addingTestingRoute(
                testingSendRoute,
                signingKey: paired.responderRelationship.localIdentity.localEndpoint.signingKey,
                issuedAt: candidateAt
            )
        var localRelationship = paired.offererRelationship
        localRelationship.peerIdentity.sendRoutes = peerRouteSet
        XCTAssertTrue(localRelationship.isStructurallyValid)
        let harness = try makeHarness(label: #function, relationship: localRelationship)
        defer { try? FileManager.default.removeItem(at: harness.directory) }

        let eligible = await harness.client.routeProbesToSend(
            in: localRelationship,
            observedAt: candidateAt
        )
        XCTAssertEqual(eligible.map(\.routeID), [testingSendRoute.routeID])
        let expired = await harness.client.routeProbesToSend(
            in: localRelationship,
            observedAt: testingSendRoute.expiresAt
        )
        XCTAssertTrue(expired.isEmpty)
    }

    private func assertPreparedPublicationRejected(
        _ prepared: HeadlessPreparedSend,
        by client: HeadlessMessagingClient,
        at date: Date
    ) async {
        do {
            _ = try await client.publishPreparedSend(prepared, at: date)
            XCTFail("Forged prepared publication was accepted")
        } catch let error as HeadlessMessagingClientError {
            XCTAssertEqual(error, .conflictingEnvelope)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    private func assertDuplicatePrepareRejected(
        by client: HeadlessMessagingClient,
        relationshipID: UUID,
        transactionID: UUID,
        at date: Date
    ) async {
        do {
            _ = try await client.prepareSend(
                body: .text("duplicate action"),
                relationshipID: relationshipID,
                eventID: UUID(),
                clientTransactionID: transactionID,
                sentAt: date
            )
            XCTFail("Duplicate local transaction was accepted")
        } catch let error as HeadlessMessagingClientError {
            XCTAssertEqual(error, .conflictingEnvelope)
        } catch {
            XCTFail("Unexpected duplicate-prepare error: \(error)")
        }
    }

    private func makeHarness(
        label: String,
        relationship suppliedRelationship: PairwiseRelationshipV2? = nil
    ) throws -> (
        directory: URL,
        store: ClientStateStore,
        client: HeadlessMessagingClient,
        relationshipID: UUID
    ) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweave-durability-\(label)-\(UUID().uuidString)"
        )
        let store = ClientStateStore(
            fileURL: directory.appendingPathComponent("state.json"),
            useEncryption: false
        )
        let relationship: PairwiseRelationshipV2
        if let suppliedRelationship {
            relationship = suppliedRelationship
        } else {
            relationship = try makeRelationship()
        }
        var state = try ClientState(displayName: "Local only", createdAt: origin)
        try state.updateActivePersona {
            try $0.upsert(relationship: relationship)
        }
        return (
            directory: directory,
            store: store,
            client: try HeadlessMessagingClient(
                stateStore: store,
                initialState: state
            ),
            relationshipID: relationship.id
        )
    }

    private func makeRelationship() throws -> PairwiseRelationshipV2 {
        let offer = try ContactPairingHandshakeV2.makeOffer(
            createdAt: origin,
            expiresAt: origin.addingTimeInterval(300)
        )
        var pendingOffer = offer.pending
        var ledger = RendezvousRedemptionLedgerV2()
        return try ContactPairingHandshakeV2.establish(
            pendingOffer: &pendingOffer,
            invitation: offer.invitation,
            offerer: try makeParticipant(name: "Local", host: "local.offline.invalid"),
            responder: try makeParticipant(name: "Peer", host: "peer.offline.invalid"),
            ledger: &ledger,
            at: origin.addingTimeInterval(1)
        ).offererRelationship
    }

    private func makeParticipant(
        name: String,
        host: String
    ) throws -> PreparedContactParticipantV2 {
        let pending = try PendingContactParticipantV2.prepare(
            relationshipPseudonym: name,
            relay: offlineRelay(host: host),
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

    private func makeGroupRuntimeRecord(at date: Date) throws -> GroupRuntimeRecord {
        let groupID = UUID()
        let memberHandle = GroupScopedMemberHandleV2.generate()
        let signingKey = try SigningKeyPair.generate()
        let agreementKey = try AgreementKeyPair.generate()
        let admission = try GroupCredentialAdmissionV2.create(
            groupId: groupID,
            memberHandle: memberHandle,
            credentialHandle: .generate(),
            groupSigningKey: signingKey,
            groupAgreementKey: agreementKey,
            issuedAt: date,
            expiresAt: date.addingTimeInterval(3_600)
        )
        let leaf = try GroupMemberCredentialV2.fromVerifiedProjection(
            admission,
            addedEpoch: 1
        )
        let credential = LocalGroupCredentialV2(
            groupId: groupID,
            memberHandle: memberHandle,
            credentialHandle: leaf.credentialHandle,
            admissionDigest: leaf.admissionDigest,
            signingKey: signingKey,
            agreementKey: agreementKey
        )
        let creator = GroupMemberV2(id: memberHandle, role: .owner, addedEpoch: 1)
        let provider = NoctweavePQGroupExperimentalProviderV2()
        let membership = try provider.membership(
            groupId: groupID,
            epoch: 1,
            members: [creator],
            leaves: [leaf]
        )
        let prepared = try provider.prepareGenesis(
            membership: membership,
            localCredential: credential
        )
        let providerDigest = try XCTUnwrap(prepared.providerCommitDigest)
        let state = try SignedGroupStateV2.initial(
            groupId: groupID,
            creator: creator,
            creatorAdmission: admission,
            providerGenesisDigest: providerDigest,
            signingKey: signingKey,
            signedAt: date
        )
        let acceptance = GroupCryptoAcceptedEpochV2(
            proposal: prepared.proposal,
            providerCommitDigest: providerDigest,
            signedCommitDigest: state.commitDigest,
            acceptedTranscriptHash: state.confirmedTranscriptHash
        )
        return GroupRuntimeRecord(
            groupId: groupID,
            localCredential: credential,
            signedState: state,
            cryptoState: try provider.finalizePreparedEpoch(
                prepared,
                acceptance: acceptance
            )
        )
    }

    private func jsonObject<T: Encodable>(_ value: T) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: NoctweaveCoder.encode(value, sortedKeys: true)
            ) as? [String: Any]
        )
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
