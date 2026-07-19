import Foundation
import XCTest
@testable import NoctweaveCore

final class HeadlessOpaqueRouteSyncDurabilityTests: XCTestCase {
    private enum FixtureError: Error {
        case invalidRelayResponse
        case retryLimitExceeded
    }

    private struct Fixture {
        let rootDirectory: URL
        let senderDirectory: URL
        let receiverDirectory: URL
        let receiverStateURL: URL
        let server: RelayServer
        let endpoint: RelayEndpoint
        let sender: HeadlessMessagingClient
        let receiver: HeadlessMessagingClient
        let receiverStore: ClientStateStore
        let relationshipID: UUID
        let baseDate: Date
    }

    func testMaintenanceStartsOneFreshRouteBeforeExpiryAndResumesAfterReopen() async throws {
        let fixture = try await makeFixture(
            label: #function,
            receiverRouteExpiresIn: 29 * 60
        )
        defer { tearDown(fixture) }
        let observedAt = NoctweaveRendezvousV2.canonicalTimestamp(Date())
        let before = try await fixture.receiver.relationship(fixture.relationshipID)
        let originalRouteID = try XCTUnwrap(
            before.localAdvertisedRoutes.routes.first { $0.state == .active }
        ).routeID

        let report = try await fixture.receiver.maintainRelationship(
            relationshipID: fixture.relationshipID,
            at: observedAt
        )

        XCTAssertEqual(report.routeDisposition, .rolloverStarted)
        XCTAssertNotNil(report.startedRollover)
        XCTAssertNil(report.prekeyPublication)
        XCTAssertTrue(report.finalizedRouteIDs.isEmpty)
        let after = try await fixture.receiver.relationship(fixture.relationshipID)
        XCTAssertEqual(after.localReceiveRoutes.count, 2)
        let replacement = try XCTUnwrap(
            after.localAdvertisedRoutes.routes.first { $0.state == .testing }
        )
        XCTAssertNotEqual(replacement.routeID, originalRouteID)
        XCTAssertEqual(
            after.protocolIntents.filter {
                $0.kind == .rolloverRoute && !$0.state.isTerminal
            }.count,
            1
        )

        let reopened = try await HeadlessMessagingClient.open(
            stateStore: fixture.receiverStore,
            displayName: "ignored after reopen"
        )
        let resumed = try await reopened.maintainRelationship(
            relationshipID: fixture.relationshipID,
            at: observedAt.addingTimeInterval(1)
        )
        XCTAssertEqual(resumed.routeDisposition, .rolloverInProgress)
        XCTAssertEqual(resumed.resumedRollovers.count, 1)
        XCTAssertNil(resumed.startedRollover)
        let reopenedRelationship = try await reopened.relationship(fixture.relationshipID)
        XCTAssertEqual(reopenedRelationship.localReceiveRoutes.count, 2)
    }

    func testPartialBundleCommitsEachPageAndCompletesOnceAfterReopen() async throws {
        let fixture = try await makeFixture(label: #function)
        defer { tearDown(fixture) }

        let prepared = try await fixture.sender.prepareSend(
            body: .text(String(repeating: "p", count: 2_000)),
            relationshipID: fixture.relationshipID,
            sentAt: fixture.baseDate.addingTimeInterval(2)
        )
        let delivery = try await pendingDelivery(
            for: prepared,
            client: fixture.sender
        )
        XCTAssertGreaterThan(delivery.packets.count, 1)
        let sendRoute = try await activeSendRoute(in: fixture.sender, fixture: fixture)
        try await append(delivery.packets, through: sendRoute)

        let firstPage = try await syncOneRoute(
            fixture.receiver,
            relationshipID: fixture.relationshipID,
            maximumPackets: 1
        )
        XCTAssertTrue(firstPage.receivedEvents.isEmpty)
        XCTAssertTrue(firstPage.hasMore)

        let afterFirstPage = try await fixture.receiver.relationship(fixture.relationshipID)
        let firstRoute = try XCTUnwrap(afterFirstPage.localReceiveRoutes.first)
        XCTAssertEqual(firstRoute.committedSequence, 1)
        XCTAssertEqual(firstRoute.reassembler.pendingBundleCount, 1)
        XCTAssertGreaterThan(firstRoute.reassembler.bufferedPayloadBytes, 0)

        let reopened = try await HeadlessMessagingClient.open(
            stateStore: fixture.receiverStore,
            displayName: "ignored after reopen"
        )
        let reopenedRelationship = try await reopened.relationship(fixture.relationshipID)
        XCTAssertEqual(reopenedRelationship, afterFirstPage)

        var receivedEvents: [ConversationEvent] = []
        var hasMore = true
        var remainingAttempts = delivery.packets.count + 1
        while hasMore, remainingAttempts > 0 {
            let result = try await syncOneRoute(
                reopened,
                relationshipID: fixture.relationshipID,
                maximumPackets: 1
            )
            receivedEvents.append(contentsOf: result.receivedEvents)
            hasMore = result.hasMore
            remainingAttempts -= 1
        }
        guard !hasMore else { throw FixtureError.retryLimitExceeded }

        XCTAssertEqual(receivedEvents.filter { $0.id == prepared.event.id }.count, 1)
        let drained = try await syncOneRoute(
            reopened,
            relationshipID: fixture.relationshipID,
            maximumPackets: 1
        )
        XCTAssertTrue(drained.receivedEvents.isEmpty)

        let finalRelationship = try await reopened.relationship(fixture.relationshipID)
        XCTAssertEqual(finalRelationship.events.filter { $0.id == prepared.event.id }.count, 1)
        XCTAssertEqual(
            finalRelationship.inboundReceipts.filter {
                $0.envelopeId == prepared.envelope.id
            }.count,
            1
        )
        let finalRoute = try XCTUnwrap(finalRelationship.localReceiveRoutes.first)
        XCTAssertEqual(finalRoute.committedSequence, UInt64(delivery.packets.count))
        XCTAssertEqual(finalRoute.reassembler.pendingBundleCount, 0)
        XCTAssertEqual(finalRoute.reassembler.bufferedPayloadBytes, 0)
    }

    func testWrongPayloadKeyPacketIsQuarantinedWithoutBlockingValidEvent() async throws {
        let fixture = try await makeFixture(label: #function)
        defer { tearDown(fixture) }

        let prepared = try await fixture.sender.prepareSend(
            body: .text("valid after wrong payload key"),
            relationshipID: fixture.relationshipID,
            sentAt: fixture.baseDate.addingTimeInterval(2)
        )
        let delivery = try await pendingDelivery(
            for: prepared,
            client: fixture.sender
        )
        let sendRoute = try await activeSendRoute(in: fixture.sender, fixture: fixture)
        let wrongKeyRoute = try replacingPayloadKey(
            in: sendRoute,
            with: .generate()
        )
        let poison = try OpaqueRouteSealedBundleV2.seal(
            Data("structurally valid wrong-key packet".utf8),
            to: wrongKeyRoute
        )
        XCTAssertEqual(poison.packets.count, 1)

        try await append(poison.packets, through: sendRoute)
        try await append(delivery.packets, through: sendRoute)
        let result = try await syncOneRoute(
            fixture.receiver,
            relationshipID: fixture.relationshipID,
            maximumPackets: 256
        )
        XCTAssertEqual(result.receivedEvents.map(\.id), [prepared.event.id])

        let relationship = try await fixture.receiver.relationship(fixture.relationshipID)
        let quarantined = try XCTUnwrap(
            relationship.transportQuarantine.first {
                $0.packetID == poison.packets[0].packetID
            }
        )
        XCTAssertEqual(quarantined.reason, .invalidCiphertext)
        XCTAssertEqual(quarantined.relaySequence, 1)
        XCTAssertNil(quarantined.innerEnvelopeID)
        XCTAssertEqual(quarantined.recordDigest.count, 32)
        XCTAssertEqual(
            relationship.localReceiveRoutes.first?.committedSequence,
            UInt64(1 + delivery.packets.count)
        )
        XCTAssertEqual(relationship.events.filter { $0.id == prepared.event.id }.count, 1)
    }

    func testDuplicatePeerTransactionIsQuarantinedWithoutWedgeBeforeValidEvent() async throws {
        let fixture = try await makeFixture(label: #function)
        defer { tearDown(fixture) }

        let transactionID = UUID()
        let first = try await fixture.sender.prepareSend(
            body: .text("first transaction"),
            relationshipID: fixture.relationshipID,
            clientTransactionID: transactionID,
            sentAt: fixture.baseDate.addingTimeInterval(2)
        )
        let firstDelivery = try await pendingDelivery(for: first, client: fixture.sender)
        let sendRoute = try await activeSendRoute(in: fixture.sender, fixture: fixture)
        try await append(firstDelivery.packets, through: sendRoute)
        let firstSync = try await syncOneRoute(
            fixture.receiver,
            relationshipID: fixture.relationshipID,
            maximumPackets: 256
        )
        XCTAssertEqual(firstSync.receivedEvents.map(\.id), [first.event.id])

        let senderRelationship = try await fixture.sender.relationship(fixture.relationshipID)
        var conversation = try XCTUnwrap(senderRelationship.directSessions.first)
        let poisonEvent = ConversationEvent(
            clientTransactionId: transactionID,
            conversationId: senderRelationship.conversationID,
            authorEndpointHandle: senderRelationship.localEndpointHandle,
            createdAt: fixture.baseDate.addingTimeInterval(3),
            kind: .application,
            content: try XCTUnwrap(.text("duplicate transaction poison"))
        )
        let poisonEnvelope = try MessageEngine.encryptDirectV4(
            wirePayload: .application(poisonEvent),
            eventID: poisonEvent.id,
            relationship: senderRelationship,
            conversation: &conversation,
            bootstrap: .none,
            sentAt: poisonEvent.createdAt
        )
        let validEvent = ConversationEvent(
            conversationId: senderRelationship.conversationID,
            authorEndpointHandle: senderRelationship.localEndpointHandle,
            createdAt: fixture.baseDate.addingTimeInterval(4),
            kind: .application,
            content: try XCTUnwrap(.text("valid after duplicate transaction"))
        )
        let validEnvelope = try MessageEngine.encryptDirectV4(
            wirePayload: .application(validEvent),
            eventID: validEvent.id,
            relationship: senderRelationship,
            conversation: &conversation,
            bootstrap: .none,
            sentAt: validEvent.createdAt
        )
        let poisonBundle = try OpaqueRouteSealedBundleV2.seal(
            NoctweaveCoder.encode(poisonEnvelope, sortedKeys: true),
            to: sendRoute
        )
        let validBundle = try OpaqueRouteSealedBundleV2.seal(
            NoctweaveCoder.encode(validEnvelope, sortedKeys: true),
            to: sendRoute
        )

        try await append(poisonBundle.packets, through: sendRoute)
        try await append(validBundle.packets, through: sendRoute)
        let result = try await syncOneRoute(
            fixture.receiver,
            relationshipID: fixture.relationshipID,
            maximumPackets: 256
        )
        XCTAssertEqual(result.receivedEvents.map(\.id), [validEvent.id])

        let relationship = try await fixture.receiver.relationship(fixture.relationshipID)
        XCTAssertFalse(relationship.events.contains { $0.id == poisonEvent.id })
        XCTAssertTrue(relationship.events.contains { $0.id == validEvent.id })
        let quarantine = try XCTUnwrap(relationship.transportQuarantine.first {
            $0.innerEnvelopeID == poisonEnvelope.id
        })
        XCTAssertEqual(quarantine.reason, .replayConflict)
    }

    func testSignatureMutatedEnvelopeIsQuarantinedByPacketCoordinatesBeforeExactOriginal() async throws {
        let fixture = try await makeFixture(label: #function)
        defer { tearDown(fixture) }

        let prepared = try await fixture.sender.prepareSend(
            body: .text("exact original survives signature poison"),
            relationshipID: fixture.relationshipID,
            sentAt: fixture.baseDate.addingTimeInterval(2)
        )
        let originalDelivery = try await pendingDelivery(
            for: prepared,
            client: fixture.sender
        )
        let sendRoute = try await activeSendRoute(in: fixture.sender, fixture: fixture)
        let mutatedEnvelope = try signatureMutated(prepared.envelope)
        let mutatedBytes = try NoctweaveCoder.encode(mutatedEnvelope, sortedKeys: true)
        let mutatedBundle = try OpaqueRouteSealedBundleV2.seal(
            mutatedBytes,
            to: sendRoute
        )

        try await append(mutatedBundle.packets, through: sendRoute)
        try await append(originalDelivery.packets, through: sendRoute)
        let result = try await syncOneRoute(
            fixture.receiver,
            relationshipID: fixture.relationshipID,
            maximumPackets: 256
        )
        XCTAssertEqual(result.receivedEvents.map(\.id), [prepared.event.id])

        let expectedPacket = try XCTUnwrap(mutatedBundle.packets.last)
        let relationship = try await fixture.receiver.relationship(fixture.relationshipID)
        let quarantined = try XCTUnwrap(
            relationship.transportQuarantine.first {
                $0.packetID == expectedPacket.packetID
            }
        )
        XCTAssertEqual(quarantined.reason, .invalidAttribution)
        XCTAssertEqual(quarantined.relaySequence, UInt64(mutatedBundle.packets.count))
        XCTAssertEqual(quarantined.innerEnvelopeID, mutatedEnvelope.id)
        XCTAssertEqual(quarantined.recordDigest.count, 32)
        XCTAssertEqual(relationship.events.filter { $0.id == prepared.event.id }.count, 1)
        XCTAssertEqual(
            relationship.inboundReceipts.filter {
                $0.envelopeId == prepared.envelope.id
            }.count,
            1
        )
    }

    func testStateSaveFailureLeavesCursorAndEventsUnchangedThenRetriesExactly() async throws {
        let fixture = try await makeFixture(label: #function)
        defer { tearDown(fixture) }

        let prepared = try await fixture.sender.prepareSend(
            body: .text("retry the exact relay page after local save failure"),
            relationshipID: fixture.relationshipID,
            sentAt: fixture.baseDate.addingTimeInterval(2)
        )
        let delivery = try await pendingDelivery(
            for: prepared,
            client: fixture.sender
        )
        let sendRoute = try await activeSendRoute(in: fixture.sender, fixture: fixture)
        try await append(delivery.packets, through: sendRoute)

        let beforeFailure = try await fixture.receiver.relationship(fixture.relationshipID)
        let savedDirectory = fixture.rootDirectory.appendingPathComponent(
            "receiver-state-saved"
        )
        try FileManager.default.moveItem(
            at: fixture.receiverDirectory,
            to: savedDirectory
        )
        try Data("not a directory".utf8).write(to: fixture.receiverDirectory)
        var restored = false
        defer {
            if !restored {
                try? FileManager.default.removeItem(at: fixture.receiverDirectory)
                try? FileManager.default.moveItem(
                    at: savedDirectory,
                    to: fixture.receiverDirectory
                )
            }
        }

        do {
            _ = try await syncOneRoute(
                fixture.receiver,
                relationshipID: fixture.relationshipID,
                maximumPackets: 256
            )
            XCTFail("Sync unexpectedly committed through an invalid state-store path")
        } catch {
            XCTAssertFalse(error is HeadlessMessagingClientError)
        }
        let afterFailure = try await fixture.receiver.relationship(fixture.relationshipID)
        XCTAssertEqual(afterFailure, beforeFailure)

        try FileManager.default.removeItem(at: fixture.receiverDirectory)
        try FileManager.default.moveItem(
            at: savedDirectory,
            to: fixture.receiverDirectory
        )
        restored = true

        let retried = try await syncOneRoute(
            fixture.receiver,
            relationshipID: fixture.relationshipID,
            maximumPackets: 256
        )
        XCTAssertEqual(retried.receivedEvents.map(\.id), [prepared.event.id])
        let drained = try await syncOneRoute(
            fixture.receiver,
            relationshipID: fixture.relationshipID,
            maximumPackets: 256
        )
        XCTAssertTrue(drained.receivedEvents.isEmpty)

        let afterRetry = try await fixture.receiver.relationship(fixture.relationshipID)
        XCTAssertEqual(afterRetry.events.filter { $0.id == prepared.event.id }.count, 1)
        XCTAssertEqual(
            afterRetry.inboundReceipts.filter {
                $0.envelopeId == prepared.envelope.id
            }.count,
            1
        )
        XCTAssertEqual(
            afterRetry.localReceiveRoutes.first?.committedSequence,
            UInt64(delivery.packets.count)
        )
    }

    func testAuthenticatedInvalidRouteProbeRetainsRatchetProgressForFollowingMessage() async throws {
        let fixture = try await makeFixture(label: #function)
        defer { tearDown(fixture) }

        let senderRelationship = try await fixture.sender.relationship(fixture.relationshipID)
        let sendRoute = try XCTUnwrap(senderRelationship.peerIdentity.sendRoutes.routes.first)
        let invalidProbe = RelationshipRouteProbeV2(
            relationshipID: UUID(),
            routeID: sendRoute.routeID,
            routeSetRevision: senderRelationship.peerIdentity.sendRoutes.revision
        )
        let invalidControl = try await fixture.sender.sendRelationshipControl(
            kind: .routeProbe,
            payload: invalidProbe,
            relationshipID: fixture.relationshipID,
            sentAt: fixture.baseDate.addingTimeInterval(2)
        )
        XCTAssertEqual(invalidControl.acceptedDeliveryCount, 1)

        let valid = try await fixture.sender.sendText(
            "valid after authenticated invalid control",
            relationshipID: fixture.relationshipID,
            sentAt: fixture.baseDate.addingTimeInterval(3)
        )
        XCTAssertEqual(valid.acceptedDeliveryCount, 1)

        let result = try await syncOneRoute(
            fixture.receiver,
            relationshipID: fixture.relationshipID,
            maximumPackets: 256
        )
        XCTAssertEqual(result.receivedEvents.map(\.id), [valid.event.id])
        let relationship = try await fixture.receiver.relationship(fixture.relationshipID)
        XCTAssertTrue(relationship.transportQuarantine.contains {
            $0.reason == .invalidControl
                && $0.innerEnvelopeID == invalidControl.envelope.id
        })
        XCTAssertEqual(relationship.events.filter { $0.id == valid.event.id }.count, 1)
        XCTAssertFalse(relationship.events.contains { $0.id == invalidControl.event.id })
        XCTAssertEqual(
            relationship.inboundReceipts.filter {
                $0.envelopeId == invalidControl.envelope.id
                    || $0.envelopeId == valid.envelope.id
            }.count,
            2
        )
        let session = try XCTUnwrap(relationship.directSessions.first)
        XCTAssertEqual(session.receiveChain.counter, 2)
        XCTAssertEqual(session.ratchetState, .active)
    }

    func testFirstGappedRouteDoesNotStarveLaterHealthyRoute() async throws {
        let fixture = try await makeFixture(label: #function)
        defer { tearDown(fixture) }

        let policy = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .oneHour,
            quotaBucket: .packets256
        )
        let additionalParticipant = try await makeParticipant(
            pseudonym: "Additional receiver route",
            relay: fixture.endpoint,
            policy: policy,
            createdAt: fixture.baseDate.addingTimeInterval(2)
        )
        let additionalRoute = additionalParticipant.localReceiveRoute
        let healthySendRoute = try additionalRoute.peerSendRoute(state: .active)

        var receiverRelationship = try await fixture.receiver.relationship(
            fixture.relationshipID
        )
        let originalSendRoute = try XCTUnwrap(
            receiverRelationship.localReceiveRoutes.first
        ).peerSendRoute(state: .active)
        let firstRouteID = try XCTUnwrap(
            receiverRelationship.localReceiveRoutes.first?.route.routeID
        )
        receiverRelationship.localReceiveRoutes[0].gapState = OpaqueRouteGapStateV2(
            reason: .sequenceDiscontinuity,
            expectedSequence: 0,
            observedSequence: 1,
            retentionFloorSequence: 0,
            detectedAt: fixture.baseDate.addingTimeInterval(3)
        )
        receiverRelationship.localReceiveRoutes.append(additionalRoute)
        receiverRelationship.localAdvertisedRoutes = try PairwiseRouteSetV2.create(
            relationshipID: fixture.relationshipID,
            ownerEndpointHandle: receiverRelationship.localEndpointHandle,
            activeRoutes: [originalSendRoute, healthySendRoute],
            issuedAt: fixture.baseDate.addingTimeInterval(3),
            signingKey: receiverRelationship.localIdentity.localEndpoint.signingKey
        )
        XCTAssertTrue(receiverRelationship.isStructurallyValid)
        let receiverScope = await fixture.receiver.mintActivePersonaScopeToken()
        try await fixture.receiver.addRelationship(
            receiverRelationship,
            personaScope: receiverScope
        )

        let prepared = try await fixture.sender.prepareSend(
            body: .text("healthy second route remains available"),
            relationshipID: fixture.relationshipID,
            sentAt: fixture.baseDate.addingTimeInterval(4)
        )
        let healthyBundle = try OpaqueRouteSealedBundleV2.seal(
            NoctweaveCoder.encode(prepared.envelope, sortedKeys: true),
            to: healthySendRoute
        )
        try await append(healthyBundle.packets, through: healthySendRoute)

        let results = try await fixture.receiver.sync(
            relationshipID: fixture.relationshipID,
            maximumPackets: 256
        )
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].receivedEvents.map(\.id), [prepared.event.id])

        let finalRelationship = try await fixture.receiver.relationship(
            fixture.relationshipID
        )
        let failedRoute = try XCTUnwrap(finalRelationship.localReceiveRoutes.first {
            $0.route.routeID == firstRouteID
        })
        let healthyRoute = try XCTUnwrap(finalRelationship.localReceiveRoutes.first {
            $0.route.routeID == additionalRoute.route.routeID
        })
        XCTAssertEqual(failedRoute.gapState?.reason, .sequenceDiscontinuity)
        XCTAssertEqual(failedRoute.committedSequence, 0)
        XCTAssertEqual(healthyRoute.committedSequence, UInt64(healthyBundle.packets.count))
        XCTAssertEqual(finalRelationship.events.filter { $0.id == prepared.event.id }.count, 1)
    }

    func testBlockingCursorCommittedPartialBundlePreventsCompletionAfterUnblock() async throws {
        let fixture = try await makeFixture(label: #function)
        defer { tearDown(fixture) }

        let prepared = try await fixture.sender.prepareSend(
            body: .text(String(repeating: "b", count: 2_000)),
            relationshipID: fixture.relationshipID,
            sentAt: fixture.baseDate.addingTimeInterval(2)
        )
        let delivery = try await pendingDelivery(
            for: prepared,
            client: fixture.sender
        )
        XCTAssertGreaterThan(delivery.packets.count, 1)
        let sendRoute = try await activeSendRoute(in: fixture.sender, fixture: fixture)
        try await append(delivery.packets, through: sendRoute)

        let firstPage = try await syncOneRoute(
            fixture.receiver,
            relationshipID: fixture.relationshipID,
            maximumPackets: 1
        )
        XCTAssertTrue(firstPage.receivedEvents.isEmpty)
        XCTAssertTrue(firstPage.hasMore)
        let partial = try await fixture.receiver.relationship(fixture.relationshipID)
        XCTAssertEqual(partial.localReceiveRoutes.first?.committedSequence, 1)
        XCTAssertEqual(partial.localReceiveRoutes.first?.reassembler.pendingBundleCount, 1)

        var blockedPolicy = partial.localPolicy
        blockedPolicy.consent = .blocked
        try await fixture.receiver.setRelationshipLocalPolicy(
            blockedPolicy,
            relationshipID: fixture.relationshipID,
            at: fixture.baseDate.addingTimeInterval(3)
        )
        let blocked = try await fixture.receiver.relationship(fixture.relationshipID)
        XCTAssertEqual(blocked.localReceiveRoutes.first?.reassembler.pendingBundleCount, 0)
        XCTAssertEqual(blocked.localReceiveRoutes.first?.reassembler.bufferedPayloadBytes, 0)

        let reopened = try await HeadlessMessagingClient.open(
            stateStore: fixture.receiverStore,
            displayName: "ignored after blocked reopen"
        )
        let reopenedBlocked = try await reopened.relationship(fixture.relationshipID)
        var acceptedPolicy = reopenedBlocked.localPolicy
        XCTAssertEqual(acceptedPolicy.consent, .blocked)
        XCTAssertEqual(
            reopenedBlocked.localReceiveRoutes.first?.reassembler.pendingBundleCount,
            0
        )
        acceptedPolicy.consent = .accepted
        try await reopened.setRelationshipLocalPolicy(
            acceptedPolicy,
            relationshipID: fixture.relationshipID,
            at: fixture.baseDate.addingTimeInterval(4)
        )

        let remainder = try await syncOneRoute(
            reopened,
            relationshipID: fixture.relationshipID,
            maximumPackets: 256
        )
        XCTAssertTrue(remainder.receivedEvents.isEmpty)
        XCTAssertFalse(remainder.hasMore)
        let drained = try await syncOneRoute(
            reopened,
            relationshipID: fixture.relationshipID,
            maximumPackets: 256
        )
        XCTAssertTrue(drained.receivedEvents.isEmpty)

        let finalRelationship = try await reopened.relationship(fixture.relationshipID)
        XCTAssertFalse(finalRelationship.events.contains { $0.id == prepared.event.id })
        XCTAssertFalse(finalRelationship.inboundReceipts.contains {
            $0.envelopeId == prepared.envelope.id
        })
        XCTAssertEqual(
            finalRelationship.localReceiveRoutes.first?.committedSequence,
            UInt64(delivery.packets.count)
        )
    }

    func testAutomaticReceiptFailureAfterLocalCommitStillReturnsEventExactlyOnce() async throws {
        let fixture = try await makeFixture(label: #function)
        defer { tearDown(fixture) }

        let prepared = try await fixture.sender.prepareSend(
            body: .text("inbound event survives automatic follow-up failure"),
            relationshipID: fixture.relationshipID,
            sentAt: fixture.baseDate.addingTimeInterval(2)
        )
        let delivery = try await pendingDelivery(
            for: prepared,
            client: fixture.sender
        )
        let receiverSendRoute = try await activeSendRoute(
            in: fixture.sender,
            fixture: fixture
        )
        try await append(delivery.packets, through: receiverSendRoute)

        let senderRelationship = try await fixture.sender.relationship(fixture.relationshipID)
        var receiverRelationship = try await fixture.receiver.relationship(
            fixture.relationshipID
        )
        let originalPeerRoute = try XCTUnwrap(
            receiverRelationship.peerIdentity.sendRoutes.routes.first
        )
        let expiredPeerRoute = try replacingExpiry(
            in: originalPeerRoute,
            expiresAt: fixture.baseDate.addingTimeInterval(5)
        )
        receiverRelationship.peerIdentity.sendRoutes = try PairwiseRouteSetV2.create(
            relationshipID: fixture.relationshipID,
            ownerEndpointHandle: senderRelationship.localEndpointHandle,
            activeRoutes: [expiredPeerRoute],
            issuedAt: fixture.baseDate.addingTimeInterval(1),
            signingKey: senderRelationship.localIdentity.localEndpoint.signingKey
        )
        XCTAssertTrue(receiverRelationship.isStructurallyValid)
        let receiverScope = await fixture.receiver.mintActivePersonaScopeToken()
        try await fixture.receiver.addRelationship(
            receiverRelationship,
            personaScope: receiverScope
        )

        let result = try await syncOneRoute(
            fixture.receiver,
            relationshipID: fixture.relationshipID,
            maximumPackets: 256
        )
        XCTAssertEqual(result.receivedEvents.map(\.id), [prepared.event.id])
        XCTAssertNotNil(result.committedCursor)
        let drained = try await syncOneRoute(
            fixture.receiver,
            relationshipID: fixture.relationshipID,
            maximumPackets: 256
        )
        XCTAssertTrue(drained.receivedEvents.isEmpty)

        let finalRelationship = try await fixture.receiver.relationship(
            fixture.relationshipID
        )
        XCTAssertEqual(finalRelationship.events.filter { $0.id == prepared.event.id }.count, 1)
        XCTAssertFalse(finalRelationship.events.contains {
            $0.authorEndpointHandle == finalRelationship.localEndpointHandle
                && $0.kind == .receipt
                && $0.content.type == .deliveryReceipt
        })
        XCTAssertTrue(finalRelationship.pendingDeliveries.isEmpty)
        XCTAssertEqual(
            finalRelationship.inboundReceipts.filter {
                $0.envelopeId == prepared.envelope.id
            }.count,
            1
        )
    }

    private func makeFixture(
        label: String,
        receiverRouteExpiresIn: TimeInterval? = nil
    ) async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweave-live-sync-\(label)-\(UUID().uuidString)"
        )
        let senderDirectory = root.appendingPathComponent("sender-state")
        let receiverDirectory = root.appendingPathComponent("receiver-state")
        let senderStateURL = senderDirectory.appendingPathComponent("state.json")
        let receiverStateURL = receiverDirectory.appendingPathComponent("state.json")
        let port = UInt16.random(in: 40_000...57_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(
            store: RelayStore(),
            opaqueRouteStore: OpaqueRouteRelayStoreV2()
        )
        do {
            try server.start(host: "127.0.0.1", port: port)
            try await Task.sleep(nanoseconds: 100_000_000)

            let baseDate = NoctweaveRendezvousV2.canonicalTimestamp(
                Date().addingTimeInterval(-10)
            )
            let policy = OpaqueRoutePolicyV2(
                paddingBucket: .bytes4096,
                retentionBucket: .oneHour,
                quotaBucket: .packets256
            )
            let senderParticipant = try await makeParticipant(
                pseudonym: "Sender",
                relay: endpoint,
                policy: policy,
                createdAt: baseDate
            )
            let receiverParticipant = try await makeParticipant(
                pseudonym: "Receiver",
                relay: endpoint,
                policy: policy,
                createdAt: baseDate
            )
            var pendingOffer = try ContactPairingHandshakeV2.makeOffer(
                createdAt: baseDate,
                expiresAt: baseDate.addingTimeInterval(300)
            )
            var redemptionLedger = RendezvousRedemptionLedgerV2()
            let pairing = try ContactPairingHandshakeV2.establish(
                pendingOffer: &pendingOffer.pending,
                invitation: pendingOffer.invitation,
                offerer: senderParticipant,
                responder: receiverParticipant,
                ledger: &redemptionLedger,
                at: baseDate.addingTimeInterval(1)
            )

            var senderRelationship = pairing.offererRelationship
            var receiverRelationship = pairing.responderRelationship
            if let receiverRouteExpiresIn {
                let original = try XCTUnwrap(receiverRelationship.localReceiveRoutes.first)
                let expiry = NoctweaveRendezvousV2.canonicalTimestamp(
                    Date().addingTimeInterval(receiverRouteExpiresIn)
                )
                let shortened = try replacingExpiry(in: original, expiresAt: expiry)
                let advertised = try shortened.peerSendRoute(state: .active)
                let routeSet = try PairwiseRouteSetV2.create(
                    relationshipID: receiverRelationship.id,
                    ownerEndpointHandle: receiverRelationship.localEndpointHandle,
                    activeRoutes: [advertised],
                    issuedAt: receiverRelationship.localAdvertisedRoutes.issuedAt,
                    signingKey: receiverRelationship.localIdentity.localEndpoint.signingKey
                )
                receiverRelationship.localReceiveRoutes = [shortened]
                receiverRelationship.localAdvertisedRoutes = routeSet
                senderRelationship.peerIdentity.sendRoutes = routeSet
            }

            var senderState = try ClientState(
                displayName: "Sender local persona",
                createdAt: baseDate
            )
            try senderState.updateActivePersona {
                try $0.upsert(relationship: senderRelationship)
            }
            var receiverState = try ClientState(
                displayName: "Receiver local persona",
                createdAt: baseDate
            )
            try receiverState.updateActivePersona {
                try $0.upsert(relationship: receiverRelationship)
            }
            let senderStore = ClientStateStore(
                fileURL: senderStateURL,
                protection: .insecurePlaintextForTesting
            )
            let receiverStore = ClientStateStore(
                fileURL: receiverStateURL,
                protection: .insecurePlaintextForTesting
            )
            try await senderStore.save(senderState, replacing: nil)
            try await receiverStore.save(receiverState, replacing: nil)
            return Fixture(
                rootDirectory: root,
                senderDirectory: senderDirectory,
                receiverDirectory: receiverDirectory,
                receiverStateURL: receiverStateURL,
                server: server,
                endpoint: endpoint,
                sender: try HeadlessMessagingClient(
                    stateStore: senderStore,
                    initialState: senderState
                ),
                receiver: try HeadlessMessagingClient(
                    stateStore: receiverStore,
                    initialState: receiverState
                ),
                receiverStore: receiverStore,
                relationshipID: pairing.relationshipID,
                baseDate: baseDate
            )
        } catch {
            server.stop()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private func makeParticipant(
        pseudonym: String,
        relay: RelayEndpoint,
        policy: OpaqueRoutePolicyV2,
        createdAt: Date
    ) async throws -> PreparedContactParticipantV2 {
        let pending = try PendingContactParticipantV2.prepare(
            relationshipPseudonym: pseudonym,
            relay: relay,
            policy: policy,
            createdAt: createdAt
        )
        let response = try await RelayClient(endpoint: relay).send(
            .createOpaqueRouteV2(
                CreateOpaqueRouteRelayRequestV2(
                    request: pending.routeCreateRequest,
                    renewCapability: pending.clientCapabilities.renewCapability
                )
            )
        )
        guard case .opaqueRoute(let route)? = response.successBody else {
            throw FixtureError.invalidRelayResponse
        }
        return try pending.activate(createdRoute: route)
    }

    private func tearDown(_ fixture: Fixture) {
        fixture.server.stop()
        try? FileManager.default.removeItem(at: fixture.rootDirectory)
    }

    private func pendingDelivery(
        for prepared: HeadlessPreparedSend,
        client: HeadlessMessagingClient
    ) async throws -> PendingOpaqueRouteDeliveryV2 {
        let relationship = try await client.relationship(prepared.relationshipID)
        return try XCTUnwrap(relationship.pendingDeliveries.first {
            prepared.deliveryIDs.contains($0.id)
        })
    }

    private func activeSendRoute(
        in client: HeadlessMessagingClient,
        fixture: Fixture
    ) async throws -> OpaqueSendRouteV2 {
        let relationship = try await client.relationship(fixture.relationshipID)
        return try XCTUnwrap(relationship.peerIdentity.sendRoutes.routes.first {
            $0.state == .active
        })
    }

    private func append(
        _ packets: [OpaqueRoutePacketV2],
        through route: OpaqueSendRouteV2
    ) async throws {
        let client = RelayClient(endpoint: route.relay)
        for packet in packets {
            let response = try await client.send(
                .appendOpaqueRouteV2(
                    AppendOpaqueRouteRelayRequestV2(
                        packet: packet,
                        sendCapability: route.sendCapability
                    )
                )
            )
            guard case .opaqueRouteAppend(let receipt)? = response.successBody,
                  receipt.packetID == packet.packetID else {
                throw FixtureError.invalidRelayResponse
            }
        }
    }

    private func syncOneRoute(
        _ client: HeadlessMessagingClient,
        relationshipID: UUID,
        maximumPackets: UInt16
    ) async throws -> HeadlessSyncResult {
        let results = try await client.sync(
            relationshipID: relationshipID,
            maximumPackets: maximumPackets
        )
        return try XCTUnwrap(results.first)
    }

    private func replacingPayloadKey(
        in route: OpaqueSendRouteV2,
        with payloadKey: OpaqueRoutePayloadKeyV2
    ) throws -> OpaqueSendRouteV2 {
        try OpaqueSendRouteV2(
            routeID: route.routeID,
            relay: route.relay,
            sendCapability: route.sendCapability,
            payloadKey: payloadKey,
            routeRevision: route.routeRevision,
            policy: route.policy,
            validFrom: route.validFrom,
            expiresAt: route.expiresAt,
            priority: route.priority,
            state: route.state,
            testedAt: route.testedAt,
            drainAfter: route.drainAfter,
            revokedAt: route.revokedAt
        )
    }

    private func replacingExpiry(
        in route: OpaqueSendRouteV2,
        expiresAt: Date
    ) throws -> OpaqueSendRouteV2 {
        try OpaqueSendRouteV2(
            routeID: route.routeID,
            relay: route.relay,
            sendCapability: route.sendCapability,
            payloadKey: route.payloadKey,
            routeRevision: route.routeRevision,
            policy: route.policy,
            validFrom: route.validFrom,
            expiresAt: expiresAt,
            priority: route.priority,
            state: route.state,
            testedAt: route.testedAt,
            drainAfter: route.drainAfter,
            revokedAt: route.revokedAt
        )
    }

    private func replacingExpiry(
        in route: LocalOpaqueReceiveRouteV2,
        expiresAt: Date
    ) throws -> LocalOpaqueReceiveRouteV2 {
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: NoctweaveCoder.encode(route.route, sortedKeys: true)
            ) as? [String: Any]
        )
        let lease = try OpaqueRouteLeaseV2(
            issuedAt: route.route.lease.issuedAt,
            expiresAt: expiresAt,
            policy: route.route.lease.policy
        )
        object["lease"] = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: NoctweaveCoder.encode(lease, sortedKeys: true)
            ) as? [String: Any]
        )
        let replacement = try NoctweaveCoder.decode(
            OpaqueReceiveRouteV2.self,
            from: JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        )
        return try LocalOpaqueReceiveRouteV2(
            relay: route.relay,
            route: replacement,
            clientCapabilities: route.clientCapabilities,
            payloadKey: route.payloadKey,
            committedCursor: route.committedCursor,
            committedSequence: route.committedSequence,
            committedRecordDigest: route.committedRecordDigest,
            gapState: route.gapState,
            reassembler: route.reassembler
        )
    }

    private func signatureMutated(
        _ envelope: DirectEnvelopeV4
    ) throws -> DirectEnvelopeV4 {
        var signature = envelope.signature
        guard !signature.isEmpty else { throw FixtureError.invalidRelayResponse }
        signature[signature.startIndex] ^= 0x01
        return DirectEnvelopeV4(
            id: envelope.id,
            payloadFormat: envelope.payloadFormat,
            conversationId: envelope.conversationId,
            sessionId: envelope.sessionId,
            eventId: envelope.eventId,
            senderEndpointHandle: envelope.senderEndpointHandle,
            senderBindingDigest: envelope.senderBindingDigest,
            recipientEndpointHandle: envelope.recipientEndpointHandle,
            recipientBindingDigest: envelope.recipientBindingDigest,
            cipherSuite: envelope.cipherSuite,
            negotiatedCapabilitiesDigest: envelope.negotiatedCapabilitiesDigest,
            bootstrap: envelope.bootstrap,
            sentAt: envelope.sentAt,
            messageCounter: envelope.messageCounter,
            payload: envelope.payload,
            signature: signature
        )
    }
}
