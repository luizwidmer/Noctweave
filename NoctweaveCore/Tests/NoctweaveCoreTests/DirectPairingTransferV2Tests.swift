import Foundation
import XCTest
@testable import NoctweaveCore

final class DirectPairingTransferV2Tests: XCTestCase {
    private let origin = Date(timeIntervalSince1970: 1_900_100_000)

    func testDirectCarrierCompletesAuthenticatedPairingWithoutRendezvousRelay() throws {
        var offer = try ContactPairingHandshakeV2.makeOffer(
            createdAt: origin,
            expiresAt: origin.addingTimeInterval(300)
        )
        let offerer = try makeParticipant(name: "Alice", host: "alice.example")
        let responder = try makeParticipant(name: "Bob", host: "bob.example")

        let invitationTransfer = try roundTrip(
            .invitation(offer.invitation)
        )
        let invitation = try XCTUnwrap(invitationTransfer.invitation)

        let responderStart = try ContactPairingResponderFlowV2.begin(
            invitation: invitation,
            participant: responder,
            at: origin.addingTimeInterval(1)
        )
        var responderFlow = responderStart.flow
        let responseTransfer = try roundTrip(
            .response(
                openRequest: responderStart.openRequest,
                acceptanceFrame: responderStart.acceptanceFrame
            )
        )

        var ledger = RendezvousRedemptionLedgerV2()
        let offererStart = try ContactPairingOffererFlowV2.begin(
            pendingOffer: &offer.pending,
            invitation: invitation,
            participant: offerer,
            openRequest: try XCTUnwrap(responseTransfer.openRequest),
            acceptanceFrame: try XCTUnwrap(responseTransfer.frame),
            ledger: &ledger,
            at: origin.addingTimeInterval(2)
        )
        var offererFlow = offererStart.flow
        let contactOfferTransfer = try roundTrip(.offer(offererStart.offerFrame))

        let responderConfirmation = try responderFlow.receiveOffer(
            try XCTUnwrap(contactOfferTransfer.frame),
            at: origin.addingTimeInterval(3)
        )
        let confirmationTransfer = try roundTrip(.confirmation(responderConfirmation))

        let offererCompletion = try offererFlow.receiveConfirmation(
            try XCTUnwrap(confirmationTransfer.frame),
            at: origin.addingTimeInterval(4)
        )
        let finalTransfer = try roundTrip(
            .finalConfirmation(offererCompletion.confirmationFrame)
        )
        let responderRelationship = try responderFlow.receiveConfirmation(
            try XCTUnwrap(finalTransfer.frame),
            at: origin.addingTimeInterval(5)
        )

        XCTAssertEqual(offererCompletion.relationship.id, responderRelationship.id)
        XCTAssertEqual(
            offererCompletion.relationship.peerIdentity.signingPublicKey,
            responder.localIdentity.relationshipAuthority.signingKey.publicKeyData
        )
        XCTAssertEqual(
            responderRelationship.peerIdentity.signingPublicKey,
            offerer.localIdentity.relationshipAuthority.signingKey.publicKeyData
        )
        XCTAssertEqual(ledger.redemptionCount, 1)
    }

    func testDirectCarrierCreatesBidirectionalLiveConversation() async throws {
        let port = UInt16.random(in: 53_100...54_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(
            store: RelayStore(),
            opaqueRouteStore: OpaqueRouteRelayStoreV2()
        )
        let started = expectation(description: "relay started")
        server.onEvent = { event in
            if case .started = event { started.fulfill() }
        }
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2)

        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweave-direct-pairing-\(UUID().uuidString)",
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let alice = try await makeClient(name: "Alice", directory: root.appendingPathComponent("alice"))
        let bob = try await makeClient(name: "Bob", directory: root.appendingPathComponent("bob"))
        let now = NoctweaveRendezvousV2.canonicalTimestamp(Date())

        let alicePending = try await alice.prepareContactParticipant(
            relay: endpoint,
            relationshipPseudonym: "Alice",
            createdAt: now
        )
        let aliceParticipant = try await alice.activateContactParticipant(alicePending)
        let bobPending = try await bob.prepareContactParticipant(
            relay: endpoint,
            relationshipPseudonym: "Bob",
            createdAt: now
        )
        let bobParticipant = try await bob.activateContactParticipant(bobPending)

        var offer = try await alice.makeContactPairingInvitation(
            createdAt: now,
            expiresAt: now.addingTimeInterval(300)
        )
        let invitation = try XCTUnwrap(
            roundTrip(.invitation(offer.invitation)).invitation
        )
        let responderStart = try ContactPairingResponderFlowV2.begin(
            invitation: invitation,
            participant: bobParticipant,
            at: now.addingTimeInterval(1)
        )
        var responderFlow = responderStart.flow
        let response = try roundTrip(.response(
            openRequest: responderStart.openRequest,
            acceptanceFrame: responderStart.acceptanceFrame
        ))
        var ledger = RendezvousRedemptionLedgerV2()
        let offererStart = try ContactPairingOffererFlowV2.begin(
            pendingOffer: &offer.pending,
            invitation: invitation,
            participant: aliceParticipant,
            openRequest: try XCTUnwrap(response.openRequest),
            acceptanceFrame: try XCTUnwrap(response.frame),
            ledger: &ledger,
            at: now.addingTimeInterval(2)
        )
        var offererFlow = offererStart.flow
        let contactOffer = try roundTrip(.offer(offererStart.offerFrame))
        let responderConfirmation = try responderFlow.receiveOffer(
            try XCTUnwrap(contactOffer.frame),
            at: now.addingTimeInterval(3)
        )
        let confirmation = try roundTrip(.confirmation(responderConfirmation))
        let offererCompletion = try offererFlow.receiveConfirmation(
            try XCTUnwrap(confirmation.frame),
            at: now.addingTimeInterval(4)
        )
        let final = try roundTrip(
            .finalConfirmation(offererCompletion.confirmationFrame)
        )
        let bobRelationship = try responderFlow.receiveConfirmation(
            try XCTUnwrap(final.frame),
            at: now.addingTimeInterval(5)
        )

        let aliceScope = await alice.mintActivePersonaScopeToken()
        try await alice.addRelationship(
            offererCompletion.relationship,
            consent: .accepted,
            personaScope: aliceScope
        )
        let bobScope = await bob.mintActivePersonaScopeToken()
        try await bob.addRelationship(
            bobRelationship,
            consent: .accepted,
            personaScope: bobScope
        )

        let aliceMessage = try await alice.prepareSend(
            body: .text("hello from Alice"),
            relationshipID: offererCompletion.relationship.id,
            sentAt: now.addingTimeInterval(6)
        )
        let alicePublication = try await alice.publishPreparedSend(
            aliceMessage,
            at: now.addingTimeInterval(7)
        )
        XCTAssertEqual(alicePublication.acceptedDeliveryCount, 1)
        let bobSync = try await bob.sync(relationshipID: bobRelationship.id)
        XCTAssertEqual(bobSync.flatMap(\.receivedEvents).map(\.id), [aliceMessage.event.id])

        let bobMessage = try await bob.prepareSend(
            body: .text("hello from Bob"),
            relationshipID: bobRelationship.id,
            sentAt: now.addingTimeInterval(8)
        )
        let bobPublication = try await bob.publishPreparedSend(
            bobMessage,
            at: now.addingTimeInterval(9)
        )
        XCTAssertEqual(bobPublication.acceptedDeliveryCount, 1)
        let aliceSync = try await alice.sync(
            relationshipID: offererCompletion.relationship.id
        )
        XCTAssertTrue(
            aliceSync.flatMap(\.receivedEvents).map(\.id).contains(bobMessage.event.id),
            "The reply must arrive even when an automatic delivery receipt shares the route."
        )
    }

    func testLiveBuiltAppExchangeHarness() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["NOCTWEAVE_RUN_LIVE_APP_SCENARIO"] == "1" else {
            throw XCTSkip("The built-app exchange harness is opt-in.")
        }
        let rootPath = try XCTUnwrap(environment["NOCTWEAVE_LIVE_APP_ROOT"])
        let port = try XCTUnwrap(UInt16(environment["NOCTWEAVE_LIVE_APP_PORT"] ?? ""))
        let root = URL(fileURLWithPath: rootPath, isDirectory: true).standardizedFileURL
        let senderDirectory = root.appendingPathComponent("sender", isDirectory: true)
        let receiverDirectory = root.appendingPathComponent("receiver", isDirectory: true)
        let senderStateURL = senderDirectory.appendingPathComponent("state.json")
        let receiverStateURL = receiverDirectory.appendingPathComponent("state.json")
        XCTAssertFalse(FileManager.default.fileExists(atPath: senderStateURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: receiverStateURL.path))
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: root.path
        )

        let server = RelayServer(
            store: RelayStore(),
            opaqueRouteStore: OpaqueRouteRelayStoreV2()
        )
        let started = expectation(description: "live app relay started")
        server.onEvent = { event in
            if case .started = event { started.fulfill() }
        }
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 5)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)

        let sender = try await makeClient(
            name: "Sender",
            directory: senderDirectory,
            completeOnboarding: true
        )
        let receiver = try await makeClient(
            name: "Receiver",
            directory: receiverDirectory,
            completeOnboarding: true
        )
        let now = NoctweaveRendezvousV2.canonicalTimestamp(Date())
        let senderPending = try await sender.prepareContactParticipant(
            relay: endpoint,
            relationshipPseudonym: "Sender",
            createdAt: now
        )
        let senderParticipant = try await sender.activateContactParticipant(senderPending)
        let receiverPending = try await receiver.prepareContactParticipant(
            relay: endpoint,
            relationshipPseudonym: "Receiver",
            createdAt: now
        )
        let receiverParticipant = try await receiver.activateContactParticipant(receiverPending)

        var offer = try await sender.makeContactPairingInvitation(
            createdAt: now,
            expiresAt: now.addingTimeInterval(300)
        )
        let invitation = offer.invitation
        let responderStart = try ContactPairingResponderFlowV2.begin(
            invitation: invitation,
            participant: receiverParticipant,
            at: now.addingTimeInterval(1)
        )
        var responderFlow = responderStart.flow
        var ledger = RendezvousRedemptionLedgerV2()
        let offererStart = try ContactPairingOffererFlowV2.begin(
            pendingOffer: &offer.pending,
            invitation: invitation,
            participant: senderParticipant,
            openRequest: responderStart.openRequest,
            acceptanceFrame: responderStart.acceptanceFrame,
            ledger: &ledger,
            at: now.addingTimeInterval(2)
        )
        var offererFlow = offererStart.flow
        let responderConfirmation = try responderFlow.receiveOffer(
            offererStart.offerFrame,
            at: now.addingTimeInterval(3)
        )
        let offererCompletion = try offererFlow.receiveConfirmation(
            responderConfirmation,
            at: now.addingTimeInterval(4)
        )
        let receiverRelationship = try responderFlow.receiveConfirmation(
            offererCompletion.confirmationFrame,
            at: now.addingTimeInterval(5)
        )

        let senderScope = await sender.mintActivePersonaScopeToken()
        try await sender.addRelationship(
            offererCompletion.relationship,
            consent: .accepted,
            personaScope: senderScope
        )
        let receiverScope = await receiver.mintActivePersonaScopeToken()
        try await receiver.addRelationship(
            receiverRelationship,
            consent: .accepted,
            personaScope: receiverScope
        )

        let proofText = "Noctweave attachment proof \(UUID().uuidString.lowercased())\n"
        let proofURL = root.appendingPathComponent("attachment-proof.txt")
        try Data(proofText.utf8).write(to: proofURL, options: .atomic)
        let readyURL = root.appendingPathComponent("ready.json")
        let metadata: [String: Any] = [
            "relayPort": Int(port),
            "relationshipID": offererCompletion.relationship.id.uuidString,
            "senderState": senderStateURL.path,
            "receiverState": receiverStateURL.path,
            "attachmentPath": proofURL.path,
            "attachmentText": proofText.trimmingCharacters(in: .newlines),
        ]
        let readyData = try JSONSerialization.data(
            withJSONObject: metadata,
            options: [.prettyPrinted, .sortedKeys]
        )
        try readyData.write(to: readyURL, options: .atomic)
        FileHandle.standardError.write(
            Data("[NoctweaveLiveApp] ready \(readyURL.path)\n".utf8)
        )

        let stopURL = root.appendingPathComponent("stop")
        let deadline = Date().addingTimeInterval(15 * 60)
        while Date() < deadline,
              !FileManager.default.fileExists(atPath: stopURL.path) {
            try await Task.sleep(nanoseconds: 250_000_000)
        }
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: stopURL.path),
            "The built-app exchange harness timed out before its stop marker arrived."
        )
    }

    func testDirectCarrierRejectsUnknownFields() throws {
        let offer = try ContactPairingHandshakeV2.makeOffer(
            createdAt: origin,
            expiresAt: origin.addingTimeInterval(300)
        )
        let transfer = try DirectPairingTransferV2.invitation(offer.invitation)
        let encoded = try NoctweaveCoder.encode(transfer, sortedKeys: true)
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        object["account"] = "forbidden"
        let malformed = try JSONSerialization.data(withJSONObject: object)

        XCTAssertThrowsError(
            try NoctweaveCoder.decode(DirectPairingTransferV2.self, from: malformed)
        )
    }

    private func roundTrip(
        _ transfer: @autoclosure () throws -> DirectPairingTransferV2
    ) throws -> DirectPairingTransferV2 {
        let value = try transfer()
        XCTAssertTrue(value.isStructurallyValid)
        let decoded = try DirectPairingTransferV2.decode(value.encoded())
        XCTAssertEqual(decoded, value)
        return decoded
    }

    private func makeParticipant(
        name: String,
        host: String
    ) throws -> PreparedContactParticipantV2 {
        let relay = RelayEndpoint(host: host, port: 443, useTLS: true, transport: .websocket)
        let pending = try PendingContactParticipantV2.prepare(
            relationshipPseudonym: name,
            relay: relay,
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

    private func makeClient(
        name: String,
        directory: URL,
        completeOnboarding: Bool = false
    ) async throws -> HeadlessMessagingClient {
        var state = try ClientState(displayName: name, createdAt: origin)
        if completeOnboarding {
            try state.completeOnboarding(
                privacyPolicyAccepted: true,
                termsOfUseAccepted: true
            )
        }
        let store = ClientStateStore(
            fileURL: directory.appendingPathComponent("state.json"),
            protection: .insecurePlaintextForTesting
        )
        try await store.save(state, replacing: nil)
        return try HeadlessMessagingClient(stateStore: store, initialState: state)
    }
}
