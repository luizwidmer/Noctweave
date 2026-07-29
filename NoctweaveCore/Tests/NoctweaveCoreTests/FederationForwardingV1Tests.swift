import Foundation
import XCTest
@testable import NoctweaveCore

final class FederationForwardingV1Tests: XCTestCase {
    func testSignedDeliveryRejectsDestinationSubstitution() throws {
        let sourceKey = try RelayIdentityKeyMaterialV1.generate()
        let destinationKey = try RelayIdentityKeyMaterialV1.generate()
        let otherDestinationKey = try RelayIdentityKeyMaterialV1.generate()
        let federation = FederationDescriptor(mode: .manual, name: "signed-delivery")
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: 9_339)
        let capabilities = RelayCapabilityManifestV2.advertised(
            attachmentsEnabled: true,
            wakeEnabled: false,
            hiddenRetrievalEnabled: false,
            onionEnabled: false,
            mixnetEnabled: false,
            federationForwardingEnabled: true
        )
        let identity = try sourceKey.makeSignedClaim(
            sequence: 1,
            relayKind: .standard,
            federation: federation,
            advertisedEndpoints: [endpoint],
            noctwebSuffix: NoctwebRelaySuffixV1(rawValue: ".source"),
            capabilities: capabilities
        )
        let append = try makeAppend(endpoint: endpoint)
        let delivery = try FederatedOpaqueRouteDeliveryV1.signed(
            sourceIdentity: identity,
            sourceKey: sourceKey,
            destinationRelayID: destinationKey.relayID,
            append: append
        )

        XCTAssertTrue(try delivery.verifyThrowing(
            expectedDestinationRelayID: destinationKey.relayID,
            federation: federation
        ))
        XCTAssertFalse(try delivery.verifyThrowing(
            expectedDestinationRelayID: otherDestinationKey.relayID,
            federation: federation
        ))
    }

    func testForwardingRequestRoundTripsOnStrictWire() throws {
        let destinationKey = try RelayIdentityKeyMaterialV1.generate()
        let endpoint = RelayEndpoint(host: "relay.example", port: 443, useTLS: true)
        let request = RelayRequest.forwardOpaqueRouteV1(
            FederatedOpaqueRouteForwardRequestV1(
                destinationRelayID: destinationKey.relayID,
                destination: endpoint,
                append: try makeAppend(endpoint: endpoint)
            )
        )

        let encoded = try NoctweaveCoder.encode(request)
        let decoded = try NoctweaveCoder.decode(RelayRequest.self, from: encoded)
        XCTAssertEqual(decoded.requestID, request.requestID)
        XCTAssertEqual(decoded.binding, request.binding)
        guard case .forwardOpaqueRoute(let decodedBody) = decoded.body else {
            return XCTFail("Expected a federation forwarding request.")
        }
        XCTAssertEqual(decodedBody.destinationRelayID, destinationKey.relayID)
        XCTAssertEqual(decodedBody.destination, endpoint)
        XCTAssertEqual(
            decodedBody.append.packet.packetID,
            {
                guard case .forwardOpaqueRoute(let originalBody) = request.body else {
                    return decodedBody.append.packet.packetID
                }
                return originalBody.append.packet.packetID
            }()
        )

        var root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        var body = try XCTUnwrap(root["body"] as? [String: Any])
        body["legacyRelayName"] = "not signed"
        root["body"] = body
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                RelayRequest.self,
                from: JSONSerialization.data(withJSONObject: root)
            )
        )
    }

    func testManualFederationForwardsOpaquePacketExactlyOnceToDestination() async throws {
        let federation = FederationDescriptor(mode: .manual, name: "forward-e2e")
        let sourceKey = try RelayIdentityKeyMaterialV1.generate()
        let destinationKey = try RelayIdentityKeyMaterialV1.generate()
        let source = RelayServer(
            store: RelayStore(),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation
            ),
            relayIdentity: sourceKey
        )
        let destination = RelayServer(
            store: RelayStore(),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation
            ),
            relayIdentity: destinationKey
        )
        let sourceStarted = expectation(description: "source relay started")
        let destinationStarted = expectation(description: "destination relay started")
        var sourcePort: UInt16 = 0
        var destinationPort: UInt16 = 0
        source.onEvent = { event in
            if case .started(let port) = event {
                sourcePort = port
                sourceStarted.fulfill()
            }
        }
        destination.onEvent = { event in
            if case .started(let port) = event {
                destinationPort = port
                destinationStarted.fulfill()
            }
        }
        try source.start(port: 0)
        try destination.start(port: 0)
        defer {
            source.stop()
            destination.stop()
        }
        await fulfillment(of: [sourceStarted, destinationStarted], timeout: 5)
        XCTAssertNotEqual(sourcePort, 0)
        XCTAssertNotEqual(destinationPort, 0)
        let sourceEndpoint = RelayEndpoint(host: "127.0.0.1", port: sourcePort)
        let destinationEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: destinationPort
        )
        source.updateFederationRuntimeSettings(
            from: RelayConfiguration(
                kind: .standard,
                federation: federation,
                advertisedEndpoint: sourceEndpoint,
                federationAllowList: [destinationEndpoint]
            )
        )
        destination.updateFederationRuntimeSettings(
            from: RelayConfiguration(
                kind: .standard,
                federation: federation,
                advertisedEndpoint: destinationEndpoint,
                federationAllowList: [sourceEndpoint]
            )
        )

        let destinationClient = RelayClient(endpoint: destinationEndpoint)
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let policy = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .oneHour,
            quotaBucket: .packets64
        )
        let issuedAt = Date()
        let lease = try OpaqueRouteLeaseV2(
            issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(3_600),
            policy: policy
        )
        let create = try material.makeCreateRequest(
            lease: lease,
            idempotencyKey: .generate()
        )
        let createResponse = try await destinationClient.send(
            .createOpaqueRouteV2(
                CreateOpaqueRouteRelayRequestV2(
                    request: create,
                    renewCapability: material.renewCapability
                )
            )
        )
        guard case .opaqueRoute(let created)? = createResponse.successBody else {
            return XCTFail("Destination route creation failed.")
        }
        let sendRoute = try OpaqueSendRouteV2(
            routeID: material.routeID,
            relay: destinationEndpoint,
            sendCapability: material.sendCapability,
            payloadKey: .generate(),
            routeRevision: created.lease.renewalSequence,
            policy: created.lease.policy,
            validFrom: created.lease.issuedAt,
            expiresAt: created.lease.expiresAt,
            state: .active,
            testedAt: created.lease.issuedAt
        )
        let packet = try XCTUnwrap(
            OpaqueRouteSealedBundleV2.seal(
                Data("cross-relay ciphertext".utf8),
                to: sendRoute
            ).packets.first
        )
        let append = AppendOpaqueRouteRelayRequestV2(
            packet: packet,
            sendCapability: material.sendCapability
        )
        let forwarded = try await RelayClient(endpoint: sourceEndpoint).send(
            .forwardOpaqueRouteV1(
                FederatedOpaqueRouteForwardRequestV1(
                    destinationRelayID: destinationKey.relayID,
                    destination: destinationEndpoint,
                    append: append
                )
            )
        )
        guard case .opaqueRouteAppend(let receipt)? = forwarded.successBody else {
            return XCTFail("Source relay did not return the destination append receipt.")
        }
        XCTAssertEqual(receipt.packetID, packet.packetID)

        let sync = try material.makeSyncRequest(after: nil, limit: 8)
        let synced = try await destinationClient.send(
            .syncOpaqueRouteV2(
                SyncOpaqueRouteRelayRequestV2(
                    request: sync,
                    readCredential: material.readCredential
                )
            )
        )
        guard case .opaqueRouteSync(let batch)? = synced.successBody else {
            return XCTFail("Destination route sync failed.")
        }
        XCTAssertEqual(batch.packets.map(\.packet.packetID), [packet.packetID])
    }

    func testHeadlessClientUsesSelectedHomeRelayForCrossRelayDelivery() async throws {
        let federation = FederationDescriptor(mode: .manual, name: "client-forward-e2e")
        let source = RelayServer(
            store: RelayStore(),
            configuration: RelayConfiguration(kind: .standard, federation: federation),
            relayIdentity: try RelayIdentityKeyMaterialV1.generate()
        )
        let destination = RelayServer(
            store: RelayStore(),
            configuration: RelayConfiguration(kind: .standard, federation: federation),
            relayIdentity: try RelayIdentityKeyMaterialV1.generate()
        )
        let sourceStarted = expectation(description: "source relay started")
        let destinationStarted = expectation(description: "destination relay started")
        var sourcePort: UInt16 = 0
        var destinationPort: UInt16 = 0
        source.onEvent = { event in
            if case .started(let port) = event {
                sourcePort = port
                sourceStarted.fulfill()
            }
        }
        destination.onEvent = { event in
            if case .started(let port) = event {
                destinationPort = port
                destinationStarted.fulfill()
            }
        }
        try source.start(port: 0)
        try destination.start(port: 0)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweave-client-forward-\(UUID().uuidString)",
            isDirectory: true
        )
        defer {
            source.stop()
            destination.stop()
            try? FileManager.default.removeItem(at: root)
        }
        await fulfillment(of: [sourceStarted, destinationStarted], timeout: 5)
        let sourceEndpoint = RelayEndpoint(host: "127.0.0.1", port: sourcePort)
        let destinationEndpoint = RelayEndpoint(host: "127.0.0.1", port: destinationPort)
        source.updateFederationRuntimeSettings(
            from: RelayConfiguration(
                kind: .standard,
                federation: federation,
                advertisedEndpoint: sourceEndpoint,
                federationAllowList: [destinationEndpoint]
            )
        )
        destination.updateFederationRuntimeSettings(
            from: RelayConfiguration(
                kind: .standard,
                federation: federation,
                advertisedEndpoint: destinationEndpoint,
                federationAllowList: [sourceEndpoint]
            )
        )

        let now = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
        let policy = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .sixHours,
            quotaBucket: .packets256
        )
        let senderParticipant = try await makeParticipant(
            pseudonym: "sender",
            relay: sourceEndpoint,
            policy: policy,
            createdAt: now
        )
        let receiverParticipant = try await makeParticipant(
            pseudonym: "receiver",
            relay: destinationEndpoint,
            policy: policy,
            createdAt: now
        )
        var offer = try ContactPairingHandshakeV2.makeOffer(
            createdAt: now,
            expiresAt: now.addingTimeInterval(300)
        )
        var ledger = RendezvousRedemptionLedgerV2()
        let pairing = try ContactPairingHandshakeV2.establish(
            pendingOffer: &offer.pending,
            invitation: offer.invitation,
            offerer: senderParticipant,
            responder: receiverParticipant,
            ledger: &ledger,
            at: now.addingTimeInterval(1)
        )

        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        var senderState = try ClientState(displayName: "Sender", createdAt: now)
        try senderState.updateActivePersona {
            try $0.upsert(relationship: pairing.offererRelationship)
        }
        var receiverState = try ClientState(displayName: "Receiver", createdAt: now)
        try receiverState.updateActivePersona {
            try $0.upsert(relationship: pairing.responderRelationship)
        }
        let senderStore = ClientStateStore(
            fileURL: root.appendingPathComponent("sender.json"),
            protection: .insecurePlaintextForTesting
        )
        let receiverStore = ClientStateStore(
            fileURL: root.appendingPathComponent("receiver.json"),
            protection: .insecurePlaintextForTesting
        )
        try await senderStore.save(senderState, replacing: nil)
        try await receiverStore.save(receiverState, replacing: nil)
        let sender = try HeadlessMessagingClient(
            stateStore: senderStore,
            initialState: senderState
        )
        let receiver = try HeadlessMessagingClient(
            stateStore: receiverStore,
            initialState: receiverState
        )
        try await sender.upsertRelayPreference(
            endpoint: sourceEndpoint,
            name: "Home",
            accessPassword: nil
        )
        let configuredSender = await sender.snapshot()
        let homePreference = try XCTUnwrap(
            configuredSender.relayPreferences.first { $0.endpoint == sourceEndpoint }
        )
        try await sender.setPreferredRelayPreference(
            homePreference.id,
            forPersonaID: configuredSender.activePersona.id
        )

        let sent = try await sender.sendText(
            "forwarded by the home relay",
            relationshipID: pairing.relationshipID,
            sentAt: now.addingTimeInterval(2)
        )
        XCTAssertEqual(sent.acceptedDeliveryCount, 1)
        let received = try await receiver.sync(
            relationshipID: pairing.relationshipID,
            maximumPackets: 32
        )
        XCTAssertEqual(received.flatMap(\.receivedEvents).map(\.id), [sent.event.id])
    }

    private func makeAppend(
        endpoint: RelayEndpoint
    ) throws -> AppendOpaqueRouteRelayRequestV2 {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let policy = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .oneHour,
            quotaBucket: .packets64
        )
        let issuedAt = Date()
        let route = try OpaqueSendRouteV2(
            routeID: material.routeID,
            relay: endpoint,
            sendCapability: material.sendCapability,
            payloadKey: .generate(),
            routeRevision: 0,
            policy: policy,
            validFrom: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(3_600),
            state: .active,
            testedAt: issuedAt
        )
        let packet = try XCTUnwrap(
            OpaqueRouteSealedBundleV2.seal(Data("opaque".utf8), to: route)
                .packets.first
        )
        return AppendOpaqueRouteRelayRequestV2(
            packet: packet,
            sendCapability: material.sendCapability
        )
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
            throw HeadlessMessagingClientError.invalidRelayResponse
        }
        return try pending.activate(createdRoute: route)
    }
}
