import Foundation
import XCTest
@testable import NoctweaveCore

final class CuratedFederationAdmissionTests: XCTestCase {
    func testCuratedQuorumRetainsPinsAndRejectsConflicts() {
        let unpinned = RelayEndpoint(
            host: "relay.example",
            port: 443,
            useTLS: true
        )
        var pinned = unpinned
        pinned.tlsCertificateFingerprintSHA256 = Data(
            repeating: 0x51,
            count: 32
        )
        var conflicting = unpinned
        conflicting.tlsCertificateFingerprintSHA256 = Data(
            repeating: 0x52,
            count: 32
        )
        XCTAssertEqual(
            RelayServer.endpointConstrainedByTrustedPins(
                requested: unpinned,
                trusted: [unpinned, pinned]
            )?.tlsCertificateFingerprintSHA256,
            pinned.tlsCertificateFingerprintSHA256
        )
        XCTAssertNil(RelayServer.endpointConstrainedByTrustedPins(
            requested: unpinned,
            trusted: [pinned, conflicting]
        ))
    }

    func testCoordinatorNamespaceClaimRequiresRemoteQuorum() async throws {
        let federation = FederationDescriptor(
            mode: .curated,
            name: "coordinator-namespace-quorum"
        )
        let token = "test-coordinator-quorum-token"
        let coordinatorB = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorRegistrationToken: token
            )
        )
        let coordinatorBEndpoint = try await startOnLoopback(
            coordinatorB,
            description: "remote coordinator started"
        )
        defer { coordinatorB.stop() }
        let coordinatorA = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorRegistrationToken: token,
                federationCoordinatorEndpoints: [
                    try await pinnedEndpoint(coordinatorBEndpoint)
                ],
                curatedCoordinatorQuorum: 2,
                allowPrivateFederationEndpoints: true
            )
        )
        let coordinatorAEndpoint = try await startOnLoopback(
            coordinatorA,
            description: "local coordinator started"
        )
        defer { coordinatorA.stop() }
        let nodeKey = try RelayIdentityKeyMaterialV1.generate()
        let suffix = NoctwebRelaySuffixV1(rawValue: ".coordinatorpeer")!
        let node = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                noctwebRelaySuffix: suffix
            ),
            relayIdentity: nodeKey
        )
        let nodeEndpoint = try await startOnLoopback(
            node,
            description: "coordinator peer started"
        )
        defer { node.stop() }
        try await register(
            nodeEndpoint,
            with: coordinatorAEndpoint,
            token: token
        )
        let nodeInfo = try await relayInfo(nodeEndpoint)
        let identity = try XCTUnwrap(nodeInfo.relayIdentity)
        let claim = RelayRequest.claimNoctwebNamespaceV1(
            NoctwebNamespaceClaimRequestV1(identity: identity)
        )
        let client = RelayClient(endpoint: coordinatorAEndpoint)
        let rejected = try await client.send(claim)
        XCTAssertEqual(rejected.error?.code, .authenticationRequired)
        let before = await coordinatorA.noctwebNamespaceRecords()
        XCTAssertFalse(before.contains { $0.suffix == suffix })

        try await register(
            nodeEndpoint,
            with: coordinatorBEndpoint,
            token: token
        )
        let accepted = try await client.send(claim)
        XCTAssertNotNil(accepted.successBody)
        let after = await coordinatorA.noctwebNamespaceRecords()
        XCTAssertTrue(after.contains {
            $0.suffix == suffix && $0.ownerRelayID == nodeKey.relayID
        })
    }

    func testNamespaceAndDeliveryRequireConfiguredCoordinatorQuorum()
        async throws
    {
        let federation = FederationDescriptor(
            mode: .curated,
            name: "curated-admission-quorum"
        )
        let token = "test-curated-registration-token"
        let coordinatorConfiguration = RelayConfiguration(
            kind: .coordinator,
            federation: federation,
            coordinatorRegistrationToken: token
        )
        let coordinatorA = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: coordinatorConfiguration
        )
        let coordinatorB = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: coordinatorConfiguration
        )
        let coordinatorAEndpoint = try await startOnLoopback(
            coordinatorA,
            description: "coordinator A started"
        )
        defer { coordinatorA.stop() }
        let coordinatorBEndpoint = try await startOnLoopback(
            coordinatorB,
            description: "coordinator B started"
        )
        defer { coordinatorB.stop() }
        let decoyCoordinator = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: coordinatorConfiguration
        )
        let decoyEndpoint = try await startOnLoopback(
            decoyCoordinator,
            description: "decoy coordinator started"
        )
        defer { decoyCoordinator.stop() }
        let coordinatorAPin = try await pinnedEndpoint(coordinatorAEndpoint)
        let coordinatorBPin = try await pinnedEndpoint(coordinatorBEndpoint)
        // An unusable mirror of A must not prevent trying A's live endpoint.
        let staleMirror = RelayEndpoint(
            host: decoyEndpoint.host,
            port: decoyEndpoint.port,
            useTLS: decoyEndpoint.useTLS,
            transport: decoyEndpoint.transport,
            directorySigningPublicKey:
                coordinatorAPin.directorySigningPublicKey
        )
        let pinnedCoordinators = [
            staleMirror, coordinatorAPin, coordinatorBPin
        ]

        let nodeKey = try RelayIdentityKeyMaterialV1.generate()
        let nodeSuffix = NoctwebRelaySuffixV1(rawValue: ".curatednode")!
        let node = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                noctwebRelaySuffix: nodeSuffix
            ),
            relayIdentity: nodeKey
        )
        let nodeEndpoint = try await startOnLoopback(
            node,
            description: "curated node started"
        )
        defer { node.stop() }
        try await register(
            nodeEndpoint,
            with: coordinatorAEndpoint,
            token: token
        )

        let destinationKey = try RelayIdentityKeyMaterialV1.generate()
        let destination = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                federationCoordinatorEndpoints: pinnedCoordinators,
                curatedCoordinatorQuorum: 2,
                noctwebRelaySuffix:
                    NoctwebRelaySuffixV1(rawValue: ".curateddestination"),
                allowPrivateFederationEndpoints: true
            ),
            relayIdentity: destinationKey
        )
        let destinationEndpoint = try await startOnLoopback(
            destination,
            description: "curated destination started"
        )
        defer { destination.stop() }
        try await register(
            destinationEndpoint,
            with: coordinatorAEndpoint,
            token: token
        )
        try await register(
            destinationEndpoint,
            with: coordinatorBEndpoint,
            token: token
        )
        node.updateFederationRuntimeSettings(from: RelayConfiguration(
            kind: .standard,
            federation: federation,
            federationCoordinatorEndpoints: pinnedCoordinators,
            curatedCoordinatorQuorum: 2,
            advertisedEndpoint: nodeEndpoint,
            allowPrivateFederationEndpoints: true
        ))

        let nodeInfo = try await relayInfo(nodeEndpoint)
        let nodeIdentity = try XCTUnwrap(nodeInfo.relayIdentity)
        let claim = RelayRequest.claimNoctwebNamespaceV1(
            NoctwebNamespaceClaimRequestV1(identity: nodeIdentity)
        )
        let destinationClient = RelayClient(endpoint: destinationEndpoint)
        let firstClaim = try await destinationClient.send(claim)
        XCTAssertEqual(firstClaim.error?.code, .authenticationRequired)
        let firstRecords = await destination.noctwebNamespaceRecords()
        XCTAssertFalse(firstRecords.contains { $0.suffix == nodeSuffix })

        let inboundAppend = try await makeAppend(on: destinationEndpoint)
        let delivery = try FederatedOpaqueRouteDeliveryV1.signed(
            sourceIdentity: nodeIdentity,
            sourceKey: nodeKey,
            destinationRelayID: destinationKey.relayID,
            append: inboundAppend
        )
        let firstDelivery = try await destinationClient.send(
            .deliverOpaqueRouteV1(delivery)
        )
        XCTAssertEqual(firstDelivery.error?.code, .authenticationRequired)

        let outboundAppend = try await makeAppend(on: nodeEndpoint)
        let forwarding = RelayRequest.forwardOpaqueRouteV1(
            FederatedOpaqueRouteForwardRequestV1(
                destinationRelayID: nodeKey.relayID,
                destination: nodeEndpoint,
                append: outboundAppend
            )
        )
        let firstForward = try await destinationClient.send(forwarding)
        XCTAssertEqual(firstForward.error?.code, .unavailable)

        try await register(
            nodeEndpoint,
            with: coordinatorBEndpoint,
            token: token
        )
        let admittedClaim = try await destinationClient.send(claim)
        XCTAssertNotNil(admittedClaim.successBody)
        let records = await destination.noctwebNamespaceRecords()
        XCTAssertTrue(records.contains {
            $0.suffix == nodeSuffix
                && $0.ownerRelayID == nodeKey.relayID
        })
        let admittedDelivery = try await destinationClient.send(
            .deliverOpaqueRouteV1(delivery)
        )
        XCTAssertNotNil(admittedDelivery.successBody)
        let admittedForward = try await destinationClient.send(forwarding)
        XCTAssertNotNil(admittedForward.successBody)
    }

    private func startOnLoopback(
        _ relay: RelayServer,
        description: String
    ) async throws -> RelayEndpoint {
        let started = expectation(description: description)
        var port: UInt16?
        relay.onEvent = { event in
            if case .started(let boundPort) = event {
                port = boundPort
                started.fulfill()
            }
        }
        try relay.start(host: "127.0.0.1", port: 0)
        await fulfillment(of: [started], timeout: 5)
        return RelayEndpoint(
            host: "127.0.0.1",
            port: try XCTUnwrap(port)
        )
    }

    private func relayInfo(_ endpoint: RelayEndpoint) async throws -> RelayInfo {
        let response = try await RelayClient(endpoint: endpoint).send(.info())
        guard case .relayInfo(let info)? = response.successBody else {
            throw RelayNetworkError.invalidResponse
        }
        return info
    }

    private func pinnedEndpoint(_ endpoint: RelayEndpoint) async throws
        -> RelayEndpoint
    {
        let info = try await relayInfo(endpoint)
        let key = try XCTUnwrap(info.federationDirectoryPublicKey)
        return RelayEndpoint(
            host: endpoint.host,
            port: endpoint.port,
            useTLS: endpoint.useTLS,
            transport: endpoint.transport,
            directorySigningPublicKey: key
        )
    }

    private func register(
        _ node: RelayEndpoint,
        with coordinator: RelayEndpoint,
        token: String
    ) async throws {
        let response = try await RelayClient(
            endpoint: coordinator,
            authToken: token
        ).send(
            .registerFederationNode(
                FederationNodeRegistrationRequest(
                    endpoint: node,
                    relayInfo: try await relayInfo(node),
                    ttlSeconds: 120
                )
            )
        )
        XCTAssertNotNil(response.successBody)
    }

    private func makeAppend(on endpoint: RelayEndpoint) async throws
        -> AppendOpaqueRouteRelayRequestV2
    {
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
        let response = try await RelayClient(endpoint: endpoint).send(
            .createOpaqueRouteV2(
                CreateOpaqueRouteRelayRequestV2(
                    request: create,
                    renewCapability: material.renewCapability
                )
            )
        )
        guard case .opaqueRoute(let created)? = response.successBody else {
            throw RelayNetworkError.invalidResponse
        }
        let route = try OpaqueSendRouteV2(
            routeID: material.routeID,
            relay: endpoint,
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
                Data("curated ciphertext".utf8),
                to: route
            ).packets.first
        )
        return AppendOpaqueRouteRelayRequestV2(
            packet: packet,
            sendCapability: material.sendCapability
        )
    }
}
