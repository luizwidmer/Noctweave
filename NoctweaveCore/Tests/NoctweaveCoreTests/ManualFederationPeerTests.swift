import XCTest
@testable import NoctweaveCore

final class ManualFederationPeerTests: XCTestCase {
    func testManualFederationTreatsAllowListedStandardRelayAsLivePeer() async throws {
        let federation = FederationDescriptor(mode: .manual, name: "manual-live-test")
        let relayA = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 0),
            configuration: RelayConfiguration(kind: .standard, federation: federation)
        )
        let relayB = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 0),
            configuration: RelayConfiguration(kind: .standard, federation: federation)
        )

        let startedA = expectation(description: "relay A started")
        let startedB = expectation(description: "relay B started")
        let portA = UInt16.random(in: 45_000...49_999)
        var portB = UInt16.random(in: 50_000...54_999)
        while portB == portA {
            portB = UInt16.random(in: 50_000...54_999)
        }
        relayA.onEvent = { (event: RelayServer.Event) in
            if case .started = event {
                startedA.fulfill()
            }
        }
        relayB.onEvent = { (event: RelayServer.Event) in
            if case .started = event {
                startedB.fulfill()
            }
        }

        try relayA.start(host: "127.0.0.1", port: portA)
        try relayB.start(host: "127.0.0.1", port: portB)
        defer {
            relayA.stop()
            relayB.stop()
        }
        await fulfillment(of: [startedA, startedB], timeout: 5)

        let endpointA = RelayEndpoint(
            host: "127.0.0.1",
            port: portA,
            transport: .tcp
        )
        let endpointB = RelayEndpoint(
            host: "127.0.0.1",
            port: portB,
            transport: .tcp
        )
        relayA.updateFederationRuntimeSettings(
            from: RelayConfiguration(
                kind: .standard,
                federation: federation,
                coordinatorHeartbeatSeconds: 15,
                coordinatorDirectoryMaxStalenessSeconds: 60,
                advertisedEndpoint: endpointA,
                federationAllowList: [endpointB]
            )
        )
        relayB.updateFederationRuntimeSettings(
            from: RelayConfiguration(
                kind: .standard,
                federation: federation,
                coordinatorHeartbeatSeconds: 15,
                coordinatorDirectoryMaxStalenessSeconds: 60,
                advertisedEndpoint: endpointB,
                federationAllowList: [endpointA]
            )
        )

        let request = RelayRequest.listFederationNodes(
            ListFederationNodesRequest(
                mode: .manual,
                federationName: federation.name,
                onlyHealthy: true,
                maxStalenessSeconds: 60,
                requireSignedSnapshot: false
            )
        )
        let directoryA = try await RelayClient(endpoint: endpointA).send(request)
        let directoryB = try await RelayClient(endpoint: endpointB).send(request)

        guard case .federationNodes(let nodesA)? = directoryA.successBody,
              case .federationNodes(let nodesB)? = directoryB.successBody else {
            return XCTFail("Manual relays must return a live peer directory.")
        }
        XCTAssertEqual(nodesA.nodes.map(\.endpoint), [endpointB])
        XCTAssertEqual(nodesB.nodes.map(\.endpoint), [endpointA])
        XCTAssertEqual(nodesA.nodes.first?.relayInfo.kind, .standard)
        XCTAssertEqual(nodesB.nodes.first?.relayInfo.kind, .standard)
        XCTAssertEqual(nodesA.nodes.first?.relayInfo.federation, federation)
        XCTAssertEqual(nodesB.nodes.first?.relayInfo.federation, federation)
        XCTAssertNil(nodesA.snapshot)
        XCTAssertNil(nodesB.snapshot)
    }

    func testManualFederationDoesNotDiscoverUnlistedRelay() async throws {
        let federation = FederationDescriptor(mode: .manual, name: "manual-closed-test")
        let relay = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 0),
            configuration: RelayConfiguration(kind: .standard, federation: federation)
        )
        let started = expectation(description: "relay started")
        let port = UInt16.random(in: 55_000...59_999)
        relay.onEvent = { (event: RelayServer.Event) in
            if case .started = event {
                started.fulfill()
            }
        }
        try relay.start(host: "127.0.0.1", port: port)
        defer { relay.stop() }
        await fulfillment(of: [started], timeout: 5)

        let endpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: port,
            transport: .tcp
        )
        let response = try await RelayClient(endpoint: endpoint).send(
            .listFederationNodes(
                ListFederationNodesRequest(
                    mode: .manual,
                    federationName: federation.name,
                    onlyHealthy: true,
                    requireSignedSnapshot: false
                )
            )
        )
        guard case .federationNodes(let directory)? = response.successBody else {
            return XCTFail("Expected a manual federation directory.")
        }
        XCTAssertTrue(directory.nodes.isEmpty)
    }

    func testManualFederationRejectsDynamicRegistration() async throws {
        let federation = FederationDescriptor(
            mode: .manual,
            name: "manual-operator-owned"
        )
        let relay = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 0),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation
            )
        )
        let started = expectation(description: "manual relay started")
        let port = UInt16.random(in: 40_000...44_999)
        relay.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try relay.start(host: "127.0.0.1", port: port)
        defer { relay.stop() }
        await fulfillment(of: [started], timeout: 5)

        let response = try await RelayClient(
            endpoint: RelayEndpoint(host: "127.0.0.1", port: port)
        ).send(
            .registerFederationNode(
                FederationNodeRegistrationRequest(
                    endpoint: RelayEndpoint(
                        host: "127.0.0.1",
                        port: port == UInt16.max ? port - 1 : port + 1
                    ),
                    relayInfo: RelayConfiguration(
                        kind: .standard,
                        federation: federation
                    ).makeInfo(),
                    ttlSeconds: 120
                )
            )
        )

        XCTAssertEqual(response.status, .error)
        XCTAssertEqual(
            response.error?.message,
            "Manual federation does not accept relay registration; configure peers explicitly."
        )
    }
}
