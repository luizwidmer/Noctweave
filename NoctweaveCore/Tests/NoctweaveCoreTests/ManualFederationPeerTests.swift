import XCTest
@testable import NoctweaveCore

final class ManualFederationPeerTests: XCTestCase {
    func testFederationOutboundEndpointRetainsOperatorTLSPin() {
        let pin = Data(repeating: 0x42, count: 32)
        let requested = RelayEndpoint(
            host: "relay.example",
            port: 443,
            useTLS: true
        )
        let configured = RelayEndpoint(
            host: "relay.example",
            port: 443,
            useTLS: true,
            tlsCertificateFingerprintSHA256: pin
        )
        let selected = RelayServer.endpointConstrainedByTrustedPin(
            requested: requested,
            trusted: configured
        )
        XCTAssertEqual(selected?.tlsCertificateFingerprintSHA256, pin)

        var conflicting = requested
        conflicting.tlsCertificateFingerprintSHA256 = Data(
            repeating: 0x43,
            count: 32
        )
        XCTAssertNil(RelayServer.endpointConstrainedByTrustedPin(
            requested: conflicting,
            trusted: configured
        ))
    }

    func testSoloNamespaceRejectsRemoteClaim() async throws {
        let relay = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: RelayConfiguration(kind: .standard)
        )
        let endpoint = try await startOnLoopback(
            relay,
            description: "solo relay started"
        )
        defer { relay.stop() }
        let suffix = NoctwebRelaySuffixV1(rawValue: ".outsider")!
        let attacker = try namespaceClaim(
            key: RelayIdentityKeyMaterialV1.generate(),
            federation: FederationDescriptor(mode: .solo),
            suffix: suffix,
            endpoint: endpoint
        )

        let response = try await RelayClient(endpoint: endpoint).send(
            .claimNoctwebNamespaceV1(
                NoctwebNamespaceClaimRequestV1(identity: attacker)
            )
        )
        XCTAssertEqual(response.error?.code, .authenticationRequired)
        let records = await relay.noctwebNamespaceRecords()
        XCTAssertTrue(records.isEmpty)
    }

    func testManualNamespaceRejectsUnlistedAndForgedClaimsWithoutReadSideImport()
        async throws
    {
        let federation = FederationDescriptor(
            mode: .manual,
            name: "manual-namespace-admission",
            description: "source operator note"
        )
        let receiverFederation = FederationDescriptor(
            mode: .manual,
            name: federation.name,
            description: "receiver operator note"
        )
        let peerSuffix = NoctwebRelaySuffixV1(rawValue: ".allowedpeer")!
        let peerKey = try RelayIdentityKeyMaterialV1.generate()
        let peer = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                noctwebRelaySuffix: peerSuffix
            ),
            relayIdentity: peerKey
        )
        let peerEndpoint = try await startOnLoopback(
            peer,
            description: "allowed peer started"
        )
        defer { peer.stop() }
        let decoy = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation
            )
        )
        let decoyEndpoint = try await startOnLoopback(
            decoy,
            description: "decoy relay started"
        )
        defer { decoy.stop() }
        let receiver = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: receiverFederation,
                federationAllowList: [decoyEndpoint, peerEndpoint],
                allowPrivateFederationEndpoints: true
            )
        )
        let receiverEndpoint = try await startOnLoopback(
            receiver,
            description: "receiver started"
        )
        defer { receiver.stop() }

        let snapshotResponse = try await RelayClient(
            endpoint: receiverEndpoint
        ).send(
            .getNoctwebNamespaceSnapshotV1(
                NoctwebNamespaceSnapshotRequestV1(
                    federationMode: .manual,
                    federationName: federation.name
                )
            )
        )
        XCTAssertNotNil(snapshotResponse.successBody)
        let afterSnapshot = await receiver.noctwebNamespaceRecords()
        XCTAssertTrue(afterSnapshot.isEmpty)

        let unlistedSuffix = NoctwebRelaySuffixV1(rawValue: ".unlisted")!
        let unlisted = try namespaceClaim(
            key: RelayIdentityKeyMaterialV1.generate(),
            federation: federation,
            suffix: unlistedSuffix,
            endpoint: receiverEndpoint
        )
        let unlistedResponse = try await RelayClient(
            endpoint: receiverEndpoint
        ).send(
            .claimNoctwebNamespaceV1(
                NoctwebNamespaceClaimRequestV1(identity: unlisted)
            )
        )
        XCTAssertEqual(unlistedResponse.error?.code, .authenticationRequired)
        let afterUnlisted = await receiver.noctwebNamespaceRecords()
        XCTAssertTrue(afterUnlisted.isEmpty)

        let forgedSuffix = NoctwebRelaySuffixV1(rawValue: ".forgedpeer")!
        let forged = try namespaceClaim(
            key: RelayIdentityKeyMaterialV1.generate(),
            federation: federation,
            suffix: forgedSuffix,
            endpoint: peerEndpoint
        )
        let forgedResponse = try await RelayClient(
            endpoint: receiverEndpoint
        ).send(
            .claimNoctwebNamespaceV1(
                NoctwebNamespaceClaimRequestV1(identity: forged)
            )
        )
        XCTAssertEqual(forgedResponse.error?.code, .authenticationRequired)
        let afterForged = await receiver.noctwebNamespaceRecords()
        XCTAssertTrue(afterForged.isEmpty)

        let infoResponse = try await RelayClient(endpoint: peerEndpoint).send(
            .info()
        )
        guard case .relayInfo(let info)? = infoResponse.successBody,
              let peerIdentity = info.relayIdentity else {
            return XCTFail("Expected the allowed peer's signed identity.")
        }
        let fallbackIdentity = try peerKey.makeSignedClaim(
            sequence: peerIdentity.claim.sequence + 1,
            relayKind: .standard,
            federation: federation,
            advertisedEndpoints: [decoyEndpoint, peerEndpoint],
            noctwebSuffix: peerSuffix,
            capabilities: try XCTUnwrap(info.protocolCapabilities)
        )
        let admittedResponse = try await RelayClient(
            endpoint: receiverEndpoint
        ).send(
            .claimNoctwebNamespaceV1(
                NoctwebNamespaceClaimRequestV1(identity: fallbackIdentity)
            )
        )
        XCTAssertNotNil(admittedResponse.successBody)
        let records = await receiver.noctwebNamespaceRecords()
        XCTAssertEqual(records.first?.suffix, peerSuffix)
        XCTAssertEqual(records.first?.ownerRelayID, peerIdentity.claim.relayID)
    }

    func testManualNamespaceAcceptsAllowlistedLiveHostRelay() async throws {
        let federation = FederationDescriptor(
            mode: .manual,
            name: "manual-host-namespace"
        )
        let suffix = NoctwebRelaySuffixV1(rawValue: ".hosted")!
        let hostStore = try RelayNoctwebHostStore(
            directoryURL: nil,
            signingPrivateKeyData:
                RelayNoctwebHostStore.generateSigningPrivateKey()
        )
        try hostStore.load()
        let host = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: RelayConfiguration(
                kind: .host,
                federation: federation,
                noctwebRelaySuffix: suffix
            ),
            relayIdentity: try RelayIdentityKeyMaterialV1.generate(),
            noctwebHostStore: hostStore
        )
        let hostEndpoint = try await startOnLoopback(
            host,
            description: "host relay started"
        )
        defer { host.stop() }
        let receiver = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                federationAllowList: [hostEndpoint]
            )
        )
        let receiverEndpoint = try await startOnLoopback(
            receiver,
            description: "receiver started"
        )
        defer { receiver.stop() }

        let infoResponse = try await RelayClient(endpoint: hostEndpoint).send(
            .info()
        )
        guard case .relayInfo(let info)? = infoResponse.successBody,
              let identity = info.relayIdentity else {
            return XCTFail("Expected the host relay's signed identity.")
        }
        let response = try await RelayClient(endpoint: receiverEndpoint).send(
            .claimNoctwebNamespaceV1(
                NoctwebNamespaceClaimRequestV1(identity: identity)
            )
        )
        XCTAssertNotNil(response.successBody)
        let records = await receiver.noctwebNamespaceRecords()
        XCTAssertEqual(records.first?.suffix, suffix)
        XCTAssertEqual(records.first?.ownerRelayID, identity.claim.relayID)
    }

    func testRuntimeRefreshReannouncesNamespaceToLateManualPeer()
        async throws
    {
        let federation = FederationDescriptor(
            mode: .manual,
            name: "manual-namespace-healing"
        )
        let suffix = NoctwebRelaySuffixV1(rawValue: ".latepeer")!
        let sourcePort = UInt16.random(in: 35_000...39_999)
        var destinationPort = UInt16.random(in: 40_000...44_999)
        while destinationPort == sourcePort {
            destinationPort = UInt16.random(in: 40_000...44_999)
        }
        let sourceEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: sourcePort
        )
        let destinationEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: destinationPort
        )
        let sourceConfiguration = RelayConfiguration(
            kind: .standard,
            federation: federation,
            advertisedEndpoint: sourceEndpoint,
            noctwebRelaySuffix: suffix,
            netHostEnabled: true,
            federationAllowList: [destinationEndpoint],
            allowPrivateFederationEndpoints: true
        )
        let hostStore = try RelayNoctwebHostStore(
            directoryURL: nil,
            signingPrivateKeyData:
                RelayNoctwebHostStore.generateSigningPrivateKey()
        )
        try hostStore.load()
        let source = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 0),
            configuration: sourceConfiguration,
            relayIdentity: try RelayIdentityKeyMaterialV1.generate(),
            noctwebHostStore: hostStore
        )
        let destination = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 0),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                advertisedEndpoint: destinationEndpoint,
                federationAllowList: [sourceEndpoint],
                allowPrivateFederationEndpoints: true
            )
        )
        let sourceStarted = expectation(description: "source started")
        let destinationStarted = expectation(
            description: "late destination started"
        )
        source.onEvent = { (event: RelayServer.Event) in
            if case .started = event {
                sourceStarted.fulfill()
            }
        }
        destination.onEvent = { (event: RelayServer.Event) in
            if case .started = event {
                destinationStarted.fulfill()
            }
        }

        try source.start(host: "127.0.0.1", port: sourcePort)
        await fulfillment(of: [sourceStarted], timeout: 5)
        try destination.start(
            host: "127.0.0.1",
            port: destinationPort
        )
        defer {
            source.stop()
            destination.stop()
        }
        await fulfillment(of: [destinationStarted], timeout: 5)

        source.updateFederationRuntimeSettings(
            from: sourceConfiguration
        )

        let deadline = Date().addingTimeInterval(5)
        var records = await destination.noctwebNamespaceRecords()
        while !records.contains(where: { $0.suffix == suffix }),
              Date() < deadline {
            try await Task.sleep(nanoseconds: 20_000_000)
            records = await destination.noctwebNamespaceRecords()
        }
        XCTAssertEqual(
            records.first(where: { $0.suffix == suffix })?
                .activeIdentityClaim?.claim.advertisedEndpoints,
            [sourceEndpoint]
        )
    }

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

    private func namespaceClaim(
        key: RelayIdentityKeyMaterialV1,
        federation: FederationDescriptor,
        suffix: NoctwebRelaySuffixV1,
        endpoint: RelayEndpoint
    ) throws -> SignedRelayIdentityClaimV1 {
        let configuration = RelayConfiguration(
            kind: .standard,
            federation: federation
        )
        let capabilities = try XCTUnwrap(
            configuration.makeInfo().protocolCapabilities
        )
        return try key.makeSignedClaim(
            sequence: Int(Date().timeIntervalSince1970),
            relayKind: .standard,
            federation: federation,
            advertisedEndpoints: [endpoint],
            noctwebSuffix: suffix,
            capabilities: capabilities
        )
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
}
