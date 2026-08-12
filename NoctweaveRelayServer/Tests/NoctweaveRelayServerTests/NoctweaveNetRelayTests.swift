import Crypto
import Foundation
import XCTest
@preconcurrency import NIOCore
@preconcurrency import NIOFoundationCompat
@preconcurrency import NIOPosix
@testable import NoctweaveRelayServer

final class NoctweaveNetRelayTests: XCTestCase {
    func testCurrentRelayTopologyContainsExactlyThreeRoles() {
        XCTAssertEqual(RelayKind.allCases, [.standard, .passthrough, .host])
        XCTAssertFalse(RelayKind.coordinator.isCurrentTopologyRole)
    }

    func testPrivateEndpointPolicyAcceptsLANAndInternalHostsOnly() {
        XCTAssertTrue(
            PublicRelayEndpointPolicy.permitsPrivate(
                RelayEndpoint(host: "192.168.1.20", port: 9339)
            )
        )
        XCTAssertTrue(
            PublicRelayEndpointPolicy.permitsPrivate(
                RelayEndpoint(
                    host: "host.docker.internal",
                    port: 9339
                )
            )
        )
        XCTAssertFalse(
            PublicRelayEndpointPolicy.permitsPrivate(
                RelayEndpoint(host: "8.8.8.8", port: 9339)
            )
        )
    }

    func testNativeOpenFederationOverlayRejectsPlaintextAndPrivateEndpoints() {
        XCTAssertTrue(OpenFederationDHTNativeOverlayTransport.isPermittedEndpoint(
            RelayEndpoint(host: "8.8.8.8", port: 443, useTLS: true, transport: .http)
        ))
        XCTAssertFalse(OpenFederationDHTNativeOverlayTransport.isPermittedEndpoint(
            RelayEndpoint(host: "127.0.0.1", port: 443, useTLS: true, transport: .http)
        ))
        XCTAssertFalse(OpenFederationDHTNativeOverlayTransport.isPermittedEndpoint(
            RelayEndpoint(host: "8.8.8.8", port: 80, useTLS: false, transport: .http)
        ))
        XCTAssertFalse(OpenFederationDHTNativeOverlayTransport.isPermittedEndpoint(
            RelayEndpoint(host: "8.8.8.8", port: 443, useTLS: true, transport: .websocket)
        ))
    }

    func testRoleCapabilitiesAdvertiseOnlyTheirSurface() {
        let standard = RelayCapabilityManifestV2.advertised(
            relayKind: .standard,
            attachmentsEnabled: false,
            hiddenRetrievalEnabled: false,
            onionEnabled: false,
            mixnetEnabled: false,
            opaqueRouteRuntimeEnabled: true,
            openDiscoveryEnabled: false,
            rendezvousTransportEnabled: false
        )
        XCTAssertFalse(standard.supports(module: "nw.net-passthrough", version: 1))
        XCTAssertFalse(standard.supports(module: "nw.net-host", version: 1))

        let standardHost = RelayCapabilityManifestV2.advertised(
            relayKind: .standard,
            netHostEnabled: true,
            attachmentsEnabled: false,
            hiddenRetrievalEnabled: false,
            onionEnabled: false,
            mixnetEnabled: false,
            opaqueRouteRuntimeEnabled: true,
            openDiscoveryEnabled: false,
            rendezvousTransportEnabled: false
        )
        XCTAssertTrue(standardHost.supports(module: "nw.opaque-route", version: 2))
        XCTAssertTrue(standardHost.supports(module: "nw.net-host", version: 1))
        XCTAssertFalse(standardHost.supports(module: "nw.net-passthrough", version: 1))

        let passthrough = RelayCapabilityManifestV2.advertised(
            relayKind: .passthrough,
            attachmentsEnabled: true,
            hiddenRetrievalEnabled: true,
            onionEnabled: true,
            mixnetEnabled: true,
            opaqueRouteRuntimeEnabled: true,
            openDiscoveryEnabled: true,
            rendezvousTransportEnabled: true
        )
        XCTAssertEqual(
            passthrough.modules.map(\.module),
            ["nw.core", "nw.net-passthrough"]
        )

        let host = RelayCapabilityManifestV2.advertised(
            relayKind: .host,
            attachmentsEnabled: true,
            hiddenRetrievalEnabled: true,
            onionEnabled: true,
            mixnetEnabled: true,
            opaqueRouteRuntimeEnabled: true,
            openDiscoveryEnabled: true,
            rendezvousTransportEnabled: true
        )
        XCTAssertEqual(host.modules.map(\.module), ["nw.core", "nw.net-host"])
    }

    func testRelayInfoAdvertisesCoLocatedAndDedicatedHostCapability() throws {
        let standard = RelayConfiguration(
            kind: .standard,
            netHostEnabled: true
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))
        XCTAssertTrue(
            try XCTUnwrap(standard.protocolCapabilities)
                .supports(module: "nw.net-host", version: 1)
        )

        let host = RelayConfiguration(kind: .host)
            .makeInfo(now: Date(timeIntervalSince1970: 1_000))
        XCTAssertTrue(
            try XCTUnwrap(host.protocolCapabilities)
                .supports(module: "nw.net-host", version: 1)
        )
    }

    func testServerConfigEnablesHostingForStandardAndDedicatedHostRelays() {
        let standard = ServerConfig.parse(
            arguments: [
                "--relay-kind", "standard",
                "--net-host-enabled", "true",
                "--noctweb-relay-suffix", ".atelier"
            ],
            environment: [:]
        )
        XCTAssertTrue(standard.netHostEnabled)
        XCTAssertEqual(standard.noctwebRelaySuffix, ".atelier")
        XCTAssertGreaterThanOrEqual(standard.maxMessageBytes ?? 0, 2 * 1_024 * 1_024)

        let host = ServerConfig.parse(
            arguments: ["--relay-kind", "host"],
            environment: [:]
        )
        XCTAssertTrue(host.netHostEnabled)
    }

    func testHostStorePersistsVerifiesAndCapabilityReleases() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            UUID().uuidString,
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let key = Curve25519.Signing.PrivateKey()
        let payload = Data("hosted capsule bytes".utf8)
        let releaseCapability = Data(repeating: 0x29, count: 32)
        let request = NoctweaveNetHostPutRequest(
            objectID: NoctweaveNetHostPutRequest.objectID(for: payload),
            payload: payload,
            ttlSeconds: 3_600,
            releaseCapabilityDigest: NoctweaveNetHostReleaseRequest.capabilityDigest(
                releaseCapability
            ),
            idempotencyKey: Data(repeating: 0x42, count: 32)
        )
        let now = Date(
            timeIntervalSince1970: floor(Date().timeIntervalSince1970)
        )
        let store = NoctweaveNetHostStore(
            directoryURL: root,
            signingPrivateKey: key,
            maximumObjects: 2,
            maximumTotalBytes: 4_096
        )
        try store.load()
        let receipt = try store.put(request, now: now)
        XCTAssertTrue(receipt.isSignatureValid)
        XCTAssertEqual(try store.fetch(.init(objectID: request.objectID), now: now)?.payload, payload)

        let restored = NoctweaveNetHostStore(
            directoryURL: root,
            signingPrivateKey: key,
            maximumObjects: 2,
            maximumTotalBytes: 4_096
        )
        try restored.load()
        XCTAssertTrue(
            try restored.presence(.init(objectID: request.objectID), now: now).present
        )
        XCTAssertThrowsError(
            try restored.release(
                .init(
                    objectID: request.objectID,
                    releaseCapability: Data(repeating: 0x30, count: 32)
                ),
                now: now
            )
        ) {
            XCTAssertEqual(
                $0 as? NoctweaveNetHostStoreError,
                .unauthorizedRelease
            )
        }
        XCTAssertTrue(
            try restored.release(
                .init(objectID: request.objectID, releaseCapability: releaseCapability),
                now: now
            ).released
        )
        XCTAssertFalse(
            try restored.presence(.init(objectID: request.objectID), now: now).present
        )
    }

    func testHostAndPassthroughWireBindingsRoundTripExactly() throws {
        let payload = Data("capsule".utf8)
        let host = RelayRequest.putNetHostObject(
            NoctweaveNetHostPutRequest(
                objectID: NoctweaveNetHostPutRequest.objectID(for: payload),
                payload: payload,
                ttlSeconds: nil,
                releaseCapabilityDigest: Data(repeating: 0x51, count: 32),
                idempotencyKey: Data(repeating: 0x52, count: 32)
            )
        )
        let encodedHost = try RelayCodec.encoder().encode(host)
        XCTAssertEqual(
            try RelayCodec.decodeWire(RelayRequest.self, from: encodedHost),
            host
        )
        XCTAssertTrue(requestRequiresConfidentialHTTPBridge(host))
        XCTAssertFalse(relayRequestIsPermittedOverBridge(
            host,
            directSource: "203.0.113.10",
            trustedReverseProxyTLS: false
        ))
        XCTAssertTrue(relayRequestIsPermittedOverBridge(
            host,
            directSource: "127.0.0.1",
            trustedReverseProxyTLS: false
        ))
        XCTAssertTrue(relayRequestIsPermittedOverBridge(
            host,
            directSource: "203.0.113.10",
            trustedReverseProxyTLS: true
        ))
        XCTAssertFalse(requestRequiresConfidentialHTTPBridge(
            .getNetHostObject(.init(objectID: NoctweaveNetHostPutRequest.objectID(for: payload)))
        ))

        let passthrough = RelayRequest.netPassthrough(
            NoctweaveNetPassthroughRequest(
                destination: RelayEndpoint(
                    host: "relay.example",
                    port: 443,
                    useTLS: true,
                    transport: .http
                ),
                payload: Data("{}".utf8)
            )
        )
        let encodedPassthrough = try RelayCodec.encoder().encode(passthrough)
        XCTAssertEqual(
            try RelayCodec.decodeWire(
                RelayRequest.self,
                from: encodedPassthrough
            ),
            passthrough
        )
        XCTAssertTrue(requestRequiresConfidentialHTTPBridge(passthrough))
    }

    func testHostNameBindingIsDurableAndCannotBeReassigned() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            UUID().uuidString,
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let receiptKey = Curve25519.Signing.PrivateKey()
        let relayKey = try RelayIdentityKeyMaterialV1.generate()
        let suffix = NoctwebRelaySuffixV1(rawValue: ".durable")!
        let now = Date(
            timeIntervalSince1970: floor(Date().timeIntervalSince1970)
        )
        let payload = Data("signed hosted publication".utf8)
        let put = NoctweaveNetHostPutRequest(
            objectID: NoctweaveNetHostPutRequest.objectID(for: payload),
            payload: payload,
            ttlSeconds: 3_600,
            releaseCapabilityDigest: Data(repeating: 0x11, count: 32),
            idempotencyKey: Data(repeating: 0x12, count: 32)
        )
        let binding = NoctweaveNetHostNameBindingRequestV1(
            relaySuffix: suffix,
            siteLabel: "journal",
            objectID: put.objectID,
            publisherID: "nwpub1_\(String(repeating: "a", count: 64))",
            headID: "sha256:\(String(repeating: "b", count: 64))",
            revision: 1,
            previousObjectID: nil,
            idempotencyKey: Data(repeating: 0x13, count: 32)
        )
        let store = NoctweaveNetHostStore(
            directoryURL: root,
            signingPrivateKey: receiptKey
        )
        try store.load()
        _ = try store.put(put, now: now)
        XCTAssertEqual(try store.bindName(binding, now: now), binding)

        let reopened = NoctweaveNetHostStore(
            directoryURL: root,
            signingPrivateKey: receiptKey
        )
        try reopened.load()
        let request = NoctweaveNetHostNameRequestV1(
            relaySuffix: suffix,
            siteLabel: "journal"
        )
        let restored = try XCTUnwrap(
            reopened.resolveName(request, now: now)
        )
        XCTAssertEqual(restored, binding)

        let identity = try relayKey.makeSignedClaim(
            sequence: 1,
            relayKind: .host,
            federation: FederationDescriptor(
                mode: .manual,
                name: "host-name-tests"
            ),
            advertisedEndpoints: [
                RelayEndpoint(
                    host: "relay.example",
                    port: 443,
                    useTLS: true,
                    transport: .http
                )
            ],
            noctwebSuffix: suffix,
            capabilities: RelayCapabilityManifestV2.advertised(
                relayKind: .host,
                netHostEnabled: true,
                attachmentsEnabled: false,
                hiddenRetrievalEnabled: false,
                onionEnabled: false,
                mixnetEnabled: false,
                opaqueRouteRuntimeEnabled: false,
                openDiscoveryEnabled: false,
                rendezvousTransportEnabled: false
            ),
            issuedAt: now
        )
        let resolution = try NoctweaveNetHostNameResolutionV1.signed(
            binding: restored,
            updatedAt: now,
            signer: relayKey,
            at: now
        )
        XCTAssertTrue(
            try resolution.verifyThrowing(
                expectedRelayIdentity: identity,
                at: now
            )
        )

        let reassignment = NoctweaveNetHostNameBindingRequestV1(
            relaySuffix: suffix,
            siteLabel: "journal",
            objectID: put.objectID,
            publisherID: "nwpub1_\(String(repeating: "c", count: 64))",
            headID: binding.headID,
            revision: 2,
            previousObjectID: binding.objectID,
            idempotencyKey: Data(repeating: 0x14, count: 32)
        )
        XCTAssertThrowsError(
            try reopened.bindName(reassignment, now: now)
        ) {
            XCTAssertEqual(
                $0 as? NoctweaveNetHostStoreError,
                .conflict
            )
        }
    }

    func testStandardRelayResolvesAndFetchesFromFederatedHostRelay()
        throws
    {
        let federation = FederationDescriptor(
            mode: .manual,
            name: "noctweb-forwarding"
        )
        let sourcePort = try reserveRelayTestPort()
        let destinationPort = try reserveRelayTestPort()
        let sourceEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: UInt16(sourcePort),
            transport: .tcp
        )
        let destinationEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: UInt16(destinationPort),
            transport: .tcp
        )
        let sourceIdentity = RelayIdentityRuntime(
            keyMaterial: try RelayIdentityKeyMaterialV1.generate()
        )
        let destinationIdentity = RelayIdentityRuntime(
            keyMaterial: try RelayIdentityKeyMaterialV1.generate()
        )
        let hostStore = NoctweaveNetHostStore(
            directoryURL: nil,
            signingPrivateKey: Curve25519.Signing.PrivateKey()
        )
        try hostStore.load()
        let payload = Data("federated noctweb object".utf8)
        let put = NoctweaveNetHostPutRequest(
            objectID: NoctweaveNetHostPutRequest.objectID(for: payload),
            payload: payload,
            ttlSeconds: 3_600,
            releaseCapabilityDigest: Data(repeating: 0x31, count: 32),
            idempotencyKey: Data(repeating: 0x32, count: 32)
        )
        _ = try hostStore.put(put)
        let suffix = NoctwebRelaySuffixV1(rawValue: ".mesh")!
        let binding = NoctweaveNetHostNameBindingRequestV1(
            relaySuffix: suffix,
            siteLabel: "notes",
            objectID: put.objectID,
            publisherID: "nwpub1_\(String(repeating: "d", count: 64))",
            headID: "sha256:\(String(repeating: "e", count: 64))",
            revision: 1,
            previousObjectID: nil,
            idempotencyKey: Data(repeating: 0x33, count: 32)
        )
        _ = try hostStore.bindName(binding)

        let destination = try NoctweaveNetRelayTCPHarness(
            port: destinationPort,
            configuration: RelayConfiguration(
                kind: .host,
                federation: federation,
                advertisedEndpoint: destinationEndpoint,
                noctwebRelaySuffix: suffix,
                federationAllowList: [sourceEndpoint],
                allowPrivateFederationEndpoints: true
            ),
            identity: destinationIdentity,
            hostStore: hostStore
        )
        let source = try NoctweaveNetRelayTCPHarness(
            port: sourcePort,
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                advertisedEndpoint: sourceEndpoint,
                federationAllowList: [destinationEndpoint],
                allowPrivateFederationEndpoints: true
            ),
            identity: sourceIdentity
        )
        defer {
            try? source.shutdown()
            try? destination.shutdown()
        }

        let nameResponse = try source.send(
            .resolveFederatedNetHostNameV1(
                FederatedNetHostNameReadRequestV1(
                    destinationRelayID: destinationIdentity.relayID,
                    destination: destinationEndpoint,
                    request: NoctweaveNetHostNameRequestV1(
                        relaySuffix: suffix,
                        siteLabel: "notes"
                    )
                )
            )
        )
        guard case .federatedNetHostNameResolution(let name)? =
            nameResponse.successBody else {
            return XCTFail("Expected a federated name resolution.")
        }
        XCTAssertTrue(
            try name.verifyThrowing(
                expectedRelayID: destinationIdentity.relayID
            )
        )
        XCTAssertEqual(name.resolution.objectID, put.objectID)

        let objectResponse = try source.send(
            .getFederatedNetHostObjectV1(
                FederatedNetHostReadRequestV1(
                    destinationRelayID: destinationIdentity.relayID,
                    destination: destinationEndpoint,
                    request: NoctweaveNetHostObjectRequest(
                        objectID: put.objectID
                    )
                )
            )
        )
        guard case .federatedNetHostObject(let object)? =
            objectResponse.successBody else {
            return XCTFail("Expected a federated hosted object.")
        }
        XCTAssertTrue(
            try object.verifyThrowing(
                expectedRelayID: destinationIdentity.relayID
            )
        )
        XCTAssertEqual(object.object.payload, payload)
    }

    func testNamespaceRotationAndReleaseConvergeAcrossLiveManualPeers()
        throws
    {
        let federation = FederationDescriptor(
            mode: .manual,
            name: "namespace-convergence"
        )
        let firstPort = try reserveRelayTestPort()
        let secondPort = try reserveRelayTestPort()
        let firstEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: UInt16(firstPort),
            transport: .tcp
        )
        let secondEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: UInt16(secondPort),
            transport: .tcp
        )
        let first = try NoctweaveNetRelayTCPHarness(
            port: firstPort,
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                advertisedEndpoint: firstEndpoint,
                federationAllowList: [secondEndpoint],
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            )
        )
        let second = try NoctweaveNetRelayTCPHarness(
            port: secondPort,
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                advertisedEndpoint: secondEndpoint,
                federationAllowList: [firstEndpoint],
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            )
        )
        defer {
            try? first.shutdown()
            try? second.shutdown()
        }

        let suffix = NoctwebRelaySuffixV1(rawValue: ".converge")!
        let oldIdentity = try RelayIdentityKeyMaterialV1.generate()
        let newIdentity = try RelayIdentityKeyMaterialV1.generate()
        let capabilities = RelayCapabilityManifestV2.advertised(
            relayKind: .host,
            netHostEnabled: true,
            attachmentsEnabled: false,
            hiddenRetrievalEnabled: false,
            onionEnabled: false,
            mixnetEnabled: false,
            opaqueRouteRuntimeEnabled: false,
            openDiscoveryEnabled: false,
            rendezvousTransportEnabled: false
        )
        let now = Date(
            timeIntervalSince1970: floor(Date().timeIntervalSince1970)
        )
        let oldClaim = try oldIdentity.makeSignedClaim(
            sequence: 1,
            relayKind: .host,
            federation: federation,
            advertisedEndpoints: [firstEndpoint],
            noctwebSuffix: suffix,
            capabilities: capabilities,
            issuedAt: now
        )
        XCTAssertEqual(
            try first.send(
                .claimNoctwebNamespaceV1(
                    NoctwebNamespaceClaimRequestV1(
                        identity: oldClaim
                    )
                )
            ).status,
            .success
        )
        XCTAssertTrue(waitForRelayCondition {
            second.namespaceRecord(for: suffix)?.ownerRelayID
                == oldIdentity.relayID
        })

        let rotation = try RelayIdentityRotationV1.signed(
            from: oldIdentity,
            to: newIdentity,
            sequence: 2,
            issuedAt: now.addingTimeInterval(1)
        )
        let newClaim = try newIdentity.makeSignedClaim(
            sequence: 2,
            relayKind: .host,
            federation: federation,
            advertisedEndpoints: [firstEndpoint],
            noctwebSuffix: suffix,
            capabilities: capabilities,
            issuedAt: rotation.issuedAt
        )
        XCTAssertEqual(
            try first.send(
                .rotateNoctwebNamespaceV1(
                    NoctwebNamespaceRotationRequestV1(
                        rotation: rotation,
                        newIdentity: newClaim
                    )
                )
            ).status,
            .success
        )
        XCTAssertTrue(waitForRelayCondition {
            second.namespaceRecord(for: suffix)?.ownerRelayID
                == newIdentity.relayID
        })

        let release = try NoctwebNamespaceReleaseV1.signed(
            suffix: suffix,
            owner: newIdentity,
            sequence: 3,
            issuedAt: now.addingTimeInterval(2)
        )
        XCTAssertEqual(
            try first.send(
                .releaseNoctwebNamespaceV1(release)
            ).status,
            .success
        )
        XCTAssertTrue(waitForRelayCondition {
            second.namespaceRecord(for: suffix)?.status
                == .tombstoned
        })
    }

    func testNamespaceAdvertiserReannouncesClaimToLateManualPeer()
        throws
    {
        let federation = FederationDescriptor(
            mode: .manual,
            name: "namespace-late-peer"
        )
        let sourcePort = try reserveRelayTestPort()
        let destinationPort = try reserveRelayTestPort()
        let sourceEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: UInt16(sourcePort),
            transport: .tcp
        )
        let destinationEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: UInt16(destinationPort),
            transport: .tcp
        )
        let suffix = NoctwebRelaySuffixV1(rawValue: ".latepeer")!
        let sourceConfiguration = RelayConfiguration(
            kind: .standard,
            netHostEnabled: true,
            federation: federation,
            advertisedEndpoint: sourceEndpoint,
            noctwebRelaySuffix: suffix,
            federationAllowList: [destinationEndpoint],
            allowPrivateFederationEndpoints: true
        )
        let sourceStore = RelayStore(
            fileURL: nil,
            temporalBucketSeconds: 0
        )
        let sourceIdentity = RelayIdentityRuntime(
            keyMaterial: try RelayIdentityKeyMaterialV1.generate()
        )
        let sourceHostStore = NoctweaveNetHostStore(
            directoryURL: nil,
            signingPrivateKey: Curve25519.Signing.PrivateKey()
        )
        try sourceHostStore.load()
        let advertiser = NoctwebNamespaceAdvertiser(
            store: sourceStore,
            configurationStore: RelayConfigurationStore(
                sourceConfiguration
            ),
            relayIdentityRuntime: sourceIdentity,
            fallbackEndpoint: sourceEndpoint,
            forwardingRequestTimeoutSeconds: 1,
            maxMessageBytes: 512 * 1_024,
            maxLineBytes: 640 * 1_024,
            netHostStore: sourceHostStore,
            passthroughAllowedEndpoints: []
        )
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }

        advertiser.announce(on: group.next())
        Thread.sleep(forTimeInterval: 1.1)

        let destination = try NoctweaveNetRelayTCPHarness(
            port: destinationPort,
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                advertisedEndpoint: destinationEndpoint,
                federationAllowList: [sourceEndpoint],
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            )
        )
        defer { try? destination.shutdown() }

        advertiser.announce(on: group.next())

        XCTAssertTrue(waitForRelayCondition {
            destination.namespaceRecord(for: suffix)?.ownerRelayID
                == sourceIdentity.relayID
        })
    }
}

private final class NoctweaveNetRelayTCPHarness {
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let port: Int
    private let store: RelayStore

    init(
        port: Int,
        configuration: RelayConfiguration,
        identity: RelayIdentityRuntime,
        hostStore: NoctweaveNetHostStore? = nil
    ) throws {
        self.port = port
        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let endpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: UInt16(port),
            transport: .tcp
        )
        let relayStore = RelayStore(
            fileURL: nil,
            temporalBucketSeconds: 0
        )
        store = relayStore
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 16)
            .serverChannelOption(
                ChannelOptions.socketOption(.so_reuseaddr),
                value: 1
            )
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(
                    LineFrameHandler(maxLength: 640 * 1_024)
                ).flatMap {
                    channel.pipeline.addHandler(
                        RelayHandler(
                            store: relayStore,
                            maxMessageBytes: 512 * 1_024,
                            maxLineBytes: 640 * 1_024,
                            localEndpoint: endpoint,
                            relayConfiguration: configuration,
                            relayIdentityRuntime: identity,
                            forwardingRequestTimeoutSeconds: 3,
                            netHostStore: hostStore
                        )
                    )
                }
            }
            .childChannelOption(
                ChannelOptions.socketOption(.so_reuseaddr),
                value: 1
            )
        do {
            channel = try bootstrap.bind(
                host: "127.0.0.1",
                port: port
            ).wait()
        } catch {
            try? group.syncShutdownGracefully()
            throw error
        }
    }

    func send(_ request: RelayRequest) throws -> RelayResponse {
        let promise = group.next().makePromise(of: RelayResponse.self)
        let data = try RelayCodec.encoder().encode(request)
        let bootstrap = ClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(
                    LineFrameHandler(maxLength: 640 * 1_024)
                ).flatMap {
                    channel.pipeline.addHandler(
                        NoctweaveNetRelayResponseHandler(
                            requestData: data,
                            promise: promise
                        )
                    )
                }
            }
        let client = try bootstrap.connect(
            host: "127.0.0.1",
            port: port
        ).wait()
        let response = try promise.futureResult.wait()
        try? client.close().wait()
        guard response.isResponse(to: request) else {
            throw NSError(
                domain: "NoctweaveNetRelayTCPHarness",
                code: 1
            )
        }
        return response
    }

    func shutdown() throws {
        try? channel.close().wait()
        try group.syncShutdownGracefully()
    }

    func namespaceRecord(
        for suffix: NoctwebRelaySuffixV1
    ) -> NoctwebNamespaceRecordV1? {
        store.noctwebNamespaceRecord(for: suffix)
    }
}

private final class NoctweaveNetRelayResponseHandler:
    ChannelInboundHandler
{
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let requestData: Data
    private let promise: EventLoopPromise<RelayResponse>
    private var resolved = false

    init(
        requestData: Data,
        promise: EventLoopPromise<RelayResponse>
    ) {
        self.requestData = requestData
        self.promise = promise
    }

    func channelActive(context: ChannelHandlerContext) {
        var buffer = context.channel.allocator.buffer(
            capacity: requestData.count + 1
        )
        LineEncoder.wrap(requestData, into: &buffer)
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }

    func channelRead(
        context: ChannelHandlerContext,
        data: NIOAny
    ) {
        var buffer = unwrapInboundIn(data)
        guard let responseData = buffer.readData(
            length: buffer.readableBytes
        ) else {
            fail(ChannelError.inputClosed)
            return
        }
        do {
            succeed(
                try RelayCodec.decodeWire(
                    RelayResponse.self,
                    from: responseData
                )
            )
        } catch {
            fail(error)
        }
        context.close(promise: nil)
    }

    func errorCaught(
        context: ChannelHandlerContext,
        error: Error
    ) {
        fail(error)
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        fail(ChannelError.inputClosed)
    }

    private func succeed(_ response: RelayResponse) {
        guard !resolved else { return }
        resolved = true
        promise.succeed(response)
    }

    private func fail(_ error: Error) {
        guard !resolved else { return }
        resolved = true
        promise.fail(error)
    }
}

private func reserveRelayTestPort() throws -> Int {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    defer { try? group.syncShutdownGracefully() }
    let channel = try ServerBootstrap(group: group)
        .serverChannelOption(
            ChannelOptions.socketOption(.so_reuseaddr),
            value: 1
        )
        .childChannelInitializer { channel in
            channel.eventLoop.makeSucceededVoidFuture()
        }
        .bind(host: "127.0.0.1", port: 0)
        .wait()
    defer { try? channel.close().wait() }
    guard let port = channel.localAddress?.port else {
        throw NSError(
            domain: "NoctweaveNetRelayTCPHarness",
            code: 2
        )
    }
    return port
}

private func waitForRelayCondition(
    timeout: TimeInterval = 3,
    condition: () -> Bool
) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() {
            return true
        }
        Thread.sleep(forTimeInterval: 0.02)
    }
    return condition()
}
