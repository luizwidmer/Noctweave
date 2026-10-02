import Crypto
import Foundation
import XCTest
@preconcurrency import NIOCore
@preconcurrency import NIOFoundationCompat
@preconcurrency import NIOPosix
@testable import NoctweaveRelayServer

final class NoctweaveNetRelayTests: XCTestCase {
    func testMalformedHostingReceiptTranscriptFailsClosedWithoutTrapping() {
        let payload = Data("invalid receipt".utf8)
        let receipt = NoctweaveNetHostingReceipt(
            objectID: NoctweaveNetHostPutRequest.objectID(for: payload),
            byteCount: UInt64(payload.count),
            storedAt: Date(timeIntervalSince1970: .nan),
            expiresAt: Date(timeIntervalSince1970: .infinity),
            signingPublicKey: Data(repeating: 1, count: 32),
            signature: Data(repeating: 2, count: 64)
        )

        XCTAssertFalse(receipt.isStructurallyValid)
        XCTAssertFalse(receipt.signingPayload.isEmpty)
    }

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

    func testHostStoreRejectsSymlinkedCapsulePayload() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            UUID().uuidString,
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let payload = Data("expected relay capsule".utf8)
        let request = NoctweaveNetHostPutRequest(
            objectID: NoctweaveNetHostPutRequest.objectID(for: payload),
            payload: payload,
            ttlSeconds: 3_600,
            releaseCapabilityDigest: Data(repeating: 0x61, count: 32),
            idempotencyKey: Data(repeating: 0x62, count: 32)
        )
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let store = NoctweaveNetHostStore(
            directoryURL: root,
            signingPrivateKey: Curve25519.Signing.PrivateKey()
        )
        try store.load()
        _ = try store.put(request, now: now)

        let capsuleURL = root.appendingPathComponent("\(request.objectID).capsule")
        try FileManager.default.removeItem(at: capsuleURL)
        let victimURL = root.appendingPathComponent("victim.txt")
        try Data("unrelated readable file".utf8).write(to: victimURL)
        try FileManager.default.createSymbolicLink(
            at: capsuleURL,
            withDestinationURL: victimURL
        )

        XCTAssertThrowsError(
            try store.fetch(.init(objectID: request.objectID), now: now)
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
                federation: FederationDescriptor(
                    mode: .manual,
                    name: federation.name,
                    description: "Remote display text"
                ),
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

    func testManualNamespaceClaimRejectsUnlistedRelayBeforeAssigningSuffix()
        throws
    {
        let federation = FederationDescriptor(
            mode: .manual,
            name: "namespace-admission"
        )
        let relayPort = try reserveRelayTestPort()
        let allowedPort = try reserveRelayTestPort()
        let unlistedPort = try reserveRelayTestPort()
        let relayEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(relayPort), transport: .tcp
        )
        let allowedEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(allowedPort), transport: .tcp
        )
        let unlistedEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(unlistedPort), transport: .tcp
        )
        let relay = try NoctweaveNetRelayTCPHarness(
            port: relayPort,
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                advertisedEndpoint: relayEndpoint,
                federationAllowList: [allowedEndpoint],
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            )
        )
        defer { try? relay.shutdown() }

        let attacker = try RelayIdentityKeyMaterialV1.generate()
        let suffix = NoctwebRelaySuffixV1(rawValue: ".unlisted")!
        let claim = try attacker.makeSignedClaim(
            sequence: 1,
            relayKind: .host,
            federation: federation,
            advertisedEndpoints: [unlistedEndpoint],
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
            )
        )
        let response = try relay.send(
            .claimNoctwebNamespaceV1(
                NoctwebNamespaceClaimRequestV1(identity: claim)
            )
        )
        XCTAssertEqual(response.status, .error)
        XCTAssertEqual(response.error?.code, .authenticationRequired)
        XCTAssertNil(relay.namespaceRecord(for: suffix))
    }

    func testManualNamespaceClaimFallsBackToLiveAllowedEndpoint()
        throws
    {
        let federation = FederationDescriptor(
            mode: .manual,
            name: "namespace-live-member"
        )
        let receiverPort = try reserveRelayTestPort()
        let peerPort = try reserveRelayTestPort()
        let offlinePort = try reserveRelayTestPort()
        let receiverEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(receiverPort), transport: .tcp
        )
        let peerEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(peerPort), transport: .tcp
        )
        let offlineEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(offlinePort), transport: .tcp
        )
        let peerSuffix = NoctwebRelaySuffixV1(rawValue: ".allowedpeer")!
        let peerConfiguration = RelayConfiguration(
            kind: .standard,
            netHostEnabled: true,
            federation: FederationDescriptor(
                mode: .manual,
                name: federation.name,
                description: "Peer-side display text"
            ),
            advertisedEndpoint: peerEndpoint,
            noctwebRelaySuffix: peerSuffix,
            federationAllowList: [receiverEndpoint],
            allowPrivateFederationEndpoints: true
        )
        let peerKey = try RelayIdentityKeyMaterialV1.generate()
        let peerIdentity = RelayIdentityRuntime(keyMaterial: peerKey)
        let peer = try NoctweaveNetRelayTCPHarness(
            port: peerPort,
            configuration: peerConfiguration,
            identity: peerIdentity
        )
        let receiver = try NoctweaveNetRelayTCPHarness(
            port: receiverPort,
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                advertisedEndpoint: receiverEndpoint,
                federationAllowList: [offlineEndpoint, peerEndpoint],
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            )
        )
        defer {
            try? receiver.shutdown()
            try? peer.shutdown()
        }

        let forgedSuffix = NoctwebRelaySuffixV1(rawValue: ".forgedpeer")!
        let forgedKey = try RelayIdentityKeyMaterialV1.generate()
        let capabilities = RelayCapabilityManifestV2.advertised(
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
        let forgedClaim = try forgedKey.makeSignedClaim(
            sequence: 1,
            relayKind: .standard,
            federation: federation,
            advertisedEndpoints: [peerEndpoint],
            noctwebSuffix: forgedSuffix,
            capabilities: capabilities
        )
        let forgedResponse = try receiver.send(
            .claimNoctwebNamespaceV1(
                NoctwebNamespaceClaimRequestV1(identity: forgedClaim)
            )
        )
        XCTAssertEqual(forgedResponse.error?.code, .authenticationRequired)
        XCTAssertNil(receiver.namespaceRecord(for: forgedSuffix))

        let admittedClaim = try peerIdentity.signedIdentity(
            configuration: peerConfiguration,
            advertisedEndpoints: [offlineEndpoint, peerEndpoint],
            hostSigningPublicKey: nil
        )
        let admittedResponse = try receiver.send(
            .claimNoctwebNamespaceV1(
                NoctwebNamespaceClaimRequestV1(identity: admittedClaim)
            )
        )
        XCTAssertEqual(admittedResponse.status, .success)
        XCTAssertEqual(
            receiver.namespaceRecord(for: peerSuffix)?.ownerRelayID,
            peerKey.relayID
        )

        try peer.stopListening()
        let offlineSnapshot = try receiver.send(
            .getNoctwebNamespaceSnapshotV1(
                NoctwebNamespaceSnapshotRequestV1(
                    federationMode: .manual,
                    federationName: federation.name
                )
            )
        )
        XCTAssertEqual(offlineSnapshot.status, .success)
        XCTAssertEqual(
            receiver.namespaceRecord(for: peerSuffix)?.ownerRelayID,
            peerKey.relayID
        )
    }

    func testSoloNamespaceClaimRequiresLocalRelayIdentity() throws {
        let port = try reserveRelayTestPort()
        let endpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(port), transport: .tcp
        )
        let suffix = NoctwebRelaySuffixV1(rawValue: ".soloowner")!
        let configuration = RelayConfiguration(
            kind: .standard,
            netHostEnabled: true,
            federation: FederationDescriptor(mode: .solo),
            advertisedEndpoint: endpoint,
            noctwebRelaySuffix: suffix,
            allowPrivateFederationEndpoints: true
        )
        let localKey = try RelayIdentityKeyMaterialV1.generate()
        let localIdentity = RelayIdentityRuntime(keyMaterial: localKey)
        let relay = try NoctweaveNetRelayTCPHarness(
            port: port,
            configuration: configuration,
            identity: localIdentity
        )
        defer { try? relay.shutdown() }

        let attacker = try RelayIdentityKeyMaterialV1.generate()
        let capabilities = try XCTUnwrap(
            configuration.makeInfo(now: Date()).protocolCapabilities
        )
        let forgedClaim = try attacker.makeSignedClaim(
            sequence: 1,
            relayKind: .standard,
            federation: configuration.federation,
            advertisedEndpoints: [endpoint],
            noctwebSuffix: suffix,
            capabilities: capabilities
        )
        let forgedResponse = try relay.send(
            .claimNoctwebNamespaceV1(
                NoctwebNamespaceClaimRequestV1(identity: forgedClaim)
            )
        )
        XCTAssertEqual(forgedResponse.error?.code, .authenticationRequired)
        XCTAssertNil(relay.namespaceRecord(for: suffix))

        let localClaim = try localIdentity.signedIdentity(
            configuration: configuration,
            advertisedEndpoints: [endpoint],
            hostSigningPublicKey: nil
        )
        let localResponse = try relay.send(
            .claimNoctwebNamespaceV1(
                NoctwebNamespaceClaimRequestV1(identity: localClaim)
            )
        )
        XCTAssertEqual(localResponse.status, .success)
        XCTAssertEqual(
            relay.namespaceRecord(for: suffix)?.ownerRelayID,
            localKey.relayID
        )
    }

    func testConfiguredManualTransportPinFailsBeforePeerDispatch() throws {
        let federation = FederationDescriptor(
            mode: .manual, name: "pinned-manual-endpoint"
        )
        let receiverPort = try reserveRelayTestPort()
        let peerPort = try reserveRelayTestPort()
        let receiverEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(receiverPort), transport: .tcp
        )
        let peerEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(peerPort), transport: .tcp
        )
        let pinnedPeerEndpoint = RelayEndpoint(
            host: peerEndpoint.host,
            port: peerEndpoint.port,
            transport: .tcp,
            tlsCertificateFingerprintSHA256: Data(repeating: 0x5A, count: 32)
        )
        let suffix = NoctwebRelaySuffixV1(rawValue: ".pinnedpeer")!
        let peerConfiguration = RelayConfiguration(
            kind: .standard,
            federation: federation,
            advertisedEndpoint: peerEndpoint,
            noctwebRelaySuffix: suffix,
            allowPrivateFederationEndpoints: true
        )
        let peerIdentity = RelayIdentityRuntime(
            keyMaterial: try RelayIdentityKeyMaterialV1.generate()
        )
        let acceptedConnections = NoctweaveNetRelayConnectionCounter()
        let peer = try NoctweaveNetRelayTCPHarness(
            port: peerPort,
            configuration: peerConfiguration,
            identity: peerIdentity,
            onAcceptedConnection: { acceptedConnections.record() }
        )
        let receiver = try NoctweaveNetRelayTCPHarness(
            port: receiverPort,
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                advertisedEndpoint: receiverEndpoint,
                federationAllowList: [pinnedPeerEndpoint],
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            )
        )
        defer {
            try? receiver.shutdown()
            try? peer.shutdown()
        }
        let claim = try peerIdentity.signedIdentity(
            configuration: peerConfiguration,
            advertisedEndpoints: [peerEndpoint],
            hostSigningPublicKey: nil
        )
        let response = try receiver.send(
            .claimNoctwebNamespaceV1(
                NoctwebNamespaceClaimRequestV1(identity: claim)
            )
        )
        XCTAssertEqual(response.error?.code, .authenticationRequired)
        XCTAssertEqual(acceptedConnections.count, 0)
        XCTAssertNil(receiver.namespaceRecord(for: suffix))
    }

    func testNamespaceSnapshotDoesNotAssignPeerFromDirectoryInfo() throws {
        let federation = FederationDescriptor(
            mode: .manual,
            name: "namespace-snapshot-admission"
        )
        let receiverPort = try reserveRelayTestPort()
        let listedPort = try reserveRelayTestPort()
        let unboundPort = try reserveRelayTestPort()
        let receiverEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(receiverPort), transport: .tcp
        )
        let listedEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(listedPort), transport: .tcp
        )
        let unboundEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(unboundPort), transport: .tcp
        )
        let suffix = NoctwebRelaySuffixV1(rawValue: ".unbound")!
        let peer = try NoctweaveNetRelayTCPHarness(
            port: listedPort,
            configuration: RelayConfiguration(
                kind: .standard,
                netHostEnabled: true,
                federation: federation,
                advertisedEndpoint: unboundEndpoint,
                noctwebRelaySuffix: suffix,
                federationAllowList: [receiverEndpoint],
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            )
        )
        let receiver = try NoctweaveNetRelayTCPHarness(
            port: receiverPort,
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                advertisedEndpoint: receiverEndpoint,
                federationAllowList: [listedEndpoint],
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            )
        )
        defer {
            try? receiver.shutdown()
            try? peer.shutdown()
        }

        let response = try receiver.send(
            .getNoctwebNamespaceSnapshotV1(
                NoctwebNamespaceSnapshotRequestV1(
                    federationMode: .manual,
                    federationName: federation.name
                )
            )
        )
        XCTAssertEqual(response.status, .success)
        XCTAssertNil(receiver.namespaceRecord(for: suffix))
    }

    func testManualDeliveryRequiresLivePeerAndHonorsRevocationOnExistingConnection()
        throws
    {
        let federation = FederationDescriptor(
            mode: .manual,
            name: "manual-live-revocation"
        )
        let receiverPort = try reserveRelayTestPort()
        let sourcePort = try reserveRelayTestPort()
        let receiverEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(receiverPort), transport: .tcp
        )
        let sourceEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(sourcePort), transport: .tcp
        )
        let initialConfiguration = RelayConfiguration(
            kind: .standard,
            federation: federation,
            advertisedEndpoint: receiverEndpoint,
            federationAllowList: [sourceEndpoint],
            allowPrivateFederationEndpoints: true
        )
        let configurationStore = RelayConfigurationStore(initialConfiguration)
        let receiverKey = try RelayIdentityKeyMaterialV1.generate()
        let receiverConnections = NoctweaveNetRelayConnectionCounter()
        let receiver = try NoctweaveNetRelayTCPHarness(
            port: receiverPort,
            configuration: initialConfiguration,
            identity: RelayIdentityRuntime(keyMaterial: receiverKey),
            configurationStore: configurationStore,
            onAcceptedConnection: { receiverConnections.record() }
        )
        defer { try? receiver.shutdown() }

        let suffix = NoctwebRelaySuffixV1(rawValue: ".revoked")!
        let liveSourceConfiguration = RelayConfiguration(
            kind: .standard,
            federation: federation,
            advertisedEndpoint: sourceEndpoint,
            noctwebRelaySuffix: suffix,
            federationAllowList: [],
            allowPrivateFederationEndpoints: true
        )
        let liveSourceKey = try RelayIdentityKeyMaterialV1.generate()
        let liveSourceIdentity = RelayIdentityRuntime(keyMaterial: liveSourceKey)
        let liveSourceConfigurationStore = RelayConfigurationStore(
            liveSourceConfiguration
        )
        let liveSource = try NoctweaveNetRelayTCPHarness(
            port: sourcePort,
            configuration: liveSourceConfiguration,
            identity: liveSourceIdentity,
            configurationStore: liveSourceConfigurationStore
        )
        defer { try? liveSource.shutdown() }

        let sourceKey = try RelayIdentityKeyMaterialV1.generate()
        let sourceClaim = try sourceKey.makeSignedClaim(
            sequence: 1,
            relayKind: .standard,
            federation: federation,
            advertisedEndpoints: [sourceEndpoint],
            noctwebSuffix: suffix,
            capabilities: RelayCapabilityManifestV2.advertised(
                attachmentsEnabled: false,
                hiddenRetrievalEnabled: false,
                onionEnabled: false,
                mixnetEnabled: false,
                federationForwardingEnabled: true
            )
        )
        let routeID = OpaqueReceiveRouteIDV2(
            rawValue: Data(repeating: 0x61, count: 32)
        )
        let packetID = OpaqueRoutePacketIDV2(
            rawValue: Data(repeating: 0x62, count: 32)
        )
        let sendCapability = RouteSendCapabilityV2(
            rawValue: Data(repeating: 0x63, count: 32)
        )
        let now = Date()
        let provisional = OpaqueRoutePacketV2(
            routeID: routeID,
            packetID: packetID,
            sealedFrame: Data(repeating: 0x64, count: 4_096),
            authorization: OpaqueRouteAuthorizationProofV2(
                authority: .send,
                nonce: OpaqueRouteProofNonceV2(
                    rawValue: Data(repeating: 0x65, count: 32)
                ),
                operationDigest: Data(repeating: 0, count: 32),
                authorizedAt: now,
                mac: Data(repeating: 0, count: 32)
            )
        )
        let packet = OpaqueRoutePacketV2(
            routeID: routeID,
            packetID: packetID,
            sealedFrame: provisional.sealedFrame,
            authorization: try OpaqueRouteAuthorizationProofV2.make(
                authority: .send,
                routeID: routeID,
                operationDigest: provisional.operationDigest,
                authorizedAt: now,
                nonce: OpaqueRouteProofNonceV2(
                    rawValue: Data(repeating: 0x65, count: 32)
                ),
                secret: sendCapability.rawValue
            )
        )
        let renewCapability = RouteRenewCapabilityV2(
            rawValue: Data(repeating: 0x66, count: 32)
        )
        let lease = OpaqueRouteLeaseV2(
            issuedAt: now,
            expiresAt: now.addingTimeInterval(3_600),
            policy: OpaqueRoutePolicyV2(
                paddingBucket: .bytes4096,
                retentionBucket: .oneHour,
                quotaBucket: .packets64
            )
        )
        let provisionalCreate = OpaqueRouteCreateRequestV2(
            version: 2,
            routeID: routeID,
            sendCapabilityDigest: opaqueRouteCredentialDigest(
                .send, sendCapability.rawValue
            ),
            readCredentialDigest: opaqueRouteCredentialDigest(
                .read, Data(repeating: 0x67, count: 32)
            ),
            renewCapabilityDigest: opaqueRouteCredentialDigest(
                .renew, renewCapability.rawValue
            ),
            teardownCapabilityDigest: opaqueRouteCredentialDigest(
                .teardown, Data(repeating: 0x68, count: 32)
            ),
            lease: lease,
            idempotencyKey: OpaqueRouteIdempotencyKeyV2(
                rawValue: Data(repeating: 0x69, count: 32)
            ),
            authorization: OpaqueRouteAuthorizationProofV2(
                authority: .renew,
                nonce: OpaqueRouteProofNonceV2(
                    rawValue: Data(repeating: 0x6a, count: 32)
                ),
                operationDigest: Data(repeating: 0, count: 32),
                authorizedAt: now,
                mac: Data(repeating: 0, count: 32)
            )
        )
        let create = OpaqueRouteCreateRequestV2(
            version: provisionalCreate.version,
            routeID: provisionalCreate.routeID,
            sendCapabilityDigest: provisionalCreate.sendCapabilityDigest,
            readCredentialDigest: provisionalCreate.readCredentialDigest,
            renewCapabilityDigest: provisionalCreate.renewCapabilityDigest,
            teardownCapabilityDigest:
                provisionalCreate.teardownCapabilityDigest,
            lease: provisionalCreate.lease,
            idempotencyKey: provisionalCreate.idempotencyKey,
            authorization: try OpaqueRouteAuthorizationProofV2.make(
                authority: .renew,
                routeID: routeID,
                operationDigest: try XCTUnwrap(
                    provisionalCreate.transitionDigest
                ),
                authorizedAt: now,
                nonce: provisionalCreate.authorization.nonce,
                secret: renewCapability.rawValue
            )
        )
        XCTAssertEqual(
            try receiver.send(
                .createOpaqueRouteV2(
                    OpaqueRouteCreateSubmissionV2(
                        request: create,
                        renewCapability: renewCapability
                    )
                )
            ).status,
            .success
        )
        let delivery = try FederatedOpaqueRouteDeliveryV1.signed(
            sourceIdentity: sourceClaim,
            sourceKey: sourceKey,
            destinationRelayID: receiverKey.relayID,
            append: OpaqueRouteAppendSubmissionV2(
                packet: packet,
                sendCapability: sendCapability
            )
        )
        let revokedConfiguration = RelayConfiguration(
            kind: .standard,
            federation: federation,
            advertisedEndpoint: receiverEndpoint,
            federationAllowList: [],
            allowPrivateFederationEndpoints: true
        )
        let unboundResponse = try receiver.send(
            .deliverOpaqueRouteV1(delivery)
        )
        XCTAssertEqual(
            unboundResponse.error?.code,
            .authenticationRequired
        )
        let liveClaim = try liveSourceIdentity.signedIdentity(
            configuration: liveSourceConfiguration,
            advertisedEndpoints: [sourceEndpoint],
            hostSigningPublicKey: nil
        )
        let liveDelivery = try FederatedOpaqueRouteDeliveryV1.signed(
            sourceIdentity: liveClaim,
            sourceKey: liveSourceKey,
            destinationRelayID: receiverKey.relayID,
            append: OpaqueRouteAppendSubmissionV2(
                packet: packet,
                sendCapability: sendCapability
            )
        )
        XCTAssertEqual(
            try receiver.send(.deliverOpaqueRouteV1(liveDelivery)).status,
            .success
        )
        let response = try receiver.send(
            .deliverOpaqueRouteV1(liveDelivery),
            afterConnect: {
                configurationStore.replace(with: revokedConfiguration)
            }
        )
        XCTAssertEqual(response.error?.code, .authenticationRequired)

        let pinnedReceiverEndpoint = RelayEndpoint(
            host: receiverEndpoint.host,
            port: receiverEndpoint.port,
            transport: .tcp,
            tlsCertificateFingerprintSHA256: Data(repeating: 0x6B, count: 32)
        )
        liveSourceConfigurationStore.replace(with: RelayConfiguration(
            kind: .standard,
            federation: federation,
            advertisedEndpoint: sourceEndpoint,
            noctwebRelaySuffix: suffix,
            federationAllowList: [pinnedReceiverEndpoint],
            allowPrivateFederationEndpoints: true
        ))
        let beforeForward = receiverConnections.count
        let forwarding = FederatedOpaqueRouteForwardRequestV1(
            destinationRelayID: receiverKey.relayID,
            destination: receiverEndpoint,
            append: OpaqueRouteAppendSubmissionV2(
                packet: packet,
                sendCapability: sendCapability
            )
        )
        XCTAssertEqual(
            try liveSource.send(.forwardOpaqueRouteV1(forwarding)).error?.code,
            .unavailable
        )
        XCTAssertEqual(receiverConnections.count, beforeForward)
    }

    func testCuratedOutboundUsesQuorumEndorsedPinnedEndpointBeforeDispatch()
        throws
    {
        let federation = FederationDescriptor(
            mode: .curated, name: "curated-pinned-outbound"
        )
        let sourcePort = try reserveRelayTestPort()
        let destinationPort = try reserveRelayTestPort()
        let firstPort = try reserveRelayTestPort()
        let secondPort = try reserveRelayTestPort()
        let sourceEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(sourcePort), transport: .tcp
        )
        let destinationEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(destinationPort),
            transport: .tcp
        )
        let pinnedDestination = RelayEndpoint(
            host: destinationEndpoint.host,
            port: destinationEndpoint.port,
            transport: .tcp,
            tlsCertificateFingerprintSHA256: Data(repeating: 0xA4, count: 32)
        )
        let firstEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(firstPort), transport: .tcp
        )
        let secondEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(secondPort), transport: .tcp
        )
        let suffix = NoctwebRelaySuffixV1(rawValue: ".pinnedhost")!
        let destinationConfiguration = RelayConfiguration(
            kind: .host,
            federation: federation,
            advertisedEndpoint: destinationEndpoint,
            noctwebRelaySuffix: suffix,
            allowPrivateFederationEndpoints: true
        )
        let destinationIdentity = RelayIdentityRuntime(
            keyMaterial: try RelayIdentityKeyMaterialV1.generate()
        )
        let destinationInfo = try destinationIdentity.authenticatedInfo(
            destinationConfiguration.makeInfo(now: Date()),
            configuration: destinationConfiguration,
            advertisedEndpoints: [destinationEndpoint],
            hostSigningPublicKey: nil
        )
        let unpinnedRegistration = FederationNodeRegistrationRequest(
            endpoint: destinationEndpoint,
            relayInfo: destinationInfo,
            ttlSeconds: 300
        )
        let firstStore = RelayStore(fileURL: nil, temporalBucketSeconds: 0)
        let secondStore = RelayStore(fileURL: nil, temporalBucketSeconds: 0)
        _ = try firstStore.registerFederationNode(unpinnedRegistration)
        _ = try secondStore.registerFederationNode(unpinnedRegistration)
        let firstCoordinator = try NoctweaveNetRelayTCPHarness(
            port: firstPort,
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorDirectorySigningPrivateKey: try FederationDirectorySignature
                    .privateKeyDataThrowing(from: nil),
                advertisedEndpoint: firstEndpoint,
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            ),
            relayStore: firstStore
        )
        let secondCoordinator = try NoctweaveNetRelayTCPHarness(
            port: secondPort,
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorDirectorySigningPrivateKey: try FederationDirectorySignature
                    .privateKeyDataThrowing(from: nil),
                advertisedEndpoint: secondEndpoint,
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            ),
            relayStore: secondStore
        )
        let destinationConnections = NoctweaveNetRelayConnectionCounter()
        let destination = try NoctweaveNetRelayTCPHarness(
            port: destinationPort,
            configuration: destinationConfiguration,
            identity: destinationIdentity,
            onAcceptedConnection: { destinationConnections.record() }
        )
        let source = try NoctweaveNetRelayTCPHarness(
            port: sourcePort,
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                federationCoordinatorEndpoints: [firstEndpoint, secondEndpoint],
                curatedCoordinatorQuorum: 2,
                advertisedEndpoint: sourceEndpoint,
                noctwebRelaySuffix: NoctwebRelaySuffixV1(rawValue: ".pinnedsource"),
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            )
        )
        defer {
            try? source.shutdown()
            try? destination.shutdown()
            try? secondCoordinator.shutdown()
            try? firstCoordinator.shutdown()
        }

        let request = RelayRequest.resolveFederatedNetHostNameV1(
            FederatedNetHostNameReadRequestV1(
                destinationRelayID: destinationIdentity.relayID,
                destination: destinationEndpoint,
                request: NoctweaveNetHostNameRequestV1(
                    relaySuffix: suffix, siteLabel: "notes"
                )
            )
        )
        _ = try source.send(request)
        XCTAssertGreaterThan(destinationConnections.count, 0)
        let pinnedRegistration = FederationNodeRegistrationRequest(
            endpoint: pinnedDestination,
            relayInfo: destinationInfo,
            ttlSeconds: 300
        )
        _ = try firstStore.registerFederationNode(pinnedRegistration)
        _ = try secondStore.registerFederationNode(pinnedRegistration)
        let beforePinnedRequest = destinationConnections.count
        let response = try source.send(request)
        XCTAssertEqual(response.error?.code, .unavailable)
        XCTAssertEqual(destinationConnections.count, beforePinnedRequest)
    }

    func testCuratedDeliveryRequiresDistinctSignedCoordinatorQuorum()
        throws
    {
        let federation = FederationDescriptor(
            mode: .curated,
            name: "curated-delivery-quorum"
        )
        let receiverPort = try reserveRelayTestPort()
        let sourcePort = try reserveRelayTestPort()
        let offlinePort = try reserveRelayTestPort()
        let firstPort = try reserveRelayTestPort()
        let secondPort = try reserveRelayTestPort()
        let thirdPort = try reserveRelayTestPort()
        let receiverEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(receiverPort), transport: .tcp
        )
        let sourceEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(sourcePort), transport: .tcp
        )
        let offlineEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(offlinePort), transport: .tcp
        )
        let firstEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(firstPort), transport: .tcp
        )
        let secondEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(secondPort), transport: .tcp
        )
        let thirdEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(thirdPort), transport: .tcp
        )
        let suffix = NoctwebRelaySuffixV1(rawValue: ".quorumsrc")!
        let sourceConfiguration = RelayConfiguration(
            kind: .standard,
            federation: federation,
            advertisedEndpoint: sourceEndpoint,
            noctwebRelaySuffix: suffix,
            allowPrivateFederationEndpoints: true
        )
        let sourceKey = try RelayIdentityKeyMaterialV1.generate()
        let sourceIdentity = RelayIdentityRuntime(keyMaterial: sourceKey)
        let sourceInfo = try sourceIdentity.authenticatedInfo(
            sourceConfiguration.makeInfo(now: Date()),
            configuration: sourceConfiguration,
            advertisedEndpoints: [offlineEndpoint, sourceEndpoint],
            hostSigningPublicKey: nil
        )
        let offlineRegistration = FederationNodeRegistrationRequest(
            endpoint: offlineEndpoint,
            relayInfo: sourceInfo,
            ttlSeconds: 300
        )
        let registration = FederationNodeRegistrationRequest(
            endpoint: sourceEndpoint,
            relayInfo: sourceInfo,
            ttlSeconds: 300
        )
        let firstStore = RelayStore(fileURL: nil, temporalBucketSeconds: 0)
        let secondStore = RelayStore(fileURL: nil, temporalBucketSeconds: 0)
        let thirdStore = RelayStore(fileURL: nil, temporalBucketSeconds: 0)
        _ = try firstStore.registerFederationNode(offlineRegistration)
        _ = try firstStore.registerFederationNode(registration)
        _ = try secondStore.registerFederationNode(offlineRegistration)
        _ = try secondStore.registerFederationNode(registration)
        let firstDirectoryKey = try FederationDirectorySignature
            .privateKeyDataThrowing(from: nil)
        let secondDirectoryKey = firstDirectoryKey
        let thirdDirectoryKey = try FederationDirectorySignature
            .privateKeyDataThrowing(from: nil)
        let firstCoordinator = try NoctweaveNetRelayTCPHarness(
            port: firstPort,
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorDirectorySigningPrivateKey: firstDirectoryKey,
                advertisedEndpoint: firstEndpoint,
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            ),
            relayStore: firstStore
        )
        let secondCoordinator = try NoctweaveNetRelayTCPHarness(
            port: secondPort,
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorDirectorySigningPrivateKey: secondDirectoryKey,
                advertisedEndpoint: secondEndpoint,
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            ),
            relayStore: secondStore
        )
        let thirdCoordinator = try NoctweaveNetRelayTCPHarness(
            port: thirdPort,
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorDirectorySigningPrivateKey: thirdDirectoryKey,
                advertisedEndpoint: thirdEndpoint,
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            ),
            relayStore: thirdStore
        )
        let source = try NoctweaveNetRelayTCPHarness(
            port: sourcePort,
            configuration: sourceConfiguration,
            identity: sourceIdentity
        )
        let receiverKey = try RelayIdentityKeyMaterialV1.generate()
        let receiver = try NoctweaveNetRelayTCPHarness(
            port: receiverPort,
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                federationCoordinatorEndpoints: [
                    firstEndpoint, secondEndpoint, thirdEndpoint
                ],
                curatedCoordinatorQuorum: 2,
                advertisedEndpoint: receiverEndpoint,
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(keyMaterial: receiverKey)
        )
        defer {
            try? receiver.shutdown()
            try? source.shutdown()
            try? thirdCoordinator.shutdown()
            try? secondCoordinator.shutdown()
            try? firstCoordinator.shutdown()
        }

        let routeID = OpaqueReceiveRouteIDV2(
            rawValue: Data(repeating: 0x71, count: 32)
        )
        let now = Date()
        let sendCapability = RouteSendCapabilityV2(
            rawValue: Data(repeating: 0x72, count: 32)
        )
        let provisional = OpaqueRoutePacketV2(
            routeID: routeID,
            packetID: OpaqueRoutePacketIDV2(
                rawValue: Data(repeating: 0x73, count: 32)
            ),
            sealedFrame: Data(repeating: 0x74, count: 4_096),
            authorization: OpaqueRouteAuthorizationProofV2(
                authority: .send,
                nonce: OpaqueRouteProofNonceV2(
                    rawValue: Data(repeating: 0x75, count: 32)
                ),
                operationDigest: Data(repeating: 0, count: 32),
                authorizedAt: now,
                mac: Data(repeating: 0, count: 32)
            )
        )
        let packet = OpaqueRoutePacketV2(
            routeID: routeID,
            packetID: provisional.packetID,
            sealedFrame: provisional.sealedFrame,
            authorization: try OpaqueRouteAuthorizationProofV2.make(
                authority: .send,
                routeID: routeID,
                operationDigest: provisional.operationDigest,
                authorizedAt: now,
                nonce: provisional.authorization.nonce,
                secret: sendCapability.rawValue
            )
        )
        let sourceClaim = try sourceIdentity.signedIdentity(
            configuration: sourceConfiguration,
            advertisedEndpoints: [offlineEndpoint, sourceEndpoint],
            hostSigningPublicKey: nil
        )
        let delivery = try FederatedOpaqueRouteDeliveryV1.signed(
            sourceIdentity: sourceClaim,
            sourceKey: sourceKey,
            destinationRelayID: receiverKey.relayID,
            append: OpaqueRouteAppendSubmissionV2(
                packet: packet,
                sendCapability: sendCapability
            )
        )
        XCTAssertEqual(
            try receiver.send(.deliverOpaqueRouteV1(delivery)).error?.code,
            RelayErrorCode.authenticationRequired
        )
        let namespaceClaim = RelayRequest.claimNoctwebNamespaceV1(
            NoctwebNamespaceClaimRequestV1(identity: sourceClaim)
        )
        XCTAssertEqual(
            try receiver.send(namespaceClaim).error?.code,
            RelayErrorCode.authenticationRequired
        )
        XCTAssertNil(receiver.namespaceRecord(for: suffix))

        _ = try thirdStore.registerFederationNode(offlineRegistration)
        _ = try thirdStore.registerFederationNode(registration)
        XCTAssertEqual(try receiver.send(namespaceClaim).status, .success)
        XCTAssertEqual(
            try receiver.send(.deliverOpaqueRouteV1(delivery)).error?.code,
            RelayErrorCode.notFound
        )
    }

    func testInvalidFirstCoordinatorDirectoryDoesNotPinItsKey() throws {
        let federation = FederationDescriptor(
            mode: .curated,
            name: "coordinator-key-pinning"
        )
        let wrongFederation = FederationDescriptor(
            mode: .curated,
            name: "unrelated-directory"
        )
        let receiverPort = try reserveRelayTestPort()
        let coordinatorPort = try reserveRelayTestPort()
        let mismatchedPort = try reserveRelayTestPort()
        let badSignaturePort = try reserveRelayTestPort()
        let receiverEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(receiverPort), transport: .tcp
        )
        let coordinatorEndpoint = RelayEndpoint(
            host: "127.0.0.1", port: UInt16(coordinatorPort), transport: .tcp
        )
        let advertisedKey = try FederationDirectorySignature
            .privateKeyDataThrowing(from: nil)
        let expectedKey = try FederationDirectorySignature
            .publicKeyDataThrowing(
                from: FederationDirectorySignature.privateKeyDataThrowing(
                    from: nil
                )
            )
        let mismatchedEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: UInt16(mismatchedPort),
            transport: .tcp,
            directorySigningPublicKey: expectedKey
        )
        let badSignatureEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: UInt16(badSignaturePort),
            transport: .tcp
        )
        let badSignatureCoordinator = try NoctweaveNetRelayTCPHarness(
            port: badSignaturePort,
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorDirectorySigningPrivateKey:
                    try FederationDirectorySignature.privateKeyDataThrowing(
                        from: nil
                    ),
                advertisedEndpoint: badSignatureEndpoint,
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            ),
            corruptDirectorySignature: true
        )
        let mismatchedDirectoryRequests = NoctweaveNetRelayConnectionCounter()
        let mismatchedCoordinator = try NoctweaveNetRelayTCPHarness(
            port: mismatchedPort,
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorDirectorySigningPrivateKey: advertisedKey,
                advertisedEndpoint: mismatchedEndpoint,
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            ),
            onInboundRequest: { request in
                if case .listFederationNodes = request.body {
                    mismatchedDirectoryRequests.record()
                }
            }
        )
        let invalidCoordinator = try NoctweaveNetRelayTCPHarness(
            port: coordinatorPort,
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: wrongFederation,
                coordinatorDirectorySigningPrivateKey:
                    try FederationDirectorySignature.privateKeyDataThrowing(
                        from: nil
                    ),
                advertisedEndpoint: coordinatorEndpoint,
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            )
        )
        let receiverStore = RelayStore(fileURL: nil, temporalBucketSeconds: 0)
        let receiver = try NoctweaveNetRelayTCPHarness(
            port: receiverPort,
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                federationCoordinatorEndpoints: [
                    coordinatorEndpoint,
                    mismatchedEndpoint,
                    badSignatureEndpoint
                ],
                curatedCoordinatorQuorum: 1,
                advertisedEndpoint: receiverEndpoint,
                allowPrivateFederationEndpoints: true
            ),
            identity: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            ),
            relayStore: receiverStore
        )
        defer {
            try? receiver.shutdown()
            try? badSignatureCoordinator.shutdown()
            try? mismatchedCoordinator.shutdown()
            try? invalidCoordinator.shutdown()
        }

        let claimantKey = try RelayIdentityKeyMaterialV1.generate()
        let claimantEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: UInt16(try reserveRelayTestPort()),
            transport: .tcp
        )
        let claimantSuffix = NoctwebRelaySuffixV1(rawValue: ".unlisted")!
        let claimantClaim = try claimantKey.makeSignedClaim(
            sequence: 1,
            relayKind: .standard,
            federation: federation,
            advertisedEndpoints: [claimantEndpoint],
            noctwebSuffix: claimantSuffix,
            capabilities: try XCTUnwrap(
                RelayConfiguration(kind: .standard, federation: federation)
                    .makeInfo(now: Date()).protocolCapabilities
            )
        )
        let response = try receiver.send(
            .claimNoctwebNamespaceV1(
                NoctwebNamespaceClaimRequestV1(identity: claimantClaim)
            )
        )
        XCTAssertEqual(response.error?.code, .authenticationRequired)
        XCTAssertNil(receiverStore.pinnedCoordinatorPublicKey(
            for: coordinatorEndpoint
        ))
        XCTAssertNil(receiverStore.pinnedCoordinatorPublicKey(
            for: mismatchedEndpoint
        ))
        XCTAssertNil(receiverStore.pinnedCoordinatorPublicKey(
            for: badSignatureEndpoint
        ))
        XCTAssertEqual(mismatchedDirectoryRequests.count, 0)
        XCTAssertNil(receiver.namespaceRecord(for: claimantSuffix))
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
        let suffix = NoctwebRelaySuffixV1(rawValue: ".converge")!
        let oldIdentity = try RelayIdentityKeyMaterialV1.generate()
        let firstIdentity = RelayIdentityRuntime(keyMaterial: oldIdentity)
        let firstConfiguration = RelayConfiguration(
            kind: .standard,
            netHostEnabled: true,
            federation: federation,
            advertisedEndpoint: firstEndpoint,
            noctwebRelaySuffix: suffix,
            federationAllowList: [secondEndpoint],
            allowPrivateFederationEndpoints: true
        )
        let first = try NoctweaveNetRelayTCPHarness(
            port: firstPort,
            configuration: firstConfiguration,
            identity: firstIdentity
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

        let newIdentity = try RelayIdentityKeyMaterialV1.generate()
        let now = Date(
            timeIntervalSince1970: floor(Date().timeIntervalSince1970)
        )
        let oldClaim = try firstIdentity.signedIdentity(
            configuration: firstConfiguration,
            advertisedEndpoints: [firstEndpoint],
            hostSigningPublicKey: nil,
            at: now
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
            sequence: oldClaim.claim.sequence + 1,
            issuedAt: now.addingTimeInterval(1)
        )
        let newClaim = try newIdentity.makeSignedClaim(
            sequence: rotation.sequence,
            relayKind: .standard,
            federation: federation,
            advertisedEndpoints: [firstEndpoint],
            noctwebSuffix: suffix,
            capabilities: try XCTUnwrap(
                firstConfiguration.makeInfo(now: now).protocolCapabilities
            ),
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
            sequence: rotation.sequence + 1,
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
        let source = try NoctweaveNetRelayTCPHarness(
            port: sourcePort,
            configuration: sourceConfiguration,
            identity: sourceIdentity
        )
        defer { try? source.shutdown() }
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

private final class NoctweaveNetRelayRequestObserver: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    private let observe: (RelayRequest) -> Void

    init(_ observe: @escaping (RelayRequest) -> Void) {
        self.observe = observe
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buffer = unwrapInboundIn(data)
        if let payload = buffer.getData(
            at: buffer.readerIndex,
            length: buffer.readableBytes
        ), let request = try? RelayCodec.decodeWire(
            RelayRequest.self,
            from: payload
        ) {
            observe(request)
        }
        context.fireChannelRead(data)
    }
}

private final class NoctweaveNetRelayCorruptDirectorySignature:
    ChannelOutboundHandler
{
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        let buffer = unwrapOutboundIn(data)
        guard let payload = buffer.getData(
            at: buffer.readerIndex,
            length: buffer.readableBytes
        ),
        let response = try? RelayCodec.decodeWire(
            RelayResponse.self, from: payload
        ),
        case .federationNodes = response.successBody,
        var object = try? JSONSerialization.jsonObject(with: payload)
            as? [String: Any],
        var body = object["body"] as? [String: Any],
        var snapshot = body["snapshot"] as? [String: Any],
        var signature = snapshot["signature"] as? String,
        !signature.isEmpty else {
            context.write(data, promise: promise)
            return
        }
        let first = signature.removeFirst()
        signature.insert(first == "A" ? "B" : "A", at: signature.startIndex)
        snapshot["signature"] = signature
        body["snapshot"] = snapshot
        object["body"] = body
        guard let altered = try? JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys]
        ) else {
            context.write(data, promise: promise)
            return
        }
        var output = context.channel.allocator.buffer(capacity: altered.count + 1)
        LineEncoder.wrap(altered, into: &output)
        context.write(wrapOutboundOut(output), promise: promise)
    }
}

private final class NoctweaveNetRelayConnectionCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func record() {
        lock.lock()
        value += 1
        lock.unlock()
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return value
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
        configurationStore: RelayConfigurationStore? = nil,
        relayStore: RelayStore? = nil,
        hostStore: NoctweaveNetHostStore? = nil,
        onAcceptedConnection: (() -> Void)? = nil,
        onInboundRequest: ((RelayRequest) -> Void)? = nil,
        corruptDirectorySignature: Bool = false
    ) throws {
        self.port = port
        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let endpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: UInt16(port),
            transport: .tcp
        )
        let activeStore = relayStore ?? RelayStore(
            fileURL: nil,
            temporalBucketSeconds: 0
        )
        store = activeStore
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 16)
            .serverChannelOption(
                ChannelOptions.socketOption(.so_reuseaddr),
                value: 1
            )
            .childChannelInitializer { channel in
                onAcceptedConnection?()
                return channel.pipeline.addHandler(
                    LineFrameHandler(maxLength: 640 * 1_024)
                ).flatMap {
                    guard let onInboundRequest else {
                        return channel.eventLoop.makeSucceededFuture(())
                    }
                    return channel.pipeline.addHandler(
                        NoctweaveNetRelayRequestObserver(onInboundRequest)
                    )
                }.flatMap {
                    guard corruptDirectorySignature else {
                        return channel.eventLoop.makeSucceededFuture(())
                    }
                    return channel.pipeline.addHandler(
                        NoctweaveNetRelayCorruptDirectorySignature()
                    )
                }.flatMap {
                    channel.pipeline.addHandler(
                        RelayHandler(
                            store: activeStore,
                            maxMessageBytes: 512 * 1_024,
                            maxLineBytes: 640 * 1_024,
                            localEndpoint: endpoint,
                            relayConfiguration: configuration,
                            relayConfigurationStore: configurationStore,
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

    func send(
        _ request: RelayRequest,
        afterConnect: (() -> Void)? = nil
    ) throws -> RelayResponse {
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
                            promise: promise,
                            sendOnActive: afterConnect == nil
                        )
                    )
                }
            }
        let client = try bootstrap.connect(
            host: "127.0.0.1",
            port: port
        ).wait()
        if let afterConnect {
            afterConnect()
            var buffer = client.allocator.buffer(capacity: data.count + 1)
            LineEncoder.wrap(data, into: &buffer)
            try client.writeAndFlush(buffer).wait()
        }
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

    func stopListening() throws {
        try channel.close().wait()
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
    private let sendOnActive: Bool
    private var resolved = false

    init(
        requestData: Data,
        promise: EventLoopPromise<RelayResponse>,
        sendOnActive: Bool = true
    ) {
        self.requestData = requestData
        self.promise = promise
        self.sendOnActive = sendOnActive
    }

    func channelActive(context: ChannelHandlerContext) {
        guard sendOnActive else { return }
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
