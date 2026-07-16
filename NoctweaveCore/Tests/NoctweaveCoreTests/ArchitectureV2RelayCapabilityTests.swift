import XCTest
@testable import NoctweaveCore

final class ArchitectureV2RelayCapabilityTests: XCTestCase {
    func testRelayInfoAdvertisesOnlyEnabledProtocolModules() throws {
        let configuration = RelayConfiguration(
            federation: FederationDescriptor(mode: .solo),
            attachmentsEnabled: false,
            groupCreationMode: .disabled
        )
        let info = configuration.makeInfo(now: Date(timeIntervalSince1970: 1_000))
        let manifest = try XCTUnwrap(info.protocolCapabilities)

        XCTAssertTrue(manifest.isStructurallyValid)
        XCTAssertTrue(manifest.supports(module: "nw.core", version: 2))
        XCTAssertTrue(manifest.supports(module: "nw.mailbox", version: 2))
        XCTAssertFalse(manifest.supports(module: "nw.routes", version: 2))
        XCTAssertFalse(manifest.supports(module: "nw.routes", version: 3))
        XCTAssertEqual(
            ProtocolCapabilityManifest.knownModuleCatalog
                .first { $0.module == "nw.routes" }?.status,
            .experimental
        )
        XCTAssertFalse(manifest.supports(module: "nw.prekeys", version: 1))
        XCTAssertFalse(
            manifest.supports(
                module: RelayCompatibilityProfile.legacyFingerprint,
                version: 1
            )
        )
        XCTAssertFalse(manifest.modules.contains { $0.module == "nw.blobs" })
        XCTAssertFalse(manifest.modules.contains { $0.module == "nw.groups" })
        XCTAssertFalse(manifest.modules.contains { $0.module == "nw.wake" })

        let internallyEnabled = RelayConfiguration(
            experimentalRouteCapabilitiesEnabled: true
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))
        let internallyEnabledManifest = try XCTUnwrap(internallyEnabled.protocolCapabilities)
        XCTAssertFalse(internallyEnabledManifest.supports(module: "nw.routes", version: 3))

        let roundTrip = try NoctweaveCoder.decode(
            RelayInfo.self,
            from: NoctweaveCoder.encode(info, sortedKeys: true)
        )
        XCTAssertEqual(roundTrip.protocolCapabilities, manifest)
    }

    func testLegacyFingerprintProfileIsExplicitAndAdvertisedAsDeprecated() throws {
        let configuration = RelayConfiguration(
            compatibilityProfiles: [RelayCompatibilityProfile.legacyFingerprint]
        )
        let info = configuration.makeInfo(now: Date(timeIntervalSince1970: 1_000))
        let manifest = try XCTUnwrap(info.protocolCapabilities)

        XCTAssertTrue(configuration.legacyFingerprintCompatibilityEnabled)
        XCTAssertTrue(manifest.supports(module: "nw.prekeys", version: 1))
        XCTAssertTrue(manifest.supports(module: "nw.groups", version: 1))
        XCTAssertEqual(
            manifest.modules.first { $0.module == "nw.groups" }?.status,
            .deprecated
        )
        XCTAssertEqual(
            manifest.modules.first {
                $0.module == RelayCompatibilityProfile.legacyFingerprint
            }?.status,
            .deprecated
        )
        XCTAssertEqual(info.groupCreationMode, .allowed)
    }

    func testDefaultRelayRejectsLegacyFingerprintRequestFamilies() async throws {
        let port = UInt16.random(in: 42_000...45_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(store: RelayStore())
        try server.start(host: endpoint.host, port: endpoint.port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 100_000_000)

        let client = RelayClient(endpoint: endpoint)
        let legacyRequestTypes: [RelayRequestType] = [
            .sendPairRequest,
            .fetchPrekeyBundle,
            .createGroup,
            .acknowledgeMessages
        ]
        for type in legacyRequestTypes {
            let response = try await client.send(RelayRequest(type: type))
            XCTAssertEqual(response.type, .error)
            XCTAssertEqual(
                response.error,
                "Deprecated compatibility profile \(RelayCompatibilityProfile.legacyFingerprint) is disabled"
            )
        }
    }

    func testDirectV4NeverNegotiatesLegacyFingerprintProfile() throws {
        let compatibility = ProtocolModuleCapability(
            module: RelayCompatibilityProfile.legacyFingerprint,
            versions: [1],
            status: .deprecated
        )
        let manifest = ProtocolCapabilityManifest(
            modules: ProtocolCapabilityManifest.defaultActiveEndpointModules + [compatibility]
        )

        let negotiated = try DirectV4NegotiatedCapabilityManifest.negotiate(
            local: manifest,
            peer: manifest
        )

        XCTAssertFalse(
            negotiated.modules.contains {
                $0.module == RelayCompatibilityProfile.legacyFingerprint
            }
        )
        XCTAssertEqual(negotiated.modules.map(\.module), [
            "nw.core", "nw.endpoints", "nw.events", "nw.prekeys"
        ])
        XCTAssertEqual(try negotiated.digest().count, 32)
    }

    func testRelayCapabilityManifestRejectsDuplicateAndMalformedModules() {
        let valid = RelayModuleCapabilityV2(
            module: "nw.core",
            versions: [2],
            status: .provisional
        )
        XCTAssertTrue(valid.isStructurallyValid)
        XCTAssertFalse(
            RelayCapabilityManifestV2(modules: [valid, valid]).isStructurallyValid
        )
        XCTAssertFalse(
            RelayCapabilityManifestV2(
                modules: [
                    RelayModuleCapabilityV2(
                        module: "mailbox",
                        versions: [2],
                        status: .provisional
                    )
                ]
            ).isStructurallyValid
        )
    }
}
