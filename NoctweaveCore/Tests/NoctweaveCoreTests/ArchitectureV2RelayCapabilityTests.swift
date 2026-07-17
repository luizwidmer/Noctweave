import XCTest
@testable import NoctweaveCore

final class ArchitectureV2RelayCapabilityTests: XCTestCase {
    func testRelayInfoAdvertisesOnlyEnabledProtocolModules() throws {
        let configuration = RelayConfiguration(
            federation: FederationDescriptor(mode: .solo),
            attachmentsEnabled: false
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

    func testDirectV4NegotiatesTheActiveEndpointModules() throws {
        let manifest = ProtocolCapabilityManifest()

        let negotiated = try DirectV4NegotiatedCapabilityManifest.negotiate(
            local: manifest,
            peer: manifest
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
