import XCTest
@testable import NoctweaveRelayServer

final class RelayCapabilitiesV2Tests: XCTestCase {
    func testConfiguredRelayAdvertisesProvisionalCandidateModules() throws {
        let info = RelayConfiguration(
            federation: FederationDescriptor(mode: .manual),
            attachmentsEnabled: true,
            rendezvousTransportEnabled: true
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))
        let manifest = try XCTUnwrap(info.protocolCapabilities)

        XCTAssertTrue(manifest.isStructurallyValid)
        XCTAssertTrue(manifest.supports(module: "nw.core", version: 2))
        XCTAssertTrue(manifest.supports(module: "nw.opaque-route", version: 2))
        XCTAssertTrue(manifest.supports(module: "nw.rendezvous-transport", version: 2))
        for module in ["nw.core", "nw.opaque-route", "nw.rendezvous-transport", "nw.blobs", "nw.federation"] {
            XCTAssertEqual(manifest.modules.first { $0.module == module }?.status, .provisional)
        }
        XCTAssertFalse(manifest.modules.contains { $0.status == .stable })
        XCTAssertFalse(manifest.supports(module: "nw.routes", version: 2))
        XCTAssertFalse(manifest.supports(module: "nw.routes", version: 3))
        XCTAssertTrue(manifest.supports(module: "nw.blobs", version: 1))
        XCTAssertFalse(manifest.supports(module: "nw.groups", version: 1))
        XCTAssertFalse(manifest.supports(module: "nw.open-discovery", version: 1))
        let disabled = RelayConfiguration(
            opaqueRouteRuntimeEnabled: false
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))
        let disabledManifest = try XCTUnwrap(disabled.protocolCapabilities)
        XCTAssertFalse(disabledManifest.supports(module: "nw.opaque-route", version: 2))

        let encoded = try JSONEncoder().encode(info)
        let decoded = try JSONDecoder().decode(RelayInfo.self, from: encoded)
        XCTAssertEqual(decoded.protocolCapabilities, manifest)
    }

    func testOpaqueRouteCapabilityRegistryMatchesCanonicalPublicContract() throws {
        let expected: [String: UInt64] = [
            "cursorBytes": 68,
            "maxPage": 256,
            "maxPacketBytes": 65_536,
            "maxPacketsPerRoute": 1_024,
            "maxRetentionSeconds": 604_800,
            "maxRoutes": 100_000,
        ]
        XCTAssertEqual(OpaqueRouteRelayCapabilityLimitsV2.registry, expected)
        let manifest = RelayCapabilityManifestV2.advertised(
            attachmentsEnabled: false,
            hiddenRetrievalEnabled: false,
            onionEnabled: false,
            mixnetEnabled: false
        )
        XCTAssertEqual(
            try XCTUnwrap(manifest.modules.first {
                $0.module == "nw.opaque-route"
            }).limits,
            expected
        )
    }

    func testOpenDiscoveryAdvertisementIsExperimentalAndFeatureGated() throws {
        let enabled = RelayConfiguration(
            federation: FederationDescriptor(mode: .open, name: "example"),
            openFederationDHTEnabled: true,
            allowPrivateFederationEndpoints: true
        ).makeInfo()
        let enabledManifest = try XCTUnwrap(enabled.protocolCapabilities)
        XCTAssertEqual(
            enabledManifest.modules.first { $0.module == "nw.open-discovery" }?.status,
            .experimental
        )
        XCTAssertEqual(
            enabledManifest.modules.first { $0.module == "nw.federation" }?.status,
            .provisional
        )

        let disabled = RelayConfiguration(
            federation: FederationDescriptor(mode: .open, name: "example"),
            openFederationDHTEnabled: false,
            allowPrivateFederationEndpoints: true
        ).makeInfo()
        XCTAssertFalse(
            try XCTUnwrap(disabled.protocolCapabilities).supports(
                module: "nw.open-discovery",
                version: 1
            )
        )
    }

    func testDefaultRelayDoesNotAdvertiseUnavailableModules() throws {
        let info = RelayConfiguration().makeInfo()
        let manifest = try XCTUnwrap(info.protocolCapabilities)

        XCTAssertFalse(manifest.supports(module: "nw.prekeys", version: 1))
        XCTAssertFalse(manifest.supports(module: "nw.groups", version: 1))
        XCTAssertFalse(manifest.supports(module: "nw.wake", version: 1))
    }

    func testCapabilityLimitNamesMustAlreadyBeCanonical() throws {
        let valid = RelayModuleCapabilityV2(
            module: "nw.core",
            versions: [2],
            status: .provisional,
            limits: ["maxPage": 256]
        )
        XCTAssertTrue(valid.isStructurallyValid)
        XCTAssertNoThrow(try JSONEncoder().encode(valid))

        for key in [" maxPage", "maxPage ", "max\u{0}Page"] {
            let invalid = RelayModuleCapabilityV2(
                module: "nw.core",
                versions: [2],
                status: .provisional,
                limits: [key: 256]
            )
            XCTAssertFalse(invalid.isStructurallyValid)
            XCTAssertThrowsError(try JSONEncoder().encode(invalid))
        }
    }
}
