import XCTest
@testable import NoctweaveRelayServer

final class RelayCapabilitiesV2Tests: XCTestCase {
    func testConfiguredRelayAdvertisesStableOpaqueRouteAndEnabledModules() throws {
        let info = RelayConfiguration(
            federation: FederationDescriptor(mode: .manual),
            attachmentsEnabled: true
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))
        let manifest = try XCTUnwrap(info.protocolCapabilities)

        XCTAssertTrue(manifest.isStructurallyValid)
        XCTAssertTrue(manifest.supports(module: "nw.core", version: 2))
        XCTAssertTrue(manifest.supports(module: "nw.opaque-route", version: 2))
        XCTAssertFalse(manifest.supports(module: "nw.routes", version: 2))
        XCTAssertFalse(manifest.supports(module: "nw.routes", version: 3))
        XCTAssertTrue(manifest.supports(module: "nw.blobs", version: 1))
        XCTAssertFalse(manifest.supports(module: "nw.groups", version: 1))
        let disabled = RelayConfiguration(
            opaqueRouteRuntimeEnabled: false
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))
        let disabledManifest = try XCTUnwrap(disabled.protocolCapabilities)
        XCTAssertFalse(disabledManifest.supports(module: "nw.opaque-route", version: 2))

        let encoded = try JSONEncoder().encode(info)
        let decoded = try JSONDecoder().decode(RelayInfo.self, from: encoded)
        XCTAssertEqual(decoded.protocolCapabilities, manifest)
    }

    func testDefaultRelayDoesNotAdvertiseUnavailableModules() throws {
        let info = RelayConfiguration().makeInfo()
        let manifest = try XCTUnwrap(info.protocolCapabilities)

        XCTAssertFalse(manifest.supports(module: "nw.prekeys", version: 1))
        XCTAssertFalse(manifest.supports(module: "nw.groups", version: 1))
        XCTAssertEqual(info.groupCreationMode, .disabled)
    }
}
