import XCTest
@testable import NoctweaveRelayServer

final class RelayCapabilitiesV2Tests: XCTestCase {
    func testConfiguredRelayAdvertisesMailboxV2AndEnabledModules() throws {
        let info = RelayConfiguration(
            federation: FederationDescriptor(mode: .manual),
            attachmentsEnabled: true,
            groupCreationMode: .allowed,
            compatibilityProfiles: [RelayCompatibilityProfile.legacyFingerprint]
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))
        let manifest = try XCTUnwrap(info.protocolCapabilities)

        XCTAssertTrue(manifest.isStructurallyValid)
        XCTAssertTrue(manifest.supports(module: "nw.core", version: 2))
        XCTAssertTrue(manifest.supports(module: "nw.mailbox", version: 2))
        XCTAssertFalse(manifest.supports(module: "nw.routes", version: 2))
        XCTAssertFalse(manifest.supports(module: "nw.routes", version: 3))
        XCTAssertTrue(manifest.supports(module: "nw.blobs", version: 1))
        XCTAssertTrue(manifest.supports(module: "nw.groups", version: 1))
        XCTAssertEqual(
            manifest.modules.first { $0.module == "nw.groups" }?.status,
            .deprecated
        )
        XCTAssertTrue(
            manifest.supports(
                module: RelayCompatibilityProfile.legacyFingerprint,
                version: 1
            )
        )
        XCTAssertEqual(
            manifest.modules.first {
                $0.module == RelayCompatibilityProfile.legacyFingerprint
            }?.status,
            .deprecated
        )
        let internallyEnabled = RelayConfiguration(
            experimentalRouteCapabilitiesEnabled: true
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))
        let internallyEnabledManifest = try XCTUnwrap(internallyEnabled.protocolCapabilities)
        XCTAssertFalse(internallyEnabledManifest.supports(module: "nw.routes", version: 3))

        let encoded = try JSONEncoder().encode(info)
        let decoded = try JSONDecoder().decode(RelayInfo.self, from: encoded)
        XCTAssertEqual(decoded.protocolCapabilities, manifest)
    }

    func testDefaultRelayDoesNotAdvertiseLegacyFingerprintOperations() throws {
        let info = RelayConfiguration().makeInfo()
        let manifest = try XCTUnwrap(info.protocolCapabilities)

        XCTAssertFalse(manifest.supports(module: "nw.prekeys", version: 1))
        XCTAssertFalse(manifest.supports(module: "nw.groups", version: 1))
        XCTAssertFalse(
            manifest.supports(
                module: RelayCompatibilityProfile.legacyFingerprint,
                version: 1
            )
        )
        XCTAssertEqual(info.groupCreationMode, .disabled)
    }
}
