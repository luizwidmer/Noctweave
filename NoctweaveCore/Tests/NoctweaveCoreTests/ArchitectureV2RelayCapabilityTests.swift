import XCTest
@testable import NoctweaveCore

final class ArchitectureV2RelayCapabilityTests: XCTestCase {
    func testRelayInfoAdvertisesOnlyEnabledProtocolModules() throws {
        let configuration = RelayConfiguration(
            federation: FederationDescriptor(mode: .solo),
            attachmentsEnabled: false,
            rendezvousTransportEnabled: true
        )
        let info = configuration.makeInfo(now: Date(timeIntervalSince1970: 1_000))
        let manifest = try XCTUnwrap(info.protocolCapabilities)

        XCTAssertTrue(manifest.isStructurallyValid)
        XCTAssertTrue(manifest.supports(module: "nw.core", version: 2))
        XCTAssertTrue(manifest.supports(module: "nw.opaque-route", version: 2))
        XCTAssertTrue(manifest.supports(module: "nw.rendezvous-transport", version: 2))
        for module in ["nw.core", "nw.opaque-route", "nw.rendezvous-transport", "nw.federation"] {
            XCTAssertEqual(manifest.modules.first { $0.module == module }?.status, .stable)
        }
        XCTAssertFalse(manifest.supports(module: "nw.routes", version: 2))
        XCTAssertFalse(manifest.supports(module: "nw.routes", version: 3))
        XCTAssertFalse(
            ProtocolCapabilityManifest.knownModuleCatalog
                .contains { $0.module == "nw.routes" }
        )
        XCTAssertFalse(manifest.supports(module: "nw.prekeys", version: 1))
        XCTAssertFalse(manifest.modules.contains { $0.module == "nw.blobs" })
        XCTAssertFalse(manifest.modules.contains { $0.module == "nw.groups" })
        XCTAssertFalse(manifest.modules.contains { $0.module == "nw.wake" })

        let roundTrip = try NoctweaveCoder.decode(
            RelayInfo.self,
            from: NoctweaveCoder.encode(info, sortedKeys: true)
        )
        XCTAssertEqual(roundTrip.protocolCapabilities, manifest)
    }

    func testDirectV4NegotiatesOnlyCoreAndDirect() throws {
        let manifest = ProtocolCapabilityManifest()

        let negotiated = try DirectV4NegotiatedCapabilityManifest.negotiate(
            local: manifest,
            peer: manifest
        )

        XCTAssertEqual(negotiated.modules.map(\.module), ["nw.core", "nw.direct"])
        XCTAssertTrue(negotiated.contentTypes.contains { $0.supports(.text) })
        XCTAssertTrue(negotiated.contentTypes.contains { $0.supports(.deliveryReceipt) })
        XCTAssertNotNil(negotiated.limit(module: "nw.direct", name: "maxPrekeyAgeSeconds"))
        XCTAssertEqual(try negotiated.digest().count, 32)
    }

    func testContentTypeNegotiationUsesMajorVersionsAndRequiresText() throws {
        let local = ProtocolCapabilityManifest(
            contentTypes: [
                ContentTypeCapabilityV2(
                    authority: "org.noctweave",
                    name: "text",
                    majorVersions: [1, 2]
                ),
                ContentTypeCapabilityV2(.reaction)
            ]
        )
        let peer = ProtocolCapabilityManifest(
            contentTypes: [
                ContentTypeCapabilityV2(
                    authority: "org.noctweave",
                    name: "text",
                    majorVersions: [2, 3]
                ),
                ContentTypeCapabilityV2(.attachment)
            ]
        )
        let negotiated = try DirectV4NegotiatedCapabilityManifest.negotiate(
            local: local,
            peer: peer
        )
        XCTAssertEqual(
            negotiated.contentTypes,
            [
                ContentTypeCapabilityV2(
                    authority: "org.noctweave",
                    name: "text",
                    majorVersions: [2]
                )
            ]
        )

        let incompatibleText = ProtocolCapabilityManifest(
            contentTypes: [
                ContentTypeCapabilityV2(
                    authority: "org.noctweave",
                    name: "text",
                    majorVersions: [3]
                )
            ]
        )
        XCTAssertThrowsError(try DirectV4NegotiatedCapabilityManifest.negotiate(
            local: local,
            peer: incompatibleText
        )) { error in
            XCTAssertEqual(
                error as? DirectV4CapabilityNegotiationError,
                .missingRequiredContentType(ContentTypeId.text.canonicalName)
            )
        }
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
