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
            XCTAssertEqual(manifest.modules.first { $0.module == module }?.status, .provisional)
        }
        XCTAssertFalse(manifest.modules.contains { $0.status == .stable })
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
        XCTAssertFalse(manifest.modules.contains { $0.module == "nw.open-discovery" })

        let roundTrip = try NoctweaveCoder.decode(
            RelayInfo.self,
            from: NoctweaveCoder.encode(info, sortedKeys: true)
        )
        XCTAssertEqual(roundTrip.protocolCapabilities, manifest)
    }

    func testOpaqueRouteCapabilityRegistryIsCanonicalAndComplete() throws {
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
            wakeEnabled: false,
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

    func testCandidateAndExperimentalModuleCatalogStatuses() {
        let catalog = ProtocolCapabilityManifest.knownModuleCatalog

        XCTAssertEqual(
            catalog.filter { $0.status == .provisional }.map(\.module),
            [
                "nw.core",
                "nw.direct",
                "nw.opaque-route",
                "nw.rendezvous-transport",
                "nw.blobs",
                "nw.federation"
            ]
        )
        XCTAssertEqual(
            catalog.filter { $0.status == .experimental }.map(\.module),
            [
                "nw.groups",
                "nw.wake",
                "nw.open-discovery",
                "nw.privacy.hidden-retrieval",
                "nw.privacy.onion",
                "nw.privacy.mixnet"
            ]
        )
        XCTAssertFalse(catalog.contains { $0.status == .stable })
        XCTAssertEqual(
            ProtocolCapabilityManifest.defaultActiveEndpointModules.map(\.status),
            [.provisional, .provisional]
        )
    }

    func testRelayAdvertisesExperimentalOpenDiscoveryOnlyWhenDHTIsEnabled() throws {
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
