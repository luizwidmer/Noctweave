import Foundation
import XCTest
@preconcurrency import NIOHTTP1
@testable import NoctweaveRelayServer

final class OperatorWebUITests: XCTestCase {
    func testOperatorUIUsesExternalAssetsAndStrictControlPlaneLanguage() {
        XCTAssertTrue(OperatorWebUI.html.contains("Noctweave Relay Console"))
        XCTAssertTrue(OperatorWebUI.html.contains("/admin/assets/app.css"))
        XCTAssertTrue(OperatorWebUI.html.contains("/admin/assets/app.js"))
        XCTAssertFalse(OperatorWebUI.html.contains("<script>"))
        XCTAssertTrue(OperatorWebUI.css.contains("--accent:#7b61ff"))
        XCTAssertTrue(OperatorWebUI.html.contains("class=\"brandLogo\""))
        XCTAssertTrue(OperatorWebUI.javascript.contains("Authorization"))
        XCTAssertTrue(OperatorWebUI.html.contains("Secrets stay outside the browser"))
        XCTAssertTrue(OperatorWebUI.html.contains("IPFS API endpoint"))
        XCTAssertTrue(OperatorWebUI.html.contains("Hidden retrieval"))
        XCTAssertTrue(OperatorWebUI.html.contains("Onion and mixnet capabilities"))
        XCTAssertTrue(OperatorWebUI.html.contains("Active backend:"))
        XCTAssertTrue(OperatorWebUI.html.contains("aria-live=\"polite\""))
        XCTAssertTrue(OperatorWebUI.javascript.contains("restartSettingsChanged"))
        XCTAssertTrue(OperatorWebUI.javascript.contains("Configuration saved and applied"))
        XCTAssertTrue(OperatorWebUI.javascript.contains("setConditional"))
        XCTAssertFalse(OperatorWebUI.javascript.contains("ipfsTimeoutSeconds.disabled"))
        XCTAssertTrue(OperatorWebUI.css.contains("prefers-reduced-motion"))
        XCTAssertTrue(OperatorWebUI.css.contains("input:not([type=\"checkbox\"]),select{height:46px"))
        XCTAssertTrue(OperatorWebUI.css.contains("overflow-x:hidden"))
        XCTAssertTrue(OperatorWebUI.css.contains("flex:1 1 0;min-width:0"))
    }

    func testOperatorTokenAuthenticatorRequiresSingleBearerToken() {
        let authenticator = OperatorTokenAuthenticator(expectedToken: "correct-operator-token")
        var valid = HTTPHeaders()
        valid.add(name: "Authorization", value: "Bearer correct-operator-token")
        XCTAssertTrue(authenticator.authenticate(headers: valid, source: "127.0.0.1"))

        var wrong = HTTPHeaders()
        wrong.add(name: "Authorization", value: "Bearer incorrect-token")
        XCTAssertFalse(authenticator.authenticate(headers: wrong, source: "127.0.0.2"))

        var duplicate = valid
        duplicate.add(name: "Authorization", value: "Bearer correct-operator-token")
        XCTAssertFalse(authenticator.authenticate(headers: duplicate, source: "127.0.0.3"))
    }

    func testOperatorConfigurationRejectsOpenDiscoveryOutsideOpenFederation() throws {
        let base = makeBaseConfiguration()
        var editable = OperatorEditableConfiguration(configuration: base)
        editable.federationMode = FederationMode.manual.rawValue
        editable.relayPeerExchangeLimit = 1

        XCTAssertThrowsError(try editable.validatedConfiguration(from: base)) { error in
            XCTAssertEqual(
                error as? OperatorConfigurationError,
                .unsupportedTransition("DHT and peer exchange are available only in open federation mode.")
            )
        }
    }

    func testOperatorConfigurationAcceptsBoundedOpenFederationProfile() throws {
        let base = makeBaseConfiguration()
        var editable = OperatorEditableConfiguration(configuration: base)
        editable.relayName = "Community Relay"
        editable.advertisedEndpoint = "https://relay.example.org"
        editable.federationMode = FederationMode.open.rawValue
        editable.federationName = "Noctweave Public"
        editable.federationAllowList = ["https://peer.example.org"]
        editable.relayPeerExchangeLimit = 16
        editable.openFederationDHTEnabled = true
        editable.temporalBucketSeconds = 0
        editable.temporalBucketScheduleSeconds = [60, 120, 300]

        let updated = try editable.validatedConfiguration(from: base)
        XCTAssertEqual(updated.relayName, "Community Relay")
        XCTAssertEqual(updated.advertisedEndpoint?.host, "relay.example.org")
        XCTAssertEqual(updated.advertisedEndpoint?.port, 443)
        XCTAssertEqual(updated.federation.mode, .open)
        XCTAssertTrue(updated.openFederationDHTEnabled)
        XCTAssertEqual(updated.relayPeerExchangeLimit, 16)
        XCTAssertEqual(updated.temporalBucketScheduleSeconds, [60, 120, 300])
    }

    func testOperatorControlPlanePersistsAndAppliesUpdates() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let persistence = OperatorConfigurationPersistence(
            fileURL: directory.appendingPathComponent("operator-config.json")
        )
        let configurationStore = RelayConfigurationStore(makeBaseConfiguration())
        let relayStore = RelayStore(fileURL: nil, maxInboxMessages: 10, temporalBucketSeconds: 300)
        let controlPlane = OperatorControlPlane(
            configurationStore: configurationStore,
            persistence: persistence,
            relayStore: relayStore,
            startedAt: Date(timeIntervalSinceNow: -60),
            bootstrap: ["Raw TCP": "127.0.0.1:9339"],
            storageDescription: "SQLite",
            transportDescription: "TCP"
        )
        var editable = controlPlane.state().configuration
        editable.relayName = "Persisted Relay"
        editable.operatorNote = "Configured in the Web UI"
        editable.temporalBucketSeconds = 120
        editable.relayPeerExchangeLimit = 0

        let updated = try controlPlane.update(editable)
        XCTAssertEqual(updated.configuration.relayName, "Persisted Relay")
        XCTAssertEqual(configurationStore.snapshot().operatorNote, "Configured in the Web UI")
        XCTAssertEqual(try persistence.load()?.relayName, "Persisted Relay")

        let attributes = try FileManager.default.attributesOfItem(atPath: persistence.fileURL!.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testIPFSSettingsPersistAndRequireRestart() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let persistence = OperatorConfigurationPersistence(
            fileURL: directory.appendingPathComponent("operator-config.json")
        )
        let base = makeBaseConfiguration()
        let controlPlane = OperatorControlPlane(
            configurationStore: RelayConfigurationStore(base),
            persistence: persistence,
            relayStore: RelayStore(fileURL: nil, maxInboxMessages: 10),
            startedAt: Date(),
            bootstrap: [:],
            storageDescription: "SQLite",
            transportDescription: "TCP"
        )
        var editable = controlPlane.state().configuration
        editable.attachmentStorageMode = AttachmentStorageMode.ipfs.rawValue
        editable.ipfsAPIEndpoint = "http://ipfs:5001"
        editable.ipfsGatewayEndpoint = "https://gateway.example.org"
        editable.ipfsTimeoutSeconds = 20

        let updated = try controlPlane.update(editable)
        XCTAssertTrue(updated.status.restartRequired)
        XCTAssertEqual(updated.configuration.attachmentStorageMode, "ipfs")
        XCTAssertEqual(try persistence.load()?.ipfsAPIEndpoint, "http://ipfs:5001")

        var serverConfig = ServerConfig.parse(arguments: [], environment: [:])
        try persistence.load()?.applyPersistedOverrides(to: &serverConfig)
        XCTAssertEqual(serverConfig.attachmentStorageMode, .ipfs)
        XCTAssertEqual(serverConfig.ipfsAPIEndpoint?.absoluteString, "http://ipfs:5001")
        XCTAssertEqual(serverConfig.ipfsGatewayEndpoint?.absoluteString, "https://gateway.example.org")
        XCTAssertEqual(serverConfig.ipfsTimeoutSeconds, 20)
    }

    func testAdvancedPrivacyAndFederationSettingsApplyLive() throws {
        let base = makeBaseConfiguration()
        var editable = OperatorEditableConfiguration(configuration: base)
        editable.federationMode = FederationMode.open.rawValue
        editable.relayPeerExchangeLimit = 8
        editable.openFederationDHTEnabled = true
        editable.openFederationDHTMaxRecords = 128
        editable.openFederationDHTMaxRecordsPerHost = 3
        editable.openFederationDHTMaxQueryRecords = 192
        editable.hiddenRetrievalEnabled = true
        editable.hiddenRetrievalMode = HiddenRetrievalMode.coverQuery.rawValue
        editable.hiddenRetrievalCoverSize = 12
        editable.hiddenRetrievalMaxCoverSize = 48
        editable.onionTransportEnabled = true
        editable.onionTransportMaxHops = 4
        editable.onionTransportRequiresFixedSizePackets = true
        editable.mixnetTransportEnabled = true
        editable.mixnetBatchIntervalSeconds = 30
        editable.mixnetMinBatchSize = 8
        editable.mixnetCoverPacketsPerBatch = 2
        editable.mixnetMaxDelaySeconds = 120
        editable.groupSecurityModel = GroupSecurityModel.mlsDerivedTree.rawValue

        let updated = try editable.validatedConfiguration(from: base)
        XCTAssertEqual(updated.hiddenRetrieval?.defaultCoverSetSize, 12)
        XCTAssertEqual(updated.onionTransport?.maxHops, 4)
        XCTAssertEqual(updated.mixnetTransport?.minBatchSize, 8)
        XCTAssertEqual(updated.openFederationDHTMaxRecords, 128)
        XCTAssertEqual(updated.openFederationDHTMaxRecordsPerHost, 3)
        XCTAssertEqual(updated.openFederationDHTMaxQueryRecords, 192)
        XCTAssertEqual(updated.groupSecurityModel, .mlsDerivedTree)
    }

    func testLegacyOperatorConfigurationDecodesWithNewFieldsAbsent() throws {
        let current = OperatorEditableConfiguration(configuration: makeBaseConfiguration())
        let encoded = try JSONEncoder().encode(current)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        [
            "attachmentStorageMode", "ipfsAPIEndpoint", "ipfsGatewayEndpoint", "ipfsTimeoutSeconds",
            "hiddenRetrievalEnabled", "onionTransportEnabled", "mixnetTransportEnabled"
        ].forEach { object.removeValue(forKey: $0) }
        let legacyData = try JSONSerialization.data(withJSONObject: object)

        let decoded = try JSONDecoder().decode(OperatorEditableConfiguration.self, from: legacyData)
        XCTAssertNil(decoded.attachmentStorageMode)
        XCTAssertNil(decoded.hiddenRetrievalEnabled)
        XCTAssertNoThrow(try decoded.validatedConfiguration(from: makeBaseConfiguration()))
    }

    func testOperatorSecurityHeadersDisallowEmbeddingAndInlineCode() {
        var headers = HTTPHeaders()
        OperatorHTTPSecurityHeaders.apply(to: &headers)
        XCTAssertEqual(headers.first(name: "Cache-Control"), "no-store")
        XCTAssertEqual(headers.first(name: "X-Frame-Options"), "DENY")
        let policy = headers.first(name: "Content-Security-Policy") ?? ""
        XCTAssertTrue(policy.contains("script-src 'self'"))
        XCTAssertTrue(policy.contains("style-src 'self'"))
        XCTAssertTrue(policy.contains("frame-ancestors 'none'"))
        XCTAssertFalse(policy.contains("'unsafe-inline'"))
    }

    func testAdminTokenEnvironmentEnablesDefaultDockerConsolePort() {
        let config = ServerConfig.parse(
            arguments: [],
            environment: ["NOCTWEAVE_ADMIN_TOKEN": "environment-operator-token"]
        )
        XCTAssertEqual(config.adminHost, "127.0.0.1")
        XCTAssertEqual(config.adminPort, 9090)
        XCTAssertEqual(config.adminToken, "environment-operator-token")
    }

    private func makeBaseConfiguration() -> RelayConfiguration {
        RelayConfiguration(
            kind: .standard,
            federation: FederationDescriptor(mode: .solo),
            transport: .http,
            relayPeerExchangeLimit: 12,
            openFederationDHTEnabled: false,
            advertisedEndpoint: RelayEndpoint(host: "127.0.0.1", port: 9340, transport: .http)
        )
    }
}
