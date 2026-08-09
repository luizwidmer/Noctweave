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
        XCTAssertTrue(OperatorWebUI.css.contains("--accent:#c96a61"))
        XCTAssertFalse(OperatorWebUI.css.contains("rgba(91,73,211"))
        XCTAssertFalse(OperatorWebUI.css.contains("#c8c1ff"))
        XCTAssertTrue(OperatorWebUI.html.contains("class=\"brandLogo\""))
        XCTAssertTrue(OperatorWebUI.html.contains("M34 34h96v70h-26v26H34V34Z"))
        XCTAssertTrue(OperatorWebUI.html.contains("M168 146h54v76h-76v-54h22v-22Z"))
        XCTAssertFalse(OperatorWebUI.html.contains("M96 32H224V176L140"))
        XCTAssertTrue(OperatorWebUI.javascript.contains("Authorization"))
        XCTAssertTrue(OperatorWebUI.html.contains("Secrets stay outside the browser"))
        XCTAssertTrue(OperatorWebUI.html.contains("IPFS API endpoint"))
        XCTAssertTrue(OperatorWebUI.html.contains("Noctweb hosting"))
        XCTAssertTrue(OperatorWebUI.html.contains("NoctCord capabilities"))
        XCTAssertTrue(OperatorWebUI.html.contains("Decentralized wake policy"))
        XCTAssertTrue(OperatorWebUI.html.contains("id=\"relayIdentityID\""))
        XCTAssertTrue(OperatorWebUI.html.contains("id=\"relayNoctwebSuffix\""))
        XCTAssertTrue(OperatorWebUI.javascript.contains(#"s.bootstrap["Relay identity"]"#))
        XCTAssertTrue(OperatorWebUI.javascript.contains(#"s.bootstrap["Noctweb suffix"]"#))
        XCTAssertTrue(OperatorWebUI.html.contains("id=\"openNoctwebPublisher\""))
        XCTAssertTrue(OperatorWebUI.javascript.contains(#"s.bootstrap["Noctweb Publisher / Lab"]"#))
        XCTAssertTrue(OperatorWebUI.javascript.contains("window.open(url"))
        XCTAssertTrue(OperatorWebUI.html.contains("Hidden retrieval research"))
        XCTAssertTrue(OperatorWebUI.html.contains("Onion and mixnet metadata"))
        XCTAssertTrue(OperatorWebUI.html.contains("No anonymity claim"))
        XCTAssertFalse(OperatorWebUI.html.contains("Group creation"))
        XCTAssertTrue(OperatorWebUI.html.contains("Long poll"))
        XCTAssertTrue(OperatorWebUI.javascript.contains("wakeLongPollTimeoutSeconds"))
        XCTAssertTrue(OperatorWebUI.html.contains("name=\"netHostEnabled\" type=\"checkbox\""))
        XCTAssertTrue(OperatorWebUI.javascript.contains("realtimeRoutesEnabled:b(\"realtimeRoutesEnabled\")"))
        XCTAssertTrue(OperatorWebUI.html.contains("Active backend:"))
        XCTAssertTrue(OperatorWebUI.html.contains("name=\"opaqueRouteRuntimeEnabled\" type=\"checkbox\""))
        XCTAssertTrue(OperatorWebUI.javascript.contains("opaqueRouteRuntimeEnabled:b(\"opaqueRouteRuntimeEnabled\")"))
        XCTAssertTrue(OperatorWebUI.html.contains("max=\"2592000\""))
        XCTAssertTrue(OperatorWebUI.html.contains("Opaque-route packets, rendezvous routes"))
        XCTAssertFalse(OperatorWebUI.html.contains("Queues, prekeys"))
        XCTAssertTrue(OperatorWebUI.html.contains("aria-live=\"polite\""))
        XCTAssertTrue(OperatorWebUI.javascript.contains("restartSettingsChanged"))
        XCTAssertTrue(OperatorWebUI.javascript.contains("Configuration saved and applied"))
        XCTAssertTrue(OperatorWebUI.javascript.contains("setConditional"))
        XCTAssertFalse(OperatorWebUI.javascript.contains("ipfsTimeoutSeconds.disabled"))
        XCTAssertTrue(OperatorWebUI.css.contains("prefers-reduced-motion"))
        XCTAssertTrue(OperatorWebUI.css.contains("input:not([type=\"checkbox\"]),select{height:46px"))
        XCTAssertTrue(OperatorWebUI.css.contains("overflow-x:hidden"))
        XCTAssertTrue(OperatorWebUI.css.contains("flex:1 1 0;min-width:0"))
        XCTAssertTrue(OperatorWebUI.html.contains("Three steps to a usable relay"))
        XCTAssertTrue(OperatorWebUI.html.contains("data-jump-view=\"general\""))
        XCTAssertTrue(OperatorWebUI.javascript.contains("function showView(view)"))
        XCTAssertTrue(OperatorWebUI.css.contains(".quickActions"))
    }

    func testOperatorShellProvidesPersistedAppearanceAndSemanticThemeTokens() {
        XCTAssertFalse(OperatorWebUI.html.contains(#"name="color-scheme" content="dark""#))
        XCTAssertTrue(OperatorWebUI.html.contains(#"id="appearanceSelect"#))
        XCTAssertTrue(OperatorWebUI.html.contains(#"value="system"#))
        XCTAssertTrue(OperatorWebUI.html.contains(#"value="light"#))
        XCTAssertTrue(OperatorWebUI.html.contains(#"value="dark"#))
        XCTAssertTrue(OperatorWebUI.css.contains("--shell-surface-raised:#f6eee8"))
        XCTAssertTrue(OperatorWebUI.css.contains(#":root[data-theme="dark"]"#))
        XCTAssertTrue(OperatorWebUI.css.contains("prefers-color-scheme:dark"))
        XCTAssertTrue(OperatorWebUI.css.contains("safe-area-inset-bottom"))
        XCTAssertTrue(OperatorWebUI.javascript.contains("noctweave.operator.appearance"))
        XCTAssertTrue(OperatorWebUI.javascript.contains("localStorage"))
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

    func testOperatorConfigurationAllowsHostCapableRelayInManualFederation() throws {
        var base = makeBaseConfiguration()
        base.netHostEnabled = true
        var editable = OperatorEditableConfiguration(configuration: base)
        editable.federationMode = FederationMode.manual.rawValue
        editable.federationAllowList = ["https://peer.example.org"]

        let updated = try editable.validatedConfiguration(from: base)
        XCTAssertTrue(updated.isNetHostEnabled)
        XCTAssertEqual(updated.federation.mode, .manual)
        XCTAssertEqual(updated.noctwebRelaySuffix?.rawValue, ".relaytest")
    }

    func testOperatorConfigurationRequiresSuffixBeforeJoiningFederation() throws {
        var base = makeBaseConfiguration()
        base.noctwebRelaySuffix = nil
        var editable = OperatorEditableConfiguration(configuration: base)
        editable.federationMode = FederationMode.manual.rawValue

        XCTAssertThrowsError(try editable.validatedConfiguration(from: base)) { error in
            XCTAssertEqual(
                error as? OperatorConfigurationError,
                .unsupportedTransition(
                    "Federated relays require a claimed Noctweb suffix."
                )
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

    func testOperatorConfigurationAcceptsThirtyDayAttachmentRetentionOnly() throws {
        let base = makeBaseConfiguration()
        var editable = OperatorEditableConfiguration(configuration: base)
        editable.attachmentDefaultTTLSeconds = 2_592_000
        editable.attachmentMaxTTLSeconds = 2_592_000
        XCTAssertEqual(
            try editable.validatedConfiguration(from: base).attachmentMaxTTLSeconds,
            OperatorEditableConfiguration.maximumAttachmentTTLSeconds
        )

        editable.attachmentMaxTTLSeconds = 2_592_001
        XCTAssertThrowsError(try editable.validatedConfiguration(from: base)) { error in
            XCTAssertEqual(error as? OperatorConfigurationError, .invalidField("attachment retention"))
        }
    }

    func testOperatorControlPlanePersistsAndAppliesUpdates() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let persistence = OperatorConfigurationPersistence(
            fileURL: directory.appendingPathComponent("operator-config.json")
        )
        let configurationStore = RelayConfigurationStore(makeBaseConfiguration())
        let relayStore = RelayStore(fileURL: nil, temporalBucketSeconds: 300)
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
        editable.opaqueRouteRuntimeEnabled = false

        let updated = try controlPlane.update(editable)
        XCTAssertEqual(updated.configuration.relayName, "Persisted Relay")
        XCTAssertFalse(updated.configuration.opaqueRouteRuntimeEnabled)
        XCTAssertFalse(configurationStore.snapshot().isOpaqueRouteRuntimeEnabled)
        XCTAssertEqual(configurationStore.snapshot().operatorNote, "Configured in the Web UI")
        XCTAssertEqual(try persistence.load()?.relayName, "Persisted Relay")

        let attributes = try FileManager.default.attributesOfItem(atPath: persistence.fileURL!.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testOperatorConfigurationRejectsDuplicateSemanticJSONFields() throws {
        let editable = OperatorEditableConfiguration(configuration: makeBaseConfiguration())
        let encoded = try JSONEncoder().encode(editable)
        let json = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        let field = #""relayName":"#
        XCTAssertTrue(json.contains(field))

        for replacement in [
            #""relayName":"shadow","relayName":"#,
            #""relayName":"shadow","\u0072elayName":"#
        ] {
            let ambiguous = json.replacingOccurrences(of: field, with: replacement)
            XCTAssertThrowsError(
                try decodeOperatorJSON(
                    OperatorEditableConfiguration.self,
                    from: Data(ambiguous.utf8)
                )
            ) { error in
                XCTAssertTrue(String(describing: error).contains("duplicate object member"))
            }
        }
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
            relayStore: RelayStore(fileURL: nil),
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

    func testNoctwebHostingAndSuffixAreStagedUntilRestart() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let persistence = OperatorConfigurationPersistence(
            fileURL: directory.appendingPathComponent("operator-config.json")
        )
        var base = makeBaseConfiguration()
        base.netHostEnabled = false
        base.noctwebRelaySuffix = nil
        let configurationStore = RelayConfigurationStore(base)
        let controlPlane = OperatorControlPlane(
            configurationStore: configurationStore,
            persistence: persistence,
            relayStore: RelayStore(fileURL: nil),
            startedAt: Date(),
            bootstrap: [:],
            storageDescription: "SQLite",
            transportDescription: "TCP"
        )
        var editable = controlPlane.state().configuration
        editable.netHostEnabled = true
        editable.noctwebRelaySuffix = ".community"

        let staged = try controlPlane.update(editable)
        XCTAssertTrue(staged.status.restartRequired)
        XCTAssertFalse(configurationStore.snapshot().isNetHostEnabled)
        XCTAssertNil(configurationStore.snapshot().noctwebRelaySuffix)

        var serverConfig = ServerConfig.parse(arguments: [], environment: [:])
        try persistence.load()?.applyPersistedOverrides(to: &serverConfig)
        XCTAssertTrue(serverConfig.netHostEnabled)
        XCTAssertEqual(serverConfig.noctwebRelaySuffix, ".community")
    }

    func testRealtimeAndWakeSettingsApplyLiveAndAdvertiseAccurately() throws {
        let base = makeBaseConfiguration()
        var editable = OperatorEditableConfiguration(configuration: base)
        editable.realtimeRoutesEnabled = false
        editable.sharedLogsEnabled = false
        editable.ephemeralPresenceEnabled = false
        editable.mediaBlobsEnabled = false
        editable.wakeEnabled = true
        editable.wakeMode = DecentralizedWakeMode.longPoll.rawValue
        editable.wakeMinPollSeconds = 15
        editable.wakeMaxPollSeconds = 120
        editable.wakeJitterPermille = 400
        editable.wakeLongPollTimeoutSeconds = 45

        let updated = try editable.validatedConfiguration(from: base)
        XCTAssertFalse(updated.areRealtimeRoutesEnabled)
        XCTAssertFalse(updated.areSharedLogsEnabled)
        XCTAssertFalse(updated.isEphemeralPresenceEnabled)
        XCTAssertFalse(updated.areMediaBlobsEnabled)
        XCTAssertEqual(updated.wakeSupport?.mode, .longPoll)
        XCTAssertEqual(updated.wakeSupport?.longPollTimeoutSeconds, 45)
        let manifest = try XCTUnwrap(updated.makeInfo().protocolCapabilities)
        XCTAssertTrue(manifest.supports(module: "nw.wake", version: 1))
        for module in ["nw.realtime-route", "nw.shared-log", "nw.ephemeral-presence", "nw.media-blobs"] {
            XCTAssertFalse(manifest.supports(module: module, version: 1), module)
        }
    }

    func testServerConfigParsesRealtimeAndWakeEnvironment() {
        let config = ServerConfig.parse(
            arguments: [],
            environment: [
                "NOCTWEAVE_WAKE_MODE": "longPoll",
                "NOCTWEAVE_WAKE_MIN_POLL_SECONDS": "20",
                "NOCTWEAVE_WAKE_MAX_POLL_SECONDS": "180",
                "NOCTWEAVE_WAKE_LONG_POLL_TIMEOUT_SECONDS": "40",
                "NOCTWEAVE_REALTIME_ROUTES": "false",
                "NOCTWEAVE_SHARED_LOGS": "false",
                "NOCTWEAVE_EPHEMERAL_PRESENCE": "false",
                "NOCTWEAVE_MEDIA_BLOBS": "false"
            ]
        )
        XCTAssertEqual(config.wakeSupport?.mode, .longPoll)
        XCTAssertEqual(config.wakeSupport?.minPollIntervalSeconds, 20)
        XCTAssertEqual(config.wakeSupport?.maxPollIntervalSeconds, 180)
        XCTAssertEqual(config.wakeSupport?.longPollTimeoutSeconds, 40)
        XCTAssertFalse(config.realtimeRoutesEnabled)
        XCTAssertFalse(config.sharedLogsEnabled)
        XCTAssertFalse(config.ephemeralPresenceEnabled)
        XCTAssertFalse(config.mediaBlobsEnabled)
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
        let updated = try editable.validatedConfiguration(from: base)
        XCTAssertEqual(updated.hiddenRetrieval?.defaultCoverSetSize, 12)
        XCTAssertEqual(updated.onionTransport?.maxHops, 4)
        XCTAssertEqual(updated.mixnetTransport?.minBatchSize, 8)
        XCTAssertEqual(updated.openFederationDHTMaxRecords, 128)
        XCTAssertEqual(updated.openFederationDHTMaxRecordsPerHost, 3)
        XCTAssertEqual(updated.openFederationDHTMaxQueryRecords, 192)
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
            advertisedEndpoint: RelayEndpoint(host: "127.0.0.1", port: 9340, transport: .http),
            noctwebRelaySuffix: NoctwebRelaySuffixV1(rawValue: ".relaytest")
        )
    }
}
