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
        XCTAssertTrue(OperatorWebUI.css.contains("--accent:#8274ff"))
        XCTAssertTrue(OperatorWebUI.javascript.contains("Authorization"))
        XCTAssertTrue(OperatorWebUI.html.contains("Secrets stay outside the browser"))
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
            environment: ["NOCTYRA_ADMIN_TOKEN": "environment-operator-token"]
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
