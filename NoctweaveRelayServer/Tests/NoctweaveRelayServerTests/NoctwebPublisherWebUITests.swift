import Crypto
import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class NoctwebPublisherWebUITests: XCTestCase {
    private let key = Data((0..<32).map(UInt8.init))

    func testAutomaticNamespaceAndConfigAreStableAndBoundToHostKey() throws {
        let surface = try NoctwebPublisherSurface(
            hostSigningPublicKey: key,
            operatorSuffix: nil
        )
        XCTAssertTrue(surface.relayNamespaceID.hasPrefix("sha256:"))
        XCTAssertEqual(surface.relayNamespaceID.count, 71)
        XCTAssertTrue(surface.relaySuffix.hasPrefix("r-"))
        XCTAssertEqual(surface.relaySuffix.count, 18)
        XCTAssertFalse(surface.usesCustomSuffix)

        let config = try XCTUnwrap(surface.response(
            method: "GET",
            uri: "/noctweb/config.json"
        ))
        XCTAssertEqual(config.statusCode, 200)
        XCTAssertEqual(config.contentType, "application/json; charset=utf-8")
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: config.body) as? [String: Any]
        )
        XCTAssertEqual(object["relayNamespaceID"] as? String, surface.relayNamespaceID)
        XCTAssertEqual(object["relaySuffix"] as? String, surface.relaySuffix)
        XCTAssertEqual(object["hostSigningPublicKey"] as? String, key.base64EncodedString())
        XCTAssertEqual(object["maximumObjectBytes"] as? Int, 1_024 * 1_024)
        XCTAssertNil(String(data: config.body, encoding: .utf8)?.range(
            of: "password",
            options: .caseInsensitive
        ))
    }

    func testCustomSuffixIsCanonicalAndReservedOrUnsafeLabelsFail() throws {
        let custom = try NoctwebPublisherSurface(
            hostSigningPublicKey: key,
            operatorSuffix: ".atelier"
        )
        XCTAssertEqual(custom.relaySuffix, "atelier")
        XCTAssertTrue(custom.usesCustomSuffix)

        for suffix in ["r-reserved", "UPPER", "two.parts", "-edge", "edge-", "xn--alias", ""] {
            XCTAssertThrowsError(
                try NoctwebPublisherSurface(
                    hostSigningPublicKey: key,
                    operatorSuffix: suffix
                )
            )
        }
        XCTAssertThrowsError(
            try NoctwebPublisherSurface(
                hostSigningPublicKey: Data(repeating: 1, count: 31),
                operatorSuffix: nil
            )
        )
    }

    func testRoutesAreExactMethodBoundedAndKeepRelaySurfaceSeparate() throws {
        let surface = try NoctwebPublisherSurface(
            hostSigningPublicKey: key,
            operatorSuffix: nil
        )
        let redirect = try XCTUnwrap(surface.response(method: "GET", uri: "/noctweb"))
        XCTAssertEqual(redirect.statusCode, 308)
        XCTAssertEqual(redirect.headers["Location"], "/noctweb/")

        XCTAssertEqual(
            surface.response(method: "POST", uri: "/noctweb/")?.statusCode,
            405
        )
        XCTAssertEqual(
            surface.response(method: "GET", uri: "/noctweb/../admin")?.statusCode,
            404
        )
        XCTAssertNil(surface.response(method: "GET", uri: "/relay"))
        XCTAssertNil(surface.response(method: "GET", uri: "/admin/"))
    }

    func testPublisherParentHasExternalAssetsAndStrictCSP() throws {
        let surface = try NoctwebPublisherSurface(
            hostSigningPublicKey: key,
            operatorSuffix: nil
        )
        let page = try XCTUnwrap(surface.response(method: "GET", uri: "/noctweb/"))
        let html = try XCTUnwrap(String(data: page.body, encoding: .utf8))
        XCTAssertEqual(page.statusCode, 200)
        XCTAssertTrue(html.contains(#"href="/noctweb/assets/app.css""#))
        XCTAssertTrue(html.contains(#"src="/noctweb/assets/app.js""#))
        XCTAssertFalse(html.contains("<style"))
        XCTAssertFalse(html.contains("<script>"))
        XCTAssertFalse(html.contains(#"src="http"#))
        XCTAssertFalse(html.contains(#"href="http"#))
        XCTAssertEqual(
            page.headers["Content-Security-Policy"],
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; frame-src blob:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; worker-src 'none'; manifest-src 'none'"
        )
        XCTAssertEqual(page.headers["X-Frame-Options"], "DENY")
    }

    func testPublisherScriptPreservesIdentityHostingAndSandboxBoundaries() throws {
        let surface = try NoctwebPublisherSurface(
            hostSigningPublicKey: key,
            operatorSuffix: nil
        )
        let response = try XCTUnwrap(surface.response(
            method: "GET",
            uri: "/noctweb/assets/app.js"
        ))
        let script = try XCTUnwrap(String(data: response.body, encoding: .utf8))
        let page = try XCTUnwrap(surface.response(method: "GET", uri: "/noctweb/"))
        let html = try XCTUnwrap(String(data: page.body, encoding: .utf8))

        for expected in [
            "indexedDB.open",
            #"generateKey("#,
            #"{ name: "Ed25519" }"#,
            "privateKey.extractable",
            #"fetch("/relay""#,
            #"module: "nw.net-host""#,
            "crypto.getRandomValues",
            "randomBytes(32)",
            "org.noctweave.net/host-release/v1",
            "org.noctweave.net/hosting-receipt/v1",
            "noctweb-hosted-capsule-v1",
            "noctweb-lab-v3",
            "org.noctweave.noctweb/signed-head/v3",
            "org.noctweave.noctweb/head-hash/v1",
            "previousCapsuleObjectID",
            "previousHeadID",
            #"relayRequest("bind""#,
            "verifyNameBinding",
            "Relay returned an invalid signed name binding",
            "Revision hosted, named, and receipt verified",
            "Hosting receipt signature verification failed",
            "Publisher signature verification failed",
            "connect-src 'none'",
            "Unhost this relay copy",
            "Hosted copy unavailable",
            "The publisher workspace remains available",
            "verifyStoredHostingState",
            "receipt and presence verified",
            "verification unavailable",
            "MAX_TRACKED_HOSTED_COPIES",
            "persistHostingLedger",
            "Unhost all copies"
        ] {
            XCTAssertTrue(script.contains(expected), "Missing \(expected)")
        }
        XCTAssertTrue(html.contains(#"sandbox="allow-scripts""#))
        XCTAssertTrue(html.contains("Hosted is not finalized"))
        XCTAssertTrue(html.contains("compiled React compatible"))
        XCTAssertFalse(html.contains(#"name="color-scheme" content="dark""#))
        XCTAssertTrue(html.contains(#"id="appearanceSelect"#))
        XCTAssertTrue(html.contains(#"value="system"#))
        XCTAssertTrue(html.contains(#"value="light"#))
        XCTAssertTrue(html.contains(#"value="dark"#))
        let stylesheet = try XCTUnwrap(surface.response(method: "GET", uri: "/noctweb/assets/app.css"))
        let css = try XCTUnwrap(String(data: stylesheet.body, encoding: .utf8))
        XCTAssertTrue(css.contains("--shell-accent: #c96a61"))
        XCTAssertTrue(css.contains("--shell-accent-strong: #922d35"))
        XCTAssertTrue(css.contains("brand-mark { background: linear-gradient(145deg, #c96a61, #922d35)"))
        XCTAssertFalse(script.contains("allow-same-origin"))
        XCTAssertTrue(script.contains("noctweave.publisher.appearance"))
        XCTAssertTrue(script.contains("localStorage"))
        XCTAssertFalse(script.contains("sessionStorage"))
        XCTAssertFalse(script.contains("cdn."))
        XCTAssertFalse(script.contains("Finalized"))
        XCTAssertFalse(script.contains("authToken: password"))
        XCTAssertFalse(script.contains(#"const PROFILE = "noctweb-publisher-v1""#))
        XCTAssertFalse(script.contains("org.noctweave.noctweb/publisher-bundle/v1"))
    }

    func testPublisherShellThemeDoesNotOwnGeneratedWebsiteAccentOrContent() throws {
        let surface = try NoctwebPublisherSurface(
            hostSigningPublicKey: key,
            operatorSuffix: nil
        )
        let response = try XCTUnwrap(surface.response(method: "GET", uri: "/noctweb/assets/app.js"))
        let script = try XCTUnwrap(String(data: response.body, encoding: .utf8))
        XCTAssertTrue(script.contains("${project.accent}"))
        XCTAssertTrue(script.contains("${title}"))
        XCTAssertTrue(script.contains("${body}"))
        XCTAssertTrue(script.contains("background: ${project.accent}"))
        XCTAssertFalse(script.contains("var(--shell-accent)"))
    }

    func testPublisherRequiresLoopbackOrExplicitTrustedProxyTLS() {
        XCTAssertTrue(noctwebPublisherTransportIsPermitted(
            directSource: "127.0.0.1",
            trustedReverseProxyTLS: false
        ))
        XCTAssertTrue(noctwebPublisherTransportIsPermitted(
            directSource: "::1",
            trustedReverseProxyTLS: false
        ))
        XCTAssertFalse(noctwebPublisherTransportIsPermitted(
            directSource: "203.0.113.10",
            trustedReverseProxyTLS: false
        ))
        XCTAssertTrue(noctwebPublisherTransportIsPermitted(
            directSource: "203.0.113.10",
            trustedReverseProxyTLS: true
        ))
        XCTAssertTrue(noctwebPublisherTransportIsPermitted(
            directSource: "172.17.0.1",
            trustedReverseProxyTLS: false,
            trustedLocalContainerBridge: true
        ))
    }
}
