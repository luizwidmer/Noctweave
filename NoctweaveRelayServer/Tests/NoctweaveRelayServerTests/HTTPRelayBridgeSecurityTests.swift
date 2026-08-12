import XCTest
@preconcurrency import NIOHTTP1
@testable import NoctweaveRelayServer

final class HTTPRelayBridgeSecurityTests: XCTestCase {
    func testRelayRequiresExactlyOneJSONContentType() {
        XCTAssertTrue(relayRequestHasJSONContentType(headers([
            ("Content-Type", "application/json; charset=utf-8")
        ])))
        XCTAssertFalse(relayRequestHasJSONContentType(headers([])))
        XCTAssertFalse(relayRequestHasJSONContentType(headers([
            ("Content-Type", "text/plain")
        ])))
        XCTAssertFalse(relayRequestHasJSONContentType(headers([
            ("Content-Type", "application/json"),
            ("Content-Type", "text/plain")
        ])))
    }

    func testLoopbackBrowserRequestsMustBeSameOriginAndLoopbackNamed() {
        XCTAssertTrue(relayBrowserOriginIsPermitted(
            headers: headers([
                ("Host", "127.0.0.1:9340"),
                ("Origin", "http://127.0.0.1:9340")
            ]),
            directSource: "127.0.0.1",
            trustedReverseProxyTLS: false
        ))
        XCTAssertFalse(relayBrowserOriginIsPermitted(
            headers: headers([
                ("Host", "127.0.0.1:9340"),
                ("Origin", "https://attacker.example")
            ]),
            directSource: "127.0.0.1",
            trustedReverseProxyTLS: false
        ))
        XCTAssertFalse(relayBrowserOriginIsPermitted(
            headers: headers([
                ("Host", "rebound.attacker.example:9340"),
                ("Origin", "http://rebound.attacker.example:9340")
            ]),
            directSource: "127.0.0.1",
            trustedReverseProxyTLS: false
        ))
        XCTAssertFalse(relayBrowserOriginIsPermitted(
            headers: headers([
                ("Host", "127.0.0.1:9340"),
                ("Origin", "null")
            ]),
            directSource: "127.0.0.1",
            trustedReverseProxyTLS: false
        ))
    }

    func testTrustedTLSProxyRequiresHTTPSSameOrigin() {
        XCTAssertTrue(relayBrowserOriginIsPermitted(
            headers: headers([
                ("Host", "relay.example"),
                ("Origin", "https://relay.example")
            ]),
            directSource: "172.17.0.1",
            trustedReverseProxyTLS: true
        ))
        XCTAssertFalse(relayBrowserOriginIsPermitted(
            headers: headers([
                ("Host", "relay.example"),
                ("Origin", "http://relay.example")
            ]),
            directSource: "172.17.0.1",
            trustedReverseProxyTLS: true
        ))
    }

    func testNonBrowserClientsRemainSupportedButCrossSiteMetadataFailsClosed() {
        XCTAssertTrue(relayBrowserOriginIsPermitted(
            headers: headers([("Host", "127.0.0.1:9340")]),
            directSource: "127.0.0.1",
            trustedReverseProxyTLS: false
        ))
        XCTAssertFalse(relayBrowserOriginIsPermitted(
            headers: headers([
                ("Host", "127.0.0.1:9340"),
                ("Sec-Fetch-Site", "cross-site")
            ]),
            directSource: "127.0.0.1",
            trustedReverseProxyTLS: false
        ))
    }

    private func headers(_ fields: [(String, String)]) -> HTTPHeaders {
        var headers = HTTPHeaders()
        for (name, value) in fields {
            headers.add(name: name, value: value)
        }
        return headers
    }
}
