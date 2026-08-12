import XCTest
@preconcurrency import NIOCore
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

    func testForwardedSourceHeadersRequireExplicitTrustAndNoAmbiguity() throws {
        let loopback = try SocketAddress(ipAddress: "127.0.0.1", port: 9_340)
        let containerProxy = try SocketAddress(ipAddress: "172.17.0.2", port: 9_340)
        let spoofed = headers([
            ("CF-Connecting-IP", "203.0.113.7"),
            ("X-Forwarded-For", "203.0.113.7, 127.0.0.1")
        ])
        XCTAssertEqual(
            relayHTTPSourceKey(address: loopback, headers: spoofed),
            "127.0.0.1"
        )
        XCTAssertEqual(
            relayHTTPSourceKey(
                address: loopback,
                headers: spoofed,
                trustForwardedHeaders: true
            ),
            "203.0.113.7"
        )
        XCTAssertEqual(
            relayHTTPSourceKey(address: containerProxy, headers: spoofed),
            "172.17.0.2"
        )
        XCTAssertEqual(
            relayHTTPSourceKey(
                address: containerProxy,
                headers: spoofed,
                trustForwardedHeaders: true
            ),
            "203.0.113.7"
        )

        XCTAssertEqual(
            relayHTTPSourceKey(
                address: loopback,
                headers: headers([
                    ("CF-Connecting-IP", "203.0.113.7"),
                    ("X-Forwarded-For", "198.51.100.9")
                ]),
                trustForwardedHeaders: true
            ),
            "127.0.0.1"
        )
        XCTAssertEqual(
            relayHTTPSourceKey(
                address: loopback,
                headers: headers([
                    ("CF-Connecting-IP", "203.0.113.7"),
                    ("CF-Connecting-IP", "198.51.100.9")
                ]),
                trustForwardedHeaders: true
            ),
            "127.0.0.1"
        )
        XCTAssertEqual(
            relayHTTPSourceKey(
                address: containerProxy,
                headers: headers([
                    ("X-Forwarded-For", "203.0.113.7"),
                    ("X-Forwarded-For", "198.51.100.9")
                ]),
                trustForwardedHeaders: true
            ),
            "172.17.0.2"
        )
    }

    private func headers(_ fields: [(String, String)]) -> HTTPHeaders {
        var headers = HTTPHeaders()
        for (name, value) in fields {
            headers.add(name: name, value: value)
        }
        return headers
    }
}
