import XCTest
@testable import NoctweaveCore

final class RelayEndpointParserTests: XCTestCase {
    func testParsesHTTPSWithoutExplicitPort() throws {
        let endpoint = try RelayEndpointParser.parse("https://relay.example")

        XCTAssertEqual(endpoint.host, "relay.example")
        XCTAssertEqual(endpoint.port, 443)
        XCTAssertTrue(endpoint.useTLS)
        XCTAssertEqual(endpoint.transport, .http)
    }

    func testParsesHTTPWithExplicitPort() throws {
        let endpoint = try RelayEndpointParser.parse("http://127.0.0.1:9339")

        XCTAssertEqual(endpoint.host, "127.0.0.1")
        XCTAssertEqual(endpoint.port, 9339)
        XCTAssertFalse(endpoint.useTLS)
        XCTAssertEqual(endpoint.transport, .http)
    }

    func testParsesWebSocketSchemes() throws {
        let ws = try RelayEndpointParser.parse("ws://relay.local:8080")
        let wss = try RelayEndpointParser.parse("wss://relay.example")

        XCTAssertEqual(ws.transport, .websocket)
        XCTAssertFalse(ws.useTLS)
        XCTAssertEqual(ws.port, 8080)
        XCTAssertEqual(wss.transport, .websocket)
        XCTAssertTrue(wss.useTLS)
        XCTAssertEqual(wss.port, 443)
    }

    func testParsesBareHostPortAndBareHost() throws {
        let hostPort = try RelayEndpointParser.parse("relay.local:9339")
        let hostOnly = try RelayEndpointParser.parse("relay.local")

        XCTAssertEqual(hostPort.host, "relay.local")
        XCTAssertEqual(hostPort.port, 9339)
        XCTAssertEqual(hostPort.transport, .tcp)
        XCTAssertEqual(hostOnly.host, "relay.local")
        XCTAssertEqual(hostOnly.port, 9339)
        XCTAssertEqual(hostOnly.transport, .tcp)
    }

    func testParsesBracketedIPv6() throws {
        let endpoint = try RelayEndpointParser.parse("[::1]:9339")

        XCTAssertEqual(endpoint.host, "::1")
        XCTAssertEqual(endpoint.port, 9339)
        XCTAssertEqual(endpoint.transport, .tcp)
    }

    func testRejectsInvalidPort() {
        XCTAssertThrowsError(try RelayEndpointParser.parse("relay.local:notaport")) { error in
            XCTAssertEqual(error as? RelayEndpointParserError, .invalidPort("notaport"))
        }
        XCTAssertThrowsError(try RelayEndpointParser.parse("relay.local:0")) { error in
            XCTAssertEqual(error as? RelayEndpointParserError, .invalidPort("0"))
        }
    }

    func testRejectsUnknownURLSchemeInsteadOfDowngradingToTCP() {
        XCTAssertThrowsError(try RelayEndpointParser.parse("htps://relay.example")) { error in
            XCTAssertEqual(error as? RelayEndpointParserError, .unsupportedScheme("htps"))
        }
    }

    func testRejectsURLSecretsAndRequestComponents() {
        XCTAssertThrowsError(try RelayEndpointParser.parse("https://user:pass@relay.example")) { error in
            XCTAssertEqual(error as? RelayEndpointParserError, .unsupportedURLComponent("user info"))
        }
        XCTAssertThrowsError(try RelayEndpointParser.parse("https://relay.example?token=secret")) { error in
            XCTAssertEqual(error as? RelayEndpointParserError, .unsupportedURLComponent("query parameters"))
        }
        XCTAssertThrowsError(try RelayEndpointParser.parse("https://relay.example#secret")) { error in
            XCTAssertEqual(error as? RelayEndpointParserError, .unsupportedURLComponent("fragments"))
        }
        XCTAssertThrowsError(try RelayEndpointParser.parse("https://relay.example/custom/relay")) { error in
            XCTAssertEqual(error as? RelayEndpointParserError, .unsupportedURLComponent("paths"))
        }
    }

    func testRejectsMalformedBareHosts() {
        XCTAssertThrowsError(try RelayEndpointParser.parse("relay host"))
        XCTAssertThrowsError(try RelayEndpointParser.parse("relay.example/path"))
        XCTAssertThrowsError(try RelayEndpointParser.parse("::1"))
    }
}
