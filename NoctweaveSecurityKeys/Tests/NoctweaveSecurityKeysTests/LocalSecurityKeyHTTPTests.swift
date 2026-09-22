// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import XCTest
@testable import NoctweaveSecurityKeys

final class LocalSecurityKeyHTTPTests: XCTestCase {
    func testEachPageUsesItsAppBrandAndCallbackWithNoExternalResources() throws {
        for app in LocalSecurityKeyApp.allCases {
            let data = LocalSecurityKeyPage.html(options: Data("{}".utf8), registration: true, token: "session", nonce: "nonce", app: app)
            let page = try XCTUnwrap(String(data: data, encoding: .utf8))
            XCTAssertTrue(page.contains(app.name))
            XCTAssertTrue(page.contains(app.callbackScheme + "://complete/"))
            for other in LocalSecurityKeyApp.allCases where other != app {
                XCTAssertFalse(page.contains(other.callbackScheme))
            }
            XCTAssertFalse(page.contains("https://"))
            XCTAssertFalse(page.contains("http://"))
            XCTAssertTrue(page.contains("navigator.credentials[ceremony]"))
        }
    }

    private let port: UInt16 = 49_152
    private let token = "random-session-token"

    private func request(_ method: String = "GET", target: String? = nil, headers: String = "", body: String = "") -> Data {
        Data("\(method) \(target ?? "/\(token)") HTTP/1.1\r\nHost: localhost:\(port)\r\n\(headers)\r\n\(body)".utf8)
    }

    func testFragmentedRequestAndCorrectPageRoute() throws {
        let bytes = request()
        for count in 0..<bytes.count { XCTAssertNil(try LocalSecurityKeyHTTP.parse(Data(bytes.prefix(count)))) }
        let parsed = try XCTUnwrap(LocalSecurityKeyHTTP.parse(bytes))
        guard case .page = try parsed.route(port: port, token: token) else { return XCTFail("Wrong route") }
    }

    func testRejectsAmbiguousFramingAndBoundedInput() {
        for headers in ["Host: other\r\n", "Content-Length: 0\r\nContent-Length: 0\r\n", "Transfer-Encoding: chunked\r\n",
                        "Content-Length: -1\r\n", "Content-Length: 999999999999999999999\r\n", "Content-Length: 131073\r\n",
                        "Content-Encoding: gzip\r\n", "Expect: 100-continue\r\n", " X-Folded: test\r\n", "X-Header: one\nInjected: two\r\n"] {
            XCTAssertThrowsError(try LocalSecurityKeyHTTP.parse(request(headers: headers)))
        }
        XCTAssertThrowsError(try LocalSecurityKeyHTTP.parse(request(body: "extra")))
        XCTAssertThrowsError(try LocalSecurityKeyHTTP.parse(request() + request()))
        XCTAssertThrowsError(try LocalSecurityKeyHTTP.parse(Data(repeating: 65, count: 8_193)))
        XCTAssertThrowsError(try LocalSecurityKeyHTTP.parse(request(headers: "X-Header: \(String(repeating: "a", count: 8_192))\r\n")))
    }

    func testResultRequiresExactHostOriginTokenAndContentType() throws {
        let headers = "Origin: http://localhost:\(port)\r\nContent-Type: application/json\r\nContent-Length: 2\r\n"
        let data = request("POST", target: "/\(token)/result", headers: headers, body: "{}")
        let parsed = try XCTUnwrap(LocalSecurityKeyHTTP.parse(data))
        guard case .result = try parsed.route(port: port, token: token) else { return XCTFail("Wrong route") }
        XCTAssertEqual(parsed.body, Data("{}".utf8))
        let text = try XCTUnwrap(String(data: data, encoding: .utf8))
        for bad in [
            text.replacingOccurrences(of: "Host: localhost:\(port)", with: "Host: 127.0.0.1:\(port)"),
            text.replacingOccurrences(of: "Origin: http://localhost:\(port)", with: "Origin: https://outside.test"),
            text.replacingOccurrences(of: "Origin: http://localhost:\(port)\r\n", with: ""),
            text.replacingOccurrences(of: "application/json", with: "text/plain"),
            text.replacingOccurrences(of: "/\(token)/result", with: "/wrong/result"),
            text.replacingOccurrences(of: "/\(token)/result", with: "/\(token)/result?ignored=1"),
            text.replacingOccurrences(of: "Content-Type:", with: "Sec-Fetch-Site: cross-site\r\nContent-Type:")
        ] {
            XCTAssertThrowsError(try XCTUnwrap(LocalSecurityKeyHTTP.parse(Data(bad.utf8))).route(port: port, token: token))
        }
        XCTAssertThrowsError(try parsed.route(port: port + 1, token: token))
    }

    @MainActor
    func testLoopbackServesOneResultRejectsForgeryAndCloses() async throws {
        let server = try LocalSecurityKeyServer(options: Data("{}".utf8), registration: false)
        let port = try await server.start()
        defer { server.close() }
        let base = "http://localhost:\(port)"
        let url = try XCTUnwrap(URL(string: base + "/" + server.token))
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 2
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let (page, response) = try await session.data(from: url)
        let http = try XCTUnwrap(response as? HTTPURLResponse)
        XCTAssertEqual(http.statusCode, 200)
        XCTAssertEqual(http.value(forHTTPHeaderField: "Cache-Control"), "no-store")
        XCTAssertTrue(http.value(forHTTPHeaderField: "Content-Security-Policy")?.contains("default-src 'none'") == true)
        XCTAssertTrue(String(data: page, encoding: .utf8)?.contains("navigator.credentials[ceremony]") == true)
        var post = URLRequest(url: url.appendingPathComponent("result"))
        post.httpMethod = "POST"
        post.httpBody = Data("{\"test\":true}".utf8)
        post.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (_, rejected) = try await session.data(for: post)
        XCTAssertEqual((rejected as? HTTPURLResponse)?.statusCode, 400)
        XCTAssertNil(server.result)
        post.setValue(base, forHTTPHeaderField: "Origin")
        let (_, accepted) = try await session.data(for: post)
        XCTAssertEqual((accepted as? HTTPURLResponse)?.statusCode, 200)
        XCTAssertEqual(server.result, post.httpBody)
        let (_, replay) = try await session.data(for: post)
        XCTAssertEqual((replay as? HTTPURLResponse)?.statusCode, 409)
        server.close()
        XCTAssertNil(server.result)
        do { _ = try await session.data(from: url); XCTFail("Closed listener still accepted a request") } catch {}
        do { _ = try await server.start(); XCTFail("A ceremony was reused") } catch {}
    }
}
