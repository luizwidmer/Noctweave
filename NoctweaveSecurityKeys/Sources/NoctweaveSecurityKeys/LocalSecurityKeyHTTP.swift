// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

/// A single-request HTTP/1.1 parser for the short-lived loopback ceremony.
/// Rejects ambiguous framing, duplicate headers, and pipelining.
struct LocalSecurityKeyHTTP {
    static let maximumHeaders = 8_192
    static let maximumBody = 131_072

    let method: String
    let target: String
    let headers: [String: String]
    let body: Data

    static func parse(_ data: Data) throws -> Self? {
        guard data.count <= maximumHeaders + maximumBody else { throw SecurityKeyError.invalidResponse }
        guard let split = data.range(of: Data("\r\n\r\n".utf8)) else {
            guard data.count <= maximumHeaders else { throw SecurityKeyError.invalidResponse }
            return nil
        }
        guard split.upperBound <= maximumHeaders,
              let text = String(data: data[..<split.lowerBound], encoding: .utf8),
              text.utf8.allSatisfy({ $0 == 13 || $0 == 10 || (32...126).contains($0) }) else {
            throw SecurityKeyError.invalidResponse
        }
        let lines = text.components(separatedBy: "\r\n")
        let first = (lines.first ?? "").components(separatedBy: " ")
        guard first.count == 3, ["GET", "POST"].contains(first[0]), first[2] == "HTTP/1.1",
              first[1].hasPrefix("/"), first[1].utf8.count <= 256 else { throw SecurityKeyError.invalidResponse }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { throw SecurityKeyError.invalidResponse }
            let name = String(line[..<colon]).lowercased()
            guard !name.isEmpty, name.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }),
                  headers[name] == nil else { throw SecurityKeyError.invalidResponse }
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard !value.contains("\r"), !value.contains("\n") else { throw SecurityKeyError.invalidResponse }
            headers[name] = value
        }
        guard headers["transfer-encoding"] == nil, headers["content-encoding"] == nil,
              headers["expect"] == nil, headers["host"] != nil else { throw SecurityKeyError.invalidResponse }
        let length: Int
        if let value = headers["content-length"] {
            guard !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }),
                  let count = Int(value), count <= maximumBody else { throw SecurityKeyError.invalidResponse }
            length = count
        } else {
            guard first[0] == "GET" else { throw SecurityKeyError.invalidResponse }
            length = 0
        }
        guard first[0] != "GET" || length == 0 else { throw SecurityKeyError.invalidResponse }
        let body = Data(data[split.upperBound...])
        guard body.count <= length else { throw SecurityKeyError.invalidResponse }
        guard body.count == length else { return nil }
        return Self(method: first[0], target: first[1], headers: headers, body: body)
    }

    enum Route { case page, result }
    func route(port: UInt16, token: String) throws -> Route {
        guard port != 0, headers["host"] == "localhost:\(port)" else { throw SecurityKeyError.invalidResponse }
        let origin = "http://localhost:\(port)"
        if let supplied = headers["origin"], supplied != origin { throw SecurityKeyError.invalidResponse }
        if method == "GET", target == "/\(token)" { return .page }
        guard method == "POST", target == "/\(token)/result", headers["origin"] == origin,
              headers["content-type"] == "application/json", !body.isEmpty,
              headers["sec-fetch-site"] == nil || headers["sec-fetch-site"] == "same-origin" else {
            throw SecurityKeyError.invalidResponse
        }
        return .result
    }

    static func response(status: String, body: Data, contentType: String, nonce: String) -> Data {
        let headers = [
            "HTTP/1.1 \(status)", "Content-Type: \(contentType)", "Content-Length: \(body.count)",
            "Connection: close", "Cache-Control: no-store", "Pragma: no-cache",
            "X-Content-Type-Options: nosniff", "Referrer-Policy: no-referrer", "X-Frame-Options: DENY",
            "Content-Security-Policy: default-src 'none'; img-src data:; script-src 'nonce-\(nonce)'; style-src 'nonce-\(nonce)'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            "Permissions-Policy: publickey-credentials-create=(self), publickey-credentials-get=(self)"
        ].joined(separator: "\r\n") + "\r\n\r\n"
        return Data(headers.utf8) + body
    }
}
