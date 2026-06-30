import Foundation
import Network
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Security)
import Security
#endif

public struct RelayClient {
    public let endpoint: RelayEndpoint
    public let authToken: String?
    public static let maxResponseBytes = 1_000_000
    public static let defaultTimeout: TimeInterval = 8

    public init(endpoint: RelayEndpoint, authToken: String? = nil) {
        self.endpoint = endpoint
        self.authToken = authToken
    }

    public func send(_ request: RelayRequest, timeout: TimeInterval = defaultTimeout) async throws -> RelayResponse {
        let effectiveAuthToken = authToken ?? request.authToken
        let authenticatedRequest = request.withAuthToken(effectiveAuthToken)
        switch endpoint.transport {
        case .tcp:
            return try await sendTCP(authenticatedRequest, timeout: timeout)
        case .http:
            do {
                return try await sendHTTP(authenticatedRequest, timeout: timeout)
            } catch {
                return try await sendTCP(authenticatedRequest, timeout: timeout)
            }
        case .websocket:
            do {
                return try await sendWebSocket(authenticatedRequest, timeout: timeout)
            } catch {
                do {
                    return try await sendHTTP(authenticatedRequest, timeout: timeout)
                } catch {
                    return try await sendTCP(authenticatedRequest, timeout: timeout)
                }
            }
        }
    }

    private func sendTCP(_ request: RelayRequest, timeout: TimeInterval) async throws -> RelayResponse {
        guard let port = NWEndpoint.Port(rawValue: endpoint.port) else {
            throw RelayNetworkError.connectionFailed
        }
        let parameters = RelayNetworkTransport.clientParameters(for: endpoint)
        let connection = NWConnection(host: NWEndpoint.Host(endpoint.host), port: port, using: parameters)
        defer { connection.cancel() }
        return try await withTimeout(seconds: timeout) {
            try await connection.awaitReady()
            let data = try NoctweaveCoder.encode(request)
            try await connection.sendLine(data)
            let responseData = try await connection.receiveLine(maxLength: Self.maxResponseBytes)
            return try NoctweaveCoder.decode(RelayResponse.self, from: responseData)
        }
    }

    private func sendHTTP(_ request: RelayRequest, timeout: TimeInterval) async throws -> RelayResponse {
        guard var components = URLComponents(string: "/") else {
            throw RelayNetworkError.invalidResponse
        }
        components.scheme = endpoint.useTLS ? "https" : "http"
        components.host = endpoint.host
        let defaultPort: UInt16 = endpoint.useTLS ? 443 : 80
        components.port = endpoint.port == defaultPort ? nil : Int(endpoint.port)
        components.path = "/relay"
        guard let url = components.url else {
            throw RelayNetworkError.invalidResponse
        }

        var mutableRequest = URLRequest(url: url)
        mutableRequest.httpMethod = "POST"
        mutableRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        mutableRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        mutableRequest.httpBody = try NoctweaveCoder.encode(request)
        let httpRequest = mutableRequest

        return try await withTimeout(seconds: timeout) {
            do {
                let session = makeURLSession()
                defer { session.invalidateAndCancel() }
                let (data, response) = try await session.data(for: httpRequest)
                guard data.count <= Self.maxResponseBytes else {
                    throw RelayNetworkError.invalidResponse
                }
                guard let httpResponse = response as? HTTPURLResponse else {
                    throw RelayClientResponseError.invalidHTTPResponse
                }
                guard (200...299).contains(httpResponse.statusCode) else {
                    throw Self.makeHTTPStatusError(response: httpResponse, data: data)
                }
                return try Self.decodeRelayResponse(data, for: request.type)
            } catch {
                // Compatibility path for HTTP reverse-proxied relays exposing only GET /health.
                if request.type == .health {
                    return try await sendHTTPHealthProbe()
                }
                throw error
            }
        }
    }

    private func sendWebSocket(_ request: RelayRequest, timeout: TimeInterval) async throws -> RelayResponse {
        guard var components = URLComponents(string: "/") else {
            throw RelayNetworkError.invalidResponse
        }
        components.scheme = endpoint.useTLS ? "wss" : "ws"
        components.host = endpoint.host
        let defaultPort: UInt16 = endpoint.useTLS ? 443 : 80
        components.port = endpoint.port == defaultPort ? nil : Int(endpoint.port)
        components.path = "/relay"
        guard let url = components.url else {
            throw RelayNetworkError.invalidResponse
        }

        let session = makeURLSession()
        let task = session.webSocketTask(with: url)
        task.resume()
        defer {
            task.cancel(with: URLSessionWebSocketTask.CloseCode.normalClosure, reason: nil)
            session.invalidateAndCancel()
        }

        return try await withTimeout(seconds: timeout) {
            let data = try NoctweaveCoder.encode(request)
            try await task.send(URLSessionWebSocketTask.Message.data(data))
            let message = try await task.receive()
            let responseData: Data
            switch message {
            case .data(let payload):
                responseData = payload
            case .string(let text):
                responseData = Data(text.utf8)
            @unknown default:
                throw RelayNetworkError.invalidResponse
            }
            guard responseData.count <= Self.maxResponseBytes else {
                throw RelayNetworkError.invalidResponse
            }
            return try Self.decodeRelayResponse(responseData, for: request.type)
        }
    }

    private func sendHTTPHealthProbe() async throws -> RelayResponse {
        guard var components = URLComponents(string: "/") else {
            throw RelayNetworkError.invalidResponse
        }
        components.scheme = endpoint.useTLS ? "https" : "http"
        components.host = endpoint.host
        let defaultPort: UInt16 = endpoint.useTLS ? 443 : 80
        components.port = endpoint.port == defaultPort ? nil : Int(endpoint.port)
        components.path = "/health"
        guard let url = components.url else {
            throw RelayNetworkError.invalidResponse
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json, text/plain;q=0.9", forHTTPHeaderField: "Accept")
        let session = makeURLSession()
        defer { session.invalidateAndCancel() }
        let (data, response) = try await session.data(for: request)
        guard data.count <= Self.maxResponseBytes else {
            throw RelayNetworkError.invalidResponse
        }
        guard let httpResponse = response as? HTTPURLResponse else {
            throw RelayClientResponseError.invalidHTTPResponse
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw Self.makeHTTPStatusError(response: httpResponse, data: data)
        }
        return try Self.decodeRelayResponse(data, for: .health)
    }

    private static func decodeRelayResponse(_ data: Data, for type: RelayRequestType) throws -> RelayResponse {
        if let decoded = try? NoctweaveCoder.decode(RelayResponse.self, from: data) {
            return decoded
        }
        if type == .health, isHealthyPayload(data) {
            return .ok()
        }
        throw RelayClientResponseError.invalidPayload(
            details: "Relay returned unexpected response payload: \(responsePreview(data))"
        )
    }

    private static func isHealthyPayload(_ data: Data) -> Bool {
        let text = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() ?? ""
        if text == "ok" || text == "healthy" || text == "up" || text == "\"ok\"" {
            return true
        }
        struct BasicHealthPayload: Decodable {
            let ok: Bool?
            let healthy: Bool?
            let status: String?
        }
        if let payload = try? JSONDecoder().decode(BasicHealthPayload.self, from: data) {
            if payload.ok == true || payload.healthy == true {
                return true
            }
            if let status = payload.status?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
               status == "ok" || status == "healthy" || status == "up" {
                return true
            }
        }
        return false
    }

    private static func responsePreview(_ data: Data) -> String {
        guard !data.isEmpty else {
            return "<empty>"
        }
        let text = String(data: data, encoding: .utf8) ?? "<binary \(data.count) bytes>"
        let compact = text.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " ")
        if compact.count <= 160 {
            return compact
        }
        let index = compact.index(compact.startIndex, offsetBy: 160)
        return String(compact[..<index]) + "..."
    }

    private static func makeHTTPStatusError(response: HTTPURLResponse, data: Data) -> RelayClientResponseError {
        let preview = responsePreview(data)
        let serverHeader = response.value(forHTTPHeaderField: "Server")?.lowercased() ?? ""
        let isCloudflare = serverHeader.contains("cloudflare") || preview.lowercased().contains("error code: 1010")
        if isCloudflare && response.statusCode == 403 {
            return .cloudflareBlocked(
                details: "Cloudflare blocked relay traffic (HTTP 403 / code 1010). Disable WAF/challenge/bot protections for /relay, /health, and /info on this relay domain."
            )
        }
        return .badHTTPStatus(code: response.statusCode, bodyPreview: preview)
    }

    private func makeURLSession() -> URLSession {
        let delegate = endpoint.tlsCertificateFingerprintSHA256.map {
            RelayPinnedSessionDelegate(expectedLeafCertificateSHA256: $0)
        }
        return URLSession(
            configuration: .ephemeral,
            delegate: delegate,
            delegateQueue: nil
        )
    }
}

private struct RelayTimeoutError: LocalizedError {
    var errorDescription: String? { "Relay request timed out." }
}

private enum RelayClientResponseError: LocalizedError {
    case invalidHTTPResponse
    case badHTTPStatus(code: Int, bodyPreview: String)
    case invalidPayload(details: String)
    case cloudflareBlocked(details: String)

    var errorDescription: String? {
        switch self {
        case .invalidHTTPResponse:
            return "Relay returned an invalid HTTP response."
        case .badHTTPStatus(let code, let bodyPreview):
            return "Relay returned HTTP \(code): \(bodyPreview)"
        case .invalidPayload(let details):
            return details
        case .cloudflareBlocked(let details):
            return details
        }
    }
}

private func withTimeout<T>(
    seconds: TimeInterval,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    let duration = max(0, seconds)
    let nanos = UInt64(duration * 1_000_000_000)
    return try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask {
            try await operation()
        }
        group.addTask {
            try await Task.sleep(nanoseconds: nanos)
            throw RelayTimeoutError()
        }
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}

#if canImport(Security) && canImport(CryptoKit)
private final class RelayPinnedSessionDelegate: NSObject, URLSessionDelegate {
    private let expectedLeafCertificateSHA256: Data

    init(expectedLeafCertificateSHA256: Data) {
        self.expectedLeafCertificateSHA256 = expectedLeafCertificateSHA256
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error),
              RelayTLSVerifier.trustMatchesLeafCertificateSHA256(trust, expectedFingerprint: expectedLeafCertificateSHA256) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}
#endif
