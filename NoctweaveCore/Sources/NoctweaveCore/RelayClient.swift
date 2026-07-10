import Foundation
import Network
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Security)
import Security
#endif

public struct RelayTLSObservation {
    public let response: RelayResponse
    public let leafCertificateSHA256: Data?

    public init(response: RelayResponse, leafCertificateSHA256: Data?) {
        self.response = response
        self.leafCertificateSHA256 = leafCertificateSHA256
    }
}

public enum RelayClientPolicyError: Error, Equatable, Sendable {
    case invalidMaximumResponseBytes
    case invalidMaximumRequestBytes
    case invalidTimeout
}

/// Deployment-tunable relay client resource policy. The public absolute limits
/// remain fixed safety ceilings so an operator cannot accidentally configure
/// unbounded allocations or request durations.
public struct RelayClientPolicy: Equatable, Sendable {
    public static let defaultMaximumResponseBytes = 1_000_000
    public static let defaultMaximumRequestBytes = 512 * 1_024
    public static let defaultTimeout: TimeInterval = 8

    public static let absoluteMaximumResponseBytes = 16 * 1_024 * 1_024
    public static let absoluteMaximumRequestBytes = 8 * 1_024 * 1_024
    public static let absoluteMaximumTimeout: TimeInterval = 300

    public static let `default` = RelayClientPolicy(
        validatedMaximumResponseBytes: defaultMaximumResponseBytes,
        validatedMaximumRequestBytes: defaultMaximumRequestBytes,
        validatedTimeout: defaultTimeout
    )

    public let maximumResponseBytes: Int
    public let maximumRequestBytes: Int
    public let timeout: TimeInterval

    public init(
        maximumResponseBytes: Int = defaultMaximumResponseBytes,
        maximumRequestBytes: Int = defaultMaximumRequestBytes,
        timeout: TimeInterval = defaultTimeout
    ) throws {
        guard (1_024...Self.absoluteMaximumResponseBytes).contains(maximumResponseBytes) else {
            throw RelayClientPolicyError.invalidMaximumResponseBytes
        }
        guard (1_024...Self.absoluteMaximumRequestBytes).contains(maximumRequestBytes) else {
            throw RelayClientPolicyError.invalidMaximumRequestBytes
        }
        guard timeout.isFinite, timeout >= 0.1, timeout <= Self.absoluteMaximumTimeout else {
            throw RelayClientPolicyError.invalidTimeout
        }
        self.init(
            validatedMaximumResponseBytes: maximumResponseBytes,
            validatedMaximumRequestBytes: maximumRequestBytes,
            validatedTimeout: timeout
        )
    }

    private init(
        validatedMaximumResponseBytes: Int,
        validatedMaximumRequestBytes: Int,
        validatedTimeout: TimeInterval
    ) {
        maximumResponseBytes = validatedMaximumResponseBytes
        maximumRequestBytes = validatedMaximumRequestBytes
        timeout = validatedTimeout
    }
}

public struct RelayClient {
    public let endpoint: RelayEndpoint
    public let authToken: String?
    public let policy: RelayClientPolicy
    public static let maxResponseBytes = RelayClientPolicy.defaultMaximumResponseBytes
    public static let maxRequestBytes = RelayClientPolicy.defaultMaximumRequestBytes
    public static let maxAuthenticationBytes = 4_096
    public static let defaultTimeout = RelayClientPolicy.defaultTimeout

    public init(
        endpoint: RelayEndpoint,
        authToken: String? = nil,
        policy: RelayClientPolicy = .default
    ) {
        self.endpoint = endpoint
        self.authToken = authToken
        self.policy = policy
    }

    public func send(_ request: RelayRequest, timeout: TimeInterval? = nil) async throws -> RelayResponse {
        try await sendInternal(request, timeout: timeout ?? policy.timeout, observedLeafCertificateSHA256: nil)
    }

    /// Sends a normal relay request while returning the system-trusted TLS leaf fingerprint.
    /// The observation is produced only when the full relay request succeeds; plaintext
    /// transports return `nil`.
    public func sendObservingTLS(
        _ request: RelayRequest,
        timeout: TimeInterval? = nil
    ) async throws -> RelayTLSObservation {
        let observation = RelayTLSObservationBox()
        let observer: @Sendable (Data) -> Void = { fingerprint in
            observation.record(fingerprint)
        }
        let response = try await sendInternal(
            request,
            timeout: timeout ?? policy.timeout,
            observedLeafCertificateSHA256: endpoint.useTLS ? observer : nil
        )
        return RelayTLSObservation(
            response: response,
            leafCertificateSHA256: observation.value
        )
    }

    private func sendInternal(
        _ request: RelayRequest,
        timeout: TimeInterval,
        observedLeafCertificateSHA256: (@Sendable (Data) -> Void)?
    ) async throws -> RelayResponse {
        guard timeout.isFinite, timeout >= 0.1, timeout <= 300 else {
            throw RelayNetworkError.invalidTimeout
        }
        guard endpoint.port > 0,
              !endpoint.host.isEmpty,
              endpoint.tlsCertificateFingerprintSHA256.map({ $0.count == 32 }) ?? true else {
            throw RelayNetworkError.invalidResponse
        }
        let effectiveAuthToken = authToken ?? request.authToken
        guard effectiveAuthToken.map({ $0.utf8.count <= Self.maxAuthenticationBytes }) ?? true else {
            throw RelayNetworkError.invalidAuthentication
        }
        let authenticatedRequest = request.withAuthToken(effectiveAuthToken)
        let encodedRequest = try NoctweaveCoder.encode(authenticatedRequest)
        guard encodedRequest.count <= policy.maximumRequestBytes else {
            throw RelayNetworkError.requestTooLarge
        }
        switch endpoint.transport {
        case .tcp:
            return try await sendTCP(
                authenticatedRequest,
                encodedRequest: encodedRequest,
                timeout: timeout,
                observedLeafCertificateSHA256: observedLeafCertificateSHA256
            )
        case .http:
            return try await sendHTTP(
                authenticatedRequest,
                encodedRequest: encodedRequest,
                timeout: timeout,
                observedLeafCertificateSHA256: observedLeafCertificateSHA256
            )
        case .websocket:
            return try await sendWebSocket(
                authenticatedRequest,
                encodedRequest: encodedRequest,
                timeout: timeout,
                observedLeafCertificateSHA256: observedLeafCertificateSHA256
            )
        }
    }

    private func sendTCP(
        _ request: RelayRequest,
        encodedRequest: Data,
        timeout: TimeInterval,
        observedLeafCertificateSHA256: (@Sendable (Data) -> Void)?
    ) async throws -> RelayResponse {
        guard let port = NWEndpoint.Port(rawValue: endpoint.port) else {
            throw RelayNetworkError.connectionFailed
        }
        let parameters = RelayNetworkTransport.clientParameters(
            for: endpoint,
            observedLeafCertificateSHA256: observedLeafCertificateSHA256
        )
        let connection = NWConnection(host: NWEndpoint.Host(endpoint.host), port: port, using: parameters)
        defer { connection.cancel() }
        return try await withTimeout(seconds: timeout) {
            try await connection.awaitReady()
            try await connection.sendLine(encodedRequest)
            let responseData = try await connection.receiveLine(maxLength: policy.maximumResponseBytes)
            return try NoctweaveCoder.decode(RelayResponse.self, from: responseData)
        }
    }

    private func sendHTTP(
        _ request: RelayRequest,
        encodedRequest: Data,
        timeout: TimeInterval,
        observedLeafCertificateSHA256: (@Sendable (Data) -> Void)?
    ) async throws -> RelayResponse {
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
        mutableRequest.httpBody = encodedRequest
        mutableRequest.timeoutInterval = timeout
        let httpRequest = mutableRequest

        return try await withTimeout(seconds: timeout) {
            do {
                let (data, response) = try await BoundedURLSessionLoader.load(
                    httpRequest,
                    maximumBytes: policy.maximumResponseBytes,
                    expectedLeafCertificateSHA256: endpoint.tlsCertificateFingerprintSHA256,
                    observedLeafCertificateSHA256: observedLeafCertificateSHA256
                )
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
                    return try await sendHTTPHealthProbe(
                        observedLeafCertificateSHA256: observedLeafCertificateSHA256
                    )
                }
                throw error
            }
        }
    }

    private func sendWebSocket(
        _ request: RelayRequest,
        encodedRequest: Data,
        timeout: TimeInterval,
        observedLeafCertificateSHA256: (@Sendable (Data) -> Void)?
    ) async throws -> RelayResponse {
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

        let session = makeURLSession(observedLeafCertificateSHA256: observedLeafCertificateSHA256)
        let task = session.webSocketTask(with: url)
        task.resume()
        defer {
            task.cancel(with: URLSessionWebSocketTask.CloseCode.normalClosure, reason: nil)
            session.invalidateAndCancel()
        }

        return try await withTimeout(seconds: timeout) {
            try await task.send(URLSessionWebSocketTask.Message.data(encodedRequest))
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
            guard responseData.count <= policy.maximumResponseBytes else {
                throw RelayNetworkError.invalidResponse
            }
            return try Self.decodeRelayResponse(responseData, for: request.type)
        }
    }

    private func sendHTTPHealthProbe(
        observedLeafCertificateSHA256: (@Sendable (Data) -> Void)?
    ) async throws -> RelayResponse {
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
        let (data, response) = try await BoundedURLSessionLoader.load(
            request,
            maximumBytes: policy.maximumResponseBytes,
            expectedLeafCertificateSHA256: endpoint.tlsCertificateFingerprintSHA256,
            observedLeafCertificateSHA256: observedLeafCertificateSHA256
        )
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
            details: "Relay returned an unexpected response payload (\(data.count) bytes)."
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

    static func responseSummary(_ data: Data) -> String {
        guard !data.isEmpty else {
            return "<empty>"
        }
        guard data.count <= 256 else {
            return "<redacted \(data.count) bytes>"
        }
        let text = String(data: data, encoding: .utf8) ?? "<binary \(data.count) bytes>"
        let compact = text.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " ")
        let lowercased = compact.lowercased()
        if lowercased.contains("cloudflare") || lowercased.contains("error code:") {
            return "<redacted Cloudflare error page, \(data.count) bytes>"
        }
        return "<redacted \(data.count) bytes>"
    }

    private static func makeHTTPStatusError(response: HTTPURLResponse, data: Data) -> RelayClientResponseError {
        let summary = responseSummary(data)
        let serverHeader = response.value(forHTTPHeaderField: "Server")?.lowercased() ?? ""
        let isCloudflare = serverHeader.contains("cloudflare") || summary.contains("Cloudflare")
        if isCloudflare && response.statusCode == 403 {
            return .cloudflareBlocked(
                details: "Cloudflare blocked relay traffic (HTTP 403 / code 1010). Disable WAF/challenge/bot protections for /relay, /health, and /info on this relay domain."
            )
        }
        return .badHTTPStatus(code: response.statusCode, bodySummary: summary)
    }

    private func makeURLSession(
        observedLeafCertificateSHA256: (@Sendable (Data) -> Void)?
    ) -> URLSession {
        let delegate: RelayTLSSessionDelegate? = {
            guard endpoint.tlsCertificateFingerprintSHA256 != nil || observedLeafCertificateSHA256 != nil else {
                return nil
            }
            return RelayTLSSessionDelegate(
                expectedLeafCertificateSHA256: endpoint.tlsCertificateFingerprintSHA256,
                observedLeafCertificateSHA256: observedLeafCertificateSHA256
            )
        }()
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

private final class RelayTLSObservationBox: @unchecked Sendable {
    private let lock = NSLock()
    private var fingerprint: Data?

    func record(_ value: Data) {
        guard value.count == 32 else { return }
        lock.lock()
        if fingerprint == nil {
            fingerprint = value
        }
        lock.unlock()
    }

    var value: Data? {
        lock.lock()
        defer { lock.unlock() }
        return fingerprint
    }
}

private enum RelayClientResponseError: LocalizedError {
    case invalidHTTPResponse
    case badHTTPStatus(code: Int, bodySummary: String)
    case invalidPayload(details: String)
    case cloudflareBlocked(details: String)

    var errorDescription: String? {
        switch self {
        case .invalidHTTPResponse:
            return "Relay returned an invalid HTTP response."
        case .badHTTPStatus(let code, let bodySummary):
            return "Relay returned HTTP \(code): \(bodySummary)"
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
private final class RelayTLSSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let expectedLeafCertificateSHA256: Data?
    private let observedLeafCertificateSHA256: (@Sendable (Data) -> Void)?

    init(
        expectedLeafCertificateSHA256: Data?,
        observedLeafCertificateSHA256: (@Sendable (Data) -> Void)?
    ) {
        self.expectedLeafCertificateSHA256 = expectedLeafCertificateSHA256
        self.observedLeafCertificateSHA256 = observedLeafCertificateSHA256
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
              let observedFingerprint = RelayTLSVerifier.leafCertificateSHA256(trust),
              expectedLeafCertificateSHA256.map({ $0 == observedFingerprint }) ?? true else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        observedLeafCertificateSHA256?(observedFingerprint)
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}
#endif
