import Foundation

public enum OpenFederationDHTGatewayTransportError: Error, Equatable {
    case invalidBaseURL
    case invalidURL
    case nonHTTPResponse
    case badStatus(Int)
    case responseTooLarge
    case invalidResponse
}

public final class OpenFederationDHTHTTPGatewayTransport: OpenFederationDHTTransport {
    public let baseURL: URL
    public let authToken: String?
    public let timeout: TimeInterval
    public let maxResponseBytes: Int

    private let session: URLSession

    public init(
        baseURL: URL,
        session: URLSession? = nil,
        authToken: String? = nil,
        timeout: TimeInterval = 8,
        maxResponseBytes: Int = 256 * 1024
    ) {
        self.baseURL = baseURL
        self.session = session ?? URLSession(configuration: .ephemeral)
        let normalizedToken = authToken?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.authToken = normalizedToken?.isEmpty == false ? normalizedToken : nil
        self.timeout = max(1, timeout)
        self.maxResponseBytes = max(1024, maxResponseBytes)
    }

    public func publish(_ record: OpenFederationDHTRecord, namespace: String) async throws {
        guard let url = makeRecordsURL() else {
            throw OpenFederationDHTGatewayTransportError.invalidURL
        }
        let body = try NoctweaveCoder.encode(
            GatewayPublishRequest(namespace: namespace, record: record),
            sortedKeys: true
        )
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.httpMethod = "POST"
        request.httpBody = body
        applyCommonHeaders(to: &request)
        let (data, response) = try await session.data(for: request)
        try validate(response: response, data: data)
    }

    public func query(namespace: String, limit: Int) async throws -> [OpenFederationDHTRecord] {
        guard let url = makeRecordsURL(namespace: namespace, limit: limit) else {
            throw OpenFederationDHTGatewayTransportError.invalidURL
        }
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.httpMethod = "GET"
        applyCommonHeaders(to: &request)
        let (data, response) = try await session.data(for: request)
        try validate(response: response, data: data)
        guard !data.isEmpty else {
            return []
        }
        if let envelope = try? NoctweaveCoder.decode(GatewayQueryResponse.self, from: data) {
            return Array(envelope.records.prefix(max(1, limit)))
        }
        if let records = try? NoctweaveCoder.decode([OpenFederationDHTRecord].self, from: data) {
            return Array(records.prefix(max(1, limit)))
        }
        throw OpenFederationDHTGatewayTransportError.invalidResponse
    }

    private func makeRecordsURL(namespace: String? = nil, limit: Int? = nil) -> URL? {
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              components.host?.isEmpty == false else {
            return nil
        }

        let basePath = components.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        components.path = "/" + ([basePath, "v1", "open-federation", "dht", "records"]
            .filter { !$0.isEmpty }
            .joined(separator: "/"))

        var queryItems: [URLQueryItem] = []
        if let namespace {
            queryItems.append(URLQueryItem(name: "namespace", value: namespace))
        }
        if let limit {
            queryItems.append(URLQueryItem(name: "limit", value: String(max(1, limit))))
        }
        components.queryItems = queryItems.isEmpty ? nil : queryItems
        return components.url
    }

    private func applyCommonHeaders(to request: inout URLRequest) {
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Noctyra-DHT-Gateway/1", forHTTPHeaderField: "User-Agent")
        if let authToken {
            request.setValue("Bearer \(authToken)", forHTTPHeaderField: "Authorization")
        }
    }

    private func validate(response: URLResponse, data: Data) throws {
        guard data.count <= maxResponseBytes else {
            throw OpenFederationDHTGatewayTransportError.responseTooLarge
        }
        guard let http = response as? HTTPURLResponse else {
            throw OpenFederationDHTGatewayTransportError.nonHTTPResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            throw OpenFederationDHTGatewayTransportError.badStatus(http.statusCode)
        }
    }

    private struct GatewayPublishRequest: Codable {
        let namespace: String
        let record: OpenFederationDHTRecord
    }

    private struct GatewayQueryResponse: Codable {
        let records: [OpenFederationDHTRecord]
    }
}
