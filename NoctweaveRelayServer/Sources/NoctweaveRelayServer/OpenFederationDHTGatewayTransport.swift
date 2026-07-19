import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

enum OpenFederationDHTGatewayTransportError: Error, Equatable {
    case invalidURL
    case nonHTTPResponse
    case badStatus(Int)
    case responseTooLarge
    case invalidResponse
    case invalidConfiguration
}

final class OpenFederationDHTHTTPGatewayTransport: OpenFederationDHTTransport {
    let baseURL: URL
    let authToken: String?
    let timeout: TimeInterval
    let maxResponseBytes: Int

    private let session: URLSession

    init(
        baseURL: URL,
        session: URLSession? = nil,
        authToken: String? = nil,
        timeout: TimeInterval = 8,
        maxResponseBytes: Int = 256 * 1024
    ) throws {
        let normalizedToken = authToken?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard timeout.isFinite,
              (1...60).contains(timeout),
              (1_024...(1_024 * 1_024)).contains(maxResponseBytes),
              normalizedToken.map({ $0.utf8.count <= 4_096 }) ?? true else {
            throw OpenFederationDHTGatewayTransportError.invalidConfiguration
        }
        self.baseURL = baseURL
        self.session = session ?? URLSession(configuration: .ephemeral)
        self.authToken = normalizedToken?.isEmpty == false ? normalizedToken : nil
        self.timeout = timeout
        self.maxResponseBytes = maxResponseBytes
    }

    func publish(_ record: OpenFederationDHTRecord, namespace: String) async throws {
        guard isValidNamespace(namespace) else {
            throw OpenFederationDHTGatewayTransportError.invalidURL
        }
        guard let url = makeRecordsURL() else {
            throw OpenFederationDHTGatewayTransportError.invalidURL
        }
        let body = try RelayCodec.encoder(sortedKeys: true).encode(
            GatewayPublishRequest(namespace: namespace, record: record)
        )
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.httpMethod = "POST"
        request.httpBody = body
        applyCommonHeaders(to: &request)
        let (data, response) = try await boundedLoad(request)
        try validate(response: response, data: data)
    }

    func query(namespace: String, limit: Int) async throws -> [OpenFederationDHTRecord] {
        guard isValidNamespace(namespace),
              (1...OpenFederationDHTDiscoveryConfiguration.maximumQueryRecords).contains(limit) else {
            throw OpenFederationDHTGatewayTransportError.invalidURL
        }
        guard let url = makeRecordsURL(namespace: namespace, limit: limit) else {
            throw OpenFederationDHTGatewayTransportError.invalidURL
        }
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.httpMethod = "GET"
        applyCommonHeaders(to: &request)
        let (data, response) = try await boundedLoad(request)
        try validate(response: response, data: data)
        return try Self.decodeQueryResponse(data, limit: limit)
    }

    static func decodeQueryResponse(_ data: Data, limit: Int) throws -> [OpenFederationDHTRecord] {
        guard (1...OpenFederationDHTDiscoveryConfiguration.maximumQueryRecords).contains(limit) else {
            throw OpenFederationDHTGatewayTransportError.invalidResponse
        }
        do {
            let envelope = try RelayCodec.decodeWire(GatewayQueryResponse.self, from: data)
            return Array(envelope.records.prefix(max(1, limit)))
        } catch {
            throw OpenFederationDHTGatewayTransportError.invalidResponse
        }
    }

    private func makeRecordsURL(namespace: String? = nil, limit: Int? = nil) -> URL? {
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              components.host?.isEmpty == false,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              components.port.map({ $0 > 0 && $0 <= 65_535 }) ?? true else {
            return nil
        }

        let basePath = components.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard basePath.utf8.count <= 1_024 else {
            return nil
        }
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
        request.setValue("Noctweave-Relay-DHT-Gateway/1", forHTTPHeaderField: "User-Agent")
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

    private func boundedLoad(_ request: URLRequest) async throws -> (Data, URLResponse) {
        do {
            return try await BoundedURLSessionLoader.load(
                request,
                configuration: session.configuration,
                maximumBytes: maxResponseBytes
            )
        } catch BoundedURLSessionLoaderError.responseTooLarge {
            throw OpenFederationDHTGatewayTransportError.responseTooLarge
        }
    }

    private func isValidNamespace(_ namespace: String) -> Bool {
        !namespace.isEmpty
            && namespace.utf8.count <= 128
            && namespace.rangeOfCharacter(from: .whitespacesAndNewlines) == nil
    }

    private struct GatewayPublishRequest: Codable {
        let namespace: String
        let record: OpenFederationDHTRecord
    }

    private struct GatewayQueryResponse: Codable {
        let records: [OpenFederationDHTRecord]

        private enum CodingKeys: String, CodingKey {
            case records
        }

        init(from decoder: Decoder) throws {
            let strict = try decoder.container(keyedBy: GatewayCodingKey.self)
            guard Set(strict.allKeys.map(\.stringValue)) == [CodingKeys.records.rawValue] else {
                throw DecodingError.dataCorrupted(
                    .init(codingPath: decoder.codingPath, debugDescription: "Gateway response fields are not exact")
                )
            }
            let container = try decoder.container(keyedBy: CodingKeys.self)
            records = try container.decode([OpenFederationDHTRecord].self, forKey: .records)
        }
    }

    private struct GatewayCodingKey: CodingKey {
        let stringValue: String
        let intValue: Int?

        init?(stringValue: String) {
            self.stringValue = stringValue
            intValue = nil
        }

        init?(intValue: Int) {
            stringValue = String(intValue)
            self.intValue = intValue
        }
    }
}
