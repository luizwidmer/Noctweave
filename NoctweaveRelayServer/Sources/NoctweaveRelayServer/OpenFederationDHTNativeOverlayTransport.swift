import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

enum OpenFederationDHTNativeOverlayTransportError: Error, Equatable {
    case unsupportedEndpointTransport
    case invalidURL
    case nonHTTPResponse
    case badStatus(Int)
    case responseTooLarge
    case invalidResponse
}

protocol OpenFederationDHTRelayQueryClient: AnyObject {
    func send(_ request: RelayRequest, to endpoint: RelayEndpoint) async throws -> RelayResponse
}

final class OpenFederationDHTHTTPRelayQueryClient: OpenFederationDHTRelayQueryClient {
    private let session: URLSession
    private let timeout: TimeInterval
    private let maxResponseBytes: Int

    init(
        session: URLSession? = nil,
        timeout: TimeInterval = 8,
        maxResponseBytes: Int = 256 * 1024
    ) {
        self.session = session ?? URLSession(configuration: .ephemeral)
        self.timeout = max(1, timeout)
        self.maxResponseBytes = max(1024, maxResponseBytes)
    }

    func send(_ request: RelayRequest, to endpoint: RelayEndpoint) async throws -> RelayResponse {
        guard endpoint.transport == .http else {
            throw OpenFederationDHTNativeOverlayTransportError.unsupportedEndpointTransport
        }
        guard let url = relayURL(for: endpoint) else {
            throw OpenFederationDHTNativeOverlayTransportError.invalidURL
        }
        let body = try RelayCodec.encoder(sortedKeys: true).encode(request)
        var urlRequest = URLRequest(url: url, timeoutInterval: timeout)
        urlRequest.httpMethod = "POST"
        urlRequest.httpBody = body
        urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("Noctyra-Relay-Native-DHT/1", forHTTPHeaderField: "User-Agent")

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await BoundedURLSessionLoader.load(
                urlRequest,
                configuration: session.configuration,
                maximumBytes: maxResponseBytes
            )
        } catch BoundedURLSessionLoaderError.responseTooLarge {
            throw OpenFederationDHTNativeOverlayTransportError.responseTooLarge
        }
        guard let http = response as? HTTPURLResponse else {
            throw OpenFederationDHTNativeOverlayTransportError.nonHTTPResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            throw OpenFederationDHTNativeOverlayTransportError.badStatus(http.statusCode)
        }
        guard let decoded = try? RelayCodec.decoder().decode(RelayResponse.self, from: data) else {
            throw OpenFederationDHTNativeOverlayTransportError.invalidResponse
        }
        return decoded
    }

    private func relayURL(for endpoint: RelayEndpoint) -> URL? {
        var components = URLComponents()
        components.scheme = endpoint.useTLS ? "https" : "http"
        components.host = endpoint.host
        components.port = Int(endpoint.port)
        components.path = "/relay"
        return components.url
    }
}

final class OpenFederationDHTNativeOverlayTransport: OpenFederationDHTTransport {
    let seedEndpoints: [RelayEndpoint]
    let maxVisitedEndpoints: Int
    let maxPeerHintsPerEndpoint: Int

    private let client: OpenFederationDHTRelayQueryClient

    init(
        seedEndpoints: [RelayEndpoint],
        client: OpenFederationDHTRelayQueryClient,
        maxVisitedEndpoints: Int = 16,
        maxPeerHintsPerEndpoint: Int = 8
    ) {
        self.seedEndpoints = Self.deduplicated(seedEndpoints)
        self.client = client
        self.maxVisitedEndpoints = max(1, maxVisitedEndpoints)
        self.maxPeerHintsPerEndpoint = max(0, maxPeerHintsPerEndpoint)
    }

    func publish(_ record: OpenFederationDHTRecord, namespace: String) async throws {
        let request = RelayRequest.publishOpenFederationDHTRecord(
            PublishOpenFederationDHTRecordRequest(namespace: namespace, record: record)
        )
        var firstError: Error?
        var delivered = false
        for endpoint in seedEndpoints.prefix(maxVisitedEndpoints) {
            do {
                let response = try await client.send(request, to: endpoint)
                if response.type == .ok {
                    delivered = true
                } else if firstError == nil {
                    firstError = OpenFederationDHTNativeOverlayTransportError.invalidResponse
                }
            } catch {
                if firstError == nil {
                    firstError = error
                }
            }
        }
        if !delivered, let firstError {
            throw firstError
        }
    }

    func query(namespace: String, limit: Int) async throws -> [OpenFederationDHTRecord] {
        let boundedLimit = max(1, limit)
        var queue = seedEndpoints
        var visited = Set<String>()
        var records: [OpenFederationDHTRecord] = []
        var firstError: Error?

        while !queue.isEmpty, visited.count < maxVisitedEndpoints, records.count < boundedLimit {
            let endpoint = queue.removeFirst()
            let endpointKey = Self.key(for: endpoint)
            guard !visited.contains(endpointKey) else {
                continue
            }
            visited.insert(endpointKey)

            do {
                let infoResponse = try await client.send(.info(), to: endpoint)
                if let hints = infoResponse.relayInfo?.knownOpenPeers {
                    for hint in hints.prefix(maxPeerHintsPerEndpoint) {
                        let key = Self.key(for: hint)
                        if !visited.contains(key), !queue.contains(where: { Self.key(for: $0) == key }) {
                            queue.append(hint)
                        }
                    }
                }

                let listResponse = try await client.send(
                    .listOpenFederationDHTRecords(
                        ListOpenFederationDHTRecordsRequest(namespace: namespace, limit: boundedLimit)
                    ),
                    to: endpoint
                )
                if listResponse.type == .openFederationDHTRecords {
                    records.append(contentsOf: listResponse.openFederationDHTRecords ?? [])
                } else if firstError == nil {
                    firstError = OpenFederationDHTNativeOverlayTransportError.invalidResponse
                }
            } catch {
                if firstError == nil {
                    firstError = error
                }
            }
        }

        if records.isEmpty, let firstError {
            throw firstError
        }
        return Array(records.prefix(boundedLimit))
    }

    private static func deduplicated(_ endpoints: [RelayEndpoint]) -> [RelayEndpoint] {
        var seen = Set<String>()
        var result: [RelayEndpoint] = []
        for endpoint in endpoints {
            let key = Self.key(for: endpoint)
            guard !seen.contains(key) else {
                continue
            }
            seen.insert(key)
            result.append(endpoint)
        }
        return result
    }

    private static func key(for endpoint: RelayEndpoint) -> String {
        "\(endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()):\(endpoint.port):\(endpoint.useTLS ? 1 : 0):\(endpoint.transport.rawValue)"
    }
}
