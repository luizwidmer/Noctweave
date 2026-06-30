import Foundation

public enum RelayEndpointParserError: Error, Equatable, LocalizedError {
    case empty
    case missingHost
    case invalidPort(String)

    public var errorDescription: String? {
        switch self {
        case .empty:
            return "Relay endpoint is empty."
        case .missingHost:
            return "Relay endpoint is missing a host."
        case .invalidPort(let value):
            return "Relay endpoint has an invalid port: \(value)."
        }
    }
}

public enum RelayEndpointParser {
    public static func parse(_ value: String, defaultTCPPort: UInt16 = 9339) throws -> RelayEndpoint {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw RelayEndpointParserError.empty }

        if trimmed.contains("://"),
           let components = URLComponents(string: trimmed),
           let scheme = components.scheme,
           !scheme.isEmpty {
            return try parseURLComponents(components, scheme: scheme, defaultTCPPort: defaultTCPPort)
        }

        if trimmed.hasPrefix("["), let close = trimmed.firstIndex(of: "]") {
            let host = String(trimmed[trimmed.index(after: trimmed.startIndex)..<close])
            guard !host.isEmpty else { throw RelayEndpointParserError.missingHost }
            let remainder = trimmed[trimmed.index(after: close)...].trimmingCharacters(in: .whitespacesAndNewlines)
            guard remainder.isEmpty || remainder.hasPrefix(":") else {
                throw RelayEndpointParserError.invalidPort(String(remainder))
            }
            let port = try parseBarePort(remainder.isEmpty ? "" : String(remainder.dropFirst()), defaultPort: defaultTCPPort)
            return RelayEndpoint(host: host, port: port, useTLS: false, transport: .tcp)
        }

        let colonCount = trimmed.filter { $0 == ":" }.count
        if colonCount == 0 {
            return RelayEndpoint(host: trimmed, port: defaultTCPPort, useTLS: false, transport: .tcp)
        }

        guard colonCount == 1 else {
            throw RelayEndpointParserError.missingHost
        }
        let parts = trimmed.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty else {
            throw RelayEndpointParserError.missingHost
        }
        let port = try parseBarePort(String(parts[1]), defaultPort: defaultTCPPort)
        return RelayEndpoint(host: String(parts[0]), port: port, useTLS: false, transport: .tcp)
    }

    private static func parseURLComponents(
        _ components: URLComponents,
        scheme: String,
        defaultTCPPort: UInt16
    ) throws -> RelayEndpoint {
        guard let host = components.host, !host.isEmpty else {
            throw RelayEndpointParserError.missingHost
        }
        let loweredScheme = scheme.lowercased()
        let defaultPort: UInt16
        let transport: RelayEndpointTransport
        let useTLS: Bool

        switch loweredScheme {
        case "https":
            defaultPort = 443
            transport = .http
            useTLS = true
        case "http":
            defaultPort = 80
            transport = .http
            useTLS = false
        case "wss":
            defaultPort = 443
            transport = .websocket
            useTLS = true
        case "ws":
            defaultPort = 80
            transport = .websocket
            useTLS = false
        case "tls":
            defaultPort = defaultTCPPort
            transport = .tcp
            useTLS = true
        case "tcp":
            defaultPort = defaultTCPPort
            transport = .tcp
            useTLS = false
        default:
            defaultPort = defaultTCPPort
            transport = .tcp
            useTLS = false
        }

        let parsedPort = components.port.map { UInt16(exactly: $0) } ?? defaultPort
        guard let port = parsedPort else {
            throw RelayEndpointParserError.invalidPort(String(components.port ?? -1))
        }

        return RelayEndpoint(host: host, port: port, useTLS: useTLS, transport: transport)
    }

    private static func parseBarePort(_ value: String, defaultPort: UInt16) throws -> UInt16 {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return defaultPort }
        guard let port = UInt16(trimmed) else {
            throw RelayEndpointParserError.invalidPort(trimmed)
        }
        return port
    }
}
