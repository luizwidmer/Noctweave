import Foundation

public enum RelayEndpointParserError: Error, Equatable, LocalizedError {
    case empty
    case missingHost
    case invalidPort(String)
    case unsupportedScheme(String)
    case unsupportedURLComponent(String)

    public var errorDescription: String? {
        switch self {
        case .empty:
            return "Relay endpoint is empty."
        case .missingHost:
            return "Relay endpoint is missing a host."
        case .invalidPort(let value):
            return "Relay endpoint has an invalid port: \(value)."
        case .unsupportedScheme(let value):
            return "Relay endpoint has an unsupported scheme: \(value)."
        case .unsupportedURLComponent(let value):
            return "Relay endpoint cannot include \(value)."
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
            try validateHost(host)
            let remainder = trimmed[trimmed.index(after: close)...].trimmingCharacters(in: .whitespacesAndNewlines)
            guard remainder.isEmpty || remainder.hasPrefix(":") else {
                throw RelayEndpointParserError.invalidPort(String(remainder))
            }
            let port = try parseBarePort(remainder.isEmpty ? "" : String(remainder.dropFirst()), defaultPort: defaultTCPPort)
            return RelayEndpoint(host: host, port: port, useTLS: false, transport: .tcp)
        }

        let colonCount = trimmed.filter { $0 == ":" }.count
        if colonCount == 0 {
            try validateHost(trimmed)
            return RelayEndpoint(host: trimmed, port: defaultTCPPort, useTLS: false, transport: .tcp)
        }

        guard colonCount == 1 else {
            throw RelayEndpointParserError.missingHost
        }
        let parts = trimmed.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty else {
            throw RelayEndpointParserError.missingHost
        }
        try validateHost(String(parts[0]))
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
        if components.user != nil || components.password != nil {
            throw RelayEndpointParserError.unsupportedURLComponent("user info")
        }
        if components.query != nil {
            throw RelayEndpointParserError.unsupportedURLComponent("query parameters")
        }
        if components.fragment != nil {
            throw RelayEndpointParserError.unsupportedURLComponent("fragments")
        }
        if !components.percentEncodedPath.isEmpty, components.percentEncodedPath != "/" {
            throw RelayEndpointParserError.unsupportedURLComponent("paths")
        }
        try validateHost(host)
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
            throw RelayEndpointParserError.unsupportedScheme(scheme)
        }

        let parsedPort = components.port.map { UInt16(exactly: $0) } ?? defaultPort
        guard let port = parsedPort, port > 0 else {
            throw RelayEndpointParserError.invalidPort(String(components.port ?? -1))
        }

        return RelayEndpoint(host: host, port: port, useTLS: useTLS, transport: transport)
    }

    private static func parseBarePort(_ value: String, defaultPort: UInt16) throws -> UInt16 {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return defaultPort }
        guard let port = UInt16(trimmed), port > 0 else {
            throw RelayEndpointParserError.invalidPort(trimmed)
        }
        return port
    }

    private static func validateHost(_ host: String) throws {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw RelayEndpointParserError.missingHost
        }
        guard trimmed == host,
              !trimmed.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) }),
              !trimmed.contains("/"),
              !trimmed.contains("?"),
              !trimmed.contains("#"),
              !trimmed.contains("@") else {
            throw RelayEndpointParserError.missingHost
        }
    }
}
