import Foundation

/// The transport boundary that makes a relay capability-bearing request
/// confidential. A trusted reverse proxy is an explicit operator assertion;
/// it does not turn the relay's local listener into a TLS listener.
public enum EffectiveTransportConfidentiality: String, Codable, Equatable, Sendable {
    case none
    case listenerTLS
    case trustedReverseProxyTLS
    case loopback

    public var permitsCapabilityTransport: Bool {
        self != .none
    }
}

public struct RelayTransportConfidentialityConfiguration: Codable, Equatable, Sendable {
    public let listenerTLS: Bool
    public let trustedReverseProxyTLS: Bool

    public init(
        listenerTLS: Bool = false,
        trustedReverseProxyTLS: Bool = false
    ) {
        self.listenerTLS = listenerTLS
        self.trustedReverseProxyTLS = trustedReverseProxyTLS
    }

    public var configuredEffectiveTransport: EffectiveTransportConfidentiality {
        if listenerTLS { return .listenerTLS }
        if trustedReverseProxyTLS { return .trustedReverseProxyTLS }
        return .none
    }

    public func effectiveTransport(
        isLiteralLoopbackSource: Bool
    ) -> EffectiveTransportConfidentiality {
        if listenerTLS { return .listenerTLS }
        if trustedReverseProxyTLS { return .trustedReverseProxyTLS }
        if isLiteralLoopbackSource { return .loopback }
        return .none
    }
}
