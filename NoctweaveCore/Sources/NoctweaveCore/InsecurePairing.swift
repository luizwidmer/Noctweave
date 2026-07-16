import Foundation

public enum InsecurePairingMethod: String, Codable, CaseIterable, Identifiable {
    case bluetooth
    case localNetwork
    case relay

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .bluetooth:
            return "Bluetooth"
        case .localNetwork:
            return "Local Network"
        case .relay:
            return "Relay"
        }
    }
}

public struct InsecurePairingSettings: Codable, Equatable {
    public var isEnabled: Bool
    public var acknowledgeInterceptRisk: Bool
    public var allowInboundRequests: Bool
    public var method: InsecurePairingMethod?

    public init(
        isEnabled: Bool = false,
        acknowledgeInterceptRisk: Bool = false,
        allowInboundRequests: Bool = false,
        method: InsecurePairingMethod? = nil
    ) {
        self.isEnabled = isEnabled
        self.acknowledgeInterceptRisk = acknowledgeInterceptRisk
        self.allowInboundRequests = allowInboundRequests
        self.method = method
    }

    public var isReady: Bool {
        isEnabled && acknowledgeInterceptRisk
    }
}
