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

public struct PairingAnnouncement: Codable, Identifiable, Equatable {
    public let id: UUID
    public let offer: ContactOffer
    public let announcedAt: Date
    public let expiresAt: Date

    public init(id: UUID = UUID(), offer: ContactOffer, announcedAt: Date, expiresAt: Date) {
        self.id = id
        self.offer = offer
        self.announcedAt = announcedAt
        self.expiresAt = expiresAt
    }
}

public struct PairingRequest: Codable, Identifiable, Equatable {
    public let id: UUID
    public let from: ContactOffer
    public let sentAt: Date

    public init(id: UUID = UUID(), from: ContactOffer, sentAt: Date) {
        self.id = id
        self.from = from
        self.sentAt = sentAt
    }
}
