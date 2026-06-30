import Foundation

public struct SessionReset: Codable, Equatable {
    public let initiatedAt: Date

    public init(initiatedAt: Date = Date()) {
        self.initiatedAt = initiatedAt
    }
}
