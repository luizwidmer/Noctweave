import Foundation

public struct ResendRequest: Codable, Equatable {
    public let count: Int

    public init(count: Int) {
        self.count = max(1, count)
    }
}
