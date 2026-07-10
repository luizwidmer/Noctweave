import Foundation

public struct ResendRequest: Codable, Equatable {
    public static let maximumCount = 64
    public let count: Int

    public init(count: Int) {
        self.count = min(Self.maximumCount, max(1, count))
    }

    private enum CodingKeys: String, CodingKey {
        case count
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decoded = try container.decode(Int.self, forKey: .count)
        guard (1...Self.maximumCount).contains(decoded) else {
            throw DecodingError.dataCorruptedError(
                forKey: .count,
                in: container,
                debugDescription: "Resend count must be between 1 and \(Self.maximumCount)."
            )
        }
        count = decoded
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(count, forKey: .count)
    }
}
