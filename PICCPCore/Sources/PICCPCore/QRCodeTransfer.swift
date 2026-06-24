import CryptoKit
import Foundation
import Security

public struct QRChunkFrame: Equatable {
    public let id: String
    public let index: Int
    public let total: Int
    public let checksum: String
    public let chunk: String
}

public enum QRChunkResult: Equatable {
    case single(String)
    case partial(id: String, received: Int, total: Int)
    case complete(String)
    case invalid
}

public enum QRCodeTransfer {
    public static let prefix = "PICCPQR1"
    public static let maximumFrameCount = 128
    public static let maximumChunkCharacters = 1_200
    public static let maximumAssembledCharacters = maximumFrameCount * maximumChunkCharacters

    public static func encodeFrames(_ message: String, maxChunkSize: Int = 600) -> [String] {
        guard !message.isEmpty, message.count <= maximumAssembledCharacters else {
            return []
        }
        guard maxChunkSize > 0 else {
            return [message]
        }
        let boundedChunkSize = min(maximumChunkCharacters, maxChunkSize)
        if message.count <= boundedChunkSize {
            return [message]
        }

        let id = randomId()
        let checksumValue = checksum(message)
        let chunks = chunkString(message, maxChunkSize: boundedChunkSize)
        guard chunks.count <= maximumFrameCount else {
            return []
        }
        let total = chunks.count
        return chunks.enumerated().map { index, chunk in
            "\(prefix)|\(id)|\(index + 1)|\(total)|\(checksumValue)|\(chunk)"
        }
    }

    public static func decodeFrame(_ text: String) -> QRChunkFrame? {
        guard text.hasPrefix(prefix) else {
            return nil
        }
        let parts = text.split(separator: "|", maxSplits: 5, omittingEmptySubsequences: false)
        guard parts.count == 6 else {
            return nil
        }
        guard parts[0] == prefix else {
            return nil
        }
        let id = String(parts[1])
        guard let index = Int(parts[2]), let total = Int(parts[3]) else {
            return nil
        }
        guard index > 0,
              total > 0,
              total <= maximumFrameCount,
              index <= total else {
            return nil
        }
        guard parts[1].count <= 64,
              parts[4].count <= 128,
              parts[5].count <= maximumChunkCharacters else {
            return nil
        }
        let checksumValue = String(parts[4])
        let chunk = String(parts[5])
        return QRChunkFrame(id: id, index: index, total: total, checksum: checksumValue, chunk: chunk)
    }

    public static func assemble(_ frames: [QRChunkFrame]) -> String? {
        guard let first = frames.first else {
            return nil
        }
        let total = first.total
        let checksumValue = first.checksum
        let id = first.id
        guard frames.allSatisfy({ $0.total == total && $0.checksum == checksumValue && $0.id == id }) else {
            return nil
        }
        var map: [Int: QRChunkFrame] = [:]
        for frame in frames {
            map[frame.index] = frame
        }
        if map.count != total {
            return nil
        }
        let chunks = (1...total).compactMap { map[$0]?.chunk }
        guard chunks.count == total else {
            return nil
        }
        let message = chunks.joined()
        guard message.count <= maximumAssembledCharacters else {
            return nil
        }
        guard checksum(message) == checksumValue else {
            return nil
        }
        return message
    }

    public static func checksum(_ message: String) -> String {
        let digest = SHA256.hash(data: Data(message.utf8))
        return Data(digest).base64EncodedString()
    }

    private static func randomId() -> String {
        var bytes = [UInt8](repeating: 0, count: 8)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status != errSecSuccess {
            for index in bytes.indices {
                bytes[index] = UInt8.random(in: 0...255)
            }
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func chunkString(_ value: String, maxChunkSize: Int) -> [String] {
        var chunks: [String] = []
        var start = value.startIndex
        while start < value.endIndex {
            let end = value.index(start, offsetBy: maxChunkSize, limitedBy: value.endIndex) ?? value.endIndex
            chunks.append(String(value[start..<end]))
            start = end
        }
        return chunks
    }
}

public struct QRChunkCollector {
    private var framesById: [String: [Int: QRChunkFrame]] = [:]
    private static let maximumConcurrentTransfers = 8

    public init() {}

    public mutating func consume(_ text: String) -> QRChunkResult {
        guard text.count <= QRCodeTransfer.maximumAssembledCharacters else {
            return .invalid
        }
        guard let frame = QRCodeTransfer.decodeFrame(text) else {
            return .single(text)
        }

        if framesById[frame.id] == nil,
           framesById.count >= Self.maximumConcurrentTransfers,
           let oldestId = framesById.keys.sorted().first {
            framesById.removeValue(forKey: oldestId)
        }
        var map = framesById[frame.id] ?? [:]
        map[frame.index] = frame
        framesById[frame.id] = map

        if map.count < frame.total {
            return .partial(id: frame.id, received: map.count, total: frame.total)
        }

        let frames = map.values.sorted(by: { $0.index < $1.index })
        if let message = QRCodeTransfer.assemble(frames) {
            framesById.removeValue(forKey: frame.id)
            return .complete(message)
        }

        framesById.removeValue(forKey: frame.id)
        return .invalid
    }
}
