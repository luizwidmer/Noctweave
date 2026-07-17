import CryptoKit
import Foundation

public struct ChainKeyState: Codable, Equatable {
    public var keyData: Data
    public var counter: UInt64
    public var skippedMessageKeys: [UInt64: Data]

    public static let defaultMaxSkip: UInt64 = 64
    public static let absoluteMaxSkip: UInt64 = 1_024
    private static let keyByteCount = 32

    public init(keyData: Data, counter: UInt64 = 0, skippedMessageKeys: [UInt64: Data] = [:]) {
        self.keyData = keyData
        self.counter = counter
        self.skippedMessageKeys = skippedMessageKeys
    }

    private enum CodingKeys: String, CodingKey {
        case keyData
        case counter
        case skippedMessageKeys
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        keyData = try container.decode(Data.self, forKey: .keyData)
        counter = try container.decodeIfPresent(UInt64.self, forKey: .counter) ?? 0
        skippedMessageKeys = try container.decodeIfPresent([UInt64: Data].self, forKey: .skippedMessageKeys) ?? [:]
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .keyData,
                in: container,
                debugDescription: "Invalid or oversized ratchet chain state."
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(keyData, forKey: .keyData)
        try container.encode(counter, forKey: .counter)
        if !skippedMessageKeys.isEmpty {
            try container.encode(skippedMessageKeys, forKey: .skippedMessageKeys)
        }
    }

    public mutating func nextMessageKey() throws -> (counter: UInt64, key: SymmetricKey) {
        guard isStructurallyValid, counter < UInt64.max else {
            throw CryptoError.counterOutOfOrder
        }
        let current = counter
        let (messageKey, nextChain) = try deriveKeys(for: counter)
        keyData.secureWipe()
        keyData = nextChain
        counter += 1
        return (current, SymmetricKey(data: messageKey))
    }

    public mutating func messageKey(
        for targetCounter: UInt64,
        maxSkip: UInt64 = ChainKeyState.defaultMaxSkip
    ) throws -> SymmetricKey {
        guard isStructurallyValid, maxSkip <= Self.absoluteMaxSkip else {
            throw CryptoError.invalidPayload
        }
        if var cached = skippedMessageKeys.removeValue(forKey: targetCounter) {
            let key = SymmetricKey(data: cached)
            cached.secureWipe()
            return key
        }
        if targetCounter < counter {
            throw CryptoError.counterReplay
        }
        let distance = targetCounter - counter
        if distance > maxSkip {
            throw CryptoError.counterWindowExceeded
        }
        while counter < targetCounter {
            guard counter < UInt64.max else {
                throw CryptoError.counterOutOfOrder
            }
            let (messageKey, nextChain) = try deriveKeys(for: counter)
            cacheSkippedKey(counter, messageKey, max: maxSkip)
            keyData.secureWipe()
            keyData = nextChain
            counter += 1
        }
        guard counter < UInt64.max else {
            throw CryptoError.counterOutOfOrder
        }
        let (messageKey, nextChain) = try deriveKeys(for: counter)
        keyData.secureWipe()
        keyData = nextChain
        counter += 1
        return SymmetricKey(data: messageKey)
    }

    public var isStructurallyValid: Bool {
        keyData.count == Self.keyByteCount
            && skippedMessageKeys.count <= Int(Self.absoluteMaxSkip)
            && skippedMessageKeys.values.allSatisfy { $0.count == Self.keyByteCount }
            && skippedMessageKeys.keys.allSatisfy { $0 < counter }
    }

    mutating func secureWipe() {
        keyData.secureWipe()
        for key in skippedMessageKeys.keys {
            var skipped = skippedMessageKeys.removeValue(forKey: key)
            skipped?.secureWipe()
        }
        counter = 0
    }

    private func deriveKeys(for counter: UInt64) throws -> (messageKey: Data, nextChain: Data) {
        let key = SymmetricKey(data: keyData)
        var counterBytes = counter.bigEndian
        let counterData = Data(bytes: &counterBytes, count: MemoryLayout<UInt64>.size)
        let messageLabel = Data("MSG".utf8) + counterData
        let chainLabel = Data("CK".utf8) + counterData
        let messageKey = HMAC<SHA256>.authenticationCode(for: messageLabel, using: key)
        let chainKey = HMAC<SHA256>.authenticationCode(for: chainLabel, using: key)
        return (Data(messageKey), Data(chainKey))
    }

    private mutating func cacheSkippedKey(_ counter: UInt64, _ messageKey: Data, max: UInt64) {
        skippedMessageKeys[counter] = messageKey
        let limit = Int(min(max, Self.absoluteMaxSkip))
        if skippedMessageKeys.count > limit {
            let overflow = skippedMessageKeys.count - limit
            let keysToRemove = skippedMessageKeys.keys.sorted().prefix(overflow)
            for key in keysToRemove {
                var removed = skippedMessageKeys.removeValue(forKey: key)
                removed?.secureWipe()
            }
        }
    }
}
