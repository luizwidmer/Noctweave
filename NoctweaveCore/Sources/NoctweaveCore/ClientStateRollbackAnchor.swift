import Foundation
#if canImport(Security)
import Security
#endif

public enum ClientStateRollbackAnchorError: Error, Equatable, Sendable {
    case invalidAnchor
    case compareAndSwapFailed
    case unavailable(status: Int32)
}

public enum ClientStateRollbackAnchorKind: String, Codable, Equatable, Sendable {
    case state
    case erased
}

/// Trusted local evidence for the newest encrypted client-state generation.
///
/// This record is local storage authority only. It is never serialized into a
/// persona, relationship, group, message, route, or relay request. A pending
/// value makes the file/anchor update crash recoverable without accepting an
/// older committed snapshot.
public struct ClientStateRollbackAnchor: Codable, Equatable, Sendable {
    public static let maximumGeneration: UInt64 = 9_007_199_254_740_991

    public let generation: UInt64
    public let stateDigest: Data
    public let kind: ClientStateRollbackAnchorKind

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case generation
        case stateDigest
        case kind
    }

    public init(
        generation: UInt64,
        stateDigest: Data,
        kind: ClientStateRollbackAnchorKind = .state
    ) throws {
        self.generation = generation
        self.stateDigest = stateDigest
        self.kind = kind
        guard isStructurallyValid else {
            throw ClientStateRollbackAnchorError.invalidAnchor
        }
    }

    public init(from decoder: Decoder) throws {
        try requireExactRollbackAnchorKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            generation: values.decode(UInt64.self, forKey: .generation),
            stateDigest: values.decode(Data.self, forKey: .stateDigest),
            kind: values.decode(ClientStateRollbackAnchorKind.self, forKey: .kind)
        )
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid state anchor")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(generation, forKey: .generation)
        try values.encode(stateDigest, forKey: .stateDigest)
        try values.encode(kind, forKey: .kind)
    }

    public var isStructurallyValid: Bool {
        generation > 0
            && generation <= Self.maximumGeneration
            && stateDigest.count == 32
    }
}

public struct ClientStateRollbackAnchorRecord: Codable, Equatable, Sendable {
    public let current: ClientStateRollbackAnchor?
    public let pending: ClientStateRollbackAnchor?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case current
        case pending
    }

    public init(
        current: ClientStateRollbackAnchor?,
        pending: ClientStateRollbackAnchor?
    ) throws {
        self.current = current
        self.pending = pending
        guard isStructurallyValid else {
            throw ClientStateRollbackAnchorError.invalidAnchor
        }
    }

    public init(from decoder: Decoder) throws {
        try requireExactRollbackAnchorKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            current: values.decodeIfPresent(ClientStateRollbackAnchor.self, forKey: .current),
            pending: values.decodeIfPresent(ClientStateRollbackAnchor.self, forKey: .pending)
        )
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid state anchor record"
                )
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(current, forKey: .current)
        try values.encode(pending, forKey: .pending)
    }

    public var isStructurallyValid: Bool {
        guard current != nil || pending != nil,
              current?.isStructurallyValid != false,
              pending?.isStructurallyValid != false else {
            return false
        }
        guard let pending else { return current != nil }
        if let current {
            return current.generation < ClientStateRollbackAnchor.maximumGeneration
                && pending.generation == current.generation + 1
                && pending.stateDigest != current.stateDigest
        }
        return pending.generation == 1
    }
}

/// The host must place this uniquely scoped record in integrity-protected
/// storage that cannot be rolled back with the encrypted state file.
/// `compareAndSwap` must be atomic and durable before returning. A conflicting
/// expected value must throw `compareAndSwapFailed`; it must never overwrite a
/// newer record. Built-in Apple storage is mutated only while
/// `ClientStateStore` holds the path-scoped cross-process file lock; custom
/// hosts must provide equivalent serialization inside this operation.
public protocol ClientStateRollbackAnchorStore: Sendable {
    func load() throws -> ClientStateRollbackAnchorRecord?
    func compareAndSwap(
        expected: ClientStateRollbackAnchorRecord?,
        replacement: ClientStateRollbackAnchorRecord
    ) throws
}

/// Process-local implementation for tests and explicitly bounded development.
/// It is not persistent rollback protection and must not be represented as one.
public final class VolatileClientStateRollbackAnchorStore:
    ClientStateRollbackAnchorStore, @unchecked Sendable {
    private let lock = NSLock()
    private var record: ClientStateRollbackAnchorRecord?

    public init(record: ClientStateRollbackAnchorRecord? = nil) {
        self.record = record
    }

    public func load() throws -> ClientStateRollbackAnchorRecord? {
        lock.lock()
        defer { lock.unlock() }
        return record
    }

    public func compareAndSwap(
        expected: ClientStateRollbackAnchorRecord?,
        replacement: ClientStateRollbackAnchorRecord
    ) throws {
        guard replacement.isStructurallyValid else {
            throw ClientStateRollbackAnchorError.invalidAnchor
        }
        lock.lock()
        defer { lock.unlock() }
        guard record == expected else {
            throw ClientStateRollbackAnchorError.compareAndSwapFailed
        }
        record = replacement
    }
}

#if canImport(Security)
final class KeychainClientStateRollbackAnchorStore:
    ClientStateRollbackAnchorStore, @unchecked Sendable {
    private static let operationLock = NSLock()

    private let service: String
    private let account: String

    init(service: String, account: String) {
        self.service = service
        self.account = account
    }

    func load() throws -> ClientStateRollbackAnchorRecord? {
        Self.operationLock.lock()
        defer { Self.operationLock.unlock() }
        return try loadUnlocked()
    }

    func compareAndSwap(
        expected: ClientStateRollbackAnchorRecord?,
        replacement: ClientStateRollbackAnchorRecord
    ) throws {
        guard replacement.isStructurallyValid else {
            throw ClientStateRollbackAnchorError.invalidAnchor
        }
        Self.operationLock.lock()
        defer { Self.operationLock.unlock() }
        guard try loadUnlocked() == expected else {
            throw ClientStateRollbackAnchorError.compareAndSwapFailed
        }
        let encoded = try NoctweaveCoder.encode(replacement, sortedKeys: true)
        if expected == nil {
            var attributes: [String: Any] = baseQuery
            attributes[kSecValueData as String] = encoded
            #if os(iOS)
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            #endif
            let status = SecItemAdd(attributes as CFDictionary, nil)
            guard status == errSecSuccess else {
                throw ClientStateRollbackAnchorError.unavailable(status: status)
            }
        } else {
            let status = SecItemUpdate(
                baseQuery as CFDictionary,
                [kSecValueData as String: encoded] as CFDictionary
            )
            guard status == errSecSuccess else {
                throw ClientStateRollbackAnchorError.unavailable(status: status)
            }
        }
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
        ]
    }

    private func loadUnlocked() throws -> ClientStateRollbackAnchorRecord? {
        var query = baseQuery
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw ClientStateRollbackAnchorError.unavailable(status: status)
        }
        return try NoctweaveCoder.decode(ClientStateRollbackAnchorRecord.self, from: data)
    }
}
#endif

private struct RollbackAnchorCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private func requireExactRollbackAnchorKeys<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ type: Key.Type
) throws where Key.AllCases: Collection {
    let strict = try decoder.container(keyedBy: RollbackAnchorCodingKey.self)
    guard Set(strict.allKeys.map(\.stringValue))
            == Set(type.allCases.map(\.stringValue)) else {
        throw DecodingError.dataCorrupted(
            .init(codingPath: decoder.codingPath, debugDescription: "Anchor fields must match")
        )
    }
}
