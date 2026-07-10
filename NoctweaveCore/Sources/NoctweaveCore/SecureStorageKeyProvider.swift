import CryptoKit
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
#if canImport(Security)
import Security
#endif

public enum SecureStorageKeyAccessibility: Sendable {
    case whenUnlockedDeviceOnly
    case afterFirstUnlockDeviceOnly
}

public enum SecureStorageKeyProviderError: Error, Equatable, Sendable {
    case unavailable(status: Int32)
}

/// Loads each Keychain-backed symmetric key at most once per process.
///
/// Keychain authorization may display UI on macOS. Keeping the resulting
/// `SymmetricKey` in process memory prevents routine state, attachment, and
/// thread operations from repeatedly asking the user to authorize the same item.
public final class SecureStorageKeyProvider: @unchecked Sendable {
    public static let shared = SecureStorageKeyProvider()

    private struct CacheKey: Hashable {
        let service: String
        let account: String
        let accessGroup: String?
    }

    private let lock = NSLock()
    private var keys: [CacheKey: SymmetricKey] = [:]

    private init() {}

    public func loadOrCreateKey(
        service: String,
        account: String,
        accessGroup: String? = nil,
        accessibility: SecureStorageKeyAccessibility = .whenUnlockedDeviceOnly
    ) throws -> SymmetricKey {
        let cacheKey = CacheKey(service: service, account: account, accessGroup: accessGroup)
        lock.lock()
        defer { lock.unlock() }
        if let cached = keys[cacheKey] {
            return cached
        }
        #if canImport(Security)
        let key = try Self.loadOrCreateFromKeychain(
            service: service,
            account: account,
            accessGroup: accessGroup,
            accessibility: accessibility
        )
        keys[cacheKey] = key
        return key
        #else
        throw SecureStorageKeyProviderError.unavailable(status: -1)
        #endif
    }

    public func clearProcessCache() {
        lock.lock()
        keys.removeAll(keepingCapacity: false)
        lock.unlock()
    }

    #if canImport(Security)
    private static func loadOrCreateFromKeychain(
        service: String,
        account: String,
        accessGroup: String?,
        accessibility: SecureStorageKeyAccessibility
    ) throws -> SymmetricKey {
        if let existing = try loadKey(service: service, account: account, accessGroup: accessGroup) {
            return existing
        }
        let key = SymmetricKey(size: .bits256)
        return try saveKey(
            key,
            service: service,
            account: account,
            accessGroup: accessGroup,
            accessibility: accessibility
        )
    }

    private static func loadKey(service: String, account: String, accessGroup: String?) throws -> SymmetricKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, var data = item as? Data else {
            throw SecureStorageKeyProviderError.unavailable(status: status)
        }
        defer { data.secureWipeForKeyProvider() }
        return SymmetricKey(data: data)
    }

    private static func saveKey(
        _ key: SymmetricKey,
        service: String,
        account: String,
        accessGroup: String?,
        accessibility: SecureStorageKeyAccessibility
    ) throws -> SymmetricKey {
        var data = key.withUnsafeBytes { Data($0) }
        defer { data.secureWipeForKeyProvider() }
        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        #if os(iOS)
        attributes[kSecAttrAccessible as String] = accessibility == .afterFirstUnlockDeviceOnly
            ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        #endif
        if let accessGroup {
            attributes[kSecAttrAccessGroup as String] = accessGroup
        }
        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            guard let existing = try loadKey(service: service, account: account, accessGroup: accessGroup) else {
                throw SecureStorageKeyProviderError.unavailable(status: status)
            }
            return existing
        }
        guard status == errSecSuccess else {
            throw SecureStorageKeyProviderError.unavailable(status: status)
        }
        return key
    }
    #endif
}

private extension Data {
    mutating func secureWipeForKeyProvider() {
        guard !isEmpty else { return }
        let byteCount = count
        withUnsafeMutableBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            #if canImport(Darwin)
            _ = memset_s(baseAddress, byteCount, 0, byteCount)
            #else
            rawBuffer.initializeMemory(as: UInt8.self, repeating: 0)
            #endif
        }
        removeAll(keepingCapacity: false)
    }
}
