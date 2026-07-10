import Foundation
import CryptoKit
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
#if canImport(Security)
import Security
#endif

public actor ClientStateStore {
    public static let maximumPlaintextBytes = 64 * 1024 * 1024
    public static let maximumStoredBytes = 96 * 1024 * 1024
    private let fileURL: URL
    private let useEncryption: Bool
    private let suppliedEncryptionKey: SymmetricKey?

    public init(
        fileURL: URL,
        useEncryption: Bool = true,
        encryptionKey: SymmetricKey? = nil
    ) {
        self.fileURL = fileURL
        self.useEncryption = useEncryption
        self.suppliedEncryptionKey = encryptionKey
    }

    public func load() throws -> ClientState? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        let values = try fileURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard values.isRegularFile == true,
              let fileSize = values.fileSize,
              fileSize >= 0,
              fileSize <= Self.maximumStoredBytes else {
            throw ClientStateStoreError.stateTooLarge
        }
        var data = try Data(contentsOf: fileURL)
        defer { data.secureWipe() }
        guard data.count <= Self.maximumStoredBytes else {
            throw ClientStateStoreError.stateTooLarge
        }
        var payload = try decryptIfNeeded(data)
        defer { payload.secureWipe() }
        guard payload.count <= Self.maximumPlaintextBytes else {
            throw ClientStateStoreError.stateTooLarge
        }
        return try NoctweaveCoder.decode(ClientState.self, from: payload)
    }

    public func save(_ state: ClientState) throws {
        let directory = fileURL.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        var payload = try NoctweaveCoder.encode(state)
        defer { payload.secureWipe() }
        guard payload.count <= Self.maximumPlaintextBytes else {
            throw ClientStateStoreError.stateTooLarge
        }
        var data = try encryptIfNeeded(payload)
        defer { data.secureWipe() }
        guard data.count <= Self.maximumStoredBytes else {
            throw ClientStateStoreError.stateTooLarge
        }
        try writeData(data)
    }

    public func warmUpKeychain() throws {
        guard useEncryption else { return }
        _ = try encryptionKey()
    }

    private func encryptIfNeeded(_ payload: Data) throws -> Data {
        guard useEncryption else {
            return payload
        }
        let key = try encryptionKey()
        let sealed = try AES.GCM.seal(payload, using: key)
        guard var combined = sealed.combined else {
            throw ClientStateStoreError.encryptionFailed
        }
        defer { combined.secureWipe() }
        let envelope = EncryptedStateEnvelope(version: 1, sealed: combined)
        return try NoctweaveCoder.encode(envelope)
    }

    private func decryptIfNeeded(_ data: Data) throws -> Data {
        guard useEncryption else {
            return data
        }
        guard let envelope = try? NoctweaveCoder.decode(EncryptedStateEnvelope.self, from: data),
              envelope.version == 1 else {
            throw ClientStateStoreError.unexpectedPlaintextInEncryptedMode
        }
        let sealed = try AES.GCM.SealedBox(combined: envelope.sealed)
        let key = try encryptionKey()
        guard let opened = try? AES.GCM.open(sealed, using: key) else {
            throw ClientStateStoreError.encryptionFailed
        }
        return opened
    }

    private func writeData(_ data: Data) throws {
        #if os(iOS)
        try data.write(to: fileURL, options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: fileURL, options: [.atomic])
        #endif
        do {
            try applyPrivacyAttributes()
        } catch {
            try? FileManager.default.removeItem(at: fileURL)
            throw error
        }
    }

    private func encryptionKey() throws -> SymmetricKey {
        if let suppliedEncryptionKey {
            return suppliedEncryptionKey
        }
        return try ClientStateKeychain.loadOrCreateKey()
    }

    private func applyPrivacyAttributes() throws {
        #if canImport(Darwin)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = fileURL
        try mutableURL.setResourceValues(values)
        #endif
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }
}

private struct EncryptedStateEnvelope: Codable {
    let version: Int
    let sealed: Data
}

private enum ClientStateStoreError: Error {
    case encryptionFailed
    case unexpectedPlaintextInEncryptedMode
    case stateTooLarge
}

#if canImport(Security)
private enum ClientStateKeychain {
    private static let service = "com.noctyra.securestorage"
    private static let account = "vault-key-v1"

    static func loadOrCreateKey() throws -> SymmetricKey {
        if let existing = try loadKey(service: service, account: account) {
            return existing
        }
        let key = SymmetricKey(size: .bits256)
        try saveKey(key, service: service, account: account)
        return key
    }

    private static func loadKey(service: String, account: String) throws -> SymmetricKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, var data = item as? Data else {
            throw ClientStateKeychainError.unavailable(status: status)
        }
        defer { data.secureWipe() }
        return SymmetricKey(data: data)
    }

    private static func saveKey(_ key: SymmetricKey, service: String, account: String) throws {
        var data = key.withUnsafeBytes { Data($0) }
        defer { data.secureWipe() }
        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        #if os(iOS)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        #endif
        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecAttrSynchronizable as String: kCFBooleanFalse as Any
            ]
            let update: [String: Any] = [
                kSecValueData as String: data
            ]
            let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            guard updateStatus == errSecSuccess else {
                throw ClientStateKeychainError.unavailable(status: updateStatus)
            }
            return
        }
        guard status == errSecSuccess else {
            throw ClientStateKeychainError.unavailable(status: status)
        }
    }
}

private enum ClientStateKeychainError: Error {
    case unavailable(status: OSStatus)
}
#else
private enum ClientStateKeychain {
    static func loadOrCreateKey() throws -> SymmetricKey {
        throw ClientStateStoreError.encryptionFailed
    }
}
#endif
