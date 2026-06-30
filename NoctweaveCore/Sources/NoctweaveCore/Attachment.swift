import CryptoKit
import Foundation

public struct AttachmentDescriptor: Codable, Equatable, Identifiable {
    public let id: UUID
    public let fileName: String?
    public let mimeType: String
    public let byteCount: Int
    public let sha256: Data
    public let chunkCount: Int
    public let chunkSize: Int

    public init(
        id: UUID = UUID(),
        fileName: String?,
        mimeType: String,
        byteCount: Int,
        sha256: Data,
        chunkCount: Int,
        chunkSize: Int
    ) {
        self.id = id
        self.fileName = fileName
        self.mimeType = mimeType
        self.byteCount = byteCount
        self.sha256 = sha256
        self.chunkCount = chunkCount
        self.chunkSize = chunkSize
    }
}

public struct AttachmentInfo: Codable, Equatable {
    public let descriptor: AttachmentDescriptor
    public var localFileName: String?
    public var relay: RelayEndpoint?
    public var cryptoContext: AttachmentCryptoContext?
    public var messageKeyData: Data?

    public init(
        descriptor: AttachmentDescriptor,
        localFileName: String? = nil,
        relay: RelayEndpoint? = nil,
        cryptoContext: AttachmentCryptoContext? = nil,
        messageKeyData: Data? = nil
    ) {
        self.descriptor = descriptor
        self.localFileName = localFileName
        self.relay = relay
        self.cryptoContext = cryptoContext
        self.messageKeyData = messageKeyData
    }
}

public struct AttachmentCryptoContext: Codable, Equatable {
    public let conversationId: String
    public let sessionId: String
    public let messageCounter: UInt64

    public init(conversationId: String, sessionId: String, messageCounter: UInt64) {
        self.conversationId = conversationId
        self.sessionId = sessionId
        self.messageCounter = messageCounter
    }
}

public enum AttachmentCrypto {
    private static let salt = Data("NOCTWEAVE-ATTACH".utf8)

    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    public static func keyData(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    public static func key(from data: Data) -> SymmetricKey {
        SymmetricKey(data: data)
    }

    public static func deriveKey(
        messageKey: SymmetricKey,
        attachmentId: UUID,
        chunkIndex: Int
    ) -> SymmetricKey {
        let info = Data("ATTACH:\(attachmentId.uuidString):\(chunkIndex)".utf8)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: messageKey,
            salt: salt,
            info: info,
            outputByteCount: 32
        )
    }

    public static func authenticatedData(
        conversationId: String,
        sessionId: String,
        messageCounter: UInt64,
        attachmentId: UUID,
        chunkIndex: Int,
        byteCount: Int
    ) -> Data {
        Data("\(conversationId):\(sessionId):\(messageCounter):\(attachmentId.uuidString):\(chunkIndex):\(byteCount)".utf8)
    }

    public static func encryptChunk(
        plaintext: Data,
        messageKey: SymmetricKey,
        attachmentId: UUID,
        chunkIndex: Int,
        authenticatedData: Data
    ) throws -> EncryptedPayload {
        let key = deriveKey(messageKey: messageKey, attachmentId: attachmentId, chunkIndex: chunkIndex)
        return try CryptoBox.encrypt(plaintext, key: key, authenticatedData: authenticatedData)
    }

    public static func decryptChunk(
        payload: EncryptedPayload,
        messageKey: SymmetricKey,
        attachmentId: UUID,
        chunkIndex: Int,
        authenticatedData: Data
    ) throws -> Data {
        let key = deriveKey(messageKey: messageKey, attachmentId: attachmentId, chunkIndex: chunkIndex)
        return try CryptoBox.decrypt(payload, key: key, authenticatedData: authenticatedData)
    }
}
