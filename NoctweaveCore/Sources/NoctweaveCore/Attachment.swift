import CryptoKit
import Foundation

public struct AttachmentDescriptor: Codable, Equatable, Identifiable {
    public static let maximumTransportBytes = 8 * 1024 * 1024
    public static let maximumTransportChunks = 128
    public static let maximumTransportChunkBytes = 64 * 1024
    public let id: UUID
    public let fileName: String?
    public let mimeType: String
    public let byteCount: Int
    public let sha256: Data
    public let chunkCount: Int
    public let chunkSize: Int
    public let relayTTLSeconds: Int?

    public init(
        id: UUID = UUID(),
        fileName: String?,
        mimeType: String,
        byteCount: Int,
        sha256: Data,
        chunkCount: Int,
        chunkSize: Int,
        relayTTLSeconds: Int? = nil
    ) {
        self.id = id
        self.fileName = fileName
        self.mimeType = mimeType
        self.byteCount = byteCount
        self.sha256 = sha256
        self.chunkCount = chunkCount
        self.chunkSize = chunkSize
        self.relayTTLSeconds = relayTTLSeconds
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case fileName
        case mimeType
        case byteCount
        case sha256
        case chunkCount
        case chunkSize
        case relayTTLSeconds
    }

    public init(from decoder: Decoder) throws {
        try requireExactAttachmentFields(
            decoder,
            CodingKeys.self,
            context: "attachment descriptor"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        fileName = try container.decodeIfPresent(String.self, forKey: .fileName)
        mimeType = try container.decode(String.self, forKey: .mimeType)
        byteCount = try container.decode(Int.self, forKey: .byteCount)
        sha256 = try container.decode(Data.self, forKey: .sha256)
        chunkCount = try container.decode(Int.self, forKey: .chunkCount)
        chunkSize = try container.decode(Int.self, forKey: .chunkSize)
        relayTTLSeconds = try container.decodeIfPresent(Int.self, forKey: .relayTTLSeconds)
        guard isStructurallyValid() else {
            throw DecodingError.dataCorruptedError(
                forKey: .id,
                in: container,
                debugDescription: "Attachment descriptor is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid() else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Attachment descriptor is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        if let fileName {
            try container.encode(fileName, forKey: .fileName)
        } else {
            try container.encodeNil(forKey: .fileName)
        }
        try container.encode(mimeType, forKey: .mimeType)
        try container.encode(byteCount, forKey: .byteCount)
        try container.encode(sha256, forKey: .sha256)
        try container.encode(chunkCount, forKey: .chunkCount)
        try container.encode(chunkSize, forKey: .chunkSize)
        if let relayTTLSeconds {
            try container.encode(relayTTLSeconds, forKey: .relayTTLSeconds)
        } else {
            try container.encodeNil(forKey: .relayTTLSeconds)
        }
    }

    public func isStructurallyValid(
        maximumBytes: Int = AttachmentDescriptor.maximumTransportBytes,
        maximumChunks: Int = AttachmentDescriptor.maximumTransportChunks,
        maximumChunkBytes: Int = AttachmentDescriptor.maximumTransportChunkBytes
    ) -> Bool {
        guard fileName == nil,
              byteCount > 0,
              byteCount <= maximumBytes,
              chunkSize > 0,
              chunkSize <= maximumChunkBytes,
              chunkCount > 0,
              chunkCount <= maximumChunks,
              sha256.count == 32 else {
            return false
        }
        let expectedChunkCount = (byteCount / chunkSize) + (byteCount % chunkSize == 0 ? 0 : 1)
        guard expectedChunkCount == chunkCount else { return false }
        let normalizedMIME = mimeType.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedMIME.isEmpty,
              normalizedMIME.utf8.count <= 128,
              normalizedMIME.utf8.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e && $0 != 0x3b }) else {
            return false
        }
        if let relayTTLSeconds, relayTTLSeconds <= 0 {
            return false
        }
        return true
    }
}

public struct AttachmentInfo: Codable, Equatable {
    public let descriptor: AttachmentDescriptor
    public var localFileName: String?
    public var relay: RelayEndpoint?
    public var cryptoContext: AttachmentCryptoContext?
    public var messageKeyData: Data?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case descriptor
        case localFileName
        case relay
        case cryptoContext
        case messageKeyData
    }

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

    public init(from decoder: Decoder) throws {
        try requireExactAttachmentFields(
            decoder,
            CodingKeys.self,
            context: "attachment information"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        descriptor = try container.decode(AttachmentDescriptor.self, forKey: .descriptor)
        localFileName = try container.decodeIfPresent(String.self, forKey: .localFileName)
        relay = try container.decodeIfPresent(RelayEndpoint.self, forKey: .relay)
        cryptoContext = try container.decodeIfPresent(
            AttachmentCryptoContext.self,
            forKey: .cryptoContext
        )
        messageKeyData = try container.decodeIfPresent(Data.self, forKey: .messageKeyData)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .descriptor,
                in: container,
                debugDescription: "Attachment information is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Attachment information is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(descriptor, forKey: .descriptor)
        if let localFileName {
            try container.encode(localFileName, forKey: .localFileName)
        } else {
            try container.encodeNil(forKey: .localFileName)
        }
        if let relay {
            try container.encode(relay, forKey: .relay)
        } else {
            try container.encodeNil(forKey: .relay)
        }
        if let cryptoContext {
            try container.encode(cryptoContext, forKey: .cryptoContext)
        } else {
            try container.encodeNil(forKey: .cryptoContext)
        }
        if let messageKeyData {
            try container.encode(messageKeyData, forKey: .messageKeyData)
        } else {
            try container.encodeNil(forKey: .messageKeyData)
        }
    }

    public var isStructurallyValid: Bool {
        descriptor.isStructurallyValid()
            && (localFileName.map(Self.isValidLocalFileName) ?? true)
            && relay?.isStructurallyValidRelationshipRouteEndpointV2 != false
            && cryptoContext?.isStructurallyValid != false
            && (messageKeyData.map({ $0.count == 32 }) ?? true)
    }

    private static func isValidLocalFileName(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.count <= 255
            && value != "."
            && value != ".."
            && !value.contains("/")
            && !value.contains("\\")
            && value.unicodeScalars.allSatisfy {
                !CharacterSet.controlCharacters.contains($0)
            }
    }
}

public struct AttachmentCryptoContext: Codable, Equatable {
    public let conversationId: String
    public let sessionId: String
    public let messageCounter: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case conversationId
        case sessionId
        case messageCounter
    }

    public init(conversationId: String, sessionId: String, messageCounter: UInt64) {
        self.conversationId = conversationId
        self.sessionId = sessionId
        self.messageCounter = messageCounter
    }

    public init(from decoder: Decoder) throws {
        try requireExactAttachmentFields(
            decoder,
            CodingKeys.self,
            context: "attachment cryptographic context"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        conversationId = try container.decode(String.self, forKey: .conversationId)
        sessionId = try container.decode(String.self, forKey: .sessionId)
        messageCounter = try container.decode(UInt64.self, forKey: .messageCounter)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .conversationId,
                in: container,
                debugDescription: "Attachment cryptographic context is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Attachment cryptographic context is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(conversationId, forKey: .conversationId)
        try container.encode(sessionId, forKey: .sessionId)
        try container.encode(messageCounter, forKey: .messageCounter)
    }

    public var isStructurallyValid: Bool {
        Self.isValidIdentifier(conversationId) && Self.isValidIdentifier(sessionId)
    }

    private static func isValidIdentifier(_ value: String) -> Bool {
        !value.isEmpty
            && value == value.trimmingCharacters(in: .whitespacesAndNewlines)
            && value.utf8.count <= 256
            && value.unicodeScalars.allSatisfy {
                !CharacterSet.controlCharacters.contains($0)
            }
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

private struct AttachmentCodingKey: CodingKey {
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

private func requireExactAttachmentFields<Keys: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _: Keys.Type,
    context: String
) throws where Keys.AllCases: Collection {
    let strict = try decoder.container(keyedBy: AttachmentCodingKey.self)
    let expected = Set(Keys.allCases.map(\.stringValue))
    guard Set(strict.allKeys.map(\.stringValue)) == expected else {
        throw DecodingError.dataCorrupted(
            DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: "Fields must match the current \(context) schema exactly"
            )
        )
    }
}
