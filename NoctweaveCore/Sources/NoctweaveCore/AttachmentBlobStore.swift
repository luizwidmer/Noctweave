import CryptoKit
import Foundation

public enum AttachmentBlobStoreError: Error {
    case invalidEndpoint
    case uploadFailed(String)
    case fetchFailed(String)
    case digestMismatch
}

public struct AttachmentExternalRecord: Codable, Equatable {
    public let backend: String
    public let locator: String
    public let byteCount: Int
    public let sha256Hex: String
    public let expiresAt: Date

    public init(backend: String, locator: String, byteCount: Int, sha256Hex: String, expiresAt: Date) {
        self.backend = backend
        self.locator = locator
        self.byteCount = byteCount
        self.sha256Hex = sha256Hex
        self.expiresAt = expiresAt
    }
}

public protocol AttachmentBlobStore {
    var backendName: String { get }

    func put(_ data: Data, attachmentId: UUID, chunkIndex: Int, expiresAt: Date) throws -> AttachmentExternalRecord
    func get(_ record: AttachmentExternalRecord) throws -> Data
    func delete(_ record: AttachmentExternalRecord)
}

public enum AttachmentBlobDigest {
    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
