import Foundation

public struct Envelope: Codable, Identifiable, Equatable {
    public let id: UUID
    public let conversationId: String
    public let sessionId: String?
    public let senderFingerprint: String
    public let sentAt: Date
    public let messageCounter: UInt64
    public let kemCiphertext: Data?
    public let prekey: PrekeyReference?
    public let rootRatchet: RootRatchet?
    public let payload: EncryptedPayload
    public let signature: Data

    public init(
        id: UUID = UUID(),
        conversationId: String,
        sessionId: String? = nil,
        senderFingerprint: String,
        sentAt: Date,
        messageCounter: UInt64,
        kemCiphertext: Data? = nil,
        prekey: PrekeyReference? = nil,
        rootRatchet: RootRatchet? = nil,
        payload: EncryptedPayload,
        signature: Data
    ) {
        self.id = id
        self.conversationId = conversationId
        self.sessionId = sessionId
        self.senderFingerprint = senderFingerprint
        self.sentAt = sentAt
        self.messageCounter = messageCounter
        self.kemCiphertext = kemCiphertext
        self.prekey = prekey
        self.rootRatchet = rootRatchet
        self.payload = payload
        self.signature = signature
    }

    public func verifySignature(publicSigningKey: Data) -> Bool {
        guard let data = try? PICCPCoder.encode(signaturePayload, sortedKeys: true) else {
            return false
        }
        return SigningKeyPair.verify(signature: signature, data: data, publicKeyData: publicSigningKey)
    }

    public static func signableData(
        conversationId: String,
        sessionId: String?,
        senderFingerprint: String,
        sentAt: Date,
        messageCounter: UInt64,
        kemCiphertext: Data?,
        prekey: PrekeyReference?,
        rootRatchet: RootRatchet?,
        payload: EncryptedPayload
    ) throws -> Data {
        let payload = SignaturePayload(
            conversationId: conversationId,
            sessionId: sessionId,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: messageCounter,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            rootRatchet: rootRatchet,
            payload: payload
        )
        return try PICCPCoder.encode(payload, sortedKeys: true)
    }

    private var signaturePayload: SignaturePayload {
        SignaturePayload(
            conversationId: conversationId,
            sessionId: sessionId,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: messageCounter,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            rootRatchet: rootRatchet,
            payload: payload
        )
    }
}

private struct SignaturePayload: Codable {
    let conversationId: String
    let sessionId: String?
    let senderFingerprint: String
    let sentAt: Date
    let messageCounter: UInt64
    let kemCiphertext: Data?
    let prekey: PrekeyReference?
    let rootRatchet: RootRatchet?
    let payload: EncryptedPayload
}
