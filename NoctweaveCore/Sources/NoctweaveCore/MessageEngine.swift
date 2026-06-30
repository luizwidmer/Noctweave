import CryptoKit
import Foundation

public struct RootRatchetContext {
    public let ratchet: RootRatchet
    public let sharedSecret: Data

    public init(ratchet: RootRatchet, sharedSecret: Data) {
        self.ratchet = ratchet
        self.sharedSecret = sharedSecret
    }
}

public enum MessageEngine {
    public static func makeContactOffer(
        identity: Identity,
        inboxId: String,
        relay: RelayEndpoint,
        inboxAccessPublicKey: Data? = nil
    ) throws -> ContactOffer {
        try ContactOffer.create(
            displayName: identity.displayName,
            inboxId: inboxId,
            relay: relay,
            signingKey: identity.signingKey,
            agreementPublicKey: identity.agreementKey.publicKeyData,
            inboxAccessPublicKey: inboxAccessPublicKey
        )
    }

    public static func contact(from offer: ContactOffer) throws -> Contact {
        let offer = try offer.verified()
        return Contact(
            displayName: offer.displayName,
            inboxId: offer.inboxId,
            relay: offer.relay,
            signingPublicKey: offer.signingPublicKey,
            agreementPublicKey: offer.agreementPublicKey
        )
    }

    public static func createOutboundSession(
        identity: Identity,
        contact: Contact,
        recipientAgreementPublicKey: Data? = nil
    ) throws -> (conversation: Conversation, kemCiphertext: Data) {
        let publicKey = recipientAgreementPublicKey ?? contact.agreementPublicKey
        let kemOutput = try AgreementKeyPair.encapsulate(to: publicKey)
        let conversation = conversationFromSharedSecret(sharedSecret: kemOutput.sharedSecret, identity: identity, contact: contact)
        return (conversation, kemOutput.ciphertext)
    }

    public static func createInboundSession(
        identity: Identity,
        contact: Contact,
        kemCiphertext: Data,
        agreementKey: AgreementKeyPair? = nil
    ) throws -> Conversation {
        let key = agreementKey ?? identity.agreementKey
        let sharedSecret = try key.decapsulate(ciphertext: kemCiphertext)
        return conversationFromSharedSecret(sharedSecret: sharedSecret, identity: identity, contact: contact)
    }

    private static func conversationFromSharedSecret(sharedSecret: Data, identity: Identity, contact: Contact) -> Conversation {
        let (sendLabel, receiveLabel) = labelsForAgreement(ourKey: identity.agreementKey.publicKeyData, theirKey: contact.agreementPublicKey)
        let rootKey = deriveRootKey(sharedSecret: sharedSecret, priorRootKey: nil)
        let (sendKey, receiveKey) = deriveChains(rootKey: rootKey, sendLabel: sendLabel, receiveLabel: receiveLabel)
        let conversationId = conversationIdForAgreement(ourKey: identity.agreementKey.publicKeyData, theirKey: contact.agreementPublicKey)
        let sessionId = sessionIdForSharedSecret(sharedSecret)
        return Conversation(
            id: conversationId,
            contactId: contact.id,
            sessionId: sessionId,
            rootKey: rootKey,
            rootCounter: 0,
            sendChain: ChainKeyState(keyData: sendKey),
            receiveChain: ChainKeyState(keyData: receiveKey)
        )
    }

    public static func createRootRatchet(contact: Contact, conversation: Conversation) throws -> RootRatchetContext {
        let nextCounter = conversation.rootCounter + 1
        let kemOutput = try AgreementKeyPair.encapsulate(to: contact.agreementPublicKey)
        let ratchet = RootRatchet(counter: nextCounter, kemCiphertext: kemOutput.ciphertext)
        return RootRatchetContext(ratchet: ratchet, sharedSecret: kemOutput.sharedSecret)
    }

    public static func applyRootRatchet(
        sharedSecret: Data,
        counter: UInt64,
        identity: Identity,
        contact: Contact,
        conversation: inout Conversation
    ) {
        guard counter > conversation.rootCounter else {
            return
        }
        let rootKey = deriveRootKey(sharedSecret: sharedSecret, priorRootKey: conversation.rootKey)
        let (sendLabel, receiveLabel) = labelsForAgreement(
            ourKey: identity.agreementKey.publicKeyData,
            theirKey: contact.agreementPublicKey
        )
        let (sendKey, receiveKey) = deriveChains(rootKey: rootKey, sendLabel: sendLabel, receiveLabel: receiveLabel)
        conversation.rootKey = rootKey
        conversation.rootCounter = counter
        conversation.sessionId = sessionIdForSharedSecret(sharedSecret)
        conversation.sendChain = ChainKeyState(keyData: sendKey)
        conversation.receiveChain = ChainKeyState(keyData: receiveKey)
    }

    public static func encrypt(
        body: MessageBody,
        senderSigningKey: SigningKeyPair,
        senderFingerprint: String,
        conversation: inout Conversation,
        kemCiphertext: Data? = nil,
        prekey: PrekeyReference? = nil,
        rootRatchet: RootRatchet? = nil,
        authenticatedContext: MessageAuthenticatedContext? = nil,
        sentAt: Date = Date(),
        metadataBucketSeconds: Int? = nil
    ) throws -> Envelope {
        let payloadData = try PaddedMessagePlaintext.encode(body)
        let prepared = try prepareMessageKey(conversation: &conversation)
        let encrypted = try encryptPayload(
            payloadData,
            conversationId: conversation.id,
            sessionId: conversation.sessionId,
            authenticatedContext: authenticatedContext,
            messageCounter: prepared.counter,
            messageKey: prepared.key
        )
        let sentAt = MetadataMinimizer.bucketedTimestamp(sentAt, bucketSeconds: metadataBucketSeconds)
        let visibleRootRatchet = rootRatchet?.bucketed(metadataBucketSeconds: metadataBucketSeconds)
        let signable = try Envelope.signableData(
            conversationId: conversation.id,
            sessionId: conversation.sessionId,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: prepared.counter,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            rootRatchet: visibleRootRatchet,
            authenticatedContext: authenticatedContext,
            payload: encrypted
        )
        let signature = try senderSigningKey.sign(signable)
        return Envelope(
            conversationId: conversation.id,
            sessionId: conversation.sessionId,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: prepared.counter,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            rootRatchet: visibleRootRatchet,
            authenticatedContext: authenticatedContext,
            payload: encrypted,
            signature: signature
        )
    }

    public static func prepareMessageKey(
        conversation: inout Conversation
    ) throws -> (counter: UInt64, key: SymmetricKey) {
        try conversation.sendChain.nextMessageKey()
    }

    public static func encrypt(
        body: MessageBody,
        senderSigningKey: SigningKeyPair,
        senderFingerprint: String,
        conversation: Conversation,
        messageCounter: UInt64,
        messageKey: SymmetricKey,
        kemCiphertext: Data? = nil,
        prekey: PrekeyReference? = nil,
        rootRatchet: RootRatchet? = nil,
        authenticatedContext: MessageAuthenticatedContext? = nil,
        sentAt: Date = Date(),
        metadataBucketSeconds: Int? = nil
    ) throws -> Envelope {
        let payloadData = try PaddedMessagePlaintext.encode(body)
        let encrypted = try encryptPayload(
            payloadData,
            conversationId: conversation.id,
            sessionId: conversation.sessionId,
            authenticatedContext: authenticatedContext,
            messageCounter: messageCounter,
            messageKey: messageKey
        )
        let sentAt = MetadataMinimizer.bucketedTimestamp(sentAt, bucketSeconds: metadataBucketSeconds)
        let visibleRootRatchet = rootRatchet?.bucketed(metadataBucketSeconds: metadataBucketSeconds)
        let signable = try Envelope.signableData(
            conversationId: conversation.id,
            sessionId: conversation.sessionId,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: messageCounter,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            rootRatchet: visibleRootRatchet,
            authenticatedContext: authenticatedContext,
            payload: encrypted
        )
        let signature = try senderSigningKey.sign(signable)
        return Envelope(
            conversationId: conversation.id,
            sessionId: conversation.sessionId,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: messageCounter,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            rootRatchet: visibleRootRatchet,
            authenticatedContext: authenticatedContext,
            payload: encrypted,
            signature: signature
        )
    }

    public static func decrypt(
        envelope: Envelope,
        contact: Contact,
        conversation: inout Conversation
    ) throws -> MessageBody {
        let result = try decryptWithKey(envelope: envelope, contact: contact, conversation: &conversation)
        return result.body
    }

    public static func decryptWithKey(
        envelope: Envelope,
        contact: Contact,
        conversation: inout Conversation
    ) throws -> (body: MessageBody, messageKey: SymmetricKey) {
        guard envelope.conversationId == conversation.id else {
            throw CryptoError.invalidPayload
        }
        if let sessionId = envelope.sessionId {
            if conversation.sessionId != sessionId {
                throw CryptoError.invalidPayload
            }
        } else if !conversation.sessionId.isEmpty {
            throw CryptoError.invalidPayload
        }
        guard envelope.verifySignature(publicSigningKey: contact.signingPublicKey) else {
            throw CryptoError.invalidSignature
        }
        let sessionId = envelope.sessionId ?? conversation.sessionId
        let key = try conversation.receiveChain.messageKey(
            for: envelope.messageCounter,
            maxSkip: ChainKeyState.defaultMaxSkip
        )
        let authenticatedData = try authenticatedData(
            conversationId: conversation.id,
            sessionId: sessionId,
            context: envelope.authenticatedContext
        )
        let plaintext = try CryptoBox.decrypt(envelope.payload, key: key, authenticatedData: authenticatedData)
        if conversation.sessionId.isEmpty, let sessionId = envelope.sessionId {
            conversation.sessionId = sessionId
        }
        let body = try PaddedMessagePlaintext.decode(plaintext)
        return (body, key)
    }

    public static func appendMessage(
        body: MessageBody,
        direction: MessageDirection,
        counter: UInt64,
        timestamp: Date,
        conversation: inout Conversation
    ) -> Message? {
        switch body {
        case .text(let text):
            let message = Message(direction: direction, body: text, timestamp: timestamp, counter: counter)
            conversation.messages.append(message)
            return message
        case .attachment(let descriptor):
            let title = descriptor.fileName?.isEmpty == false ? descriptor.fileName! : "Image"
            let message = Message(
                direction: direction,
                body: title,
                timestamp: timestamp,
                counter: counter,
                attachment: AttachmentInfo(descriptor: descriptor)
            )
            conversation.messages.append(message)
            return message
        case .identityRotation:
            return nil
        case .identityReset:
            return nil
        case .sessionReset:
            return nil
        case .resendRequest:
            return nil
        }
    }

    private static func deriveRootKey(sharedSecret: Data, priorRootKey: Data?) -> Data {
        let salt: Data
        if let priorRootKey, !priorRootKey.isEmpty {
            salt = priorRootKey
        } else {
            salt = Data("NOCTWEAVE-ROOT".utf8)
        }
        return CryptoBox.deriveChainKey(sharedSecret: sharedSecret, salt: salt, info: Data("ROOT".utf8))
    }

    private static func deriveChains(rootKey: Data, sendLabel: String, receiveLabel: String) -> (Data, Data) {
        let salt = Data("NOCTWEAVE-CHAIN".utf8)
        let sendKey = CryptoBox.deriveChainKey(sharedSecret: rootKey, salt: salt, info: Data(sendLabel.utf8))
        let receiveKey = CryptoBox.deriveChainKey(sharedSecret: rootKey, salt: salt, info: Data(receiveLabel.utf8))
        return (sendKey, receiveKey)
    }

    public static func conversationIdForAgreement(ourKey: Data, theirKey: Data) -> String {
        let ordered = [ourKey, theirKey].sorted(by: { $0.lexicographicallyPrecedes($1) })
        let combined = ordered[0] + ordered[1]
        let hash = SHA256.hash(data: combined)
        return Data(hash).base64EncodedString()
    }

    private static func sessionIdForSharedSecret(_ sharedSecret: Data) -> String {
        let label = Data("NOCTWEAVE-SESSION".utf8)
        let hash = SHA256.hash(data: label + sharedSecret)
        return Data(hash).base64EncodedString()
    }

    private static func authenticatedData(
        conversationId: String,
        sessionId: String,
        context: MessageAuthenticatedContext?
    ) throws -> Data {
        let payload = MessageAuthenticatedDataPayload(
            version: 1,
            conversationId: conversationId,
            sessionId: sessionId,
            context: context
        )
        return try NoctweaveCoder.encode(payload, sortedKeys: true)
    }

    private static func encryptPayload(
        _ payload: Data,
        conversationId: String,
        sessionId: String,
        authenticatedContext: MessageAuthenticatedContext?,
        messageCounter: UInt64,
        messageKey: SymmetricKey
    ) throws -> EncryptedPayload {
        let authenticatedData = try authenticatedData(
            conversationId: conversationId,
            sessionId: sessionId,
            context: authenticatedContext
        )
        return try CryptoBox.encrypt(payload, key: messageKey, authenticatedData: authenticatedData)
    }

    private static func labelsForAgreement(ourKey: Data, theirKey: Data) -> (String, String) {
        if ourKey.lexicographicallyPrecedes(theirKey) {
            return ("A", "B")
        }
        return ("B", "A")
    }
}

private struct MessageAuthenticatedDataPayload: Codable {
    let version: Int
    let conversationId: String
    let sessionId: String
    let context: MessageAuthenticatedContext?
}
