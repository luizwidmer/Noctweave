import CryptoKit
import Foundation

public enum MessageEngine {
    public static func pairwiseBinding(
        for relationship: PairwiseRelationshipV2
    ) throws -> PairwiseEndpointBindingV4 {
        guard relationship.isStructurallyValid else {
            throw CryptoError.invalidPayload
        }
        return try PairwiseEndpointBindingV4.create(
            relationshipId: relationship.id,
            localEndpointHandle: relationship.localEndpointHandle,
            peerEndpointHandle: relationship.peerIdentity.sendRoutes.ownerEndpointHandle,
            localEndpoint: relationship.localIdentity.endpointBinding,
            peerEndpoint: relationship.peerIdentity.endpointBinding
        )
    }

    public static func createOutboundEndpointSession(
        relationship: PairwiseRelationshipV2,
        now: Date = Date()
    ) throws -> (
        conversation: Conversation,
        kemCiphertext: Data,
        prekey: PrekeyReference
    ) {
        guard relationship.isStructurallyValid else { throw CryptoError.invalidPayload }
        let local = relationship.localIdentity
        let peerEndpoint = relationship.peerIdentity.endpointBinding
        let binding = try pairwiseBinding(for: relationship)
        let negotiation = try binding.validatedNegotiation(
            localEndpoint: local.endpointBinding,
            peerEndpoint: peerEndpoint
        )
        let signedPrekey = peerEndpoint.prekeyBundle.signedPrekey
        guard signedPrekey.verify(using: peerEndpoint.signingPublicKey) else {
            throw CryptoError.invalidSignature
        }
        try validateNegotiatedPrekeyFreshness(
            signedPrekey,
            negotiation: negotiation,
            now: now
        )
        var kemOutput = try AgreementKeyPair.encapsulate(to: signedPrekey.publicKey)
        defer { kemOutput.sharedSecret.secureWipe() }
        return (
            conversation: conversationFromSharedSecret(
                sharedSecret: kemOutput.sharedSecret,
                relationship: relationship,
                binding: binding
            ),
            kemCiphertext: kemOutput.ciphertext,
            prekey: PrekeyReference(kind: .signed, id: signedPrekey.id)
        )
    }

    public static func createInboundEndpointSession(
        relationship: PairwiseRelationshipV2,
        bootstrap: DirectBootstrapV4,
        now: Date = Date()
    ) throws -> Conversation {
        guard relationship.isStructurallyValid,
              let material = bootstrap.signedPrekeyMaterial else {
            throw CryptoError.invalidPayload
        }
        let local = relationship.localIdentity
        let binding = try pairwiseBinding(for: relationship)
        let negotiation = try binding.validatedNegotiation(
            localEndpoint: local.endpointBinding,
            peerEndpoint: relationship.peerIdentity.endpointBinding
        )
        guard material.prekey.kind == .signed,
              let advertised = local.localEndpoint.prekeys.signedPrekey(id: material.prekey.id),
              advertised.verify(using: local.localEndpoint.signingKey.publicKeyData),
              let prekeyKey = local.localEndpoint.prekeys.signedPrekeyKeyPair(
                id: material.prekey.id,
                now: now
              ) else {
            throw CryptoError.invalidPayload
        }
        try validateNegotiatedPrekeyFreshness(advertised, negotiation: negotiation, now: now)
        var sharedSecret = try prekeyKey.decapsulate(ciphertext: material.kemCiphertext)
        defer { sharedSecret.secureWipe() }
        return conversationFromSharedSecret(
            sharedSecret: sharedSecret,
            relationship: relationship,
            binding: binding
        )
    }

    public static func prepareMessageKey(
        conversation: inout Conversation
    ) throws -> (counter: UInt64, key: SymmetricKey) {
        try conversation.sendChain.nextMessageKey()
    }

    public static func encryptDirectV4(
        wirePayload: WirePayloadV2,
        eventID: UUID,
        relationship: PairwiseRelationshipV2,
        conversation: inout Conversation,
        bootstrap: DirectBootstrapV4 = .none,
        sentAt: Date,
        metadataBucketSeconds: Int? = nil
    ) throws -> DirectEnvelopeV4 {
        guard relationship.id == conversation.relationshipID else {
            throw CryptoError.invalidPayload
        }
        var candidate = conversation
        let prepared = try prepareMessageKey(conversation: &candidate)
        let envelope = try encryptDirectV4(
            wirePayload: wirePayload,
            eventID: eventID,
            relationship: relationship,
            conversation: candidate,
            messageCounter: prepared.counter,
            messageKey: prepared.key,
            bootstrap: bootstrap,
            sentAt: sentAt,
            metadataBucketSeconds: metadataBucketSeconds
        )
        conversation.sendChain = candidate.sendChain
        return envelope
    }

    public static func encryptDirectV4(
        wirePayload: WirePayloadV2,
        eventID: UUID,
        relationship: PairwiseRelationshipV2,
        conversation: Conversation,
        messageCounter: UInt64,
        messageKey: SymmetricKey,
        bootstrap: DirectBootstrapV4 = .none,
        sentAt: Date,
        metadataBucketSeconds: Int? = nil
    ) throws -> DirectEnvelopeV4 {
        let local = relationship.localIdentity
        let peerEndpoint = relationship.peerIdentity.endpointBinding
        let binding = try pairwiseBinding(for: relationship)
        let negotiation = try binding.validatedNegotiation(
            localEndpoint: local.endpointBinding,
            peerEndpoint: peerEndpoint
        )
        let visibleSentAt = MetadataMinimizer.bucketedTimestamp(
            sentAt,
            bucketSeconds: metadataBucketSeconds
        )
        try wirePayload.validateDirectV4(
            eventId: eventID,
            senderEndpointHandle: relationship.localEndpointHandle,
            conversationId: relationship.conversationID,
            sentAt: visibleSentAt,
            signingPublicKey: local.localEndpoint.signingKey.publicKeyData
        )
        try validateOutbound(
            relationship: relationship,
            conversation: conversation,
            binding: binding,
            negotiation: negotiation,
            bootstrap: bootstrap
        )
        var plaintext = try PaddedMessagePlaintext.encodeWirePayloadV2(wirePayload)
        defer { plaintext.secureWipe() }
        let envelopeID = UUID()
        let authenticatedData = try DirectEnvelopeV4.authenticatedData(
            id: envelopeID,
            conversationId: relationship.conversationID,
            sessionId: conversation.sessionId,
            eventId: eventID,
            senderEndpointHandle: binding.localEndpointHandle,
            senderBindingDigest: binding.localBindingReferenceDigest,
            recipientEndpointHandle: binding.peerEndpointHandle,
            recipientBindingDigest: binding.peerBindingReferenceDigest,
            cipherSuite: negotiation.cipherSuite,
            negotiatedCapabilitiesDigest: try negotiation.digest(),
            bootstrap: bootstrap,
            sentAt: visibleSentAt,
            messageCounter: messageCounter
        )
        let encrypted = try CryptoBox.encrypt(
            plaintext,
            key: messageKey,
            authenticatedData: authenticatedData
        )
        var envelope = DirectEnvelopeV4(
            id: envelopeID,
            conversationId: relationship.conversationID,
            sessionId: conversation.sessionId,
            eventId: eventID,
            senderEndpointHandle: binding.localEndpointHandle,
            senderBindingDigest: binding.localBindingReferenceDigest,
            recipientEndpointHandle: binding.peerEndpointHandle,
            recipientBindingDigest: binding.peerBindingReferenceDigest,
            cipherSuite: negotiation.cipherSuite,
            negotiatedCapabilitiesDigest: try negotiation.digest(),
            bootstrap: bootstrap,
            sentAt: visibleSentAt,
            messageCounter: messageCounter,
            payload: encrypted,
            signature: Data()
        )
        envelope = DirectEnvelopeV4(
            id: envelope.id,
            conversationId: envelope.conversationId,
            sessionId: envelope.sessionId,
            eventId: envelope.eventId,
            senderEndpointHandle: envelope.senderEndpointHandle,
            senderBindingDigest: envelope.senderBindingDigest,
            recipientEndpointHandle: envelope.recipientEndpointHandle,
            recipientBindingDigest: envelope.recipientBindingDigest,
            cipherSuite: envelope.cipherSuite,
            negotiatedCapabilitiesDigest: envelope.negotiatedCapabilitiesDigest,
            bootstrap: envelope.bootstrap,
            sentAt: envelope.sentAt,
            messageCounter: envelope.messageCounter,
            payload: envelope.payload,
            signature: try local.localEndpoint.signingKey.sign(envelope.signableData())
        )
        guard envelope.isStructurallyValid else { throw CryptoError.invalidPayload }
        return envelope
    }

    public static func decryptDirectV4(
        envelope: DirectEnvelopeV4,
        relationship: PairwiseRelationshipV2,
        conversation: inout Conversation
    ) throws -> DirectV4DecryptionResultV2 {
        let local = relationship.localIdentity
        let peerEndpoint = relationship.peerIdentity.endpointBinding
        let binding = try pairwiseBinding(for: relationship)
        let negotiation = try binding.validatedNegotiation(
            localEndpoint: local.endpointBinding,
            peerEndpoint: peerEndpoint
        )
        let negotiationDigest = try negotiation.digest()
        let session = conversation.endpointSession
        guard relationship.id == conversation.relationshipID,
              envelope.conversationId == relationship.conversationID,
              envelope.sessionId == conversation.sessionId,
              envelope.cipherSuite == negotiation.cipherSuite,
              envelope.negotiatedCapabilitiesDigest == negotiationDigest,
              envelope.recipientEndpointHandle == relationship.localEndpointHandle,
              envelope.recipientBindingDigest == binding.localBindingReferenceDigest,
              envelope.senderEndpointHandle == binding.peerEndpointHandle,
              envelope.senderBindingDigest == binding.peerBindingReferenceDigest,
              session.relationshipID == relationship.id,
              session.localEndpointHandle == binding.localEndpointHandle,
              session.localBindingReferenceDigest == binding.localBindingReferenceDigest,
              session.peerEndpointHandle == binding.peerEndpointHandle,
              session.peerBindingReferenceDigest == binding.peerBindingReferenceDigest,
              UInt64(envelope.payload.ciphertext.count)
                <= negotiation.limit(module: "nw.direct", name: "maxCiphertextBytes") ?? 0 else {
            throw CryptoError.invalidPayload
        }
        var candidate = conversation
        let decrypted = try decryptWirePayload(
            envelope: envelope,
            signingPublicKey: peerEndpoint.signingPublicKey,
            conversation: &candidate
        )
        try validateNegotiatedWirePayloadLimits(decrypted.payload, negotiation: negotiation)
        let disposition: DirectV4PayloadDispositionV2
        switch decrypted.payload.kind {
        case .application:
            guard let event = decrypted.payload.application else {
                throw WirePayloadV2Error.invalidApplicationEvent
            }
            disposition = .application(event, try decrypted.payload.applicationProjection())
        case .control:
            disposition = try decrypted.payload.controlDisposition(
                conversationId: relationship.conversationID,
                eventId: envelope.eventId,
                senderEndpointHandle: envelope.senderEndpointHandle,
                receivedAt: envelope.sentAt,
                signingPublicKey: peerEndpoint.signingPublicKey
            )
        }
        conversation = candidate
        return DirectV4DecryptionResultV2(
            disposition: disposition,
            messageKey: decrypted.messageKey
        )
    }

    @discardableResult
    public static func appendMessage(
        id: UUID,
        body: MessageBody,
        direction: MessageDirection,
        counter: UInt64,
        timestamp: Date,
        conversation: inout Conversation,
        attachmentRelay: RelayEndpoint? = nil,
        messageKey: SymmetricKey? = nil
    ) -> Message {
        let message: Message
        switch body {
        case .text(let text):
            message = Message(
                id: id,
                direction: direction,
                body: text,
                timestamp: timestamp,
                counter: counter
            )
        case .attachment(let descriptor):
            message = Message(
                id: id,
                direction: direction,
                body: attachmentTitle(for: descriptor),
                timestamp: timestamp,
                counter: counter,
                attachment: AttachmentInfo(
                    descriptor: descriptor,
                    relay: attachmentRelay,
                    cryptoContext: AttachmentCryptoContext(
                        conversationId: conversation.id,
                        sessionId: conversation.sessionId,
                        messageCounter: counter
                    ),
                    messageKeyData: messageKey.map(AttachmentCrypto.keyData)
                )
            )
        }
        conversation.messages.append(message)
        return message
    }

    private static func conversationFromSharedSecret(
        sharedSecret: Data,
        relationship: PairwiseRelationshipV2,
        binding: PairwiseEndpointBindingV4
    ) -> Conversation {
        let local = relationship.localIdentity.endpointBinding
        let peer = relationship.peerIdentity.endpointBinding
        let rootKey = deriveRootKey(
            sharedSecret: sharedSecret,
            relationshipID: relationship.id,
            binding: binding
        )
        let labels = labelsForAgreement(
            ourKey: local.agreementPublicKey,
            theirKey: peer.agreementPublicKey
        )
        let chains = deriveChains(
            rootKey: rootKey,
            sendLabel: labels.0,
            receiveLabel: labels.1
        )
        let session = DirectEndpointSessionIdentity(
            relationshipID: relationship.id,
            localEndpointHandle: binding.localEndpointHandle,
            localBindingReferenceDigest: binding.localBindingReferenceDigest,
            peerEndpointHandle: binding.peerEndpointHandle,
            peerBindingReferenceDigest: binding.peerBindingReferenceDigest
        )
        return Conversation(
            id: relationship.conversationID,
            relationshipID: relationship.id,
            endpointSession: session,
            sessionId: directV4SessionID(rootKey: rootKey, binding: binding),
            rootKey: rootKey,
            sendChain: ChainKeyState(keyData: chains.0),
            receiveChain: ChainKeyState(keyData: chains.1)
        )
    }

    private static func decryptWirePayload(
        envelope: DirectEnvelopeV4,
        signingPublicKey: Data,
        conversation: inout Conversation
    ) throws -> (payload: WirePayloadV2, messageKey: SymmetricKey) {
        guard envelope.payloadFormat == NoctweaveWirePayloadV2.directV4Format,
              envelope.verifySignature(publicSigningKey: signingPublicKey) else {
            throw CryptoError.invalidSignature
        }
        var receiveChain = conversation.receiveChain
        let key = try receiveChain.messageKey(
            for: envelope.messageCounter,
            maxSkip: ChainKeyState.defaultMaxSkip
        )
        var plaintext = try CryptoBox.decrypt(
            envelope.payload,
            key: key,
            authenticatedData: try envelope.authenticatedData()
        )
        defer { plaintext.secureWipe() }
        let payload = try PaddedMessagePlaintext.decodeWirePayloadV2(plaintext)
        try payload.validateDirectV4(
            eventId: envelope.eventId,
            senderEndpointHandle: envelope.senderEndpointHandle,
            conversationId: envelope.conversationId,
            sentAt: envelope.sentAt,
            signingPublicKey: signingPublicKey
        )
        conversation.receiveChain = receiveChain
        return (payload, key)
    }

    private static func validateOutbound(
        relationship: PairwiseRelationshipV2,
        conversation: Conversation,
        binding: PairwiseEndpointBindingV4,
        negotiation: DirectV4NegotiatedCapabilityManifest,
        bootstrap: DirectBootstrapV4
    ) throws {
        let session = conversation.endpointSession
        guard relationship.isStructurallyValid,
              conversation.isStructurallyValid,
              conversation.relationshipID == relationship.id,
              binding.relationshipId == relationship.id,
              binding.isStructurallyValid,
              bootstrap.isStructurallyValid,
              binding.localEndpointHandle == session.localEndpointHandle,
              binding.localBindingReferenceDigest == session.localBindingReferenceDigest,
              binding.peerEndpointHandle == session.peerEndpointHandle,
              binding.peerBindingReferenceDigest == session.peerBindingReferenceDigest,
              conversation.sessionId == directV4SessionID(rootKey: conversation.rootKey, binding: binding),
              negotiation.cipherSuite == binding.cipherSuite else {
            throw DirectV4CapabilityNegotiationError.transcriptMismatch
        }
    }

    private static func validateNegotiatedPrekeyFreshness(
        _ prekey: SignedPrekey,
        negotiation: DirectV4NegotiatedCapabilityManifest,
        now: Date
    ) throws {
        guard let seconds = negotiation.limit(
            module: "nw.direct",
            name: "maxPrekeyAgeSeconds"
        ), prekey.isFresh(at: now),
           prekey.issuedAt >= now.addingTimeInterval(-TimeInterval(seconds)),
           prekey.issuedAt <= now.addingTimeInterval(PrekeyBundle.maximumFutureClockSkew) else {
            throw CryptoError.invalidPayload
        }
    }

    private static func validateNegotiatedWirePayloadLimits(
        _ payload: WirePayloadV2,
        negotiation: DirectV4NegotiatedCapabilityManifest
    ) throws {
        guard let event = payload.application else { return }
        let content = event.content
        guard let maxParameters = negotiation.limit(module: "nw.core", name: "maxContentParameters"),
              let maxParameterBytes = negotiation.limit(module: "nw.core", name: "maxContentParameterBytes"),
              let maxPayloadBytes = negotiation.limit(module: "nw.core", name: "maxContentPayloadBytes"),
              let maxFallbackBytes = negotiation.limit(module: "nw.core", name: "maxFallbackBytes"),
              UInt64(content.parameters.count) <= maxParameters,
              UInt64(content.payload.count) <= maxPayloadBytes,
              UInt64(content.fallbackText?.utf8.count ?? 0) <= maxFallbackBytes,
              content.parameters.allSatisfy({ key, value in
                  UInt64(key.utf8.count) <= maxParameterBytes
                    && UInt64(value.utf8.count) <= maxParameterBytes
              }) else {
            throw CryptoError.invalidPayload
        }
    }

    private static func deriveRootKey(
        sharedSecret: Data,
        relationshipID: UUID,
        binding: PairwiseEndpointBindingV4
    ) -> Data {
        var info = Data("Noctweave/direct-v4/root".utf8)
        info.append(Data(relationshipID.uuidString.lowercased().utf8))
        info.append(binding.negotiatedCapabilitiesDigest)
        return CryptoBox.deriveChainKey(
            sharedSecret: sharedSecret,
            salt: Data("NOCTWEAVE-ROOT".utf8),
            info: info
        )
    }

    private static func deriveChains(
        rootKey: Data,
        sendLabel: String,
        receiveLabel: String
    ) -> (Data, Data) {
        let salt = Data("NOCTWEAVE-CHAIN".utf8)
        return (
            CryptoBox.deriveChainKey(
                sharedSecret: rootKey,
                salt: salt,
                info: Data(sendLabel.utf8)
            ),
            CryptoBox.deriveChainKey(
                sharedSecret: rootKey,
                salt: salt,
                info: Data(receiveLabel.utf8)
            )
        )
    }

    private static func directV4SessionID(
        rootKey: Data,
        binding: PairwiseEndpointBindingV4
    ) -> String {
        var material = Data("NOCTWEAVE-SESSION".utf8)
        material.append(Data(binding.relationshipId.uuidString.lowercased().utf8))
        material.append(Data(binding.cipherSuite.utf8))
        material.append(binding.negotiatedCapabilitiesDigest)
        material.append(rootKey)
        return Data(SHA256.hash(data: material)).base64EncodedString()
    }

    private static func labelsForAgreement(
        ourKey: Data,
        theirKey: Data
    ) -> (String, String) {
        ourKey.lexicographicallyPrecedes(theirKey) ? ("A", "B") : ("B", "A")
    }

    private static func attachmentTitle(for descriptor: AttachmentDescriptor) -> String {
        let mimeType = descriptor.mimeType
            .split(separator: ";", maxSplits: 1)
            .first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() ?? descriptor.mimeType.lowercased()
        if mimeType.hasPrefix("audio/") { return "Voice message" }
        if mimeType.hasPrefix("image/") { return "Image" }
        return "Attachment"
    }
}
