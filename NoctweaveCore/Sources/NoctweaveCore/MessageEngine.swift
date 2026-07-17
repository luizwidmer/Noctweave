import CryptoKit
import Foundation

public enum MessageEngine {
    public static func makeCertifiedContactOffer(
        identity: Identity,
        identityGenerationId: UUID,
        localEndpoint: LocalEndpointState,
        endpointSetManifest: EndpointSetManifest,
        inboxId: String,
        relay: RelayEndpoint,
        inboxAccessPublicKey: Data? = nil,
        issuedAt: Date = Date()
    ) throws -> ContactOffer {
        let endpoint = try CertifiedGenerationEndpoint.create(
            identity: identity,
            endpoint: localEndpoint,
            manifest: endpointSetManifest,
            issuedAt: issuedAt
        )
        return try ContactOffer.createCertified(
            displayName: identity.displayName,
            inboxId: inboxId,
            relay: relay,
            identity: identity,
            identityGenerationId: identityGenerationId,
            endpointSetManifest: endpointSetManifest,
            preferredGenerationEndpoint: endpoint,
            inboxAccessPublicKey: inboxAccessPublicKey
        )
    }

    public static func contact(from offer: ContactOffer) throws -> Contact {
        let offer = try offer.verified()
        guard offer.version == CertifiedGenerationEndpoint.version,
              offer.identityGenerationId != nil,
              offer.endpointSetCheckpoint != nil,
              offer.preferredGenerationEndpoint != nil else {
            throw ContactOfferError.invalidStructure
        }
        return Contact(
            displayName: offer.displayName,
            inboxId: offer.inboxId,
            relay: offer.relay,
            signingPublicKey: offer.signingPublicKey,
            agreementPublicKey: offer.agreementPublicKey,
            identityGenerationId: offer.identityGenerationId,
            endpointSetCheckpoint: offer.endpointSetCheckpoint,
            preferredGenerationEndpoint: offer.preferredGenerationEndpoint,
            endpointAuthoritySigningPublicKey: offer.signingPublicKey
        )
    }

    public static func createOutboundEndpointSession(
        localEndpoint: LocalEndpointState,
        localCertificate: CertifiedGenerationEndpoint,
        pairwiseBinding: PairwiseEndpointBindingV4,
        contact: Contact,
        now: Date = Date()
    ) throws -> (conversation: Conversation, kemCiphertext: Data, prekey: PrekeyReference) {
        let peerEndpoint = try contact.certifiedGenerationEndpoint()
        let negotiation = try pairwiseBinding.validatedNegotiation(
            localEndpoint: localCertificate,
            peerEndpoint: peerEndpoint
        )
        guard localCertificate.endpointId == localEndpoint.id,
              localCertificate.signingPublicKey == localEndpoint.signingKey.publicKeyData,
              localCertificate.agreementPublicKey == localEndpoint.agreementKey.publicKeyData,
              pairwiseBinding.isStructurallyValid,
              peerEndpoint.prekeyBundle.isStructurallyValid(now: now) else {
            throw CryptoError.invalidPayload
        }
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
        let endpointSession = DirectEndpointSessionIdentity(
            contactId: contact.id,
            localEndpointId: localEndpoint.id,
            localEndpointHandle: pairwiseBinding.localEndpointHandle,
            localCertificateReferenceDigest: pairwiseBinding.localCertificateReferenceDigest,
            localManifestEpoch: localCertificate.manifestEpoch,
            peerEndpointId: peerEndpoint.endpointId,
            peerEndpointHandle: pairwiseBinding.peerEndpointHandle,
            peerCertificateReferenceDigest: pairwiseBinding.peerCertificateReferenceDigest,
            peerManifestEpoch: peerEndpoint.manifestEpoch
        )
        let conversation = conversationFromSharedSecret(
            sharedSecret: kemOutput.sharedSecret,
            ourAgreementPublicKey: localEndpoint.agreementKey.publicKeyData,
            theirAgreementPublicKey: peerEndpoint.agreementPublicKey,
            contactId: contact.id,
            endpointSession: endpointSession,
            directV4Binding: pairwiseBinding,
            conversationId: conversationIdForEndpoints(
                localCertificate,
                peerEndpoint,
                pairwiseBinding: pairwiseBinding
            )
        )
        return (
            conversation,
            kemOutput.ciphertext,
            PrekeyReference(kind: .signed, id: signedPrekey.id)
        )
    }

    public static func createInboundEndpointSession(
        localEndpoint: LocalEndpointState,
        localCertificate: CertifiedGenerationEndpoint,
        senderEndpoint: CertifiedGenerationEndpoint,
        pairwiseBinding: PairwiseEndpointBindingV4,
        contact: Contact,
        bootstrap: DirectBootstrapV4,
        now: Date = Date()
    ) throws -> Conversation {
        guard let material = bootstrap.signedPrekeyMaterial else {
            throw CryptoError.invalidPayload
        }
        let expectedPeer = try contact.certifiedGenerationEndpoint()
        let negotiation = try pairwiseBinding.validatedNegotiation(
            localEndpoint: localCertificate,
            peerEndpoint: senderEndpoint
        )
        guard senderEndpoint.endpointId == expectedPeer.endpointId,
              senderEndpoint.signingPublicKey == expectedPeer.signingPublicKey,
              senderEndpoint.agreementPublicKey == expectedPeer.agreementPublicKey,
              localCertificate.endpointId == localEndpoint.id,
              pairwiseBinding.isStructurallyValid,
              material.prekey.kind == .signed,
              let advertisedPrekey = localEndpoint.prekeys.signedPrekey(id: material.prekey.id),
              advertisedPrekey.verify(using: localEndpoint.signingKey.publicKeyData),
              let prekeyKey = localEndpoint.prekeys.signedPrekeyKeyPair(
                  id: material.prekey.id,
                  now: now
              ) else {
            throw CryptoError.invalidPayload
        }
        try validateNegotiatedPrekeyFreshness(
            advertisedPrekey,
            negotiation: negotiation,
            now: now
        )
        var sharedSecret = try prekeyKey.decapsulate(ciphertext: material.kemCiphertext)
        defer { sharedSecret.secureWipe() }
        let endpointSession = DirectEndpointSessionIdentity(
            contactId: contact.id,
            localEndpointId: localEndpoint.id,
            localEndpointHandle: pairwiseBinding.localEndpointHandle,
            localCertificateReferenceDigest: pairwiseBinding.localCertificateReferenceDigest,
            localManifestEpoch: localCertificate.manifestEpoch,
            peerEndpointId: senderEndpoint.endpointId,
            peerEndpointHandle: pairwiseBinding.peerEndpointHandle,
            peerCertificateReferenceDigest: pairwiseBinding.peerCertificateReferenceDigest,
            peerManifestEpoch: senderEndpoint.manifestEpoch
        )
        return conversationFromSharedSecret(
            sharedSecret: sharedSecret,
            ourAgreementPublicKey: localEndpoint.agreementKey.publicKeyData,
            theirAgreementPublicKey: senderEndpoint.agreementPublicKey,
            contactId: contact.id,
            endpointSession: endpointSession,
            directV4Binding: pairwiseBinding,
            conversationId: conversationIdForEndpoints(
                localCertificate,
                senderEndpoint,
                pairwiseBinding: pairwiseBinding
            )
        )
    }

    private static func conversationFromSharedSecret(
        sharedSecret: Data,
        ourAgreementPublicKey: Data,
        theirAgreementPublicKey: Data,
        contactId: UUID,
        endpointSession: DirectEndpointSessionIdentity,
        directV4Binding: PairwiseEndpointBindingV4,
        conversationId: String
    ) -> Conversation {
        let (sendLabel, receiveLabel) = labelsForAgreement(
            ourKey: ourAgreementPublicKey,
            theirKey: theirAgreementPublicKey
        )
        let rootKey = deriveRootKey(
            sharedSecret: sharedSecret,
            priorRootKey: nil,
            directV4Binding: directV4Binding
        )
        let (sendKey, receiveKey) = deriveChains(rootKey: rootKey, sendLabel: sendLabel, receiveLabel: receiveLabel)
        let sessionId = directV4SessionId(
            rootKey: rootKey,
            cipherSuite: directV4Binding.cipherSuite,
            negotiatedCapabilitiesDigest: directV4Binding.negotiatedCapabilitiesDigest
        )
        return Conversation(
            id: conversationId,
            contactId: contactId,
            endpointSession: endpointSession,
            sessionId: sessionId,
            rootKey: rootKey,
            rootCounter: 0,
            sendChain: ChainKeyState(keyData: sendKey),
            receiveChain: ChainKeyState(keyData: receiveKey)
        )
    }

    public static func prepareMessageKey(
        conversation: inout Conversation
    ) throws -> (counter: UInt64, key: SymmetricKey) {
        try conversation.sendChain.nextMessageKey()
    }

    public static func encryptDirectV4(
        wirePayload: WirePayloadV2,
        eventId: UUID,
        senderSigningKey: SigningKeyPair,
        senderEndpoint: CertifiedGenerationEndpoint,
        recipientEndpoint: CertifiedGenerationEndpoint,
        pairwiseBinding: PairwiseEndpointBindingV4,
        conversation: inout Conversation,
        bootstrap: DirectBootstrapV4 = .none,
        sentAt: Date,
        metadataBucketSeconds: Int? = nil
    ) throws -> DirectEnvelopeV4 {
        var candidateConversation = conversation
        let prepared = try prepareMessageKey(conversation: &candidateConversation)
        let envelope = try encryptDirectV4(
            wirePayload: wirePayload,
            eventId: eventId,
            senderSigningKey: senderSigningKey,
            senderEndpoint: senderEndpoint,
            recipientEndpoint: recipientEndpoint,
            pairwiseBinding: pairwiseBinding,
            conversation: candidateConversation,
            messageCounter: prepared.counter,
            messageKey: prepared.key,
            bootstrap: bootstrap,
            sentAt: sentAt,
            metadataBucketSeconds: metadataBucketSeconds
        )
        conversation.sendChain = candidateConversation.sendChain
        return envelope
    }

    public static func encryptDirectV4(
        wirePayload: WirePayloadV2,
        eventId: UUID,
        senderSigningKey: SigningKeyPair,
        senderEndpoint: CertifiedGenerationEndpoint,
        recipientEndpoint: CertifiedGenerationEndpoint,
        pairwiseBinding: PairwiseEndpointBindingV4,
        conversation: Conversation,
        messageCounter: UInt64,
        messageKey: SymmetricKey,
        bootstrap: DirectBootstrapV4 = .none,
        sentAt: Date,
        metadataBucketSeconds: Int? = nil
    ) throws -> DirectEnvelopeV4 {
        let negotiation = try pairwiseBinding.validatedNegotiation(
            localEndpoint: senderEndpoint,
            peerEndpoint: recipientEndpoint
        )
        let negotiationDigest = try negotiation.digest()
        let visibleSentAt = MetadataMinimizer.bucketedTimestamp(
            sentAt,
            bucketSeconds: metadataBucketSeconds
        )
        try wirePayload.validateDirectV4(
            eventId: eventId,
            senderEndpointHandle: pairwiseBinding.localEndpointHandle,
            conversationId: conversation.id,
            sentAt: visibleSentAt
        )
        let payloadData = try PaddedMessagePlaintext.encodeWirePayloadV2(wirePayload)
        return try encryptEncodedPayload(
            payloadData,
            eventId: eventId,
            senderSigningKey: senderSigningKey,
            senderEndpoint: senderEndpoint,
            recipientEndpoint: recipientEndpoint,
            pairwiseBinding: pairwiseBinding,
            cipherSuite: negotiation.cipherSuite,
            negotiatedCapabilitiesDigest: negotiationDigest,
            conversation: conversation,
            messageCounter: messageCounter,
            messageKey: messageKey,
            bootstrap: bootstrap,
            visibleSentAt: visibleSentAt
        )
    }

    private static func encryptEncodedPayload(
        _ encodedPayload: Data,
        eventId: UUID,
        senderSigningKey: SigningKeyPair,
        senderEndpoint: CertifiedGenerationEndpoint,
        recipientEndpoint: CertifiedGenerationEndpoint,
        pairwiseBinding: PairwiseEndpointBindingV4,
        cipherSuite: String,
        negotiatedCapabilitiesDigest: Data,
        conversation: Conversation,
        messageCounter: UInt64,
        messageKey: SymmetricKey,
        bootstrap: DirectBootstrapV4,
        visibleSentAt: Date
    ) throws -> DirectEnvelopeV4 {
        try validateOutboundDirectV4Fields(
            senderSigningKey: senderSigningKey,
            senderEndpoint: senderEndpoint,
            recipientEndpoint: recipientEndpoint,
            pairwiseBinding: pairwiseBinding,
            cipherSuite: cipherSuite,
            negotiatedCapabilitiesDigest: negotiatedCapabilitiesDigest,
            bootstrap: bootstrap,
            conversation: conversation
        )
        var payloadData = encodedPayload
        defer { payloadData.secureWipe() }
        let envelopeId = UUID()
        let authenticatedData = try DirectEnvelopeV4.authenticatedData(
            id: envelopeId,
            conversationId: conversation.id,
            sessionId: conversation.sessionId,
            eventId: eventId,
            senderEndpointHandle: pairwiseBinding.localEndpointHandle,
            senderCertificateDigest: pairwiseBinding.localCertificateReferenceDigest,
            senderEndpointSetEpoch: senderEndpoint.manifestEpoch,
            recipientEndpointHandle: pairwiseBinding.peerEndpointHandle,
            recipientCertificateDigest: pairwiseBinding.peerCertificateReferenceDigest,
            recipientEndpointSetEpoch: recipientEndpoint.manifestEpoch,
            cipherSuite: cipherSuite,
            negotiatedCapabilitiesDigest: negotiatedCapabilitiesDigest,
            bootstrap: bootstrap,
            sentAt: visibleSentAt,
            messageCounter: messageCounter
        )
        let encrypted = try CryptoBox.encrypt(
            payloadData,
            key: messageKey,
            authenticatedData: authenticatedData
        )
        var envelope = DirectEnvelopeV4(
            id: envelopeId,
            conversationId: conversation.id,
            sessionId: conversation.sessionId,
            eventId: eventId,
            senderEndpointHandle: pairwiseBinding.localEndpointHandle,
            senderCertificateDigest: pairwiseBinding.localCertificateReferenceDigest,
            senderEndpointSetEpoch: senderEndpoint.manifestEpoch,
            recipientEndpointHandle: pairwiseBinding.peerEndpointHandle,
            recipientCertificateDigest: pairwiseBinding.peerCertificateReferenceDigest,
            recipientEndpointSetEpoch: recipientEndpoint.manifestEpoch,
            cipherSuite: cipherSuite,
            negotiatedCapabilitiesDigest: negotiatedCapabilitiesDigest,
            bootstrap: bootstrap,
            sentAt: visibleSentAt,
            messageCounter: messageCounter,
            payload: encrypted,
            signature: Data()
        )
        let signature = try senderSigningKey.sign(envelope.signableData())
        envelope = DirectEnvelopeV4(
            id: envelope.id,
            conversationId: envelope.conversationId,
            sessionId: envelope.sessionId,
            eventId: envelope.eventId,
            senderEndpointHandle: envelope.senderEndpointHandle,
            senderCertificateDigest: envelope.senderCertificateDigest,
            senderEndpointSetEpoch: envelope.senderEndpointSetEpoch,
            recipientEndpointHandle: envelope.recipientEndpointHandle,
            recipientCertificateDigest: envelope.recipientCertificateDigest,
            recipientEndpointSetEpoch: envelope.recipientEndpointSetEpoch,
            cipherSuite: envelope.cipherSuite,
            negotiatedCapabilitiesDigest: envelope.negotiatedCapabilitiesDigest,
            bootstrap: envelope.bootstrap,
            sentAt: envelope.sentAt,
            messageCounter: envelope.messageCounter,
            payload: envelope.payload,
            signature: signature
        )
        guard envelope.isStructurallyValid else { throw CryptoError.invalidPayload }
        return envelope
    }

    public static func decryptDirectV4(
        envelope: DirectEnvelopeV4,
        contact: Contact,
        localIdentity: Identity,
        localEndpoint: LocalEndpointState,
        localManifest: EndpointSetManifest,
        localCertificate: CertifiedGenerationEndpoint,
        pairwiseBinding: PairwiseEndpointBindingV4,
        conversation: inout Conversation
    ) throws -> (body: MessageBody, messageKey: SymmetricKey) {
        var candidateConversation = conversation
        let result = try decryptDirectV4Payload(
            envelope: envelope,
            contact: contact,
            localIdentity: localIdentity,
            localEndpoint: localEndpoint,
            localManifest: localManifest,
            localCertificate: localCertificate,
            pairwiseBinding: pairwiseBinding,
            conversation: &candidateConversation
        )
        guard let body = result.disposition.body else {
            throw WirePayloadV2Error.unknownControl
        }
        conversation = candidateConversation
        return (body, result.messageKey)
    }

    public static func decryptDirectV4Payload(
        envelope: DirectEnvelopeV4,
        contact: Contact,
        localIdentity: Identity,
        localEndpoint: LocalEndpointState,
        localManifest: EndpointSetManifest,
        localCertificate: CertifiedGenerationEndpoint,
        pairwiseBinding: PairwiseEndpointBindingV4,
        conversation: inout Conversation
    ) throws -> DirectV4DecryptionResultV2 {
        let senderEndpoint = try contact.certifiedGenerationEndpoint()
        _ = try localCertificate.verified(
            identityPublicKey: localIdentity.signingKey.publicKeyData,
            manifest: localManifest,
            now: localCertificate.prekeyBundle.createdAt
        )
        let negotiation = try pairwiseBinding.validatedNegotiation(
            localEndpoint: localCertificate,
            peerEndpoint: senderEndpoint
        )
        let negotiationDigest = try negotiation.digest()
        guard envelope.cipherSuite == negotiation.cipherSuite,
              envelope.negotiatedCapabilitiesDigest == negotiationDigest,
              envelope.recipientEndpointHandle == pairwiseBinding.localEndpointHandle,
              envelope.recipientEndpointSetEpoch == localCertificate.manifestEpoch,
              envelope.recipientCertificateDigest
                == pairwiseBinding.localCertificateReferenceDigest,
              localCertificate.identityGenerationId == localEndpoint.identityGenerationId,
              localCertificate.endpointId == localEndpoint.id,
              localCertificate.signingPublicKey == localEndpoint.signingKey.publicKeyData,
              localCertificate.agreementPublicKey == localEndpoint.agreementKey.publicKeyData,
              localCertificate.isStructurallyValid(
                  now: localCertificate.prekeyBundle.createdAt
              ),
              envelope.senderEndpointHandle == pairwiseBinding.peerEndpointHandle,
              envelope.senderCertificateDigest
                == pairwiseBinding.peerCertificateReferenceDigest,
              envelope.senderEndpointSetEpoch == senderEndpoint.manifestEpoch,
              let endpointSession = conversation.endpointSession,
              endpointSession.contactId == contact.id,
              endpointSession.localEndpointId == localEndpoint.id,
              endpointSession.localEndpointHandle == pairwiseBinding.localEndpointHandle,
              endpointSession.localCertificateReferenceDigest
                == pairwiseBinding.localCertificateReferenceDigest,
              endpointSession.localManifestEpoch == localCertificate.manifestEpoch,
              endpointSession.peerEndpointId == senderEndpoint.endpointId,
              endpointSession.peerEndpointHandle == pairwiseBinding.peerEndpointHandle,
              endpointSession.peerCertificateReferenceDigest
                == pairwiseBinding.peerCertificateReferenceDigest,
              endpointSession.peerManifestEpoch == senderEndpoint.manifestEpoch,
              conversation.id == conversationIdForEndpoints(
                  localCertificate,
                  senderEndpoint,
                  pairwiseBinding: pairwiseBinding
              ),
              conversation.sessionId == directV4SessionId(
                  rootKey: conversation.rootKey,
                  cipherSuite: envelope.cipherSuite,
                  negotiatedCapabilitiesDigest: envelope.negotiatedCapabilitiesDigest
              ),
              UInt64(envelope.payload.ciphertext.count)
                <= negotiation.limit(
                    module: "nw.core",
                    name: "maxCiphertextBytes"
                ) ?? 0 else {
            throw CryptoError.invalidPayload
        }
        var candidateConversation = conversation
        let decrypted = try decryptWirePayloadWithSigningKey(
            envelope: envelope,
            publicSigningKey: senderEndpoint.signingPublicKey,
            conversation: &candidateConversation
        )
        try validateNegotiatedWirePayloadLimits(
            decrypted.payload,
            negotiation: negotiation
        )
        let disposition: DirectV4PayloadDispositionV2
        switch decrypted.payload.kind {
        case .application:
            guard let event = decrypted.payload.application else {
                throw WirePayloadV2Error.invalidApplicationEvent
            }
            disposition = .application(event, try decrypted.payload.applicationProjection())
        case .control:
            disposition = try decrypted.payload.controlDisposition(
                conversationId: conversation.id,
                eventId: envelope.eventId,
                senderEndpointHandle: envelope.senderEndpointHandle,
                receivedAt: envelope.sentAt
            )
        }
        conversation = candidateConversation
        return DirectV4DecryptionResultV2(
            disposition: disposition,
            messageKey: decrypted.messageKey
        )
    }

    private static func decryptWirePayloadWithSigningKey(
        envelope: DirectEnvelopeV4,
        publicSigningKey: Data,
        conversation: inout Conversation
    ) throws -> (payload: WirePayloadV2, messageKey: SymmetricKey) {
        guard envelope.payloadFormat == NoctweaveWirePayloadV2.directV4Format else {
            throw WirePayloadV2Error.directV4FormatRequired
        }
        let conversationId = conversation.id
        let decrypted: (value: WirePayloadV2, messageKey: SymmetricKey) = try decryptPayloadWithSigningKey(
            envelope: envelope,
            publicSigningKey: publicSigningKey,
            conversation: &conversation
        ) { plaintext in
            let payload = try PaddedMessagePlaintext.decodeWirePayloadV2(plaintext)
            try payload.validateDirectV4(
                eventId: envelope.eventId,
                senderEndpointHandle: envelope.senderEndpointHandle,
                conversationId: conversationId,
                sentAt: envelope.sentAt
            )
            return payload
        }
        return (decrypted.value, decrypted.messageKey)
    }

    private static func decryptPayloadWithSigningKey<T>(
        envelope: DirectEnvelopeV4,
        publicSigningKey: Data,
        conversation: inout Conversation,
        decode: (Data) throws -> T
    ) throws -> (value: T, messageKey: SymmetricKey) {
        guard envelope.conversationId == conversation.id,
              envelope.sessionId == conversation.sessionId else {
            throw CryptoError.invalidPayload
        }
        guard envelope.verifySignature(publicSigningKey: publicSigningKey) else {
            throw CryptoError.invalidSignature
        }
        var candidateReceiveChain = conversation.receiveChain
        let key = try candidateReceiveChain.messageKey(
            for: envelope.messageCounter,
            maxSkip: ChainKeyState.defaultMaxSkip
        )
        let authenticatedData = try envelope.authenticatedData()
        var plaintext = try CryptoBox.decrypt(envelope.payload, key: key, authenticatedData: authenticatedData)
        defer { plaintext.secureWipe() }
        let value = try decode(plaintext)
        conversation.receiveChain = candidateReceiveChain
        return (value, key)
    }

    public static func appendMessage(
        id: UUID = UUID(),
        body: MessageBody,
        direction: MessageDirection,
        counter: UInt64,
        timestamp: Date,
        conversation: inout Conversation,
        attachmentRelay: RelayEndpoint? = nil,
        messageKey: SymmetricKey? = nil
    ) -> Message? {
        switch body {
        case .text(let text):
            let message = Message(id: id, direction: direction, body: text, timestamp: timestamp, counter: counter)
            conversation.messages.append(message)
            return message
        case .attachment(let descriptor):
            let title = attachmentTitle(for: descriptor)
            let message = Message(
                    id: id,
                    direction: direction,
                    body: title,
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

    private static func attachmentTitle(for descriptor: AttachmentDescriptor) -> String {
        let mimeType = descriptor.mimeType
            .split(separator: ";", maxSplits: 1)
            .first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() ?? descriptor.mimeType.lowercased()
        if mimeType.hasPrefix("audio/") {
            return "Voice message"
        }
        if mimeType.hasPrefix("image/") {
            return "Image"
        }
        return "Attachment"
    }

    private static func deriveRootKey(
        sharedSecret: Data,
        priorRootKey: Data?,
        directV4Binding: PairwiseEndpointBindingV4
    ) -> Data {
        let salt: Data
        if let priorRootKey, !priorRootKey.isEmpty {
            salt = priorRootKey
        } else {
            salt = Data("NOCTWEAVE-ROOT".utf8)
        }
        var info = Data("ROOT".utf8)
        info.append(directV4SessionBindingData(directV4Binding))
        return CryptoBox.deriveChainKey(sharedSecret: sharedSecret, salt: salt, info: info)
    }

    private static func deriveChains(rootKey: Data, sendLabel: String, receiveLabel: String) -> (Data, Data) {
        let salt = Data("NOCTWEAVE-CHAIN".utf8)
        let sendKey = CryptoBox.deriveChainKey(sharedSecret: rootKey, salt: salt, info: Data(sendLabel.utf8))
        let receiveKey = CryptoBox.deriveChainKey(sharedSecret: rootKey, salt: salt, info: Data(receiveLabel.utf8))
        return (sendKey, receiveKey)
    }

    public static func conversationIdForEndpoints(
        _ first: CertifiedGenerationEndpoint,
        _ second: CertifiedGenerationEndpoint,
        pairwiseBinding: PairwiseEndpointBindingV4
    ) -> String {
        let entries = [
            Data(pairwiseBinding.localEndpointHandle.rawValue.utf8) + first.agreementPublicKey,
            Data(pairwiseBinding.peerEndpointHandle.rawValue.utf8) + second.agreementPublicKey
        ].sorted { $0.lexicographicallyPrecedes($1) }
        var combined = Data("Noctweave/direct-endpoint-conversation/v4".utf8)
        combined.append(directV4SessionBindingData(pairwiseBinding))
        combined.append(entries[0])
        combined.append(entries[1])
        return Data(SHA256.hash(data: combined)).base64EncodedString()
    }

    private static func directV4SessionId(
        rootKey: Data,
        cipherSuite: String,
        negotiatedCapabilitiesDigest: Data
    ) -> String {
        var material = Data("NOCTWEAVE-SESSION".utf8)
        material.append(directV4SessionBindingData(
            cipherSuite: cipherSuite,
            negotiatedCapabilitiesDigest: negotiatedCapabilitiesDigest
        ))
        material.append(rootKey)
        return Data(SHA256.hash(data: material)).base64EncodedString()
    }

    private static func directV4SessionBindingData(
        _ binding: PairwiseEndpointBindingV4
    ) -> Data {
        directV4SessionBindingData(
            cipherSuite: binding.cipherSuite,
            negotiatedCapabilitiesDigest: binding.negotiatedCapabilitiesDigest
        )
    }

    private static func directV4SessionBindingData(
        cipherSuite: String,
        negotiatedCapabilitiesDigest: Data
    ) -> Data {
        var data = Data("Noctweave/direct-v4-session-binding/v1".utf8)
        data.append(Data(cipherSuite.utf8))
        data.append(negotiatedCapabilitiesDigest)
        return data
    }

    private static func validateNegotiatedPrekeyFreshness(
        _ prekey: SignedPrekey,
        negotiation: DirectV4NegotiatedCapabilityManifest,
        now: Date
    ) throws {
        guard let seconds = negotiation.limit(
            module: "nw.prekeys",
            name: "maxPrekeyAgeSeconds"
        ),
        prekey.isFresh(at: now),
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
        guard let maxParameters = negotiation.limit(
                  module: "nw.events",
                  name: "maxContentParameters"
              ),
              let maxParameterBytes = negotiation.limit(
                  module: "nw.events",
                  name: "maxContentParameterBytes"
              ),
              let maxPayloadBytes = negotiation.limit(
                  module: "nw.events",
                  name: "maxContentPayloadBytes"
              ),
              let maxFallbackBytes = negotiation.limit(
                  module: "nw.events",
                  name: "maxFallbackBytes"
              ),
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

    private static func validateOutboundDirectV4Fields(
        senderSigningKey: SigningKeyPair,
        senderEndpoint: CertifiedGenerationEndpoint,
        recipientEndpoint: CertifiedGenerationEndpoint,
        pairwiseBinding: PairwiseEndpointBindingV4,
        cipherSuite: String,
        negotiatedCapabilitiesDigest: Data,
        bootstrap: DirectBootstrapV4,
        conversation: Conversation
    ) throws {
        guard pairwiseBinding.isStructurallyValid,
              bootstrap.isStructurallyValid,
              senderSigningKey.publicKeyData == senderEndpoint.signingPublicKey,
              let session = conversation.endpointSession,
              pairwiseBinding.localEndpointHandle == session.localEndpointHandle,
              pairwiseBinding.localCertificateReferenceDigest
                == session.localCertificateReferenceDigest,
              senderEndpoint.manifestEpoch == session.localManifestEpoch,
              pairwiseBinding.peerEndpointHandle == session.peerEndpointHandle,
              pairwiseBinding.peerCertificateReferenceDigest
                == session.peerCertificateReferenceDigest,
              recipientEndpoint.manifestEpoch == session.peerManifestEpoch,
              conversation.sessionId == directV4SessionId(
                  rootKey: conversation.rootKey,
                  cipherSuite: cipherSuite,
                  negotiatedCapabilitiesDigest: negotiatedCapabilitiesDigest
              ) else {
            throw DirectV4CapabilityNegotiationError.transcriptMismatch
        }
    }

    private static func labelsForAgreement(ourKey: Data, theirKey: Data) -> (String, String) {
        if ourKey.lexicographicallyPrecedes(theirKey) {
            return ("A", "B")
        }
        return ("B", "A")
    }
}
