import CryptoKit
import Foundation

public enum MessageEngine {
    public static func makeCertifiedContactOffer(
        identity: Identity,
        identityGenerationId: UUID,
        localInstallation: LocalInstallationState,
        installationManifest: InstallationManifest,
        inboxId: String,
        relay: RelayEndpoint,
        inboxAccessPublicKey: Data? = nil,
        issuedAt: Date = Date()
    ) throws -> ContactOffer {
        let endpoint = try CertifiedInstallationEndpoint.create(
            identity: identity,
            installation: localInstallation,
            manifest: installationManifest,
            issuedAt: issuedAt
        )
        return try ContactOffer.createCertified(
            displayName: identity.displayName,
            inboxId: inboxId,
            relay: relay,
            identity: identity,
            identityGenerationId: identityGenerationId,
            installationManifest: installationManifest,
            preferredInstallationEndpoint: endpoint,
            inboxAccessPublicKey: inboxAccessPublicKey
        )
    }

    public static func contact(from offer: ContactOffer) throws -> Contact {
        let offer = try offer.verified()
        guard offer.version == CertifiedInstallationEndpoint.version,
              offer.identityGenerationId != nil,
              offer.installationCheckpoint != nil,
              offer.preferredInstallationEndpoint != nil else {
            throw ContactOfferError.invalidStructure
        }
        return Contact(
            displayName: offer.displayName,
            inboxId: offer.inboxId,
            relay: offer.relay,
            signingPublicKey: offer.signingPublicKey,
            agreementPublicKey: offer.agreementPublicKey,
            identityGenerationId: offer.identityGenerationId,
            installationCheckpoint: offer.installationCheckpoint,
            preferredInstallationEndpoint: offer.preferredInstallationEndpoint,
            endpointAuthoritySigningPublicKey: offer.signingPublicKey
        )
    }

    public static func createOutboundInstallationSession(
        localInstallation: LocalInstallationState,
        localEndpoint: CertifiedInstallationEndpoint,
        pairwiseBinding: PairwiseInstallationBindingV4,
        contact: Contact,
        now: Date = Date()
    ) throws -> (conversation: Conversation, kemCiphertext: Data, prekey: PrekeyReference) {
        let peerEndpoint = try contact.certifiedInstallationEndpoint()
        let negotiation = try pairwiseBinding.validatedNegotiation(
            localEndpoint: localEndpoint,
            peerEndpoint: peerEndpoint
        )
        guard localEndpoint.installationId == localInstallation.id,
              localEndpoint.signingPublicKey == localInstallation.signingKey.publicKeyData,
              localEndpoint.agreementPublicKey == localInstallation.agreementKey.publicKeyData,
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
            localInstallationId: localInstallation.id,
            localInstallationHandle: pairwiseBinding.localInstallationHandle,
            localCertificateReferenceDigest: pairwiseBinding.localCertificateReferenceDigest,
            localManifestEpoch: localEndpoint.manifestEpoch,
            peerInstallationId: peerEndpoint.installationId,
            peerInstallationHandle: pairwiseBinding.peerInstallationHandle,
            peerCertificateReferenceDigest: pairwiseBinding.peerCertificateReferenceDigest,
            peerManifestEpoch: peerEndpoint.manifestEpoch
        )
        let conversation = conversationFromSharedSecret(
            sharedSecret: kemOutput.sharedSecret,
            ourAgreementPublicKey: localInstallation.agreementKey.publicKeyData,
            theirAgreementPublicKey: peerEndpoint.agreementPublicKey,
            contactId: contact.id,
            endpointSession: endpointSession,
            directV4Binding: pairwiseBinding,
            conversationId: conversationIdForEndpoints(
                localEndpoint,
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

    public static func createInboundInstallationSession(
        localInstallation: LocalInstallationState,
        localEndpoint: CertifiedInstallationEndpoint,
        senderEndpoint: CertifiedInstallationEndpoint,
        pairwiseBinding: PairwiseInstallationBindingV4,
        contact: Contact,
        kemCiphertext: Data,
        prekey: PrekeyReference?,
        now: Date = Date()
    ) throws -> Conversation {
        let expectedPeer = try contact.certifiedInstallationEndpoint()
        let negotiation = try pairwiseBinding.validatedNegotiation(
            localEndpoint: localEndpoint,
            peerEndpoint: senderEndpoint
        )
        guard senderEndpoint.installationId == expectedPeer.installationId,
              senderEndpoint.signingPublicKey == expectedPeer.signingPublicKey,
              senderEndpoint.agreementPublicKey == expectedPeer.agreementPublicKey,
              localEndpoint.installationId == localInstallation.id,
              pairwiseBinding.isStructurallyValid,
              prekey?.kind == .signed,
              let prekeyId = prekey?.id,
              let advertisedPrekey = localInstallation.prekeys.signedPrekey(id: prekeyId),
              advertisedPrekey.verify(using: localInstallation.signingKey.publicKeyData),
              let prekeyKey = localInstallation.prekeys.signedPrekeyKeyPair(
                  id: prekeyId,
                  now: now
              ) else {
            throw CryptoError.invalidPayload
        }
        try validateNegotiatedPrekeyFreshness(
            advertisedPrekey,
            negotiation: negotiation,
            now: now
        )
        var sharedSecret = try prekeyKey.decapsulate(ciphertext: kemCiphertext)
        defer { sharedSecret.secureWipe() }
        let endpointSession = DirectEndpointSessionIdentity(
            contactId: contact.id,
            localInstallationId: localInstallation.id,
            localInstallationHandle: pairwiseBinding.localInstallationHandle,
            localCertificateReferenceDigest: pairwiseBinding.localCertificateReferenceDigest,
            localManifestEpoch: localEndpoint.manifestEpoch,
            peerInstallationId: senderEndpoint.installationId,
            peerInstallationHandle: pairwiseBinding.peerInstallationHandle,
            peerCertificateReferenceDigest: pairwiseBinding.peerCertificateReferenceDigest,
            peerManifestEpoch: senderEndpoint.manifestEpoch
        )
        return conversationFromSharedSecret(
            sharedSecret: sharedSecret,
            ourAgreementPublicKey: localInstallation.agreementKey.publicKeyData,
            theirAgreementPublicKey: senderEndpoint.agreementPublicKey,
            contactId: contact.id,
            endpointSession: endpointSession,
            directV4Binding: pairwiseBinding,
            conversationId: conversationIdForEndpoints(
                localEndpoint,
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
        directV4Binding: PairwiseInstallationBindingV4,
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
        senderSigningKey: SigningKeyPair,
        senderFingerprint: String,
        conversation: inout Conversation,
        kemCiphertext: Data? = nil,
        prekey: PrekeyReference? = nil,
        rootRatchet: RootRatchet? = nil,
        authenticatedContext: MessageAuthenticatedContext,
        sentAt: Date,
        metadataBucketSeconds: Int? = nil
    ) throws -> Envelope {
        var candidateConversation = conversation
        let prepared = try prepareMessageKey(conversation: &candidateConversation)
        let envelope = try encryptDirectV4(
            wirePayload: wirePayload,
            senderSigningKey: senderSigningKey,
            senderFingerprint: senderFingerprint,
            conversation: candidateConversation,
            messageCounter: prepared.counter,
            messageKey: prepared.key,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            rootRatchet: rootRatchet,
            authenticatedContext: authenticatedContext,
            sentAt: sentAt,
            metadataBucketSeconds: metadataBucketSeconds
        )
        conversation.sendChain = candidateConversation.sendChain
        return envelope
    }

    public static func encryptDirectV4(
        wirePayload: WirePayloadV2,
        senderSigningKey: SigningKeyPair,
        senderFingerprint: String,
        conversation: Conversation,
        messageCounter: UInt64,
        messageKey: SymmetricKey,
        kemCiphertext: Data? = nil,
        prekey: PrekeyReference? = nil,
        rootRatchet: RootRatchet? = nil,
        authenticatedContext: MessageAuthenticatedContext,
        sentAt: Date,
        metadataBucketSeconds: Int? = nil
    ) throws -> Envelope {
        guard authenticatedContext.purpose == .directV4,
              let direct = authenticatedContext.directV4 else {
            throw WirePayloadV2Error.directV4FormatRequired
        }
        let visibleSentAt = MetadataMinimizer.bucketedTimestamp(
            sentAt,
            bucketSeconds: metadataBucketSeconds
        )
        try wirePayload.validateDirectV4(
            context: direct,
            conversationId: conversation.id,
            sentAt: visibleSentAt
        )
        let payloadData = try PaddedMessagePlaintext.encodeWirePayloadV2(wirePayload)
        return try encryptEncodedPayload(
            payloadData,
            senderSigningKey: senderSigningKey,
            senderFingerprint: senderFingerprint,
            conversation: conversation,
            messageCounter: messageCounter,
            messageKey: messageKey,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            rootRatchet: rootRatchet,
            authenticatedContext: authenticatedContext,
            visibleSentAt: visibleSentAt,
            metadataBucketSeconds: metadataBucketSeconds
        )
    }

    private static func encryptEncodedPayload(
        _ encodedPayload: Data,
        senderSigningKey: SigningKeyPair,
        senderFingerprint: String,
        conversation: Conversation,
        messageCounter: UInt64,
        messageKey: SymmetricKey,
        kemCiphertext: Data?,
        prekey: PrekeyReference?,
        rootRatchet: RootRatchet?,
        authenticatedContext: MessageAuthenticatedContext,
        visibleSentAt: Date,
        metadataBucketSeconds: Int?
    ) throws -> Envelope {
        try validateOutboundDirectV4Context(
            authenticatedContext,
            conversation: conversation
        )
        var payloadData = encodedPayload
        defer { payloadData.secureWipe() }
        let encrypted = try encryptPayload(
            payloadData,
            conversationId: conversation.id,
            sessionId: conversation.sessionId,
            authenticatedContext: authenticatedContext,
            messageCounter: messageCounter,
            messageKey: messageKey
        )
        let visibleRootRatchet = rootRatchet?.bucketed(metadataBucketSeconds: metadataBucketSeconds)
        let envelopeId = UUID()
        let signable = try Envelope.signableData(
            id: envelopeId,
            conversationId: conversation.id,
            sessionId: conversation.sessionId,
            senderFingerprint: senderFingerprint,
            sentAt: visibleSentAt,
            messageCounter: messageCounter,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            rootRatchet: visibleRootRatchet,
            authenticatedContext: authenticatedContext,
            payload: encrypted
        )
        let signature = try senderSigningKey.sign(signable)
        return Envelope(
            id: envelopeId,
            conversationId: conversation.id,
            sessionId: conversation.sessionId,
            senderFingerprint: senderFingerprint,
            sentAt: visibleSentAt,
            messageCounter: messageCounter,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            rootRatchet: visibleRootRatchet,
            authenticatedContext: authenticatedContext,
            payload: encrypted,
            signature: signature
        )
    }

    public static func decryptDirectV4(
        envelope: Envelope,
        contact: Contact,
        localIdentity: Identity,
        localInstallation: LocalInstallationState,
        localManifest: InstallationManifest,
        localEndpoint: CertifiedInstallationEndpoint,
        pairwiseBinding: PairwiseInstallationBindingV4,
        conversation: inout Conversation
    ) throws -> (body: MessageBody, messageKey: SymmetricKey) {
        var candidateConversation = conversation
        let result = try decryptDirectV4Payload(
            envelope: envelope,
            contact: contact,
            localIdentity: localIdentity,
            localInstallation: localInstallation,
            localManifest: localManifest,
            localEndpoint: localEndpoint,
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
        envelope: Envelope,
        contact: Contact,
        localIdentity: Identity,
        localInstallation: LocalInstallationState,
        localManifest: InstallationManifest,
        localEndpoint: CertifiedInstallationEndpoint,
        pairwiseBinding: PairwiseInstallationBindingV4,
        conversation: inout Conversation
    ) throws -> DirectV4DecryptionResultV2 {
        let senderEndpoint = try contact.certifiedInstallationEndpoint()
        _ = try localEndpoint.verified(
            identityPublicKey: localIdentity.signingKey.publicKeyData,
            manifest: localManifest,
            now: localEndpoint.prekeyBundle.createdAt
        )
        let negotiation = try pairwiseBinding.validatedNegotiation(
            localEndpoint: localEndpoint,
            peerEndpoint: senderEndpoint
        )
        let negotiationDigest = try negotiation.digest()
        guard envelope.authenticatedContext?.purpose == .directV4,
              let direct = envelope.authenticatedContext?.directV4,
              direct.cipherSuite == negotiation.cipherSuite,
              direct.negotiatedCapabilitiesDigest == negotiationDigest,
              direct.recipientInstallationHandle == pairwiseBinding.localInstallationHandle,
              direct.recipientManifestEpoch == localEndpoint.manifestEpoch,
              direct.recipientCertificateDigest
                == pairwiseBinding.localCertificateReferenceDigest,
              localEndpoint.identityGenerationId == localInstallation.identityGenerationId,
              localEndpoint.installationId == localInstallation.id,
              localEndpoint.signingPublicKey == localInstallation.signingKey.publicKeyData,
              localEndpoint.agreementPublicKey == localInstallation.agreementKey.publicKeyData,
              localEndpoint.isStructurallyValid(
                  now: localEndpoint.prekeyBundle.createdAt
              ),
              direct.senderInstallationHandle == pairwiseBinding.peerInstallationHandle,
              direct.senderCertificateDigest
                == pairwiseBinding.peerCertificateReferenceDigest,
              direct.senderManifestEpoch == senderEndpoint.manifestEpoch,
              envelope.senderFingerprint == pairwiseBinding.peerInstallationHandle.rawValue,
              let endpointSession = conversation.endpointSession,
              endpointSession.contactId == contact.id,
              endpointSession.localInstallationId == localInstallation.id,
              endpointSession.localInstallationHandle == pairwiseBinding.localInstallationHandle,
              endpointSession.localCertificateReferenceDigest
                == pairwiseBinding.localCertificateReferenceDigest,
              endpointSession.localManifestEpoch == localEndpoint.manifestEpoch,
              endpointSession.peerInstallationId == senderEndpoint.installationId,
              endpointSession.peerInstallationHandle == pairwiseBinding.peerInstallationHandle,
              endpointSession.peerCertificateReferenceDigest
                == pairwiseBinding.peerCertificateReferenceDigest,
              endpointSession.peerManifestEpoch == senderEndpoint.manifestEpoch,
              conversation.id == conversationIdForEndpoints(
                  localEndpoint,
                  senderEndpoint,
                  pairwiseBinding: pairwiseBinding
              ),
              conversation.sessionId == directV4SessionId(
                  rootKey: conversation.rootKey,
                  cipherSuite: direct.cipherSuite,
                  negotiatedCapabilitiesDigest: direct.negotiatedCapabilitiesDigest
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
                context: direct,
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
        envelope: Envelope,
        publicSigningKey: Data,
        conversation: inout Conversation
    ) throws -> (payload: WirePayloadV2, messageKey: SymmetricKey) {
        guard envelope.authenticatedContext?.purpose == .directV4,
              let direct = envelope.authenticatedContext?.directV4,
              direct.payloadFormat == NoctweaveWirePayloadV2.directV4Format else {
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
                context: direct,
                conversationId: conversationId,
                sentAt: envelope.sentAt
            )
            return payload
        }
        return (decrypted.value, decrypted.messageKey)
    }

    private static func decryptPayloadWithSigningKey<T>(
        envelope: Envelope,
        publicSigningKey: Data,
        conversation: inout Conversation,
        decode: (Data) throws -> T
    ) throws -> (value: T, messageKey: SymmetricKey) {
        guard envelope.conversationId == conversation.id,
              let authenticatedContext = envelope.authenticatedContext,
              authenticatedContext.purpose == .directV4,
              authenticatedContext.directV4 != nil else {
            throw CryptoError.invalidPayload
        }
        if let sessionId = envelope.sessionId {
            if conversation.sessionId != sessionId {
                throw CryptoError.invalidPayload
            }
        } else if !conversation.sessionId.isEmpty {
            throw CryptoError.invalidPayload
        }
        guard envelope.verifySignature(publicSigningKey: publicSigningKey) else {
            throw CryptoError.invalidSignature
        }
        let sessionId = envelope.sessionId ?? conversation.sessionId
        var candidateReceiveChain = conversation.receiveChain
        let key = try candidateReceiveChain.messageKey(
            for: envelope.messageCounter,
            maxSkip: ChainKeyState.defaultMaxSkip
        )
        let authenticatedData = try authenticatedData(
            conversationId: conversation.id,
            sessionId: sessionId,
            context: authenticatedContext,
            messageCounter: envelope.messageCounter
        )
        var plaintext = try CryptoBox.decrypt(envelope.payload, key: key, authenticatedData: authenticatedData)
        defer { plaintext.secureWipe() }
        let value = try decode(plaintext)
        conversation.receiveChain = candidateReceiveChain
        if conversation.sessionId.isEmpty, let sessionId = envelope.sessionId {
            conversation.sessionId = sessionId
        }
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
        directV4Binding: PairwiseInstallationBindingV4
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
        _ first: CertifiedInstallationEndpoint,
        _ second: CertifiedInstallationEndpoint,
        pairwiseBinding: PairwiseInstallationBindingV4
    ) -> String {
        let entries = [
            Data(pairwiseBinding.localInstallationHandle.rawValue.utf8) + first.agreementPublicKey,
            Data(pairwiseBinding.peerInstallationHandle.rawValue.utf8) + second.agreementPublicKey
        ].sorted { $0.lexicographicallyPrecedes($1) }
        var combined = Data("Noctweave/direct-installation-conversation/v4".utf8)
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
        _ binding: PairwiseInstallationBindingV4
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

    private static func validateOutboundDirectV4Context(
        _ context: MessageAuthenticatedContext,
        conversation: Conversation
    ) throws {
        guard context.purpose == .directV4,
              let direct = context.directV4,
              direct.isStructurallyValid,
              let session = conversation.endpointSession,
              direct.senderInstallationHandle == session.localInstallationHandle,
              direct.senderCertificateDigest == session.localCertificateReferenceDigest,
              direct.senderManifestEpoch == session.localManifestEpoch,
              direct.recipientInstallationHandle == session.peerInstallationHandle,
              direct.recipientCertificateDigest == session.peerCertificateReferenceDigest,
              direct.recipientManifestEpoch == session.peerManifestEpoch,
              conversation.sessionId == directV4SessionId(
                  rootKey: conversation.rootKey,
                  cipherSuite: direct.cipherSuite,
                  negotiatedCapabilitiesDigest: direct.negotiatedCapabilitiesDigest
              ) else {
            throw DirectV4CapabilityNegotiationError.transcriptMismatch
        }
    }

    private static func authenticatedData(
        conversationId: String,
        sessionId: String,
        context: MessageAuthenticatedContext,
        messageCounter: UInt64
    ) throws -> Data {
        guard context.purpose == .directV4, context.directV4 != nil else {
            throw WirePayloadV2Error.directV4FormatRequired
        }
        return try NoctweaveCoder.encode(
            DirectMessageAuthenticatedDataPayloadV4(
                version: CertifiedInstallationEndpoint.version,
                conversationId: conversationId,
                sessionId: sessionId,
                messageCounter: messageCounter,
                context: context
            ),
            sortedKeys: true
        )
    }

    private static func encryptPayload(
        _ payload: Data,
        conversationId: String,
        sessionId: String,
        authenticatedContext: MessageAuthenticatedContext,
        messageCounter: UInt64,
        messageKey: SymmetricKey
    ) throws -> EncryptedPayload {
        let authenticatedData = try authenticatedData(
            conversationId: conversationId,
            sessionId: sessionId,
            context: authenticatedContext,
            messageCounter: messageCounter
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

private struct DirectMessageAuthenticatedDataPayloadV4: Codable {
    let version: Int
    let conversationId: String
    let sessionId: String
    let messageCounter: UInt64
    let context: MessageAuthenticatedContext
}
