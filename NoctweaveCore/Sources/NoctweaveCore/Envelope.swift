import Foundation

public enum MessageAuthenticatedContextPurpose: String, Codable, Equatable {
    case group
    case directV4
}

public struct DirectMessageAuthenticatedContextV4: Codable, Equatable {
    public let version: Int
    public let payloadFormat: String
    public let cipherSuite: String
    public let negotiatedCapabilitiesDigest: Data
    public let eventId: UUID
    public let senderInstallationHandle: RelationshipInstallationHandle
    public let senderCertificateDigest: Data
    public let recipientInstallationHandle: RelationshipInstallationHandle
    public let senderManifestEpoch: UInt64
    public let recipientManifestEpoch: UInt64
    public let recipientCertificateDigest: Data

    public init(
        cipherSuite: String,
        negotiatedCapabilitiesDigest: Data,
        eventId: UUID,
        senderInstallationHandle: RelationshipInstallationHandle,
        senderCertificateDigest: Data,
        recipientInstallationHandle: RelationshipInstallationHandle,
        senderManifestEpoch: UInt64,
        recipientManifestEpoch: UInt64,
        recipientCertificateDigest: Data
    ) throws {
        self.version = CertifiedInstallationEndpoint.version
        self.payloadFormat = NoctweaveWirePayloadV2.directV4Format
        self.cipherSuite = cipherSuite
        self.negotiatedCapabilitiesDigest = negotiatedCapabilitiesDigest
        self.eventId = eventId
        self.senderInstallationHandle = senderInstallationHandle
        self.senderCertificateDigest = senderCertificateDigest
        self.recipientInstallationHandle = recipientInstallationHandle
        self.senderManifestEpoch = senderManifestEpoch
        self.recipientManifestEpoch = recipientManifestEpoch
        self.recipientCertificateDigest = recipientCertificateDigest
    }

    public var isStructurallyValid: Bool {
        version == CertifiedInstallationEndpoint.version
            && payloadFormat == NoctweaveWirePayloadV2.directV4Format
            && cipherSuite == DirectV4CipherSuite.identifier
            && negotiatedCapabilitiesDigest.count == 32
            && senderInstallationHandle.isStructurallyValid
            && senderCertificateDigest.count == 32
            && recipientInstallationHandle.isStructurallyValid
            && recipientCertificateDigest.count == 32
    }
}

public struct GroupMessageAuthenticatedContext: Codable, Equatable {
    public let protocolVersion: String
    public let cipherSuite: String
    public let groupId: UUID
    public let epoch: UInt64
    public let senderFingerprint: String
    public let transcriptHash: Data

    public init(
        protocolVersion: String = MLSGroupEpochState.currentProtocolVersion,
        cipherSuite: String = MLSGroupEpochState.currentCipherSuite,
        groupId: UUID,
        epoch: UInt64,
        senderFingerprint: String,
        transcriptHash: Data
    ) {
        self.protocolVersion = protocolVersion
        self.cipherSuite = cipherSuite
        self.groupId = groupId
        self.epoch = epoch
        self.senderFingerprint = senderFingerprint
        self.transcriptHash = transcriptHash
    }
}

public struct MessageAuthenticatedContext: Codable, Equatable {
    public let purpose: MessageAuthenticatedContextPurpose
    public let group: GroupMessageAuthenticatedContext?
    public let directV4: DirectMessageAuthenticatedContextV4?

    public init(
        purpose: MessageAuthenticatedContextPurpose,
        group: GroupMessageAuthenticatedContext?,
        directV4: DirectMessageAuthenticatedContextV4? = nil
    ) {
        self.purpose = purpose
        self.group = group
        self.directV4 = directV4
    }

    public static func group(
        protocolVersion: String = MLSGroupEpochState.currentProtocolVersion,
        cipherSuite: String = MLSGroupEpochState.currentCipherSuite,
        groupId: UUID,
        epoch: UInt64,
        senderFingerprint: String,
        transcriptHash: Data
    ) -> MessageAuthenticatedContext {
        MessageAuthenticatedContext(
            purpose: .group,
            group: GroupMessageAuthenticatedContext(
                protocolVersion: protocolVersion,
                cipherSuite: cipherSuite,
                groupId: groupId,
                epoch: epoch,
                senderFingerprint: senderFingerprint,
                transcriptHash: transcriptHash
            ),
            directV4: nil
        )
    }

    public static func directV4(
        eventId: UUID,
        senderEndpoint: CertifiedInstallationEndpoint,
        recipientEndpoint: CertifiedInstallationEndpoint,
        pairwiseBinding: PairwiseInstallationBindingV4
    ) throws -> MessageAuthenticatedContext {
        let negotiation = try pairwiseBinding.validatedNegotiation(
            localEndpoint: senderEndpoint,
            peerEndpoint: recipientEndpoint
        )
        guard pairwiseBinding.isStructurallyValid else {
            throw CryptoError.invalidPayload
        }
        return MessageAuthenticatedContext(
            purpose: .directV4,
            group: nil,
            directV4: try DirectMessageAuthenticatedContextV4(
                cipherSuite: negotiation.cipherSuite,
                negotiatedCapabilitiesDigest: try negotiation.digest(),
                eventId: eventId,
                senderInstallationHandle: pairwiseBinding.localInstallationHandle,
                senderCertificateDigest: pairwiseBinding.localCertificateReferenceDigest,
                recipientInstallationHandle: pairwiseBinding.peerInstallationHandle,
                senderManifestEpoch: senderEndpoint.manifestEpoch,
                recipientManifestEpoch: recipientEndpoint.manifestEpoch,
                recipientCertificateDigest: pairwiseBinding.peerCertificateReferenceDigest
            )
        )
    }
}

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
    public let authenticatedContext: MessageAuthenticatedContext?
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
        authenticatedContext: MessageAuthenticatedContext? = nil,
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
        self.authenticatedContext = authenticatedContext
        self.payload = payload
        self.signature = signature
    }

    public func verifySignature(publicSigningKey: Data) -> Bool {
        guard isStructurallyValid,
              SigningKeyPair.isValidPublicKey(publicSigningKey),
              let data = try? NoctweaveCoder.encode(signaturePayload, sortedKeys: true) else {
            return false
        }
        if authenticatedContext?.purpose == .directV4 {
            guard authenticatedContext?.directV4?.senderInstallationHandle.rawValue
                    == senderFingerprint else {
                return false
            }
        } else if senderFingerprint != CryptoBox.fingerprint(for: publicSigningKey) {
            return false
        }
        return SigningKeyPair.verify(signature: signature, data: data, publicKeyData: publicSigningKey)
    }

    public var isStructurallyValid: Bool {
        let ciphertextBytes = payload.ciphertext.count
        guard !conversationId.isEmpty,
              conversationId.utf8.count <= 256,
              sessionId?.utf8.count ?? 0 <= 128,
              Self.isCanonicalFingerprint(senderFingerprint),
              sentAt.timeIntervalSince1970.isFinite,
              payload.nonce.count == 12,
              payload.tag.count == 16,
              (PaddedMessagePlaintext.minimumPaddedBytes...PaddedMessagePlaintext.maximumPaddedBytes)
                .contains(ciphertextBytes),
              ciphertextBytes > 0,
              (ciphertextBytes & (ciphertextBytes - 1)) == 0,
              signature.count == 3_309,
              kemCiphertext?.count ?? 1_088 == 1_088,
              rootRatchet?.kemCiphertext.count ?? 1_088 == 1_088,
              rootRatchet?.sentAt.timeIntervalSince1970.isFinite ?? true else {
            return false
        }
        if let context = authenticatedContext {
            switch context.purpose {
            case .group:
                guard let group = context.group,
                      context.directV4 == nil,
                      group.protocolVersion == MLSGroupEpochState.currentProtocolVersion,
                      group.cipherSuite == MLSGroupEpochState.currentCipherSuite,
                      group.senderFingerprint == senderFingerprint,
                      group.transcriptHash.count == 32 else {
                    return false
                }
            case .directV4:
                guard context.group == nil,
                      let direct = context.directV4,
                      direct.isStructurallyValid,
                      direct.senderInstallationHandle.rawValue == senderFingerprint else {
                    return false
                }
            }
        }
        return true
    }

    private static func isCanonicalFingerprint(_ value: String) -> Bool {
        guard let decoded = Data(base64Encoded: value), decoded.count == 32 else { return false }
        return decoded.base64EncodedString() == value
    }

    public static func signableData(
        id: UUID,
        conversationId: String,
        sessionId: String?,
        senderFingerprint: String,
        sentAt: Date,
        messageCounter: UInt64,
        kemCiphertext: Data?,
        prekey: PrekeyReference?,
        rootRatchet: RootRatchet?,
        authenticatedContext: MessageAuthenticatedContext?,
        payload: EncryptedPayload
    ) throws -> Data {
        let payload = SignaturePayload(
            id: id,
            conversationId: conversationId,
            sessionId: sessionId,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: messageCounter,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            rootRatchet: rootRatchet,
            authenticatedContext: authenticatedContext,
            payload: payload
        )
        return try NoctweaveCoder.encode(payload, sortedKeys: true)
    }

    private var signaturePayload: SignaturePayload {
        SignaturePayload(
            id: id,
            conversationId: conversationId,
            sessionId: sessionId,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: messageCounter,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            rootRatchet: rootRatchet,
            authenticatedContext: authenticatedContext,
            payload: payload
        )
    }
}

private struct SignaturePayload: Codable {
    let id: UUID
    let conversationId: String
    let sessionId: String?
    let senderFingerprint: String
    let sentAt: Date
    let messageCounter: UInt64
    let kemCiphertext: Data?
    let prekey: PrekeyReference?
    let rootRatchet: RootRatchet?
    let authenticatedContext: MessageAuthenticatedContext?
    let payload: EncryptedPayload
}
