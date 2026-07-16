import CryptoKit
import Foundation

public enum HistoryAccessScope: String, Codable, Equatable {
    case readOnlyHistory
}

/// A peer-assisted, transport-neutral history handoff. This protocol transfers an inert local
/// projection; it is deliberately separate from generation-scoped endpoint
/// admission and live self-sync.
public enum NoctweaveHistoryTransferV2 {
    public static let version = NoctweaveSelfSyncV2.version
    public static let archiveCipherSuite = "AES-256-GCM"
    public static let keyWrapSuite = "ML-KEM-768+HKDF-SHA256+AES-256-GCM"
    public static let maximumArchivePlaintextBytes = 32 * 1_024 * 1_024
    public static let maximumArchiveEncryptedBytes = maximumArchivePlaintextBytes + 28
    public static let maximumEncodedPackageBytes = 48 * 1_024 * 1_024
    /// The encrypted inner package is padded to one of these public size classes before transport.
    /// Transports learn a coarse bucket, never the exact inner archive size.
    public static let sealedArchivePaddingBuckets = [
        64 * 1_024,
        256 * 1_024,
        1 * 1_024 * 1_024,
        4 * 1_024 * 1_024,
        16 * 1_024 * 1_024,
        64 * 1_024 * 1_024
    ]
    public static let maximumSealedCiphertextBytes = 64 * 1_024 * 1_024
    /// JSON/base64 overhead for the largest sealed ciphertext is bounded below this limit.
    public static let maximumEncodedTransportBytes = 96 * 1_024 * 1_024
    public static let maximumTransferLifetime: TimeInterval = 24 * 60 * 60
    public static let maximumConversations = 2_048
    public static let maximumEvents = 100_000
    public static let maximumEventsPerConversation = 25_000
    public static let maximumAttachmentReferences = 20_000
    public static let maximumContactAliases = 10_000
    public static let maximumImportReceipts = 512
    public static let maximumSignatureBytes = 16 * 1_024
    public static let maximumKEMCiphertextBytes = 64 * 1_024
}

public enum HistoryTransferV2Error: Error, Equatable {
    case invalidProjection
    case controlEventExcluded
    case invalidPackage
    case archiveTooLarge
    case itemLimitExceeded
    case notYetValid
    case expired
    case wrongIdentityGeneration
    case wrongRecipient
    case unauthorizedSender
    case manifestDigestMismatch
    case ciphertextDigestMismatch
    case keyWrapDigestMismatch
    case invalidAuthoritySignature
    case invalidInstallationSignature
    case crossGenerationApprovalRequired
    case invalidCrossGenerationApproval
    case decryptionFailed
    case replayConflict
    case replayLedgerFull
}

public enum HistoryEventProjectionKindV2: String, Codable, Equatable {
    case application
    case receipt
}

/// An inert rendering record. Control events are intentionally not representable.
public struct HistoryEventProjectionV2: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let clientTransactionId: UUID
    public let conversationId: String
    public let authorInstallationHandle: RelationshipInstallationHandle
    public let createdAt: Date
    public let kind: HistoryEventProjectionKindV2
    public let content: EncodedContent
    public let relation: EventRelation?

    public init(
        version: Int = NoctweaveHistoryTransferV2.version,
        id: UUID,
        clientTransactionId: UUID,
        conversationId: String,
        authorInstallationHandle: RelationshipInstallationHandle,
        createdAt: Date,
        kind: HistoryEventProjectionKindV2,
        content: EncodedContent,
        relation: EventRelation? = nil
    ) {
        self.version = version
        self.id = id
        self.clientTransactionId = clientTransactionId
        self.conversationId = conversationId
        self.authorInstallationHandle = authorInstallationHandle
        self.createdAt = createdAt
        self.kind = kind
        self.content = content
        self.relation = relation
    }

    public init(projecting event: ConversationEvent) throws {
        let projectedKind: HistoryEventProjectionKindV2
        switch event.kind {
        case .application:
            projectedKind = .application
        case .receipt:
            projectedKind = .receipt
        case .control:
            throw HistoryTransferV2Error.controlEventExcluded
        }
        self.init(
            id: event.id,
            clientTransactionId: event.clientTransactionId,
            conversationId: event.conversationId,
            authorInstallationHandle: event.authorInstallationHandle,
            createdAt: event.createdAt,
            kind: projectedKind,
            content: event.content,
            relation: event.relation
        )
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveHistoryTransferV2.version
            && !conversationId.isEmpty
            && conversationId.utf8.count <= 256
            && conversationId.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
            && authorInstallationHandle.isStructurallyValid
            && createdAt.timeIntervalSince1970.isFinite
            && content.isStructurallyValid
            && !(kind == .receipt && relation != nil)
    }
}

public struct HistoryConversationProjectionV2: Codable, Equatable, Identifiable {
    public var id: String { conversationId }
    public let conversationId: String
    public let events: [HistoryEventProjectionV2]

    public init(conversationId: String, events: [HistoryEventProjectionV2]) {
        self.conversationId = conversationId
        self.events = events.sorted {
            if $0.createdAt != $1.createdAt { return $0.createdAt < $1.createdAt }
            return $0.id.uuidString < $1.id.uuidString
        }
    }

    public var isStructurallyValid: Bool {
        !conversationId.isEmpty
            && conversationId.utf8.count <= 256
            && !events.isEmpty
            && events.count <= NoctweaveHistoryTransferV2.maximumEventsPerConversation
            && Set(events.map(\.id)).count == events.count
            && events.allSatisfy { $0.isStructurallyValid && $0.conversationId == conversationId }
    }
}

/// Metadata only: no blob locator, content key, message key, ratchet context, or fetch capability.
public struct HistoryAttachmentReferenceV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let sourceEventId: UUID
    public let mimeType: String
    public let byteCount: UInt64
    public let sha256: Data

    public init(
        id: UUID,
        sourceEventId: UUID,
        mimeType: String,
        byteCount: UInt64,
        sha256: Data
    ) {
        self.id = id
        self.sourceEventId = sourceEventId
        self.mimeType = mimeType
        self.byteCount = byteCount
        self.sha256 = sha256
    }

    public var isStructurallyValid: Bool {
        let normalizedMIME = mimeType.trimmingCharacters(in: .whitespacesAndNewlines)
        return !normalizedMIME.isEmpty
            && normalizedMIME == mimeType
            && mimeType.utf8.count <= 128
            && mimeType.utf8.allSatisfy { $0 >= 0x20 && $0 <= 0x7e && $0 != 0x3b }
            && byteCount > 0
            && byteCount <= NoctweaveSelfSyncV2.maximumArchiveBytes
            && sha256.count == 32
    }

    public var canFetchAttachment: Bool { false }
}

/// A local display alias associated with an opaque relationship identifier.
public struct HistoryContactAliasV2: Codable, Equatable, Identifiable {
    public var id: String { relationshipId }
    public let relationshipId: String
    public let alias: String

    public init(relationshipId: String, alias: String) {
        self.relationshipId = relationshipId
        self.alias = alias
    }

    public var isStructurallyValid: Bool {
        let normalizedAlias = alias.trimmingCharacters(in: .whitespacesAndNewlines)
        return !relationshipId.isEmpty
            && relationshipId.utf8.count <= 256
            && relationshipId.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
            && !normalizedAlias.isEmpty
            && normalizedAlias == alias
            && alias.utf8.count <= 256
            && alias.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
    }
}

/// The only plaintext accepted by the exporter and returned by the importer.
///
/// Its schema has no identity or installation private keys, inbox authority, ratchet/root/chain
/// state, reusable prekeys, self-sync key, app-lock material, routes, mailbox credentials, group
/// leaves, or future-participation authorization.
public struct ReadOnlyHistoryProjectionV2: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let identityGenerationId: UUID
    public let exportedAt: Date
    public let conversations: [HistoryConversationProjectionV2]
    public let attachmentReferences: [HistoryAttachmentReferenceV2]
    public let contactAliases: [HistoryContactAliasV2]

    public init(
        version: Int = NoctweaveHistoryTransferV2.version,
        id: UUID = UUID(),
        identityGenerationId: UUID,
        exportedAt: Date = Date(),
        conversations: [HistoryConversationProjectionV2],
        attachmentReferences: [HistoryAttachmentReferenceV2] = [],
        contactAliases: [HistoryContactAliasV2] = []
    ) {
        self.version = version
        self.id = id
        self.identityGenerationId = identityGenerationId
        self.exportedAt = exportedAt
        self.conversations = conversations.sorted { $0.conversationId < $1.conversationId }
        self.attachmentReferences = attachmentReferences.sorted { $0.id.uuidString < $1.id.uuidString }
        self.contactAliases = contactAliases.sorted { $0.relationshipId < $1.relationshipId }
    }

    public var totalEventCount: Int? {
        var total = 0
        for conversation in conversations {
            let addition = total.addingReportingOverflow(conversation.events.count)
            guard !addition.overflow else { return nil }
            total = addition.partialValue
        }
        return total
    }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveHistoryTransferV2.version,
              exportedAt.timeIntervalSince1970.isFinite,
              conversations.count <= NoctweaveHistoryTransferV2.maximumConversations,
              attachmentReferences.count <= NoctweaveHistoryTransferV2.maximumAttachmentReferences,
              contactAliases.count <= NoctweaveHistoryTransferV2.maximumContactAliases,
              Set(conversations.map(\.conversationId)).count == conversations.count,
              Set(attachmentReferences.map(\.id)).count == attachmentReferences.count,
              Set(contactAliases.map(\.relationshipId)).count == contactAliases.count,
              let totalEventCount,
              totalEventCount <= NoctweaveHistoryTransferV2.maximumEvents,
              conversations.allSatisfy(\.isStructurallyValid),
              attachmentReferences.allSatisfy(\.isStructurallyValid),
              contactAliases.allSatisfy(\.isStructurallyValid) else {
            return false
        }
        let eventIds = Set(conversations.flatMap { $0.events.map(\.id) })
        return attachmentReferences.allSatisfy { eventIds.contains($0.sourceEventId) }
    }

    public var authorizesMailboxSync: Bool { false }
    public var authorizesSending: Bool { false }
    public var authorizesGroupParticipation: Bool { false }
    public var authorizesFutureEpochs: Bool { false }
    public var authorizesFutureParticipation: Bool { false }
}

/// Explicit, short-lived authorization to carry inert history from one burned
/// identity generation into a different generation. Possessing it reveals the
/// otherwise separate generations to its intended recipient, so it must remain
/// local/private. It is never endpoint-admission, mailbox, group, route,
/// self-sync, contact-continuity, or future-participation authority.
public struct CrossGenerationHistoryBridgeApprovalV2: Codable, Equatable, Identifiable {
    public static let purpose = "Noctweave/read-only-history-generation-bridge/v2"

    public let id: UUID
    public let version: Int
    public let purpose: String
    public let sourceIdentityGenerationId: UUID
    public let recipientIdentityGenerationId: UUID
    public let senderEndpointId: UUID
    public let recipientEndpointId: UUID
    public let senderIdentityAuthorityPublicKey: Data
    public let senderEndpointSigningPublicKey: Data
    public let recipientAgreementPublicKeyDigest: Data
    public let nonce: Data
    public let issuedAt: Date
    public let expiresAt: Date
    public let authoritySignature: Data
    public let endpointPossessionSignature: Data

    public init(
        id: UUID = UUID(),
        version: Int = NoctweaveHistoryTransferV2.version,
        purpose: String = CrossGenerationHistoryBridgeApprovalV2.purpose,
        sourceIdentityGenerationId: UUID,
        recipientIdentityGenerationId: UUID,
        senderEndpointId: UUID,
        recipientEndpointId: UUID,
        senderIdentityAuthorityPublicKey: Data,
        senderEndpointSigningPublicKey: Data,
        recipientAgreementPublicKeyDigest: Data,
        nonce: Data,
        issuedAt: Date,
        expiresAt: Date,
        authoritySignature: Data,
        endpointPossessionSignature: Data
    ) {
        self.id = id
        self.version = version
        self.purpose = purpose
        self.sourceIdentityGenerationId = sourceIdentityGenerationId
        self.recipientIdentityGenerationId = recipientIdentityGenerationId
        self.senderEndpointId = senderEndpointId
        self.recipientEndpointId = recipientEndpointId
        self.senderIdentityAuthorityPublicKey = senderIdentityAuthorityPublicKey
        self.senderEndpointSigningPublicKey = senderEndpointSigningPublicKey
        self.recipientAgreementPublicKeyDigest = recipientAgreementPublicKeyDigest
        self.nonce = nonce
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.authoritySignature = authoritySignature
        self.endpointPossessionSignature = endpointPossessionSignature
    }

    public static func create(
        sourceIdentityGenerationId: UUID,
        recipientIdentityGenerationId: UUID,
        senderEndpointId: UUID,
        recipientEndpointId: UUID,
        senderIdentityAuthorityKey: SigningKeyPair,
        senderEndpointSigningKey: SigningKeyPair,
        recipientAgreementPublicKey: Data,
        nonce: Data? = nil,
        issuedAt: Date = Date(),
        expiresAt: Date
    ) throws -> CrossGenerationHistoryBridgeApprovalV2 {
        let nonce = nonce ?? SymmetricKey(size: .bits256).dataRepresentation
        let unsigned = CrossGenerationHistoryBridgeApprovalPayloadV2(
            id: UUID(),
            version: NoctweaveHistoryTransferV2.version,
            purpose: Self.purpose,
            sourceIdentityGenerationId: sourceIdentityGenerationId,
            recipientIdentityGenerationId: recipientIdentityGenerationId,
            senderEndpointId: senderEndpointId,
            recipientEndpointId: recipientEndpointId,
            senderIdentityAuthorityPublicKey: senderIdentityAuthorityKey.publicKeyData,
            senderEndpointSigningPublicKey: senderEndpointSigningKey.publicKeyData,
            recipientAgreementPublicKeyDigest: Data(SHA256.hash(data: recipientAgreementPublicKey)),
            nonce: nonce,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
        guard unsigned.isStructurallyValid,
              AgreementKeyPair.isValidPublicKey(recipientAgreementPublicKey) else {
            throw HistoryTransferV2Error.invalidCrossGenerationApproval
        }
        let authorizationData = try unsigned.signableData()
        let authoritySignature = try senderIdentityAuthorityKey.sign(authorizationData)
        let possession = CrossGenerationHistoryBridgePossessionV2(
            approvalDigest: Data(SHA256.hash(data: authorizationData)),
            authoritySignatureDigest: Data(SHA256.hash(data: authoritySignature))
        )
        let approval = CrossGenerationHistoryBridgeApprovalV2(
            id: unsigned.id,
            sourceIdentityGenerationId: sourceIdentityGenerationId,
            recipientIdentityGenerationId: recipientIdentityGenerationId,
            senderEndpointId: senderEndpointId,
            recipientEndpointId: recipientEndpointId,
            senderIdentityAuthorityPublicKey: senderIdentityAuthorityKey.publicKeyData,
            senderEndpointSigningPublicKey: senderEndpointSigningKey.publicKeyData,
            recipientAgreementPublicKeyDigest: unsigned.recipientAgreementPublicKeyDigest,
            nonce: nonce,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            authoritySignature: authoritySignature,
            endpointPossessionSignature: try senderEndpointSigningKey.sign(
                possession.signableData()
            )
        )
        guard approval.verify(at: issuedAt) else {
            throw HistoryTransferV2Error.invalidCrossGenerationApproval
        }
        return approval
    }

    public var isStructurallyValid: Bool {
        payload.isStructurallyValid
            && authoritySignature.count == 3_309
            && endpointPossessionSignature.count == 3_309
    }

    public var digest: Data? {
        guard let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else { return nil }
        return Data(SHA256.hash(data: encoded))
    }

    public func verify(at date: Date) -> Bool {
        guard isStructurallyValid,
              date.timeIntervalSince1970.isFinite,
              date >= issuedAt,
              date < expiresAt,
              let authorizationData = try? payload.signableData(),
              SigningKeyPair.verify(
                  signature: authoritySignature,
                  data: authorizationData,
                  publicKeyData: senderIdentityAuthorityPublicKey
              ) else {
            return false
        }
        let possession = CrossGenerationHistoryBridgePossessionV2(
            approvalDigest: Data(SHA256.hash(data: authorizationData)),
            authoritySignatureDigest: Data(SHA256.hash(data: authoritySignature))
        )
        guard let possessionData = try? possession.signableData() else { return false }
        return SigningKeyPair.verify(
            signature: endpointPossessionSignature,
            data: possessionData,
            publicKeyData: senderEndpointSigningPublicKey
        )
    }

    public var authorizesMailboxSync: Bool { false }
    public var authorizesSending: Bool { false }
    public var authorizesGroupParticipation: Bool { false }
    public var authorizesFutureEpochs: Bool { false }
    public var authorizesFutureParticipation: Bool { false }
    public var containsPrivateGenerationLink: Bool { true }
    public var authorizesIdentityContinuity: Bool { false }

    private var payload: CrossGenerationHistoryBridgeApprovalPayloadV2 {
        CrossGenerationHistoryBridgeApprovalPayloadV2(
            id: id,
            version: version,
            purpose: purpose,
            sourceIdentityGenerationId: sourceIdentityGenerationId,
            recipientIdentityGenerationId: recipientIdentityGenerationId,
            senderEndpointId: senderEndpointId,
            recipientEndpointId: recipientEndpointId,
            senderIdentityAuthorityPublicKey: senderIdentityAuthorityPublicKey,
            senderEndpointSigningPublicKey: senderEndpointSigningPublicKey,
            recipientAgreementPublicKeyDigest: recipientAgreementPublicKeyDigest,
            nonce: nonce,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
    }
}

public struct HistoryArchiveManifestV2: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let projectionId: UUID
    public let identityGenerationId: UUID
    public let createdByInstallationId: UUID
    public let recipientIdentityGenerationId: UUID
    public let recipientInstallationId: UUID
    public let recipientAgreementPublicKeyDigest: Data
    public let crossGenerationApprovalDigest: Data?
    public let scope: HistoryAccessScope
    public let createdAt: Date
    public let expiresAt: Date
    public let archiveCipherSuite: String
    public let plaintextByteCount: UInt64
    public let encryptedByteCount: UInt64
    public let projectionDigest: Data
    public let ciphertextDigest: Data
    public let conversationCount: UInt32
    public let eventCount: UInt32
    public let attachmentReferenceCount: UInt32
    public let contactAliasCount: UInt32

    public init(
        version: Int = NoctweaveHistoryTransferV2.version,
        id: UUID,
        projectionId: UUID,
        identityGenerationId: UUID,
        createdByInstallationId: UUID,
        recipientIdentityGenerationId: UUID? = nil,
        recipientInstallationId: UUID,
        recipientAgreementPublicKeyDigest: Data,
        crossGenerationApprovalDigest: Data? = nil,
        scope: HistoryAccessScope = .readOnlyHistory,
        createdAt: Date,
        expiresAt: Date,
        archiveCipherSuite: String = NoctweaveHistoryTransferV2.archiveCipherSuite,
        plaintextByteCount: UInt64,
        encryptedByteCount: UInt64,
        projectionDigest: Data,
        ciphertextDigest: Data,
        conversationCount: UInt32,
        eventCount: UInt32,
        attachmentReferenceCount: UInt32,
        contactAliasCount: UInt32
    ) {
        self.version = version
        self.id = id
        self.projectionId = projectionId
        self.identityGenerationId = identityGenerationId
        self.createdByInstallationId = createdByInstallationId
        self.recipientIdentityGenerationId = recipientIdentityGenerationId ?? identityGenerationId
        self.recipientInstallationId = recipientInstallationId
        self.recipientAgreementPublicKeyDigest = recipientAgreementPublicKeyDigest
        self.crossGenerationApprovalDigest = crossGenerationApprovalDigest
        self.scope = scope
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.archiveCipherSuite = archiveCipherSuite
        self.plaintextByteCount = plaintextByteCount
        self.encryptedByteCount = encryptedByteCount
        self.projectionDigest = projectionDigest
        self.ciphertextDigest = ciphertextDigest
        self.conversationCount = conversationCount
        self.eventCount = eventCount
        self.attachmentReferenceCount = attachmentReferenceCount
        self.contactAliasCount = contactAliasCount
    }

    public var isStructurallyValid: Bool {
        let lifetime = expiresAt.timeIntervalSince(createdAt)
        return version == NoctweaveHistoryTransferV2.version
            && recipientAgreementPublicKeyDigest.count == 32
            && (recipientIdentityGenerationId == identityGenerationId
                ? crossGenerationApprovalDigest == nil
                : crossGenerationApprovalDigest?.count == 32)
            && scope == .readOnlyHistory
            && createdAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && lifetime > 0
            && lifetime <= NoctweaveHistoryTransferV2.maximumTransferLifetime
            && archiveCipherSuite == NoctweaveHistoryTransferV2.archiveCipherSuite
            && plaintextByteCount > 0
            && plaintextByteCount <= UInt64(NoctweaveHistoryTransferV2.maximumArchivePlaintextBytes)
            && encryptedByteCount == plaintextByteCount + 28
            && encryptedByteCount <= UInt64(NoctweaveHistoryTransferV2.maximumArchiveEncryptedBytes)
            && projectionDigest.count == 32
            && ciphertextDigest.count == 32
            && conversationCount <= UInt32(NoctweaveHistoryTransferV2.maximumConversations)
            && eventCount <= UInt32(NoctweaveHistoryTransferV2.maximumEvents)
            && attachmentReferenceCount <= UInt32(NoctweaveHistoryTransferV2.maximumAttachmentReferences)
            && contactAliasCount <= UInt32(NoctweaveHistoryTransferV2.maximumContactAliases)
    }

    public var digest: Data? {
        guard let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else { return nil }
        return Data(SHA256.hash(data: encoded))
    }
}

public struct HistoryArchiveKeyWrapV2: Codable, Equatable {
    public let version: Int
    public let keyWrapSuite: String
    public let kemCiphertext: Data
    public let encryptedArchiveKey: EncryptedPayload

    public init(
        version: Int = NoctweaveHistoryTransferV2.version,
        keyWrapSuite: String = NoctweaveHistoryTransferV2.keyWrapSuite,
        kemCiphertext: Data,
        encryptedArchiveKey: EncryptedPayload
    ) {
        self.version = version
        self.keyWrapSuite = keyWrapSuite
        self.kemCiphertext = kemCiphertext
        self.encryptedArchiveKey = encryptedArchiveKey
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveHistoryTransferV2.version
            && keyWrapSuite == NoctweaveHistoryTransferV2.keyWrapSuite
            && !kemCiphertext.isEmpty
            && kemCiphertext.count <= NoctweaveHistoryTransferV2.maximumKEMCiphertextBytes
            && encryptedArchiveKey.nonce.count == 12
            && encryptedArchiveKey.ciphertext.count == 32
            && encryptedArchiveKey.tag.count == 16
    }

    public var digest: Data? {
        guard let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else { return nil }
        return Data(SHA256.hash(data: encoded))
    }
}

/// The signed inner archive. This object contains identity and installation metadata and must not
/// be sent directly over a transport. Seal it as `SealedHistoryArchiveTransportV2` first.
///
/// Its two signatures have distinct purposes: the identity authority authorizes the handoff, then
/// the sending installation proves possession over that exact authorization.
public struct EncryptedHistoryArchiveV2: Codable, Equatable, Identifiable {
    public var id: UUID { manifest.id }
    public let manifest: HistoryArchiveManifestV2
    public let manifestDigest: Data
    public let encryptedProjection: EncryptedPayload
    public let keyWrap: HistoryArchiveKeyWrapV2
    public let keyWrapDigest: Data
    public let senderIdentityAuthorityPublicKey: Data
    public let senderInstallationSigningPublicKey: Data
    public let authoritySignature: Data
    public let installationPossessionSignature: Data

    public init(
        manifest: HistoryArchiveManifestV2,
        manifestDigest: Data,
        encryptedProjection: EncryptedPayload,
        keyWrap: HistoryArchiveKeyWrapV2,
        keyWrapDigest: Data,
        senderIdentityAuthorityPublicKey: Data,
        senderInstallationSigningPublicKey: Data,
        authoritySignature: Data,
        installationPossessionSignature: Data
    ) {
        self.manifest = manifest
        self.manifestDigest = manifestDigest
        self.encryptedProjection = encryptedProjection
        self.keyWrap = keyWrap
        self.keyWrapDigest = keyWrapDigest
        self.senderIdentityAuthorityPublicKey = senderIdentityAuthorityPublicKey
        self.senderInstallationSigningPublicKey = senderInstallationSigningPublicKey
        self.authoritySignature = authoritySignature
        self.installationPossessionSignature = installationPossessionSignature
    }

    public var isStructurallyValid: Bool {
        manifest.isStructurallyValid
            && manifestDigest.count == 32
            && encryptedProjection.nonce.count == 12
            && encryptedProjection.ciphertext.count == Int(manifest.plaintextByteCount)
            && encryptedProjection.tag.count == 16
            && keyWrap.isStructurallyValid
            && keyWrapDigest.count == 32
            && SigningKeyPair.isValidPublicKey(senderIdentityAuthorityPublicKey)
            && SigningKeyPair.isValidPublicKey(senderInstallationSigningPublicKey)
            && senderIdentityAuthorityPublicKey != senderInstallationSigningPublicKey
            && !authoritySignature.isEmpty
            && authoritySignature.count <= NoctweaveHistoryTransferV2.maximumSignatureBytes
            && !installationPossessionSignature.isEmpty
            && installationPossessionSignature.count <= NoctweaveHistoryTransferV2.maximumSignatureBytes
    }

    /// Low-level encoding used only as plaintext for the recipient-encrypted outer transport seal.
    public func encodedForOuterSeal() throws -> Data {
        guard isStructurallyValid else { throw HistoryTransferV2Error.invalidPackage }
        let encoded = try NoctweaveCoder.encode(self, sortedKeys: true)
        guard encoded.count <= NoctweaveHistoryTransferV2.maximumEncodedPackageBytes else {
            throw HistoryTransferV2Error.archiveTooLarge
        }
        return encoded
    }
}

/// The only history-transfer object intended for relays, object stores, files, or peer transports.
///
/// All sender/recipient identifiers, public keys, timestamps, counts, signatures, and exact inner
/// size are inside the recipient-encrypted ciphertext. The clear wrapper deliberately contains
/// only the protocol version, one ML-KEM ciphertext, and the AES-GCM components.
public struct SealedHistoryArchiveTransportV2: Codable, Equatable {
    public let version: Int
    public let kemCiphertext: Data
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data

    public init(
        version: Int = NoctweaveHistoryTransferV2.version,
        kemCiphertext: Data,
        nonce: Data,
        ciphertext: Data,
        tag: Data
    ) {
        self.version = version
        self.kemCiphertext = kemCiphertext
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveHistoryTransferV2.version
            && !kemCiphertext.isEmpty
            && kemCiphertext.count <= NoctweaveHistoryTransferV2.maximumKEMCiphertextBytes
            && nonce.count == 12
            && NoctweaveHistoryTransferV2.sealedArchivePaddingBuckets.contains(ciphertext.count)
            && ciphertext.count <= NoctweaveHistoryTransferV2.maximumSealedCiphertextBytes
            && tag.count == 16
    }

    public func encodedForTransport() throws -> Data {
        guard isStructurallyValid else { throw HistoryTransferV2Error.invalidPackage }
        let encoded = try NoctweaveCoder.encode(self, sortedKeys: true)
        guard encoded.count <= NoctweaveHistoryTransferV2.maximumEncodedTransportBytes else {
            throw HistoryTransferV2Error.archiveTooLarge
        }
        return encoded
    }

    fileprivate var encryptedPayload: EncryptedPayload {
        EncryptedPayload(nonce: nonce, ciphertext: ciphertext, tag: tag)
    }
}

public struct HistoryArchiveImportTrustV2: Equatable {
    public let identityGenerationId: UUID
    public let recipientIdentityGenerationId: UUID
    public let senderInstallationId: UUID
    public let recipientInstallationId: UUID
    public let senderIdentityAuthorityPublicKey: Data
    public let senderInstallationSigningPublicKey: Data
    let crossGenerationApprovalDigest: Data?

    public init(
        identityGenerationId: UUID,
        senderInstallationId: UUID,
        recipientInstallationId: UUID,
        senderIdentityAuthorityPublicKey: Data,
        senderInstallationSigningPublicKey: Data
    ) {
        self.identityGenerationId = identityGenerationId
        self.recipientIdentityGenerationId = identityGenerationId
        self.senderInstallationId = senderInstallationId
        self.recipientInstallationId = recipientInstallationId
        self.senderIdentityAuthorityPublicKey = senderIdentityAuthorityPublicKey
        self.senderInstallationSigningPublicKey = senderInstallationSigningPublicKey
        self.crossGenerationApprovalDigest = nil
    }

    init(bridging approval: CrossGenerationHistoryBridgeApprovalV2) {
        identityGenerationId = approval.sourceIdentityGenerationId
        recipientIdentityGenerationId = approval.recipientIdentityGenerationId
        senderInstallationId = approval.senderEndpointId
        recipientInstallationId = approval.recipientEndpointId
        senderIdentityAuthorityPublicKey = approval.senderIdentityAuthorityPublicKey
        senderInstallationSigningPublicKey = approval.senderEndpointSigningPublicKey
        crossGenerationApprovalDigest = approval.digest
    }

    public var isStructurallyValid: Bool {
        SigningKeyPair.isValidPublicKey(senderIdentityAuthorityPublicKey)
            && SigningKeyPair.isValidPublicKey(senderInstallationSigningPublicKey)
            && senderIdentityAuthorityPublicKey != senderInstallationSigningPublicKey
            && (recipientIdentityGenerationId == identityGenerationId
                ? crossGenerationApprovalDigest == nil
                : crossGenerationApprovalDigest?.count == 32)
    }
}

public struct HistoryArchiveImportReceiptV2: Codable, Equatable, Identifiable {
    public var id: UUID { archiveId }
    public let archiveId: UUID
    public let manifestDigest: Data
    public let projectionDigest: Data
    public let importedAt: Date

    public init(archiveId: UUID, manifestDigest: Data, projectionDigest: Data, importedAt: Date) {
        self.archiveId = archiveId
        self.manifestDigest = manifestDigest
        self.projectionDigest = projectionDigest
        self.importedAt = importedAt
    }

    public var isStructurallyValid: Bool {
        manifestDigest.count == 32
            && projectionDigest.count == 32
            && importedAt.timeIntervalSince1970.isFinite
    }
}

public struct HistoryArchiveImportLedgerV2: Codable, Equatable {
    public private(set) var receipts: [HistoryArchiveImportReceiptV2]

    public init(receipts: [HistoryArchiveImportReceiptV2] = []) {
        self.receipts = receipts
    }

    public var isStructurallyValid: Bool {
        receipts.count <= NoctweaveHistoryTransferV2.maximumImportReceipts
            && Set(receipts.map(\.archiveId)).count == receipts.count
            && receipts.allSatisfy(\.isStructurallyValid)
    }

    fileprivate func disposition(for package: EncryptedHistoryArchiveV2) throws -> HistoryArchiveImportDispositionV2 {
        guard let existing = receipts.first(where: { $0.archiveId == package.id }) else {
            guard receipts.count < NoctweaveHistoryTransferV2.maximumImportReceipts else {
                throw HistoryTransferV2Error.replayLedgerFull
            }
            return .imported
        }
        guard existing.manifestDigest == package.manifestDigest,
              existing.projectionDigest == package.manifest.projectionDigest else {
            throw HistoryTransferV2Error.replayConflict
        }
        return .alreadyImported
    }

    fileprivate mutating func record(_ package: EncryptedHistoryArchiveV2, at date: Date) {
        guard !receipts.contains(where: { $0.archiveId == package.id }) else { return }
        receipts.append(
            HistoryArchiveImportReceiptV2(
                archiveId: package.id,
                manifestDigest: package.manifestDigest,
                projectionDigest: package.manifest.projectionDigest,
                importedAt: date
            )
        )
    }
}

public enum HistoryArchiveImportDispositionV2: String, Codable, Equatable {
    case imported
    case alreadyImported
}

public struct HistoryArchiveImportResultV2: Equatable {
    public let projection: ReadOnlyHistoryProjectionV2
    public let disposition: HistoryArchiveImportDispositionV2

    public init(projection: ReadOnlyHistoryProjectionV2, disposition: HistoryArchiveImportDispositionV2) {
        self.projection = projection
        self.disposition = disposition
    }
}

public enum HistoryTransferV2 {
    /// Creates the privacy-preserving transport package. This is the recommended export API.
    public static func exportArchive(
        _ projection: ReadOnlyHistoryProjectionV2,
        archiveId: UUID = UUID(),
        senderIdentityAuthorityKey: SigningKeyPair,
        senderInstallationId: UUID,
        senderInstallationSigningKey: SigningKeyPair,
        recipientInstallationId: UUID,
        recipientAgreementPublicKey: Data,
        createdAt: Date = Date(),
        expiresAt: Date
    ) throws -> SealedHistoryArchiveTransportV2 {
        let innerArchive = try exportInnerArchive(
            projection,
            archiveId: archiveId,
            senderIdentityAuthorityKey: senderIdentityAuthorityKey,
            senderInstallationId: senderInstallationId,
            senderInstallationSigningKey: senderInstallationSigningKey,
            recipientInstallationId: recipientInstallationId,
            recipientAgreementPublicKey: recipientAgreementPublicKey,
            createdAt: createdAt,
            expiresAt: expiresAt
        )
        return try sealForTransport(
            innerArchive,
            recipientAgreementPublicKey: recipientAgreementPublicKey
        )
    }

    /// Low-level construction of the signed inner archive. The returned object exposes metadata
    /// and must be wrapped by `sealForTransport` before leaving the process.
    public static func exportInnerArchive(
        _ projection: ReadOnlyHistoryProjectionV2,
        archiveId: UUID = UUID(),
        senderIdentityAuthorityKey: SigningKeyPair,
        senderInstallationId: UUID,
        senderInstallationSigningKey: SigningKeyPair,
        recipientInstallationId: UUID,
        recipientAgreementPublicKey: Data,
        createdAt: Date = Date(),
        expiresAt: Date
    ) throws -> EncryptedHistoryArchiveV2 {
        try makeInnerArchive(
            projection,
            archiveId: archiveId,
            senderIdentityAuthorityKey: senderIdentityAuthorityKey,
            senderInstallationId: senderInstallationId,
            senderInstallationSigningKey: senderInstallationSigningKey,
            recipientIdentityGenerationId: projection.identityGenerationId,
            recipientInstallationId: recipientInstallationId,
            recipientAgreementPublicKey: recipientAgreementPublicKey,
            crossGenerationApproval: nil,
            createdAt: createdAt,
            expiresAt: expiresAt
        )
    }

    /// Explicit cross-generation history bridge. The approval is independently
    /// signed by the source generation authority and source endpoint and is
    /// bound into every archive transcript. It grants inert history only.
    public static func exportCrossGenerationArchive(
        _ projection: ReadOnlyHistoryProjectionV2,
        archiveId: UUID = UUID(),
        senderIdentityAuthorityKey: SigningKeyPair,
        senderEndpointId: UUID,
        senderEndpointSigningKey: SigningKeyPair,
        recipientEndpointId: UUID,
        recipientAgreementPublicKey: Data,
        approval: CrossGenerationHistoryBridgeApprovalV2,
        createdAt: Date = Date(),
        expiresAt: Date
    ) throws -> SealedHistoryArchiveTransportV2 {
        let innerArchive = try makeInnerArchive(
            projection,
            archiveId: archiveId,
            senderIdentityAuthorityKey: senderIdentityAuthorityKey,
            senderInstallationId: senderEndpointId,
            senderInstallationSigningKey: senderEndpointSigningKey,
            recipientIdentityGenerationId: approval.recipientIdentityGenerationId,
            recipientInstallationId: recipientEndpointId,
            recipientAgreementPublicKey: recipientAgreementPublicKey,
            crossGenerationApproval: approval,
            createdAt: createdAt,
            expiresAt: expiresAt
        )
        return try sealForTransport(
            innerArchive,
            recipientAgreementPublicKey: recipientAgreementPublicKey
        )
    }

    private static func makeInnerArchive(
        _ projection: ReadOnlyHistoryProjectionV2,
        archiveId: UUID,
        senderIdentityAuthorityKey: SigningKeyPair,
        senderInstallationId: UUID,
        senderInstallationSigningKey: SigningKeyPair,
        recipientIdentityGenerationId: UUID,
        recipientInstallationId: UUID,
        recipientAgreementPublicKey: Data,
        crossGenerationApproval: CrossGenerationHistoryBridgeApprovalV2?,
        createdAt: Date,
        expiresAt: Date
    ) throws -> EncryptedHistoryArchiveV2 {
        guard projection.isStructurallyValid,
              SigningKeyPair.isValidPublicKey(senderIdentityAuthorityKey.publicKeyData),
              SigningKeyPair.isValidPublicKey(senderInstallationSigningKey.publicKeyData),
              senderIdentityAuthorityKey.publicKeyData != senderInstallationSigningKey.publicKeyData,
              AgreementKeyPair.isValidPublicKey(recipientAgreementPublicKey),
              createdAt.timeIntervalSince1970.isFinite,
              expiresAt.timeIntervalSince1970.isFinite else {
            throw HistoryTransferV2Error.invalidProjection
        }
        let lifetime = expiresAt.timeIntervalSince(createdAt)
        guard lifetime > 0 else { throw HistoryTransferV2Error.expired }
        guard lifetime <= NoctweaveHistoryTransferV2.maximumTransferLifetime else {
            throw HistoryTransferV2Error.invalidPackage
        }

        let crossGenerationApprovalDigest: Data?
        if recipientIdentityGenerationId == projection.identityGenerationId {
            guard crossGenerationApproval == nil else {
                throw HistoryTransferV2Error.invalidCrossGenerationApproval
            }
            crossGenerationApprovalDigest = nil
        } else {
            guard let approval = crossGenerationApproval,
                  approval.verify(at: createdAt),
                  approval.sourceIdentityGenerationId == projection.identityGenerationId,
                  approval.recipientIdentityGenerationId == recipientIdentityGenerationId,
                  approval.senderEndpointId == senderInstallationId,
                  approval.recipientEndpointId == recipientInstallationId,
                  approval.senderIdentityAuthorityPublicKey
                    == senderIdentityAuthorityKey.publicKeyData,
                  approval.senderEndpointSigningPublicKey
                    == senderInstallationSigningKey.publicKeyData,
                  approval.recipientAgreementPublicKeyDigest
                    == Data(SHA256.hash(data: recipientAgreementPublicKey)),
                  expiresAt <= approval.expiresAt,
                  let approvalDigest = approval.digest else {
                throw HistoryTransferV2Error.invalidCrossGenerationApproval
            }
            crossGenerationApprovalDigest = approvalDigest
        }

        var encodedProjection = try NoctweaveCoder.encode(projection, sortedKeys: true)
        defer { encodedProjection.secureWipe() }
        guard !encodedProjection.isEmpty,
              encodedProjection.count <= NoctweaveHistoryTransferV2.maximumArchivePlaintextBytes else {
            throw HistoryTransferV2Error.archiveTooLarge
        }
        guard let eventCount = projection.totalEventCount,
              let conversationCount = UInt32(exactly: projection.conversations.count),
              let encodedEventCount = UInt32(exactly: eventCount),
              let attachmentCount = UInt32(exactly: projection.attachmentReferences.count),
              let aliasCount = UInt32(exactly: projection.contactAliases.count) else {
            throw HistoryTransferV2Error.itemLimitExceeded
        }

        let projectionDigest = Data(SHA256.hash(data: encodedProjection))
        let recipientKeyDigest = Data(SHA256.hash(data: recipientAgreementPublicKey))
        let encryptionContext = HistoryArchiveEncryptionContextV2(
            archiveId: archiveId,
            projectionId: projection.id,
            identityGenerationId: projection.identityGenerationId,
            createdByInstallationId: senderInstallationId,
            recipientIdentityGenerationId: recipientIdentityGenerationId,
            recipientInstallationId: recipientInstallationId,
            recipientAgreementPublicKeyDigest: recipientKeyDigest,
            crossGenerationApprovalDigest: crossGenerationApprovalDigest,
            createdAt: createdAt,
            expiresAt: expiresAt,
            plaintextByteCount: UInt64(encodedProjection.count),
            projectionDigest: projectionDigest,
            conversationCount: conversationCount,
            eventCount: encodedEventCount,
            attachmentReferenceCount: attachmentCount,
            contactAliasCount: aliasCount
        )
        let encryptionAAD = try NoctweaveCoder.encode(encryptionContext, sortedKeys: true)
        var archiveKeyData = SymmetricKey(size: .bits256).dataRepresentation
        defer { archiveKeyData.secureWipe() }
        let encryptedProjection = try CryptoBox.encrypt(
            encodedProjection,
            key: SymmetricKey(data: archiveKeyData),
            authenticatedData: encryptionAAD
        )
        let encryptedProjectionEncoding = try NoctweaveCoder.encode(encryptedProjection, sortedKeys: true)
        let ciphertextDigest = Data(SHA256.hash(data: encryptedProjectionEncoding))
        let manifest = HistoryArchiveManifestV2(
            id: archiveId,
            projectionId: projection.id,
            identityGenerationId: projection.identityGenerationId,
            createdByInstallationId: senderInstallationId,
            recipientIdentityGenerationId: recipientIdentityGenerationId,
            recipientInstallationId: recipientInstallationId,
            recipientAgreementPublicKeyDigest: recipientKeyDigest,
            crossGenerationApprovalDigest: crossGenerationApprovalDigest,
            createdAt: createdAt,
            expiresAt: expiresAt,
            plaintextByteCount: UInt64(encodedProjection.count),
            encryptedByteCount: UInt64(encryptedProjection.nonce.count + encryptedProjection.ciphertext.count + encryptedProjection.tag.count),
            projectionDigest: projectionDigest,
            ciphertextDigest: ciphertextDigest,
            conversationCount: conversationCount,
            eventCount: encodedEventCount,
            attachmentReferenceCount: attachmentCount,
            contactAliasCount: aliasCount
        )
        guard let manifestDigest = manifest.digest else { throw HistoryTransferV2Error.invalidPackage }

        var kemOutput = try AgreementKeyPair.encapsulate(to: recipientAgreementPublicKey)
        defer { kemOutput.sharedSecret.secureWipe() }
        let keyWrapContext = HistoryKeyWrapContextV2(
            archiveId: archiveId,
            manifestDigest: manifestDigest,
            identityGenerationId: projection.identityGenerationId,
            recipientIdentityGenerationId: recipientIdentityGenerationId,
            recipientInstallationId: recipientInstallationId,
            recipientAgreementPublicKeyDigest: recipientKeyDigest,
            crossGenerationApprovalDigest: crossGenerationApprovalDigest,
            scope: .readOnlyHistory,
            expiresAt: expiresAt
        )
        let keyWrapAAD = try NoctweaveCoder.encode(keyWrapContext, sortedKeys: true)
        var wrappingKeyData = CryptoBox.deriveChainKey(
            sharedSecret: kemOutput.sharedSecret,
            salt: manifestDigest,
            info: keyWrapAAD
        )
        defer { wrappingKeyData.secureWipe() }
        let keyWrap = HistoryArchiveKeyWrapV2(
            kemCiphertext: kemOutput.ciphertext,
            encryptedArchiveKey: try CryptoBox.encrypt(
                archiveKeyData,
                key: SymmetricKey(data: wrappingKeyData),
                authenticatedData: keyWrapAAD
            )
        )
        guard let keyWrapDigest = keyWrap.digest else { throw HistoryTransferV2Error.invalidPackage }
        let authorization = HistoryAuthorityAuthorizationV2(
            archiveId: archiveId,
            manifestDigest: manifestDigest,
            keyWrapDigest: keyWrapDigest,
            identityGenerationId: projection.identityGenerationId,
            recipientIdentityGenerationId: recipientIdentityGenerationId,
            senderInstallationId: senderInstallationId,
            senderIdentityAuthorityPublicKey: senderIdentityAuthorityKey.publicKeyData,
            senderInstallationSigningPublicKey: senderInstallationSigningKey.publicKeyData,
            recipientInstallationId: recipientInstallationId,
            recipientAgreementPublicKeyDigest: recipientKeyDigest,
            crossGenerationApprovalDigest: crossGenerationApprovalDigest,
            scope: .readOnlyHistory,
            expiresAt: expiresAt
        )
        let authorizationData = try NoctweaveCoder.encode(authorization, sortedKeys: true)
        let authoritySignature = try senderIdentityAuthorityKey.sign(authorizationData)
        let possession = HistoryInstallationPossessionV2(
            authorizationDigest: Data(SHA256.hash(data: authorizationData)),
            authoritySignatureDigest: Data(SHA256.hash(data: authoritySignature))
        )
        let possessionData = try NoctweaveCoder.encode(possession, sortedKeys: true)
        let installationSignature = try senderInstallationSigningKey.sign(possessionData)
        let package = EncryptedHistoryArchiveV2(
            manifest: manifest,
            manifestDigest: manifestDigest,
            encryptedProjection: encryptedProjection,
            keyWrap: keyWrap,
            keyWrapDigest: keyWrapDigest,
            senderIdentityAuthorityPublicKey: senderIdentityAuthorityKey.publicKeyData,
            senderInstallationSigningPublicKey: senderInstallationSigningKey.publicKeyData,
            authoritySignature: authoritySignature,
            installationPossessionSignature: installationSignature
        )
        guard package.isStructurallyValid else { throw HistoryTransferV2Error.invalidPackage }
        return package
    }

    /// Low-level sealing helper for callers that constructed an inner archive separately.
    public static func sealForTransport(
        _ innerArchive: EncryptedHistoryArchiveV2,
        recipientAgreementPublicKey: Data
    ) throws -> SealedHistoryArchiveTransportV2 {
        guard innerArchive.isStructurallyValid,
              AgreementKeyPair.isValidPublicKey(recipientAgreementPublicKey),
              innerArchive.manifest.recipientAgreementPublicKeyDigest
                == Data(SHA256.hash(data: recipientAgreementPublicKey)) else {
            throw HistoryTransferV2Error.wrongRecipient
        }

        var encodedInnerArchive = try innerArchive.encodedForOuterSeal()
        defer { encodedInnerArchive.secureWipe() }
        let lengthPrefixBytes = MemoryLayout<UInt64>.size
        let unpaddedByteCount = lengthPrefixBytes + encodedInnerArchive.count
        guard let paddedByteCount = NoctweaveHistoryTransferV2.sealedArchivePaddingBuckets
            .first(where: { $0 >= unpaddedByteCount }),
              paddedByteCount <= NoctweaveHistoryTransferV2.maximumSealedCiphertextBytes else {
            throw HistoryTransferV2Error.archiveTooLarge
        }

        var paddedInnerArchive = Data()
        paddedInnerArchive.reserveCapacity(paddedByteCount)
        var encodedLength = UInt64(encodedInnerArchive.count).bigEndian
        withUnsafeBytes(of: &encodedLength) { paddedInnerArchive.append(contentsOf: $0) }
        paddedInnerArchive.append(encodedInnerArchive)
        paddedInnerArchive.append(
            Data(repeating: 0, count: paddedByteCount - paddedInnerArchive.count)
        )
        defer { paddedInnerArchive.secureWipe() }

        var kemOutput = try AgreementKeyPair.encapsulate(to: recipientAgreementPublicKey)
        defer { kemOutput.sharedSecret.secureWipe() }
        let kemCiphertextDigest = Data(SHA256.hash(data: kemOutput.ciphertext))
        let sealContext = HistoryOuterSealContextV2(
            version: NoctweaveHistoryTransferV2.version,
            kemCiphertextDigest: kemCiphertextDigest,
            paddedByteCount: UInt64(paddedByteCount)
        )
        let authenticatedData = try NoctweaveCoder.encode(sealContext, sortedKeys: true)
        var transportKeyData = CryptoBox.deriveChainKey(
            sharedSecret: kemOutput.sharedSecret,
            salt: kemCiphertextDigest,
            info: authenticatedData
        )
        defer { transportKeyData.secureWipe() }
        let encrypted = try CryptoBox.encrypt(
            paddedInnerArchive,
            key: SymmetricKey(data: transportKeyData),
            authenticatedData: authenticatedData
        )
        let sealed = SealedHistoryArchiveTransportV2(
            kemCiphertext: kemOutput.ciphertext,
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
            tag: encrypted.tag
        )
        guard sealed.isStructurallyValid else { throw HistoryTransferV2Error.invalidPackage }
        return sealed
    }

    /// Imports a sealed transport package. Callers must atomically persist the returned projection
    /// and the mutated replay ledger; use a ledger copy until that storage transaction commits.
    public static func importArchive(
        encodedPackage: Data,
        trust: HistoryArchiveImportTrustV2,
        recipientAgreementKey: AgreementKeyPair,
        ledger: inout HistoryArchiveImportLedgerV2,
        at date: Date = Date()
    ) throws -> HistoryArchiveImportResultV2 {
        guard !encodedPackage.isEmpty,
              encodedPackage.count <= NoctweaveHistoryTransferV2.maximumEncodedTransportBytes else {
            throw HistoryTransferV2Error.archiveTooLarge
        }
        guard let package = try? NoctweaveCoder.decode(
            SealedHistoryArchiveTransportV2.self,
            from: encodedPackage
        ) else {
            throw HistoryTransferV2Error.invalidPackage
        }
        return try importArchive(
            package,
            trust: trust,
            recipientAgreementKey: recipientAgreementKey,
            ledger: &ledger,
            at: date
        )
    }

    public static func importCrossGenerationArchive(
        encodedPackage: Data,
        approval: CrossGenerationHistoryBridgeApprovalV2,
        recipientAgreementKey: AgreementKeyPair,
        ledger: inout HistoryArchiveImportLedgerV2,
        at date: Date = Date()
    ) throws -> HistoryArchiveImportResultV2 {
        guard approval.verify(at: date),
              approval.recipientAgreementPublicKeyDigest
                == Data(SHA256.hash(data: recipientAgreementKey.publicKeyData)) else {
            throw HistoryTransferV2Error.invalidCrossGenerationApproval
        }
        return try importArchive(
            encodedPackage: encodedPackage,
            trust: HistoryArchiveImportTrustV2(bridging: approval),
            recipientAgreementKey: recipientAgreementKey,
            ledger: &ledger,
            at: date
        )
    }

    public static func importCrossGenerationArchive(
        _ package: SealedHistoryArchiveTransportV2,
        approval: CrossGenerationHistoryBridgeApprovalV2,
        recipientAgreementKey: AgreementKeyPair,
        ledger: inout HistoryArchiveImportLedgerV2,
        at date: Date = Date()
    ) throws -> HistoryArchiveImportResultV2 {
        guard approval.verify(at: date),
              approval.recipientAgreementPublicKeyDigest
                == Data(SHA256.hash(data: recipientAgreementKey.publicKeyData)) else {
            throw HistoryTransferV2Error.invalidCrossGenerationApproval
        }
        return try importArchive(
            package,
            trust: HistoryArchiveImportTrustV2(bridging: approval),
            recipientAgreementKey: recipientAgreementKey,
            ledger: &ledger,
            at: date
        )
    }

    /// Imports a decoded sealed transport package. Caller storage must commit the projection and
    /// replay ledger together before treating the import as durable.
    public static func importArchive(
        _ package: SealedHistoryArchiveTransportV2,
        trust: HistoryArchiveImportTrustV2,
        recipientAgreementKey: AgreementKeyPair,
        ledger: inout HistoryArchiveImportLedgerV2,
        at date: Date = Date()
    ) throws -> HistoryArchiveImportResultV2 {
        guard package.isStructurallyValid else { throw HistoryTransferV2Error.invalidPackage }
        let kemCiphertextDigest = Data(SHA256.hash(data: package.kemCiphertext))
        let sealContext = HistoryOuterSealContextV2(
            version: package.version,
            kemCiphertextDigest: kemCiphertextDigest,
            paddedByteCount: UInt64(package.ciphertext.count)
        )
        let authenticatedData = try NoctweaveCoder.encode(sealContext, sortedKeys: true)
        var sharedSecret: Data
        do {
            sharedSecret = try recipientAgreementKey.decapsulate(ciphertext: package.kemCiphertext)
        } catch {
            throw HistoryTransferV2Error.decryptionFailed
        }
        defer { sharedSecret.secureWipe() }
        var transportKeyData = CryptoBox.deriveChainKey(
            sharedSecret: sharedSecret,
            salt: kemCiphertextDigest,
            info: authenticatedData
        )
        defer { transportKeyData.secureWipe() }
        var paddedInnerArchive: Data
        do {
            paddedInnerArchive = try CryptoBox.decrypt(
                package.encryptedPayload,
                key: SymmetricKey(data: transportKeyData),
                authenticatedData: authenticatedData
            )
        } catch {
            throw HistoryTransferV2Error.decryptionFailed
        }
        defer { paddedInnerArchive.secureWipe() }

        let lengthPrefixBytes = MemoryLayout<UInt64>.size
        guard paddedInnerArchive.count == package.ciphertext.count,
              paddedInnerArchive.count >= lengthPrefixBytes else {
            throw HistoryTransferV2Error.invalidPackage
        }
        var encodedLength: UInt64 = 0
        for byte in paddedInnerArchive.prefix(lengthPrefixBytes) {
            encodedLength = (encodedLength << 8) | UInt64(byte)
        }
        guard encodedLength > 0,
              encodedLength <= UInt64(NoctweaveHistoryTransferV2.maximumEncodedPackageBytes),
              let innerLength = Int(exactly: encodedLength),
              innerLength <= paddedInnerArchive.count - lengthPrefixBytes else {
            throw HistoryTransferV2Error.invalidPackage
        }
        let innerEnd = lengthPrefixBytes + innerLength
        guard paddedInnerArchive[innerEnd...].allSatisfy({ $0 == 0 }) else {
            throw HistoryTransferV2Error.invalidPackage
        }
        var encodedInnerArchive = Data(paddedInnerArchive[lengthPrefixBytes..<innerEnd])
        defer { encodedInnerArchive.secureWipe() }
        guard let innerArchive = try? NoctweaveCoder.decode(
            EncryptedHistoryArchiveV2.self,
            from: encodedInnerArchive
        ) else {
            throw HistoryTransferV2Error.invalidPackage
        }
        return try importInnerArchive(
            innerArchive,
            trust: trust,
            recipientAgreementKey: recipientAgreementKey,
            ledger: &ledger,
            at: date
        )
    }

    /// Low-level inner import for conformance/testing. Never accept these bytes from a transport;
    /// doing so exposes archive metadata outside the outer recipient seal.
    public static func importInnerArchive(
        encodedPackage: Data,
        trust: HistoryArchiveImportTrustV2,
        recipientAgreementKey: AgreementKeyPair,
        ledger: inout HistoryArchiveImportLedgerV2,
        at date: Date = Date()
    ) throws -> HistoryArchiveImportResultV2 {
        guard !encodedPackage.isEmpty,
              encodedPackage.count <= NoctweaveHistoryTransferV2.maximumEncodedPackageBytes else {
            throw HistoryTransferV2Error.archiveTooLarge
        }
        guard let package = try? NoctweaveCoder.decode(
            EncryptedHistoryArchiveV2.self,
            from: encodedPackage
        ) else {
            throw HistoryTransferV2Error.invalidPackage
        }
        return try importInnerArchive(
            package,
            trust: trust,
            recipientAgreementKey: recipientAgreementKey,
            ledger: &ledger,
            at: date
        )
    }

    /// Low-level decoded inner import. Prefer `importArchive` with a sealed package.
    public static func importInnerArchive(
        _ package: EncryptedHistoryArchiveV2,
        trust: HistoryArchiveImportTrustV2,
        recipientAgreementKey: AgreementKeyPair,
        ledger: inout HistoryArchiveImportLedgerV2,
        at date: Date = Date()
    ) throws -> HistoryArchiveImportResultV2 {
        guard date.timeIntervalSince1970.isFinite,
              trust.isStructurallyValid,
              ledger.isStructurallyValid else {
            throw HistoryTransferV2Error.invalidPackage
        }
        guard package.manifest.plaintextByteCount <= UInt64(NoctweaveHistoryTransferV2.maximumArchivePlaintextBytes),
              package.manifest.encryptedByteCount <= UInt64(NoctweaveHistoryTransferV2.maximumArchiveEncryptedBytes) else {
            throw HistoryTransferV2Error.archiveTooLarge
        }
        guard package.isStructurallyValid else { throw HistoryTransferV2Error.invalidPackage }
        guard package.manifest.identityGenerationId == trust.identityGenerationId else {
            throw HistoryTransferV2Error.wrongIdentityGeneration
        }
        guard package.manifest.recipientIdentityGenerationId
                == trust.recipientIdentityGenerationId else {
            if package.manifest.recipientIdentityGenerationId
                != package.manifest.identityGenerationId {
                throw HistoryTransferV2Error.crossGenerationApprovalRequired
            }
            throw HistoryTransferV2Error.wrongIdentityGeneration
        }
        guard package.manifest.crossGenerationApprovalDigest
                == trust.crossGenerationApprovalDigest else {
            throw package.manifest.recipientIdentityGenerationId
                == package.manifest.identityGenerationId
                ? HistoryTransferV2Error.invalidPackage
                : HistoryTransferV2Error.invalidCrossGenerationApproval
        }
        guard package.manifest.createdByInstallationId == trust.senderInstallationId,
              package.senderIdentityAuthorityPublicKey == trust.senderIdentityAuthorityPublicKey,
              package.senderInstallationSigningPublicKey == trust.senderInstallationSigningPublicKey else {
            throw HistoryTransferV2Error.unauthorizedSender
        }
        guard package.manifest.recipientInstallationId == trust.recipientInstallationId,
              package.manifest.recipientAgreementPublicKeyDigest == Data(SHA256.hash(data: recipientAgreementKey.publicKeyData)) else {
            throw HistoryTransferV2Error.wrongRecipient
        }
        guard date >= package.manifest.createdAt else { throw HistoryTransferV2Error.notYetValid }
        guard date < package.manifest.expiresAt else { throw HistoryTransferV2Error.expired }
        guard package.manifest.digest == package.manifestDigest else {
            throw HistoryTransferV2Error.manifestDigestMismatch
        }
        let encryptedProjectionEncoding = try NoctweaveCoder.encode(package.encryptedProjection, sortedKeys: true)
        guard Data(SHA256.hash(data: encryptedProjectionEncoding)) == package.manifest.ciphertextDigest else {
            throw HistoryTransferV2Error.ciphertextDigestMismatch
        }
        guard package.keyWrap.digest == package.keyWrapDigest else {
            throw HistoryTransferV2Error.keyWrapDigestMismatch
        }

        let authorization = HistoryAuthorityAuthorizationV2(
            archiveId: package.id,
            manifestDigest: package.manifestDigest,
            keyWrapDigest: package.keyWrapDigest,
            identityGenerationId: package.manifest.identityGenerationId,
            recipientIdentityGenerationId: package.manifest.recipientIdentityGenerationId,
            senderInstallationId: package.manifest.createdByInstallationId,
            senderIdentityAuthorityPublicKey: package.senderIdentityAuthorityPublicKey,
            senderInstallationSigningPublicKey: package.senderInstallationSigningPublicKey,
            recipientInstallationId: package.manifest.recipientInstallationId,
            recipientAgreementPublicKeyDigest: package.manifest.recipientAgreementPublicKeyDigest,
            crossGenerationApprovalDigest: package.manifest.crossGenerationApprovalDigest,
            scope: package.manifest.scope,
            expiresAt: package.manifest.expiresAt
        )
        let authorizationData = try NoctweaveCoder.encode(authorization, sortedKeys: true)
        guard SigningKeyPair.verify(
            signature: package.authoritySignature,
            data: authorizationData,
            publicKeyData: package.senderIdentityAuthorityPublicKey
        ) else {
            throw HistoryTransferV2Error.invalidAuthoritySignature
        }
        let possession = HistoryInstallationPossessionV2(
            authorizationDigest: Data(SHA256.hash(data: authorizationData)),
            authoritySignatureDigest: Data(SHA256.hash(data: package.authoritySignature))
        )
        let possessionData = try NoctweaveCoder.encode(possession, sortedKeys: true)
        guard SigningKeyPair.verify(
            signature: package.installationPossessionSignature,
            data: possessionData,
            publicKeyData: package.senderInstallationSigningPublicKey
        ) else {
            throw HistoryTransferV2Error.invalidInstallationSignature
        }

        let disposition = try ledger.disposition(for: package)
        let keyWrapContext = HistoryKeyWrapContextV2(
            archiveId: package.id,
            manifestDigest: package.manifestDigest,
            identityGenerationId: package.manifest.identityGenerationId,
            recipientIdentityGenerationId: package.manifest.recipientIdentityGenerationId,
            recipientInstallationId: package.manifest.recipientInstallationId,
            recipientAgreementPublicKeyDigest: package.manifest.recipientAgreementPublicKeyDigest,
            crossGenerationApprovalDigest: package.manifest.crossGenerationApprovalDigest,
            scope: package.manifest.scope,
            expiresAt: package.manifest.expiresAt
        )
        let keyWrapAAD = try NoctweaveCoder.encode(keyWrapContext, sortedKeys: true)
        var sharedSecret: Data
        do {
            sharedSecret = try recipientAgreementKey.decapsulate(ciphertext: package.keyWrap.kemCiphertext)
        } catch {
            throw HistoryTransferV2Error.decryptionFailed
        }
        defer { sharedSecret.secureWipe() }
        var wrappingKeyData = CryptoBox.deriveChainKey(
            sharedSecret: sharedSecret,
            salt: package.manifestDigest,
            info: keyWrapAAD
        )
        defer { wrappingKeyData.secureWipe() }
        var archiveKeyData: Data
        do {
            archiveKeyData = try CryptoBox.decrypt(
                package.keyWrap.encryptedArchiveKey,
                key: SymmetricKey(data: wrappingKeyData),
                authenticatedData: keyWrapAAD
            )
        } catch {
            throw HistoryTransferV2Error.decryptionFailed
        }
        defer { archiveKeyData.secureWipe() }
        guard archiveKeyData.count == 32 else { throw HistoryTransferV2Error.decryptionFailed }

        let encryptionContext = HistoryArchiveEncryptionContextV2(manifest: package.manifest)
        let encryptionAAD = try NoctweaveCoder.encode(encryptionContext, sortedKeys: true)
        var plaintext: Data
        do {
            plaintext = try CryptoBox.decrypt(
                package.encryptedProjection,
                key: SymmetricKey(data: archiveKeyData),
                authenticatedData: encryptionAAD
            )
        } catch {
            throw HistoryTransferV2Error.decryptionFailed
        }
        defer { plaintext.secureWipe() }
        guard plaintext.count == Int(package.manifest.plaintextByteCount),
              Data(SHA256.hash(data: plaintext)) == package.manifest.projectionDigest,
              let projection = try? NoctweaveCoder.decode(ReadOnlyHistoryProjectionV2.self, from: plaintext),
              projection.isStructurallyValid,
              projection.id == package.manifest.projectionId,
              projection.identityGenerationId == package.manifest.identityGenerationId,
              projection.conversations.count == Int(package.manifest.conversationCount),
              projection.totalEventCount == Int(package.manifest.eventCount),
              projection.attachmentReferences.count == Int(package.manifest.attachmentReferenceCount),
              projection.contactAliases.count == Int(package.manifest.contactAliasCount) else {
            throw HistoryTransferV2Error.invalidProjection
        }

        // Commit only after authentication, decryption, digest checks, decoding, and all bounds pass.
        if disposition == .imported {
            ledger.record(package, at: date)
        }
        return HistoryArchiveImportResultV2(projection: projection, disposition: disposition)
    }
}

private struct CrossGenerationHistoryBridgeApprovalPayloadV2: Codable {
    let id: UUID
    let version: Int
    let purpose: String
    let sourceIdentityGenerationId: UUID
    let recipientIdentityGenerationId: UUID
    let senderEndpointId: UUID
    let recipientEndpointId: UUID
    let senderIdentityAuthorityPublicKey: Data
    let senderEndpointSigningPublicKey: Data
    let recipientAgreementPublicKeyDigest: Data
    let nonce: Data
    let issuedAt: Date
    let expiresAt: Date

    var isStructurallyValid: Bool {
        let lifetime = expiresAt.timeIntervalSince(issuedAt)
        return version == NoctweaveHistoryTransferV2.version
            && purpose == CrossGenerationHistoryBridgeApprovalV2.purpose
            && sourceIdentityGenerationId != recipientIdentityGenerationId
            && SigningKeyPair.isValidPublicKey(senderIdentityAuthorityPublicKey)
            && SigningKeyPair.isValidPublicKey(senderEndpointSigningPublicKey)
            && senderIdentityAuthorityPublicKey != senderEndpointSigningPublicKey
            && recipientAgreementPublicKeyDigest.count == 32
            && nonce.count == 32
            && issuedAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && lifetime > 0
            && lifetime <= NoctweaveHistoryTransferV2.maximumTransferLifetime
    }

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

private struct CrossGenerationHistoryBridgePossessionV2: Codable {
    let purpose: String
    let approvalDigest: Data
    let authoritySignatureDigest: Data

    init(approvalDigest: Data, authoritySignatureDigest: Data) {
        purpose = "Noctweave/read-only-history-generation-bridge-possession/v2"
        self.approvalDigest = approvalDigest
        self.authoritySignatureDigest = authoritySignatureDigest
    }

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

private struct HistoryArchiveEncryptionContextV2: Encodable {
    let domain = "Noctweave/history-archive-content/v2"
    let archiveId: UUID
    let projectionId: UUID
    let identityGenerationId: UUID
    let createdByInstallationId: UUID
    let recipientIdentityGenerationId: UUID
    let recipientInstallationId: UUID
    let recipientAgreementPublicKeyDigest: Data
    let crossGenerationApprovalDigest: Data?
    let scope = HistoryAccessScope.readOnlyHistory
    let createdAt: Date
    let expiresAt: Date
    let archiveCipherSuite = NoctweaveHistoryTransferV2.archiveCipherSuite
    let plaintextByteCount: UInt64
    let projectionDigest: Data
    let conversationCount: UInt32
    let eventCount: UInt32
    let attachmentReferenceCount: UInt32
    let contactAliasCount: UInt32

    init(
        archiveId: UUID,
        projectionId: UUID,
        identityGenerationId: UUID,
        createdByInstallationId: UUID,
        recipientIdentityGenerationId: UUID,
        recipientInstallationId: UUID,
        recipientAgreementPublicKeyDigest: Data,
        crossGenerationApprovalDigest: Data?,
        createdAt: Date,
        expiresAt: Date,
        plaintextByteCount: UInt64,
        projectionDigest: Data,
        conversationCount: UInt32,
        eventCount: UInt32,
        attachmentReferenceCount: UInt32,
        contactAliasCount: UInt32
    ) {
        self.archiveId = archiveId
        self.projectionId = projectionId
        self.identityGenerationId = identityGenerationId
        self.createdByInstallationId = createdByInstallationId
        self.recipientIdentityGenerationId = recipientIdentityGenerationId
        self.recipientInstallationId = recipientInstallationId
        self.recipientAgreementPublicKeyDigest = recipientAgreementPublicKeyDigest
        self.crossGenerationApprovalDigest = crossGenerationApprovalDigest
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.plaintextByteCount = plaintextByteCount
        self.projectionDigest = projectionDigest
        self.conversationCount = conversationCount
        self.eventCount = eventCount
        self.attachmentReferenceCount = attachmentReferenceCount
        self.contactAliasCount = contactAliasCount
    }

    init(manifest: HistoryArchiveManifestV2) {
        self.init(
            archiveId: manifest.id,
            projectionId: manifest.projectionId,
            identityGenerationId: manifest.identityGenerationId,
            createdByInstallationId: manifest.createdByInstallationId,
            recipientIdentityGenerationId: manifest.recipientIdentityGenerationId,
            recipientInstallationId: manifest.recipientInstallationId,
            recipientAgreementPublicKeyDigest: manifest.recipientAgreementPublicKeyDigest,
            crossGenerationApprovalDigest: manifest.crossGenerationApprovalDigest,
            createdAt: manifest.createdAt,
            expiresAt: manifest.expiresAt,
            plaintextByteCount: manifest.plaintextByteCount,
            projectionDigest: manifest.projectionDigest,
            conversationCount: manifest.conversationCount,
            eventCount: manifest.eventCount,
            attachmentReferenceCount: manifest.attachmentReferenceCount,
            contactAliasCount: manifest.contactAliasCount
        )
    }
}

private struct HistoryKeyWrapContextV2: Encodable {
    let domain = "Noctweave/history-archive-key-wrap/v2"
    let archiveId: UUID
    let manifestDigest: Data
    let identityGenerationId: UUID
    let recipientIdentityGenerationId: UUID
    let recipientInstallationId: UUID
    let recipientAgreementPublicKeyDigest: Data
    let crossGenerationApprovalDigest: Data?
    let scope: HistoryAccessScope
    let expiresAt: Date
}

private struct HistoryAuthorityAuthorizationV2: Encodable {
    let domain = "Noctweave/history-archive-authority-authorization/v2"
    let archiveId: UUID
    let manifestDigest: Data
    let keyWrapDigest: Data
    let identityGenerationId: UUID
    let recipientIdentityGenerationId: UUID
    let senderInstallationId: UUID
    let senderIdentityAuthorityPublicKey: Data
    let senderInstallationSigningPublicKey: Data
    let recipientInstallationId: UUID
    let recipientAgreementPublicKeyDigest: Data
    let crossGenerationApprovalDigest: Data?
    let scope: HistoryAccessScope
    let expiresAt: Date
}

private struct HistoryInstallationPossessionV2: Encodable {
    let domain = "Noctweave/history-archive-installation-possession/v2"
    let authorizationDigest: Data
    let authoritySignatureDigest: Data
}

private struct HistoryOuterSealContextV2: Encodable {
    let domain = "Noctweave/history-archive-outer-seal/v2"
    let version: Int
    let kemCiphertextDigest: Data
    let paddedByteCount: UInt64
}
