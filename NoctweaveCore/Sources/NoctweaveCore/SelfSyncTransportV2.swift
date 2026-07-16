import CryptoKit
import Foundation

/// The transport-safe self-sync profile. It is intentionally not advertised
/// until independent opaque routes and the complete endpoint lifecycle are
/// connected. All generation and endpoint identifiers below remain inside
/// authenticated ciphertext.
public enum NoctweaveSignedSelfSyncV2 {
    public static let version = 2
    public static let cipherSuite = "ML-KEM-768+HKDF-SHA256+ML-DSA-65+AES-256-GCM"
    public static let maximumPreferenceBytes = 4 * 1_024
    public static let maximumRecentSourceReceipts = 1_024
    public static let maximumWelcomeLifetime: TimeInterval = 24 * 60 * 60
    public static let recordPaddingBuckets = [4_096, 16_384, 65_536, 262_144, 1_048_576]
    public static let welcomePaddingBuckets = [8_192, 16_384, 65_536]
}

public enum SignedSelfSyncV2Error: Error, Equatable {
    case invalidStructure
    case invalidManifest
    case unauthorizedSource
    case invalidSignature
    case wrongGeneration
    case wrongSource
    case wrongEpoch
    case sequenceGap
    case sourceFork
    case replayConflict
    case recordTooLarge
    case decryptionFailed
    case expired
    case wrongRecipient
    case welcomeReplay
}

public enum SelfSyncConsentStateV2: String, Codable, Equatable, Hashable {
    case requests
    case allowed
    case blocked
}

public struct SelfSyncConsentUpdateV2: Codable, Equatable {
    public let relationshipId: UUID
    public let revision: UInt64
    public let state: SelfSyncConsentStateV2
    public let updatedAt: Date

    public init(
        relationshipId: UUID,
        revision: UInt64,
        state: SelfSyncConsentStateV2,
        updatedAt: Date
    ) {
        self.relationshipId = relationshipId
        self.revision = revision
        self.state = state
        self.updatedAt = updatedAt
    }

    public var isStructurallyValid: Bool {
        revision > 0 && updatedAt.timeIntervalSince1970.isFinite
    }
}

public struct SelfSyncReadMarkerV2: Codable, Equatable {
    public let relationshipId: UUID
    public let logicalPosition: UInt64
    public let throughEventId: UUID
    public let updatedAt: Date

    public init(
        relationshipId: UUID,
        logicalPosition: UInt64,
        throughEventId: UUID,
        updatedAt: Date
    ) {
        self.relationshipId = relationshipId
        self.logicalPosition = logicalPosition
        self.throughEventId = throughEventId
        self.updatedAt = updatedAt
    }

    public var isStructurallyValid: Bool {
        logicalPosition > 0 && updatedAt.timeIntervalSince1970.isFinite
    }
}

public enum SelfSyncPreferenceValueV2: Codable, Equatable {
    case boolean(Bool)
    case integer(Int64)
    case string(String)
    case bytes(Data)

    public var isStructurallyValid: Bool {
        switch self {
        case .boolean, .integer:
            return true
        case .string(let value):
            return !value.isEmpty
                && value.utf8.count <= NoctweaveSignedSelfSyncV2.maximumPreferenceBytes
                && value.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
        case .bytes(let value):
            return !value.isEmpty
                && value.count <= NoctweaveSignedSelfSyncV2.maximumPreferenceBytes
        }
    }
}

public struct SelfSyncPreferenceUpdateV2: Codable, Equatable {
    public let key: String
    public let revision: UInt64
    public let value: SelfSyncPreferenceValueV2
    public let updatedAt: Date

    public init(
        key: String,
        revision: UInt64,
        value: SelfSyncPreferenceValueV2,
        updatedAt: Date
    ) {
        self.key = key
        self.revision = revision
        self.value = value
        self.updatedAt = updatedAt
    }

    public var isStructurallyValid: Bool {
        let normalized = key.trimmingCharacters(in: .whitespacesAndNewlines)
        return !normalized.isEmpty
            && normalized == key
            && key.utf8.count <= 128
            && key.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
            && revision > 0
            && value.isStructurallyValid
            && updatedAt.timeIntervalSince1970.isFinite
    }
}

/// Closed, typed replicated state. Adding a new security-relevant case is a
/// protocol change; arbitrary bytes cannot masquerade as endpoint, route, or
/// group control state.
public enum TypedSelfSyncPayloadV2: Codable, Equatable {
    case conversationEvent(ConversationEvent)
    case endpointManifest(InstallationManifest)
    case relationshipRouteSet(RelationshipRouteSetV2)
    case groupCommit(SignedGroupCommitV2)
    case consent(SelfSyncConsentUpdateV2)
    case readMarker(SelfSyncReadMarkerV2)
    case preference(SelfSyncPreferenceUpdateV2)

    public var isStructurallyValid: Bool {
        switch self {
        case .conversationEvent(let event):
            return event.isStructurallyValid
        case .endpointManifest(let manifest):
            return manifest.isStructurallyValid
        case .relationshipRouteSet(let routeSet):
            return routeSet.isStructurallyValid
        case .groupCommit(let commit):
            return commit.isStructurallyValid
        case .consent(let update):
            return update.isStructurallyValid
        case .readMarker(let marker):
            return marker.isStructurallyValid
        case .preference(let update):
            return update.isStructurallyValid
        }
    }
}

/// One source-authenticated event in the hidden, generation-bounded self-sync
/// protocol. A shared encryption key is never treated as source authority.
public struct SignedSelfSyncRecordV2: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let identityGenerationId: UUID
    public let sourceEndpointId: UUID
    public let manifestEpoch: UInt64
    public let sourceSequence: UInt64
    public let previousSourceDigest: Data?
    public let createdAt: Date
    public let payload: TypedSelfSyncPayloadV2
    public let sourceSignature: Data

    public init(
        version: Int = NoctweaveSignedSelfSyncV2.version,
        id: UUID,
        identityGenerationId: UUID,
        sourceEndpointId: UUID,
        manifestEpoch: UInt64,
        sourceSequence: UInt64,
        previousSourceDigest: Data?,
        createdAt: Date,
        payload: TypedSelfSyncPayloadV2,
        sourceSignature: Data
    ) {
        self.version = version
        self.id = id
        self.identityGenerationId = identityGenerationId
        self.sourceEndpointId = sourceEndpointId
        self.manifestEpoch = manifestEpoch
        self.sourceSequence = sourceSequence
        self.previousSourceDigest = previousSourceDigest
        self.createdAt = createdAt
        self.payload = payload
        self.sourceSignature = sourceSignature
    }

    public static func create(
        id: UUID = UUID(),
        identityGenerationId: UUID,
        sourceEndpointId: UUID,
        manifestEpoch: UInt64,
        sourceSequence: UInt64,
        previousSourceDigest: Data?,
        createdAt: Date = Date(),
        payload: TypedSelfSyncPayloadV2,
        sourceSigningKey: SigningKeyPair
    ) throws -> SignedSelfSyncRecordV2 {
        let signable = SignedSelfSyncRecordPayloadV2(
            version: NoctweaveSignedSelfSyncV2.version,
            id: id,
            identityGenerationId: identityGenerationId,
            sourceEndpointId: sourceEndpointId,
            manifestEpoch: manifestEpoch,
            sourceSequence: sourceSequence,
            previousSourceDigest: previousSourceDigest,
            createdAt: createdAt,
            payload: payload
        )
        let result = SignedSelfSyncRecordV2(
            id: id,
            identityGenerationId: identityGenerationId,
            sourceEndpointId: sourceEndpointId,
            manifestEpoch: manifestEpoch,
            sourceSequence: sourceSequence,
            previousSourceDigest: previousSourceDigest,
            createdAt: createdAt,
            payload: payload,
            sourceSignature: try sourceSigningKey.sign(
                NoctweaveCoder.encode(signable, sortedKeys: true)
            )
        )
        guard result.isStructurallyValid else {
            throw SignedSelfSyncV2Error.invalidStructure
        }
        return result
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveSignedSelfSyncV2.version
            && sourceSequence > 0
            && ((sourceSequence == 1 && previousSourceDigest == nil)
                || (sourceSequence > 1 && previousSourceDigest?.count == 32))
            && createdAt.timeIntervalSince1970.isFinite
            && payload.isStructurallyValid
            && sourceSignature.count == 3_309
    }

    public var digest: Data? {
        guard isStructurallyValid,
              let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else {
            return nil
        }
        return Data(SHA256.hash(data: encoded))
    }

    public func verify(
        manifest: InstallationManifest,
        identityPublicKey: Data
    ) -> Bool {
        guard isStructurallyValid,
              manifest.identityGenerationId == identityGenerationId,
              manifest.epoch == manifestEpoch,
              manifest.verify(identityPublicKey: identityPublicKey),
              createdAt >= manifest.issuedAt,
              let source = manifest.installations.first(where: { $0.id == sourceEndpointId }),
              source.isActive(at: createdAt, manifestEpoch: manifestEpoch),
              let encoded = try? NoctweaveCoder.encode(signaturePayload, sortedKeys: true) else {
            return false
        }
        return SigningKeyPair.verify(
            signature: sourceSignature,
            data: encoded,
            publicKeyData: source.signingPublicKey
        )
    }

    private var signaturePayload: SignedSelfSyncRecordPayloadV2 {
        SignedSelfSyncRecordPayloadV2(
            version: version,
            id: id,
            identityGenerationId: identityGenerationId,
            sourceEndpointId: sourceEndpointId,
            manifestEpoch: manifestEpoch,
            sourceSequence: sourceSequence,
            previousSourceDigest: previousSourceDigest,
            createdAt: createdAt,
            payload: payload
        )
    }
}

private struct SignedSelfSyncRecordPayloadV2: Encodable {
    let domain = "Noctweave/signed-self-sync-record/v2"
    let version: Int
    let id: UUID
    let identityGenerationId: UUID
    let sourceEndpointId: UUID
    let manifestEpoch: UInt64
    let sourceSequence: UInt64
    let previousSourceDigest: Data?
    let createdAt: Date
    let payload: TypedSelfSyncPayloadV2
}

public struct SelfSyncSourceReceiptV2: Codable, Equatable {
    public let sequence: UInt64
    public let recordId: UUID
    public let recordDigest: Data

    public init(sequence: UInt64, recordId: UUID, recordDigest: Data) {
        self.sequence = sequence
        self.recordId = recordId
        self.recordDigest = recordDigest
    }

    public var isStructurallyValid: Bool {
        sequence > 0 && recordDigest.count == 32
    }
}

public enum SelfSyncSourceApplyResultV2: Equatable {
    case applied
    case exactDuplicate
}

/// Endpoint-local verification state for one source endpoint. Old compacted
/// replays fail closed; no cursor advances across a gap or a fork.
public struct SelfSyncSourceChainV2: Codable, Equatable {
    public let identityGenerationId: UUID
    public let sourceEndpointId: UUID
    public private(set) var throughSequence: UInt64
    public private(set) var lastRecordDigest: Data?
    public private(set) var recentReceipts: [SelfSyncSourceReceiptV2]

    public init(
        identityGenerationId: UUID,
        sourceEndpointId: UUID,
        throughSequence: UInt64 = 0,
        lastRecordDigest: Data? = nil,
        recentReceipts: [SelfSyncSourceReceiptV2] = []
    ) {
        self.identityGenerationId = identityGenerationId
        self.sourceEndpointId = sourceEndpointId
        self.throughSequence = throughSequence
        self.lastRecordDigest = lastRecordDigest
        self.recentReceipts = recentReceipts.sorted { $0.sequence < $1.sequence }
    }

    public var isStructurallyValid: Bool {
        let receiptsValid = recentReceipts.count <= NoctweaveSignedSelfSyncV2.maximumRecentSourceReceipts
            && Set(recentReceipts.map(\.sequence)).count == recentReceipts.count
            && Set(recentReceipts.map(\.recordId)).count == recentReceipts.count
            && recentReceipts.allSatisfy(\.isStructurallyValid)
            && recentReceipts.allSatisfy { $0.sequence <= throughSequence }
        if throughSequence == 0 {
            return lastRecordDigest == nil && recentReceipts.isEmpty
        }
        return lastRecordDigest?.count == 32
            && recentReceipts.last?.sequence == throughSequence
            && recentReceipts.last?.recordDigest == lastRecordDigest
            && receiptsValid
    }

    public mutating func apply(
        _ record: SignedSelfSyncRecordV2,
        manifest: InstallationManifest,
        identityPublicKey: Data
    ) throws -> SelfSyncSourceApplyResultV2 {
        guard isStructurallyValid else { throw SignedSelfSyncV2Error.invalidStructure }
        guard record.identityGenerationId == identityGenerationId else {
            throw SignedSelfSyncV2Error.wrongGeneration
        }
        guard record.sourceEndpointId == sourceEndpointId else {
            throw SignedSelfSyncV2Error.wrongSource
        }
        guard record.manifestEpoch == manifest.epoch else {
            throw SignedSelfSyncV2Error.wrongEpoch
        }
        guard record.verify(manifest: manifest, identityPublicKey: identityPublicKey),
              let digest = record.digest else {
            throw SignedSelfSyncV2Error.invalidSignature
        }

        if record.sourceSequence <= throughSequence {
            if recentReceipts.contains(where: {
                $0.sequence == record.sourceSequence
                    && $0.recordId == record.id
                    && $0.recordDigest == digest
            }) {
                return .exactDuplicate
            }
            throw SignedSelfSyncV2Error.replayConflict
        }
        guard throughSequence < UInt64.max,
              record.sourceSequence == throughSequence + 1 else {
            throw SignedSelfSyncV2Error.sequenceGap
        }
        guard record.previousSourceDigest == lastRecordDigest else {
            throw SignedSelfSyncV2Error.sourceFork
        }

        throughSequence = record.sourceSequence
        lastRecordDigest = digest
        recentReceipts.append(
            SelfSyncSourceReceiptV2(
                sequence: record.sourceSequence,
                recordId: record.id,
                recordDigest: digest
            )
        )
        if recentReceipts.count > NoctweaveSignedSelfSyncV2.maximumRecentSourceReceipts {
            recentReceipts.removeFirst(
                recentReceipts.count - NoctweaveSignedSelfSyncV2.maximumRecentSourceReceipts
            )
        }
        return .applied
    }
}

/// Relay-visible record: no generation, endpoint, manifest, or social metadata.
public struct SealedSelfSyncRecordV2: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let storedAtBucket: Date
    public let cipherSuite: String
    public let payload: EncryptedPayload

    public init(
        version: Int = NoctweaveSignedSelfSyncV2.version,
        id: UUID,
        storedAtBucket: Date,
        cipherSuite: String = NoctweaveSignedSelfSyncV2.cipherSuite,
        payload: EncryptedPayload
    ) {
        self.version = version
        self.id = id
        self.storedAtBucket = storedAtBucket
        self.cipherSuite = cipherSuite
        self.payload = payload
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveSignedSelfSyncV2.version
            && storedAtBucket.timeIntervalSince1970.isFinite
            && cipherSuite == NoctweaveSignedSelfSyncV2.cipherSuite
            && payload.nonce.count == 12
            && payload.tag.count == 16
            && NoctweaveSignedSelfSyncV2.recordPaddingBuckets.contains(payload.ciphertext.count)
    }

    public static func seal(
        _ record: SignedSelfSyncRecordV2,
        epochKeyData: Data,
        storedAt: Date = Date()
    ) throws -> SealedSelfSyncRecordV2 {
        guard record.isStructurallyValid, epochKeyData.count == 32 else {
            throw SignedSelfSyncV2Error.invalidStructure
        }
        let frame = try SelfSyncTransportFrameV2.encode(
            record,
            buckets: NoctweaveSignedSelfSyncV2.recordPaddingBuckets
        )
        let bucketed = Date(
            timeIntervalSince1970: floor(storedAt.timeIntervalSince1970 / 60) * 60
        )
        let context = SelfSyncRecordAuthenticatedContextV2(
            version: NoctweaveSignedSelfSyncV2.version,
            id: record.id,
            storedAtBucket: bucketed,
            cipherSuite: NoctweaveSignedSelfSyncV2.cipherSuite
        )
        let authenticatedData = try NoctweaveCoder.encode(context, sortedKeys: true)
        return SealedSelfSyncRecordV2(
            id: record.id,
            storedAtBucket: bucketed,
            payload: try CryptoBox.encrypt(
                frame,
                key: SymmetricKey(data: epochKeyData),
                authenticatedData: authenticatedData
            )
        )
    }

    public func open(epochKeyData: Data) throws -> SignedSelfSyncRecordV2 {
        guard isStructurallyValid, epochKeyData.count == 32 else {
            throw SignedSelfSyncV2Error.invalidStructure
        }
        let context = SelfSyncRecordAuthenticatedContextV2(
            version: version,
            id: id,
            storedAtBucket: storedAtBucket,
            cipherSuite: cipherSuite
        )
        let authenticatedData = try NoctweaveCoder.encode(context, sortedKeys: true)
        let frame: Data
        do {
            frame = try CryptoBox.decrypt(
                payload,
                key: SymmetricKey(data: epochKeyData),
                authenticatedData: authenticatedData
            )
        } catch {
            throw SignedSelfSyncV2Error.decryptionFailed
        }
        let record: SignedSelfSyncRecordV2 = try SelfSyncTransportFrameV2.decode(frame)
        guard record.id == id, record.isStructurallyValid else {
            throw SignedSelfSyncV2Error.invalidStructure
        }
        return record
    }
}

private struct SelfSyncRecordAuthenticatedContextV2: Encodable {
    let domain = "Noctweave/sealed-self-sync-record/v2"
    let version: Int
    let id: UUID
    let storedAtBucket: Date
    let cipherSuite: String
}

/// A fresh self-sync epoch key, signed by the generation authority and sealed
/// independently to one active endpoint. It authorizes no inbox, route, group,
/// identity recovery, or future generation.
public struct SelfSyncEpochWelcomeV2: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let identityGenerationId: UUID
    public let manifestEpoch: UInt64
    public let selfSyncEpoch: UInt64
    public let previousEpochDigest: Data?
    public let recipientEndpointId: UUID
    public let epochKeyData: Data
    public let issuedAt: Date
    public let expiresAt: Date
    public let authoritySignature: Data

    public init(
        version: Int = NoctweaveSignedSelfSyncV2.version,
        id: UUID,
        identityGenerationId: UUID,
        manifestEpoch: UInt64,
        selfSyncEpoch: UInt64,
        previousEpochDigest: Data?,
        recipientEndpointId: UUID,
        epochKeyData: Data,
        issuedAt: Date,
        expiresAt: Date,
        authoritySignature: Data
    ) {
        self.version = version
        self.id = id
        self.identityGenerationId = identityGenerationId
        self.manifestEpoch = manifestEpoch
        self.selfSyncEpoch = selfSyncEpoch
        self.previousEpochDigest = previousEpochDigest
        self.recipientEndpointId = recipientEndpointId
        self.epochKeyData = epochKeyData
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.authoritySignature = authoritySignature
    }

    public static func create(
        id: UUID = UUID(),
        identityGenerationId: UUID,
        manifestEpoch: UInt64,
        selfSyncEpoch: UInt64,
        previousEpochDigest: Data?,
        recipientEndpointId: UUID,
        epochKeyData: Data,
        issuedAt: Date = Date(),
        expiresAt: Date,
        identitySigningKey: SigningKeyPair
    ) throws -> SelfSyncEpochWelcomeV2 {
        let payload = SelfSyncEpochWelcomePayloadV2(
            version: NoctweaveSignedSelfSyncV2.version,
            id: id,
            identityGenerationId: identityGenerationId,
            manifestEpoch: manifestEpoch,
            selfSyncEpoch: selfSyncEpoch,
            previousEpochDigest: previousEpochDigest,
            recipientEndpointId: recipientEndpointId,
            epochKeyData: epochKeyData,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
        let result = SelfSyncEpochWelcomeV2(
            id: id,
            identityGenerationId: identityGenerationId,
            manifestEpoch: manifestEpoch,
            selfSyncEpoch: selfSyncEpoch,
            previousEpochDigest: previousEpochDigest,
            recipientEndpointId: recipientEndpointId,
            epochKeyData: epochKeyData,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            authoritySignature: try identitySigningKey.sign(
                NoctweaveCoder.encode(payload, sortedKeys: true)
            )
        )
        guard result.isStructurallyValid else {
            throw SignedSelfSyncV2Error.invalidStructure
        }
        return result
    }

    public var isStructurallyValid: Bool {
        let lifetime = expiresAt.timeIntervalSince(issuedAt)
        return version == NoctweaveSignedSelfSyncV2.version
            && selfSyncEpoch > 0
            && ((selfSyncEpoch == 1 && previousEpochDigest == nil)
                || (selfSyncEpoch > 1 && previousEpochDigest?.count == 32))
            && epochKeyData.count == 32
            && issuedAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && lifetime > 0
            && lifetime <= NoctweaveSignedSelfSyncV2.maximumWelcomeLifetime
            && authoritySignature.count == 3_309
    }

    public var digest: Data? {
        guard isStructurallyValid,
              let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else {
            return nil
        }
        return Data(SHA256.hash(data: encoded))
    }

    public func verify(
        manifest: InstallationManifest,
        identityPublicKey: Data,
        expectedRecipientEndpointId: UUID,
        now: Date = Date()
    ) -> Bool {
        guard isStructurallyValid,
              now.timeIntervalSince1970.isFinite,
              now >= issuedAt,
              now < expiresAt,
              expectedRecipientEndpointId == recipientEndpointId,
              identityGenerationId == manifest.identityGenerationId,
              manifestEpoch == manifest.epoch,
              manifest.verify(identityPublicKey: identityPublicKey),
              let recipient = manifest.installations.first(where: { $0.id == recipientEndpointId }),
              recipient.isActive(at: now, manifestEpoch: manifestEpoch),
              let encoded = try? NoctweaveCoder.encode(signaturePayload, sortedKeys: true) else {
            return false
        }
        return SigningKeyPair.verify(
            signature: authoritySignature,
            data: encoded,
            publicKeyData: identityPublicKey
        )
    }

    private var signaturePayload: SelfSyncEpochWelcomePayloadV2 {
        SelfSyncEpochWelcomePayloadV2(
            version: version,
            id: id,
            identityGenerationId: identityGenerationId,
            manifestEpoch: manifestEpoch,
            selfSyncEpoch: selfSyncEpoch,
            previousEpochDigest: previousEpochDigest,
            recipientEndpointId: recipientEndpointId,
            epochKeyData: epochKeyData,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
    }
}

private struct SelfSyncEpochWelcomePayloadV2: Encodable {
    let domain = "Noctweave/self-sync-epoch-welcome/v2"
    let version: Int
    let id: UUID
    let identityGenerationId: UUID
    let manifestEpoch: UInt64
    let selfSyncEpoch: UInt64
    let previousEpochDigest: Data?
    let recipientEndpointId: UUID
    let epochKeyData: Data
    let issuedAt: Date
    let expiresAt: Date
}

/// Relay-visible KEM envelope for one Welcome. Recipient and generation
/// identifiers remain inside the padded ciphertext.
public struct SealedSelfSyncEpochWelcomeV2: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let cipherSuite: String
    public let kemCiphertext: Data
    public let payload: EncryptedPayload

    public init(
        version: Int = NoctweaveSignedSelfSyncV2.version,
        id: UUID,
        cipherSuite: String = NoctweaveSignedSelfSyncV2.cipherSuite,
        kemCiphertext: Data,
        payload: EncryptedPayload
    ) {
        self.version = version
        self.id = id
        self.cipherSuite = cipherSuite
        self.kemCiphertext = kemCiphertext
        self.payload = payload
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveSignedSelfSyncV2.version
            && cipherSuite == NoctweaveSignedSelfSyncV2.cipherSuite
            && !kemCiphertext.isEmpty
            && payload.nonce.count == 12
            && payload.tag.count == 16
            && NoctweaveSignedSelfSyncV2.welcomePaddingBuckets.contains(payload.ciphertext.count)
    }

    public static func seal(
        _ welcome: SelfSyncEpochWelcomeV2,
        recipientAgreementPublicKey: Data
    ) throws -> SealedSelfSyncEpochWelcomeV2 {
        guard welcome.isStructurallyValid,
              AgreementKeyPair.isValidPublicKey(recipientAgreementPublicKey) else {
            throw SignedSelfSyncV2Error.invalidStructure
        }
        var kem = try AgreementKeyPair.encapsulate(to: recipientAgreementPublicKey)
        defer { kem.sharedSecret.secureWipe() }
        let context = SelfSyncWelcomeAuthenticatedContextV2(
            version: NoctweaveSignedSelfSyncV2.version,
            id: welcome.id,
            cipherSuite: NoctweaveSignedSelfSyncV2.cipherSuite,
            kemCiphertextDigest: Data(SHA256.hash(data: kem.ciphertext))
        )
        let authenticatedData = try NoctweaveCoder.encode(context, sortedKeys: true)
        let keyData = CryptoBox.deriveChainKey(
            sharedSecret: kem.sharedSecret,
            salt: Data(SHA256.hash(data: kem.ciphertext)),
            info: authenticatedData
        )
        let frame = try SelfSyncTransportFrameV2.encode(
            welcome,
            buckets: NoctweaveSignedSelfSyncV2.welcomePaddingBuckets
        )
        return SealedSelfSyncEpochWelcomeV2(
            id: welcome.id,
            kemCiphertext: kem.ciphertext,
            payload: try CryptoBox.encrypt(
                frame,
                key: SymmetricKey(data: keyData),
                authenticatedData: authenticatedData
            )
        )
    }

    public func open(
        recipientAgreementKey: AgreementKeyPair,
        manifest: InstallationManifest,
        identityPublicKey: Data,
        expectedRecipientEndpointId: UUID,
        now: Date = Date()
    ) throws -> SelfSyncEpochWelcomeV2 {
        guard isStructurallyValid else { throw SignedSelfSyncV2Error.invalidStructure }
        var sharedSecret: Data
        do {
            sharedSecret = try recipientAgreementKey.decapsulate(ciphertext: kemCiphertext)
        } catch {
            throw SignedSelfSyncV2Error.decryptionFailed
        }
        defer { sharedSecret.secureWipe() }
        let context = SelfSyncWelcomeAuthenticatedContextV2(
            version: version,
            id: id,
            cipherSuite: cipherSuite,
            kemCiphertextDigest: Data(SHA256.hash(data: kemCiphertext))
        )
        let authenticatedData = try NoctweaveCoder.encode(context, sortedKeys: true)
        let keyData = CryptoBox.deriveChainKey(
            sharedSecret: sharedSecret,
            salt: Data(SHA256.hash(data: kemCiphertext)),
            info: authenticatedData
        )
        let frame: Data
        do {
            frame = try CryptoBox.decrypt(
                payload,
                key: SymmetricKey(data: keyData),
                authenticatedData: authenticatedData
            )
        } catch {
            throw SignedSelfSyncV2Error.decryptionFailed
        }
        let welcome: SelfSyncEpochWelcomeV2 = try SelfSyncTransportFrameV2.decode(frame)
        guard welcome.id == id else { throw SignedSelfSyncV2Error.invalidStructure }
        guard welcome.recipientEndpointId == expectedRecipientEndpointId else {
            throw SignedSelfSyncV2Error.wrongRecipient
        }
        guard now < welcome.expiresAt else { throw SignedSelfSyncV2Error.expired }
        guard welcome.verify(
            manifest: manifest,
            identityPublicKey: identityPublicKey,
            expectedRecipientEndpointId: expectedRecipientEndpointId,
            now: now
        ) else {
            throw SignedSelfSyncV2Error.invalidSignature
        }
        return welcome
    }
}

private struct SelfSyncWelcomeAuthenticatedContextV2: Encodable {
    let domain = "Noctweave/sealed-self-sync-epoch-welcome/v2"
    let version: Int
    let id: UUID
    let cipherSuite: String
    let kemCiphertextDigest: Data
}

public struct SelfSyncWelcomeReplayLedgerV2: Codable, Equatable {
    public static let maximumConsumedWelcomes = 256
    public private(set) var highestConsumedEpoch: UInt64
    public private(set) var consumedWelcomeIds: [UUID]

    public init(
        highestConsumedEpoch: UInt64 = 0,
        consumedWelcomeIds: [UUID] = []
    ) {
        self.highestConsumedEpoch = highestConsumedEpoch
        self.consumedWelcomeIds = consumedWelcomeIds
    }

    public var isStructurallyValid: Bool {
        consumedWelcomeIds.count <= Self.maximumConsumedWelcomes
            && Set(consumedWelcomeIds).count == consumedWelcomeIds.count
            && (highestConsumedEpoch == 0
                ? consumedWelcomeIds.isEmpty
                : !consumedWelcomeIds.isEmpty)
    }

    public mutating func consume(
        _ welcome: SelfSyncEpochWelcomeV2,
        manifest: InstallationManifest,
        identityPublicKey: Data,
        expectedRecipientEndpointId: UUID,
        now: Date = Date()
    ) throws {
        guard isStructurallyValid,
              welcome.verify(
                  manifest: manifest,
                  identityPublicKey: identityPublicKey,
                  expectedRecipientEndpointId: expectedRecipientEndpointId,
                  now: now
              ) else {
            throw SignedSelfSyncV2Error.invalidStructure
        }
        guard welcome.selfSyncEpoch > highestConsumedEpoch,
              !consumedWelcomeIds.contains(welcome.id) else {
            throw SignedSelfSyncV2Error.welcomeReplay
        }
        highestConsumedEpoch = welcome.selfSyncEpoch
        consumedWelcomeIds.append(welcome.id)
        if consumedWelcomeIds.count > Self.maximumConsumedWelcomes {
            consumedWelcomeIds.removeFirst(consumedWelcomeIds.count - Self.maximumConsumedWelcomes)
        }
    }
}

private enum SelfSyncTransportFrameV2 {
    static func encode<T: Encodable>(_ value: T, buckets: [Int]) throws -> Data {
        let encoded = try NoctweaveCoder.encode(value, sortedKeys: true)
        guard encoded.count <= Int(UInt32.max),
              let bucket = buckets.first(where: { $0 >= encoded.count + 4 }) else {
            throw SignedSelfSyncV2Error.recordTooLarge
        }
        var frame = Data()
        frame.reserveCapacity(bucket)
        var length = UInt32(encoded.count).bigEndian
        Swift.withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }
        frame.append(encoded)
        frame.append(Data(repeating: 0, count: bucket - frame.count))
        return frame
    }

    static func decode<T: Decodable>(_ frame: Data) throws -> T {
        guard frame.count >= 4 else { throw SignedSelfSyncV2Error.invalidStructure }
        let length = frame.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let end = 4 + Int(length)
        guard end <= frame.count,
              frame[end...].allSatisfy({ $0 == 0 }) else {
            throw SignedSelfSyncV2Error.invalidStructure
        }
        do {
            return try NoctweaveCoder.decode(T.self, from: Data(frame[4..<end]))
        } catch {
            throw SignedSelfSyncV2Error.invalidStructure
        }
    }
}
