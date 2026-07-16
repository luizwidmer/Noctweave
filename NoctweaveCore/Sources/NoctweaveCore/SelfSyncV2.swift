import CryptoKit
import Foundation

public enum NoctweaveSelfSyncV2 {
    public static let version = 2
    public static let cipherSuite = "AES-256-GCM"
    public static let maximumEventPayloadBytes = 512 * 1_024
    public static let maximumSnapshotStateBytes = 2 * 1_024 * 1_024
    public static let maximumRendezvousPayloadBytes = 4 * 1_024 * 1_024
    public static let maximumTemporaryRouteBytes = 2_048
    public static let maximumRendezvousLifetime: TimeInterval = 10 * 60
    public static let maximumArchiveBytes: UInt64 = 16 * 1_024 * 1_024 * 1_024
    public static let maximumWrappedArchiveKeyBytes = 64 * 1_024
    public static let paddingBuckets = [4_096, 16_384, 65_536, 262_144, 1_048_576, 4_194_304]
}

public struct SelfSyncStreamHandle: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public var isStructurallyValid: Bool {
        guard let decoded = Data(base64Encoded: rawValue), decoded.count == 32 else { return false }
        return decoded.base64EncodedString() == rawValue
    }
}

/// External work that must complete after one endpoint is removed. Advancing
/// the endpoint set and rekeying local self-sync are not presented as complete
/// remote revocation until every obligation has been durably handled.
public enum EndpointRemovalCleanupKindV2: String, Codable, Equatable, Hashable, CaseIterable {
    case publishEndpointSet
    case redistributeSelfSyncKey
    case revokeMailboxAccess
    case removeRelationshipRoutes
    case removeGroupClients
}

public struct EndpointRemovalCleanupObligationV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let identityGenerationId: UUID
    public let removedEndpointId: UUID
    public let endpointSetEpoch: UInt64
    public let endpointSetDigest: Data
    public let replacementSelfSyncStreamDigest: Data
    public let remainingEndpointIds: [UUID]
    public let kind: EndpointRemovalCleanupKindV2
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        identityGenerationId: UUID,
        removedEndpointId: UUID,
        endpointSetEpoch: UInt64,
        endpointSetDigest: Data,
        replacementSelfSyncStreamDigest: Data,
        remainingEndpointIds: [UUID],
        kind: EndpointRemovalCleanupKindV2,
        createdAt: Date
    ) {
        self.id = id
        self.identityGenerationId = identityGenerationId
        self.removedEndpointId = removedEndpointId
        self.endpointSetEpoch = endpointSetEpoch
        self.endpointSetDigest = endpointSetDigest
        self.replacementSelfSyncStreamDigest = replacementSelfSyncStreamDigest
        self.remainingEndpointIds = Array(Set(remainingEndpointIds)).sorted {
            $0.uuidString < $1.uuidString
        }
        self.kind = kind
        self.createdAt = createdAt
    }

    public var isStructurallyValid: Bool {
        endpointSetDigest.count == 32
            && replacementSelfSyncStreamDigest.count == 32
            && remainingEndpointIds.count <= NoctweaveArchitectureV2.maximumInstallations
            && Set(remainingEndpointIds).count == remainingEndpointIds.count
            && !remainingEndpointIds.contains(removedEndpointId)
            && createdAt.timeIntervalSince1970.isFinite
    }
}

/// Atomic local result of endpoint removal. The replacement self-sync key is
/// retained only in `IdentityProfile.selfSyncV2`; this result carries digests
/// and a bounded explicit cleanup plan, never the new secret.
public struct EndpointRemovalResultV2: Codable, Equatable {
    public let identityGenerationId: UUID
    public let removedEndpointId: UUID
    public let endpointSetEpoch: UInt64
    public let endpointSetDigest: Data
    public let replacementSelfSyncStreamDigest: Data
    public let cleanupObligations: [EndpointRemovalCleanupObligationV2]

    public init(
        identityGenerationId: UUID,
        removedEndpointId: UUID,
        endpointSetEpoch: UInt64,
        endpointSetDigest: Data,
        replacementSelfSyncStreamDigest: Data,
        cleanupObligations: [EndpointRemovalCleanupObligationV2]
    ) {
        self.identityGenerationId = identityGenerationId
        self.removedEndpointId = removedEndpointId
        self.endpointSetEpoch = endpointSetEpoch
        self.endpointSetDigest = endpointSetDigest
        self.replacementSelfSyncStreamDigest = replacementSelfSyncStreamDigest
        self.cleanupObligations = cleanupObligations.sorted { $0.kind.rawValue < $1.kind.rawValue }
    }

    public var isStructurallyValid: Bool {
        let expectedKinds = Set(EndpointRemovalCleanupKindV2.allCases)
        return endpointSetDigest.count == 32
            && replacementSelfSyncStreamDigest.count == 32
            && !cleanupObligations.isEmpty
            && cleanupObligations.count
                <= NoctweaveArchitectureV2.maximumEndpointCleanupObligations
            && Set(cleanupObligations.map(\.id)).count == cleanupObligations.count
            && Set(cleanupObligations.map(\.kind)) == expectedKinds
            && cleanupObligations.allSatisfy {
                $0.isStructurallyValid
                    && $0.identityGenerationId == identityGenerationId
                    && $0.removedEndpointId == removedEndpointId
                    && $0.endpointSetEpoch == endpointSetEpoch
                    && $0.endpointSetDigest == endpointSetDigest
                    && $0.replacementSelfSyncStreamDigest == replacementSelfSyncStreamDigest
            }
    }

    public var requiresExternalCleanup: Bool { true }
    public var authorizesFutureParticipation: Bool { false }
}

/// Durable local record for the remote work left by an endpoint-set removal.
/// The exact obligations live with the profile until each one is acknowledged;
/// ignoring the immediate removal return value cannot lose cleanup state.
public struct EndpointRemovalJournalV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let result: EndpointRemovalResultV2
    public let completedObligationIds: [UUID]
    public let createdAt: Date
    public let updatedAt: Date

    public init(
        id: UUID = UUID(),
        result: EndpointRemovalResultV2,
        completedObligationIds: [UUID] = [],
        createdAt: Date,
        updatedAt: Date? = nil
    ) {
        self.id = id
        self.result = result
        self.completedObligationIds = Array(Set(completedObligationIds)).sorted {
            $0.uuidString < $1.uuidString
        }
        self.createdAt = createdAt
        self.updatedAt = updatedAt ?? createdAt
    }

    public var pendingObligations: [EndpointRemovalCleanupObligationV2] {
        let completed = Set(completedObligationIds)
        return result.cleanupObligations.filter { !completed.contains($0.id) }
    }

    public var isStructurallyValid: Bool {
        let obligationIds = Set(result.cleanupObligations.map(\.id))
        let completed = Set(completedObligationIds)
        return result.isStructurallyValid
            && completedObligationIds.count == completed.count
            && completed.isSubset(of: obligationIds)
            && completed.count < obligationIds.count
            && createdAt.timeIntervalSince1970.isFinite
            && updatedAt.timeIntervalSince1970.isFinite
            && updatedAt >= createdAt
    }

    /// Replays are idempotent. Completing the final obligation returns `nil`,
    /// which tells the profile to remove the fully settled journal.
    public func completing(
        obligationId: UUID,
        at date: Date
    ) -> EndpointRemovalJournalV2? {
        guard date.timeIntervalSince1970.isFinite,
              date >= updatedAt,
              result.cleanupObligations.contains(where: { $0.id == obligationId }) else {
            return self
        }
        if completedObligationIds.contains(obligationId) { return self }
        let completed = completedObligationIds + [obligationId]
        if completed.count == result.cleanupObligations.count { return nil }
        return EndpointRemovalJournalV2(
            id: id,
            result: result,
            completedObligationIds: completed,
            createdAt: createdAt,
            updatedAt: date
        )
    }
}

public enum SelfSyncEventKind: String, Codable, Equatable, Hashable, CaseIterable {
    case installationManifestChanged
    case outboundConversationEvent
    case relationshipChanged
    case routeSetChanged
    case groupMembershipChanged
    case consentChanged
    case readMarkerAdvanced
    case preferenceChanged
    case historyRequested
    case historyOffered
}

/// This plaintext type is valid only inside an `EncryptedSelfSyncRecord`.
public struct SelfSyncEvent: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let identityGenerationId: UUID
    public let sourceInstallationId: UUID
    public let sourceSequence: UInt64
    public let createdAt: Date
    public let kind: SelfSyncEventKind
    public let encodedPayload: Data

    public init(
        version: Int = NoctweaveSelfSyncV2.version,
        id: UUID = UUID(),
        identityGenerationId: UUID,
        sourceInstallationId: UUID,
        sourceSequence: UInt64,
        createdAt: Date = Date(),
        kind: SelfSyncEventKind,
        encodedPayload: Data
    ) {
        self.version = version
        self.id = id
        self.identityGenerationId = identityGenerationId
        self.sourceInstallationId = sourceInstallationId
        self.sourceSequence = sourceSequence
        self.createdAt = createdAt
        self.kind = kind
        self.encodedPayload = encodedPayload
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveSelfSyncV2.version
            && sourceSequence > 0
            && createdAt.timeIntervalSince1970.isFinite
            && !encodedPayload.isEmpty
            && encodedPayload.count <= NoctweaveSelfSyncV2.maximumEventPayloadBytes
    }
}

public struct SelfSyncInstallationCursor: Codable, Equatable {
    public let installationId: UUID
    public let throughSequence: UInt64

    public init(installationId: UUID, throughSequence: UInt64) {
        self.installationId = installationId
        self.throughSequence = throughSequence
    }
}

/// A compacted replicated-state image. Live ratchet chains and reusable prekeys must never be included.
public struct SelfSyncSnapshot: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let identityGenerationId: UUID
    public let sourceInstallationId: UUID
    public let createdAt: Date
    public let through: [SelfSyncInstallationCursor]
    public let encodedReplicatedState: Data
    public let stateDigest: Data

    public init(
        version: Int = NoctweaveSelfSyncV2.version,
        id: UUID = UUID(),
        identityGenerationId: UUID,
        sourceInstallationId: UUID,
        createdAt: Date = Date(),
        through: [SelfSyncInstallationCursor],
        encodedReplicatedState: Data
    ) {
        self.version = version
        self.id = id
        self.identityGenerationId = identityGenerationId
        self.sourceInstallationId = sourceInstallationId
        self.createdAt = createdAt
        self.through = through.sorted { $0.installationId.uuidString < $1.installationId.uuidString }
        self.encodedReplicatedState = encodedReplicatedState
        self.stateDigest = Data(SHA256.hash(data: encodedReplicatedState))
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveSelfSyncV2.version
            && createdAt.timeIntervalSince1970.isFinite
            && !through.isEmpty
            && through.count <= NoctweaveArchitectureV2.maximumInstallations
            && Set(through.map(\.installationId)).count == through.count
            && through.contains { $0.installationId == sourceInstallationId }
            && !encodedReplicatedState.isEmpty
            && encodedReplicatedState.count <= NoctweaveSelfSyncV2.maximumSnapshotStateBytes
            && stateDigest == Data(SHA256.hash(data: encodedReplicatedState))
    }
}

public enum SelfSyncRecordPlaintext: Codable, Equatable {
    case event(SelfSyncEvent)
    case snapshot(SelfSyncSnapshot)

    public var id: UUID {
        switch self {
        case .event(let event): return event.id
        case .snapshot(let snapshot): return snapshot.id
        }
    }

    public var identityGenerationId: UUID {
        switch self {
        case .event(let event): return event.identityGenerationId
        case .snapshot(let snapshot): return snapshot.identityGenerationId
        }
    }

    public var isStructurallyValid: Bool {
        switch self {
        case .event(let event): return event.isStructurallyValid
        case .snapshot(let snapshot): return snapshot.isStructurallyValid
        }
    }
}

public enum SelfSyncV2Error: Error, Equatable {
    case invalidPlaintext
    case invalidEnvelope
    case recordTooLarge
    case wrongStream
    case wrongIdentityGeneration
    case decryptionFailed
    case invalidRendezvous
}

/// Relay-visible self-sync data exposes only an opaque stream, random record ID, time bucket, and size bucket.
public struct EncryptedSelfSyncRecord: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let stream: SelfSyncStreamHandle
    public let storedAtBucket: Date
    public let cipherSuite: String
    public let payload: EncryptedPayload

    public init(
        version: Int = NoctweaveSelfSyncV2.version,
        id: UUID,
        stream: SelfSyncStreamHandle,
        storedAtBucket: Date,
        cipherSuite: String = NoctweaveSelfSyncV2.cipherSuite,
        payload: EncryptedPayload
    ) {
        self.version = version
        self.id = id
        self.stream = stream
        self.storedAtBucket = storedAtBucket
        self.cipherSuite = cipherSuite
        self.payload = payload
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveSelfSyncV2.version
            && stream.isStructurallyValid
            && storedAtBucket.timeIntervalSince1970.isFinite
            && cipherSuite == NoctweaveSelfSyncV2.cipherSuite
            && payload.nonce.count == 12
            && payload.tag.count == 16
            && NoctweaveSelfSyncV2.paddingBuckets.contains(payload.ciphertext.count)
    }

    public static func seal(
        _ plaintext: SelfSyncRecordPlaintext,
        stream: SelfSyncStreamHandle,
        key: SymmetricKey,
        storedAt: Date = Date()
    ) throws -> EncryptedSelfSyncRecord {
        guard plaintext.isStructurallyValid, stream.isStructurallyValid else {
            throw SelfSyncV2Error.invalidPlaintext
        }
        let encoded = try NoctweaveCoder.encode(plaintext, sortedKeys: true)
        guard encoded.count <= Int(UInt32.max) else { throw SelfSyncV2Error.recordTooLarge }
        let requiredBytes = 4 + encoded.count
        guard let bucket = NoctweaveSelfSyncV2.paddingBuckets.first(where: { $0 >= requiredBytes }) else {
            throw SelfSyncV2Error.recordTooLarge
        }

        var frame = Data()
        frame.reserveCapacity(bucket)
        var encodedLength = UInt32(encoded.count).bigEndian
        Swift.withUnsafeBytes(of: &encodedLength) { frame.append(contentsOf: $0) }
        frame.append(encoded)
        frame.append(Data(repeating: 0, count: bucket - frame.count))

        let bucketedDate = Date(
            timeIntervalSince1970: floor(storedAt.timeIntervalSince1970 / 60) * 60
        )
        let context = SelfSyncAuthenticatedContext(
            version: NoctweaveSelfSyncV2.version,
            recordId: plaintext.id,
            stream: stream,
            storedAtBucket: bucketedDate,
            cipherSuite: NoctweaveSelfSyncV2.cipherSuite
        )
        let authenticatedData = try NoctweaveCoder.encode(context, sortedKeys: true)
        return EncryptedSelfSyncRecord(
            id: plaintext.id,
            stream: stream,
            storedAtBucket: bucketedDate,
            payload: try CryptoBox.encrypt(frame, key: key, authenticatedData: authenticatedData)
        )
    }

    public func open(
        key: SymmetricKey,
        expectedStream: SelfSyncStreamHandle,
        expectedIdentityGenerationId: UUID
    ) throws -> SelfSyncRecordPlaintext {
        guard isStructurallyValid else { throw SelfSyncV2Error.invalidEnvelope }
        guard stream == expectedStream else { throw SelfSyncV2Error.wrongStream }
        let context = SelfSyncAuthenticatedContext(
            version: version,
            recordId: id,
            stream: stream,
            storedAtBucket: storedAtBucket,
            cipherSuite: cipherSuite
        )
        let authenticatedData = try NoctweaveCoder.encode(context, sortedKeys: true)
        guard let frame = try? CryptoBox.decrypt(payload, key: key, authenticatedData: authenticatedData),
              frame.count >= 4 else {
            throw SelfSyncV2Error.decryptionFailed
        }

        let encodedLength = frame.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let payloadEnd = 4 + Int(encodedLength)
        guard payloadEnd <= frame.count,
              frame[payloadEnd...].allSatisfy({ $0 == 0 }),
              let plaintext = try? NoctweaveCoder.decode(
                SelfSyncRecordPlaintext.self,
                from: Data(frame[4..<payloadEnd])
              ),
              plaintext.isStructurallyValid,
              plaintext.id == id else {
            throw SelfSyncV2Error.invalidPlaintext
        }
        guard plaintext.identityGenerationId == expectedIdentityGenerationId else {
            throw SelfSyncV2Error.wrongIdentityGeneration
        }
        return plaintext
    }
}

private struct SelfSyncAuthenticatedContext: Encodable {
    let domain = "Noctweave/self-sync-record/v2"
    let version: Int
    let recordId: UUID
    let stream: SelfSyncStreamHandle
    let storedAtBucket: Date
    let cipherSuite: String
}

public enum RendezvousPurpose: String, Codable, Equatable, Hashable, CaseIterable {
    case contactPairing
    case endpointAdmission
    case relayMigration
    case groupInvitation
    case historyTransfer
}

public struct RendezvousOffer: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let purpose: RendezvousPurpose
    public let ephemeralAgreementPublicKey: Data
    public let temporaryRoute: String
    public let oneTimeToken: Data
    public let createdAt: Date
    public let expiresAt: Date
    public let supportedArchitectureVersions: [UInt16]

    public init(
        version: Int = NoctweaveSelfSyncV2.version,
        id: UUID = UUID(),
        purpose: RendezvousPurpose,
        ephemeralAgreementPublicKey: Data,
        temporaryRoute: String,
        oneTimeToken: Data,
        createdAt: Date = Date(),
        expiresAt: Date,
        supportedArchitectureVersions: [UInt16] = [2]
    ) {
        self.version = version
        self.id = id
        self.purpose = purpose
        self.ephemeralAgreementPublicKey = ephemeralAgreementPublicKey
        self.temporaryRoute = temporaryRoute
        self.oneTimeToken = oneTimeToken
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.supportedArchitectureVersions = Array(Set(supportedArchitectureVersions)).sorted()
    }

    public var isStructurallyValid: Bool {
        let normalizedRoute = temporaryRoute.trimmingCharacters(in: .whitespacesAndNewlines)
        let lifetime = expiresAt.timeIntervalSince(createdAt)
        return version == NoctweaveSelfSyncV2.version
            && AgreementKeyPair.isValidPublicKey(ephemeralAgreementPublicKey)
            && !normalizedRoute.isEmpty
            && normalizedRoute == temporaryRoute
            && temporaryRoute.utf8.count <= NoctweaveSelfSyncV2.maximumTemporaryRouteBytes
            && temporaryRoute.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
            && oneTimeToken.count == 32
            && createdAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && lifetime > 0
            && lifetime <= NoctweaveSelfSyncV2.maximumRendezvousLifetime
            && !supportedArchitectureVersions.isEmpty
            && supportedArchitectureVersions.count <= 8
            && supportedArchitectureVersions.contains(UInt16(NoctweaveArchitectureV2.version))
    }

    public func isUsable(at date: Date = Date(), for expectedPurpose: RendezvousPurpose) -> Bool {
        isStructurallyValid
            && purpose == expectedPurpose
            && date >= createdAt
            && date < expiresAt
    }

    public var purposeBindingDigest: Data? {
        guard isStructurallyValid,
              let encoded = try? NoctweaveCoder.encode(bindingPayload, sortedKeys: true) else {
            return nil
        }
        return Data(SHA256.hash(data: encoded))
    }

    private var bindingPayload: RendezvousBindingPayload {
        RendezvousBindingPayload(
            offerId: id,
            purpose: purpose,
            ephemeralAgreementPublicKey: ephemeralAgreementPublicKey,
            temporaryRoute: temporaryRoute,
            oneTimeToken: oneTimeToken,
            createdAt: createdAt,
            expiresAt: expiresAt,
            supportedArchitectureVersions: supportedArchitectureVersions
        )
    }
}

private struct RendezvousBindingPayload: Encodable {
    let domain = "Noctweave/rendezvous/v2"
    let offerId: UUID
    let purpose: RendezvousPurpose
    let ephemeralAgreementPublicKey: Data
    let temporaryRoute: String
    let oneTimeToken: Data
    let createdAt: Date
    let expiresAt: Date
    let supportedArchitectureVersions: [UInt16]
}

public struct EncryptedRendezvousPayload: Codable, Equatable {
    public let version: Int
    public let offerId: UUID
    public let purpose: RendezvousPurpose
    public let expiresAt: Date
    public let payload: EncryptedPayload

    public init(
        version: Int = NoctweaveSelfSyncV2.version,
        offerId: UUID,
        purpose: RendezvousPurpose,
        expiresAt: Date,
        payload: EncryptedPayload
    ) {
        self.version = version
        self.offerId = offerId
        self.purpose = purpose
        self.expiresAt = expiresAt
        self.payload = payload
    }

    public static func seal(
        _ plaintext: Data,
        for offer: RendezvousOffer,
        key: SymmetricKey,
        at date: Date = Date()
    ) throws -> EncryptedRendezvousPayload {
        guard offer.isUsable(at: date, for: offer.purpose),
              !plaintext.isEmpty,
              plaintext.count <= NoctweaveSelfSyncV2.maximumRendezvousPayloadBytes,
              let binding = offer.purposeBindingDigest else {
            throw SelfSyncV2Error.invalidRendezvous
        }
        return EncryptedRendezvousPayload(
            offerId: offer.id,
            purpose: offer.purpose,
            expiresAt: offer.expiresAt,
            payload: try CryptoBox.encrypt(plaintext, key: key, authenticatedData: binding)
        )
    }

    public func open(
        for offer: RendezvousOffer,
        expectedPurpose: RendezvousPurpose,
        key: SymmetricKey,
        at date: Date = Date()
    ) throws -> Data {
        guard version == NoctweaveSelfSyncV2.version,
              offerId == offer.id,
              purpose == expectedPurpose,
              purpose == offer.purpose,
              expiresAt == offer.expiresAt,
              offer.isUsable(at: date, for: expectedPurpose),
              payload.nonce.count == 12,
              payload.tag.count == 16,
              !payload.ciphertext.isEmpty,
              payload.ciphertext.count <= NoctweaveSelfSyncV2.maximumRendezvousPayloadBytes,
              let binding = offer.purposeBindingDigest,
              let plaintext = try? CryptoBox.decrypt(payload, key: key, authenticatedData: binding),
              !plaintext.isEmpty,
              plaintext.count <= NoctweaveSelfSyncV2.maximumRendezvousPayloadBytes else {
            throw SelfSyncV2Error.invalidRendezvous
        }
        return plaintext
    }
}

public struct HistoryArchiveManifest: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let identityGenerationId: UUID
    public let snapshotId: UUID
    public let createdByInstallationId: UUID
    public let encryptedByteCount: UInt64
    public let ciphertextDigest: Data
    public let createdAt: Date
    public let expiresAt: Date?

    public init(
        version: Int = NoctweaveSelfSyncV2.version,
        id: UUID = UUID(),
        identityGenerationId: UUID,
        snapshotId: UUID,
        createdByInstallationId: UUID,
        encryptedByteCount: UInt64,
        ciphertextDigest: Data,
        createdAt: Date = Date(),
        expiresAt: Date? = nil
    ) {
        self.version = version
        self.id = id
        self.identityGenerationId = identityGenerationId
        self.snapshotId = snapshotId
        self.createdByInstallationId = createdByInstallationId
        self.encryptedByteCount = encryptedByteCount
        self.ciphertextDigest = ciphertextDigest
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveSelfSyncV2.version
            && encryptedByteCount > 0
            && encryptedByteCount <= NoctweaveSelfSyncV2.maximumArchiveBytes
            && ciphertextDigest.count == 32
            && createdAt.timeIntervalSince1970.isFinite
            && (expiresAt?.timeIntervalSince1970.isFinite ?? true)
            && (expiresAt.map { $0 > createdAt } ?? true)
    }
}

public enum HistoryAccessScope: String, Codable, Equatable {
    case readOnlyHistory
}

/// This grant decrypts an archive only. It can never authorize future sends, mailbox sync, or group leaves.
public struct HistoryAccessGrant: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let archiveId: UUID
    public let archiveManifestDigest: Data
    public let identityGenerationId: UUID
    public let recipientInstallationId: UUID
    public let scope: HistoryAccessScope
    public let wrappedArchiveKey: Data
    public let createdAt: Date
    public let expiresAt: Date

    public init(
        version: Int = NoctweaveSelfSyncV2.version,
        id: UUID = UUID(),
        archiveId: UUID,
        archiveManifestDigest: Data,
        identityGenerationId: UUID,
        recipientInstallationId: UUID,
        scope: HistoryAccessScope = .readOnlyHistory,
        wrappedArchiveKey: Data,
        createdAt: Date = Date(),
        expiresAt: Date
    ) {
        self.version = version
        self.id = id
        self.archiveId = archiveId
        self.archiveManifestDigest = archiveManifestDigest
        self.identityGenerationId = identityGenerationId
        self.recipientInstallationId = recipientInstallationId
        self.scope = scope
        self.wrappedArchiveKey = wrappedArchiveKey
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }

    public var authorizesFutureParticipation: Bool { false }

    public var isStructurallyValid: Bool {
        version == NoctweaveSelfSyncV2.version
            && archiveManifestDigest.count == 32
            && !wrappedArchiveKey.isEmpty
            && wrappedArchiveKey.count <= NoctweaveSelfSyncV2.maximumWrappedArchiveKeyBytes
            && createdAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && expiresAt > createdAt
    }

    public func canImportHistory(at date: Date = Date()) -> Bool {
        isStructurallyValid && date >= createdAt && date < expiresAt
    }
}

/// Future participation requires a separately verified signed installation manifest.
public struct InstallationParticipationAuthorization: Codable, Equatable {
    public let identityGenerationId: UUID
    public let installationId: UUID
    public let manifestEpoch: UInt64
    public let manifestDigest: Data

    public init(
        identityGenerationId: UUID,
        installationId: UUID,
        manifestEpoch: UInt64,
        manifestDigest: Data
    ) {
        self.identityGenerationId = identityGenerationId
        self.installationId = installationId
        self.manifestEpoch = manifestEpoch
        self.manifestDigest = manifestDigest
    }

    public var isStructurallyValid: Bool {
        manifestEpoch > 0 && manifestDigest.count == 32
    }
}
