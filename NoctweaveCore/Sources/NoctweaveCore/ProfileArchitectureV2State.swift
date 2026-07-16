import CryptoKit
import Foundation

/// A bounded cryptographic commitment to canonical events removed from a
/// relationship's recent window. Every compaction round commits to the prior
/// checkpoint and to the ordered canonical bytes of the newly removed prefix.
public struct RelationshipEventCheckpointV2: Codable, Equatable {
    public static let version = NoctweaveArchitectureV2.version
    public static let digestDomain = "Noctweave/relationship-event-checkpoint/v2"

    public let version: Int
    public let relationshipId: UUID
    public let compactedEventCount: UInt64
    public let lastCompactedEventId: UUID
    public let digest: Data

    public init(
        version: Int = RelationshipEventCheckpointV2.version,
        relationshipId: UUID,
        compactedEventCount: UInt64,
        lastCompactedEventId: UUID,
        digest: Data
    ) {
        self.version = version
        self.relationshipId = relationshipId
        self.compactedEventCount = compactedEventCount
        self.lastCompactedEventId = lastCompactedEventId
        self.digest = digest
    }

    public func isStructurallyValid(for relationshipId: UUID) -> Bool {
        version == Self.version
            && self.relationshipId == relationshipId
            && compactedEventCount > 0
            && digest.count == SHA256.byteCount
    }

    static func advancing(
        previous: RelationshipEventCheckpointV2?,
        relationshipId: UUID,
        removedEvents: [ConversationEvent]
    ) throws -> RelationshipEventCheckpointV2 {
        guard !removedEvents.isEmpty,
              removedEvents.allSatisfy(\.isStructurallyValid),
              previous?.isStructurallyValid(for: relationshipId) ?? true else {
            throw RelationshipEventCheckpointError.invalidInput
        }
        let previousCount = previous?.compactedEventCount ?? 0
        guard UInt64(removedEvents.count) <= UInt64.max - previousCount else {
            throw RelationshipEventCheckpointError.countOverflow
        }
        var hasher = SHA256()
        updateLengthPrefixed(Data(Self.digestDomain.utf8), into: &hasher)
        hasher.update(data: uint64Bytes(UInt64(Self.version)))
        updateLengthPrefixed(
            Data(relationshipId.uuidString.lowercased().utf8),
            into: &hasher
        )
        hasher.update(data: uint64Bytes(previousCount))
        hasher.update(data: uint64Bytes(UInt64(removedEvents.count)))
        if let previousDigest = previous?.digest {
            hasher.update(data: Data([1]))
            hasher.update(data: previousDigest)
        } else {
            hasher.update(data: Data([0]))
        }
        for event in removedEvents {
            let canonicalEvent = try NoctweaveCoder.encode(event, sortedKeys: true)
            updateLengthPrefixed(canonicalEvent, into: &hasher)
        }
        return RelationshipEventCheckpointV2(
            relationshipId: relationshipId,
            compactedEventCount: previousCount + UInt64(removedEvents.count),
            lastCompactedEventId: removedEvents[removedEvents.count - 1].id,
            digest: Data(hasher.finalize())
        )
    }

    private static func updateLengthPrefixed(_ data: Data, into hasher: inout SHA256) {
        hasher.update(data: uint64Bytes(UInt64(data.count)))
        hasher.update(data: data)
    }

    private static func uint64Bytes(_ value: UInt64) -> Data {
        var bigEndian = value.bigEndian
        return withUnsafeBytes(of: &bigEndian) { Data($0) }
    }
}

public enum RelationshipEventCheckpointError: Error, Equatable {
    case invalidInput
    case countOverflow
}

/// Installation-aware state for one pairwise relationship. Legacy inbox
/// addresses are deliberately not promoted into v2 route capabilities: route
/// sets remain empty until an authenticated v2 route advertisement is learned.
public struct RelationshipStateV2: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let contactId: UUID
    public let localInstallationHandle: RelationshipInstallationHandle
    public private(set) var conversationIds: [String]
    public private(set) var routeSets: [RelationshipRouteSetV2]
    public private(set) var events: [ConversationEvent]
    public private(set) var eventCheckpoint: RelationshipEventCheckpointV2?
    public let createdAt: Date

    public init(
        version: Int = NoctweaveArchitectureV2.version,
        id: UUID = UUID(),
        contactId: UUID,
        localInstallationHandle: RelationshipInstallationHandle,
        conversationIds: [String] = [],
        routeSets: [RelationshipRouteSetV2] = [],
        events: [ConversationEvent] = [],
        eventCheckpoint: RelationshipEventCheckpointV2? = nil,
        createdAt: Date = Date()
    ) {
        self.version = version
        self.id = id
        self.contactId = contactId
        self.localInstallationHandle = localInstallationHandle
        self.conversationIds = Array(Set(conversationIds)).sorted()
        self.routeSets = routeSets.sorted {
            $0.ownerInstallationHandle.rawValue < $1.ownerInstallationHandle.rawValue
        }
        self.events = events
        self.eventCheckpoint = eventCheckpoint
        self.createdAt = createdAt
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveArchitectureV2.version
            && localInstallationHandle.isStructurallyValid
            && createdAt.timeIntervalSince1970.isFinite
            && conversationIds.count <= 64
            && Set(conversationIds).count == conversationIds.count
            && conversationIds.allSatisfy {
                !$0.isEmpty && $0.utf8.count <= 256
            }
            && routeSets.count <= NoctweaveArchitectureV2.maximumInstallations * 2
            && Set(routeSets.map(\.ownerInstallationHandle)).count == routeSets.count
            && routeSets.allSatisfy {
                $0.relationshipId == id && $0.isStructurallyValid
            }
            && events.count <= NoctweaveArchitectureV2.maximumRelationshipEvents
            && Set(events.map(\.id)).count == events.count
            && events.allSatisfy {
                $0.isStructurallyValid && conversationIds.contains($0.conversationId)
            }
            && (eventCheckpoint?.isStructurallyValid(for: id) ?? true)
            && totalEventCount != nil
    }

    /// Retains prior conversation identifiers because immutable events may
    /// refer to sessions that have since rotated.
    @discardableResult
    public mutating func includeConversationIds(_ identifiers: [String]) -> Bool {
        let merged = Array(Set(conversationIds + identifiers)).sorted()
        guard merged.count <= 64,
              merged.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 256 }) else {
            return false
        }
        guard merged != conversationIds else { return false }
        conversationIds = merged
        return true
    }

    /// Persists only structurally valid, cryptographically verified route
    /// snapshots. Binding the supplied installation key to the peer identity
    /// remains the caller's authenticated installation-manifest check.
    @discardableResult
    public mutating func upsertVerifiedRouteSet(
        _ routeSet: RelationshipRouteSetV2,
        ownerSigningPublicKey: Data
    ) -> Bool {
        guard routeSet.relationshipId == id,
              routeSet.verify(ownerSigningPublicKey: ownerSigningPublicKey) else {
            return false
        }
        if let index = routeSets.firstIndex(where: {
            $0.ownerInstallationHandle == routeSet.ownerInstallationHandle
        }) {
            let current = routeSets[index]
            if current == routeSet { return true }
            guard current.revision < UInt64.max,
                  routeSet.revision == current.revision + 1,
                  routeSet.previousDigest == current.digest else {
                return false
            }
            routeSets[index] = routeSet
        } else {
            guard routeSets.count < NoctweaveArchitectureV2.maximumInstallations * 2 else {
                return false
            }
            routeSets.append(routeSet)
        }
        routeSets.sort {
            $0.ownerInstallationHandle.rawValue < $1.ownerInstallationHandle.rawValue
        }
        return true
    }

    @discardableResult
    public mutating func appendEvent(_ event: ConversationEvent) -> Bool {
        guard event.isStructurallyValid,
              conversationIds.contains(event.conversationId) else {
            return false
        }
        if let existing = events.first(where: { $0.id == event.id }) {
            return existing == event
        }
        guard events.count <= NoctweaveArchitectureV2.maximumRelationshipEvents else {
            return false
        }
        if events.count == NoctweaveArchitectureV2.maximumRelationshipEvents {
            let recentWindow = NoctweaveArchitectureV2.relationshipEventRecentWindow
            guard recentWindow > 0,
                  recentWindow < NoctweaveArchitectureV2.maximumRelationshipEvents else {
                return false
            }
            let removalCount = events.count - recentWindow
            let removedEvents = Array(events.prefix(removalCount))
            guard let nextCheckpoint = try? RelationshipEventCheckpointV2.advancing(
                previous: eventCheckpoint,
                relationshipId: id,
                removedEvents: removedEvents
            ) else {
                return false
            }
            var retainedEvents = Array(events.suffix(recentWindow))
            retainedEvents.append(event)
            eventCheckpoint = nextCheckpoint
            events = retainedEvents
            return true
        }
        events.append(event)
        return true
    }

    public var totalEventCount: UInt64? {
        let compacted = eventCheckpoint?.compactedEventCount ?? 0
        guard UInt64(events.count) <= UInt64.max - compacted else { return nil }
        return compacted + UInt64(events.count)
    }
}

/// Local secret and progress state for one identity generation's hidden self-sync stream.
/// It belongs beside the profile's other private keys and must never be copied
/// into a self-sync event or snapshot payload.
public struct SelfSyncLocalStateV2: Codable, Equatable {
    public let version: Int
    public let identityGenerationId: UUID
    public let stream: SelfSyncStreamHandle
    public private(set) var encryptionKeyData: Data
    public private(set) var nextSourceSequence: UInt64
    public private(set) var appliedCursors: [SelfSyncInstallationCursor]

    public init(
        version: Int = NoctweaveSelfSyncV2.version,
        identityGenerationId: UUID,
        stream: SelfSyncStreamHandle,
        encryptionKeyData: Data,
        nextSourceSequence: UInt64 = 1,
        appliedCursors: [SelfSyncInstallationCursor] = []
    ) {
        self.version = version
        self.identityGenerationId = identityGenerationId
        self.stream = stream
        self.encryptionKeyData = encryptionKeyData
        self.nextSourceSequence = nextSourceSequence
        self.appliedCursors = appliedCursors.sorted {
            $0.installationId.uuidString < $1.installationId.uuidString
        }
    }

    public static func generate(identityGenerationId: UUID) -> SelfSyncLocalStateV2 {
        let streamMaterial = SymmetricKey(size: .bits256).dataRepresentation
        return SelfSyncLocalStateV2(
            identityGenerationId: identityGenerationId,
            stream: SelfSyncStreamHandle(rawValue: streamMaterial.base64EncodedString()),
            encryptionKeyData: SymmetricKey(size: .bits256).dataRepresentation
        )
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveSelfSyncV2.version
            && stream.isStructurallyValid
            && encryptionKeyData.count == 32
            && nextSourceSequence > 0
            && appliedCursors.count <= NoctweaveArchitectureV2.maximumInstallations
            && Set(appliedCursors.map(\.installationId)).count == appliedCursors.count
    }

    /// Reserves and seals one source-ordered event. Persist the mutated state
    /// and returned record atomically before publication.
    public mutating func sealEvent(
        sourceInstallationId: UUID,
        kind: SelfSyncEventKind,
        encodedPayload: Data,
        createdAt: Date = Date()
    ) throws -> EncryptedSelfSyncRecord {
        guard isStructurallyValid,
              nextSourceSequence < UInt64.max else {
            throw SelfSyncV2Error.invalidPlaintext
        }
        let event = SelfSyncEvent(
            identityGenerationId: identityGenerationId,
            sourceInstallationId: sourceInstallationId,
            sourceSequence: nextSourceSequence,
            createdAt: createdAt,
            kind: kind,
            encodedPayload: encodedPayload
        )
        let record = try EncryptedSelfSyncRecord.seal(
            .event(event),
            stream: stream,
            key: SymmetricKey(data: encryptionKeyData),
            storedAt: createdAt
        )
        nextSourceSequence += 1
        return record
    }

    @discardableResult
    public mutating func advanceAppliedCursor(
        installationId: UUID,
        throughSequence: UInt64
    ) -> Bool {
        if let index = appliedCursors.firstIndex(where: { $0.installationId == installationId }) {
            guard throughSequence > appliedCursors[index].throughSequence else { return false }
            appliedCursors[index] = SelfSyncInstallationCursor(
                installationId: installationId,
                throughSequence: throughSequence
            )
        } else {
            guard appliedCursors.count < NoctweaveArchitectureV2.maximumInstallations else {
                return false
            }
            appliedCursors.append(
                SelfSyncInstallationCursor(
                    installationId: installationId,
                    throughSequence: throughSequence
                )
            )
        }
        appliedCursors.sort { $0.installationId.uuidString < $1.installationId.uuidString }
        return true
    }
}
