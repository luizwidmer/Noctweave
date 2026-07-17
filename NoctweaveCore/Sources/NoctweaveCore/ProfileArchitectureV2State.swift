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

/// Endpoint-aware state for one pairwise relationship. Reachability is held
/// only as authenticated opaque send routes learned inside that relationship.
public struct RelationshipStateV2: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let contactId: UUID
    public let localEndpointHandle: RelationshipEndpointHandle
    public private(set) var conversationIds: [String]
    public private(set) var routeSets: [PairwiseRouteSetV2]
    public private(set) var events: [ConversationEvent]
    public private(set) var eventCheckpoint: RelationshipEventCheckpointV2?
    public let createdAt: Date

    public init(
        version: Int = NoctweaveArchitectureV2.version,
        id: UUID = UUID(),
        contactId: UUID,
        localEndpointHandle: RelationshipEndpointHandle,
        conversationIds: [String] = [],
        routeSets: [PairwiseRouteSetV2] = [],
        events: [ConversationEvent] = [],
        eventCheckpoint: RelationshipEventCheckpointV2? = nil,
        createdAt: Date = Date()
    ) {
        self.version = version
        self.id = id
        self.contactId = contactId
        self.localEndpointHandle = localEndpointHandle
        self.conversationIds = Array(Set(conversationIds)).sorted()
        self.routeSets = routeSets.sorted {
            $0.ownerEndpointHandle.rawValue < $1.ownerEndpointHandle.rawValue
        }
        self.events = events
        self.eventCheckpoint = eventCheckpoint
        self.createdAt = createdAt
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveArchitectureV2.version
            && localEndpointHandle.isStructurallyValid
            && createdAt.timeIntervalSince1970.isFinite
            && conversationIds.count <= 64
            && Set(conversationIds).count == conversationIds.count
            && conversationIds.allSatisfy {
                !$0.isEmpty && $0.utf8.count <= 256
            }
            && routeSets.count <= NoctweaveArchitectureV2.maximumEndpoints * 2
            && Set(routeSets.map(\.ownerEndpointHandle)).count == routeSets.count
            && routeSets.allSatisfy {
            $0.relationshipID == id && $0.isStructurallyValid
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
    /// snapshots. Binding the supplied endpoint key to the peer identity
    /// remains the caller's authenticated endpoint-manifest check.
    @discardableResult
    public mutating func upsertVerifiedRouteSet(
        _ routeSet: PairwiseRouteSetV2,
        ownerSigningPublicKey: Data
    ) -> Bool {
        guard routeSet.relationshipID == id,
              routeSet.verify(ownerSigningPublicKey: ownerSigningPublicKey) else {
            return false
        }
        if let index = routeSets.firstIndex(where: {
            $0.ownerEndpointHandle == routeSet.ownerEndpointHandle
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
            guard routeSets.count < NoctweaveArchitectureV2.maximumEndpoints * 2 else {
                return false
            }
            routeSets.append(routeSet)
        }
        routeSets.sort {
            $0.ownerEndpointHandle.rawValue < $1.ownerEndpointHandle.rawValue
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

public enum SelfSyncLocalStateV2Error: Error, Equatable {
    case invalidState
    case sequenceExhausted
    case sourceCapacityReached
    case wrongGeneration
}

public struct SelfSyncReceiveResultV2: Equatable {
    public let sourceResult: SelfSyncSourceApplyResultV2
    public let payload: TypedSelfSyncPayloadV2
    public let identityGenerationId: UUID
    public let sourceOrderKey: Data
    public let recordId: UUID
    public let recordDigest: Data

    init(
        sourceResult: SelfSyncSourceApplyResultV2,
        payload: TypedSelfSyncPayloadV2,
        identityGenerationId: UUID,
        sourceOrderKey: Data,
        recordId: UUID,
        recordDigest: Data
    ) {
        self.sourceResult = sourceResult
        self.payload = payload
        self.identityGenerationId = identityGenerationId
        self.sourceOrderKey = sourceOrderKey
        self.recordId = recordId
        self.recordDigest = recordDigest
    }
}

/// Local secret and progress state for one identity generation's signed hidden
/// self-sync epoch. It contains no relay, account, provider, recovery, or
/// cross-generation identifier. Each source endpoint still authenticates its
/// own records; possession of the shared epoch key alone is never authority.
public struct SelfSyncLocalStateV2: Codable, Equatable {
    public let version: Int
    public let identityGenerationId: UUID
    public private(set) var selfSyncEpoch: UInt64
    public private(set) var previousEpochDigest: Data?
    public private(set) var epochKeyData: Data
    public private(set) var nextSourceSequence: UInt64
    public private(set) var lastSourceDigest: Data?
    public private(set) var appliedSourceChains: [SelfSyncSourceChainV2]

    public init(
        version: Int = NoctweaveSelfSyncV2.version,
        identityGenerationId: UUID,
        selfSyncEpoch: UInt64 = 1,
        previousEpochDigest: Data? = nil,
        epochKeyData: Data,
        nextSourceSequence: UInt64 = 1,
        lastSourceDigest: Data? = nil,
        appliedSourceChains: [SelfSyncSourceChainV2] = []
    ) {
        self.version = version
        self.identityGenerationId = identityGenerationId
        self.selfSyncEpoch = selfSyncEpoch
        self.previousEpochDigest = previousEpochDigest
        self.epochKeyData = epochKeyData
        self.nextSourceSequence = nextSourceSequence
        self.lastSourceDigest = lastSourceDigest
        self.appliedSourceChains = appliedSourceChains.sorted {
            $0.sourceEndpointId.uuidString < $1.sourceEndpointId.uuidString
        }
    }

    public static func generate(
        identityGenerationId: UUID,
        selfSyncEpoch: UInt64 = 1,
        previousEpochDigest: Data? = nil
    ) -> SelfSyncLocalStateV2 {
        SelfSyncLocalStateV2(
            identityGenerationId: identityGenerationId,
            selfSyncEpoch: selfSyncEpoch,
            previousEpochDigest: previousEpochDigest,
            epochKeyData: SymmetricKey(size: .bits256).dataRepresentation
        )
    }

    public var epochCommitmentDigest: Data {
        var material = Data("Noctweave/self-sync-epoch-commitment/v2".utf8)
        material.append(0)
        material.append(Data(identityGenerationId.uuidString.lowercased().utf8))
        var epoch = selfSyncEpoch.bigEndian
        Swift.withUnsafeBytes(of: &epoch) { material.append(contentsOf: $0) }
        material.append(Data(SHA256.hash(data: epochKeyData)))
        return Data(SHA256.hash(data: material))
    }

    public var isStructurallyValid: Bool {
        let sourceIds = appliedSourceChains.map(\.sourceEndpointId)
        return version == NoctweaveSelfSyncV2.version
            && selfSyncEpoch > 0
            && ((selfSyncEpoch == 1 && previousEpochDigest == nil)
                || (selfSyncEpoch > 1 && previousEpochDigest?.count == 32))
            && epochKeyData.count == 32
            && nextSourceSequence > 0
            && ((nextSourceSequence == 1 && lastSourceDigest == nil)
                || (nextSourceSequence > 1 && lastSourceDigest?.count == 32))
            && appliedSourceChains.count <= NoctweaveArchitectureV2.maximumEndpoints
            && Set(sourceIds).count == sourceIds.count
            && appliedSourceChains.allSatisfy {
                $0.identityGenerationId == identityGenerationId && $0.isStructurallyValid
            }
    }

    /// Creates a fresh epoch after endpoint-set change. The old epoch key is
    /// not retained and no membership or continuity crosses an identity burn.
    public func rotatingEpoch() throws -> SelfSyncLocalStateV2 {
        guard isStructurallyValid, selfSyncEpoch < UInt64.max else {
            throw SelfSyncLocalStateV2Error.invalidState
        }
        return Self.generate(
            identityGenerationId: identityGenerationId,
            selfSyncEpoch: selfSyncEpoch + 1,
            previousEpochDigest: epochCommitmentDigest
        )
    }

    /// Reserves, endpoint-signs, and seals one source-ordered record. Persist
    /// the mutated state and exact returned ciphertext atomically before
    /// publication; a retry must reuse the returned ciphertext.
    public mutating func sealEvent(
        sourceEndpointId: UUID,
        manifestEpoch: UInt64,
        payload: TypedSelfSyncPayloadV2,
        sourceSigningKey: SigningKeyPair,
        createdAt: Date = Date()
    ) throws -> SealedSelfSyncRecordV2 {
        guard isStructurallyValid else {
            throw SelfSyncLocalStateV2Error.invalidState
        }
        guard nextSourceSequence < UInt64.max else {
            throw SelfSyncLocalStateV2Error.sequenceExhausted
        }
        let record = try SignedSelfSyncRecordV2.create(
            identityGenerationId: identityGenerationId,
            sourceEndpointId: sourceEndpointId,
            manifestEpoch: manifestEpoch,
            sourceSequence: nextSourceSequence,
            previousSourceDigest: lastSourceDigest,
            createdAt: createdAt,
            payload: payload,
            sourceSigningKey: sourceSigningKey
        )
        guard let digest = record.digest else {
            throw SelfSyncLocalStateV2Error.invalidState
        }
        let sealed = try SealedSelfSyncRecordV2.seal(
            record,
            epochKeyData: epochKeyData,
            storedAt: createdAt
        )
        nextSourceSequence += 1
        lastSourceDigest = digest
        return sealed
    }

    /// Opens and source-verifies one record against an authenticated current
    /// generation manifest, then advances exactly one source chain. Callers
    /// should invoke this on a candidate copy and persist the returned payload,
    /// candidate state, and any application projection in one transaction.
    public mutating func openAndAdvance(
        _ sealed: SealedSelfSyncRecordV2,
        manifest: EndpointSetManifest,
        identityPublicKey: Data
    ) throws -> SelfSyncReceiveResultV2 {
        guard isStructurallyValid else {
            throw SelfSyncLocalStateV2Error.invalidState
        }
        let record = try sealed.open(epochKeyData: epochKeyData)
        guard record.identityGenerationId == identityGenerationId,
              manifest.identityGenerationId == identityGenerationId else {
            throw SelfSyncLocalStateV2Error.wrongGeneration
        }

        let index = appliedSourceChains.firstIndex {
            $0.sourceEndpointId == record.sourceEndpointId
        }
        var candidate = index.map { appliedSourceChains[$0] }
            ?? SelfSyncSourceChainV2(
                identityGenerationId: identityGenerationId,
                sourceEndpointId: record.sourceEndpointId
            )
        if index == nil,
           appliedSourceChains.count >= NoctweaveArchitectureV2.maximumEndpoints {
            throw SelfSyncLocalStateV2Error.sourceCapacityReached
        }
        let result = try candidate.apply(
            record,
            manifest: manifest,
            identityPublicKey: identityPublicKey
        )
        guard let recordDigest = record.digest else {
            throw SelfSyncLocalStateV2Error.invalidState
        }
        if result == .applied {
            if let index {
                appliedSourceChains[index] = candidate
            } else {
                appliedSourceChains.append(candidate)
                appliedSourceChains.sort {
                    $0.sourceEndpointId.uuidString < $1.sourceEndpointId.uuidString
                }
            }
        }
        var sourceOrderMaterial = Data("Noctweave/self-sync-source-order/v2".utf8)
        sourceOrderMaterial.append(0)
        sourceOrderMaterial.append(
            Data(identityGenerationId.uuidString.lowercased().utf8)
        )
        sourceOrderMaterial.append(0)
        sourceOrderMaterial.append(
            Data(record.sourceEndpointId.uuidString.lowercased().utf8)
        )
        return SelfSyncReceiveResultV2(
            sourceResult: result,
            payload: record.payload,
            identityGenerationId: identityGenerationId,
            sourceOrderKey: Data(SHA256.hash(data: sourceOrderMaterial)),
            recordId: record.id,
            recordDigest: recordDigest
        )
    }

}
