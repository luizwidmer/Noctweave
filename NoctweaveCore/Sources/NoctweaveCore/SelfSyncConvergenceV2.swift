import Foundation

/// Deterministic, generation-local projections derived only from records that
/// passed `SelfSyncLocalStateV2.openAndAdvance`. Arrival time is never a
/// conflict-resolution input.
public enum NoctweaveSelfSyncConvergenceV2 {
    public static let version = NoctweaveSignedSelfSyncV2.version
    public static let maximumConsentStates = 4_096
    public static let maximumReadMarkers = 4_096
    public static let maximumPreferences = 512
}

public enum SelfSyncConvergenceV2Error: Error, Equatable {
    case invalidState
    case wrongGeneration
    case capacityReached
}

public enum SelfSyncExternalHandlingV2: Equatable {
    case conversationEvent(ConversationEvent)
    case endpointSetManifest(EndpointSetManifest)
    case relationshipRouteSet(RelationshipRouteSetV2)
    case groupCommit(SignedGroupCommitV2)
}

public enum SelfSyncConvergenceApplyResultV2: Equatable {
    case projectionChanged
    case projectionUnchanged
    case exactDuplicate
    case requiresExternalHandling(SelfSyncExternalHandlingV2)
}

/// Stable conflict stamp. `sourceOrderKey` is a generation-bound digest of the
/// authenticated source, not a reusable endpoint identifier.
public struct SelfSyncConvergenceStampV2: Codable, Equatable {
    public let sourceOrderKey: Data
    public let recordDigest: Data

    init(sourceOrderKey: Data, recordDigest: Data) {
        self.sourceOrderKey = sourceOrderKey
        self.recordDigest = recordDigest
    }

    public var isStructurallyValid: Bool {
        sourceOrderKey.count == 32 && recordDigest.count == 32
    }

    fileprivate func isPreferred(over other: SelfSyncConvergenceStampV2) -> Bool {
        if sourceOrderKey != other.sourceOrderKey {
            return other.sourceOrderKey.lexicographicallyPrecedes(sourceOrderKey)
        }
        return other.recordDigest.lexicographicallyPrecedes(recordDigest)
    }
}

public struct SelfSyncConvergedConsentV2: Codable, Equatable {
    public let update: SelfSyncConsentUpdateV2
    public let stamp: SelfSyncConvergenceStampV2

    init(update: SelfSyncConsentUpdateV2, stamp: SelfSyncConvergenceStampV2) {
        self.update = update
        self.stamp = stamp
    }

    public var isStructurallyValid: Bool {
        update.isStructurallyValid && stamp.isStructurallyValid
    }
}

public struct SelfSyncConvergedReadMarkerV2: Codable, Equatable {
    public let marker: SelfSyncReadMarkerV2
    public let stamp: SelfSyncConvergenceStampV2

    init(marker: SelfSyncReadMarkerV2, stamp: SelfSyncConvergenceStampV2) {
        self.marker = marker
        self.stamp = stamp
    }

    public var isStructurallyValid: Bool {
        marker.isStructurallyValid && stamp.isStructurallyValid
    }
}

public struct SelfSyncConvergedPreferenceV2: Codable, Equatable {
    public let update: SelfSyncPreferenceUpdateV2
    public let stamp: SelfSyncConvergenceStampV2

    init(update: SelfSyncPreferenceUpdateV2, stamp: SelfSyncConvergenceStampV2) {
        self.update = update
        self.stamp = stamp
    }

    public var isStructurallyValid: Bool {
        update.isStructurallyValid && stamp.isStructurallyValid
    }
}

/// Bounded local projection for one disposable identity generation. Security
/// state remains outside this projection and is returned to an explicit
/// protocol handler.
public struct SelfSyncConvergenceProjectionV2: Codable, Equatable {
    public let version: Int
    public let identityGenerationId: UUID
    public private(set) var consentStates: [SelfSyncConvergedConsentV2]
    public private(set) var readMarkers: [SelfSyncConvergedReadMarkerV2]
    public private(set) var preferences: [SelfSyncConvergedPreferenceV2]

    public init(identityGenerationId: UUID) {
        version = NoctweaveSelfSyncConvergenceV2.version
        self.identityGenerationId = identityGenerationId
        consentStates = []
        readMarkers = []
        preferences = []
    }

    init(
        identityGenerationId: UUID,
        consentStates: [SelfSyncConvergedConsentV2],
        readMarkers: [SelfSyncConvergedReadMarkerV2],
        preferences: [SelfSyncConvergedPreferenceV2]
    ) throws {
        version = NoctweaveSelfSyncConvergenceV2.version
        self.identityGenerationId = identityGenerationId
        self.consentStates = consentStates.sorted(by: Self.consentOrder)
        self.readMarkers = readMarkers.sorted(by: Self.readOrder)
        self.preferences = preferences.sorted(by: Self.preferenceOrder)
        guard isStructurallyValid else {
            throw SelfSyncConvergenceV2Error.invalidState
        }
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveSelfSyncConvergenceV2.version
            && consentStates.count <= NoctweaveSelfSyncConvergenceV2.maximumConsentStates
            && readMarkers.count <= NoctweaveSelfSyncConvergenceV2.maximumReadMarkers
            && preferences.count <= NoctweaveSelfSyncConvergenceV2.maximumPreferences
            && consentStates.allSatisfy(\.isStructurallyValid)
            && readMarkers.allSatisfy(\.isStructurallyValid)
            && preferences.allSatisfy(\.isStructurallyValid)
            && Set(consentStates.map { $0.update.relationshipId }).count == consentStates.count
            && Set(readMarkers.map { $0.marker.relationshipId }).count == readMarkers.count
            && Set(preferences.map { $0.update.key }).count == preferences.count
            && consentStates.elementsEqual(consentStates.sorted(by: Self.consentOrder))
            && readMarkers.elementsEqual(readMarkers.sorted(by: Self.readOrder))
            && preferences.elementsEqual(preferences.sorted(by: Self.preferenceOrder))
    }

    /// Accepts no unsigned payload. The receive result has no public
    /// initializer and is emitted only after authenticated decryption, source
    /// signature verification, and exact source-chain advancement.
    @discardableResult
    public mutating func apply(
        _ verified: SelfSyncReceiveResultV2
    ) throws -> SelfSyncConvergenceApplyResultV2 {
        guard isStructurallyValid,
              verified.sourceOrderKey.count == 32,
              verified.recordDigest.count == 32 else {
            throw SelfSyncConvergenceV2Error.invalidState
        }
        guard verified.identityGenerationId == identityGenerationId else {
            throw SelfSyncConvergenceV2Error.wrongGeneration
        }
        if verified.sourceResult == .exactDuplicate {
            return .exactDuplicate
        }

        let stamp = SelfSyncConvergenceStampV2(
            sourceOrderKey: verified.sourceOrderKey,
            recordDigest: verified.recordDigest
        )
        switch verified.payload {
        case .consent(let update):
            return try applyConsent(update, stamp: stamp)
        case .readMarker(let marker):
            return try applyReadMarker(marker, stamp: stamp)
        case .preference(let update):
            return try applyPreference(update, stamp: stamp)
        case .conversationEvent(let event):
            return .requiresExternalHandling(.conversationEvent(event))
        case .endpointSetManifest(let manifest):
            return .requiresExternalHandling(.endpointSetManifest(manifest))
        case .relationshipRouteSet(let routeSet):
            return .requiresExternalHandling(.relationshipRouteSet(routeSet))
        case .groupCommit(let commit):
            return .requiresExternalHandling(.groupCommit(commit))
        }
    }

    private mutating func applyConsent(
        _ update: SelfSyncConsentUpdateV2,
        stamp: SelfSyncConvergenceStampV2
    ) throws -> SelfSyncConvergenceApplyResultV2 {
        guard update.isStructurallyValid else {
            throw SelfSyncConvergenceV2Error.invalidState
        }
        if let index = consentStates.firstIndex(where: {
            $0.update.relationshipId == update.relationshipId
        }) {
            let current = consentStates[index]
            guard update.revision > current.update.revision
                    || (update.revision == current.update.revision
                        && stamp.isPreferred(over: current.stamp)) else {
                return .projectionUnchanged
            }
            consentStates[index] = SelfSyncConvergedConsentV2(
                update: update,
                stamp: stamp
            )
        } else {
            guard consentStates.count
                    < NoctweaveSelfSyncConvergenceV2.maximumConsentStates else {
                throw SelfSyncConvergenceV2Error.capacityReached
            }
            consentStates.append(SelfSyncConvergedConsentV2(update: update, stamp: stamp))
            consentStates.sort(by: Self.consentOrder)
        }
        return .projectionChanged
    }

    private mutating func applyReadMarker(
        _ marker: SelfSyncReadMarkerV2,
        stamp: SelfSyncConvergenceStampV2
    ) throws -> SelfSyncConvergenceApplyResultV2 {
        guard marker.isStructurallyValid else {
            throw SelfSyncConvergenceV2Error.invalidState
        }
        if let index = readMarkers.firstIndex(where: {
            $0.marker.relationshipId == marker.relationshipId
        }) {
            let current = readMarkers[index]
            guard marker.logicalPosition > current.marker.logicalPosition
                    || (marker.logicalPosition == current.marker.logicalPosition
                        && stamp.isPreferred(over: current.stamp)) else {
                return .projectionUnchanged
            }
            readMarkers[index] = SelfSyncConvergedReadMarkerV2(
                marker: marker,
                stamp: stamp
            )
        } else {
            guard readMarkers.count
                    < NoctweaveSelfSyncConvergenceV2.maximumReadMarkers else {
                throw SelfSyncConvergenceV2Error.capacityReached
            }
            readMarkers.append(SelfSyncConvergedReadMarkerV2(marker: marker, stamp: stamp))
            readMarkers.sort(by: Self.readOrder)
        }
        return .projectionChanged
    }

    private mutating func applyPreference(
        _ update: SelfSyncPreferenceUpdateV2,
        stamp: SelfSyncConvergenceStampV2
    ) throws -> SelfSyncConvergenceApplyResultV2 {
        guard update.isStructurallyValid else {
            throw SelfSyncConvergenceV2Error.invalidState
        }
        if let index = preferences.firstIndex(where: { $0.update.key == update.key }) {
            let current = preferences[index]
            guard update.revision > current.update.revision
                    || (update.revision == current.update.revision
                        && stamp.isPreferred(over: current.stamp)) else {
                return .projectionUnchanged
            }
            preferences[index] = SelfSyncConvergedPreferenceV2(
                update: update,
                stamp: stamp
            )
        } else {
            guard preferences.count
                    < NoctweaveSelfSyncConvergenceV2.maximumPreferences else {
                throw SelfSyncConvergenceV2Error.capacityReached
            }
            preferences.append(SelfSyncConvergedPreferenceV2(update: update, stamp: stamp))
            preferences.sort(by: Self.preferenceOrder)
        }
        return .projectionChanged
    }

    private static func consentOrder(
        _ lhs: SelfSyncConvergedConsentV2,
        _ rhs: SelfSyncConvergedConsentV2
    ) -> Bool {
        lhs.update.relationshipId.uuidString.lowercased()
            < rhs.update.relationshipId.uuidString.lowercased()
    }

    private static func readOrder(
        _ lhs: SelfSyncConvergedReadMarkerV2,
        _ rhs: SelfSyncConvergedReadMarkerV2
    ) -> Bool {
        lhs.marker.relationshipId.uuidString.lowercased()
            < rhs.marker.relationshipId.uuidString.lowercased()
    }

    private static func preferenceOrder(
        _ lhs: SelfSyncConvergedPreferenceV2,
        _ rhs: SelfSyncConvergedPreferenceV2
    ) -> Bool {
        Data(lhs.update.key.utf8).lexicographicallyPrecedes(Data(rhs.update.key.utf8))
    }

    private enum CodingKeys: String, CodingKey {
        case version
        case identityGenerationId
        case consentStates
        case readMarkers
        case preferences
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        identityGenerationId = try container.decode(UUID.self, forKey: .identityGenerationId)
        consentStates = try container.decode(
            [SelfSyncConvergedConsentV2].self,
            forKey: .consentStates
        )
        readMarkers = try container.decode(
            [SelfSyncConvergedReadMarkerV2].self,
            forKey: .readMarkers
        )
        preferences = try container.decode(
            [SelfSyncConvergedPreferenceV2].self,
            forKey: .preferences
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Invalid self-sync convergence projection"
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid self-sync convergence projection"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(identityGenerationId, forKey: .identityGenerationId)
        try container.encode(consentStates, forKey: .consentStates)
        try container.encode(readMarkers, forKey: .readMarkers)
        try container.encode(preferences, forKey: .preferences)
    }
}
