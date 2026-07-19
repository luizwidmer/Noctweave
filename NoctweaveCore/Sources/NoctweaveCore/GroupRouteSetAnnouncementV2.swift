import Foundation

public enum GroupRouteSetAnnouncementV2Error: Error, Equatable {
    case invalidAnnouncement
    case invalidSignature
    case invalidSuccessor
    case routeSetMissing
    case routeSetExpired
}

private struct GroupRouteAnnouncementCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private func requireExactGroupRouteAnnouncementKeys<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ type: Key.Type
) throws where Key.AllCases: Collection {
    let strict = try decoder.container(keyedBy: GroupRouteAnnouncementCodingKey.self)
    guard Set(strict.allKeys.map(\.stringValue))
            == Set(type.allCases.map(\.stringValue)) else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "Group route announcement fields must match exactly"
            )
        )
    }
}

/// Group-control artifact announcing one credential's current opaque routes.
/// It is sealed independently to each peer route and signed only by the
/// announcing group credential. It creates no cross-group continuity.
public struct SignedGroupRouteSetAnnouncementV2: Codable, Equatable, Identifiable {
    public static let version = 2

    public let version: Int
    public let id: UUID
    public let groupID: UUID
    public let stateEpoch: UInt64
    public let routeSet: SignedGroupOpaqueRouteSetV2
    public let announcedAt: Date
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case groupID
        case stateEpoch
        case routeSet
        case announcedAt
        case signature
    }

    private init(
        version: Int = Self.version,
        id: UUID,
        groupID: UUID,
        stateEpoch: UInt64,
        routeSet: SignedGroupOpaqueRouteSetV2,
        announcedAt: Date,
        signature: Data
    ) {
        self.version = version
        self.id = id
        self.groupID = groupID
        self.stateEpoch = stateEpoch
        self.routeSet = routeSet
        self.announcedAt = announcedAt
        self.signature = signature
    }

    public static func create(
        id: UUID = UUID(),
        state: SignedGroupStateV2,
        routeSet: SignedGroupOpaqueRouteSetV2,
        localCredential: LocalGroupCredentialV2,
        announcedAt: Date = Date()
    ) throws -> Self {
        guard let leaf = state.activeCredentials.first(where: {
            $0.credentialHandle == localCredential.credentialHandle
        }),
              leaf.memberHandle == localCredential.memberHandle,
              leaf.admissionDigest == localCredential.admissionDigest,
              leaf.signingPublicKey == localCredential.signingKey.publicKeyData,
              routeSet.groupID == state.groupId,
              routeSet.ownerCredentialHandle == localCredential.credentialHandle,
              routeSet.ownerAdmissionDigest == localCredential.admissionDigest,
              try routeSet.verifyThrowing(
                  ownerSigningPublicKey: localCredential.signingKey.publicKeyData
              ),
              announcedAt.timeIntervalSince1970.isFinite,
              routeSet.issuedAt <= announcedAt,
              announcedAt < routeSet.expiresAt else {
            throw GroupRouteSetAnnouncementV2Error.invalidAnnouncement
        }
        var result = Self(
            id: id,
            groupID: state.groupId,
            stateEpoch: state.epoch,
            routeSet: routeSet,
            announcedAt: announcedAt,
            signature: Data()
        )
        result = Self(
            id: id,
            groupID: state.groupId,
            stateEpoch: state.epoch,
            routeSet: routeSet,
            announcedAt: announcedAt,
            signature: try localCredential.signingKey.sign(result.signableData())
        )
        guard result.isStructurallyValid else {
            throw GroupRouteSetAnnouncementV2Error.invalidAnnouncement
        }
        return result
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupRouteAnnouncementKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            id: try values.decode(UUID.self, forKey: .id),
            groupID: try values.decode(UUID.self, forKey: .groupID),
            stateEpoch: try values.decode(UInt64.self, forKey: .stateEpoch),
            routeSet: try values.decode(SignedGroupOpaqueRouteSetV2.self, forKey: .routeSet),
            announcedAt: try values.decode(Date.self, forKey: .announcedAt),
            signature: try values.decode(Data.self, forKey: .signature)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .signature,
                in: values,
                debugDescription: "Invalid signed group route announcement"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid route announcement")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(id, forKey: .id)
        try values.encode(groupID, forKey: .groupID)
        try values.encode(stateEpoch, forKey: .stateEpoch)
        try values.encode(routeSet, forKey: .routeSet)
        try values.encode(announcedAt, forKey: .announcedAt)
        try values.encode(signature, forKey: .signature)
    }

    public var isStructurallyValid: Bool {
        version == Self.version
            && stateEpoch > 0
            && routeSet.isStructurallyValid
            && routeSet.groupID == groupID
            && announcedAt.timeIntervalSince1970.isFinite
            && routeSet.issuedAt <= announcedAt
            && announcedAt < routeSet.expiresAt
            && !signature.isEmpty
            && signature.count <= 8 * 1_024
    }

    public func verified(
        against state: SignedGroupStateV2,
        observedAt: Date
    ) throws -> Self {
        guard isStructurallyValid,
              state.groupId == groupID,
              stateEpoch <= state.epoch,
              observedAt.timeIntervalSince1970.isFinite,
              announcedAt <= observedAt.addingTimeInterval(
                  NoctweaveSignedGroupV2.maximumClockSkewSeconds
              ),
              observedAt < routeSet.expiresAt,
              let leaf = state.activeCredentials.first(where: {
                  $0.credentialHandle == routeSet.ownerCredentialHandle
              }),
              leaf.admissionDigest == routeSet.ownerAdmissionDigest else {
            throw GroupRouteSetAnnouncementV2Error.invalidAnnouncement
        }
        return try verified(
            ownerSigningPublicKey: leaf.signingPublicKey,
            observedAt: observedAt
        )
    }

    func verified(
        ownerSigningPublicKey: Data,
        observedAt: Date
    ) throws -> Self {
        guard isStructurallyValid,
              observedAt.timeIntervalSince1970.isFinite,
              announcedAt <= observedAt.addingTimeInterval(
                  NoctweaveSignedGroupV2.maximumClockSkewSeconds
              ),
              observedAt < routeSet.expiresAt,
              try routeSet.verifyThrowing(
                  ownerSigningPublicKey: ownerSigningPublicKey
              ) else {
            throw GroupRouteSetAnnouncementV2Error.invalidAnnouncement
        }
        guard try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: signableData(),
            publicKeyData: ownerSigningPublicKey
        ) else {
            throw GroupRouteSetAnnouncementV2Error.invalidSignature
        }
        return self
    }

    private func signableData() throws -> Data {
        try NoctweaveCoder.encode(
            GroupRouteSetAnnouncementSignatureContextV2(
                version: version,
                id: id,
                groupID: groupID,
                stateEpoch: stateEpoch,
                routeSetDigest: try requiredRouteSetDigest(),
                announcedAt: announcedAt
            ),
            sortedKeys: true
        )
    }

    private func requiredRouteSetDigest() throws -> Data {
        guard let digest = routeSet.digest else {
            throw GroupRouteSetAnnouncementV2Error.invalidAnnouncement
        }
        return digest
    }
}

private struct GroupRouteSetAnnouncementSignatureContextV2: Codable {
    let version: Int
    let id: UUID
    let groupID: UUID
    let stateEpoch: UInt64
    let routeSetDigest: Data
    let announcedAt: Date
}

public struct CachedGroupRouteSetV2: Codable, Equatable, Identifiable {
    public var id: GroupScopedCredentialHandleV2 {
        announcement.routeSet.ownerCredentialHandle
    }
    public let announcement: SignedGroupRouteSetAnnouncementV2
    public let observedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case announcement
        case observedAt
    }

    public init(
        announcement: SignedGroupRouteSetAnnouncementV2,
        observedAt: Date
    ) {
        self.announcement = announcement
        self.observedAt = observedAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupRouteAnnouncementKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            announcement: try values.decode(
                SignedGroupRouteSetAnnouncementV2.self,
                forKey: .announcement
            ),
            observedAt: try values.decode(Date.self, forKey: .observedAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .observedAt,
                in: values,
                debugDescription: "Invalid cached group route set"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid cached route set")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(announcement, forKey: .announcement)
        try values.encode(observedAt, forKey: .observedAt)
    }

    public var isStructurallyValid: Bool {
        announcement.isStructurallyValid
            && observedAt.timeIntervalSince1970.isFinite
            && announcement.announcedAt <= observedAt.addingTimeInterval(
                NoctweaveSignedGroupV2.maximumClockSkewSeconds
            )
            && observedAt < announcement.routeSet.expiresAt
    }
}

/// Latest signer-authorized monotonic route announcement for each active remote
/// group credential. Direct successors remain hash-chained; a strictly newer
/// signed checkpoint repairs a receiver that missed expiring intermediate
/// revisions. Entries are local encrypted state; no relay or persona is an
/// authority for them.
public struct GroupPeerRouteSetCacheV2: Codable, Equatable {
    public static let version = 2
    public static let maximumEntries = 128

    public let version: Int
    public let entries: [CachedGroupRouteSetV2]

    public static let empty = GroupPeerRouteSetCacheV2(uncheckedEntries: [])

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case entries
    }

    private init(uncheckedEntries: [CachedGroupRouteSetV2]) {
        version = Self.version
        entries = uncheckedEntries
    }

    public init(entries: [CachedGroupRouteSetV2] = []) throws {
        self.init(uncheckedEntries: entries.sorted(by: Self.entryOrdering))
        guard isStructurallyValid else {
            throw GroupRouteSetAnnouncementV2Error.invalidAnnouncement
        }
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupRouteAnnouncementKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let decodedVersion = try values.decode(Int.self, forKey: .version)
        let decodedEntries = try values.decode([CachedGroupRouteSetV2].self, forKey: .entries)
        self.init(uncheckedEntries: decodedEntries)
        guard decodedVersion == version,
              isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .entries,
                in: values,
                debugDescription: "Invalid group route cache"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid route cache")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(entries, forKey: .entries)
    }

    public var isStructurallyValid: Bool {
        version == Self.version
            && entries.count <= Self.maximumEntries
            && entries == entries.sorted(by: Self.entryOrdering)
            && Set(entries.map(\.id)).count == entries.count
            && entries.allSatisfy(\.isStructurallyValid)
    }

    public func validated(
        against state: SignedGroupStateV2,
        localCredential: LocalGroupCredentialV2
    ) throws -> Bool {
        guard isStructurallyValid,
              state.groupId == localCredential.groupId else {
            return false
        }
        for entry in entries {
            guard entry.id != localCredential.credentialHandle else {
                return false
            }
            _ = try entry.announcement.verified(
                against: state,
                observedAt: entry.observedAt
            )
        }
        return true
    }

    public func accepting(
        _ announcement: SignedGroupRouteSetAnnouncementV2,
        state: SignedGroupStateV2,
        localCredential: LocalGroupCredentialV2,
        observedAt: Date
    ) throws -> Self {
        _ = try announcement.verified(against: state, observedAt: observedAt)
        let handle = announcement.routeSet.ownerCredentialHandle
        guard handle != localCredential.credentialHandle else {
            throw GroupRouteSetAnnouncementV2Error.invalidAnnouncement
        }
        var updated = entries
        if let index = updated.firstIndex(where: { $0.id == handle }) {
            let prior = updated[index].announcement
            if prior.routeSet == announcement.routeSet { return self }
            let signingKey = try requiredSigningKey(for: handle, state: state)
            let isDirectSuccessor = prior.routeSet.revision < UInt64.max
                && announcement.routeSet.revision == prior.routeSet.revision + 1
            let isAcceptedCheckpoint: Bool
            if isDirectSuccessor {
                isAcceptedCheckpoint = try announcement.routeSet.isValidSuccessorThrowing(
                    of: prior.routeSet,
                    ownerSigningPublicKey: signingKey
                )
            } else {
                // A credential signature authorizes an absolute monotonic
                // checkpoint when one or more expiring revisions were missed.
                // Same/older revisions remain invalid, and a direct revision
                // must still prove its hash-chain predecessor.
                let isNewerCheckpoint = announcement.routeSet.revision
                    > prior.routeSet.revision
                    && announcement.routeSet.issuedAt >= prior.routeSet.issuedAt
                isAcceptedCheckpoint = isNewerCheckpoint
                    ? try announcement.routeSet.verifyThrowing(
                        ownerSigningPublicKey: signingKey
                    )
                    : false
            }
            guard isAcceptedCheckpoint else {
                throw GroupRouteSetAnnouncementV2Error.invalidSuccessor
            }
            updated[index] = CachedGroupRouteSetV2(
                announcement: announcement,
                observedAt: observedAt
            )
        } else {
            guard updated.count < Self.maximumEntries else {
                throw GroupRouteSetAnnouncementV2Error.invalidAnnouncement
            }
            updated.append(CachedGroupRouteSetV2(
                announcement: announcement,
                observedAt: observedAt
            ))
        }
        let result = try Self(entries: updated)
        guard try result.validated(against: state, localCredential: localCredential) else {
            throw GroupRouteSetAnnouncementV2Error.invalidAnnouncement
        }
        return result
    }

    public func pruning(
        to state: SignedGroupStateV2,
        localCredential: LocalGroupCredentialV2
    ) throws -> Self {
        let active = Set(state.activeCredentials.map(\.credentialHandle))
        let retained = entries.filter {
            active.contains($0.id) && $0.id != localCredential.credentialHandle
        }
        let result = try Self(entries: retained)
        guard try result.validated(against: state, localCredential: localCredential) else {
            throw GroupRouteSetAnnouncementV2Error.invalidAnnouncement
        }
        return result
    }

    public func routeSets(
        for credentials: [GroupMemberCredentialV2],
        at date: Date
    ) throws -> [SignedGroupOpaqueRouteSetV2] {
        guard date.timeIntervalSince1970.isFinite else {
            throw GroupRouteSetAnnouncementV2Error.invalidAnnouncement
        }
        return try credentials.map { credential in
            guard let entry = entries.first(where: { $0.id == credential.credentialHandle }),
                  entry.announcement.routeSet.ownerAdmissionDigest
                    == credential.admissionDigest,
                  !entry.announcement.routeSet.usableRoutes(at: date).isEmpty else {
                throw GroupRouteSetAnnouncementV2Error.routeSetMissing
            }
            return entry.announcement.routeSet
        }
    }

    private func requiredSigningKey(
        for handle: GroupScopedCredentialHandleV2,
        state: SignedGroupStateV2
    ) throws -> Data {
        guard let key = state.activeCredentials.first(where: {
            $0.credentialHandle == handle
        })?.signingPublicKey else {
            throw GroupRouteSetAnnouncementV2Error.invalidAnnouncement
        }
        return key
    }

    private static func entryOrdering(
        _ lhs: CachedGroupRouteSetV2,
        _ rhs: CachedGroupRouteSetV2
    ) -> Bool {
        lhs.id.rawValue < rhs.id.rawValue
    }
}

extension NoctweavePQGroupRuntimeV2 {
    public func peerRouteCacheSnapshot() -> GroupPeerRouteSetCacheV2 {
        record.peerRouteCache
    }

    /// Verifies and saves one encrypted group-control announcement before its
    /// relay page can be committed. Exact replay is idempotent; a skipped or
    /// forked revision is rejected.
    public func acceptPeerRouteSetAnnouncement(
        _ announcement: SignedGroupRouteSetAnnouncementV2,
        observedAt: Date = Date()
    ) async throws {
        try requireActiveRuntime()
        let updated = try record.peerRouteCache.accepting(
            announcement,
            state: record.signedState,
            localCredential: record.localCredential,
            observedAt: observedAt
        )
        if updated == record.peerRouteCache { return }
        try await persist(record.replacing(peerRouteCache: updated))
    }

    /// Resolves exact routes for every remote credential in `state`. Current
    /// members come only from the authenticated cache. Explicit additions are
    /// accepted solely for credentials not yet present in that cache (the
    /// invitation bootstrap case).
    public func routeSetsForTransport(
        state targetState: SignedGroupStateV2? = nil,
        additionalRouteSets: [SignedGroupOpaqueRouteSetV2] = [],
        at date: Date = Date()
    ) throws -> [SignedGroupOpaqueRouteSetV2] {
        let target = targetState ?? record.signedState
        guard target.groupId == record.groupId,
              date.timeIntervalSince1970.isFinite,
              Set(additionalRouteSets.map(\.ownerCredentialHandle)).count
                == additionalRouteSets.count else {
            throw GroupRouteSetAnnouncementV2Error.invalidAnnouncement
        }
        let required = target.activeCredentials.filter {
            $0.memberHandle != record.localCredential.memberHandle
        }
        var selected = Dictionary(uniqueKeysWithValues: record.peerRouteCache.entries.map {
            ($0.id, $0.announcement.routeSet)
        })
        for routeSet in additionalRouteSets {
            guard selected[routeSet.ownerCredentialHandle] == nil,
                  let credential = required.first(where: {
                      $0.credentialHandle == routeSet.ownerCredentialHandle
                  }),
                  routeSet.groupID == record.groupId,
                  routeSet.ownerAdmissionDigest == credential.admissionDigest,
                  try routeSet.verifyThrowing(
                      ownerSigningPublicKey: credential.signingPublicKey
                  ),
                  !routeSet.usableRoutes(at: date).isEmpty else {
                throw GroupRouteSetAnnouncementV2Error.invalidAnnouncement
            }
            selected[routeSet.ownerCredentialHandle] = routeSet
        }
        return try required.map { credential in
            guard let routeSet = selected[credential.credentialHandle],
                  routeSet.ownerAdmissionDigest == credential.admissionDigest,
                  try routeSet.verifyThrowing(
                      ownerSigningPublicKey: credential.signingPublicKey
                  ),
                  !routeSet.usableRoutes(at: date).isEmpty else {
                throw GroupRouteSetAnnouncementV2Error.routeSetMissing
            }
            return routeSet
        }
    }
}
