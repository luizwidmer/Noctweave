import Foundation

public enum PendingGroupAdmissionV2Error: Error, Equatable {
    case invalidState
    case conflictingArtifact
    case anchorRequired
    case routeAlreadyActivated
    case admissionIncomplete
}

private struct PendingGroupAdmissionCodingKey: CodingKey {
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

/// A local, one-use group admission journal. Every key and route capability in
/// this value is scoped only to `groupID`; it is not an account, persona
/// authority, device record, or reusable identity. The admission projection
/// and signed route set are the only public artifacts.
public struct PendingGroupAdmissionV2: Codable, Equatable, Identifiable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let version = 2

    public let version: Int
    public let id: UUID
    public let groupID: UUID
    public let invitationBindingDigest: Data
    public let localCredential: LocalGroupCredentialV2
    public let admission: GroupCredentialAdmissionV2
    public let pendingRoute: PendingLocalOpaqueReceiveRouteV2?
    public let activeRoute: GroupLocalOpaqueReceiveRouteV2?
    public let advertisedRouteSet: SignedGroupOpaqueRouteSetV2?
    public let anchor: GroupJoinAnchorV2?
    public let anchorPinnedAt: Date?
    public let peerRouteCache: GroupPeerRouteSetCacheV2
    public let transition: GroupEpochTransitionEnvelopeV2?
    public let transitionObservedAt: Date?
    public let welcome: SignedGroupWelcomeV2?
    public let welcomeObservedAt: Date?
    public let createdAt: Date
    public let updatedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case groupID
        case invitationBindingDigest
        case localCredential
        case admission
        case pendingRoute
        case activeRoute
        case advertisedRouteSet
        case anchor
        case anchorPinnedAt
        case peerRouteCache
        case transition
        case transitionObservedAt
        case welcome
        case welcomeObservedAt
        case createdAt
        case updatedAt
    }

    private init(
        version: Int = Self.version,
        id: UUID,
        groupID: UUID,
        invitationBindingDigest: Data,
        localCredential: LocalGroupCredentialV2,
        admission: GroupCredentialAdmissionV2,
        pendingRoute: PendingLocalOpaqueReceiveRouteV2?,
        activeRoute: GroupLocalOpaqueReceiveRouteV2?,
        advertisedRouteSet: SignedGroupOpaqueRouteSetV2?,
        anchor: GroupJoinAnchorV2?,
        anchorPinnedAt: Date?,
        peerRouteCache: GroupPeerRouteSetCacheV2,
        transition: GroupEpochTransitionEnvelopeV2?,
        transitionObservedAt: Date?,
        welcome: SignedGroupWelcomeV2?,
        welcomeObservedAt: Date?,
        createdAt: Date,
        updatedAt: Date
    ) {
        self.version = version
        self.id = id
        self.groupID = groupID
        self.invitationBindingDigest = invitationBindingDigest
        self.localCredential = localCredential
        self.admission = admission
        self.pendingRoute = pendingRoute
        self.activeRoute = activeRoute
        self.advertisedRouteSet = advertisedRouteSet
        self.anchor = anchor
        self.anchorPinnedAt = anchorPinnedAt
        self.peerRouteCache = peerRouteCache
        self.transition = transition
        self.transitionObservedAt = transitionObservedAt
        self.welcome = welcome
        self.welcomeObservedAt = welcomeObservedAt
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    public static func prepare(
        id: UUID = UUID(),
        groupID: UUID,
        invitationBindingDigest: Data,
        relay: RelayEndpoint,
        policy: OpaqueRoutePolicyV2 = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .sixHours,
            quotaBucket: .packets256
        ),
        expiresAt: Date,
        createdAt: Date = Date()
    ) throws -> PendingGroupAdmissionV2 {
        guard invitationBindingDigest.count == 32,
              createdAt.timeIntervalSince1970.isFinite,
              expiresAt.timeIntervalSince1970.isFinite,
              createdAt < expiresAt else {
            throw PendingGroupAdmissionV2Error.invalidState
        }
        let memberHandle = GroupScopedMemberHandleV2.generate()
        let signingKey = try SigningKeyPair.generate()
        let agreementKey = try AgreementKeyPair.generate()
        let admission = try GroupCredentialAdmissionV2.create(
            groupId: groupID,
            memberHandle: memberHandle,
            groupSigningKey: signingKey,
            groupAgreementKey: agreementKey,
            issuedAt: createdAt,
            expiresAt: expiresAt
        )
        guard let admissionDigest = admission.digest else {
            throw PendingGroupAdmissionV2Error.invalidState
        }
        let localCredential = LocalGroupCredentialV2(
            groupId: groupID,
            memberHandle: memberHandle,
            credentialHandle: admission.credentialHandle,
            admissionDigest: admissionDigest,
            signingKey: signingKey,
            agreementKey: agreementKey
        )
        let pendingRoute = try PendingLocalOpaqueReceiveRouteV2.prepare(
            relay: relay,
            policy: policy,
            createdAt: createdAt
        )
        let result = Self(
            id: id,
            groupID: groupID,
            invitationBindingDigest: invitationBindingDigest,
            localCredential: localCredential,
            admission: admission,
            pendingRoute: pendingRoute,
            activeRoute: nil,
            advertisedRouteSet: nil,
            anchor: nil,
            anchorPinnedAt: nil,
            peerRouteCache: .empty,
            transition: nil,
            transitionObservedAt: nil,
            welcome: nil,
            welcomeObservedAt: nil,
            createdAt: createdAt,
            updatedAt: createdAt
        )
        guard try result.isStructurallyValidThrowing else {
            throw PendingGroupAdmissionV2Error.invalidState
        }
        return result
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PendingGroupAdmissionCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Pending group admission fields must match exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            id: try values.decode(UUID.self, forKey: .id),
            groupID: try values.decode(UUID.self, forKey: .groupID),
            invitationBindingDigest: try values.decode(
                Data.self,
                forKey: .invitationBindingDigest
            ),
            localCredential: try values.decode(
                LocalGroupCredentialV2.self,
                forKey: .localCredential
            ),
            admission: try values.decode(GroupCredentialAdmissionV2.self, forKey: .admission),
            pendingRoute: try values.decodeIfPresent(
                PendingLocalOpaqueReceiveRouteV2.self,
                forKey: .pendingRoute
            ),
            activeRoute: try values.decodeIfPresent(
                GroupLocalOpaqueReceiveRouteV2.self,
                forKey: .activeRoute
            ),
            advertisedRouteSet: try values.decodeIfPresent(
                SignedGroupOpaqueRouteSetV2.self,
                forKey: .advertisedRouteSet
            ),
            anchor: try values.decodeIfPresent(GroupJoinAnchorV2.self, forKey: .anchor),
            anchorPinnedAt: try values.decodeIfPresent(Date.self, forKey: .anchorPinnedAt),
            peerRouteCache: try values.decode(
                GroupPeerRouteSetCacheV2.self,
                forKey: .peerRouteCache
            ),
            transition: try values.decodeIfPresent(
                GroupEpochTransitionEnvelopeV2.self,
                forKey: .transition
            ),
            transitionObservedAt: try values.decodeIfPresent(
                Date.self,
                forKey: .transitionObservedAt
            ),
            welcome: try values.decodeIfPresent(SignedGroupWelcomeV2.self, forKey: .welcome),
            welcomeObservedAt: try values.decodeIfPresent(
                Date.self,
                forKey: .welcomeObservedAt
            ),
            createdAt: try values.decode(Date.self, forKey: .createdAt),
            updatedAt: try values.decode(Date.self, forKey: .updatedAt)
        )
        guard try isStructurallyValidThrowing else {
            throw DecodingError.dataCorruptedError(
                forKey: .localCredential,
                in: values,
                debugDescription: "Pending group admission is invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid group admission")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(id, forKey: .id)
        try values.encode(groupID, forKey: .groupID)
        try values.encode(invitationBindingDigest, forKey: .invitationBindingDigest)
        try values.encode(localCredential, forKey: .localCredential)
        try values.encode(admission, forKey: .admission)
        try values.encode(pendingRoute, forKey: .pendingRoute)
        try values.encode(activeRoute, forKey: .activeRoute)
        try values.encode(advertisedRouteSet, forKey: .advertisedRouteSet)
        try values.encode(anchor, forKey: .anchor)
        try values.encode(anchorPinnedAt, forKey: .anchorPinnedAt)
        try values.encode(peerRouteCache, forKey: .peerRouteCache)
        try values.encode(transition, forKey: .transition)
        try values.encode(transitionObservedAt, forKey: .transitionObservedAt)
        try values.encode(welcome, forKey: .welcome)
        try values.encode(welcomeObservedAt, forKey: .welcomeObservedAt)
        try values.encode(createdAt, forKey: .createdAt)
        try values.encode(updatedAt, forKey: .updatedAt)
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard version == Self.version,
                  invitationBindingDigest.count == 32,
                  try localCredential.isStructurallyValidThrowing,
                  admission.isStructurallyValid,
                  groupID == localCredential.groupId,
                  groupID == admission.groupId,
                  admission.memberHandle == localCredential.memberHandle,
                  admission.credentialHandle == localCredential.credentialHandle,
                  admission.groupSigningPublicKey == localCredential.signingKey.publicKeyData,
                  admission.groupAgreementPublicKey == localCredential.agreementKey.publicKeyData,
                  admission.digest == localCredential.admissionDigest,
                  createdAt == admission.issuedAt,
                  createdAt.timeIntervalSince1970.isFinite,
                  updatedAt.timeIntervalSince1970.isFinite,
                  updatedAt >= createdAt,
                  try admission.verified(
                      forGroupId: groupID,
                      memberHandle: localCredential.memberHandle,
                      selection: .currentExperimental,
                      now: createdAt
                  ) == admission,
                  (pendingRoute == nil) != (activeRoute == nil),
                  (activeRoute == nil) == (advertisedRouteSet == nil),
                  pendingRoute?.isStructurallyValid != false,
                  activeRoute?.isStructurallyValid != false,
                  try routeProjectionIsValid(),
                  (anchor == nil) == (anchorPinnedAt == nil),
                  (transition == nil) == (transitionObservedAt == nil),
                  (welcome == nil) == (welcomeObservedAt == nil),
                  transition == nil || anchor != nil,
                  welcome == nil || anchor != nil,
                  (try anchor.map {
                      try peerRouteCache.validated(
                          against: $0.baseState,
                          localCredential: localCredential
                      )
                  } ?? peerRouteCache.entries.isEmpty),
                  try pinnedAnchorIsValid(),
                  try stagedTransitionIsValid(),
                  try stagedWelcomeIsValid() else {
                return false
            }
            return true
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    public var isReadyToJoin: Bool {
        activeRoute != nil
            && advertisedRouteSet != nil
            && anchor != nil
            && transition != nil
            && welcome != nil
            && peerRoutesReady
            && completionObservedAt != nil
    }

    public var completionObservedAt: Date? {
        guard let anchorPinnedAt,
              let transitionObservedAt,
              let welcomeObservedAt,
              let activatedAt = activeRoute?.activatedAt else {
            return nil
        }
        return max(max(anchorPinnedAt, transitionObservedAt), max(welcomeObservedAt, activatedAt))
    }

    public var peerRoutesReady: Bool {
        guard let transition, let observedAt = completionObservedAt else {
            return false
        }
        let remote = transition.nextState.activeCredentials.filter {
            $0.memberHandle != localCredential.memberHandle
        }
        return (try? peerRouteCache.routeSets(for: remote, at: observedAt)) != nil
    }

    public func activatingRoute(
        _ createdRoute: OpaqueReceiveRouteV2,
        at date: Date
    ) throws -> Self {
        if let activeRoute {
            guard activeRoute.localRoute.route == createdRoute else {
                throw PendingGroupAdmissionV2Error.routeAlreadyActivated
            }
            return self
        }
        guard let pendingRoute,
              date.timeIntervalSince1970.isFinite else {
            throw PendingGroupAdmissionV2Error.invalidState
        }
        let localRoute = try pendingRoute.activate(createdRoute: createdRoute)
        let active = try GroupLocalOpaqueReceiveRouteV2(
            localRoute: localRoute,
            advertisedState: .active,
            activatedAt: date
        )
        let advertised = try active.advertisedSendRoute()
        let routeSet = try SignedGroupOpaqueRouteSetV2.create(
            groupID: groupID,
            ownerCredentialHandle: localCredential.credentialHandle,
            ownerAdmissionDigest: localCredential.admissionDigest,
            routes: [advertised],
            issuedAt: date,
            expiresAt: advertised.expiresAt,
            signingKey: localCredential.signingKey
        )
        let result = replacing(
            pendingRoute: .some(nil),
            activeRoute: .some(active),
            advertisedRouteSet: .some(routeSet),
            updatedAt: date
        )
        guard try result.isStructurallyValidThrowing else {
            throw PendingGroupAdmissionV2Error.invalidState
        }
        return result
    }

    public func pinning(
        anchor: GroupJoinAnchorV2,
        invitationBindingDigest: Data,
        observedAt: Date
    ) throws -> Self {
        guard invitationBindingDigest == self.invitationBindingDigest,
              observedAt.timeIntervalSince1970.isFinite else {
            throw PendingGroupAdmissionV2Error.invalidState
        }
        if let existing = self.anchor {
            guard existing == anchor else {
                throw PendingGroupAdmissionV2Error.conflictingArtifact
            }
            return self
        }
        let result = replacing(
            anchor: .some(anchor),
            anchorPinnedAt: .some(observedAt),
            updatedAt: observedAt
        )
        guard try result.isStructurallyValidThrowing else {
            throw PendingGroupAdmissionV2Error.invalidState
        }
        return result
    }

    public func staging(
        transition: GroupEpochTransitionEnvelopeV2,
        observedAt: Date
    ) throws -> Self {
        guard anchor != nil else { throw PendingGroupAdmissionV2Error.anchorRequired }
        if let existing = self.transition {
            guard existing == transition else {
                throw PendingGroupAdmissionV2Error.conflictingArtifact
            }
            return self
        }
        let result = replacing(
            transition: .some(transition),
            transitionObservedAt: .some(observedAt),
            updatedAt: observedAt
        )
        guard try result.isStructurallyValidThrowing else {
            throw PendingGroupAdmissionV2Error.invalidState
        }
        return result
    }

    public func staging(
        welcome: SignedGroupWelcomeV2,
        observedAt: Date
    ) throws -> Self {
        guard anchor != nil else { throw PendingGroupAdmissionV2Error.anchorRequired }
        if let existing = self.welcome {
            guard existing == welcome else {
                throw PendingGroupAdmissionV2Error.conflictingArtifact
            }
            return self
        }
        let result = replacing(
            welcome: .some(welcome),
            welcomeObservedAt: .some(observedAt),
            updatedAt: observedAt
        )
        guard try result.isStructurallyValidThrowing else {
            throw PendingGroupAdmissionV2Error.invalidState
        }
        return result
    }

    public func staging(
        routeAnnouncement: SignedGroupRouteSetAnnouncementV2,
        observedAt: Date
    ) throws -> Self {
        guard let anchor else { throw PendingGroupAdmissionV2Error.anchorRequired }
        let updated = try peerRouteCache.accepting(
            routeAnnouncement,
            state: anchor.baseState,
            localCredential: localCredential,
            observedAt: observedAt
        )
        if updated == peerRouteCache { return self }
        let result = replacing(
            peerRouteCache: updated,
            updatedAt: observedAt
        )
        guard try result.isStructurallyValidThrowing else {
            throw PendingGroupAdmissionV2Error.invalidState
        }
        return result
    }

    public func inboundTransportState(
        announcement: SignedGroupRouteSetAnnouncementV2,
        pendingAnnouncementID: UUID?
    ) throws -> GroupOpaqueRouteInboundStateV2 {
        guard let activeRoute, let advertisedRouteSet else {
            throw PendingGroupAdmissionV2Error.admissionIncomplete
        }
        guard announcement.routeSet == advertisedRouteSet,
              pendingAnnouncementID == nil || pendingAnnouncementID == announcement.id else {
            throw PendingGroupAdmissionV2Error.invalidState
        }
        let result = GroupOpaqueRouteInboundStateV2(
            localRoutes: [activeRoute],
            advertisedRouteSet: advertisedRouteSet,
            advertisedRouteAnnouncement: announcement,
            pendingRouteAnnouncementID: pendingAnnouncementID,
            routeSetOwnerSigningPublicKey: localCredential.signingKey.publicKeyData
        )
        guard result.isStructurallyValid else {
            throw PendingGroupAdmissionV2Error.invalidState
        }
        return result
    }

    private func replacing(
        pendingRoute: PendingLocalOpaqueReceiveRouteV2?? = nil,
        activeRoute: GroupLocalOpaqueReceiveRouteV2?? = nil,
        advertisedRouteSet: SignedGroupOpaqueRouteSetV2?? = nil,
        anchor: GroupJoinAnchorV2?? = nil,
        anchorPinnedAt: Date?? = nil,
        peerRouteCache: GroupPeerRouteSetCacheV2? = nil,
        transition: GroupEpochTransitionEnvelopeV2?? = nil,
        transitionObservedAt: Date?? = nil,
        welcome: SignedGroupWelcomeV2?? = nil,
        welcomeObservedAt: Date?? = nil,
        updatedAt: Date? = nil
    ) -> Self {
        Self(
            version: version,
            id: id,
            groupID: groupID,
            invitationBindingDigest: invitationBindingDigest,
            localCredential: localCredential,
            admission: admission,
            pendingRoute: pendingRoute ?? self.pendingRoute,
            activeRoute: activeRoute ?? self.activeRoute,
            advertisedRouteSet: advertisedRouteSet ?? self.advertisedRouteSet,
            anchor: anchor ?? self.anchor,
            anchorPinnedAt: anchorPinnedAt ?? self.anchorPinnedAt,
            peerRouteCache: peerRouteCache ?? self.peerRouteCache,
            transition: transition ?? self.transition,
            transitionObservedAt: transitionObservedAt ?? self.transitionObservedAt,
            welcome: welcome ?? self.welcome,
            welcomeObservedAt: welcomeObservedAt ?? self.welcomeObservedAt,
            createdAt: createdAt,
            updatedAt: max(self.updatedAt, updatedAt ?? self.updatedAt)
        )
    }

    private func routeProjectionIsValid() throws -> Bool {
        if let pendingRoute {
            return pendingRoute.createdAt == createdAt
        }
        guard let activeRoute, let advertisedRouteSet else { return false }
        let advertisedRoute = try activeRoute.advertisedSendRoute()
        return activeRoute.localRoute.route.routeID
                == activeRoute.localRoute.clientCapabilities.routeID
            && advertisedRouteSet.groupID == groupID
            && advertisedRouteSet.ownerCredentialHandle == localCredential.credentialHandle
            && advertisedRouteSet.ownerAdmissionDigest == localCredential.admissionDigest
            && advertisedRouteSet.routes == [advertisedRoute]
            && advertisedRouteSet.verify(
                ownerSigningPublicKey: localCredential.signingKey.publicKeyData
            )
    }

    private func pinnedAnchorIsValid() throws -> Bool {
        guard let anchor else { return true }
        guard let anchorPinnedAt,
              anchor.baseState.groupId == groupID,
              anchor.destinationMemberHandle == localCredential.memberHandle,
              anchor.destinationCredentialHandle == localCredential.credentialHandle,
              anchor.destinationAdmissionDigest == localCredential.admissionDigest,
              createdAt <= anchorPinnedAt,
              anchor.issuedAt <= anchorPinnedAt.addingTimeInterval(
                  NoctweaveSignedGroupV2.maximumClockSkewSeconds
              ),
              anchorPinnedAt < anchor.expiresAt,
              anchor.expiresAt <= admission.expiresAt else {
            return false
        }
        return true
    }

    private func stagedTransitionIsValid() throws -> Bool {
        guard let transition else { return true }
        guard let anchor, let transitionObservedAt,
              transition.commit.groupId == groupID,
              transition.commit.baseEpoch == anchor.baseState.epoch,
              transitionObservedAt >= createdAt else {
            return false
        }
        _ = try transition.commit.verifiedTransition(
            from: anchor.baseState,
            observedAt: transitionObservedAt
        )
        _ = try transition.nextState.verified(
            previousState: anchor.baseState,
            commit: transition.commit,
            observedAt: transitionObservedAt
        )
        guard let leaf = transition.nextState.activeCredentials.first(where: {
            $0.memberHandle == localCredential.memberHandle
                && $0.credentialHandle == localCredential.credentialHandle
        }) else { return false }
        return leaf.admissionDigest == localCredential.admissionDigest
            && leaf.signingPublicKey == localCredential.signingKey.publicKeyData
            && leaf.agreementPublicKey == localCredential.agreementKey.publicKeyData
    }

    private func stagedWelcomeIsValid() throws -> Bool {
        guard let welcome else { return true }
        guard let anchor, let welcomeObservedAt,
              welcome.isStructurallyValid,
              welcome.groupId == groupID,
              welcome.destinationCredentialHandle == localCredential.credentialHandle,
              welcome.destinationAdmissionDigest == localCredential.admissionDigest,
              welcomeObservedAt >= createdAt,
              anchor.baseState.epoch < UInt64.max,
              welcome.epoch == anchor.baseState.epoch + 1 else {
            return false
        }
        if let transition {
            let observedAt = max(
                transitionObservedAt ?? welcomeObservedAt,
                welcomeObservedAt
            )
            _ = try welcome.verified(against: transition.nextState, now: observedAt)
        }
        return true
    }

    public var description: String { "PendingGroupAdmissionV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

public struct HeadlessGroupAdmissionPreparationV2: Codable, Equatable {
    public let admissionID: UUID
    public let groupID: UUID
    public let admission: GroupCredentialAdmissionV2
    public let routeID: OpaqueReceiveRouteIDV2
}

public struct HeadlessGroupAdmissionRouteResultV2: Codable, Equatable {
    public let admissionID: UUID
    public let groupID: UUID
    public let admission: GroupCredentialAdmissionV2
    public let routeSet: SignedGroupOpaqueRouteSetV2
    public let completed: Bool
}

public struct HeadlessGroupAdmissionProgressV2: Codable, Equatable {
    public let admissionID: UUID
    public let groupID: UUID
    public let routeReady: Bool
    public let anchorPinned: Bool
    public let peerRoutesReady: Bool
    public let transitionStaged: Bool
    public let welcomeStaged: Bool
    public let completed: Bool

    public init(_ admission: PendingGroupAdmissionV2, completed: Bool = false) {
        admissionID = admission.id
        groupID = admission.groupID
        routeReady = admission.activeRoute != nil
        anchorPinned = admission.anchor != nil
        peerRoutesReady = admission.peerRoutesReady
        transitionStaged = admission.transition != nil
        welcomeStaged = admission.welcome != nil
        self.completed = completed
    }
}

actor VolatileGroupJoinPersistenceV2: GroupRuntimeRecordPersistence {
    private var record: GroupRuntimeRecord?

    func load() -> GroupRuntimeRecord? { record }
    func save(_ record: GroupRuntimeRecord) { self.record = record }
}
