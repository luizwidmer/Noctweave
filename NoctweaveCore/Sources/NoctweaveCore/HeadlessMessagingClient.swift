import CryptoKit
import Foundation

public enum HeadlessMessagingClientError: Error, Equatable {
    case invalidState
    case relationshipNotFound
    case relayRejected
    case invalidRelayResponse
    case noUsableRoute
    case conflictingEnvelope
    case invalidControl
    case incompleteBundle
    case continuityNotAllowed
    case routeGapDetected
    case unsupportedContentType
    case relationshipConsentRequired
    case relationshipBlocked
    case receiptDisabled
    case staleGroupRuntime
    case groupAdmissionNotFound
}

public struct HeadlessSendResult: Codable, Equatable {
    public let event: ConversationEvent
    public let envelope: DirectEnvelopeV4
    public let acceptedDeliveryCount: Int
    public let pendingDeliveryCount: Int
    public let failedDeliveryCount: Int
    public let nextRetryNotBefore: Date?
}

/// A logical event and its exact encrypted outbox artifacts after durable
/// local persistence but before any relay I/O. UI local echo should use this
/// result and reconcile later publication by `event.id`/transaction ID.
public struct HeadlessPreparedSend: Codable, Equatable {
    public let relationshipID: UUID
    public let event: ConversationEvent
    public let envelope: DirectEnvelopeV4
    public let deliveryIDs: [UUID]

    public init(
        relationshipID: UUID,
        event: ConversationEvent,
        envelope: DirectEnvelopeV4,
        deliveryIDs: [UUID]
    ) {
        self.relationshipID = relationshipID
        self.event = event
        self.envelope = envelope
        self.deliveryIDs = deliveryIDs
    }
}

public struct HeadlessPublicationResult: Codable, Equatable {
    public let relationshipID: UUID
    public let eventID: UUID
    public let acceptedDeliveryCount: Int
    public let pendingDeliveryCount: Int
    public let failedDeliveryCount: Int
    public let nextRetryNotBefore: Date?
}

public struct HeadlessRouteRolloverResult: Codable, Equatable {
    public let relationshipID: UUID
    public let routeID: OpaqueReceiveRouteIDV2
    public let state: ProtocolIntentStateV2
    public let routeSetPublication: HeadlessPublicationResult?
}

/// Current maintenance outcome for one unlinkable relationship endpoint.
/// This is local operational state only; it is never placed on the wire.
public enum HeadlessRouteMaintenanceDispositionV2: String, Codable, Equatable {
    case healthy
    case rolloverInProgress
    case rolloverStarted
    case rolloverFailed
    case routeExpired
    case noLocalRoute
    case blocked
}

public struct HeadlessRelationshipMaintenanceReportV2: Codable, Equatable {
    public let relationshipID: UUID
    public let observedAt: Date
    public let routeDisposition: HeadlessRouteMaintenanceDispositionV2
    public let resumedRollovers: [HeadlessRouteRolloverResult]
    public let startedRollover: HeadlessRouteRolloverResult?
    public let prekeyPublication: HeadlessPublicationResult?
    public let finalizedRouteIDs: [OpaqueReceiveRouteIDV2]

    public var requiresFollowUp: Bool {
        routeDisposition == .rolloverInProgress
            || routeDisposition == .rolloverFailed
            || routeDisposition == .routeExpired
            || routeDisposition == .noLocalRoute
            || resumedRollovers.contains { !$0.state.isTerminal }
            || startedRollover.map { !$0.state.isTerminal } == true
    }
}

public struct HeadlessBlobUploadResult: Codable, Equatable {
    public let relationshipID: UUID
    public let uploadID: UUID
    public let attachmentID: UUID
    public let chunkIndex: Int
    public let state: ProtocolIntentStateV2
    public let accepted: Bool
}

public struct HeadlessSyncResult: Codable, Equatable {
    public let relationshipID: UUID
    public let receivedEvents: [ConversationEvent]
    public let committedCursor: OpaqueRouteCursorV2?
    public let hasMore: Bool
}

/// Durable local preparation of one group application event. When
/// `transportOperation` is non-nil its exact route packets have already been
/// saved and may be resumed byte-for-byte after a process restart.
public struct HeadlessPreparedGroupApplicationV2: Codable, Equatable {
    public let groupID: UUID
    public let event: GroupConversationEventV2
    public let envelope: GroupApplicationEnvelopeV2
    public let transportOperation: GroupOpaqueRouteOutboundOperationV2?
    public let complete: Bool

    public init(
        groupID: UUID,
        event: GroupConversationEventV2,
        envelope: GroupApplicationEnvelopeV2,
        transportOperation: GroupOpaqueRouteOutboundOperationV2?,
        complete: Bool
    ) {
        self.groupID = groupID
        self.event = event
        self.envelope = envelope
        self.transportOperation = transportOperation
        self.complete = complete
    }
}

/// Durable local preparation of a group epoch transition and its Welcomes.
/// Group authority remains group-scoped; this contains no account, persona,
/// device, installation, or globally reusable endpoint identity.
public struct HeadlessPreparedGroupEpochV2: Codable, Equatable {
    public let groupID: UUID
    public let publication: GroupEpochPublication
    public let transportOperation: GroupOpaqueRouteOutboundOperationV2?
    public let complete: Bool

    public init(
        groupID: UUID,
        publication: GroupEpochPublication,
        transportOperation: GroupOpaqueRouteOutboundOperationV2?,
        complete: Bool
    ) {
        self.groupID = groupID
        self.publication = publication
        self.transportOperation = transportOperation
        self.complete = complete
    }
}

public struct HeadlessPreparedGroupDeletionV2: Codable, Equatable {
    public let groupID: UUID
    public let tombstone: SignedGroupDeletionTombstoneV2
    public let transportOperation: GroupOpaqueRouteOutboundOperationV2?
    public let complete: Bool

    public init(
        groupID: UUID,
        tombstone: SignedGroupDeletionTombstoneV2,
        transportOperation: GroupOpaqueRouteOutboundOperationV2?,
        complete: Bool
    ) {
        self.groupID = groupID
        self.tombstone = tombstone
        self.transportOperation = transportOperation
        self.complete = complete
    }
}

/// Why a durable group transport operation stopped. Exact packets remain in
/// the encrypted client state for every non-complete disposition.
public enum HeadlessGroupTransportDispositionV2: String, Codable, Equatable {
    case complete
    case pendingRetry
    case authorizationRecoveryRequired
    case relayRejected
    case invalidRelayResponse
}

public struct HeadlessGroupTransportResumeResultV2: Codable, Equatable {
    public let groupID: UUID
    public let operationID: UUID
    public let logicalID: UUID
    public let kind: GroupOpaqueRouteOutboundOperationKindV2
    public let acceptedCredentialHandles: [GroupScopedCredentialHandleV2]
    public let attemptedPublicationCount: Int
    public let acceptedPublicationCount: Int
    public let pendingPublicationCount: Int
    public let complete: Bool
    public let disposition: HeadlessGroupTransportDispositionV2

    public init(
        groupID: UUID,
        operationID: UUID,
        logicalID: UUID,
        kind: GroupOpaqueRouteOutboundOperationKindV2,
        acceptedCredentialHandles: [GroupScopedCredentialHandleV2],
        attemptedPublicationCount: Int,
        acceptedPublicationCount: Int,
        pendingPublicationCount: Int,
        complete: Bool,
        disposition: HeadlessGroupTransportDispositionV2
    ) {
        self.groupID = groupID
        self.operationID = operationID
        self.logicalID = logicalID
        self.kind = kind
        self.acceptedCredentialHandles = acceptedCredentialHandles
        self.attemptedPublicationCount = attemptedPublicationCount
        self.acceptedPublicationCount = acceptedPublicationCount
        self.pendingPublicationCount = pendingPublicationCount
        self.complete = complete
        self.disposition = disposition
    }
}

/// Public headless client for the clean 1.0 architecture. A persona is local
/// organization only; all cryptographic state and delivery authority is scoped
/// to a `PairwiseRelationshipV2`.
public actor HeadlessMessagingClient {
    /// Routes are replaced, not renewed. Starting thirty minutes before the
    /// six-hour lease expires leaves time for signed make-before-break route
    /// publication, a peer probe, and the overlap drain window.
    public static let routeReplacementLeadTime: TimeInterval = 30 * 60

    private var state: ClientState
    private let stateStore: ClientStateStore
    private let personaScopeIssuer = UUID()
    private var activeDeliveryIntentIDs = Set<UUID>()
    private var activeBlobIntentIDs = Set<UUID>()
    private var activeRolloverIntentIDs = Set<UUID>()
    private var stateSaveInProgress = false
    private var stateSaveWaiters: [CheckedContinuation<Void, Never>] = []
    private var activeRelationshipTransactions = Set<UUID>()
    private var relationshipTransactionWaiters:
        [UUID: [CheckedContinuation<Void, Never>]] = [:]
    private var activeGroupTransactions = Set<UUID>()
    private var groupTransactionWaiters:
        [UUID: [CheckedContinuation<Void, Never>]] = [:]

    public init(
        stateStore: ClientStateStore,
        initialState: ClientState
    ) throws {
        guard try initialState.isStructurallyValidThrowing else {
            throw HeadlessMessagingClientError.invalidState
        }
        self.stateStore = stateStore
        self.state = initialState
    }

    public static func open(
        stateStore: ClientStateStore,
        displayName: String
    ) async throws -> HeadlessMessagingClient {
        if let existing = try await stateStore.load() {
            return try HeadlessMessagingClient(
                stateStore: stateStore,
                initialState: existing
            )
        }
        let state = try ClientState(displayName: displayName)
        try await stateStore.save(state)
        return try HeadlessMessagingClient(
            stateStore: stateStore,
            initialState: state
        )
    }

    public func snapshot() -> ClientState { state }

    public func activePersona() -> PersonaProfileV1 { state.activePersona }

    /// Mints a process-local guard for relationship or group construction that
    /// may suspend outside this actor. A persona burn invalidates every token
    /// minted for the replaced local persona.
    public func mintActivePersonaScopeToken() -> LocalPersonaScopeToken {
        LocalPersonaScopeToken(
            personaID: state.activePersonaID,
            clientInstanceNonce: personaScopeIssuer
        )
    }

    public func relationship(_ relationshipID: UUID) throws -> PairwiseRelationshipV2 {
        guard let relationship = state.activePersona.relationships.first(where: {
            $0.id == relationshipID
        }) else {
            throw HeadlessMessagingClientError.relationshipNotFound
        }
        return relationship
    }

    public func addRelationship(
        _ relationship: PairwiseRelationshipV2,
        consent: RelationshipConsentStateV2 = .accepted,
        personaScope: LocalPersonaScopeToken
    ) async throws {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationship.id) {
            return try await withRelationshipTransaction(relationship.id) {
                try await self.addRelationship(
                    relationship,
                    consent: consent,
                    personaScope: personaScope
                )
            }
        }
        var relationship = relationship
        relationship.localPolicy.consent = consent
        guard try relationship.isStructurallyValidThrowing else {
            throw HeadlessMessagingClientError.invalidState
        }
        try await withStateSaveLock {
            guard personaScope.clientInstanceNonce == personaScopeIssuer,
                  state.activePersonaID == personaScope.personaID else {
                throw HeadlessMessagingClientError.invalidState
            }
            var candidate = state
            try candidate.updateActivePersona { persona in
                try persona.upsert(relationship: relationship)
            }
            try await stateStore.save(candidate)
            state = candidate
        }
    }

    /// Updates only local presentation/consent policy for one unlinkable
    /// relationship. No control event or relay-visible metadata is emitted.
    public func setRelationshipLocalPolicy(
        _ policy: RelationshipLocalPolicyV2,
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.setRelationshipLocalPolicy(
                    policy,
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        guard policy.isStructurallyValid,
              date.timeIntervalSince1970.isFinite else {
            throw HeadlessMessagingClientError.invalidState
        }
        var relationship = try relationship(relationshipID)
        relationship.localPolicy = policy
        if policy.consent == .blocked {
            // A block severs live receive processing for this relationship.
            // Cursor-committed partial bundles cannot be reconstructed after
            // this point, so discard them before the blocked state is saved.
            for routeIndex in relationship.localReceiveRoutes.indices {
                _ = try relationship.localReceiveRoutes[routeIndex]
                    .updateReassembler { reassembler in
                        reassembler.discardPendingBundles()
                    }
            }
            let abandonedEventIDs = Set(
                relationship.pendingDeliveries.map(\.logicalEventID)
            )
            relationship.pendingDeliveries.removeAll(keepingCapacity: false)
            relationship.deliveryStates.removeAll { state in
                state.state == .locallyPersisted
                    && abandonedEventIDs.contains(state.eventId)
            }
            relationship.pendingRouteRollovers.removeAll(keepingCapacity: false)
            relationship.pendingAttachmentUploads.removeAll(keepingCapacity: false)
            relationship.directSessions.removeAll(keepingCapacity: false)
            for index in relationship.protocolIntents.indices
                where !relationship.protocolIntents[index].state.isTerminal
                    && (relationship.protocolIntents[index].kind == .sendEvent
                        || relationship.protocolIntents[index].kind
                            == .renewRelationshipPrekey
                        || relationship.protocolIntents[index].kind == .rolloverRoute
                        || relationship.protocolIntents[index].kind == .uploadBlob) {
                if let failed = relationship.protocolIntents[index].failingPermanently(
                    errorClass: .authorizationRejected,
                    at: max(date, relationship.protocolIntents[index].updatedAt)
                ) {
                    relationship.protocolIntents[index] = failed
                }
            }
        }
        try await commitRelationship(relationship)
    }

    /// Blocking succeeds locally before any network action. Relay teardown is
    /// best-effort and relationship-scoped; failed routes remain available for
    /// a later retry without re-enabling message processing.
    @discardableResult
    public func blockRelationship(
        _ relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> [OpaqueReceiveRouteIDV2] {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.blockRelationship(relationshipID, at: date)
            }
        }
        var policy = try relationship(relationshipID).localPolicy
        policy.consent = .blocked
        try await setRelationshipLocalPolicy(
            policy,
            relationshipID: relationshipID,
            at: date
        )
        return try await teardownBlockedRelationshipRoutes(
            relationshipID: relationshipID,
            at: date
        )
    }

    public func addGroupRuntime(
        _ record: GroupRuntimeRecord,
        personaScope: LocalPersonaScopeToken
    ) async throws {
        guard try record.isStructurallyValidThrowing else {
            throw HeadlessMessagingClientError.invalidState
        }
        try await withStateSaveLock {
            guard personaScope.clientInstanceNonce == personaScopeIssuer,
                  state.activePersonaID == personaScope.personaID else {
                throw HeadlessMessagingClientError.invalidState
            }
            var candidate = state
            try candidate.updateActivePersona { persona in
                try persona.upsert(groupRuntime: record)
            }
            try await stateStore.save(candidate)
            state = candidate
        }
    }

    /// Opens the group runtime against this client's encrypted state store.
    /// The returned actor remains group-scoped and transport-independent; every
    /// mutation is written back atomically to the active local persona.
    public func openGroupRuntime(
        groupID: UUID
    ) throws -> NoctweavePQGroupRuntimeV2 {
        let originatingPersonaID = state.activePersonaID
        guard let record = state.activePersona.groupRuntimes.first(where: {
            $0.groupId == groupID
        }) else {
            throw HeadlessMessagingClientError.invalidState
        }
        let persistence = HeadlessGroupRuntimePersistence(
            initialRecord: record,
            saveHandler: { [self] expected, updated in
                try await persistGroupRuntime(
                    updated,
                    expectedCurrentRecord: expected,
                    originatingPersonaID: originatingPersonaID
                )
            }
        )
        return try NoctweavePQGroupRuntimeV2(
            record: record,
            persistence: persistence
        )
    }

    /// Generates a fresh, group-only credential and opaque receive-route
    /// create request, then saves both before either public projection can be
    /// published. The invitation binding is local replay-domain evidence and
    /// never becomes an account or device identifier.
    public func prepareGroupAdmission(
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
    ) async throws -> HeadlessGroupAdmissionPreparationV2 {
        if !HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await withGroupTransaction(groupID) {
                try await self.prepareGroupAdmission(
                    groupID: groupID,
                    invitationBindingDigest: invitationBindingDigest,
                    relay: relay,
                    policy: policy,
                    expiresAt: expiresAt,
                    createdAt: createdAt
                )
            }
        }
        guard !state.activePersona.groupRuntimes.contains(where: {
            $0.groupId == groupID
        }), !state.activePersona.pendingGroupAdmissions.contains(where: {
            $0.groupID == groupID
        }) else {
            throw HeadlessMessagingClientError.invalidState
        }
        let originatingPersonaID = state.activePersonaID
        let admission = try PendingGroupAdmissionV2.prepare(
            groupID: groupID,
            invitationBindingDigest: invitationBindingDigest,
            relay: relay,
            policy: policy,
            expiresAt: expiresAt,
            createdAt: createdAt
        )
        try await withStateSaveLock {
            guard state.activePersonaID == originatingPersonaID,
                  !state.activePersona.groupRuntimes.contains(where: {
                      $0.groupId == groupID
                  }), !state.activePersona.pendingGroupAdmissions.contains(where: {
                      $0.groupID == groupID
                  }) else {
                throw HeadlessMessagingClientError.invalidState
            }
            var candidate = state
            try candidate.updateActivePersona { persona in
                try persona.insert(pendingGroupAdmission: admission)
            }
            try await stateStore.save(candidate)
            state = candidate
        }
        return HeadlessGroupAdmissionPreparationV2(
            admissionID: admission.id,
            groupID: admission.groupID,
            admission: admission.admission,
            routeID: try requiredPendingGroupAdmissionRoute(admission).clientCapabilities.routeID
        )
    }

    /// Resumes the exact saved route-create request. The group credential's
    /// public admission and signed route set are the only artifacts intended
    /// for the encrypted invitation channel.
    public func resumeGroupAdmissionRoute(
        admissionID: UUID,
        at date: Date = Date()
    ) async throws -> HeadlessGroupAdmissionRouteResultV2 {
        let groupID = try pendingGroupAdmission(admissionID).groupID
        if !HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await withGroupTransaction(groupID) {
                try await self.resumeGroupAdmissionRoute(admissionID: admissionID, at: date)
            }
        }
        let current = try pendingGroupAdmission(admissionID)
        if let routeSet = current.advertisedRouteSet {
            let progress = try await completePendingGroupAdmissionIfReady(admissionID)
            return HeadlessGroupAdmissionRouteResultV2(
                admissionID: current.id,
                groupID: current.groupID,
                admission: current.admission,
                routeSet: routeSet,
                completed: progress.completed
            )
        }
        let pending = try requiredPendingGroupAdmissionRoute(current)
        let response = try await relayClient(for: pending.relay).send(
            .createOpaqueRouteV2(
                CreateOpaqueRouteRelayRequestV2(
                    request: pending.createRequest,
                    renewCapability: pending.clientCapabilities.renewCapability
                )
            )
        )
        guard case .opaqueRoute(let created)? = response.successBody else {
            throw response.status == .error
                ? HeadlessMessagingClientError.relayRejected
                : HeadlessMessagingClientError.invalidRelayResponse
        }
        let activated = try current.activatingRoute(created, at: date)
        try await persistPendingGroupAdmission(activated, expected: current)
        let progress = try await completePendingGroupAdmissionIfReady(admissionID)
        return HeadlessGroupAdmissionRouteResultV2(
            admissionID: activated.id,
            groupID: activated.groupID,
            admission: activated.admission,
            routeSet: try requiredGroupAdmissionRouteSet(activated),
            completed: progress.completed
        )
    }

    /// Pins the one-use trust anchor received through the invitation channel.
    /// Repeating the exact anchor is idempotent; a different anchor is rejected.
    public func pinGroupJoinAnchor(
        admissionID: UUID,
        anchor: GroupJoinAnchorV2,
        invitationBindingDigest: Data,
        observedAt: Date = Date()
    ) async throws -> HeadlessGroupAdmissionProgressV2 {
        let groupID = try pendingGroupAdmission(admissionID).groupID
        if !HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await withGroupTransaction(groupID) {
                try await self.pinGroupJoinAnchor(
                    admissionID: admissionID,
                    anchor: anchor,
                    invitationBindingDigest: invitationBindingDigest,
                    observedAt: observedAt
                )
            }
        }
        let current = try pendingGroupAdmission(admissionID)
        let pinned = try current.pinning(
            anchor: anchor,
            invitationBindingDigest: invitationBindingDigest,
            observedAt: observedAt
        )
        if pinned != current {
            try await persistPendingGroupAdmission(pinned, expected: current)
        }
        return try await completePendingGroupAdmissionIfReady(admissionID)
    }

    /// Saves and verifies a transition against the pinned base state without
    /// requiring its separately delivered Welcome to have arrived yet.
    public func acceptGroupAdmissionTransition(
        admissionID: UUID,
        transition: GroupEpochTransitionEnvelopeV2,
        observedAt: Date = Date()
    ) async throws -> HeadlessGroupAdmissionProgressV2 {
        let groupID = try pendingGroupAdmission(admissionID).groupID
        if !HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await withGroupTransaction(groupID) {
                try await self.acceptGroupAdmissionTransition(
                    admissionID: admissionID,
                    transition: transition,
                    observedAt: observedAt
                )
            }
        }
        let current = try pendingGroupAdmission(admissionID)
        let staged = try current.staging(transition: transition, observedAt: observedAt)
        if staged != current {
            try await persistPendingGroupAdmission(staged, expected: current)
        }
        return try await completePendingGroupAdmissionIfReady(admissionID)
    }

    /// Saves a destination-bound Welcome independently of transition arrival.
    /// Full state/commit verification runs as soon as both artifacts exist.
    public func acceptGroupAdmissionWelcome(
        admissionID: UUID,
        welcome: SignedGroupWelcomeV2,
        observedAt: Date = Date()
    ) async throws -> HeadlessGroupAdmissionProgressV2 {
        let groupID = try pendingGroupAdmission(admissionID).groupID
        if !HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await withGroupTransaction(groupID) {
                try await self.acceptGroupAdmissionWelcome(
                    admissionID: admissionID,
                    welcome: welcome,
                    observedAt: observedAt
                )
            }
        }
        let current = try pendingGroupAdmission(admissionID)
        let staged = try current.staging(welcome: welcome, observedAt: observedAt)
        if staged != current {
            try await persistPendingGroupAdmission(staged, expected: current)
        }
        return try await completePendingGroupAdmissionIfReady(admissionID)
    }

    /// Convenience demultiplexer for encrypted invitation-channel artifacts.
    public func acceptGroupAdmissionEnvelope(
        admissionID: UUID,
        envelope: ProtocolEnvelopeV1,
        observedAt: Date = Date()
    ) async throws -> HeadlessGroupAdmissionProgressV2 {
        switch envelope {
        case .groupCommitV2(let transition):
            return try await acceptGroupAdmissionTransition(
                admissionID: admissionID,
                transition: transition,
                observedAt: observedAt
            )
        case .groupWelcomeV2(let welcome):
            return try await acceptGroupAdmissionWelcome(
                admissionID: admissionID,
                welcome: welcome,
                observedAt: observedAt
            )
        case .directV4, .groupApplicationV2, .groupDeletionV2:
            throw HeadlessMessagingClientError.invalidControl
        }
    }

    public func pendingGroupAdmissionProgress() -> [HeadlessGroupAdmissionProgressV2] {
        state.activePersona.pendingGroupAdmissions.map {
            HeadlessGroupAdmissionProgressV2($0)
        }
    }

    /// Creates the first or replacement group receive route. Capability
    /// material is saved before relay I/O; the returned route set is signed
    /// only by the group's current local credential.
    public func registerGroupReceiveRoute(
        groupID: UUID,
        relay: RelayEndpoint,
        policy: OpaqueRoutePolicyV2 = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .sixHours,
            quotaBucket: .packets256
        ),
        at date: Date = Date()
    ) async throws -> HeadlessGroupReceiveRouteResultV2 {
        if !HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await withGroupTransaction(groupID) {
                try await self.registerGroupReceiveRoute(
                    groupID: groupID,
                    relay: relay,
                    policy: policy,
                    at: date
                )
            }
        }
        let runtime = try openGroupRuntime(groupID: groupID)
        let pending: PendingLocalOpaqueReceiveRouteV2
        if let existing = await runtime.inboundTransportSnapshot().pendingRoute {
            guard existing.relay == relay else {
                throw HeadlessMessagingClientError.invalidState
            }
            pending = existing
        } else {
            pending = try await runtime.prepareInboundReceiveRoute(
                relay: relay,
                policy: policy,
                createdAt: date
            )
        }
        return try await resumeGroupReceiveRoute(
            groupID: groupID,
            routeID: pending.clientCapabilities.routeID,
            at: date
        )
    }

    /// Resumes the exact persisted idempotent route-create request after a
    /// crash or transient relay failure.
    public func resumeGroupReceiveRoute(
        groupID: UUID,
        routeID: OpaqueReceiveRouteIDV2,
        at date: Date = Date()
    ) async throws -> HeadlessGroupReceiveRouteResultV2 {
        if !HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await withGroupTransaction(groupID) {
                try await self.resumeGroupReceiveRoute(
                    groupID: groupID,
                    routeID: routeID,
                    at: date
                )
            }
        }
        let runtime = try openGroupRuntime(groupID: groupID)
        guard let pending = await runtime.inboundTransportSnapshot().pendingRoute,
              pending.clientCapabilities.routeID == routeID else {
            throw HeadlessMessagingClientError.invalidState
        }
        let response = try await relayClient(for: pending.relay).send(
            .createOpaqueRouteV2(
                CreateOpaqueRouteRelayRequestV2(
                    request: pending.createRequest,
                    renewCapability: pending.clientCapabilities.renewCapability
                )
            )
        )
        guard case .opaqueRoute(let created)? = response.successBody else {
            throw response.status == .error
                ? HeadlessMessagingClientError.relayRejected
                : HeadlessMessagingClientError.invalidRelayResponse
        }
        let routeSet = try await runtime.activateInboundReceiveRoute(
            createdRoute: created,
            activatedAt: date
        )
        return HeadlessGroupReceiveRouteResultV2(
            groupID: groupID,
            routeID: routeID,
            routeSet: routeSet
        )
    }

    /// Re-signs the local send-route projection after a group-only credential
    /// changes. This creates no persona or cross-group continuity record.
    public func refreshGroupReceiveRouteSet(
        groupID: UUID,
        at date: Date = Date()
    ) async throws -> SignedGroupOpaqueRouteSetV2 {
        if !HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await withGroupTransaction(groupID) {
                try await self.refreshGroupReceiveRouteSet(groupID: groupID, at: date)
            }
        }
        return try await openGroupRuntime(groupID: groupID).refreshInboundRouteSet(at: date)
    }

    /// Removes expired draining routes only after persisting a successor that
    /// retains a live active path. Relay teardown is best-effort because the
    /// old lease is already expired and the signed successor is authoritative.
    public func finalizeExpiredGroupReceiveRoutes(
        groupID: UUID,
        at date: Date = Date()
    ) async throws -> SignedGroupOpaqueRouteSetV2? {
        if !HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await withGroupTransaction(groupID) {
                try await self.finalizeExpiredGroupReceiveRoutes(groupID: groupID, at: date)
            }
        }
        let runtime = try openGroupRuntime(groupID: groupID)
        guard let finalized = try await runtime.finalizeExpiredInboundRoutes(at: date) else {
            return nil
        }
        for route in finalized.removedRoutes {
            guard let teardown = try? route.clientCapabilities.makeTeardownRequest(
                current: route.route,
                authorizedAt: date,
                idempotencyKey: .generate()
            ) else { continue }
            _ = try? await relayClient(for: route.relay).send(
                .teardownOpaqueRouteV2(
                    TeardownOpaqueRouteRelayRequestV2(
                        request: teardown,
                        teardownCapability: route.clientCapabilities.teardownCapability
                    )
                )
            )
        }
        return finalized.routeSet
    }

    /// Synchronizes every local group route independently. Verified effects,
    /// staged epoch artifacts, partial reassembly, and the page cursor are
    /// local-durable before relay garbage-collection authorization.
    public func syncGroup(
        groupID: UUID,
        maximumPackets: UInt16 = UInt16(
            NoctweaveOpaqueRouteRelayStoreV2.maximumSyncPage
        )
    ) async throws -> [GroupInboundSyncResultV2] {
        if !HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await withGroupTransaction(groupID) {
                try await self.syncGroup(
                    groupID: groupID,
                    maximumPackets: maximumPackets
                )
            }
        }
        let runtime = try openGroupRuntime(groupID: groupID)
        let routeIDs = await runtime.inboundTransportSnapshot().localRoutes.map(\.id)
        var results: [GroupInboundSyncResultV2] = []
        var firstFailure: Error?
        for routeID in routeIDs {
            do {
                results.append(try await syncGroupRoute(
                    groupID: groupID,
                    routeID: routeID,
                    maximumPackets: maximumPackets
                ))
            } catch {
                if firstFailure == nil { firstFailure = error }
            }
        }
        if results.isEmpty, let firstFailure { throw firstFailure }
        return results
    }

    /// Persists the group sender-chain advance, exact encrypted envelope, and
    /// exact opaque-route packets as one resumable workflow before relay I/O.
    public func prepareGroupApplication(
        _ event: GroupConversationEventV2,
        routeSets: [SignedGroupOpaqueRouteSetV2],
        at date: Date = Date()
    ) async throws -> HeadlessPreparedGroupApplicationV2 {
        if !HeadlessTransactionContext.groupIDs.contains(event.groupID) {
            return try await withGroupTransaction(event.groupID) {
                try await self.prepareGroupApplication(
                    event,
                    routeSets: routeSets,
                    at: date
                )
            }
        }
        guard date.timeIntervalSince1970.isFinite else {
            throw HeadlessMessagingClientError.invalidState
        }
        let runtime = try openGroupRuntime(groupID: event.groupID)
        let envelope = try await runtime.prepareApplicationEvent(event, at: date)
        let operation = try await runtime.prepareApplicationTransport(
            eventID: event.id,
            routeSets: routeSets,
            at: date
        )
        if operation == nil {
            try await runtime.markApplicationPublished(eventID: event.id)
        }
        return HeadlessPreparedGroupApplicationV2(
            groupID: event.groupID,
            event: event,
            envelope: envelope,
            transportOperation: operation,
            complete: operation == nil
        )
    }

    /// Persists a signed group epoch transition, its Welcomes, and the exact
    /// route publications needed for the old/new credential union.
    public func prepareGroupEpoch(
        groupID: UUID,
        operation: SignedGroupCommitOperationV2,
        proposedMembers: [GroupMemberV2],
        proposedCredentials: [GroupMemberCredentialV2],
        admissionProjection: GroupCredentialAdmissionV2? = nil,
        replacementLocalCredential: LocalGroupCredentialV2? = nil,
        proposedPermissions: GroupPermissionPolicy,
        proposedMetadataDigest: Data?,
        idempotencyKey: Data,
        routeSets: [SignedGroupOpaqueRouteSetV2],
        createdAt: Date = Date()
    ) async throws -> HeadlessPreparedGroupEpochV2 {
        if !HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await withGroupTransaction(groupID) {
                try await self.prepareGroupEpoch(
                    groupID: groupID,
                    operation: operation,
                    proposedMembers: proposedMembers,
                    proposedCredentials: proposedCredentials,
                    admissionProjection: admissionProjection,
                    replacementLocalCredential: replacementLocalCredential,
                    proposedPermissions: proposedPermissions,
                    proposedMetadataDigest: proposedMetadataDigest,
                    idempotencyKey: idempotencyKey,
                    routeSets: routeSets,
                    createdAt: createdAt
                )
            }
        }
        guard createdAt.timeIntervalSince1970.isFinite else {
            throw HeadlessMessagingClientError.invalidState
        }
        let runtime = try openGroupRuntime(groupID: groupID)
        let publication = try await runtime.prepareEpoch(
            operation: operation,
            proposedMembers: proposedMembers,
            proposedCredentials: proposedCredentials,
            admissionProjection: admissionProjection,
            replacementLocalCredential: replacementLocalCredential,
            proposedPermissions: proposedPermissions,
            proposedMetadataDigest: proposedMetadataDigest,
            idempotencyKey: idempotencyKey,
            createdAt: createdAt
        )
        let transportOperation = try await runtime.prepareEpochTransport(
            intentID: publication.intentId,
            routeSets: routeSets,
            at: createdAt
        )
        if transportOperation == nil {
            try await runtime.finalizeEpoch(
                intentId: publication.intentId,
                at: createdAt
            )
        }
        return HeadlessPreparedGroupEpochV2(
            groupID: groupID,
            publication: publication,
            transportOperation: transportOperation,
            complete: transportOperation == nil
        )
    }

    /// Saves one exact signed terminal tombstone and all recipient route
    /// packets before any append. Deletion completion requires real persisted
    /// relay receipts for every current remote group credential.
    public func prepareGroupDeletion(
        groupID: UUID,
        reasonDigest: Data? = nil,
        idempotencyKey: Data,
        routeSets: [SignedGroupOpaqueRouteSetV2],
        createdAt: Date = Date()
    ) async throws -> HeadlessPreparedGroupDeletionV2 {
        if !HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await withGroupTransaction(groupID) {
                try await self.prepareGroupDeletion(
                    groupID: groupID,
                    reasonDigest: reasonDigest,
                    idempotencyKey: idempotencyKey,
                    routeSets: routeSets,
                    createdAt: createdAt
                )
            }
        }
        let runtime = try openGroupRuntime(groupID: groupID)
        let tombstone = try await runtime.prepareDeletion(
            reasonDigest: reasonDigest,
            idempotencyKey: idempotencyKey,
            createdAt: createdAt
        )
        let transport = try await runtime.prepareDeletionTransport(
            tombstoneID: tombstone.id,
            routeSets: routeSets,
            at: createdAt
        )
        if transport == nil {
            try await runtime.markDeletionPublished(
                tombstoneID: tombstone.id,
                at: createdAt
            )
        }
        return HeadlessPreparedGroupDeletionV2(
            groupID: groupID,
            tombstone: tombstone,
            transportOperation: transport,
            complete: transport == nil
        )
    }

    /// Resumes one exact persisted group transport operation. An attempt is
    /// durably recorded before every network call; only structurally valid,
    /// packet-matching relay receipts can create acceptance evidence.
    public func resumeGroupTransport(
        groupID: UUID,
        operationID: UUID,
        at date: Date = Date()
    ) async throws -> HeadlessGroupTransportResumeResultV2 {
        if !HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await withGroupTransaction(groupID) {
                try await self.resumeGroupTransport(
                    groupID: groupID,
                    operationID: operationID,
                    at: date
                )
            }
        }
        guard date.timeIntervalSince1970.isFinite else {
            throw HeadlessMessagingClientError.invalidState
        }
        let runtime = try openGroupRuntime(groupID: groupID)
        guard var currentOperation = await runtime.outboundTransportOperations()
            .first(where: { $0.id == operationID }) else {
            throw HeadlessMessagingClientError.invalidState
        }

        var attemptedPublicationIDs = Set<UUID>()
        var failureDisposition: HeadlessGroupTransportDispositionV2?

        while !currentOperation.isComplete {
            let eligible = try await runtime.eligibleOutboundTransportPublications(
                operationID: operationID
            )
            guard let candidate = eligible.first(where: {
                !attemptedPublicationIDs.contains($0.id)
            }) else { break }
            attemptedPublicationIDs.insert(candidate.id)

            let attemptAt = max(max(Date(), date), currentOperation.updatedAt)
            let publication = try await runtime.recordOutboundTransportAttempt(
                operationID: operationID,
                publicationID: candidate.id,
                at: attemptAt
            )
            var receipts: [OpaqueRouteAppendReceiptV2] = []
            receipts.reserveCapacity(publication.packets.count)
            var publicationFailure: HeadlessGroupTransportDispositionV2?

            for packet in publication.packets {
                do {
                    let response = try await relayClient(
                        for: publication.destinationRelay
                    ).send(.appendOpaqueRouteV2(
                        AppendOpaqueRouteRelayRequestV2(
                            packet: packet,
                            sendCapability: publication.sendCapability
                        )
                    ))
                    if response.status == .error {
                        if response.error?.code == .authenticationRequired,
                           groupAuthorizationProofExpired(packet, at: attemptAt) {
                            publicationFailure = .authorizationRecoveryRequired
                        } else if response.error?.retryable == true {
                            publicationFailure = .pendingRetry
                        } else {
                            publicationFailure = .relayRejected
                        }
                        break
                    }
                    guard case .opaqueRouteAppend(let receipt)? = response.successBody,
                          receipt.isStructurallyValid,
                          receipt.packetID == packet.packetID else {
                        publicationFailure = .invalidRelayResponse
                        break
                    }
                    receipts.append(receipt)
                } catch {
                    publicationFailure = .pendingRetry
                    break
                }
            }

            if let publicationFailure {
                failureDisposition = strongerGroupTransportDisposition(
                    failureDisposition,
                    publicationFailure
                )
            } else {
                let acceptedAt = max(Date(), attemptAt)
                try await runtime.recordOutboundTransportAcceptance(
                    operationID: operationID,
                    publicationID: publication.id,
                    receipts: receipts,
                    at: acceptedAt
                )
            }
            guard let refreshed = await runtime.outboundTransportOperations()
                .first(where: { $0.id == operationID }) else {
                throw HeadlessMessagingClientError.invalidState
            }
            currentOperation = refreshed
        }

        if currentOperation.isComplete {
            switch currentOperation.kind {
            case .application:
                if await runtime.pendingApplicationPublications().contains(where: {
                    $0.event.id == currentOperation.logicalID
                }) {
                    try await runtime.markApplicationPublished(
                        eventID: currentOperation.logicalID
                    )
                }
            case .epoch:
                try await runtime.finalizeEpoch(
                    intentId: currentOperation.logicalID,
                    at: max(max(Date(), date), currentOperation.updatedAt)
                )
            case .deletion:
                try await runtime.markDeletionPublished(
                    tombstoneID: currentOperation.logicalID,
                    at: max(max(Date(), date), currentOperation.updatedAt)
                )
            }
        }

        guard let completedOperation = await runtime.outboundTransportOperations()
            .first(where: { $0.id == operationID }) else {
            throw HeadlessMessagingClientError.invalidState
        }
        let acceptedCount = completedOperation.deliveries.flatMap(\.attempts)
            .filter { $0.acceptance != nil }.count
        let pendingCount = completedOperation.isComplete
            ? 0
            : completedOperation.deliveries.flatMap(\.attempts)
                .filter { $0.acceptance == nil }.count
        let disposition: HeadlessGroupTransportDispositionV2 = completedOperation.isComplete
            ? .complete
            : (failureDisposition ?? .pendingRetry)
        return HeadlessGroupTransportResumeResultV2(
            groupID: groupID,
            operationID: operationID,
            logicalID: completedOperation.logicalID,
            kind: completedOperation.kind,
            acceptedCredentialHandles: fullyAcceptedGroupCredentialHandles(
                completedOperation
            ),
            attemptedPublicationCount: attemptedPublicationIDs.count,
            acceptedPublicationCount: acceptedCount,
            pendingPublicationCount: pendingCount,
            complete: completedOperation.isComplete,
            disposition: disposition
        )
    }

    /// Resumes every incomplete operation plus operations whose relay evidence
    /// was saved before a crash but whose logical application/epoch projection
    /// was not yet finalized.
    public func resumePendingGroupTransports(
        groupID: UUID,
        at date: Date = Date()
    ) async throws -> [HeadlessGroupTransportResumeResultV2] {
        if !HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await withGroupTransaction(groupID) {
                try await self.resumePendingGroupTransports(
                    groupID: groupID,
                    at: date
                )
            }
        }
        let runtime = try openGroupRuntime(groupID: groupID)
        let snapshot = await runtime.snapshot()
        let pendingApplicationIDs = Set(
            snapshot.pendingApplicationPublications.map { $0.event.id }
        )
        let pendingEpochIDs = Set(snapshot.epochIntents.filter {
            $0.phase != .finalized
        }.map(\.id))
        let operationIDs = snapshot.outboundTransportOperations.filter { operation in
            !operation.isComplete
                || (operation.kind == .application
                    && pendingApplicationIDs.contains(operation.logicalID))
                || (operation.kind == .epoch
                    && pendingEpochIDs.contains(operation.logicalID))
        }.map(\.id)
        var results: [HeadlessGroupTransportResumeResultV2] = []
        results.reserveCapacity(operationIDs.count)
        for operationID in operationIDs {
            results.append(try await resumeGroupTransport(
                groupID: groupID,
                operationID: operationID,
                at: date
            ))
        }
        return results
    }

    public func setContinuityPolicy(
        _ policy: RelationshipContinuityPolicyV2,
        relationshipID: UUID
    ) async throws {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.setContinuityPolicy(policy, relationshipID: relationshipID)
            }
        }
        var relationship = try relationship(relationshipID)
        relationship.continuityPolicy = policy
        try await commitRelationship(relationship)
    }

    public func continuityInvitation(
        relationshipID: UUID,
        eventID: UUID,
        at date: Date = Date()
    ) throws -> ContactPairingInvitationV2 {
        let relationship = try relationship(relationshipID)
        guard relationship.localPolicy.consent == .accepted,
              relationship.continuityPolicy.allowsReceiving,
              let event = relationship.events.first(where: { $0.id == eventID }),
              event.kind == .control,
              event.content.type == RelationshipControlKindV2.continuityOffer.contentType else {
            throw HeadlessMessagingClientError.continuityNotAllowed
        }
        let offer = try NoctweaveCoder.decode(
            RelationshipContinuityOfferV2.self,
            from: event.content.payload
        )
        guard try NoctweaveCoder.encode(offer, sortedKeys: true) == event.content.payload,
              offer.relationshipID == relationshipID,
              date.timeIntervalSince1970.isFinite,
              date < offer.expiresAt else {
            throw HeadlessMessagingClientError.invalidState
        }
        return offer.invitation
    }

    public func prepareContactParticipant(
        relay: RelayEndpoint,
        relationshipPseudonym: String = "Noctweave peer",
        policy: OpaqueRoutePolicyV2 = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .sixHours,
            quotaBucket: .packets256
        ),
        createdAt: Date = Date()
    ) throws -> PendingContactParticipantV2 {
        try PendingContactParticipantV2.prepare(
            relationshipPseudonym: relationshipPseudonym,
            relay: relay,
            policy: policy,
            createdAt: createdAt
        )
    }

    public func activateContactParticipant(
        _ pending: PendingContactParticipantV2
    ) async throws -> PreparedContactParticipantV2 {
        let response = try await relayClient(for: pending.relay).send(
            .createOpaqueRouteV2(
                CreateOpaqueRouteRelayRequestV2(
                    request: pending.routeCreateRequest,
                    renewCapability: pending.clientCapabilities.renewCapability
                )
            )
        )
        guard case .opaqueRoute(let route)? = response.successBody else {
            throw HeadlessMessagingClientError.relayRejected
        }
        return try pending.activate(createdRoute: route)
    }

    public func makeContactPairingInvitation(
        createdAt: Date = Date(),
        expiresAt: Date
    ) throws -> (
        pending: PendingRendezvousOfferV2,
        invitation: ContactPairingInvitationV2
    ) {
        try ContactPairingHandshakeV2.makeOffer(
            createdAt: createdAt,
            expiresAt: expiresAt
        )
    }

    public func prepareRouteRollover(
        relationshipID: UUID,
        relay: RelayEndpoint,
        policy: OpaqueRoutePolicyV2 = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .sixHours,
            quotaBucket: .packets256
        ),
        createdAt: Date = Date()
    ) async throws -> PendingLocalOpaqueReceiveRouteV2 {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.prepareRouteRollover(
                    relationshipID: relationshipID,
                    relay: relay,
                    policy: policy,
                    createdAt: createdAt
                )
            }
        }
        var relationship = try relationship(relationshipID)
        guard relationship.localPolicy.consent != .blocked,
              relationship.localAdvertisedRoutes.revision < UInt64.max,
              relationship.pendingRouteRollovers.isEmpty,
              !relationship.protocolIntents.contains(where: {
                  $0.kind == .rolloverRoute && !$0.state.isTerminal
              }),
              !relationship.localAdvertisedRoutes.routes.contains(where: {
                  $0.state == .testing || $0.state == .draining
              }),
              relationship.localReceiveRoutes.count
                + relationship.pendingRouteRollovers.count
                < PairwiseRelationshipV2.maximumReceiveRoutes else {
            throw HeadlessMessagingClientError.invalidState
        }
        let pending = try PendingLocalOpaqueReceiveRouteV2.prepare(
            relay: relay,
            policy: policy,
            createdAt: createdAt
        )
        let requestBytes = try NoctweaveCoder.encode(
            pending.createRequest,
            sortedKeys: true
        )
        let intent = ProtocolIntentV2.prepare(
            kind: .rolloverRoute,
            targetIdentifier: pending.clientCapabilities.routeID.rawValue,
            expectedEpoch: relationship.localAdvertisedRoutes.revision + 1,
            idempotencyKey: ProtocolIntentIdempotencyKeyV2(
                rawValue: pending.createRequest.idempotencyKey.rawValue
            ),
            payloadDigest: Data(SHA256.hash(data: requestBytes)),
            createdAt: createdAt,
            expiresAt: pending.createRequest.lease.expiresAt
        )
        relationship.pendingRouteRollovers.append(pending)
        _ = try relationship.appendProtocolIntent(intent)
        try await commitRelationship(relationship)
        return pending
    }

    /// Creates a replacement route, adds it as testing state, journals the
    /// mutation, and publishes the signed route-set successor through the old
    /// working path. The old route remains active until a targeted probe is
    /// received on the replacement route.
    public func beginRouteRollover(
        _ pending: PendingLocalOpaqueReceiveRouteV2,
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> HeadlessRouteRolloverResult {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.beginRouteRollover(
                    pending,
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        let relationship = try relationship(relationshipID)
        guard relationship.pendingRouteRollovers.contains(pending) else {
            throw HeadlessMessagingClientError.invalidState
        }
        return try await resumeRouteRollover(
            routeID: pending.clientCapabilities.routeID,
            relationshipID: relationshipID,
            at: date
        )
    }

    public func resumeRouteRollover(
        routeID: OpaqueReceiveRouteIDV2,
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> HeadlessRouteRolloverResult {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.resumeRouteRollover(
                    routeID: routeID,
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        guard routeID.isStructurallyValid, date.timeIntervalSince1970.isFinite else {
            throw HeadlessMessagingClientError.invalidState
        }
        var relationship = try relationship(relationshipID)
        guard relationship.localPolicy.consent != .blocked,
              let initialIntent = relationship.protocolIntents.first(where: {
                  $0.kind == .rolloverRoute && $0.targetIdentifier == routeID.rawValue
              }) else {
            throw HeadlessMessagingClientError.invalidState
        }
        guard !activeRolloverIntentIDs.contains(initialIntent.id) else {
            return HeadlessRouteRolloverResult(
                relationshipID: relationshipID,
                routeID: routeID,
                state: initialIntent.state,
                routeSetPublication: nil
            )
        }
        activeRolloverIntentIDs.insert(initialIntent.id)
        defer { activeRolloverIntentIDs.remove(initialIntent.id) }

        var routeSetPublication: HeadlessPublicationResult?
        if initialIntent.state == .prepared {
            guard let pending = relationship.pendingRouteRollovers.first(where: {
                $0.clientCapabilities.routeID == routeID
            }) else {
                throw HeadlessMessagingClientError.invalidState
            }
            guard let attemptID = try await beginIntentAttempt(
                intentID: initialIntent.id,
                relationshipID: relationshipID,
                at: date
            ) else {
                let current = try self.relationship(relationshipID)
                let state = current.protocolIntents.first(where: {
                    $0.id == initialIntent.id
                })?.state ?? .permanentFailure
                return HeadlessRouteRolloverResult(
                    relationshipID: relationshipID,
                    routeID: routeID,
                    state: state,
                    routeSetPublication: nil
                )
            }
            let response: RelayResponse
            do {
                response = try await relayClient(for: pending.relay).send(
                    .createOpaqueRouteV2(
                        CreateOpaqueRouteRelayRequestV2(
                            request: pending.createRequest,
                            renewCapability: pending.clientCapabilities.renewCapability
                        )
                    )
                )
            } catch {
                try await finishIntentFailure(
                    intentID: initialIntent.id,
                    relationshipID: relationshipID,
                    attemptID: attemptID,
                    errorClass: .networkUnavailable,
                    at: date
                )
                let current = try self.relationship(relationshipID)
                return HeadlessRouteRolloverResult(
                    relationshipID: relationshipID,
                    routeID: routeID,
                    state: current.protocolIntents.first(where: {
                        $0.id == initialIntent.id
                    })?.state ?? .permanentFailure,
                    routeSetPublication: nil
                )
            }
            guard case .opaqueRoute(let createdRoute)? = response.successBody else {
                try await finishIntentFailure(
                    intentID: initialIntent.id,
                    relationshipID: relationshipID,
                    attemptID: attemptID,
                    errorClass: classifyRelayFailure(response),
                    at: date
                )
                let current = try self.relationship(relationshipID)
                return HeadlessRouteRolloverResult(
                    relationshipID: relationshipID,
                    routeID: routeID,
                    state: current.protocolIntents.first(where: {
                        $0.id == initialIntent.id
                    })?.state ?? .permanentFailure,
                    routeSetPublication: nil
                )
            }

            relationship = try self.relationship(relationshipID)
            guard let pendingIndex = relationship.pendingRouteRollovers.firstIndex(where: {
                $0.clientCapabilities.routeID == routeID
            }), let intentIndex = relationship.protocolIntents.firstIndex(where: {
                $0.id == initialIntent.id
            }) else {
                throw HeadlessMessagingClientError.invalidState
            }
            let persistedPending = relationship.pendingRouteRollovers[pendingIndex]
            let localRoute: LocalOpaqueReceiveRouteV2
            do {
                localRoute = try persistedPending.activate(createdRoute: createdRoute)
            } catch {
                try await finishIntentFailure(
                    intentID: initialIntent.id,
                    relationshipID: relationshipID,
                    attemptID: attemptID,
                    errorClass: .invalidPayload,
                    at: date
                )
                let current = try self.relationship(relationshipID)
                return HeadlessRouteRolloverResult(
                    relationshipID: relationshipID,
                    routeID: routeID,
                    state: current.protocolIntents.first { $0.id == initialIntent.id }?.state
                        ?? .permanentFailure,
                    routeSetPublication: nil
                )
            }
            let successor: PairwiseRouteSetV2
            do {
                let advertised = try localRoute.peerSendRoute(state: .testing)
                successor = try relationship.localAdvertisedRoutes.addingTestingRoute(
                    advertised,
                    signingKey: relationship.localIdentity.localEndpoint.signingKey,
                    issuedAt: max(date, relationship.protocolIntents[intentIndex].updatedAt)
                )
            } catch {
                try await finishIntentFailure(
                    intentID: initialIntent.id,
                    relationshipID: relationshipID,
                    attemptID: attemptID,
                    errorClass: .epochConflict,
                    at: date
                )
                let current = try self.relationship(relationshipID)
                return HeadlessRouteRolloverResult(
                    relationshipID: relationshipID,
                    routeID: routeID,
                    state: current.protocolIntents.first { $0.id == initialIntent.id }?.state
                        ?? .permanentFailure,
                    routeSetPublication: nil
                )
            }
            guard relationship.protocolIntents[intentIndex].expectedEpoch == successor.revision,
                  let published = relationship.protocolIntents[intentIndex].advancing(
                      to: .published,
                      attemptId: attemptID,
                      at: max(date, relationship.protocolIntents[intentIndex].updatedAt)
                  ) else {
                try await finishIntentFailure(
                    intentID: initialIntent.id,
                    relationshipID: relationshipID,
                    attemptID: attemptID,
                    errorClass: .epochConflict,
                    at: date
                )
                let current = try self.relationship(relationshipID)
                return HeadlessRouteRolloverResult(
                    relationshipID: relationshipID,
                    routeID: routeID,
                    state: current.protocolIntents.first { $0.id == initialIntent.id }?.state
                        ?? .permanentFailure,
                    routeSetPublication: nil
                )
            }
            relationship.localReceiveRoutes.append(localRoute)
            relationship.localAdvertisedRoutes = successor
            relationship.pendingRouteRollovers.remove(at: pendingIndex)
            relationship.protocolIntents[intentIndex] = published
            try await commitRelationship(relationship)
        }

        relationship = try self.relationship(relationshipID)
        guard let routeIntent = relationship.protocolIntents.first(where: {
            $0.id == initialIntent.id
        }) else { throw HeadlessMessagingClientError.invalidState }
        if routeIntent.state == .published,
           let attemptID = try await beginIntentAttempt(
               intentID: routeIntent.id,
               relationshipID: relationshipID,
               at: date
           ) {
            do {
                routeSetPublication = try await publishLocalRouteSet(
                    relationshipID: relationshipID,
                    sentAt: date
                )
            } catch {
                try await finishIntentFailure(
                    intentID: routeIntent.id,
                    relationshipID: relationshipID,
                    attemptID: attemptID,
                    errorClass: .dependencyUnavailable,
                    at: date
                )
                let current = try self.relationship(relationshipID)
                return HeadlessRouteRolloverResult(
                    relationshipID: relationshipID,
                    routeID: routeID,
                    state: current.protocolIntents.first { $0.id == routeIntent.id }?.state
                        ?? .permanentFailure,
                    routeSetPublication: nil
                )
            }
            relationship = try self.relationship(relationshipID)
            guard let intentIndex = relationship.protocolIntents.firstIndex(where: {
                $0.id == routeIntent.id
            }) else { throw HeadlessMessagingClientError.invalidState }
            let routeSetAccepted = (routeSetPublication?.acceptedDeliveryCount ?? 0) > 0
                || localRouteSetWasRelayAccepted(in: relationship)
            if routeSetAccepted {
                guard let committed = relationship.protocolIntents[intentIndex].advancing(
                    to: .committed,
                    attemptId: attemptID,
                    at: max(date, relationship.protocolIntents[intentIndex].updatedAt)
                ) else { throw HeadlessMessagingClientError.invalidState }
                relationship.protocolIntents[intentIndex] = committed
                try await commitRelationship(relationship)
            } else {
                try await finishIntentFailure(
                    intentID: routeIntent.id,
                    relationshipID: relationshipID,
                    attemptID: attemptID,
                    errorClass: .dependencyUnavailable,
                    at: date
                )
            }
        }

        relationship = try self.relationship(relationshipID)
        guard let finalState = relationship.protocolIntents.first(where: {
            $0.id == initialIntent.id
        })?.state else { throw HeadlessMessagingClientError.invalidState }
        return HeadlessRouteRolloverResult(
            relationshipID: relationshipID,
            routeID: routeID,
            state: finalState,
            routeSetPublication: routeSetPublication
        )
    }

    public func resumePendingRouteRollovers(
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> [HeadlessRouteRolloverResult] {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.resumePendingRouteRollovers(
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        let relationship = try relationship(relationshipID)
        let routeIDs: [OpaqueReceiveRouteIDV2] = relationship.protocolIntents.compactMap { intent in
            guard intent.kind == .rolloverRoute,
                  !intent.state.isTerminal,
                  let target = intent.targetIdentifier else { return nil }
            return OpaqueReceiveRouteIDV2(rawValue: target)
        }
        var results: [HeadlessRouteRolloverResult] = []
        for routeID in routeIDs where routeID.isStructurallyValid {
            results.append(try await resumeRouteRollover(
                routeID: routeID,
                relationshipID: relationshipID,
                at: date
            ))
        }
        return results
    }

    /// Explicitly abandons a terminal failed rollover. A pre-creation artifact
    /// is erased locally. A relay-created testing route is first replaced by
    /// a signed revoked route-set successor; ordinary drained-route finalizing
    /// can then publish/teardown it without blocking a future rollover.
    @discardableResult
    public func discardFailedRouteRollover(
        routeID: OpaqueReceiveRouteIDV2,
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> HeadlessPublicationResult? {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.discardFailedRouteRollover(
                    routeID: routeID,
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        var relationship = try relationship(relationshipID)
        guard date.timeIntervalSince1970.isFinite,
              let intent = relationship.protocolIntents.first(where: {
                  $0.kind == .rolloverRoute
                      && $0.targetIdentifier == routeID.rawValue
              }), intent.state == .permanentFailure else {
            throw HeadlessMessagingClientError.invalidState
        }
        relationship.pendingRouteRollovers.removeAll {
            $0.clientCapabilities.routeID == routeID
        }
        if let advertised = relationship.localAdvertisedRoutes.routes.first(where: {
            $0.routeID == routeID
        }), advertised.state == .testing {
            relationship.localAdvertisedRoutes = try relationship.localAdvertisedRoutes
                .abandoningTestingRoute(
                    routeID,
                    signingKey: relationship.localIdentity.localEndpoint.signingKey,
                    issuedAt: max(date, relationship.localAdvertisedRoutes.issuedAt)
                )
        }
        try await commitRelationship(relationship)
        guard relationship.localAdvertisedRoutes.routes.contains(where: {
            $0.routeID == routeID
        }) else { return nil }
        return try await publishLocalRouteSet(
            relationshipID: relationshipID,
            sentAt: date
        )
    }

    public func publishLocalRouteSet(
        relationshipID: UUID,
        sentAt: Date = Date()
    ) async throws -> HeadlessPublicationResult {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.publishLocalRouteSet(
                    relationshipID: relationshipID,
                    sentAt: sentAt
                )
            }
        }
        var relationship = try relationship(relationshipID)
        if let eventID = reusableLocalRouteSetEventID(in: relationship) {
            return try await publishPreparedEvent(
                eventID: eventID,
                relationshipID: relationshipID,
                at: sentAt
            )
        }
        let prepared = try await prepareRelationshipControl(
            kind: .routeSetUpdate,
            payload: RelationshipRouteSetUpdateV2(
                relationshipID: relationshipID,
                routeSet: relationship.localAdvertisedRoutes
            ),
            relationship: &relationship,
            sentAt: sentAt
        )
        return try await publishPreparedSend(prepared, at: sentAt)
    }

    /// Rotates only the short-lived prekey of this relationship endpoint and
    /// publishes the refreshed binding through the established relationship.
    /// No persona-wide key or cross-relationship identifier exists.
    public func renewRelationshipPrekeyIfNeeded(
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> HeadlessPublicationResult? {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.renewRelationshipPrekeyIfNeeded(
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        var relationship = try relationship(relationshipID)
        if let pendingEventID = pendingEventID(
            intentKind: .renewRelationshipPrekey,
            in: relationship
        ) {
            return try await publishPreparedEvent(
                eventID: pendingEventID,
                relationshipID: relationshipID,
                at: date
            )
        }
        guard try relationship.localIdentity.renewEndpointPrekeyIfNeeded(at: date) else {
            return nil
        }
        let prepared = try await prepareRelationshipControl(
            kind: .endpointPrekeyUpdate,
            payload: RelationshipEndpointPrekeyUpdateV2(
                relationshipID: relationshipID,
                endpointBinding: relationship.localIdentity.endpointBinding
            ),
            relationship: &relationship,
            sentAt: date
        )
        return try await publishPreparedSend(prepared, at: date)
    }

    public func publishCurrentRelationshipPrekey(
        relationshipID: UUID,
        sentAt: Date = Date()
    ) async throws -> HeadlessPublicationResult {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.publishCurrentRelationshipPrekey(
                    relationshipID: relationshipID,
                    sentAt: sentAt
                )
            }
        }
        var relationship = try relationship(relationshipID)
        if let pendingEventID = pendingEventID(
            intentKind: .renewRelationshipPrekey,
            in: relationship
        ) {
            return try await publishPreparedEvent(
                eventID: pendingEventID,
                relationshipID: relationshipID,
                at: sentAt
            )
        }
        let prepared = try await prepareRelationshipControl(
            kind: .endpointPrekeyUpdate,
            payload: RelationshipEndpointPrekeyUpdateV2(
                relationshipID: relationshipID,
                endpointBinding: relationship.localIdentity.endpointBinding
            ),
            relationship: &relationship,
            sentAt: sentAt
        )
        return try await publishPreparedSend(prepared, at: sentAt)
    }

    /// Revokes routes whose overlap window has elapsed, publishes each signed
    /// successor before teardown, then erases the local route capability only
    /// after the relay confirms teardown.
    public func finalizeDrainedRoutes(
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> [OpaqueReceiveRouteIDV2] {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.finalizeDrainedRoutes(
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        var finalized: [OpaqueReceiveRouteIDV2] = []
        while true {
            var relationship = try relationship(relationshipID)
            let candidate = relationship.localAdvertisedRoutes.routes.first {
                route in
                relationship.localReceiveRoutes.contains {
                    $0.route.routeID == route.routeID
                } && ((route.state == .draining
                        && route.drainAfter.map { date >= $0 } == true)
                    || route.state == .revoked)
            }
            guard let candidate,
                  let localRoute = relationship.localReceiveRoutes.first(where: {
                      $0.route.routeID == candidate.routeID
                  }) else {
                break
            }
            if candidate.state == .draining {
                relationship.localAdvertisedRoutes = try relationship.localAdvertisedRoutes
                    .revokingDrainedRoute(
                        candidate.routeID,
                        signingKey: relationship.localIdentity.localEndpoint.signingKey,
                        issuedAt: date
                    )
                try await commitRelationship(relationship)
            }
            let published = try await publishLocalRouteSet(
                relationshipID: relationshipID,
                sentAt: date
            )
            relationship = try self.relationship(relationshipID)
            guard published.acceptedDeliveryCount > 0
                    || localRouteSetWasRelayAccepted(in: relationship) else { break }

            let teardown = try localRoute.clientCapabilities.makeTeardownRequest(
                current: localRoute.route,
                authorizedAt: date,
                idempotencyKey: .generate()
            )
            let response = try await relayClient(for: localRoute.relay).send(
                .teardownOpaqueRouteV2(
                    TeardownOpaqueRouteRelayRequestV2(
                        request: teardown,
                        teardownCapability: localRoute.clientCapabilities.teardownCapability
                    )
                )
            )
            guard case .opaqueRoute(let tornDown)? = response.successBody,
                  tornDown.status == .tornDown else {
                throw HeadlessMessagingClientError.relayRejected
            }
            relationship = try self.relationship(relationshipID)
            relationship.localReceiveRoutes.removeAll {
                $0.route.routeID == candidate.routeID
            }
            try await commitRelationship(relationship)
            finalized.append(candidate.routeID)
        }
        return finalized
    }

    /// Performs the endpoint maintenance that a long-running client needs in
    /// one serialized relationship transaction. Replacement routes are fresh
    /// unlinkable capabilities; this never authorizes a device, account, or
    /// persona-wide endpoint and never renews a stable route identifier.
    public func maintainRelationship(
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> HeadlessRelationshipMaintenanceReportV2 {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.maintainRelationship(
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        guard date.timeIntervalSince1970.isFinite,
              date.addingTimeInterval(Self.routeReplacementLeadTime)
                .timeIntervalSince1970.isFinite else {
            throw HeadlessMessagingClientError.invalidState
        }

        var current = try relationship(relationshipID)
        guard current.localPolicy.consent != .blocked else {
            return HeadlessRelationshipMaintenanceReportV2(
                relationshipID: relationshipID,
                observedAt: date,
                routeDisposition: .blocked,
                resumedRollovers: [],
                startedRollover: nil,
                prekeyPublication: nil,
                finalizedRouteIDs: []
            )
        }

        let resumed = try await resumePendingRouteRollovers(
            relationshipID: relationshipID,
            at: date
        )
        current = try relationship(relationshipID)
        let hasReachableActiveRoute = current.localReceiveRoutes.contains { local in
            local.route.lease.expiresAt > date
                && current.localAdvertisedRoutes.routes.contains {
                    $0.routeID == local.route.routeID && $0.state == .active
                }
        }
        // Publishing a fresh prekey without a live receive route creates an
        // unreachable session-establishment artifact. Route recovery must
        // happen first; the next maintenance pass can then publish the prekey.
        let prekeyPublication = hasReachableActiveRoute
            ? try await renewRelationshipPrekeyIfNeeded(
                relationshipID: relationshipID,
                at: date
            )
            : nil
        let finalized = try await finalizeDrainedRoutes(
            relationshipID: relationshipID,
            at: date
        )

        current = try relationship(relationshipID)
        let unfinishedRollover = current.protocolIntents.contains {
            $0.kind == .rolloverRoute && !$0.state.isTerminal
        }
        let failedRolloverStillPresent = current.protocolIntents.contains { intent in
            guard intent.kind == .rolloverRoute,
                  intent.state == .permanentFailure,
                  let target = intent.targetIdentifier else { return false }
            return current.pendingRouteRollovers.contains {
                $0.clientCapabilities.routeID.rawValue == target
            } || current.localAdvertisedRoutes.routes.contains {
                $0.routeID.rawValue == target && $0.state == .testing
            }
        }

        var started: HeadlessRouteRolloverResult?
        let disposition: HeadlessRouteMaintenanceDispositionV2
        if failedRolloverStillPresent {
            disposition = .rolloverFailed
        } else if unfinishedRollover {
            disposition = .rolloverInProgress
        } else {
            let activeLocalRoute = current.localReceiveRoutes
                .filter { local in
                    current.localAdvertisedRoutes.routes.contains {
                        $0.routeID == local.route.routeID && $0.state == .active
                    }
                }
                .min { lhs, rhs in
                    lhs.route.lease.expiresAt < rhs.route.lease.expiresAt
                }
            guard let activeLocalRoute else {
                return HeadlessRelationshipMaintenanceReportV2(
                    relationshipID: relationshipID,
                    observedAt: date,
                    routeDisposition: .noLocalRoute,
                    resumedRollovers: resumed,
                    startedRollover: nil,
                    prekeyPublication: prekeyPublication,
                    finalizedRouteIDs: finalized
                )
            }
            if date >= activeLocalRoute.route.lease.expiresAt {
                disposition = .routeExpired
            } else if activeLocalRoute.route.lease.expiresAt
                        <= date.addingTimeInterval(Self.routeReplacementLeadTime) {
                let pending = try await prepareRouteRollover(
                    relationshipID: relationshipID,
                    relay: activeLocalRoute.relay,
                    policy: activeLocalRoute.route.lease.policy,
                    createdAt: date
                )
                started = try await beginRouteRollover(
                    pending,
                    relationshipID: relationshipID,
                    at: date
                )
                disposition = started?.state == .permanentFailure
                    ? .rolloverFailed
                    : .rolloverStarted
            } else {
                disposition = .healthy
            }
        }

        return HeadlessRelationshipMaintenanceReportV2(
            relationshipID: relationshipID,
            observedAt: date,
            routeDisposition: disposition,
            resumedRollovers: resumed,
            startedRollover: started,
            prekeyPublication: prekeyPublication,
            finalizedRouteIDs: finalized
        )
    }

    /// Runs maintenance independently for every relationship in the active
    /// local persona. No state or identifier is shared across relationships.
    public func maintainAllRelationships(
        at date: Date = Date()
    ) async throws -> [HeadlessRelationshipMaintenanceReportV2] {
        guard date.timeIntervalSince1970.isFinite else {
            throw HeadlessMessagingClientError.invalidState
        }
        let relationshipIDs = state.activePersona.relationships.map(\.id)
        var reports: [HeadlessRelationshipMaintenanceReportV2] = []
        reports.reserveCapacity(relationshipIDs.count)
        for relationshipID in relationshipIDs {
            reports.append(try await maintainRelationship(
                relationshipID: relationshipID,
                at: date
            ))
        }
        return reports
    }

    /// Tears down only the blocked relationship's opaque receive routes. The
    /// signed route snapshot is retained as historical relationship evidence,
    /// while successfully torn-down capability material is removed locally.
    @discardableResult
    public func teardownBlockedRelationshipRoutes(
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> [OpaqueReceiveRouteIDV2] {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.teardownBlockedRelationshipRoutes(
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        guard date.timeIntervalSince1970.isFinite,
              try relationship(relationshipID).localPolicy.consent == .blocked else {
            throw HeadlessMessagingClientError.relationshipBlocked
        }
        let routeIDs = try relationship(relationshipID).localReceiveRoutes.map {
            $0.route.routeID
        }
        var tornDown: [OpaqueReceiveRouteIDV2] = []
        for routeID in routeIDs {
            var relationship = try relationship(relationshipID)
            guard let localRoute = relationship.localReceiveRoutes.first(where: {
                $0.route.routeID == routeID
            }) else {
                continue
            }
            do {
                let teardown = try localRoute.clientCapabilities.makeTeardownRequest(
                    current: localRoute.route,
                    authorizedAt: date,
                    idempotencyKey: .generate()
                )
                let response = try await relayClient(for: localRoute.relay).send(
                    .teardownOpaqueRouteV2(
                        TeardownOpaqueRouteRelayRequestV2(
                            request: teardown,
                            teardownCapability: localRoute.clientCapabilities.teardownCapability
                        )
                    )
                )
                guard case .opaqueRoute(let result)? = response.successBody,
                      result.status == .tornDown else {
                    continue
                }
                relationship = try self.relationship(relationshipID)
                relationship.localReceiveRoutes.removeAll {
                    $0.route.routeID == routeID
                }
                try await commitRelationship(relationship)
                tornDown.append(routeID)
            } catch {
                continue
            }
        }
        return tornDown
    }

    public func sendText(
        _ text: String,
        relationshipID: UUID,
        sentAt: Date = Date()
    ) async throws -> HeadlessSendResult {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.sendText(text, relationshipID: relationshipID, sentAt: sentAt)
            }
        }
        let prepared = try await prepareSend(
            body: .text(text),
            relationshipID: relationshipID,
            sentAt: sentAt
        )
        return try await publishPreparedSendResult(prepared, at: sentAt)
    }

    public func sendAttachment(
        _ descriptor: AttachmentDescriptor,
        relationshipID: UUID,
        sentAt: Date = Date()
    ) async throws -> HeadlessSendResult {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.sendAttachment(
                    descriptor,
                    relationshipID: relationshipID,
                    sentAt: sentAt
                )
            }
        }
        let prepared = try await prepareSend(
            body: .attachment(descriptor),
            relationshipID: relationshipID,
            sentAt: sentAt
        )
        return try await publishPreparedSendResult(prepared, at: sentAt)
    }

    /// Journals an already end-to-end-encrypted attachment chunk before relay
    /// I/O. Encryption keys and plaintext remain outside this protocol record.
    public func prepareAttachmentUpload(
        _ request: UploadAttachmentRequest,
        relay: RelayEndpoint,
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> PendingAttachmentUploadV2 {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.prepareAttachmentUpload(
                    request,
                    relay: relay,
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        var relationship = try relationship(relationshipID)
        guard relationship.localPolicy.allowsUserSending,
              relationship.pendingAttachmentUploads.count
                < PairwiseRelationshipV2.maximumPendingAttachmentUploads,
              !relationship.pendingAttachmentUploads.contains(where: {
                  $0.request.attachmentId == request.attachmentId
                      && $0.request.chunkIndex == request.chunkIndex
              }),
              !relationship.pendingAttachmentUploads.contains(where: {
                  $0.request.idempotencyKey == request.idempotencyKey
              }) else {
            throw HeadlessMessagingClientError.invalidState
        }
        let pending = try PendingAttachmentUploadV2(
            relationshipID: relationshipID,
            relay: relay,
            request: request,
            queuedAt: date
        )
        let requestBytes = try NoctweaveCoder.encode(request, sortedKeys: true)
        let ttl = TimeInterval(request.ttlSeconds ?? 3_600)
        let intent = ProtocolIntentV2.prepare(
            kind: .uploadBlob,
            targetIdentifier: Data(pending.id.uuidString.lowercased().utf8),
            idempotencyKey: ProtocolIntentIdempotencyKeyV2(
                rawValue: request.idempotencyKey
            ),
            payloadDigest: Data(SHA256.hash(data: requestBytes)),
            createdAt: date,
            expiresAt: date.addingTimeInterval(ttl)
        )
        relationship.pendingAttachmentUploads.append(pending)
        _ = try relationship.appendProtocolIntent(intent)
        try await commitRelationship(relationship)
        return pending
    }

    public func publishAttachmentUpload(
        uploadID: UUID,
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> HeadlessBlobUploadResult {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.publishAttachmentUpload(
                    uploadID: uploadID,
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        var relationship = try relationship(relationshipID)
        guard relationship.localPolicy.allowsUserSending,
              let pending = relationship.pendingAttachmentUploads.first(where: {
                  $0.id == uploadID
              }), let intent = relationship.protocolIntents.first(where: {
                  $0.kind == .uploadBlob
                      && $0.targetIdentifier
                        == Data(uploadID.uuidString.lowercased().utf8)
              }) else {
            throw HeadlessMessagingClientError.invalidState
        }
        guard !activeBlobIntentIDs.contains(intent.id) else {
            return HeadlessBlobUploadResult(
                relationshipID: relationshipID,
                uploadID: uploadID,
                attachmentID: pending.request.attachmentId,
                chunkIndex: pending.request.chunkIndex,
                state: intent.state,
                accepted: false
            )
        }
        activeBlobIntentIDs.insert(intent.id)
        defer { activeBlobIntentIDs.remove(intent.id) }
        guard let attemptID = try await beginIntentAttempt(
            intentID: intent.id,
            relationshipID: relationshipID,
            at: date
        ) else {
            let current = try self.relationship(relationshipID)
            return HeadlessBlobUploadResult(
                relationshipID: relationshipID,
                uploadID: uploadID,
                attachmentID: pending.request.attachmentId,
                chunkIndex: pending.request.chunkIndex,
                state: current.protocolIntents.first(where: {
                    $0.id == intent.id
                })?.state ?? .permanentFailure,
                accepted: false
            )
        }

        let response: RelayResponse
        do {
            response = try await relayClient(for: pending.relay).send(
                .uploadAttachment(pending.request)
            )
        } catch {
            try await finishIntentFailure(
                intentID: intent.id,
                relationshipID: relationshipID,
                attemptID: attemptID,
                errorClass: .networkUnavailable,
                at: date
            )
            let current = try self.relationship(relationshipID)
            return HeadlessBlobUploadResult(
                relationshipID: relationshipID,
                uploadID: uploadID,
                attachmentID: pending.request.attachmentId,
                chunkIndex: pending.request.chunkIndex,
                state: current.protocolIntents.first(where: {
                    $0.id == intent.id
                })?.state ?? .permanentFailure,
                accepted: false
            )
        }
        guard case .attachment(let chunk)? = response.successBody,
              chunk.attachmentId == pending.request.attachmentId,
              chunk.chunkIndex == pending.request.chunkIndex,
              chunk.payload == pending.request.payload else {
            try await finishIntentFailure(
                intentID: intent.id,
                relationshipID: relationshipID,
                attemptID: attemptID,
                errorClass: classifyRelayFailure(response),
                at: date
            )
            let current = try self.relationship(relationshipID)
            return HeadlessBlobUploadResult(
                relationshipID: relationshipID,
                uploadID: uploadID,
                attachmentID: pending.request.attachmentId,
                chunkIndex: pending.request.chunkIndex,
                state: current.protocolIntents.first(where: {
                    $0.id == intent.id
                })?.state ?? .permanentFailure,
                accepted: false
            )
        }

        relationship = try self.relationship(relationshipID)
        guard let intentIndex = relationship.protocolIntents.firstIndex(where: {
            $0.id == intent.id
        }) else { throw HeadlessMessagingClientError.invalidState }
        let current = relationship.protocolIntents[intentIndex]
        let transitionAt = max(date, current.updatedAt)
        guard let published = current.advancing(
            to: .published,
            attemptId: attemptID,
            at: transitionAt
        ), let committed = published.advancing(
            to: .committed,
            attemptId: attemptID,
            at: transitionAt
        ), let finalized = committed.advancing(
            to: .finalized,
            attemptId: attemptID,
            at: transitionAt
        ) else { throw HeadlessMessagingClientError.invalidState }
        relationship.protocolIntents[intentIndex] = finalized
        relationship.pendingAttachmentUploads.removeAll { $0.id == uploadID }
        try await commitRelationship(relationship)
        return HeadlessBlobUploadResult(
            relationshipID: relationshipID,
            uploadID: uploadID,
            attachmentID: pending.request.attachmentId,
            chunkIndex: pending.request.chunkIndex,
            state: .finalized,
            accepted: true
        )
    }

    public func retryPendingAttachmentUploads(
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> [HeadlessBlobUploadResult] {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.retryPendingAttachmentUploads(
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        let ids = try relationship(relationshipID).pendingAttachmentUploads.map(\.id)
        var results: [HeadlessBlobUploadResult] = []
        for uploadID in ids {
            results.append(try await publishAttachmentUpload(
                uploadID: uploadID,
                relationshipID: relationshipID,
                at: date
            ))
        }
        return results
    }

    public func discardFailedAttachmentUpload(
        uploadID: UUID,
        relationshipID: UUID
    ) async throws {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.discardFailedAttachmentUpload(
                    uploadID: uploadID,
                    relationshipID: relationshipID
                )
            }
        }
        var relationship = try relationship(relationshipID)
        guard let intent = relationship.protocolIntents.first(where: {
            $0.kind == .uploadBlob
                && $0.targetIdentifier
                    == Data(uploadID.uuidString.lowercased().utf8)
        }), intent.state == .permanentFailure else {
            throw HeadlessMessagingClientError.invalidState
        }
        relationship.pendingAttachmentUploads.removeAll { $0.id == uploadID }
        try await commitRelationship(relationship)
    }

    /// Persists a local-echo event, immutable envelope, per-route ciphertext,
    /// and one bounded intent per destination without contacting any relay.
    public func prepareSend(
        body: MessageBody,
        relationshipID: UUID,
        eventID: UUID = UUID(),
        clientTransactionID: UUID = UUID(),
        sentAt: Date = Date()
    ) async throws -> HeadlessPreparedSend {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.prepareSend(
                    body: body,
                    relationshipID: relationshipID,
                    eventID: eventID,
                    clientTransactionID: clientTransactionID,
                    sentAt: sentAt
                )
            }
        }
        var relationship = try relationship(relationshipID)
        guard !relationship.events.contains(where: {
            $0.authorEndpointHandle == relationship.localEndpointHandle
                && $0.clientTransactionId == clientTransactionID
        }) else {
            throw HeadlessMessagingClientError.conflictingEnvelope
        }
        guard relationship.localPolicy.allowsUserSending else {
            if relationship.localPolicy.consent == .blocked {
                throw HeadlessMessagingClientError.relationshipBlocked
            }
            throw HeadlessMessagingClientError.relationshipConsentRequired
        }
        let wirePayload = try WirePayloadV2.projectingMessageBody(
            body,
            eventId: eventID,
            clientTransactionId: clientTransactionID,
            conversationId: relationship.conversationID,
            authorEndpointHandle: relationship.localEndpointHandle,
            createdAt: sentAt
        )
        guard let event = wirePayload.application else {
            throw HeadlessMessagingClientError.invalidState
        }
        return try await persistPreparedSend(
            wirePayload: wirePayload,
            event: event,
            relationship: &relationship,
            sentAt: sentAt
        )
    }

    public func publishPreparedSend(
        _ prepared: HeadlessPreparedSend,
        at date: Date = Date()
    ) async throws -> HeadlessPublicationResult {
        if !HeadlessTransactionContext.relationshipIDs.contains(prepared.relationshipID) {
            return try await withRelationshipTransaction(prepared.relationshipID) {
                try await self.publishPreparedSend(prepared, at: date)
            }
        }
        let relationship = try relationship(prepared.relationshipID)
        guard relationship.events.contains(prepared.event),
              Set(prepared.deliveryIDs).count == prepared.deliveryIDs.count,
              !prepared.deliveryIDs.isEmpty else {
            throw HeadlessMessagingClientError.invalidState
        }
        let envelopeBytes = try NoctweaveCoder.encode(prepared.envelope, sortedKeys: true)
        let digest = Data(SHA256.hash(data: envelopeBytes))
        let target = Data(prepared.event.id.uuidString.lowercased().utf8)
        guard prepared.deliveryIDs.allSatisfy({ deliveryID in
            guard let intent = relationship.protocolIntents.first(where: {
                $0.id == deliveryID
            }), intent.targetIdentifier == target,
               intent.payloadDigest == digest,
               (intent.kind == .sendEvent
                    || intent.kind == .renewRelationshipPrekey) else {
                return false
            }
            return (relationship.pendingDeliveries.first(where: {
                $0.id == deliveryID
            }).map {
                $0.logicalEventID == prepared.event.id && $0.payloadDigest == digest
            }) ?? (intent.state == .finalized)
        }) else {
            throw HeadlessMessagingClientError.conflictingEnvelope
        }
        return try await publishPreparedEvent(
            eventID: prepared.event.id,
            relationshipID: prepared.relationshipID,
            deliveryIDs: Set(prepared.deliveryIDs),
            at: date
        )
    }

    /// Resumes a persisted logical event after restart without reconstructing
    /// or re-encrypting its payload.
    public func publishPreparedEvent(
        eventID: UUID,
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> HeadlessPublicationResult {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.publishPreparedEvent(
                    eventID: eventID,
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        return try await publishPreparedEvent(
            eventID: eventID,
            relationshipID: relationshipID,
            deliveryIDs: nil,
            at: date
        )
    }

    /// Resumes a retained local action by its durable transaction ID.
    /// Repeating `prepareSend` with that ID is rejected while the bounded
    /// relationship event remains available, so retry cannot advance the
    /// ratchet or enqueue that logical event twice.
    public func publishPreparedTransaction(
        clientTransactionID: UUID,
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> HeadlessPublicationResult {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.publishPreparedTransaction(
                    clientTransactionID: clientTransactionID,
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        let relationship = try relationship(relationshipID)
        guard let eventID = relationship.events.first(where: {
            $0.authorEndpointHandle == relationship.localEndpointHandle
                && $0.clientTransactionId == clientTransactionID
        })?.id else {
            throw HeadlessMessagingClientError.invalidState
        }
        return try await publishPreparedEvent(
            eventID: eventID,
            relationshipID: relationshipID,
            at: date
        )
    }

    /// Explicitly emits a voluntary read receipt. Delivery receipts are
    /// generated automatically after durable inbound processing; read receipts
    /// are never generated without this call.
    public func markRead(
        eventID: UUID,
        relationshipID: UUID,
        sentAt: Date = Date()
    ) async throws -> HeadlessSendResult {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.markRead(
                    eventID: eventID,
                    relationshipID: relationshipID,
                    sentAt: sentAt
                )
            }
        }
        let relationship = try relationship(relationshipID)
        guard relationship.localPolicy.allowsUserSending,
              relationship.localPolicy.readReceiptsEnabled,
              isReceiptablePeerEvent(eventID, in: relationship),
              !hasLocalReceipt(
                  type: .readReceipt,
                  targetEventID: eventID,
                  in: relationship
              ) else {
            throw HeadlessMessagingClientError.invalidState
        }
        return try await sendReceipt(
            type: .readReceipt,
            targetEventID: eventID,
            relationshipID: relationshipID,
            sentAt: sentAt
        )
    }

    public func sendRelationshipControl<Payload: Codable>(
        kind: RelationshipControlKindV2,
        payload: Payload,
        relationshipID: UUID,
        destinationRouteIDs: Set<OpaqueReceiveRouteIDV2>? = nil,
        sentAt: Date = Date()
    ) async throws -> HeadlessSendResult {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.sendRelationshipControl(
                    kind: kind,
                    payload: payload,
                    relationshipID: relationshipID,
                    destinationRouteIDs: destinationRouteIDs,
                    sentAt: sentAt
                )
            }
        }
        var relationship = try relationship(relationshipID)
        let prepared = try await prepareRelationshipControl(
            kind: kind,
            payload: payload,
            relationship: &relationship,
            destinationRouteIDs: destinationRouteIDs,
            sentAt: sentAt
        )
        return try await publishPreparedSendResult(prepared, at: sentAt)
    }

    private func prepareRelationshipControl<Payload: Codable>(
        kind: RelationshipControlKindV2,
        payload: Payload,
        relationship: inout PairwiseRelationshipV2,
        destinationRouteIDs: Set<OpaqueReceiveRouteIDV2>? = nil,
        sentAt: Date
    ) async throws -> HeadlessPreparedSend {
        guard relationship.localPolicy.consent != .blocked else {
            throw HeadlessMessagingClientError.relationshipBlocked
        }
        if relationship.localPolicy.consent == .pendingRequest,
           !kind.isRelationshipMaintenanceV2 {
            throw HeadlessMessagingClientError.relationshipConsentRequired
        }
        if kind == .continuityOffer, !relationship.continuityPolicy.allowsSending {
            throw HeadlessMessagingClientError.continuityNotAllowed
        }
        let eventID = UUID()
        let control = try AuthenticatedRelationshipControlV2.create(
            kind: kind,
            payload: payload,
            relationshipID: relationship.id,
            eventID: eventID,
            senderEndpointHandle: relationship.localEndpointHandle,
            issuedAt: sentAt,
            signingKey: relationship.localIdentity.localEndpoint.signingKey
        )
        let wirePayload = try WirePayloadV2.control(control)
        return try await persistPreparedSend(
            wirePayload: wirePayload,
            event: controlAuditEvent(
                control,
                relationship: relationship,
                createdAt: sentAt
            ),
            relationship: &relationship,
            destinationRouteIDs: destinationRouteIDs,
            intentKind: kind == .endpointPrekeyUpdate
                ? .renewRelationshipPrekey
                : .sendEvent,
            sentAt: sentAt
        )
    }

    public func sendContinuityOffer(
        relationshipID: UUID,
        invitation: ContactPairingInvitationV2,
        sentAt: Date = Date()
    ) async throws -> HeadlessSendResult {
        try await sendRelationshipControl(
            kind: .continuityOffer,
            payload: RelationshipContinuityOfferV2(
                relationshipID: relationshipID,
                invitation: invitation,
                expiresAt: invitation.offer.expiresAt
            ),
            relationshipID: relationshipID,
            sentAt: sentAt
        )
    }

    public func retryPendingDeliveries(
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> Int {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.retryPendingDeliveries(
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        guard try relationship(relationshipID).localPolicy.consent != .blocked else {
            throw HeadlessMessagingClientError.relationshipBlocked
        }
        return try await publishPendingDeliveries(
            relationshipID: relationshipID,
            at: date
        )
    }

    /// Explicitly erases a terminal failed exact outbox artifact. Failed
    /// authenticated payloads are never silently regenerated or rearmed.
    public func discardFailedDelivery(
        intentID: UUID,
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.discardFailedDelivery(
                    intentID: intentID,
                    relationshipID: relationshipID,
                    at: date
                )
            }
        }
        var relationship = try relationship(relationshipID)
        guard let intent = relationship.protocolIntents.first(where: {
            $0.id == intentID
        }), (intent.kind == .sendEvent || intent.kind == .renewRelationshipPrekey),
              intent.state == .permanentFailure,
              let discarded = relationship.pendingDeliveries.first(where: {
                  $0.intentID == intentID
              }),
              intent.targetIdentifier
                == Data(discarded.logicalEventID.uuidString.lowercased().utf8),
              intent.payloadDigest == discarded.payloadDigest else {
            throw HeadlessMessagingClientError.invalidState
        }
        let eventID = discarded.logicalEventID
        let hasAlternativeDelivery = relationship.deliveryStates.contains(where: {
            $0.eventId == discarded.logicalEventID && $0.state != .locallyPersisted
        }) || relationship.pendingDeliveries.contains(where: { candidate in
            candidate.intentID != intentID
                && candidate.directSessionID == discarded.directSessionID
                && candidate.messageCounter == discarded.messageCounter
                && relationship.protocolIntents.first(where: {
                    $0.id == candidate.intentID
                })?.state != .permanentFailure
        })
        if !hasAlternativeDelivery {
            if let sessionIndex = relationship.directSessions.firstIndex(where: {
                $0.sessionId == discarded.directSessionID
            }) {
                relationship.directSessions[sessionIndex].markReset()
            }
            for later in relationship.pendingDeliveries
            where later.directSessionID == discarded.directSessionID
                && later.messageCounter > discarded.messageCounter {
                guard let index = relationship.protocolIntents.firstIndex(where: {
                    $0.id == later.intentID
                }), !relationship.protocolIntents[index].state.isTerminal else { continue }
                let current = relationship.protocolIntents[index]
                if let failed = current.failingPermanently(
                    errorClass: .dependencyFailed,
                    at: max(date, current.updatedAt)
                ) {
                    relationship.protocolIntents[index] = failed
                }
            }
        }
        relationship.pendingDeliveries.removeAll { $0.intentID == intentID }
        if !relationship.pendingDeliveries.contains(where: {
               $0.logicalEventID == eventID
           }), !relationship.protocolIntents.contains(where: { candidate in
               candidate.targetIdentifier
                    == Data(eventID.uuidString.lowercased().utf8)
                    && !candidate.state.isTerminal
           }) {
            relationship.deliveryStates.removeAll {
                $0.eventId == eventID && $0.state == .locallyPersisted
            }
        }
        try await commitRelationship(relationship)
    }

    public func sync(
        relationshipID: UUID,
        maximumPackets: UInt16 = UInt16(NoctweaveOpaqueRouteRelayStoreV2.maximumSyncPage)
    ) async throws -> [HeadlessSyncResult] {
        if !HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await withRelationshipTransaction(relationshipID) {
                try await self.sync(
                    relationshipID: relationshipID,
                    maximumPackets: maximumPackets
                )
            }
        }
        var results: [HeadlessSyncResult] = []
        let relationship = try relationship(relationshipID)
        var firstFailure: Error?
        for routeIndex in relationship.localReceiveRoutes.indices {
            do {
                results.append(try await syncRoute(
                    relationshipID: relationshipID,
                    routeIndex: routeIndex,
                    maximumPackets: maximumPackets
                ))
            } catch {
                // Receive routes are independent availability paths. One
                // stale, gapped, or temporarily unavailable relay must not
                // starve a later healthy route in the same sync pass.
                if firstFailure == nil { firstFailure = error }
            }
        }
        if results.isEmpty, let firstFailure {
            throw firstFailure
        }
        return results
    }

    /// Burns only the active local persona and creates an unrelated replacement.
    /// No continuity event, shared identifier, key or relay route is emitted.
    public func burnActivePersona(
        replacementDisplayName: String,
        at date: Date = Date()
    ) async throws -> PersonaProfileV1 {
        let replacement = try PersonaProfileV1(
            displayName: replacementDisplayName,
            createdAt: date
        )
        try await withStateSaveLock {
            var candidate = state
            guard let index = candidate.personas.firstIndex(where: {
                $0.id == candidate.activePersonaID
            }) else {
                throw HeadlessMessagingClientError.invalidState
            }
            candidate.personas[index] = replacement
            candidate.activePersonaID = replacement.id
            try await stateStore.save(candidate)
            state = candidate
        }
        return replacement
    }

    private func sendReceipt(
        type: ContentTypeId,
        targetEventID: UUID,
        relationshipID: UUID,
        sentAt: Date
    ) async throws -> HeadlessSendResult {
        var relationship = try relationship(relationshipID)
        guard relationship.localPolicy.allowsUserSending else {
            if relationship.localPolicy.consent == .blocked {
                throw HeadlessMessagingClientError.relationshipBlocked
            }
            throw HeadlessMessagingClientError.relationshipConsentRequired
        }
        guard (type != .deliveryReceipt
                || relationship.localPolicy.deliveryReceiptsEnabled),
              (type != .readReceipt
                || relationship.localPolicy.readReceiptsEnabled) else {
            throw HeadlessMessagingClientError.receiptDisabled
        }
        let content: EncodedContent?
        switch type {
        case .deliveryReceipt:
            content = .deliveryReceipt(targetEventId: targetEventID)
        case .readReceipt:
            content = .readReceipt(targetEventId: targetEventID)
        default:
            content = nil
        }
        guard let content,
              isReceiptablePeerEvent(targetEventID, in: relationship) else {
            throw HeadlessMessagingClientError.invalidState
        }
        let event = ConversationEvent(
            conversationId: relationship.conversationID,
            authorEndpointHandle: relationship.localEndpointHandle,
            createdAt: sentAt,
            kind: .receipt,
            content: content
        )
        return try await persistAndPublish(
            wirePayload: try .application(event),
            event: event,
            relationship: &relationship,
            sentAt: sentAt
        )
    }

    private func persistAndPublish(
        wirePayload: WirePayloadV2,
        event: ConversationEvent,
        relationship: inout PairwiseRelationshipV2,
        destinationRouteIDs: Set<OpaqueReceiveRouteIDV2>? = nil,
        intentKind: ProtocolIntentKindV2 = .sendEvent,
        sentAt: Date
    ) async throws -> HeadlessSendResult {
        let prepared = try await persistPreparedSend(
            wirePayload: wirePayload,
            event: event,
            relationship: &relationship,
            destinationRouteIDs: destinationRouteIDs,
            intentKind: intentKind,
            sentAt: sentAt
        )
        return try await publishPreparedSendResult(prepared, at: sentAt)
    }

    private func persistPreparedSend(
        wirePayload: WirePayloadV2,
        event: ConversationEvent,
        relationship: inout PairwiseRelationshipV2,
        destinationRouteIDs: Set<OpaqueReceiveRouteIDV2>? = nil,
        intentKind: ProtocolIntentKindV2 = .sendEvent,
        sentAt: Date
    ) async throws -> HeadlessPreparedSend {
        if event.kind == .application || event.kind == .receipt {
            guard relationship.localPolicy.allowsUserSending else {
                if relationship.localPolicy.consent == .blocked {
                    throw HeadlessMessagingClientError.relationshipBlocked
                }
                throw HeadlessMessagingClientError.relationshipConsentRequired
            }
            guard relationship.peerIdentity.endpointBinding.capabilities
                .supports(contentType: event.content.type) else {
                throw HeadlessMessagingClientError.unsupportedContentType
            }
        }
        let sessionResult: (Conversation, DirectBootstrapV4)
        if let existing = relationship.directSessions.last,
           existing.ratchetState != .reset {
            sessionResult = (existing, .none)
        } else {
            let created = try MessageEngine.createOutboundEndpointSession(
                relationship: relationship,
                now: sentAt
            )
            sessionResult = (
                created.conversation,
                .signedPrekey(
                    kemCiphertext: created.kemCiphertext,
                    prekey: created.prekey
                )
            )
        }
        var conversation = sessionResult.0
        let envelope = try MessageEngine.encryptDirectV4(
            wirePayload: wirePayload,
            eventID: event.id,
            relationship: relationship,
            conversation: &conversation,
            bootstrap: sessionResult.1,
            sentAt: sentAt
        )
        let envelopeBytes = try NoctweaveCoder.encode(envelope, sortedKeys: true)
        try relationship.upsertDirectSession(conversation)
        guard try relationship.appendEvent(event) else {
            throw HeadlessMessagingClientError.conflictingEnvelope
        }
        let deliveries = try relationship.enqueue(
            logicalEventID: event.id,
            payload: envelopeBytes,
            destinationRouteIDs: destinationRouteIDs,
            intentKind: intentKind,
            expiresAt: sentAt.addingTimeInterval(24 * 60 * 60),
            at: sentAt
        )
        guard !deliveries.isEmpty else { throw HeadlessMessagingClientError.noUsableRoute }
        _ = try relationship.recordDeliveryState(
            DeliveryStateRecord(
                eventId: event.id,
                destinationEndpoint: relationship.peerIdentity.sendRoutes.ownerEndpointHandle,
                state: .locallyPersisted,
                updatedAt: sentAt
            )
        )
        var compacted = relationship
        try compacted.compactDurableState()
        try await commitRelationship(compacted)
        relationship = try self.relationship(compacted.id)
        return HeadlessPreparedSend(
            relationshipID: relationship.id,
            event: event,
            envelope: envelope,
            deliveryIDs: deliveries.map(\.id)
        )
    }

    private func publishPreparedSendResult(
        _ prepared: HeadlessPreparedSend,
        at date: Date
    ) async throws -> HeadlessSendResult {
        let publication = try await publishPreparedSend(prepared, at: date)
        return HeadlessSendResult(
            event: prepared.event,
            envelope: prepared.envelope,
            acceptedDeliveryCount: publication.acceptedDeliveryCount,
            pendingDeliveryCount: publication.pendingDeliveryCount,
            failedDeliveryCount: publication.failedDeliveryCount,
            nextRetryNotBefore: publication.nextRetryNotBefore
        )
    }

    private func publishPreparedEvent(
        eventID: UUID,
        relationshipID: UUID,
        deliveryIDs: Set<UUID>?,
        at date: Date
    ) async throws -> HeadlessPublicationResult {
        guard date.timeIntervalSince1970.isFinite,
              try relationship(relationshipID).events.contains(where: {
                  $0.id == eventID
              }) else {
            throw HeadlessMessagingClientError.invalidState
        }
        let accepted = try await publishPendingDeliveries(
            relationshipID: relationshipID,
            eventID: eventID,
            deliveryIDs: deliveryIDs,
            at: date
        )
        let current = try relationship(relationshipID)
        let targetIdentifier = Data(eventID.uuidString.lowercased().utf8)
        let eventIntents = current.protocolIntents.filter { intent in
            (intent.kind == .sendEvent || intent.kind == .renewRelationshipPrekey)
                && intent.targetIdentifier == targetIdentifier
        }
        return HeadlessPublicationResult(
            relationshipID: relationshipID,
            eventID: eventID,
            acceptedDeliveryCount: accepted,
            pendingDeliveryCount: eventIntents.filter { !$0.state.isTerminal }.count,
            failedDeliveryCount: eventIntents.filter {
                $0.state == .permanentFailure
            }.count,
            nextRetryNotBefore: eventIntents.compactMap(\.nextAttemptNotBefore).min()
        )
    }

    private func publishPendingDeliveries(
        relationshipID: UUID,
        eventID: UUID? = nil,
        deliveryIDs: Set<UUID>? = nil,
        at date: Date = Date()
    ) async throws -> Int {
        let relationship = try relationship(relationshipID)
        guard relationship.localPolicy.consent != .blocked else {
            throw HeadlessMessagingClientError.relationshipBlocked
        }
        let candidates = relationship.pendingDeliveries.filter { delivery in
            (eventID.map { delivery.logicalEventID == $0 } ?? true)
                && (deliveryIDs.map { $0.contains(delivery.id) } ?? true)
        }
        var accepted = 0
        for delivery in candidates {
            accepted += try await publishPendingDelivery(
                deliveryID: delivery.id,
                relationshipID: relationshipID,
                at: date
            )
        }
        return accepted
    }

    private func publishPendingDelivery(
        deliveryID: UUID,
        relationshipID: UUID,
        at requestedDate: Date
    ) async throws -> Int {
        var relationship = try relationship(relationshipID)
        guard let delivery = relationship.pendingDeliveries.first(where: {
            $0.id == deliveryID
        }), let intentIndex = relationship.protocolIntents.firstIndex(where: {
            $0.id == delivery.intentID
        }) else {
            return 0
        }
        // Each opaque destination route observes one monotonic ratchet stream.
        // A later exact ciphertext waits until every lower counter for that
        // route/session has either been accepted or explicitly abandoned.
        if relationship.pendingDeliveries.contains(where: { candidate in
            candidate.destinationRouteID == delivery.destinationRouteID
                && candidate.directSessionID == delivery.directSessionID
                && candidate.messageCounter < delivery.messageCounter
        }) {
            return 0
        }
        guard !activeDeliveryIntentIDs.contains(delivery.intentID) else { return 0 }
        activeDeliveryIntentIDs.insert(delivery.intentID)
        defer { activeDeliveryIntentIDs.remove(delivery.intentID) }

        var intent = relationship.protocolIntents[intentIndex]
        if intent.state.isTerminal { return 0 }
        let attemptAt = max(max(Date(), requestedDate), intent.updatedAt)
        if let expired = intent.expiring(at: attemptAt) {
            relationship.protocolIntents[intentIndex] = expired
            try await commitRelationship(relationship)
            return 0
        }
        if let exhausted = intent.exhaustingAttempts(at: attemptAt) {
            relationship.protocolIntents[intentIndex] = exhausted
            try await commitRelationship(relationship)
            return 0
        }
        let attemptID = UUID()
        guard let begun = intent.beginningAttempt(
            id: attemptID,
            completedIntentIds: completedIntentIDs(in: relationship),
            at: attemptAt
        ) else {
            return 0
        }
        relationship.protocolIntents[intentIndex] = begun
        try await commitRelationship(relationship)
        intent = begun

        guard let sendCapability = relationship.peerIdentity.sendRoutes.routes.first(where: {
            $0.routeID == delivery.destinationRouteID
        })?.sendCapability else {
            try await finishDeliveryFailure(
                deliveryID: deliveryID,
                relationshipID: relationshipID,
                intentID: intent.id,
                attemptID: attemptID,
                errorClass: .expired,
                at: attemptAt
            )
            return 0
        }

        var deliveryForAttempt = delivery
        if let deliveryIndex = relationship.pendingDeliveries.firstIndex(where: {
            $0.id == delivery.id
        }) {
            let refreshed = try delivery.refreshingExpiredAuthorizations(
                sendCapability: sendCapability,
                at: attemptAt
            )
            if refreshed != delivery {
                relationship.pendingDeliveries[deliveryIndex] = refreshed
                // Only proof bytes changed. Persist packet IDs, sealed frames,
                // and refreshed authorization before the first retry append.
                try await commitRelationship(relationship)
                deliveryForAttempt = refreshed
            }
        }

        var failure: ProtocolIntentErrorClassV2?
        for packet in deliveryForAttempt.packets {
            do {
                let response = try await relayClient(for: deliveryForAttempt.destinationRelay).send(
                    .appendOpaqueRouteV2(
                        AppendOpaqueRouteRelayRequestV2(
                            packet: packet,
                            sendCapability: sendCapability
                        )
                    )
                )
                guard case .opaqueRouteAppend = response.successBody else {
                    failure = classifyRelayFailure(response)
                    break
                }
            } catch {
                failure = .networkUnavailable
                break
            }
        }
        if let failure {
            try await finishDeliveryFailure(
                deliveryID: deliveryID,
                relationshipID: relationshipID,
                intentID: intent.id,
                attemptID: attemptID,
                errorClass: failure,
                at: attemptAt
            )
            return 0
        }

        relationship = try self.relationship(relationshipID)
        guard let currentDelivery = relationship.pendingDeliveries.first(where: {
            $0.id == deliveryID && $0.intentID == intent.id
        }), let currentIntentIndex = relationship.protocolIntents.firstIndex(where: {
            $0.id == intent.id
        }) else {
            throw HeadlessMessagingClientError.invalidState
        }
        let currentIntent = relationship.protocolIntents[currentIntentIndex]
        let transitionAt = max(attemptAt, currentIntent.updatedAt)
        guard let published = currentIntent.advancing(
            to: .published,
            attemptId: attemptID,
            at: transitionAt
        ), let committed = published.advancing(
            to: .committed,
            attemptId: attemptID,
            at: transitionAt
        ), let finalized = committed.advancing(
            to: .finalized,
            attemptId: attemptID,
            at: transitionAt
        ) else {
            throw HeadlessMessagingClientError.invalidState
        }
        relationship.protocolIntents[currentIntentIndex] = finalized
        relationship.pendingDeliveries.removeAll { $0.id == currentDelivery.id }
        for index in relationship.deliveryStates.indices
            where relationship.deliveryStates[index].eventId == currentDelivery.logicalEventID {
            _ = relationship.deliveryStates[index].advance(
                to: .relayAccepted,
                at: max(transitionAt, relationship.deliveryStates[index].updatedAt)
            )
        }
        try await commitRelationship(relationship)
        return 1
    }

    private func finishDeliveryFailure(
        deliveryID: UUID,
        relationshipID: UUID,
        intentID: UUID,
        attemptID: UUID,
        errorClass: ProtocolIntentErrorClassV2,
        at date: Date
    ) async throws {
        guard var relationship = try? relationship(relationshipID),
              relationship.pendingDeliveries.contains(where: {
                  $0.id == deliveryID && $0.intentID == intentID
              }), let index = relationship.protocolIntents.firstIndex(where: {
            $0.id == intentID
        }) else {
            return
        }
        let current = relationship.protocolIntents[index]
        let transitionAt = max(date, current.updatedAt)
        if !errorClass.isRetryable {
            guard let failed = current.failingPermanently(
                errorClass: errorClass,
                at: transitionAt
            ) else { throw HeadlessMessagingClientError.invalidState }
            relationship.protocolIntents[index] = failed
        } else if current.attemptCount
                    >= UInt32(NoctweaveArchitectureV2.maximumIntentAttempts) {
            guard let failed = current.exhaustingAttempts(at: transitionAt) else {
                throw HeadlessMessagingClientError.invalidState
            }
            relationship.protocolIntents[index] = failed
        } else {
            let retryAt = transitionAt.addingTimeInterval(
                protocolRetryDelay(after: current.attemptCount)
            )
            guard let failed = current.recordingTransientFailure(
                attemptId: attemptID,
                errorClass: errorClass,
                retryNotBefore: retryAt,
                at: transitionAt
            ) else { throw HeadlessMessagingClientError.invalidState }
            relationship.protocolIntents[index] = failed
        }
        try await commitRelationship(relationship)
    }

    private func classifyRelayFailure(
        _ response: RelayResponse
    ) -> ProtocolIntentErrorClassV2 {
        guard let error = response.error else { return .invalidPayload }
        if error.retryable { return .relayUnavailable }
        switch error.code {
        case .authenticationRequired:
            return .authorizationRejected
        case .notFound:
            return .expired
        case .invalidRequest:
            return .invalidPayload
        case .rateLimited, .unavailable, .internalFailure, .conflict, .capacity:
            return .relayRejected
        }
    }

    private func protocolRetryDelay(after attemptCount: UInt32) -> TimeInterval {
        let exponent = min(Int(attemptCount > 0 ? attemptCount - 1 : 0), 6)
        return min(300, 5 * pow(2, Double(exponent)))
    }

    private func syncGroupRoute(
        groupID: UUID,
        routeID: OpaqueReceiveRouteIDV2,
        maximumPackets: UInt16
    ) async throws -> GroupInboundSyncResultV2 {
        let runtime = try openGroupRuntime(groupID: groupID)
        var receivedEvents = try await runtime.drainPendingInboundBundles()
        let inbound = await runtime.inboundTransportSnapshot()
        guard let wrapper = inbound.localRoutes.first(where: { $0.id == routeID }) else {
            throw HeadlessMessagingClientError.invalidState
        }
        let route = wrapper.localRoute
        guard route.gapState == nil else {
            throw HeadlessMessagingClientError.routeGapDetected
        }
        let request = try route.clientCapabilities.makeSyncRequest(
            after: route.committedCursor,
            limit: min(
                maximumPackets,
                UInt16(NoctweaveOpaqueRouteRelayStoreV2.maximumSyncPage)
            )
        )
        let response = try await relayClient(for: route.relay).send(
            .syncOpaqueRouteV2(
                SyncOpaqueRouteRelayRequestV2(
                    request: request,
                    readCredential: route.clientCapabilities.readCredential
                )
            )
        )
        guard case .opaqueRouteSync(let batch)? = response.successBody else {
            throw response.status == .error
                ? HeadlessMessagingClientError.relayRejected
                : HeadlessMessagingClientError.invalidRelayResponse
        }
        let observedAt = Date()
        if let gap = groupOpaqueRouteGap(
            in: batch,
            relativeTo: route,
            detectedAt: observedAt
        ) {
            try await runtime.markInboundRouteGap(routeID: routeID, gap: gap)
            throw HeadlessMessagingClientError.routeGapDetected
        }
        for packet in batch.packets {
            try await runtime.ingestInboundPacket(
                routeID: routeID,
                receivedPacket: packet,
                observedAt: observedAt
            )
        }
        receivedEvents += try await runtime.drainPendingInboundBundles(at: observedAt)
        try await runtime.commitInboundPage(routeID: routeID, batch: batch)

        // Local effects and cursor are durable. Relay GC failure cannot undo
        // the successful receive result and will be retried by a later sync.
        do {
            let commit = try route.clientCapabilities.makeCommitRequest(
                cursor: batch.nextCursor
            )
            let commitResponse = try await relayClient(for: route.relay).send(
                .commitOpaqueRouteV2(
                    CommitOpaqueRouteRelayRequestV2(
                        request: commit,
                        readCredential: route.clientCapabilities.readCredential
                    )
                )
            )
            guard case .opaqueRouteCommit(let receipt)? = commitResponse.successBody,
                  receipt.committedCursor == batch.nextCursor else {
                throw HeadlessMessagingClientError.invalidRelayResponse
            }
        } catch {
            // Intentionally best-effort after local persistence.
        }
        return GroupInboundSyncResultV2(
            groupID: groupID,
            routeID: routeID,
            receivedEvents: receivedEvents,
            committedCursor: batch.nextCursor,
            hasMore: batch.hasMore
        )
    }

    private func groupOpaqueRouteGap(
        in batch: OpaqueRouteSyncResponseV2,
        relativeTo route: LocalOpaqueReceiveRouteV2,
        detectedAt: Date
    ) -> OpaqueRouteGapStateV2? {
        let reason: OpaqueRouteGapReasonV2?
        if batch.retentionFloorSequence > route.committedSequence {
            reason = .retentionExpired
        } else if batch.startsAfterSequence < route.committedSequence
            || batch.nextSequence < route.committedSequence {
            reason = .cursorRegression
        } else if batch.startsAfterSequence != route.committedSequence {
            reason = .sequenceDiscontinuity
        } else if batch.startsAfterRecordDigest != route.committedRecordDigest
            || !batch.isStructurallyValid {
            reason = .digestChainBreak
        } else {
            reason = nil
        }
        return reason.map {
            OpaqueRouteGapStateV2(
                reason: $0,
                expectedSequence: route.committedSequence,
                observedSequence: batch.startsAfterSequence,
                retentionFloorSequence: batch.retentionFloorSequence,
                detectedAt: detectedAt
            )
        }
    }

    private func syncRoute(
        relationshipID: UUID,
        routeIndex: Int,
        maximumPackets: UInt16
    ) async throws -> HeadlessSyncResult {
        var relationship = try relationship(relationshipID)
        guard relationship.localReceiveRoutes.indices.contains(routeIndex) else {
            throw HeadlessMessagingClientError.invalidState
        }
        let route = relationship.localReceiveRoutes[routeIndex]
        guard route.gapState == nil else {
            throw HeadlessMessagingClientError.routeGapDetected
        }
        let request = try route.clientCapabilities.makeSyncRequest(
            after: route.committedCursor,
            limit: min(
                maximumPackets,
                UInt16(NoctweaveOpaqueRouteRelayStoreV2.maximumSyncPage)
            )
        )
        let response = try await relayClient(for: route.relay).send(
            .syncOpaqueRouteV2(
                SyncOpaqueRouteRelayRequestV2(
                    request: request,
                    readCredential: route.clientCapabilities.readCredential
                )
            )
        )
        guard case .opaqueRouteSync(let batch)? = response.successBody else {
            throw HeadlessMessagingClientError.invalidRelayResponse
        }
        let batchReceivedAt = Date()
        if let gap = opaqueRouteGap(
            in: batch,
            relativeTo: route,
            detectedAt: batchReceivedAt
        ) {
            relationship.localReceiveRoutes[routeIndex].gapState = gap
            // A terminal cursor gap makes incomplete fragments unreachable.
            // Drop only partial plaintext; retain bounded terminal replay
            // tombstones so already completed bundles remain idempotent.
            _ = try relationship.localReceiveRoutes[routeIndex]
                .updateReassembler { reassembler in
                    reassembler.discardPendingBundles()
                }
            try await commitRelationship(relationship)
            throw HeadlessMessagingClientError.routeGapDetected
        }

        var received: [ConversationEvent] = []
        for receivedPacket in batch.packets {
            var packetCandidate = relationship
            var completedBundle: OpaqueRouteReassembledBundleV2?
            var recoveredFromReassemblyPressure = false
            do {
                var result: OpaqueRoutePacketReassemblyResultV2?
                var abandonedReason: TransportQuarantineReasonV2?
                while result == nil, abandonedReason == nil {
                    do {
                        result = try packetCandidate.localReceiveRoutes[routeIndex]
                            .updateReassembler { reassembler in
                                try reassembler.consume(
                                    receivedPacket.packet,
                                    payloadKey: route.payloadKey,
                                    routeRevision: receivedPacket.routeRevision
                                )
                            }
                    } catch OpaqueRoutePacketV2Error.reassemblyCapacityExceeded {
                        let currentBundleID = try? receivedPacket.packet.open(
                            payloadKey: route.payloadKey,
                            routeRevision: receivedPacket.routeRevision
                        ).bundleID
                        let evicted = try packetCandidate.localReceiveRoutes[routeIndex]
                            .updateReassembler { reassembler in
                                reassembler.discardOldestPendingBundle()
                            }
                        guard let evicted else {
                            abandonedReason = .unsupportedPayload
                            break
                        }
                        recoveredFromReassemblyPressure = true
                        if evicted == currentBundleID {
                            abandonedReason = .reassemblyPressure
                        }
                    }
                }

                if let abandonedReason {
                    _ = try packetCandidate.recordTransportQuarantine(
                        transportQuarantineReceipt(
                            for: receivedPacket,
                            routeID: route.route.routeID,
                            reason: abandonedReason,
                            observedAt: batchReceivedAt
                        )
                    )
                    relationship = packetCandidate
                    continue
                }
                guard let result else {
                    throw HeadlessMessagingClientError.invalidState
                }
                switch result {
                case .accepted, .duplicate:
                    break
                case .complete(let bundle):
                    completedBundle = bundle
                    if packetCandidate.localPolicy.acceptsInboundEvents {
                        let innerEnvelopeID = try? NoctweaveCoder.decode(
                            DirectEnvelopeV4.self,
                            from: bundle.payload
                        ).id
                        let wasAlreadyReceipted = innerEnvelopeID.map { envelopeID in
                            packetCandidate.inboundReceipts.contains {
                                $0.envelopeId == envelopeID
                            }
                        } ?? false
                        if let event = try processInboundBundle(
                            bundle,
                            sourceRouteID: route.route.routeID,
                            receivedAt: batchReceivedAt,
                            relationship: &packetCandidate
                        ) {
                            received.append(event)
                        } else if let innerEnvelopeID,
                                  !wasAlreadyReceipted,
                                  packetCandidate.inboundReceipts.contains(where: {
                                      $0.envelopeId == innerEnvelopeID
                                  }) {
                            // A valid envelope for a retired direct session is
                            // authenticated and consumed, but cannot mutate the
                            // active conversation state.
                            _ = try packetCandidate.recordTransportQuarantine(
                                transportQuarantineReceipt(
                                    for: receivedPacket,
                                    routeID: route.route.routeID,
                                    reason: .retiredSession,
                                    observedAt: batchReceivedAt,
                                    bundle: bundle
                                )
                            )
                        }
                    }
                }
                if recoveredFromReassemblyPressure {
                    _ = try packetCandidate.recordTransportQuarantine(
                        transportQuarantineReceipt(
                            for: receivedPacket,
                            routeID: route.route.routeID,
                            reason: .reassemblyPressure,
                            observedAt: batchReceivedAt,
                            bundle: completedBundle
                        )
                    )
                }
                relationship = packetCandidate
            } catch {
                guard let reason = transportQuarantineReason(for: error) else {
                    throw error
                }
                if shouldRetirePendingReassembly(after: error),
                   let bundleID = try? receivedPacket.packet.open(
                       payloadKey: route.payloadKey,
                       routeRevision: receivedPacket.routeRevision
                   ).bundleID {
                    _ = try packetCandidate.localReceiveRoutes[routeIndex]
                        .updateReassembler { reassembler in
                            reassembler.discardPendingBundle(bundleID)
                        }
                }
                _ = try packetCandidate.recordTransportQuarantine(
                    transportQuarantineReceipt(
                        for: receivedPacket,
                        routeID: route.route.routeID,
                        reason: reason,
                        observedAt: batchReceivedAt,
                        bundle: completedBundle
                    )
                )
                relationship = packetCandidate
            }
        }

        // Inbound effects, partial reassembly state, and the page cursor become
        // durable in one local transaction. This permits cross-page and
        // post-restart completion without replaying a drained page.
        relationship.localReceiveRoutes[routeIndex].committedCursor = batch.nextCursor
        relationship.localReceiveRoutes[routeIndex].committedSequence = batch.nextSequence
        relationship.localReceiveRoutes[routeIndex].committedRecordDigest
            = batch.nextRecordDigest
        try await commitRelationship(relationship)

        // Relay GC authorization follows the local commit and cannot make a
        // later retry lose verified local effects.
        do {
            let commit = try route.clientCapabilities.makeCommitRequest(
                cursor: batch.nextCursor
            )
            let commitResponse = try await relayClient(for: route.relay).send(
                .commitOpaqueRouteV2(
                    CommitOpaqueRouteRelayRequestV2(
                        request: commit,
                        readCredential: route.clientCapabilities.readCredential
                    )
                )
            )
            guard case .opaqueRouteCommit(let committed)? = commitResponse.successBody,
                  committed.committedCursor == batch.nextCursor else {
                throw HeadlessMessagingClientError.invalidRelayResponse
            }
        } catch {
            // The local cursor and verified effects are already durable. A
            // later sync can repeat relay GC authorization; this failure must
            // not erase the successful local result from the caller.
        }
        let committedCursor = batch.nextCursor

        relationship = try self.relationship(relationshipID)
        if relationship.localPolicy.consent != .blocked {
            for eventID in deliveryReceiptTargets(in: relationship) {
                _ = try? await sendReceipt(
                    type: .deliveryReceipt,
                    targetEventID: eventID,
                    relationshipID: relationshipID,
                    sentAt: Date()
                )
            }
            relationship = try self.relationship(relationshipID)
            for probe in routeProbesToSend(
                in: relationship,
                observedAt: batchReceivedAt
            ) {
                _ = try? await sendRelationshipControl(
                    kind: .routeProbe,
                    payload: probe,
                    relationshipID: relationshipID,
                    destinationRouteIDs: [probe.routeID],
                    sentAt: Date()
                )
            }
            relationship = try self.relationship(relationshipID)
            if localRouteSetNeedsPublication(in: relationship) {
                _ = try? await publishLocalRouteSet(
                    relationshipID: relationshipID,
                    sentAt: Date()
                )
            }
        }
        relationship = try self.relationship(relationshipID)
        return HeadlessSyncResult(
            relationshipID: relationshipID,
            receivedEvents: received,
            committedCursor: committedCursor,
            hasMore: batch.hasMore
        )
    }

    private func transportQuarantineReceipt(
        for receivedPacket: OpaqueRouteReceivedPacketV2,
        routeID: OpaqueReceiveRouteIDV2,
        reason: TransportQuarantineReasonV2,
        observedAt: Date,
        bundle: OpaqueRouteReassembledBundleV2? = nil
    ) -> QuarantinedTransportEnvelopeV2 {
        let innerEnvelopeID: UUID?
        if let bundle,
           let envelope = try? NoctweaveCoder.decode(
               DirectEnvelopeV4.self,
               from: bundle.payload
           ) {
            innerEnvelopeID = envelope.id
        } else {
            innerEnvelopeID = nil
        }
        var streamMaterial = Data(
            "org.noctweave.opaque-route.stream-receipt/v2".utf8
        )
        streamMaterial.append(0)
        streamMaterial.append(routeID.rawValue)
        return QuarantinedTransportEnvelopeV2(
            streamDigest: Data(SHA256.hash(data: streamMaterial)),
            relaySequence: receivedPacket.sequence,
            packetID: receivedPacket.packet.packetID,
            recordDigest: receivedPacket.recordDigest,
            reason: reason,
            observedAt: observedAt,
            innerEnvelopeID: innerEnvelopeID
        )
    }

    /// Returns a terminal peer-controlled classification only for explicit,
    /// deterministic failures. Storage, networking, local state, PQ runtime
    /// availability, and unknown errors remain retryable and cannot authorize
    /// cursor advancement.
    private func transportQuarantineReason(
        for error: Error
    ) -> TransportQuarantineReasonV2? {
        if let error = error as? OpaqueRoutePacketV2Error {
            switch error {
            case .malformedFrame, .invalidPacket, .invalidBundle,
                    .invalidIdentifier:
                return .malformedPacket
            case .decryptionFailed, .bundleDigestMismatch:
                return .invalidCiphertext
            case .packetIdentifierConflict, .bundleConflict, .fragmentConflict:
                return .replayConflict
            case .emptyPayload, .payloadTooLarge, .fragmentCountExceeded:
                return .unsupportedPayload
            case .invalidPayloadKey, .reassemblyCapacityExceeded:
                return nil
            }
        }
        if let error = error as? CryptoError {
            switch error {
            case .invalidSignature:
                return .invalidAttribution
            case .invalidPayload:
                return .invalidEnvelope
            case .counterOutOfOrder, .counterReplay, .counterWindowExceeded:
                return .replayConflict
            case .invalidPublicKey, .invalidPrivateKey, .algorithmUnavailable,
                    .operationFailed:
                return nil
            }
        }
        if let error = error as? WirePayloadV2Error {
            switch error {
            case .invalidKnownControl:
                return .invalidControl
            case .unknownControl:
                return .unsupportedPayload
            case .directV4FormatRequired:
                return .incompatibleProtocol
            case .invalidPayload, .invalidApplicationEvent,
                    .invalidKnownApplicationContent:
                return .invalidEnvelope
            }
        }
        if let error = error as? HeadlessMessagingClientError {
            switch error {
            case .invalidControl:
                return .invalidControl
            case .conflictingEnvelope, .unsupportedContentType:
                return .invalidEnvelope
            case .invalidState, .relationshipNotFound, .relayRejected,
                    .invalidRelayResponse, .noUsableRoute, .incompleteBundle,
                    .continuityNotAllowed, .routeGapDetected,
                    .relationshipConsentRequired, .relationshipBlocked,
                    .receiptDisabled, .staleGroupRuntime, .groupAdmissionNotFound:
                return nil
            }
        }
        if let error = error as? PairwiseRelationshipV2Error,
           error == .conflictingEvent {
            return .replayConflict
        }
        if error is DecodingError {
            return .invalidEnvelope
        }
        return nil
    }

    private func shouldRetirePendingReassembly(after error: Error) -> Bool {
        guard let error = error as? OpaqueRoutePacketV2Error else {
            return false
        }
        switch error {
        case .packetIdentifierConflict, .bundleConflict, .fragmentConflict,
                .bundleDigestMismatch:
            return true
        case .invalidPayloadKey, .invalidIdentifier, .invalidPacket,
                .invalidBundle, .emptyPayload, .payloadTooLarge,
                .fragmentCountExceeded, .malformedFrame, .decryptionFailed,
                .reassemblyCapacityExceeded:
            return false
        }
    }

    private func opaqueRouteGap(
        in batch: OpaqueRouteSyncResponseV2,
        relativeTo route: LocalOpaqueReceiveRouteV2,
        detectedAt: Date
    ) -> OpaqueRouteGapStateV2? {
        let reason: OpaqueRouteGapReasonV2?
        if batch.retentionFloorSequence > route.committedSequence {
            reason = .retentionExpired
        } else if batch.startsAfterSequence < route.committedSequence
            || batch.nextSequence < route.committedSequence {
            reason = .cursorRegression
        } else if batch.startsAfterSequence != route.committedSequence {
            reason = .sequenceDiscontinuity
        } else if batch.startsAfterRecordDigest != route.committedRecordDigest
            || !batch.isStructurallyValid {
            reason = .digestChainBreak
        } else {
            reason = nil
        }
        return reason.map {
            OpaqueRouteGapStateV2(
                reason: $0,
                expectedSequence: route.committedSequence,
                observedSequence: batch.startsAfterSequence,
                retentionFloorSequence: batch.retentionFloorSequence,
                detectedAt: detectedAt
            )
        }
    }

    func processInboundBundle(
        _ bundle: OpaqueRouteReassembledBundleV2,
        sourceRouteID: OpaqueReceiveRouteIDV2,
        receivedAt: Date,
        relationship: inout PairwiseRelationshipV2
    ) throws -> ConversationEvent? {
        guard receivedAt.timeIntervalSince1970.isFinite else {
            throw HeadlessMessagingClientError.invalidState
        }
        let envelope = try NoctweaveCoder.decode(DirectEnvelopeV4.self, from: bundle.payload)
        let digest = Data(SHA256.hash(data: bundle.payload))
        if let prior = relationship.inboundReceipts.first(where: {
            $0.isReplayCandidate(
                sourceScopeId: relationship.id,
                logicalEventId: envelope.eventId,
                envelopeId: envelope.id
            )
        }) {
            guard prior.isExactReplay(
                sourceScopeId: relationship.id,
                logicalEventId: envelope.eventId,
                envelopeId: envelope.id,
                envelopeDigest: digest
            ) else {
                throw HeadlessMessagingClientError.conflictingEnvelope
            }
            return nil
        }

        var conversation: Conversation
        if let existing = relationship.directSessions.first(where: {
            $0.sessionId == envelope.sessionId
        }) {
            if existing.ratchetState == .reset {
                try authenticateRetiredSessionEnvelope(
                    envelope,
                    relationship: relationship
                )
                _ = try relationship.recordInboundReceipt(
                    InboundEnvelopeReceiptV2(
                        sourceScopeId: relationship.id,
                        logicalEventId: envelope.eventId,
                        envelopeId: envelope.id,
                        envelopeDigest: digest,
                        processedAt: receivedAt
                    )
                )
                return nil
            }
            conversation = existing
        } else {
            guard envelope.bootstrap.signedPrekeyMaterial != nil else {
                // A valid envelope from a session outside the bounded local
                // ratchet window is durably quarantined. Advancing the opaque
                // route cursor is safer than replay-wedging the mailbox, while
                // no unauthenticated bytes enter the conversation event log.
                try authenticateRetiredSessionEnvelope(
                    envelope,
                    relationship: relationship
                )
                _ = try relationship.recordInboundReceipt(
                    InboundEnvelopeReceiptV2(
                        sourceScopeId: relationship.id,
                        logicalEventId: envelope.eventId,
                        envelopeId: envelope.id,
                        envelopeDigest: digest,
                        processedAt: receivedAt
                    )
                )
                return nil
            }
            conversation = try MessageEngine.createInboundEndpointSession(
                relationship: relationship,
                bootstrap: envelope.bootstrap,
                now: receivedAt
            )
            guard conversation.sessionId == envelope.sessionId else {
                throw HeadlessMessagingClientError.conflictingEnvelope
            }
        }
        let conversationBeforeDecryption = conversation
        var candidate = relationship
        do {
            let result = try MessageEngine.decryptDirectV4(
                envelope: envelope,
                relationship: candidate,
                conversation: &conversation,
                receivedAt: receivedAt
            )
            let event: ConversationEvent
            var preservesResetState = false
            switch result.disposition {
            case .application(let application, let projection):
                event = application
                switch projection {
                case .deliveryReceipt(let receipt):
                    try applyPeerReceipt(
                        receipt,
                        state: .peerStored,
                        event: application,
                        receivedAt: receivedAt,
                        relationship: &candidate
                    )
                case .readReceipt(let receipt):
                    try applyPeerReceipt(
                        receipt,
                        state: .peerRead,
                        event: application,
                        receivedAt: receivedAt,
                        relationship: &candidate
                    )
                default:
                    break
                }
                if let body = projection.body {
                    _ = MessageEngine.appendMessage(
                        id: application.id,
                        body: body,
                        direction: .received,
                        counter: envelope.messageCounter,
                        timestamp: envelope.sentAt,
                        conversation: &conversation,
                        messageKey: result.messageKey
                    )
                }
            case .control(let control, let auditEvent):
                event = auditEvent
                switch control {
                case .sessionReset:
                    conversation.markReset()
                    preservesResetState = true
                case .routeSetUpdate(let update):
                    try applyPeerRouteSetUpdate(
                        update,
                        receivedAt: receivedAt,
                        relationship: &candidate
                    )
                case .routeProbe(let probe):
                    try applyRouteProbe(
                        probe,
                        sourceRouteID: sourceRouteID,
                        receivedAt: receivedAt,
                        relationship: &candidate
                    )
                case .endpointPrekeyUpdate(let update):
                    try applyPeerPrekeyUpdate(
                        update,
                        receivedAt: receivedAt,
                        relationship: &candidate
                    )
                case .resendRequest, .continuityOffer:
                    break
                }
            case .quarantinedControl(let quarantine):
                event = quarantine.event
                _ = try candidate.recordControlQuarantine(quarantine)
            }
            _ = try candidate.appendEvent(event)
            _ = try candidate.recordInboundReceipt(
                InboundEnvelopeReceiptV2(
                    sourceScopeId: candidate.id,
                    logicalEventId: envelope.eventId,
                    envelopeId: envelope.id,
                    envelopeDigest: digest,
                    processedAt: receivedAt
                )
            )
            if !preservesResetState {
                conversation.markMessageProcessed()
            }
            try candidate.upsertDirectSession(conversation)
            relationship = candidate
            return event
        } catch {
            // Authentication, AEAD opening and strict wire validation update
            // the local conversation only after all cryptographic checks pass.
            // If later authenticated semantics are terminally invalid, retain
            // exactly that ratchet progress and replay receipt, but none of the
            // partially applied control/application effects.
            if conversation != conversationBeforeDecryption {
                var ratchetOnly = relationship
                conversation.markMessageProcessed()
                try ratchetOnly.upsertDirectSession(conversation)
                _ = try ratchetOnly.recordInboundReceipt(
                    InboundEnvelopeReceiptV2(
                        sourceScopeId: ratchetOnly.id,
                        logicalEventId: envelope.eventId,
                        envelopeId: envelope.id,
                        envelopeDigest: digest,
                        processedAt: receivedAt
                    )
                )
                relationship = ratchetOnly
            }
            throw error
        }
    }

    private func authenticateRetiredSessionEnvelope(
        _ envelope: DirectEnvelopeV4,
        relationship: PairwiseRelationshipV2
    ) throws {
        let binding = try MessageEngine.pairwiseBinding(for: relationship)
        guard envelope.conversationId == relationship.conversationID,
              envelope.senderEndpointHandle == binding.peerEndpointHandle,
              envelope.senderBindingDigest == binding.peerBindingReferenceDigest,
              envelope.recipientEndpointHandle == binding.localEndpointHandle,
              envelope.recipientBindingDigest == binding.localBindingReferenceDigest,
              envelope.cipherSuite == binding.cipherSuite,
              envelope.negotiatedCapabilitiesDigest
                == binding.negotiatedCapabilitiesDigest,
              try envelope.verifySignatureThrowing(
                  publicSigningKey: relationship.peerIdentity.endpointBinding
                    .signingPublicKey
              ) else {
            throw HeadlessMessagingClientError.conflictingEnvelope
        }
    }

    private func applyPeerReceipt(
        _ receipt: EventReceiptContentV1,
        state: MessageDeliveryState,
        event: ConversationEvent,
        receivedAt: Date,
        relationship: inout PairwiseRelationshipV2
    ) throws {
        guard event.authorEndpointHandle
                == relationship.peerIdentity.sendRoutes.ownerEndpointHandle,
              let target = relationship.events.first(where: {
                  $0.id == receipt.targetEventId
              }),
              target.authorEndpointHandle == relationship.localEndpointHandle,
              target.kind != .receipt else {
            throw HeadlessMessagingClientError.conflictingEnvelope
        }
        for index in relationship.deliveryStates.indices
            where relationship.deliveryStates[index].eventId == target.id
                && relationship.deliveryStates[index].destinationEndpoint
                    == relationship.peerIdentity.sendRoutes.ownerEndpointHandle {
            _ = relationship.deliveryStates[index].advance(
                to: state,
                at: max(receivedAt, relationship.deliveryStates[index].updatedAt)
            )
        }
    }

    private func applyPeerRouteSetUpdate(
        _ update: RelationshipRouteSetUpdateV2,
        receivedAt: Date,
        relationship: inout PairwiseRelationshipV2
    ) throws {
        guard update.relationshipID == relationship.id,
              update.routeSet.ownerEndpointHandle
                == relationship.peerIdentity.sendRoutes.ownerEndpointHandle else {
            throw HeadlessMessagingClientError.invalidControl
        }
        if update.routeSet == relationship.peerIdentity.sendRoutes { return }
        guard try update.routeSet.isAcceptableSuccessorThrowing(
            of: relationship.peerIdentity.sendRoutes,
            ownerSigningPublicKey: relationship.peerIdentity.endpointBinding.signingPublicKey,
            observedAt: receivedAt
        ) else {
            throw HeadlessMessagingClientError.invalidControl
        }
        relationship.peerIdentity.sendRoutes = update.routeSet
    }

    private func applyPeerPrekeyUpdate(
        _ update: RelationshipEndpointPrekeyUpdateV2,
        receivedAt: Date,
        relationship: inout PairwiseRelationshipV2
    ) throws {
        guard update.relationshipID == relationship.id else {
            throw HeadlessMessagingClientError.invalidControl
        }
        let current = relationship.peerIdentity.endpointBinding
        let candidate = update.endpointBinding
        if candidate == current { return }
        guard candidate.signingPublicKey == current.signingPublicKey,
              candidate.agreementPublicKey == current.agreementPublicKey,
              candidate.capabilities == current.capabilities,
              candidate.issuedAt == current.issuedAt,
              candidate.authoritySignature == current.authoritySignature,
              candidate.authorizationDigest == current.authorizationDigest,
              candidate.prekeyBundle.createdAt > current.prekeyBundle.createdAt else {
            throw HeadlessMessagingClientError.invalidControl
        }
        do {
            _ = try candidate.verified(
                authoritySigningPublicKey: relationship.peerIdentity.signingPublicKey,
                now: receivedAt
            )
        } catch let error as CryptoError {
            throw error
        } catch {
            throw HeadlessMessagingClientError.invalidControl
        }
        relationship.peerIdentity.endpointBinding = candidate
    }

    private func applyRouteProbe(
        _ probe: RelationshipRouteProbeV2,
        sourceRouteID: OpaqueReceiveRouteIDV2,
        receivedAt: Date,
        relationship: inout PairwiseRelationshipV2
    ) throws {
        guard probe.relationshipID == relationship.id,
              probe.routeID == sourceRouteID,
              probe.routeSetRevision == relationship.localAdvertisedRoutes.revision,
              relationship.localAdvertisedRoutes.routes.contains(where: {
                  $0.routeID == probe.routeID && $0.state == .testing
              }) else {
            throw HeadlessMessagingClientError.invalidControl
        }
        let replaced = relationship.localAdvertisedRoutes.routes.compactMap {
            $0.state == .active ? $0.routeID : nil
        }
        let testingRouteSetWasAccepted = localRouteSetWasRelayAccepted(in: relationship)
        guard !replaced.isEmpty else {
            throw HeadlessMessagingClientError.invalidState
        }
        relationship.localAdvertisedRoutes = try relationship.localAdvertisedRoutes
            .promotingProbedRoute(
                probe.routeID,
                replacing: replaced,
                testedAt: receivedAt,
                overlapUntil: receivedAt.addingTimeInterval(5 * 60),
                signingKey: relationship.localIdentity.localEndpoint.signingKey,
                issuedAt: receivedAt
            )
        if let intent = relationship.protocolIntents.first(where: {
            $0.kind == .rolloverRoute
                && $0.targetIdentifier == probe.routeID.rawValue
                && !$0.state.isTerminal
        }) {
            guard let attemptID = intent.lastAttemptId,
                  let intentIndex = relationship.protocolIntents.firstIndex(where: {
                      $0.id == intent.id
                  }) else {
                throw HeadlessMessagingClientError.invalidState
            }
            var current = intent
            if current.state == .published && testingRouteSetWasAccepted {
                guard let committed = current.advancing(
                    to: .committed,
                    attemptId: attemptID,
                    at: max(receivedAt, current.updatedAt)
                ) else { throw HeadlessMessagingClientError.invalidState }
                current = committed
            }
            guard current.state == .committed,
                  let finalized = current.advancing(
                      to: .finalized,
                      attemptId: attemptID,
                      at: max(receivedAt, current.updatedAt)
                  ) else {
                throw HeadlessMessagingClientError.invalidState
            }
            relationship.protocolIntents[intentIndex] = finalized
        }
    }

    func routeProbesToSend(
        in relationship: PairwiseRelationshipV2,
        observedAt: Date
    ) -> [RelationshipRouteProbeV2] {
        guard observedAt.timeIntervalSince1970.isFinite else { return [] }
        let sent = Set(relationship.events.compactMap { event -> String? in
            guard event.authorEndpointHandle == relationship.localEndpointHandle,
                  event.kind == .control,
                  event.content.type == RelationshipControlKindV2.routeProbe.contentType,
                  eventHasDeliveryPath(event.id, in: relationship),
                  let probe = try? NoctweaveCoder.decode(
                      RelationshipRouteProbeV2.self,
                      from: event.content.payload
                  ), probe.routeSetRevision == relationship.peerIdentity.sendRoutes.revision else {
                return nil
            }
            return probe.routeID.rawValue.base64EncodedString()
        })
        return relationship.peerIdentity.sendRoutes.routes.compactMap { route in
            let key = route.routeID.rawValue.base64EncodedString()
            guard route.state == .testing,
                  observedAt >= route.validFrom,
                  observedAt < route.expiresAt,
                  !sent.contains(key) else { return nil }
            return RelationshipRouteProbeV2(
                relationshipID: relationship.id,
                routeID: route.routeID,
                routeSetRevision: relationship.peerIdentity.sendRoutes.revision
            )
        }
    }

    private func localRouteSetNeedsPublication(
        in relationship: PairwiseRelationshipV2
    ) -> Bool {
        guard relationship.localAdvertisedRoutes.revision > 0 else { return false }
        return !localRouteSetWasRelayAccepted(in: relationship)
    }

    private func localRouteSetEventID(
        in relationship: PairwiseRelationshipV2
    ) -> UUID? {
        relationship.events.reversed().first(where: { event in
            guard event.authorEndpointHandle == relationship.localEndpointHandle,
                  event.kind == .control,
                  event.content.type
                    == RelationshipControlKindV2.routeSetUpdate.contentType,
                  let update = try? NoctweaveCoder.decode(
                      RelationshipRouteSetUpdateV2.self,
                      from: event.content.payload
                  ) else {
                return false
            }
            return update.routeSet == relationship.localAdvertisedRoutes
        })?.id
    }

    private func localRouteSetWasRelayAccepted(
        in relationship: PairwiseRelationshipV2
    ) -> Bool {
        guard let eventID = localRouteSetEventID(in: relationship) else { return false }
        return relationship.deliveryStates.contains {
            $0.eventId == eventID && $0.state != .locallyPersisted
        }
    }

    private func reusableLocalRouteSetEventID(
        in relationship: PairwiseRelationshipV2
    ) -> UUID? {
        guard let eventID = localRouteSetEventID(in: relationship) else { return nil }
        if relationship.deliveryStates.contains(where: {
            $0.eventId == eventID && $0.state != .locallyPersisted
        }) {
            return eventID
        }
        let target = Data(eventID.uuidString.lowercased().utf8)
        return relationship.protocolIntents.contains(where: {
            ($0.kind == .sendEvent || $0.kind == .renewRelationshipPrekey)
                && $0.targetIdentifier == target
                && !$0.state.isTerminal
        }) ? eventID : nil
    }

    private func pendingEventID(
        intentKind: ProtocolIntentKindV2,
        in relationship: PairwiseRelationshipV2
    ) -> UUID? {
        relationship.pendingDeliveries.first(where: { delivery in
            relationship.protocolIntents.contains {
                $0.id == delivery.intentID
                    && $0.kind == intentKind
                    && !$0.state.isTerminal
            }
        })?.logicalEventID
    }

    private func deliveryReceiptTargets(
        in relationship: PairwiseRelationshipV2
    ) -> [UUID] {
        guard relationship.localPolicy.allowsUserSending,
              relationship.localPolicy.deliveryReceiptsEnabled,
              relationship.peerIdentity.endpointBinding.capabilities
            .supports(contentType: .deliveryReceipt) else {
            return []
        }
        let receipted = Set(relationship.events.compactMap { event -> UUID? in
            guard event.authorEndpointHandle == relationship.localEndpointHandle,
                  event.kind == .receipt,
                  event.content.type == .deliveryReceipt,
                  eventHasDeliveryPath(event.id, in: relationship),
                  let receipt = try? NoctweaveCoder.decode(
                      EventReceiptContentV1.self,
                      from: event.content.payload
                  ) else {
                return nil
            }
            return receipt.targetEventId
        })
        return relationship.events.compactMap { event in
            guard event.authorEndpointHandle
                    == relationship.peerIdentity.sendRoutes.ownerEndpointHandle,
                  event.kind == .application,
                  !receipted.contains(event.id) else {
                return nil
            }
            return event.id
        }
    }

    private func isReceiptablePeerEvent(
        _ eventID: UUID,
        in relationship: PairwiseRelationshipV2
    ) -> Bool {
        relationship.events.contains {
            $0.id == eventID
                && $0.authorEndpointHandle
                    == relationship.peerIdentity.sendRoutes.ownerEndpointHandle
                && $0.kind == .application
        }
    }

    private func hasLocalReceipt(
        type: ContentTypeId,
        targetEventID: UUID,
        in relationship: PairwiseRelationshipV2
    ) -> Bool {
        relationship.events.contains { event in
            guard event.authorEndpointHandle == relationship.localEndpointHandle,
                  event.kind == .receipt,
                  event.content.type == type,
                  eventHasDeliveryPath(event.id, in: relationship),
                  let receipt = try? NoctweaveCoder.decode(
                      EventReceiptContentV1.self,
                      from: event.content.payload
                  ) else {
                return false
            }
            return receipt.targetEventId == targetEventID
        }
    }

    private func eventHasDeliveryPath(
        _ eventID: UUID,
        in relationship: PairwiseRelationshipV2
    ) -> Bool {
        relationship.deliveryStates.contains {
            $0.eventId == eventID && $0.state != .locallyPersisted
        } || relationship.pendingDeliveries.contains {
            $0.logicalEventID == eventID
        }
    }

    private func controlAuditEvent(
        _ control: AuthenticatedRelationshipControlV2,
        relationship: PairwiseRelationshipV2,
        createdAt: Date
    ) -> ConversationEvent {
        ConversationEvent(
            id: control.eventID,
            clientTransactionId: control.nonce,
            conversationId: relationship.conversationID,
            authorEndpointHandle: relationship.localEndpointHandle,
            createdAt: createdAt,
            kind: .control,
            content: EncodedContent(
                type: control.type,
                parameters: ["wirePayloadVersion": String(NoctweaveWirePayloadV2.version)],
                payload: control.encodedPayload,
                fallbackText: nil,
                disposition: .silent
            )
        )
    }

    private func withRelationshipTransaction<T>(
        _ relationshipID: UUID,
        operation: () async throws -> T
    ) async rethrows -> T {
        if HeadlessTransactionContext.relationshipIDs.contains(relationshipID) {
            return try await operation()
        }
        await acquireRelationshipTransaction(relationshipID)
        defer { releaseRelationshipTransaction(relationshipID) }
        var held = HeadlessTransactionContext.relationshipIDs
        held.insert(relationshipID)
        return try await HeadlessTransactionContext.$relationshipIDs.withValue(held) {
            try await operation()
        }
    }

    private func acquireRelationshipTransaction(_ relationshipID: UUID) async {
        if !activeRelationshipTransactions.contains(relationshipID) {
            activeRelationshipTransactions.insert(relationshipID)
            return
        }
        await withCheckedContinuation { continuation in
            relationshipTransactionWaiters[relationshipID, default: []].append(continuation)
        }
    }

    private func releaseRelationshipTransaction(_ relationshipID: UUID) {
        if var waiters = relationshipTransactionWaiters[relationshipID],
           !waiters.isEmpty {
            let next = waiters.removeFirst()
            if waiters.isEmpty {
                relationshipTransactionWaiters.removeValue(forKey: relationshipID)
            } else {
                relationshipTransactionWaiters[relationshipID] = waiters
            }
            next.resume()
        } else {
            activeRelationshipTransactions.remove(relationshipID)
        }
    }

    private func withGroupTransaction<T>(
        _ groupID: UUID,
        operation: () async throws -> T
    ) async rethrows -> T {
        if HeadlessTransactionContext.groupIDs.contains(groupID) {
            return try await operation()
        }
        await acquireGroupTransaction(groupID)
        defer { releaseGroupTransaction(groupID) }
        var held = HeadlessTransactionContext.groupIDs
        held.insert(groupID)
        return try await HeadlessTransactionContext.$groupIDs.withValue(held) {
            try await operation()
        }
    }

    private func acquireGroupTransaction(_ groupID: UUID) async {
        if !activeGroupTransactions.contains(groupID) {
            activeGroupTransactions.insert(groupID)
            return
        }
        await withCheckedContinuation { continuation in
            groupTransactionWaiters[groupID, default: []].append(continuation)
        }
    }

    private func releaseGroupTransaction(_ groupID: UUID) {
        if var waiters = groupTransactionWaiters[groupID], !waiters.isEmpty {
            let next = waiters.removeFirst()
            if waiters.isEmpty {
                groupTransactionWaiters.removeValue(forKey: groupID)
            } else {
                groupTransactionWaiters[groupID] = waiters
            }
            next.resume()
        } else {
            activeGroupTransactions.remove(groupID)
        }
    }

    private func withStateSaveLock<T>(
        operation: () async throws -> T
    ) async rethrows -> T {
        await acquireStateSaveLock()
        defer { releaseStateSaveLock() }
        return try await operation()
    }

    private func acquireStateSaveLock() async {
        if !stateSaveInProgress {
            stateSaveInProgress = true
            return
        }
        await withCheckedContinuation { continuation in
            stateSaveWaiters.append(continuation)
        }
    }

    private func releaseStateSaveLock() {
        if stateSaveWaiters.isEmpty {
            stateSaveInProgress = false
        } else {
            stateSaveWaiters.removeFirst().resume()
        }
    }

    private func pendingGroupAdmission(
        _ admissionID: UUID
    ) throws -> PendingGroupAdmissionV2 {
        guard let admission = state.activePersona.pendingGroupAdmissions.first(where: {
            $0.id == admissionID
        }) else {
            throw HeadlessMessagingClientError.groupAdmissionNotFound
        }
        return admission
    }

    private func requiredPendingGroupAdmissionRoute(
        _ admission: PendingGroupAdmissionV2
    ) throws -> PendingLocalOpaqueReceiveRouteV2 {
        guard let route = admission.pendingRoute else {
            throw HeadlessMessagingClientError.invalidState
        }
        return route
    }

    private func requiredGroupAdmissionRouteSet(
        _ admission: PendingGroupAdmissionV2
    ) throws -> SignedGroupOpaqueRouteSetV2 {
        guard let routeSet = admission.advertisedRouteSet else {
            throw HeadlessMessagingClientError.invalidState
        }
        return routeSet
    }

    private func persistPendingGroupAdmission(
        _ admission: PendingGroupAdmissionV2,
        expected: PendingGroupAdmissionV2
    ) async throws {
        guard admission.id == expected.id,
              admission.groupID == expected.groupID,
              try admission.isStructurallyValidThrowing else {
            throw HeadlessMessagingClientError.invalidState
        }
        try await withStateSaveLock {
            guard state.activePersona.pendingGroupAdmissions.contains(expected) else {
                throw HeadlessMessagingClientError.groupAdmissionNotFound
            }
            var candidate = state
            try candidate.updateActivePersona { persona in
                try persona.replace(pendingGroupAdmission: admission)
            }
            guard try candidate.isStructurallyValidThrowing else {
                throw HeadlessMessagingClientError.invalidState
            }
            try await stateStore.save(candidate)
            state = candidate
        }
    }

    /// Performs the cryptographic join against an isolated volatile store,
    /// then installs the resulting runtime and removes exactly this admission
    /// in one client-state save. Other pending admissions remain untouched.
    private func completePendingGroupAdmissionIfReady(
        _ admissionID: UUID
    ) async throws -> HeadlessGroupAdmissionProgressV2 {
        let admission = try pendingGroupAdmission(admissionID)
        guard admission.isReadyToJoin else {
            return HeadlessGroupAdmissionProgressV2(admission)
        }
        guard let anchor = admission.anchor,
              let transition = admission.transition,
              let welcome = admission.welcome,
              let observedAt = admission.completionObservedAt else {
            throw HeadlessMessagingClientError.invalidState
        }
        let volatile = VolatileGroupJoinPersistenceV2()
        let joinedRuntime = try await NoctweavePQGroupRuntimeV2.join(
            anchor: anchor,
            transition: transition,
            welcome: welcome,
            localCredential: admission.localCredential,
            observedAt: observedAt,
            persistence: volatile
        )
        let joined = await joinedRuntime.snapshot().replacing(
            inboundTransport: try admission.inboundTransportState()
        )
        guard try joined.isStructurallyValidThrowing else {
            throw HeadlessMessagingClientError.invalidState
        }

        try await withStateSaveLock {
            guard state.activePersona.pendingGroupAdmissions.contains(admission),
                  !state.activePersona.groupRuntimes.contains(where: {
                      $0.groupId == admission.groupID
                  }) else {
                throw HeadlessMessagingClientError.groupAdmissionNotFound
            }
            var candidate = state
            try candidate.updateActivePersona { persona in
                guard persona.removePendingGroupAdmission(id: admission.id) == admission else {
                    throw PersonaProfileV1Error.invalidState
                }
                try persona.upsert(groupRuntime: joined)
            }
            guard try candidate.isStructurallyValidThrowing else {
                throw HeadlessMessagingClientError.invalidState
            }
            try await stateStore.save(candidate)
            state = candidate
        }
        return HeadlessGroupAdmissionProgressV2(admission, completed: true)
    }

    private func commitRelationship(
        _ relationship: PairwiseRelationshipV2
    ) async throws {
        var compacted = relationship
        try compacted.compactDurableState()
        try await withStateSaveLock {
            guard state.activePersona.relationships.contains(where: {
                $0.id == compacted.id
            }) else {
                throw HeadlessMessagingClientError.relationshipNotFound
            }
            var candidate = state
            try candidate.updateActivePersona { persona in
                try persona.upsert(relationship: compacted)
            }
            guard try candidate.isStructurallyValidThrowing else {
                throw HeadlessMessagingClientError.invalidState
            }
            try await stateStore.save(candidate)
            state = candidate
        }
    }

    private func completedIntentIDs(
        in relationship: PairwiseRelationshipV2
    ) -> Set<UUID> {
        Set(relationship.protocolIntents.filter {
            $0.state == .finalized
        }.map(\.id))
    }

    private func beginIntentAttempt(
        intentID: UUID,
        relationshipID: UUID,
        at date: Date
    ) async throws -> UUID? {
        var relationship = try relationship(relationshipID)
        guard let index = relationship.protocolIntents.firstIndex(where: {
            $0.id == intentID
        }) else { throw HeadlessMessagingClientError.invalidState }
        let current = relationship.protocolIntents[index]
        if current.state.isTerminal { return nil }
        let transitionAt = max(date, current.updatedAt)
        if let expired = current.expiring(at: transitionAt) {
            relationship.protocolIntents[index] = expired
            try await commitRelationship(relationship)
            return nil
        }
        if let exhausted = current.exhaustingAttempts(at: transitionAt) {
            relationship.protocolIntents[index] = exhausted
            try await commitRelationship(relationship)
            return nil
        }
        let attemptID = UUID()
        guard let begun = current.beginningAttempt(
            id: attemptID,
            completedIntentIds: completedIntentIDs(in: relationship),
            at: transitionAt
        ) else { return nil }
        relationship.protocolIntents[index] = begun
        try await commitRelationship(relationship)
        return attemptID
    }

    private func finishIntentFailure(
        intentID: UUID,
        relationshipID: UUID,
        attemptID: UUID,
        errorClass: ProtocolIntentErrorClassV2,
        at date: Date
    ) async throws {
        var relationship = try relationship(relationshipID)
        guard let index = relationship.protocolIntents.firstIndex(where: {
            $0.id == intentID
        }) else { throw HeadlessMessagingClientError.invalidState }
        let current = relationship.protocolIntents[index]
        let transitionAt = max(date, current.updatedAt)
        if !errorClass.isRetryable {
            guard let failed = current.failingPermanently(
                errorClass: errorClass,
                at: transitionAt
            ) else { throw HeadlessMessagingClientError.invalidState }
            relationship.protocolIntents[index] = failed
        } else if current.attemptCount
                    >= UInt32(NoctweaveArchitectureV2.maximumIntentAttempts) {
            guard let failed = current.exhaustingAttempts(at: transitionAt) else {
                throw HeadlessMessagingClientError.invalidState
            }
            relationship.protocolIntents[index] = failed
        } else {
            guard let failed = current.recordingTransientFailure(
                attemptId: attemptID,
                errorClass: errorClass,
                retryNotBefore: transitionAt.addingTimeInterval(
                    protocolRetryDelay(after: current.attemptCount)
                ),
                at: transitionAt
            ) else { throw HeadlessMessagingClientError.invalidState }
            relationship.protocolIntents[index] = failed
        }
        try await commitRelationship(relationship)
    }

    private func relayClient(for endpoint: RelayEndpoint) -> RelayClient {
        let token = state.relayPreferences.first(where: {
            $0.endpoint == endpoint
        })?.accessPassword
        return RelayClient(endpoint: endpoint, authToken: token)
    }

    private func groupAuthorizationProofExpired(
        _ packet: OpaqueRoutePacketV2,
        at date: Date
    ) -> Bool {
        let expiry = packet.authorization.authorizedAt.addingTimeInterval(
            NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew
        )
        return expiry.timeIntervalSince1970.isFinite && expiry < date
    }

    private func strongerGroupTransportDisposition(
        _ current: HeadlessGroupTransportDispositionV2?,
        _ candidate: HeadlessGroupTransportDispositionV2
    ) -> HeadlessGroupTransportDispositionV2 {
        func priority(_ value: HeadlessGroupTransportDispositionV2) -> Int {
            switch value {
            case .complete: return 0
            case .pendingRetry: return 1
            case .relayRejected: return 2
            case .invalidRelayResponse: return 3
            case .authorizationRecoveryRequired: return 4
            }
        }
        guard let current else { return candidate }
        return priority(candidate) > priority(current) ? candidate : current
    }

    private func fullyAcceptedGroupCredentialHandles(
        _ operation: GroupOpaqueRouteOutboundOperationV2
    ) -> [GroupScopedCredentialHandleV2] {
        operation.destinationSnapshots.compactMap { snapshot in
            let handle = snapshot.credential.credentialHandle
            let requiredDeliveries = operation.deliveries.filter {
                $0.requiredCredentialHandles.contains(handle)
            }
            guard !requiredDeliveries.isEmpty,
                  requiredDeliveries.allSatisfy({ delivery in
                      delivery.attempts.contains {
                          $0.publication.destinationCredentialHandle == handle
                              && $0.acceptance != nil
                      }
                  }) else {
                return nil
            }
            return handle
        }.sorted { $0.rawValue < $1.rawValue }
    }

    private func persistGroupRuntime(
        _ record: GroupRuntimeRecord,
        expectedCurrentRecord: GroupRuntimeRecord,
        originatingPersonaID: UUID
    ) async throws {
        guard try record.isStructurallyValidThrowing else {
            throw HeadlessMessagingClientError.invalidState
        }
        try await withStateSaveLock {
            guard state.activePersonaID == originatingPersonaID else {
                throw HeadlessMessagingClientError.invalidState
            }
            guard state.activePersona.groupRuntimes.first(where: {
                $0.groupId == record.groupId
            }) == expectedCurrentRecord else {
                throw HeadlessMessagingClientError.staleGroupRuntime
            }
            var candidate = state
            try candidate.updateActivePersona { persona in
                try persona.upsert(groupRuntime: record)
            }
            guard try candidate.isStructurallyValidThrowing else {
                throw HeadlessMessagingClientError.invalidState
            }
            try await stateStore.save(candidate)
            state = candidate
        }
    }
}

private enum HeadlessTransactionContext {
    @TaskLocal static var relationshipIDs: Set<UUID> = []
    @TaskLocal static var groupIDs: Set<UUID> = []
}

private actor HeadlessGroupRuntimePersistence: GroupRuntimeRecordPersistence {
    private var record: GroupRuntimeRecord
    private let saveHandler:
        @Sendable (GroupRuntimeRecord, GroupRuntimeRecord) async throws -> Void

    init(
        initialRecord: GroupRuntimeRecord,
        saveHandler: @escaping @Sendable (
            GroupRuntimeRecord,
            GroupRuntimeRecord
        ) async throws -> Void
    ) {
        record = initialRecord
        self.saveHandler = saveHandler
    }

    func load() async throws -> GroupRuntimeRecord? { record }

    func save(_ record: GroupRuntimeRecord) async throws {
        guard try record.isStructurallyValidThrowing else {
            throw GroupRuntimeError.invalidRecord
        }
        let expected = self.record
        try await saveHandler(expected, record)
        self.record = record
    }
}

private extension RelationshipControlKindV2 {
    var isRelationshipMaintenanceV2: Bool {
        switch self {
        case .routeSetUpdate, .routeProbe, .endpointPrekeyUpdate:
            return true
        case .sessionReset, .resendRequest, .continuityOffer:
            return false
        }
    }
}
