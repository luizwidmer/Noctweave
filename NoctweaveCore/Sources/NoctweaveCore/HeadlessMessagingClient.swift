import CryptoKit
import Foundation

public enum HeadlessMessagingClientError: Error, Equatable {
    case invalidState
    case relationshipNotFound
    case relayRejected
    case invalidRelayResponse
    case noUsableRoute
    case conflictingEnvelope
    case incompleteBundle
    case continuityNotAllowed
    case routeGapDetected
    case unsupportedContentType
    case relationshipConsentRequired
    case relationshipBlocked
    case receiptDisabled
}

public struct HeadlessSendResult: Codable, Equatable {
    public let event: ConversationEvent
    public let envelope: DirectEnvelopeV4
    public let acceptedDeliveryCount: Int
    public let pendingDeliveryCount: Int
}

public struct HeadlessSyncResult: Codable, Equatable {
    public let relationshipID: UUID
    public let receivedEvents: [ConversationEvent]
    public let committedCursor: OpaqueRouteCursorV2?
    public let hasMore: Bool
}

/// Public headless client for the clean 1.0 architecture. A persona is local
/// organization only; all cryptographic state and delivery authority is scoped
/// to a `PairwiseRelationshipV2`.
public actor HeadlessMessagingClient {
    private var state: ClientState
    private let stateStore: ClientStateStore
    private var sessionsByID: [String: Conversation] = [:]
    private var reassemblersByRoute: [OpaqueReceiveRouteIDV2: OpaqueRoutePacketReassemblerV2] = [:]

    public init(
        stateStore: ClientStateStore,
        initialState: ClientState
    ) throws {
        guard initialState.isStructurallyValid else {
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
        consent: RelationshipConsentStateV2 = .accepted
    ) async throws {
        var relationship = relationship
        relationship.localPolicy.consent = consent
        guard relationship.isStructurallyValid else {
            throw HeadlessMessagingClientError.invalidState
        }
        try state.updateActivePersona { persona in
            try persona.upsert(relationship: relationship)
        }
        try await persist()
    }

    /// Updates only local presentation/consent policy for one unlinkable
    /// relationship. No control event or relay-visible metadata is emitted.
    public func setRelationshipLocalPolicy(
        _ policy: RelationshipLocalPolicyV2,
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws {
        guard policy.isStructurallyValid,
              date.timeIntervalSince1970.isFinite else {
            throw HeadlessMessagingClientError.invalidState
        }
        var relationship = try relationship(relationshipID)
        relationship.localPolicy = policy
        if policy.consent == .blocked {
            relationship.pendingDeliveries.removeAll(keepingCapacity: false)
            for index in relationship.protocolIntents.indices
                where !relationship.protocolIntents[index].state.isTerminal
                    && (relationship.protocolIntents[index].kind == .sendEvent
                        || relationship.protocolIntents[index].kind == .publishContinuity) {
                if let failed = relationship.protocolIntents[index].failingPermanently(
                    errorClass: .authorizationRejected,
                    at: max(date, relationship.protocolIntents[index].updatedAt)
                ) {
                    relationship.protocolIntents[index] = failed
                }
            }
            sessionsByID = sessionsByID.filter { $0.value.relationshipID != relationshipID }
        }
        try replaceRelationship(relationship)
        try await persist()
    }

    /// Blocking succeeds locally before any network action. Relay teardown is
    /// best-effort and relationship-scoped; failed routes remain available for
    /// a later retry without re-enabling message processing.
    @discardableResult
    public func blockRelationship(
        _ relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> [OpaqueReceiveRouteIDV2] {
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

    public func addGroupRuntime(_ record: GroupRuntimeRecord) async throws {
        guard record.isStructurallyValid else {
            throw HeadlessMessagingClientError.invalidState
        }
        try state.updateActivePersona { persona in
            try persona.upsert(groupRuntime: record)
        }
        try await persist()
    }

    /// Opens the group runtime against this client's encrypted state store.
    /// The returned actor remains group-scoped and transport-independent; every
    /// mutation is written back atomically to the active local persona.
    public func openGroupRuntime(
        groupID: UUID
    ) throws -> NoctweavePQGroupRuntimeV2 {
        guard let record = state.activePersona.groupRuntimes.first(where: {
            $0.groupId == groupID
        }) else {
            throw HeadlessMessagingClientError.invalidState
        }
        let persistence = HeadlessGroupRuntimePersistence(
            initialRecord: record,
            saveHandler: { [self] updated in
                try await persistGroupRuntime(updated)
            }
        )
        return try NoctweavePQGroupRuntimeV2(
            record: record,
            persistence: persistence
        )
    }

    /// Publishes a previously persisted group fanout plan. A credential is
    /// reported accepted when at least one of its opaque routes durably accepts
    /// every packet; redundant routes are availability copies, not extra
    /// membership identities.
    public func publishGroupFanoutPlan(
        _ plan: GroupOpaqueRouteFanoutPlanV2
    ) async throws -> [GroupScopedCredentialHandleV2] {
        guard plan.isStructurallyValid else {
            throw HeadlessMessagingClientError.invalidState
        }
        var accepted = Set<GroupScopedCredentialHandleV2>()
        for publication in plan.publications {
            var routeAccepted = true
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
                    guard case .opaqueRouteAppend = response.successBody else {
                        routeAccepted = false
                        break
                    }
                } catch {
                    routeAccepted = false
                    break
                }
            }
            if routeAccepted {
                accepted.insert(publication.destinationCredentialHandle)
            }
        }
        return accepted.sorted { $0.rawValue < $1.rawValue }
    }

    public func setContinuityPolicy(
        _ policy: RelationshipContinuityPolicyV2,
        relationshipID: UUID
    ) async throws {
        var relationship = try relationship(relationshipID)
        relationship.continuityPolicy = policy
        try replaceRelationship(relationship)
        try await persist()
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
        relay: RelayEndpoint,
        policy: OpaqueRoutePolicyV2 = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .sixHours,
            quotaBucket: .packets256
        ),
        createdAt: Date = Date()
    ) throws -> PendingLocalOpaqueReceiveRouteV2 {
        try PendingLocalOpaqueReceiveRouteV2.prepare(
            relay: relay,
            policy: policy,
            createdAt: createdAt
        )
    }

    /// Creates a replacement route, adds it as testing state, journals the
    /// mutation, and publishes the signed route-set successor through the old
    /// working path. The old route remains active until a targeted probe is
    /// received on the replacement route.
    public func beginRouteRollover(
        _ pending: PendingLocalOpaqueReceiveRouteV2,
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> HeadlessSendResult {
        var relationship = try relationship(relationshipID)
        guard pending.isStructurallyValid,
              relationship.localReceiveRoutes.count
                < PairwiseRelationshipV2.maximumReceiveRoutes,
              !relationship.localReceiveRoutes.contains(where: {
                  $0.route.routeID == pending.clientCapabilities.routeID
              }) else {
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
        guard case .opaqueRoute(let createdRoute)? = response.successBody else {
            throw HeadlessMessagingClientError.relayRejected
        }
        let localRoute = try pending.activate(createdRoute: createdRoute)
        let advertised = try localRoute.peerSendRoute(state: .testing)
        let successor = try relationship.localAdvertisedRoutes.addingTestingRoute(
            advertised,
            signingKey: relationship.localIdentity.localEndpoint.signingKey,
            issuedAt: date
        )
        relationship.localReceiveRoutes.append(localRoute)
        relationship.localAdvertisedRoutes = successor
        guard let digest = successor.digest else {
            throw HeadlessMessagingClientError.invalidState
        }
        _ = try relationship.appendProtocolIntent(.prepare(
            kind: .rolloverRoute,
            targetIdentifier: pending.clientCapabilities.routeID.rawValue,
            expectedEpoch: successor.revision,
            payloadDigest: digest,
            createdAt: date,
            expiresAt: createdRoute.lease.expiresAt
        ))
        try replaceRelationship(relationship)
        try await persist()
        return try await publishLocalRouteSet(
            relationshipID: relationshipID,
            sentAt: date
        )
    }

    public func publishLocalRouteSet(
        relationshipID: UUID,
        sentAt: Date = Date()
    ) async throws -> HeadlessSendResult {
        let relationship = try relationship(relationshipID)
        return try await sendRelationshipControl(
            kind: .routeSetUpdate,
            payload: RelationshipRouteSetUpdateV2(
                relationshipID: relationshipID,
                routeSet: relationship.localAdvertisedRoutes
            ),
            relationshipID: relationshipID,
            sentAt: sentAt
        )
    }

    /// Rotates only the short-lived prekey of this relationship endpoint and
    /// publishes the refreshed binding through the established relationship.
    /// No persona-wide key or cross-relationship identifier exists.
    public func renewRelationshipPrekeyIfNeeded(
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> HeadlessSendResult? {
        var relationship = try relationship(relationshipID)
        guard try relationship.localIdentity.renewEndpointPrekeyIfNeeded(at: date) else {
            return nil
        }
        let bindingData = try NoctweaveCoder.encode(
            relationship.localIdentity.endpointBinding,
            sortedKeys: true
        )
        let intent = ProtocolIntentV2.prepare(
            kind: .renewRelationshipPrekey,
            targetIdentifier: Data(relationship.localEndpointHandle.rawValue.utf8),
            payloadDigest: Data(SHA256.hash(data: bindingData)),
            createdAt: date,
            expiresAt: date.addingTimeInterval(24 * 60 * 60)
        )
        _ = try relationship.appendProtocolIntent(intent)
        try replaceRelationship(relationship)
        try await persist()
        let sent = try await publishCurrentRelationshipPrekey(
            relationshipID: relationshipID,
            sentAt: date
        )
        if sent.acceptedDeliveryCount > 0 {
            var current = try relationship(relationshipID)
            try finalizeProtocolIntent(
                id: intent.id,
                relationship: &current,
                at: Date()
            )
            try replaceRelationship(current)
            try await persist()
        }
        return sent
    }

    public func publishCurrentRelationshipPrekey(
        relationshipID: UUID,
        sentAt: Date = Date()
    ) async throws -> HeadlessSendResult {
        let relationship = try relationship(relationshipID)
        return try await sendRelationshipControl(
            kind: .endpointPrekeyUpdate,
            payload: RelationshipEndpointPrekeyUpdateV2(
                relationshipID: relationshipID,
                endpointBinding: relationship.localIdentity.endpointBinding
            ),
            relationshipID: relationshipID,
            sentAt: sentAt
        )
    }

    /// Revokes routes whose overlap window has elapsed, publishes each signed
    /// successor before teardown, then erases the local route capability only
    /// after the relay confirms teardown.
    public func finalizeDrainedRoutes(
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> [OpaqueReceiveRouteIDV2] {
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
                try replaceRelationship(relationship)
                try await persist()
            }
            let published = try await publishLocalRouteSet(
                relationshipID: relationshipID,
                sentAt: date
            )
            guard published.acceptedDeliveryCount > 0 else { break }

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
            try replaceRelationship(relationship)
            try await persist()
            finalized.append(candidate.routeID)
        }
        return finalized
    }

    /// Tears down only the blocked relationship's opaque receive routes. The
    /// signed route snapshot is retained as historical relationship evidence,
    /// while successfully torn-down capability material is removed locally.
    @discardableResult
    public func teardownBlockedRelationshipRoutes(
        relationshipID: UUID,
        at date: Date = Date()
    ) async throws -> [OpaqueReceiveRouteIDV2] {
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
                try replaceRelationship(relationship)
                try await persist()
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
        try await send(
            body: .text(text),
            relationshipID: relationshipID,
            sentAt: sentAt
        )
    }

    public func sendAttachment(
        _ descriptor: AttachmentDescriptor,
        relationshipID: UUID,
        sentAt: Date = Date()
    ) async throws -> HeadlessSendResult {
        try await send(
            body: .attachment(descriptor),
            relationshipID: relationshipID,
            sentAt: sentAt
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
        var relationship = try relationship(relationshipID)
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
        return try await persistAndPublish(
            wirePayload: wirePayload,
            event: controlAuditEvent(
                control,
                relationship: relationship,
                createdAt: sentAt
            ),
            relationship: &relationship,
            destinationRouteIDs: destinationRouteIDs,
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
        relationshipID: UUID
    ) async throws -> Int {
        guard try relationship(relationshipID).localPolicy.allowsUserSending else {
            throw HeadlessMessagingClientError.relationshipConsentRequired
        }
        try await publishPendingDeliveries(relationshipID: relationshipID)
    }

    public func sync(
        relationshipID: UUID,
        maximumPackets: UInt16 = UInt16(NoctweaveOpaqueRouteRelayStoreV2.maximumSyncPage)
    ) async throws -> [HeadlessSyncResult] {
        var results: [HeadlessSyncResult] = []
        let relationship = try relationship(relationshipID)
        for routeIndex in relationship.localReceiveRoutes.indices {
            results.append(try await syncRoute(
                relationshipID: relationshipID,
                routeIndex: routeIndex,
                maximumPackets: maximumPackets
            ))
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
        guard let index = state.personas.firstIndex(where: {
            $0.id == state.activePersonaID
        }) else {
            throw HeadlessMessagingClientError.invalidState
        }
        state.personas[index] = replacement
        state.activePersonaID = replacement.id
        sessionsByID.removeAll(keepingCapacity: false)
        reassemblersByRoute.removeAll(keepingCapacity: false)
        try await persist()
        return replacement
    }

    private func send(
        body: MessageBody,
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
        let eventID = UUID()
        let transactionID = UUID()
        let wirePayload = try WirePayloadV2.projectingMessageBody(
            body,
            eventId: eventID,
            clientTransactionId: transactionID,
            conversationId: relationship.conversationID,
            authorEndpointHandle: relationship.localEndpointHandle,
            createdAt: sentAt
        )
        guard let event = wirePayload.application else {
            throw HeadlessMessagingClientError.invalidState
        }
        return try await persistAndPublish(
            wirePayload: wirePayload,
            event: event,
            relationship: &relationship,
            sentAt: sentAt
        )
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
        sentAt: Date
    ) async throws -> HeadlessSendResult {
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
        if let existing = sessionsByID.values.first(where: {
            $0.relationshipID == relationship.id
        }) {
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
        guard try relationship.appendEvent(event) else {
            throw HeadlessMessagingClientError.conflictingEnvelope
        }
        let intent = ProtocolIntentV2.prepare(
            kind: .sendEvent,
            targetIdentifier: Data(event.id.uuidString.lowercased().utf8),
            payloadDigest: Data(SHA256.hash(data: envelopeBytes)),
            createdAt: sentAt,
            expiresAt: sentAt.addingTimeInterval(24 * 60 * 60)
        )
        _ = try relationship.appendProtocolIntent(intent)
        let deliveries = try relationship.enqueue(
            logicalEventID: event.id,
            payload: envelopeBytes,
            destinationRouteIDs: destinationRouteIDs,
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
        try replaceRelationship(relationship)
        sessionsByID[conversation.sessionId] = conversation
        try await persist()

        let accepted = try await publishPendingDeliveries(
            relationshipID: relationship.id
        )
        let current = try self.relationship(relationship.id)
        return HeadlessSendResult(
            event: event,
            envelope: envelope,
            acceptedDeliveryCount: accepted,
            pendingDeliveryCount: current.pendingDeliveries.count
        )
    }

    private func publishPendingDeliveries(
        relationshipID: UUID
    ) async throws -> Int {
        var relationship = try relationship(relationshipID)
        guard relationship.localPolicy.allowsUserSending else {
            if relationship.localPolicy.consent == .blocked {
                throw HeadlessMessagingClientError.relationshipBlocked
            }
            throw HeadlessMessagingClientError.relationshipConsentRequired
        }
        var acceptedIDs = Set<UUID>()
        let now = Date()
        let sendCapabilities = Dictionary(
            uniqueKeysWithValues: relationship.peerIdentity.sendRoutes.routes.map {
                ($0.routeID, $0.sendCapability)
            }
        )
        guard relationship.pendingDeliveries.allSatisfy({
            sendCapabilities[$0.destinationRouteID] != nil
        }) else {
            throw HeadlessMessagingClientError.invalidState
        }
        for deliveryIndex in relationship.pendingDeliveries.indices {
            let delivery = relationship.pendingDeliveries[deliveryIndex]
            guard let sendCapability = sendCapabilities[delivery.destinationRouteID] else {
                throw HeadlessMessagingClientError.invalidState
            }
            var accepted = true
            for packet in delivery.packets {
                do {
                    let response = try await relayClient(
                        for: delivery.destinationRelay
                    ).send(.appendOpaqueRouteV2(
                        AppendOpaqueRouteRelayRequestV2(
                            packet: packet,
                            sendCapability: sendCapability
                        )
                    ))
                    guard case .opaqueRouteAppend = response.successBody else {
                        accepted = false
                        break
                    }
                } catch {
                    accepted = false
                    break
                }
            }
            if relationship.pendingDeliveries[deliveryIndex].attemptCount < UInt32.max {
                relationship.pendingDeliveries[deliveryIndex].attemptCount += 1
            }
            relationship.pendingDeliveries[deliveryIndex].lastAttemptAt = max(
                now,
                delivery.queuedAt
            )
            if accepted { acceptedIDs.insert(delivery.id) }
        }

        if !acceptedIDs.isEmpty {
            let acceptedEvents = Set(relationship.pendingDeliveries
                .filter { acceptedIDs.contains($0.id) }
                .map(\.logicalEventID))
            relationship.pendingDeliveries.removeAll { acceptedIDs.contains($0.id) }
            let fullyAcceptedEvents = acceptedEvents.filter { eventID in
                !relationship.pendingDeliveries.contains { $0.logicalEventID == eventID }
            }
            for index in relationship.deliveryStates.indices
                where acceptedEvents.contains(relationship.deliveryStates[index].eventId) {
                _ = relationship.deliveryStates[index].advance(
                    to: .relayAccepted,
                    at: max(now, relationship.deliveryStates[index].updatedAt)
                )
            }
            for index in relationship.protocolIntents.indices
                where relationship.protocolIntents[index].kind == .sendEvent
                    && !relationship.protocolIntents[index].state.isTerminal
                    && relationship.protocolIntents[index].targetIdentifier.flatMap({
                        UUID(uuidString: String(decoding: $0, as: UTF8.self))
                    }).map(fullyAcceptedEvents.contains) == true {
                let attemptID = UUID()
                let transitionAt = max(now, relationship.protocolIntents[index].updatedAt)
                guard let begun = relationship.protocolIntents[index].beginningAttempt(
                    id: attemptID,
                    completedIntentIds: completedIntentIDs(in: relationship),
                    at: transitionAt
                ), let published = begun.advancing(to: .published, attemptId: attemptID, at: transitionAt),
                   let committed = published.advancing(to: .committed, attemptId: attemptID, at: transitionAt),
                   let finalized = committed.advancing(to: .finalized, attemptId: attemptID, at: transitionAt) else {
                    continue
                }
                relationship.protocolIntents[index] = finalized
            }
        }
        try replaceRelationship(relationship)
        try await persist()
        return acceptedIDs.count
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
        if let gap = opaqueRouteGap(
            in: batch,
            relativeTo: route,
            detectedAt: Date()
        ) {
            relationship.localReceiveRoutes[routeIndex].gapState = gap
            try replaceRelationship(relationship)
            try await persist()
            throw HeadlessMessagingClientError.routeGapDetected
        }

        var reassembler = try reassemblersByRoute[route.route.routeID]
            ?? OpaqueRoutePacketReassemblerV2()
        var workingSessions = sessionsByID
        var received: [ConversationEvent] = []
        for receivedPacket in batch.packets {
            switch try reassembler.consume(
                receivedPacket.packet,
                payloadKey: route.payloadKey,
                routeRevision: receivedPacket.routeRevision
            ) {
            case .accepted, .duplicate:
                continue
            case .complete(let bundle):
                if relationship.localPolicy.acceptsInboundEvents {
                    if let event = try processInboundBundle(
                        bundle,
                        sourceRouteID: route.route.routeID,
                        relationship: &relationship,
                        sessions: &workingSessions
                    ) {
                        received.append(event)
                    }
                }
            }
        }
        reassemblersByRoute[route.route.routeID] = reassembler
        sessionsByID = workingSessions
        try replaceRelationship(relationship)
        try await persist()

        if relationship.localPolicy.consent != .blocked {
            for eventID in deliveryReceiptTargets(in: relationship) {
                _ = try await sendReceipt(
                    type: .deliveryReceipt,
                    targetEventID: eventID,
                    relationshipID: relationshipID,
                    sentAt: Date()
                )
            }
            relationship = try self.relationship(relationshipID)
            for probe in routeProbesToSend(in: relationship) {
                _ = try await sendRelationshipControl(
                    kind: .routeProbe,
                    payload: probe,
                    relationshipID: relationshipID,
                    destinationRouteIDs: [probe.routeID],
                    sentAt: Date()
                )
            }
            relationship = try self.relationship(relationshipID)
            if localRouteSetNeedsPublication(in: relationship) {
                _ = try await publishLocalRouteSet(
                    relationshipID: relationshipID,
                    sentAt: Date()
                )
            }
        }
        relationship = try self.relationship(relationshipID)

        guard reassembler.pendingBundleCount == 0 else {
            return HeadlessSyncResult(
                relationshipID: relationshipID,
                receivedEvents: received,
                committedCursor: route.committedCursor,
                hasMore: true
            )
        }
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
        relationship.localReceiveRoutes[routeIndex].committedCursor = batch.nextCursor
        relationship.localReceiveRoutes[routeIndex].committedSequence = batch.nextSequence
        relationship.localReceiveRoutes[routeIndex].committedRecordDigest = batch.nextRecordDigest
        try replaceRelationship(relationship)
        try await persist()
        return HeadlessSyncResult(
            relationshipID: relationshipID,
            receivedEvents: received,
            committedCursor: batch.nextCursor,
            hasMore: batch.hasMore
        )
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

    private func processInboundBundle(
        _ bundle: OpaqueRouteReassembledBundleV2,
        sourceRouteID: OpaqueReceiveRouteIDV2,
        relationship: inout PairwiseRelationshipV2,
        sessions: inout [String: Conversation]
    ) throws -> ConversationEvent? {
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
        if let existing = sessions[envelope.sessionId] {
            conversation = existing
        } else {
            guard envelope.bootstrap.signedPrekeyMaterial != nil else {
                throw HeadlessMessagingClientError.invalidState
            }
            conversation = try MessageEngine.createInboundEndpointSession(
                relationship: relationship,
                bootstrap: envelope.bootstrap,
                now: envelope.sentAt
            )
            guard conversation.sessionId == envelope.sessionId else {
                throw HeadlessMessagingClientError.conflictingEnvelope
            }
        }
        let result = try MessageEngine.decryptDirectV4(
            envelope: envelope,
            relationship: relationship,
            conversation: &conversation
        )
        let event: ConversationEvent
        switch result.disposition {
        case .application(let application, let projection):
            event = application
            switch projection {
            case .deliveryReceipt(let receipt):
                try applyPeerReceipt(
                    receipt,
                    state: .peerStored,
                    event: application,
                    relationship: &relationship
                )
            case .readReceipt(let receipt):
                try applyPeerReceipt(
                    receipt,
                    state: .peerRead,
                    event: application,
                    relationship: &relationship
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
            case .routeSetUpdate(let update):
                try applyPeerRouteSetUpdate(update, relationship: &relationship)
            case .routeProbe(let probe):
                try applyRouteProbe(
                    probe,
                    sourceRouteID: sourceRouteID,
                    receivedAt: auditEvent.createdAt,
                    relationship: &relationship
                )
            case .endpointPrekeyUpdate(let update):
                try applyPeerPrekeyUpdate(update, relationship: &relationship)
            case .resendRequest, .continuityOffer:
                break
            }
        case .quarantinedControl(let quarantine):
            event = quarantine.event
        }
        _ = try relationship.appendEvent(event)
        _ = try relationship.recordInboundReceipt(
            InboundEnvelopeReceiptV2(
                sourceScopeId: relationship.id,
                logicalEventId: envelope.eventId,
                envelopeId: envelope.id,
                envelopeDigest: digest,
                processedAt: Date()
            )
        )
        conversation.markMessageProcessed()
        sessions[conversation.sessionId] = conversation
        return event
    }

    private func applyPeerReceipt(
        _ receipt: EventReceiptContentV1,
        state: MessageDeliveryState,
        event: ConversationEvent,
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
                at: max(event.createdAt, relationship.deliveryStates[index].updatedAt)
            )
        }
    }

    private func applyPeerRouteSetUpdate(
        _ update: RelationshipRouteSetUpdateV2,
        relationship: inout PairwiseRelationshipV2
    ) throws {
        guard update.relationshipID == relationship.id,
              update.routeSet.ownerEndpointHandle
                == relationship.peerIdentity.sendRoutes.ownerEndpointHandle else {
            throw HeadlessMessagingClientError.conflictingEnvelope
        }
        if update.routeSet == relationship.peerIdentity.sendRoutes { return }
        guard update.routeSet.isValidSuccessor(
            of: relationship.peerIdentity.sendRoutes,
            ownerSigningPublicKey: relationship.peerIdentity.endpointBinding.signingPublicKey
        ) else {
            throw HeadlessMessagingClientError.conflictingEnvelope
        }
        relationship.peerIdentity.sendRoutes = update.routeSet
    }

    private func applyPeerPrekeyUpdate(
        _ update: RelationshipEndpointPrekeyUpdateV2,
        relationship: inout PairwiseRelationshipV2
    ) throws {
        guard update.relationshipID == relationship.id else {
            throw HeadlessMessagingClientError.conflictingEnvelope
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
              candidate.prekeyBundle.createdAt > current.prekeyBundle.createdAt,
              (try? candidate.verified(
                  authoritySigningPublicKey: relationship.peerIdentity.signingPublicKey,
                  now: candidate.prekeyBundle.createdAt
              )) != nil else {
            throw HeadlessMessagingClientError.conflictingEnvelope
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
            throw HeadlessMessagingClientError.conflictingEnvelope
        }
        let replaced = relationship.localAdvertisedRoutes.routes.compactMap {
            $0.state == .active ? $0.routeID : nil
        }
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
            try finalizeProtocolIntent(
                id: intent.id,
                relationship: &relationship,
                at: receivedAt
            )
        }
    }

    private func routeProbesToSend(
        in relationship: PairwiseRelationshipV2
    ) -> [RelationshipRouteProbeV2] {
        let sent = Set(relationship.events.compactMap { event -> String? in
            guard event.authorEndpointHandle == relationship.localEndpointHandle,
                  event.kind == .control,
                  event.content.type == RelationshipControlKindV2.routeProbe.contentType,
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
            guard route.state == .testing, !sent.contains(key) else { return nil }
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
        return !relationship.events.contains { event in
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
        }
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
                  let receipt = try? NoctweaveCoder.decode(
                      EventReceiptContentV1.self,
                      from: event.content.payload
                  ) else {
                return false
            }
            return receipt.targetEventId == targetEventID
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

    private func replaceRelationship(_ relationship: PairwiseRelationshipV2) throws {
        var compacted = relationship
        try compacted.compactDurableState()
        try state.updateActivePersona { persona in
            try persona.upsert(relationship: compacted)
        }
    }

    private func completedIntentIDs(
        in relationship: PairwiseRelationshipV2
    ) -> Set<UUID> {
        Set(relationship.protocolIntents.filter {
            $0.state == .finalized
        }.map(\.id))
    }

    private func finalizeProtocolIntent(
        id: UUID,
        relationship: inout PairwiseRelationshipV2,
        at date: Date
    ) throws {
        guard let index = relationship.protocolIntents.firstIndex(where: {
            $0.id == id
        }) else {
            throw HeadlessMessagingClientError.invalidState
        }
        let current = relationship.protocolIntents[index]
        if current.state == .finalized { return }
        let attemptID = current.lastAttemptId ?? UUID()
        guard let begun = current.beginningAttempt(
            id: attemptID,
            completedIntentIds: completedIntentIDs(in: relationship),
            at: max(date, current.updatedAt)
        ), let published = begun.advancing(
            to: .published,
            attemptId: attemptID,
            at: max(date, begun.updatedAt)
        ), let committed = published.advancing(
            to: .committed,
            attemptId: attemptID,
            at: max(date, published.updatedAt)
        ), let finalized = committed.advancing(
            to: .finalized,
            attemptId: attemptID,
            at: max(date, committed.updatedAt)
        ) else {
            throw HeadlessMessagingClientError.invalidState
        }
        relationship.protocolIntents[index] = finalized
    }

    private func relayClient(for endpoint: RelayEndpoint) -> RelayClient {
        let token = state.relayPreferences.first(where: {
            $0.endpoint == endpoint
        })?.accessPassword
        return RelayClient(endpoint: endpoint, authToken: token)
    }

    private func persist() async throws {
        guard state.isStructurallyValid else {
            throw HeadlessMessagingClientError.invalidState
        }
        try await stateStore.save(state)
    }

    private func persistGroupRuntime(_ record: GroupRuntimeRecord) async throws {
        guard record.isStructurallyValid else {
            throw HeadlessMessagingClientError.invalidState
        }
        try state.updateActivePersona { persona in
            try persona.upsert(groupRuntime: record)
        }
        try await persist()
    }
}

private actor HeadlessGroupRuntimePersistence: GroupRuntimeRecordPersistence {
    private var record: GroupRuntimeRecord
    private let saveHandler: @Sendable (GroupRuntimeRecord) async throws -> Void

    init(
        initialRecord: GroupRuntimeRecord,
        saveHandler: @escaping @Sendable (GroupRuntimeRecord) async throws -> Void
    ) {
        record = initialRecord
        self.saveHandler = saveHandler
    }

    func load() async throws -> GroupRuntimeRecord? { record }

    func save(_ record: GroupRuntimeRecord) async throws {
        guard record.isStructurallyValid else {
            throw GroupRuntimeError.invalidRecord
        }
        try await saveHandler(record)
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
