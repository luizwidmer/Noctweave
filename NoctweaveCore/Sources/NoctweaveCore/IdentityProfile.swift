import CryptoKit
import Foundation

public struct IdentityProfile: Codable, Identifiable {
    public let id: UUID
    public var architectureVersion: Int
    public var identityGenerationId: UUID?
    public var localInstallation: LocalInstallationState?
    public var installationManifest: InstallationManifest?
    public var issuedContactEndpointsV2: [CertifiedInstallationEndpoint]
    public var deliveryStates: [DeliveryStateRecord]
    public var inboundEnvelopeReceiptsV2: [InboundEnvelopeReceiptV2]
    public var quarantinedTransportEnvelopesV2: [QuarantinedTransportEnvelopeV2]
    public var quarantinedControlEvents: [QuarantinedControlEvent]
    public var protocolIntents: [ProtocolIntentV2]
    public var endpointRemovalJournalsV2: [EndpointRemovalJournalV2]
    public var relationshipsV2: [RelationshipStateV2]
    public var selfSyncV2: SelfSyncLocalStateV2?
    public var identityMutationV2: IdentityMutationJournalV2?
    public var identity: Identity
    public var inboxId: String
    public var inboxAccessKey: SigningKeyPair?
    public var relay: RelayEndpoint
    public var contacts: [Contact]
    public var conversations: [Conversation]
    public var groups: [GroupConversation]
    public var pendingDirectDeliveries: [PendingDirectDelivery]
    public var selectedRelayId: UUID?
    public var prekeys: PrekeyState
    public var continuityEvents: [ContinuityEvent]
    public var federationPolicy: FederationDescriptor?
    public var locallyLeftRelayGroupIds: [UUID]
    public var isArchived: Bool
    public var archivedAt: Date?
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        architectureVersion: Int = 1,
        identityGenerationId: UUID? = nil,
        localInstallation: LocalInstallationState? = nil,
        installationManifest: InstallationManifest? = nil,
        issuedContactEndpointsV2: [CertifiedInstallationEndpoint] = [],
        deliveryStates: [DeliveryStateRecord] = [],
        inboundEnvelopeReceiptsV2: [InboundEnvelopeReceiptV2] = [],
        quarantinedTransportEnvelopesV2: [QuarantinedTransportEnvelopeV2] = [],
        quarantinedControlEvents: [QuarantinedControlEvent] = [],
        protocolIntents: [ProtocolIntentV2] = [],
        endpointRemovalJournalsV2: [EndpointRemovalJournalV2] = [],
        relationshipsV2: [RelationshipStateV2] = [],
        selfSyncV2: SelfSyncLocalStateV2? = nil,
        identityMutationV2: IdentityMutationJournalV2? = nil,
        identity: Identity,
        inboxId: String,
        inboxAccessKey: SigningKeyPair? = nil,
        relay: RelayEndpoint,
        contacts: [Contact] = [],
        conversations: [Conversation] = [],
        groups: [GroupConversation] = [],
        pendingDirectDeliveries: [PendingDirectDelivery] = [],
        selectedRelayId: UUID? = nil,
        prekeys: PrekeyState,
        continuityEvents: [ContinuityEvent] = [],
        federationPolicy: FederationDescriptor? = nil,
        locallyLeftRelayGroupIds: [UUID] = [],
        isArchived: Bool = false,
        archivedAt: Date? = nil,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.architectureVersion = architectureVersion
        self.identityGenerationId = identityGenerationId
        self.localInstallation = localInstallation
        self.installationManifest = installationManifest
        self.issuedContactEndpointsV2 = Array(
            issuedContactEndpointsV2.suffix(NoctweaveArchitectureV2.maximumIssuedContactEndpoints)
        )
        self.deliveryStates = deliveryStates
        self.inboundEnvelopeReceiptsV2 = inboundEnvelopeReceiptsV2
        self.quarantinedTransportEnvelopesV2 = Array(
            quarantinedTransportEnvelopesV2.suffix(
                NoctweaveArchitectureV2.maximumQuarantinedTransportEnvelopes
            )
        )
        self.quarantinedControlEvents = Array(
            quarantinedControlEvents.suffix(NoctweaveArchitectureV2.maximumQuarantinedControlEvents)
        )
        self.protocolIntents = protocolIntents
        self.endpointRemovalJournalsV2 = endpointRemovalJournalsV2
        self.relationshipsV2 = relationshipsV2
        self.selfSyncV2 = selfSyncV2
        self.identityMutationV2 = identityMutationV2
        self.identity = identity
        self.inboxId = inboxId
        self.inboxAccessKey = inboxAccessKey
        self.relay = relay
        self.contacts = contacts
        self.conversations = conversations
        self.groups = groups
        self.pendingDirectDeliveries = pendingDirectDeliveries
        self.selectedRelayId = selectedRelayId
        self.prekeys = prekeys
        self.continuityEvents = continuityEvents
        self.federationPolicy = federationPolicy
        self.locallyLeftRelayGroupIds = locallyLeftRelayGroupIds
        self.isArchived = isArchived
        self.archivedAt = archivedAt
        self.createdAt = createdAt
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case architectureVersion
        case identityGenerationId
        case localInstallation
        case installationManifest
        case issuedContactEndpointsV2
        case deliveryStates
        case inboundEnvelopeReceiptsV2
        case quarantinedTransportEnvelopesV2
        case quarantinedControlEvents
        case protocolIntents
        case endpointRemovalJournalsV2
        case relationshipsV2
        case selfSyncV2
        case identityMutationV2
        case identity
        case inboxId
        case inboxAccessKey
        case relay
        case contacts
        case conversations
        case groups
        case pendingDirectDeliveries
        case selectedRelayId
        case prekeys
        case continuityEvents
        case federationPolicy
        case locallyLeftRelayGroupIds
        case isArchived
        case archivedAt
        case createdAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        architectureVersion = try container.decodeIfPresent(Int.self, forKey: .architectureVersion) ?? 1
        identityGenerationId = try container.decodeIfPresent(UUID.self, forKey: .identityGenerationId)
        localInstallation = try container.decodeIfPresent(LocalInstallationState.self, forKey: .localInstallation)
        installationManifest = try container.decodeIfPresent(
            InstallationManifest.self,
            forKey: .installationManifest
        )
        issuedContactEndpointsV2 = Array(
            (try container.decodeIfPresent(
                [CertifiedInstallationEndpoint].self,
                forKey: .issuedContactEndpointsV2
            ) ?? []).suffix(NoctweaveArchitectureV2.maximumIssuedContactEndpoints)
        )
        deliveryStates = try container.decodeIfPresent([DeliveryStateRecord].self, forKey: .deliveryStates) ?? []
        inboundEnvelopeReceiptsV2 = try container.decodeIfPresent(
            [InboundEnvelopeReceiptV2].self,
            forKey: .inboundEnvelopeReceiptsV2
        ) ?? []
        quarantinedTransportEnvelopesV2 = Array(
            (try container.decodeIfPresent(
                [QuarantinedTransportEnvelopeV2].self,
                forKey: .quarantinedTransportEnvelopesV2
            ) ?? []).suffix(NoctweaveArchitectureV2.maximumQuarantinedTransportEnvelopes)
        )
        quarantinedControlEvents = Array(
            (try container.decodeIfPresent(
                [QuarantinedControlEvent].self,
                forKey: .quarantinedControlEvents
            ) ?? []).suffix(NoctweaveArchitectureV2.maximumQuarantinedControlEvents)
        )
        protocolIntents = try container.decodeIfPresent(
            [ProtocolIntentV2].self,
            forKey: .protocolIntents
        ) ?? []
        endpointRemovalJournalsV2 = try container.decodeIfPresent(
            [EndpointRemovalJournalV2].self,
            forKey: .endpointRemovalJournalsV2
        ) ?? []
        relationshipsV2 = try container.decodeIfPresent(
            [RelationshipStateV2].self,
            forKey: .relationshipsV2
        ) ?? []
        selfSyncV2 = try container.decodeIfPresent(SelfSyncLocalStateV2.self, forKey: .selfSyncV2)
        identityMutationV2 = try container.decodeIfPresent(
            IdentityMutationJournalV2.self,
            forKey: .identityMutationV2
        )
        identity = try container.decode(Identity.self, forKey: .identity)
        inboxId = try container.decode(String.self, forKey: .inboxId)
        inboxAccessKey = try container.decodeIfPresent(SigningKeyPair.self, forKey: .inboxAccessKey)
        relay = try container.decode(RelayEndpoint.self, forKey: .relay)
        contacts = try container.decodeIfPresent([Contact].self, forKey: .contacts) ?? []
        conversations = try container.decodeIfPresent([Conversation].self, forKey: .conversations) ?? []
        groups = try container.decodeIfPresent([GroupConversation].self, forKey: .groups) ?? []
        pendingDirectDeliveries = try container.decodeIfPresent(
            [PendingDirectDelivery].self,
            forKey: .pendingDirectDeliveries
        ) ?? []
        selectedRelayId = try container.decodeIfPresent(UUID.self, forKey: .selectedRelayId)
        prekeys = try container.decode(PrekeyState.self, forKey: .prekeys)
        continuityEvents = try container.decodeIfPresent([ContinuityEvent].self, forKey: .continuityEvents) ?? []
        federationPolicy = try container.decodeIfPresent(FederationDescriptor.self, forKey: .federationPolicy)
        locallyLeftRelayGroupIds = try container.decodeIfPresent([UUID].self, forKey: .locallyLeftRelayGroupIds) ?? []
        isArchived = try container.decodeIfPresent(Bool.self, forKey: .isArchived) ?? false
        archivedAt = try container.decodeIfPresent(Date.self, forKey: .archivedAt)
        createdAt = try container.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date()
        if architectureVersion == NoctweaveArchitectureV2.version,
           !durableDirectOutboxStateIsConsistent {
            throw DecodingError.dataCorruptedError(
                forKey: .protocolIntents,
                in: container,
                debugDescription: "Architecture-v2 durable direct outbox state is inconsistent"
            )
        }
        if architectureVersion == NoctweaveArchitectureV2.version,
           (deliveryStates.count > NoctweaveArchitectureV2.maximumDeliveryStates
            || Set(deliveryStates.map {
                "\($0.eventId.uuidString.lowercased())|\($0.destinationInstallation.rawValue)"
            }).count != deliveryStates.count
            || !deliveryStates.allSatisfy(\.isStructurallyValid)) {
            throw DecodingError.dataCorruptedError(
                forKey: .deliveryStates,
                in: container,
                debugDescription: "Architecture-v2 delivery state is inconsistent"
            )
        }
        if architectureVersion == NoctweaveArchitectureV2.version,
           (endpointRemovalJournalsV2.count
                > NoctweaveArchitectureV2.maximumPendingEndpointRemovals
            || Set(endpointRemovalJournalsV2.map(\.id)).count
                != endpointRemovalJournalsV2.count
            || !endpointRemovalJournalsV2.allSatisfy(\.isStructurallyValid)) {
            throw DecodingError.dataCorruptedError(
                forKey: .endpointRemovalJournalsV2,
                in: container,
                debugDescription: "Architecture-v2 endpoint removal journal is inconsistent"
            )
        }
    }

    public var isArchitectureV2Ready: Bool {
        guard architectureVersion == NoctweaveArchitectureV2.version,
              let identityGenerationId,
              let localInstallation,
              let installationManifest,
              let inboxAccessKey,
              InboxAddress.isBound(inboxId, to: inboxAccessKey.publicKeyData),
              let localRecord = installationManifest.activeInstallations.first(where: {
                  $0.id == localInstallation.id
              }) else {
            return false
        }
        return localInstallation.identityGenerationId == identityGenerationId
            && localInstallation.prekeys.retainedSignedPrekeysAreStructurallyValid(
                using: localInstallation.signingKey.publicKeyData
            )
            && localInstallation.mailboxStateIsStructurallyValid
            && mailboxReachabilityIsGenerationScoped(localInstallation)
            && installationManifest.identityGenerationId == identityGenerationId
            && installationManifest.verify(identityPublicKey: identity.signingKey.publicKeyData)
            && localRecord.identityGenerationId == localInstallation.identityGenerationId
            && localRecord.signingPublicKey == localInstallation.signingKey.publicKeyData
            && localRecord.agreementPublicKey == localInstallation.agreementKey.publicKeyData
            && issuedContactEndpointsV2.count <= NoctweaveArchitectureV2.maximumIssuedContactEndpoints
            && Set(issuedContactEndpointsV2.compactMap(\.digest)).count
                == issuedContactEndpointsV2.count
            && Set(issuedContactEndpointsV2.compactMap(\.authorizationDigest)).count
                == issuedContactEndpointsV2.count
            && issuedContactEndpointsV2.allSatisfy {
                issuedEndpointIsAuthorized(
                    $0,
                    identityGenerationId: identityGenerationId,
                    localInstallation: localInstallation,
                    endpointSet: installationManifest
                )
            }
            && deliveryStates.count <= NoctweaveArchitectureV2.maximumDeliveryStates
            && Set(deliveryStates.map {
                "\($0.eventId.uuidString.lowercased())|\($0.destinationInstallation.rawValue)"
            }).count == deliveryStates.count
            && deliveryStates.allSatisfy(\.isStructurallyValid)
            && selfSyncV2?.identityGenerationId == identityGenerationId
            && selfSyncV2?.isStructurallyValid == true
            && inboundEnvelopeReceiptsV2.count
                <= NoctweaveArchitectureV2.maximumInboundEnvelopeReceipts
            && Set(inboundEnvelopeReceiptsV2.map {
                "\($0.sourceScopeId.uuidString.lowercased())|\($0.logicalEventId.uuidString.lowercased())"
            }).count == inboundEnvelopeReceiptsV2.count
            && Set(inboundEnvelopeReceiptsV2.map(\.envelopeId)).count
                == inboundEnvelopeReceiptsV2.count
            && inboundEnvelopeReceiptsV2.allSatisfy(\.isStructurallyValid)
            && quarantinedTransportEnvelopesV2.count
                <= NoctweaveArchitectureV2.maximumQuarantinedTransportEnvelopes
            && quarantinedTransportEnvelopesV2.allSatisfy(\.isStructurallyValid)
            && endpointRemovalJournalsV2.count
                <= NoctweaveArchitectureV2.maximumPendingEndpointRemovals
            && Set(endpointRemovalJournalsV2.map(\.id)).count
                == endpointRemovalJournalsV2.count
            && endpointRemovalJournalsV2.allSatisfy { journal in
                journal.isStructurallyValid
                    && journal.result.identityGenerationId == identityGenerationId
                    && journal.result.endpointSetEpoch <= installationManifest.epoch
                    && !installationManifest.activeInstallations.contains(where: {
                        $0.id == journal.result.removedEndpointId
                    })
            }
            && identityMutationStateIsConsistent
            && durableDirectOutboxStateIsConsistent
            && relationshipsV2.count <= 4_096
            && Set(relationshipsV2.map(\.id)).count == relationshipsV2.count
            && relationshipsV2.allSatisfy { relationship in
                relationship.isStructurallyValid
                    && localInstallation.relationshipHandles[relationship.id]
                        == relationship.localInstallationHandle
            }
            && contacts.allSatisfy { contact in
                relationshipsV2.contains { $0.contactId == contact.id }
            }
    }

    /// Every live route credential must name the exact relay/inbox route for
    /// this generation. A single pre-credential consumer ID is allowed only as
    /// the explicit migration marker for the current route; it cannot authorize
    /// a different or reusable inbox.
    private func mailboxReachabilityIsGenerationScoped(
        _ endpoint: LocalInstallationState
    ) -> Bool {
        let currentRoute = MailboxRouteCredentialV2.routeIdentifier(
            relay: relay,
            inboxId: inboxId
        )
        guard endpoint.mailboxCredentialsByRoute.allSatisfy({ routeKey, credential in
            credential.relay != nil
                && credential.inboxId?.lowercased() == inboxId.lowercased()
                && credential.routeIdentifier == routeKey
        }) else {
            return false
        }
        return endpoint.mailboxConsumerIdsByRoute.allSatisfy { routeKey, consumerId in
            if let credential = endpoint.mailboxCredentialsByRoute[routeKey] {
                return credential.consumerId == consumerId
            }
            return routeKey == currentRoute
        }
    }

    private var identityMutationStateIsConsistent: Bool {
        guard let journal = identityMutationV2 else { return true }
        guard journal.isStructurallyValid else { return false }
        switch journal.phase {
        case .prepared, .newRouteReady:
            return journal.kind == .burn
                && identity.fingerprint == journal.oldFingerprint
                && identity.signingKey.publicKeyData == journal.oldSigningPublicKey
                && journal.stagedBurn?.identity.fingerprint == journal.newFingerprint
        case .cutoverComplete, .cleanupComplete:
            guard identity.fingerprint == journal.newFingerprint else { return false }
            return journal.notifications.allSatisfy { notification in
                guard let intent = protocolIntents.first(where: { $0.id == notification.id }),
                      intent.kind == .sendEvent,
                      intent.targetIdentifier == Data(notification.contactId.uuidString.lowercased().utf8) else {
                    return false
                }
                if let pending = pendingDirectDeliveries.first(where: { $0.id == notification.id }) {
                    guard pending.contactId == notification.contactId,
                          intent.state != .finalized,
                          pending.envelope.verifySignature(
                              publicSigningKey: notification.signerPublicKey
                                  ?? journal.oldSigningPublicKey
                          ),
                          let encoded = try? NoctweaveCoder.encode(pending.envelope, sortedKeys: true) else {
                        return false
                    }
                    return intent.payloadDigest == Data(SHA256.hash(data: encoded))
                }
                return intent.state == .finalized
            }
        }
    }

    /// A pending direct delivery is recoverable only while the exact
    /// ciphertext and its nonterminal send intent remain paired. Terminal
    /// intents may remain as bounded audit records after ciphertext removal.
    private var durableDirectOutboxStateIsConsistent: Bool {
        guard pendingDirectDeliveries.count
                <= NoctweaveArchitectureV2.maximumPendingDirectDeliveries,
              protocolIntents.count <= NoctweaveArchitectureV2.maximumProtocolIntents,
              Set(pendingDirectDeliveries.map(\.id)).count == pendingDirectDeliveries.count,
              Set(protocolIntents.map(\.id)).count == protocolIntents.count,
              protocolIntents.allSatisfy(\.isStructurallyValid) else {
            return false
        }

        let pendingById = Dictionary(uniqueKeysWithValues: pendingDirectDeliveries.map { ($0.id, $0) })
        let intentsById = Dictionary(uniqueKeysWithValues: protocolIntents.map { ($0.id, $0) })
        for pending in pendingDirectDeliveries {
            guard pending.envelope.isStructurallyValid,
                  pending.queuedAt.timeIntervalSince1970.isFinite,
                  pending.attemptCount >= 0,
                  pending.lastAttemptAt?.timeIntervalSince1970.isFinite ?? true,
                  pending.lastAttemptAt.map({ $0 >= pending.queuedAt }) ?? true,
                  let intent = intentsById[pending.id],
                  intent.kind == .sendEvent,
                  intent.state != .finalized,
                  intent.targetIdentifier
                    == Data(pending.contactId.uuidString.lowercased().utf8),
                  let encoded = try? NoctweaveCoder.encode(
                      pending.envelope,
                      sortedKeys: true
                  ),
                  intent.payloadDigest == Data(SHA256.hash(data: encoded)) else {
                return false
            }
        }

        return protocolIntents.allSatisfy { intent in
            intent.kind != .sendEvent
                || intent.state == .finalized
                || intent.state == .permanentFailure
                || pendingById[intent.id] != nil
        }
    }

    /// Reconciles the legacy v1 ciphertext outbox with the v2 intent journal.
    /// It never drops pending ciphertext. Only terminal records that are not
    /// referenced by pending sends, an identity mutation, or a live intent
    /// dependency may be pruned to make bounded space.
    private mutating func reconcileDurableDirectOutboxForMigration() throws -> Bool {
        guard pendingDirectDeliveries.count
                <= NoctweaveArchitectureV2.maximumPendingDirectDeliveries,
              Set(pendingDirectDeliveries.map(\.id)).count == pendingDirectDeliveries.count,
              Set(protocolIntents.map(\.id)).count == protocolIntents.count,
              protocolIntents.allSatisfy(\.isStructurallyValid) else {
            throw IdentityProfileMigrationError.invalidV2State
        }

        let pendingById = Dictionary(
            uniqueKeysWithValues: pendingDirectDeliveries.map { ($0.id, $0) }
        )
        let pendingIds = Set(pendingById.keys)
        let mutationIds = identityMutationV2?.notificationIds ?? []
        let dependencyIds = Set(
            protocolIntents
                .filter { !$0.state.isTerminal }
                .flatMap(\.dependencies)
        )
        let protectedIntentIds = pendingIds.union(mutationIds).union(dependencyIds)
        guard protocolIntents.allSatisfy({ intent in
            intent.kind != .sendEvent
                || intent.state == .finalized
                || intent.state == .permanentFailure
                || pendingById[intent.id] != nil
        }) else {
            throw IdentityProfileMigrationError.invalidV2State
        }

        var missingIntents: [ProtocolIntentV2] = []
        for pending in pendingDirectDeliveries {
            guard pending.envelope.isStructurallyValid,
                  pending.queuedAt.timeIntervalSince1970.isFinite,
                  pending.attemptCount >= 0,
                  pending.lastAttemptAt?.timeIntervalSince1970.isFinite ?? true,
                  pending.lastAttemptAt.map({ $0 >= pending.queuedAt }) ?? true,
                  let encoded = try? NoctweaveCoder.encode(
                      pending.envelope,
                      sortedKeys: true
                  ) else {
                throw IdentityProfileMigrationError.invalidV2State
            }
            let digest = Data(SHA256.hash(data: encoded))
            let target = Data(pending.contactId.uuidString.lowercased().utf8)
            if let existing = protocolIntents.first(where: { $0.id == pending.id }) {
                guard existing.kind == .sendEvent,
                      existing.state != .finalized,
                      existing.targetIdentifier == target,
                      existing.payloadDigest == digest else {
                    throw IdentityProfileMigrationError.invalidV2State
                }
                continue
            }
            missingIntents.append(
                ProtocolIntentV2.prepare(
                    id: pending.id,
                    kind: .sendEvent,
                    targetIdentifier: target,
                    payloadDigest: digest,
                    createdAt: pending.queuedAt
                )
            )
        }

        let requiredPruneCount = max(
            0,
            protocolIntents.count + missingIntents.count
                - NoctweaveArchitectureV2.maximumProtocolIntents
        )
        let prunable = protocolIntents
            .filter { $0.state.isTerminal && !protectedIntentIds.contains($0.id) }
            .sorted {
                if $0.updatedAt == $1.updatedAt {
                    return $0.id.uuidString < $1.id.uuidString
                }
                return $0.updatedAt < $1.updatedAt
            }
        guard prunable.count >= requiredPruneCount else {
            throw IdentityProfileMigrationError.invalidV2State
        }
        let prunedIds = Set(prunable.prefix(requiredPruneCount).map(\.id))
        if !prunedIds.isEmpty {
            protocolIntents.removeAll { prunedIds.contains($0.id) }
        }
        protocolIntents.append(contentsOf: missingIntents)
        let changed = !prunedIds.isEmpty || !missingIntents.isEmpty

        guard durableDirectOutboxStateIsConsistent else {
            throw IdentityProfileMigrationError.invalidV2State
        }
        return changed
    }

    /// Performs the one-time pre-1.0 migration from a shared identity endpoint
    /// to an independently keyed local installation.
    @discardableResult
    public mutating func migrateToArchitectureV2() throws -> Bool {
        var prunedExpiredPrekeys = false
        if var installation = localInstallation {
            let retainedCount = installation.prekeys.retiredSignedPrekeys.count
            installation.prekeys.pruneExpiredSignedPrekeys()
            if installation.prekeys.retiredSignedPrekeys.count != retainedCount {
                localInstallation = installation
                prunedExpiredPrekeys = true
            }
        }
        if architectureVersion == NoctweaveArchitectureV2.version {
            let backfilledState = backfillArchitectureV2ProfileState()
            var changed = prunedExpiredPrekeys || backfilledState
            if try reconcileDurableDirectOutboxForMigration() {
                changed = true
            }
            guard isArchitectureV2Ready else { throw IdentityProfileMigrationError.invalidV2State }
            return changed
        }
        guard architectureVersion == 1 else {
            throw IdentityProfileMigrationError.unsupportedVersion(architectureVersion)
        }
        if let existingInboxAccessKey = inboxAccessKey {
            guard InboxAddress.isBound(inboxId, to: existingInboxAccessKey.publicKeyData) else {
                throw IdentityProfileMigrationError.invalidV2State
            }
        } else {
            let generatedInboxAccessKey = try SigningKeyPair.generate()
            inboxAccessKey = generatedInboxAccessKey
            inboxId = InboxAddress.derived(from: generatedInboxAccessKey.publicKeyData)
        }
        let generationId = UUID()
        let installation = try LocalInstallationState.generate(
            identityGenerationId: generationId,
            createdAt: createdAt
        )
        let manifest = try InstallationManifest.create(
            identityGenerationId: generationId,
            epoch: 0,
            installations: [installation.publicRecord(addedEpoch: 0)],
            identity: identity,
            issuedAt: createdAt
        )
        architectureVersion = NoctweaveArchitectureV2.version
        identityGenerationId = generationId
        localInstallation = installation
        installationManifest = manifest
        issuedContactEndpointsV2 = []
        endpointRemovalJournalsV2 = []
        deliveryStates = Array(
            deliveryStates.suffix(NoctweaveArchitectureV2.maximumDeliveryStates)
        )
        quarantinedControlEvents = Array(
            quarantinedControlEvents.suffix(NoctweaveArchitectureV2.maximumQuarantinedControlEvents)
        )
        _ = backfillArchitectureV2ProfileState()
        _ = try reconcileDurableDirectOutboxForMigration()
        guard isArchitectureV2Ready else { throw IdentityProfileMigrationError.invalidV2State }
        return true
    }

    var activeEndpoints: [InstallationRecord] {
        installationManifest?.activeInstallations ?? []
    }

    /// Issues one short-lived, generation- and endpoint-set-scoped challenge.
    /// The returned pending state contains a KEM secret and must remain in
    /// encrypted local storage; only its `challenge` is sent to the candidate.
    func prepareEndpointAdmission(
        candidate: EndpointAdmissionCandidateV2,
        issuedAt: Date = Date(),
        expiresAt: Date,
        nonce: Data? = nil
    ) throws -> PendingEndpointAdmissionV2 {
        guard isArchitectureV2Ready,
              let generationId = identityGenerationId,
              let endpointSet = installationManifest else {
            throw EndpointAdmissionV2Error.invalidChallenge
        }
        guard candidate.identityGenerationId == generationId else {
            throw EndpointAdmissionV2Error.wrongIdentityGeneration
        }
        guard !endpointSet.installations.contains(where: {
            $0.id == candidate.endpointId
                || $0.signingPublicKey == candidate.signingPublicKey
                || $0.agreementPublicKey == candidate.agreementPublicKey
        }) else {
            throw EndpointAdmissionV2Error.replayed
        }
        return try PendingEndpointAdmissionV2.issue(
            candidate: candidate,
            endpointSetEpoch: endpointSet.epoch,
            identityAuthorityKey: identity.signingKey,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            nonce: nonce
        )
    }

    /// Completes a challenge only after ML-DSA endpoint-possession and ML-KEM
    /// key-confirmation proofs verify. A manifest epoch advance consumes the
    /// challenge, so replay cannot add the endpoint again.
    mutating func completeEndpointAdmission(
        _ response: EndpointAdmissionResponseV2,
        pending: PendingEndpointAdmissionV2,
        at date: Date = Date()
    ) throws {
        guard isArchitectureV2Ready,
              let generationId = identityGenerationId,
              let current = installationManifest else {
            throw EndpointAdmissionV2Error.invalidChallenge
        }
        let challenge = pending.challenge
        guard challenge.identityGenerationId == generationId,
              response.identityGenerationId == generationId else {
            throw EndpointAdmissionV2Error.wrongIdentityGeneration
        }
        guard current.epoch == challenge.endpointSetEpoch else {
            if current.epoch > challenge.endpointSetEpoch
                || current.installations.contains(where: { $0.id == response.endpointId }) {
                throw EndpointAdmissionV2Error.replayed
            }
            throw EndpointAdmissionV2Error.staleEndpointSet
        }
        try response.verify(
            pending: pending,
            identityAuthorityPublicKey: identity.signingKey.publicKeyData,
            at: date
        )
        guard current.epoch < UInt64.max else {
            throw EndpointAdmissionV2Error.staleEndpointSet
        }
        let record = challenge.candidate.installationRecord(
            addedEpoch: current.epoch + 1,
            addedAt: date
        )
        guard let updated = try current.adding(
            installation: record,
            identity: identity,
            at: date
        ), updated != current else {
            throw EndpointAdmissionV2Error.invalidCandidate
        }
        installationManifest = updated
    }

    /// Removes a non-local endpoint, advances the signed endpoint set, and
    /// immediately replaces the local self-sync stream/key. The returned
    /// bounded obligations make clear that remote mailbox, route, peer, and
    /// group cleanup is still required; this is not advertised as completed
    /// remote revocation.
    mutating func removeEndpoint(
        _ endpointId: UUID,
        at date: Date = Date()
    ) throws -> EndpointRemovalResultV2? {
        guard isArchitectureV2Ready,
              date.timeIntervalSince1970.isFinite,
              endpointRemovalJournalsV2.count
                < NoctweaveArchitectureV2.maximumPendingEndpointRemovals,
              endpointId != localInstallation?.id,
              let generationId = identityGenerationId,
              let current = installationManifest,
              current.activeInstallations.contains(where: { $0.id == endpointId }),
              let updated = try current.revoking(
                  installationId: endpointId,
                  identity: identity,
                  at: date
              ),
              updated != current,
              let endpointSetDigest = updated.digest else {
            return nil
        }

        let replacementSelfSync = SelfSyncLocalStateV2.generate(
            identityGenerationId: generationId
        )
        let selfSyncDigest = Data(SHA256.hash(
            data: Data(replacementSelfSync.stream.rawValue.utf8)
        ))
        let remainingIds = updated.activeInstallations.map(\.id)
        let obligations = EndpointRemovalCleanupKindV2.allCases.map { kind in
            EndpointRemovalCleanupObligationV2(
                identityGenerationId: generationId,
                removedEndpointId: endpointId,
                endpointSetEpoch: updated.epoch,
                endpointSetDigest: endpointSetDigest,
                replacementSelfSyncStreamDigest: selfSyncDigest,
                remainingEndpointIds: remainingIds,
                kind: kind,
                createdAt: date
            )
        }
        let result = EndpointRemovalResultV2(
            identityGenerationId: generationId,
            removedEndpointId: endpointId,
            endpointSetEpoch: updated.epoch,
            endpointSetDigest: endpointSetDigest,
            replacementSelfSyncStreamDigest: selfSyncDigest,
            cleanupObligations: obligations
        )
        guard result.isStructurallyValid else {
            throw IdentityProfileMigrationError.invalidV2State
        }
        installationManifest = updated
        selfSyncV2 = replacementSelfSync
        endpointRemovalJournalsV2.append(
            EndpointRemovalJournalV2(result: result, createdAt: date)
        )
        return result
    }

    var pendingEndpointRemovalObligationsV2: [EndpointRemovalCleanupObligationV2] {
        endpointRemovalJournalsV2.flatMap(\.pendingObligations)
    }

    /// Marks one exact cleanup item as durably complete. Replaying a completed
    /// item is harmless; unknown journal/obligation identifiers fail closed.
    @discardableResult
    mutating func completeEndpointRemovalObligation(
        journalId: UUID,
        obligationId: UUID,
        at date: Date = Date()
    ) -> Bool {
        guard let index = endpointRemovalJournalsV2.firstIndex(where: { $0.id == journalId }),
              endpointRemovalJournalsV2[index].result.cleanupObligations.contains(where: {
                  $0.id == obligationId
              }),
              date.timeIntervalSince1970.isFinite,
              date >= endpointRemovalJournalsV2[index].updatedAt else {
            return false
        }
        if let updated = endpointRemovalJournalsV2[index].completing(
            obligationId: obligationId,
            at: date
        ) {
            endpointRemovalJournalsV2[index] = updated
        } else {
            endpointRemovalJournalsV2.remove(at: index)
        }
        return true
    }

    /// Adds v2-only local relationship and self-sync state without inventing
    /// peer installations or translating a legacy inbox into a bearer route.
    @discardableResult
    mutating func backfillArchitectureV2ProfileState() -> Bool {
        guard let generationId = identityGenerationId,
              var installation = localInstallation else {
            return false
        }
        var changed = false
        if selfSyncV2 == nil {
            selfSyncV2 = SelfSyncLocalStateV2.generate(identityGenerationId: generationId)
            changed = true
        }

        let conversationsByContact = Dictionary(grouping: conversations, by: \.contactId)
        for contact in contacts where !relationshipsV2.contains(where: { $0.contactId == contact.id }) {
            let relationshipId = UUID()
            let handle = RelationshipInstallationHandle.generate(
                identityGenerationId: generationId,
                installationId: installation.id,
                relationshipId: relationshipId
            )
            relationshipsV2.append(
                RelationshipStateV2(
                    id: relationshipId,
                    contactId: contact.id,
                    localInstallationHandle: handle,
                    conversationIds: conversationsByContact[contact.id, default: []].map(\.id),
                    createdAt: createdAt
                )
            )
            installation.relationshipHandles[relationshipId] = handle
            changed = true
        }

        for index in relationshipsV2.indices {
            let relationship = relationshipsV2[index]
            if installation.relationshipHandles[relationship.id] == nil {
                installation.relationshipHandles[relationship.id] = relationship.localInstallationHandle
                changed = true
            }
            if relationshipsV2[index].includeConversationIds(
                conversationsByContact[relationship.contactId, default: []].map(\.id)
            ) {
                changed = true
            }
        }
        relationshipsV2.sort { $0.id.uuidString < $1.id.uuidString }
        localInstallation = installation
        return changed
    }

    private func issuedEndpointIsAuthorized(
        _ endpoint: CertifiedInstallationEndpoint,
        identityGenerationId: UUID,
        localInstallation: LocalInstallationState,
        endpointSet: InstallationManifest
    ) -> Bool {
        guard endpoint.identityGenerationId == identityGenerationId,
              endpoint.installationId == localInstallation.id,
              endpoint.signingPublicKey == localInstallation.signingKey.publicKeyData,
              endpoint.agreementPublicKey == localInstallation.agreementKey.publicKeyData,
              endpoint.manifestEpoch <= endpointSet.epoch,
              endpoint.isStructurallyValid(now: endpoint.prekeyBundle.createdAt),
              let currentRecord = endpointSet.installations.first(where: {
                  $0.id == endpoint.installationId
              }),
              currentRecord.isActive(at: endpointSet.issuedAt, manifestEpoch: endpointSet.epoch),
              currentRecord.signingPublicKey == endpoint.signingPublicKey,
              currentRecord.agreementPublicKey == endpoint.agreementPublicKey,
              currentRecord.capabilities == endpoint.capabilities else {
            return false
        }
        return endpoint.hasValidAuthorizationSignatures(
            identityPublicKey: endpoint.identityAuthorityPublicKey
        )
    }
}

public enum IdentityProfileMigrationError: Error, Equatable {
    case unsupportedVersion(Int)
    case invalidV2State
}
