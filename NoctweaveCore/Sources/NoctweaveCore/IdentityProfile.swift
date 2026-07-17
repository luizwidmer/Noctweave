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

    private init(
        id: UUID = UUID(),
        identityGenerationId: UUID,
        localInstallation: LocalInstallationState,
        installationManifest: InstallationManifest,
        issuedContactEndpointsV2: [CertifiedInstallationEndpoint] = [],
        deliveryStates: [DeliveryStateRecord] = [],
        inboundEnvelopeReceiptsV2: [InboundEnvelopeReceiptV2] = [],
        quarantinedTransportEnvelopesV2: [QuarantinedTransportEnvelopeV2] = [],
        quarantinedControlEvents: [QuarantinedControlEvent] = [],
        protocolIntents: [ProtocolIntentV2] = [],
        endpointRemovalJournalsV2: [EndpointRemovalJournalV2] = [],
        relationshipsV2: [RelationshipStateV2] = [],
        selfSyncV2: SelfSyncLocalStateV2,
        identityMutationV2: IdentityMutationJournalV2? = nil,
        identity: Identity,
        inboxId: String,
        inboxAccessKey: SigningKeyPair,
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
        self.architectureVersion = NoctweaveArchitectureV2.version
        self.identityGenerationId = identityGenerationId
        self.localInstallation = localInstallation
        self.installationManifest = installationManifest
        self.issuedContactEndpointsV2 = issuedContactEndpointsV2
        self.deliveryStates = deliveryStates
        self.inboundEnvelopeReceiptsV2 = inboundEnvelopeReceiptsV2
        self.quarantinedTransportEnvelopesV2 = quarantinedTransportEnvelopesV2
        self.quarantinedControlEvents = quarantinedControlEvents
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

    /// Creates a complete current-generation profile in one throwing
    /// operation. Cryptographic generation failures are propagated; no empty
    /// key or partially initialized profile is ever returned.
    public static func create(
        id: UUID = UUID(),
        identity: Identity,
        relay: RelayEndpoint,
        inboxAccessKey: SigningKeyPair,
        selectedRelayId: UUID? = nil,
        prekeys: PrekeyState? = nil,
        createdAt: Date = Date()
    ) throws -> IdentityProfile {
        guard createdAt.timeIntervalSince1970.isFinite,
              SigningKeyPair.isValidPublicKey(inboxAccessKey.publicKeyData) else {
            throw IdentityProfileStateError.invalidCurrentState
        }
        let generationId = UUID()
        let localInstallation = try LocalInstallationState.generate(
            identityGenerationId: generationId,
            createdAt: createdAt
        )
        let manifest = try InstallationManifest.create(
            identityGenerationId: generationId,
            epoch: 0,
            installations: [localInstallation.publicRecord(addedEpoch: 0)],
            identity: identity,
            issuedAt: createdAt
        )
        let profile = IdentityProfile(
            id: id,
            identityGenerationId: generationId,
            localInstallation: localInstallation,
            installationManifest: manifest,
            selfSyncV2: SelfSyncLocalStateV2.generate(identityGenerationId: generationId),
            identity: identity,
            inboxId: InboxAddress.derived(from: inboxAccessKey.publicKeyData),
            inboxAccessKey: inboxAccessKey,
            relay: relay,
            selectedRelayId: selectedRelayId,
            prekeys: try prekeys ?? PrekeyState.generate(identity: identity),
            createdAt: createdAt
        )
        guard profile.isArchitectureV2Ready else {
            throw IdentityProfileStateError.invalidCurrentState
        }
        return profile
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
        architectureVersion = try container.decode(Int.self, forKey: .architectureVersion)
        guard architectureVersion == NoctweaveArchitectureV2.version else {
            throw DecodingError.dataCorruptedError(
                forKey: .architectureVersion,
                in: container,
                debugDescription: "Unsupported identity profile schema"
            )
        }
        identityGenerationId = try container.decode(UUID.self, forKey: .identityGenerationId)
        localInstallation = try container.decode(LocalInstallationState.self, forKey: .localInstallation)
        installationManifest = try container.decode(
            InstallationManifest.self,
            forKey: .installationManifest
        )
        issuedContactEndpointsV2 = try container.decode(
            [CertifiedInstallationEndpoint].self,
            forKey: .issuedContactEndpointsV2
        )
        deliveryStates = try container.decode([DeliveryStateRecord].self, forKey: .deliveryStates)
        inboundEnvelopeReceiptsV2 = try container.decode(
            [InboundEnvelopeReceiptV2].self,
            forKey: .inboundEnvelopeReceiptsV2
        )
        quarantinedTransportEnvelopesV2 = try container.decode(
            [QuarantinedTransportEnvelopeV2].self,
            forKey: .quarantinedTransportEnvelopesV2
        )
        quarantinedControlEvents = try container.decode(
            [QuarantinedControlEvent].self,
            forKey: .quarantinedControlEvents
        )
        protocolIntents = try container.decode(
            [ProtocolIntentV2].self,
            forKey: .protocolIntents
        )
        endpointRemovalJournalsV2 = try container.decode(
            [EndpointRemovalJournalV2].self,
            forKey: .endpointRemovalJournalsV2
        )
        relationshipsV2 = try container.decode(
            [RelationshipStateV2].self,
            forKey: .relationshipsV2
        )
        selfSyncV2 = try container.decode(SelfSyncLocalStateV2.self, forKey: .selfSyncV2)
        identityMutationV2 = try container.decodeIfPresent(
            IdentityMutationJournalV2.self,
            forKey: .identityMutationV2
        )
        identity = try container.decode(Identity.self, forKey: .identity)
        inboxId = try container.decode(String.self, forKey: .inboxId)
        inboxAccessKey = try container.decode(SigningKeyPair.self, forKey: .inboxAccessKey)
        relay = try container.decode(RelayEndpoint.self, forKey: .relay)
        contacts = try container.decode([Contact].self, forKey: .contacts)
        conversations = try container.decode([Conversation].self, forKey: .conversations)
        groups = try container.decode([GroupConversation].self, forKey: .groups)
        pendingDirectDeliveries = try container.decode(
            [PendingDirectDelivery].self,
            forKey: .pendingDirectDeliveries
        )
        selectedRelayId = try container.decodeIfPresent(UUID.self, forKey: .selectedRelayId)
        prekeys = try container.decode(PrekeyState.self, forKey: .prekeys)
        continuityEvents = try container.decode([ContinuityEvent].self, forKey: .continuityEvents)
        federationPolicy = try container.decodeIfPresent(FederationDescriptor.self, forKey: .federationPolicy)
        locallyLeftRelayGroupIds = try container.decode([UUID].self, forKey: .locallyLeftRelayGroupIds)
        isArchived = try container.decode(Bool.self, forKey: .isArchived)
        archivedAt = try container.decodeIfPresent(Date.self, forKey: .archivedAt)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        guard isArchitectureV2Ready else {
            throw DecodingError.dataCorruptedError(
                forKey: .architectureVersion,
                in: container,
                debugDescription: "Invalid current identity profile state"
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
    }

    /// Every live route credential must name its exact relay/inbox route.
    private func mailboxReachabilityIsGenerationScoped(
        _ endpoint: LocalInstallationState
    ) -> Bool {
        endpoint.mailboxCredentialsByRoute.allSatisfy { routeKey, credential in
            credential.relay != nil
                && credential.inboxId?.lowercased() == inboxId.lowercased()
                && credential.routeIdentifier == routeKey
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

        let replacementSelfSync: SelfSyncLocalStateV2
        if let currentSelfSync = selfSyncV2,
           currentSelfSync.identityGenerationId == generationId {
            replacementSelfSync = try currentSelfSync.rotatingEpoch()
        } else {
            replacementSelfSync = SelfSyncLocalStateV2.generate(
                identityGenerationId: generationId
            )
        }
        let selfSyncDigest = replacementSelfSync.epochCommitmentDigest
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
            throw IdentityProfileStateError.invalidCurrentState
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

public enum IdentityProfileStateError: Error, Equatable {
    case invalidCurrentState
}
