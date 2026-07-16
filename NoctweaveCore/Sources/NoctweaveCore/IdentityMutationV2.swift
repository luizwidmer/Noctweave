import Foundation

public enum IdentityMutationKindV2: String, Codable, Equatable {
    case rotation
    case burn
}

public enum IdentityMutationPhaseV2: String, Codable, Equatable {
    /// A burn generation and its exact reset envelopes are durable, while the
    /// old identity remains the active and usable profile.
    case prepared
    /// The staged burn inbox and consumer are registered, but cutover has not
    /// happened yet.
    case newRouteReady
    /// The new identity is the durable active state. Notification ciphertexts
    /// live in the ordinary retry outbox.
    case cutoverComplete
    /// Any old mailbox consumer has also been revoked.
    case cleanupComplete
}

public struct IdentityMutationNotificationV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let contactId: UUID
    public let contactDisplayName: String
    public let signerPublicKey: Data?
    public var stagedDelivery: PendingDirectDelivery?

    public init(
        id: UUID,
        contactId: UUID,
        contactDisplayName: String,
        signerPublicKey: Data? = nil,
        stagedDelivery: PendingDirectDelivery? = nil
    ) {
        self.id = id
        self.contactId = contactId
        self.contactDisplayName = contactDisplayName
        self.signerPublicKey = signerPublicKey
        self.stagedDelivery = stagedDelivery
    }

    public var isStructurallyValid: Bool {
        !contactDisplayName.isEmpty
            && contactDisplayName.utf8.count <= 256
            && (signerPublicKey.map(SigningKeyPair.isValidPublicKey) ?? true)
            && stagedDelivery.map {
                $0.id == id && $0.contactId == contactId && $0.envelope.isStructurallyValid
            } ?? true
    }
}

/// A complete but inactive identity generation used only while a burn is
/// preparing its replacement route. It is stored alongside the old active
/// profile, never recursively embeds a ClientState, and is removed at cutover.
public struct StagedIdentityGenerationV2: Codable {
    public let identity: Identity
    public let identityGenerationId: UUID
    public let localInstallation: LocalInstallationState
    public let installationManifest: InstallationManifest
    public let issuedContactEndpointsV2: [CertifiedInstallationEndpoint]
    public let selfSync: SelfSyncLocalStateV2
    public let prekeys: PrekeyState
    public let inboxId: String
    public let inboxAccessKey: SigningKeyPair
    public let relay: RelayEndpoint
    public let createdAt: Date

    public init(
        identity: Identity,
        identityGenerationId: UUID,
        localInstallation: LocalInstallationState,
        installationManifest: InstallationManifest,
        issuedContactEndpointsV2: [CertifiedInstallationEndpoint] = [],
        selfSync: SelfSyncLocalStateV2,
        prekeys: PrekeyState,
        inboxId: String,
        inboxAccessKey: SigningKeyPair,
        relay: RelayEndpoint,
        createdAt: Date
    ) {
        self.identity = identity
        self.identityGenerationId = identityGenerationId
        self.localInstallation = localInstallation
        self.installationManifest = installationManifest
        self.issuedContactEndpointsV2 = issuedContactEndpointsV2
        self.selfSync = selfSync
        self.prekeys = prekeys
        self.inboxId = inboxId
        self.inboxAccessKey = inboxAccessKey
        self.relay = relay
        self.createdAt = createdAt
    }

    public static func generate(
        displayName: String,
        relay: RelayEndpoint,
        createdAt: Date = Date()
    ) throws -> StagedIdentityGenerationV2 {
        let identity = try Identity.generate(displayName: displayName)
        let generationId = UUID()
        var installation = try LocalInstallationState.generate(
            identityGenerationId: generationId,
            createdAt: createdAt
        )
        let inboxAccessKey = try SigningKeyPair.generate()
        let inboxId = InboxAddress.derived(from: inboxAccessKey.publicKeyData)
        let routeKey = Self.mailboxRouteKey(relay: relay, inboxId: inboxId)
        _ = try installation.ensureMailboxCredential(
            for: routeKey,
            relay: relay,
            inboxId: inboxId,
            at: createdAt
        )
        let manifest = try InstallationManifest.create(
            identityGenerationId: generationId,
            epoch: 0,
            installations: [installation.publicRecord(addedEpoch: 0)],
            identity: identity,
            issuedAt: createdAt
        )
        let endpoint = try CertifiedInstallationEndpoint.create(
            identity: identity,
            installation: installation,
            manifest: manifest,
            issuedAt: createdAt
        )
        return StagedIdentityGenerationV2(
            identity: identity,
            identityGenerationId: generationId,
            localInstallation: installation,
            installationManifest: manifest,
            issuedContactEndpointsV2: [endpoint],
            selfSync: SelfSyncLocalStateV2.generate(identityGenerationId: generationId),
            prekeys: try PrekeyState.generate(identity: identity),
            inboxId: inboxId,
            inboxAccessKey: inboxAccessKey,
            relay: relay,
            createdAt: createdAt
        )
    }

    public var isStructurallyValid: Bool {
        guard createdAt.timeIntervalSince1970.isFinite,
              InboxAddress.isValid(inboxId),
              InboxAddress.derived(from: inboxAccessKey.publicKeyData) == inboxId,
              localInstallation.identityGenerationId == identityGenerationId,
              installationManifest.identityGenerationId == identityGenerationId,
              installationManifest.verify(identityPublicKey: identity.signingKey.publicKeyData),
              !issuedContactEndpointsV2.isEmpty,
              issuedContactEndpointsV2.count <= NoctweaveArchitectureV2.maximumIssuedContactEndpoints,
              issuedContactEndpointsV2.allSatisfy({ endpoint in
                  endpoint.identityGenerationId == identityGenerationId
                      && endpoint.installationId == localInstallation.id
                      && (try? endpoint.verified(
                          identityPublicKey: identity.signingKey.publicKeyData,
                          manifest: installationManifest,
                          now: endpoint.prekeyBundle.createdAt
                      )) != nil
              }),
              selfSync.identityGenerationId == identityGenerationId,
              selfSync.isStructurallyValid,
              localInstallation.mailboxStateIsStructurallyValid,
              mailboxCredential?.isStructurallyValid == true,
              let localRecord = installationManifest.activeInstallations.first(where: {
                  $0.id == localInstallation.id
              }),
              localRecord.signingPublicKey == localInstallation.signingKey.publicKeyData,
              localRecord.agreementPublicKey == localInstallation.agreementKey.publicKeyData,
              (try? prekeys.bundle(identity: identity)) != nil else {
            return false
        }
        return true
    }

    public var mailboxRouteKey: String {
        Self.mailboxRouteKey(relay: relay, inboxId: inboxId)
    }

    public var mailboxConsumerId: MailboxConsumerId? {
        mailboxCredential?.consumerId
    }

    public var mailboxCredential: MailboxRouteCredentialV2? {
        localInstallation.mailboxCredentialsByRoute[mailboxRouteKey]
    }

    private static func mailboxRouteKey(relay: RelayEndpoint, inboxId: String) -> String {
        "\(relay.transport.rawValue):\(relay.useTLS ? 1 : 0):\(relay.host.lowercased()):\(relay.port):\(inboxId.lowercased())"
    }
}

/// One exact, pre-signed retirement for an old generation's inbox on a relay.
/// It contains no private key and is safe to retry because retirement is
/// irreversible and relay tombstones accept only this request's exact digest.
public struct PendingInboxRetirementV2: Codable, Equatable {
    public let relay: RelayEndpoint
    public let request: RetireInboxRequest

    public init(
        relay: RelayEndpoint,
        request: RetireInboxRequest
    ) {
        self.relay = relay
        self.request = request
    }

    public var isStructurallyValid: Bool {
        guard InboxAddress.isValid(request.inboxId),
              !relay.host.isEmpty,
              let proof = request.accessProof,
              proof.signedAt.timeIntervalSince1970.isFinite,
              InboxAddress.isBound(request.inboxId, to: proof.publicSigningKey),
              proof.fingerprint == CryptoBox.fingerprint(for: proof.publicSigningKey),
              let signable = try? request.signableData(for: proof) else {
            return false
        }
        return SigningKeyPair.verify(
            signature: proof.signature,
            data: signable,
            publicKeyData: proof.publicSigningKey
        )
    }

    public var routeIdentifier: String {
        "\(relay.transport.rawValue):\(relay.useTLS ? 1 : 0):\(relay.host.lowercased()):\(relay.port):\(request.inboxId.lowercased())"
    }
}

/// Bounded, typed identity-transition journal. It stores only the staged burn
/// generation, exact notification ciphertexts, and pre-signed old-inbox
/// retirements; it never stores a recursive ClientState or old private key.
public struct IdentityMutationJournalV2: Codable, Identifiable {
    public static let version = 2
    public static let maximumNotifications = 256

    public let id: UUID
    public let kind: IdentityMutationKindV2
    public var phase: IdentityMutationPhaseV2
    public let oldFingerprint: String
    public let oldSigningPublicKey: Data
    public let newFingerprint: String
    public var notifications: [IdentityMutationNotificationV2]
    public var stagedBurn: StagedIdentityGenerationV2?
    public var pendingInboxRetirements: [PendingInboxRetirementV2]
    public let createdAt: Date
    public var updatedAt: Date

    public init(
        id: UUID = UUID(),
        kind: IdentityMutationKindV2,
        phase: IdentityMutationPhaseV2,
        oldFingerprint: String,
        oldSigningPublicKey: Data,
        newFingerprint: String,
        notifications: [IdentityMutationNotificationV2],
        stagedBurn: StagedIdentityGenerationV2? = nil,
        pendingInboxRetirements: [PendingInboxRetirementV2] = [],
        createdAt: Date = Date(),
        updatedAt: Date? = nil
    ) {
        self.id = id
        self.kind = kind
        self.phase = phase
        self.oldFingerprint = oldFingerprint
        self.oldSigningPublicKey = oldSigningPublicKey
        self.newFingerprint = newFingerprint
        self.notifications = notifications
        self.stagedBurn = stagedBurn
        self.pendingInboxRetirements = pendingInboxRetirements
        self.createdAt = createdAt
        self.updatedAt = updatedAt ?? createdAt
    }

    public var notificationIds: Set<UUID> {
        Set(notifications.map(\.id))
    }

    public var isStructurallyValid: Bool {
        guard SigningKeyPair.isValidPublicKey(oldSigningPublicKey),
              oldFingerprint == CryptoBox.fingerprint(for: oldSigningPublicKey),
              Self.isCanonicalFingerprint(newFingerprint),
              oldFingerprint != newFingerprint,
              notifications.count <= Self.maximumNotifications,
              Set(notifications.map(\.id)).count == notifications.count,
              Set(notifications.map(\.contactId)).count == notifications.count,
              notifications.allSatisfy(\.isStructurallyValid),
              createdAt.timeIntervalSince1970.isFinite,
              updatedAt.timeIntervalSince1970.isFinite,
              updatedAt >= createdAt,
              pendingInboxRetirements.count <= NoctweaveArchitectureV2.maximumRoutes,
              Set(pendingInboxRetirements.map(\.routeIdentifier)).count
                == pendingInboxRetirements.count,
              pendingInboxRetirements.allSatisfy(\.isStructurallyValid) else {
            return false
        }
        let signaturesAreValid = notifications.allSatisfy { notification in
            notification.stagedDelivery?.envelope.verifySignature(
                publicSigningKey: notification.signerPublicKey ?? oldSigningPublicKey
            ) ?? true
        }
        guard signaturesAreValid else { return false }

        switch (kind, phase) {
        case (.rotation, .cutoverComplete), (.rotation, .cleanupComplete):
            return stagedBurn == nil
                && pendingInboxRetirements.isEmpty
                && notifications.allSatisfy { $0.stagedDelivery == nil }
        case (.rotation, .prepared), (.rotation, .newRouteReady):
            return false
        case (.burn, .prepared), (.burn, .newRouteReady):
            return stagedBurn?.isStructurallyValid == true
                && stagedBurn?.identity.fingerprint == newFingerprint
                && notifications.allSatisfy { $0.stagedDelivery != nil }
        case (.burn, .cutoverComplete):
            return stagedBurn == nil
                && notifications.allSatisfy { $0.stagedDelivery == nil }
        case (.burn, .cleanupComplete):
            return stagedBurn == nil
                && pendingInboxRetirements.isEmpty
                && notifications.allSatisfy { $0.stagedDelivery == nil }
        }
    }

    public mutating func markNewRouteReady(at date: Date) -> Bool {
        guard kind == .burn,
              phase == .prepared,
              date.timeIntervalSince1970.isFinite,
              date >= updatedAt else { return false }
        phase = .newRouteReady
        updatedAt = date
        return true
    }

    public mutating func markCutoverComplete(at date: Date) -> Bool {
        guard kind == .burn,
              phase == .newRouteReady,
              date.timeIntervalSince1970.isFinite,
              date >= updatedAt else { return false }
        phase = pendingInboxRetirements.isEmpty ? .cleanupComplete : .cutoverComplete
        stagedBurn = nil
        notifications = notifications.map {
            IdentityMutationNotificationV2(
                id: $0.id,
                contactId: $0.contactId,
                contactDisplayName: $0.contactDisplayName,
                signerPublicKey: $0.signerPublicKey
            )
        }
        updatedAt = date
        return true
    }

    public mutating func markInboxRetired(
        routeIdentifier: String,
        at date: Date
    ) -> Bool {
        guard kind == .burn,
              phase == .cutoverComplete,
              date.timeIntervalSince1970.isFinite,
              date >= updatedAt,
              let index = pendingInboxRetirements.firstIndex(where: {
                  $0.routeIdentifier == routeIdentifier
              }) else { return false }
        pendingInboxRetirements.remove(at: index)
        if pendingInboxRetirements.isEmpty {
            phase = .cleanupComplete
        }
        updatedAt = date
        return true
    }

    private static func isCanonicalFingerprint(_ value: String) -> Bool {
        guard let decoded = Data(base64Encoded: value), decoded.count == 32 else { return false }
        return decoded.base64EncodedString() == value
    }
}
