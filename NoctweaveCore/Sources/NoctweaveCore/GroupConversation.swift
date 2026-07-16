import Foundation

public struct PendingGroupAcknowledgement: Codable, Equatable, Identifiable {
    public let envelopeId: UUID
    public let envelopeDigest: Data
    public let storedAt: Date

    public var id: UUID { envelopeId }

    init(envelopeId: UUID, envelopeDigest: Data, storedAt: Date) {
        self.envelopeId = envelopeId
        self.envelopeDigest = envelopeDigest
        self.storedAt = storedAt
    }

    var isStructurallyValid: Bool {
        envelopeDigest.count == 32 && storedAt.timeIntervalSince1970.isFinite
    }
}

enum PendingGroupAcknowledgementInsertion: Equatable {
    case inserted
    case alreadyPending
    case conflictingEnvelope
    case capacityExceeded
}

public struct GroupScopedIdentity: Codable, Equatable {
    public var displayName: String
    public var signingKey: SigningKeyPair
    public var agreementKey: AgreementKeyPair
    public let createdAt: Date

    public init(displayName: String, createdAt: Date = Date()) {
        self.displayName = displayName
        self.signingKey = SigningKeyPair()
        self.agreementKey = AgreementKeyPair()
        self.createdAt = createdAt
    }

    public static func generate(displayName: String, createdAt: Date = Date()) throws -> GroupScopedIdentity {
        GroupScopedIdentity(
            displayName: displayName,
            signingKey: try SigningKeyPair.generate(),
            agreementKey: try AgreementKeyPair.generate(),
            createdAt: createdAt
        )
    }

    public init(
        displayName: String,
        signingKey: SigningKeyPair,
        agreementKey: AgreementKeyPair,
        createdAt: Date = Date()
    ) {
        self.displayName = displayName
        self.signingKey = signingKey
        self.agreementKey = agreementKey
        self.createdAt = createdAt
    }

    public var fingerprint: String {
        CryptoBox.fingerprint(for: signingKey.publicKeyData)
    }

    public var memberProfile: RelayGroupMemberProfile {
        RelayGroupMemberProfile(
            fingerprint: fingerprint,
            displayName: displayName,
            signingPublicKey: signingKey.publicKeyData,
            agreementPublicKey: agreementKey.publicKeyData
        )
    }

    public static func == (lhs: GroupScopedIdentity, rhs: GroupScopedIdentity) -> Bool {
        lhs.displayName == rhs.displayName
            && lhs.signingKey.publicKeyData == rhs.signingKey.publicKeyData
            && lhs.agreementKey.publicKeyData == rhs.agreementKey.publicKeyData
            && lhs.createdAt == rhs.createdAt
    }
}

public struct GroupConversation: Codable, Identifiable, Equatable {
    public static let maximumPendingAcknowledgements = 512

    public let id: UUID
    public var title: String
    public var memberContactIds: [UUID]
    public var relayInboxId: String?
    public var relayEpoch: UInt64?
    public var relayTranscriptHash: Data?
    public var groupRatchetState: GroupRatchetState?
    public var createdByFingerprint: String?
    public var memberProfiles: [RelayGroupMemberProfile]
    public var scopedIdentity: GroupScopedIdentity?
    public var isPendingInvitation: Bool
    public internal(set) var pendingAcknowledgements: [PendingGroupAcknowledgement]
    public var messages: [Message]
    public var unreadCount: Int
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        title: String,
        memberContactIds: [UUID],
        relayInboxId: String? = nil,
        relayEpoch: UInt64? = nil,
        relayTranscriptHash: Data? = nil,
        groupRatchetState: GroupRatchetState? = nil,
        createdByFingerprint: String? = nil,
        memberProfiles: [RelayGroupMemberProfile] = [],
        scopedIdentity: GroupScopedIdentity? = nil,
        isPendingInvitation: Bool = false,
        messages: [Message] = [],
        unreadCount: Int = 0,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.title = title
        self.memberContactIds = Array(Set(memberContactIds))
        self.relayInboxId = relayInboxId
        self.relayEpoch = relayEpoch
        self.relayTranscriptHash = relayTranscriptHash
        self.groupRatchetState = groupRatchetState
        self.createdByFingerprint = createdByFingerprint
        self.memberProfiles = Self.uniqueMemberProfiles(memberProfiles)
        self.scopedIdentity = scopedIdentity
        self.isPendingInvitation = isPendingInvitation
        self.pendingAcknowledgements = []
        self.messages = messages
        self.unreadCount = unreadCount
        self.createdAt = createdAt
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case title
        case memberContactIds
        case relayInboxId
        case relayEpoch
        case relayTranscriptHash
        case groupRatchetState
        case createdByFingerprint
        case memberProfiles
        case scopedIdentity
        case isPendingInvitation
        case pendingAcknowledgements
        case messages
        case unreadCount
        case createdAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        memberContactIds = try container.decodeIfPresent([UUID].self, forKey: .memberContactIds) ?? []
        relayInboxId = try container.decodeIfPresent(String.self, forKey: .relayInboxId)
        relayEpoch = try container.decodeIfPresent(UInt64.self, forKey: .relayEpoch)
        relayTranscriptHash = try container.decodeIfPresent(Data.self, forKey: .relayTranscriptHash)
        groupRatchetState = try container.decodeIfPresent(GroupRatchetState.self, forKey: .groupRatchetState)
        createdByFingerprint = try container.decodeIfPresent(String.self, forKey: .createdByFingerprint)
        memberProfiles = Self.uniqueMemberProfiles(
            try container.decodeIfPresent([RelayGroupMemberProfile].self, forKey: .memberProfiles) ?? []
        )
        scopedIdentity = try container.decodeIfPresent(GroupScopedIdentity.self, forKey: .scopedIdentity)
        isPendingInvitation = try container.decodeIfPresent(Bool.self, forKey: .isPendingInvitation) ?? false
        pendingAcknowledgements = try container.decodeIfPresent(
            [PendingGroupAcknowledgement].self,
            forKey: .pendingAcknowledgements
        ) ?? []
        guard pendingAcknowledgements.count <= Self.maximumPendingAcknowledgements,
              pendingAcknowledgements.allSatisfy(\.isStructurallyValid),
              Set(pendingAcknowledgements.map(\.envelopeId)).count == pendingAcknowledgements.count else {
            throw DecodingError.dataCorruptedError(
                forKey: .pendingAcknowledgements,
                in: container,
                debugDescription: "Pending group acknowledgements are malformed or exceed the bounded window."
            )
        }
        messages = try container.decodeIfPresent([Message].self, forKey: .messages) ?? []
        unreadCount = try container.decodeIfPresent(Int.self, forKey: .unreadCount) ?? 0
        createdAt = try container.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(title, forKey: .title)
        try container.encode(memberContactIds, forKey: .memberContactIds)
        try container.encodeIfPresent(relayInboxId, forKey: .relayInboxId)
        try container.encodeIfPresent(relayEpoch, forKey: .relayEpoch)
        try container.encodeIfPresent(relayTranscriptHash, forKey: .relayTranscriptHash)
        try container.encodeIfPresent(groupRatchetState, forKey: .groupRatchetState)
        try container.encodeIfPresent(createdByFingerprint, forKey: .createdByFingerprint)
        try container.encode(memberProfiles, forKey: .memberProfiles)
        try container.encodeIfPresent(scopedIdentity, forKey: .scopedIdentity)
        try container.encode(isPendingInvitation, forKey: .isPendingInvitation)
        try container.encode(pendingAcknowledgements, forKey: .pendingAcknowledgements)
        try container.encode(messages, forKey: .messages)
        try container.encode(unreadCount, forKey: .unreadCount)
        try container.encode(createdAt, forKey: .createdAt)
    }

    public var resolvedMemberCount: Int {
        memberProfiles.isEmpty ? memberContactIds.count + 1 : memberProfiles.count
    }

    func pendingAcknowledgement(
        for envelopeId: UUID
    ) -> PendingGroupAcknowledgement? {
        pendingAcknowledgements.first { $0.envelopeId == envelopeId }
    }

    @discardableResult
    mutating func recordPendingAcknowledgement(
        envelopeId: UUID,
        envelopeDigest: Data,
        storedAt: Date = Date()
    ) -> PendingGroupAcknowledgementInsertion {
        guard envelopeDigest.count == 32, storedAt.timeIntervalSince1970.isFinite else {
            return .conflictingEnvelope
        }
        if let existing = pendingAcknowledgement(for: envelopeId) {
            return existing.envelopeDigest == envelopeDigest ? .alreadyPending : .conflictingEnvelope
        }
        guard pendingAcknowledgements.count < Self.maximumPendingAcknowledgements else {
            return .capacityExceeded
        }
        pendingAcknowledgements.append(
            PendingGroupAcknowledgement(
                envelopeId: envelopeId,
                envelopeDigest: envelopeDigest,
                storedAt: storedAt
            )
        )
        return .inserted
    }

    @discardableResult
    mutating func clearPendingAcknowledgements(_ envelopeIds: Set<UUID>) -> Int {
        guard !envelopeIds.isEmpty else { return 0 }
        let previousCount = pendingAcknowledgements.count
        pendingAcknowledgements.removeAll { envelopeIds.contains($0.envelopeId) }
        return previousCount - pendingAcknowledgements.count
    }

    private static func uniqueMemberProfiles(_ profiles: [RelayGroupMemberProfile]) -> [RelayGroupMemberProfile] {
        var byFingerprint: [String: RelayGroupMemberProfile] = [:]
        for profile in profiles {
            let fingerprint = profile.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !fingerprint.isEmpty else { continue }
            byFingerprint[fingerprint] = RelayGroupMemberProfile(
                fingerprint: fingerprint,
                displayName: profile.displayName,
                inboxId: profile.inboxId,
                relay: profile.relay,
                signingPublicKey: profile.signingPublicKey,
                agreementPublicKey: profile.agreementPublicKey
            )
        }
        return byFingerprint.values.sorted { $0.fingerprint < $1.fingerprint }
    }
}
