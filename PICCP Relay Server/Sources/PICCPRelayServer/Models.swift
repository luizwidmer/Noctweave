import Foundation
import Crypto

enum RelayKind: String, Codable, CaseIterable {
    case standard
    case discovery
    case bridge
    case archive
    case privateRelay
    case coordinator
}

enum FederationMode: String, Codable, CaseIterable {
    case solo
    case curated
    case open
}

enum GroupCreationMode: String, Codable, CaseIterable {
    case disabled
    case allowed
}

enum GroupSecurityModel: String, Codable, CaseIterable {
    case relayBackedPairwise
    case mlsDerivedTree
}

enum MLSGroupCommitOperation: String, Codable, CaseIterable {
    case create
    case update
    case addMembers
    case removeMembers
    case selfLeave
    case joinApprove
}

struct MLSGroupCommitSummary: Codable, Equatable {
    let operation: MLSGroupCommitOperation
    let actorFingerprint: String
    let epoch: UInt64
    let committedAt: Date
    let memberFingerprints: [String]
    let previousTranscriptHash: Data?
    let transcriptHash: Data
    let ratchetSecretDistribution: GroupRatchetEpochSecretDistribution?
}

struct MLSGroupEpochState: Codable, Equatable {
    static let currentProtocolVersion = "noctyra-mls-v1"
    static let currentCipherSuite = "Noctyra-MLS-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-v1"

    let protocolVersion: String
    let cipherSuite: String
    let groupId: UUID
    let epoch: UInt64
    let treeHash: Data
    let confirmedTranscriptHash: Data
    let lastCommit: MLSGroupCommitSummary

    static func initial(
        groupId: UUID,
        title: String,
        inboxId: String,
        createdByFingerprint: String,
        members: [RelayGroupMember],
        createdAt: Date,
        ratchetSecretDistribution: GroupRatchetEpochSecretDistribution? = nil
    ) -> MLSGroupEpochState {
        make(
            groupId: groupId,
            title: title,
            inboxId: inboxId,
            actorFingerprint: createdByFingerprint,
            members: members,
            epoch: 0,
            previousTranscriptHash: nil,
            operation: .create,
            committedAt: createdAt,
            ratchetSecretDistribution: ratchetSecretDistribution
        )
    }

    func advancing(
        title: String,
        inboxId: String,
        actorFingerprint: String,
        members: [RelayGroupMember],
        operation: MLSGroupCommitOperation,
        committedAt: Date,
        ratchetSecretDistribution: GroupRatchetEpochSecretDistribution? = nil
    ) -> MLSGroupEpochState {
        MLSGroupEpochState.make(
            groupId: groupId,
            title: title,
            inboxId: inboxId,
            actorFingerprint: actorFingerprint,
            members: members,
            epoch: epoch + 1,
            previousTranscriptHash: confirmedTranscriptHash,
            operation: operation,
            committedAt: committedAt,
            ratchetSecretDistribution: ratchetSecretDistribution
        )
    }

    private static func make(
        groupId: UUID,
        title: String,
        inboxId: String,
        actorFingerprint: String,
        members: [RelayGroupMember],
        epoch: UInt64,
        previousTranscriptHash: Data?,
        operation: MLSGroupCommitOperation,
        committedAt: Date,
        ratchetSecretDistribution: GroupRatchetEpochSecretDistribution?
    ) -> MLSGroupEpochState {
        let memberFingerprints = members.map(\.fingerprint).sorted()
        let treeHash = digest(
            MLSGroupTreeHashPayload(
                groupId: groupId,
                inboxId: inboxId,
                epoch: epoch,
                memberFingerprints: memberFingerprints
            )
        )
        let transcriptHash = digest(
            MLSGroupTranscriptHashPayload(
                protocolVersion: currentProtocolVersion,
                cipherSuite: currentCipherSuite,
                groupId: groupId,
                inboxId: inboxId,
                title: title,
                epoch: epoch,
                operation: operation,
                actorFingerprint: actorFingerprint,
                memberFingerprints: memberFingerprints,
                previousTranscriptHash: previousTranscriptHash,
                treeHash: treeHash,
                committedAt: committedAt
            )
        )
        let commit = MLSGroupCommitSummary(
            operation: operation,
            actorFingerprint: actorFingerprint,
            epoch: epoch,
            committedAt: committedAt,
            memberFingerprints: memberFingerprints,
            previousTranscriptHash: previousTranscriptHash,
            transcriptHash: transcriptHash,
            ratchetSecretDistribution: ratchetSecretDistribution
        )
        return MLSGroupEpochState(
            protocolVersion: currentProtocolVersion,
            cipherSuite: currentCipherSuite,
            groupId: groupId,
            epoch: epoch,
            treeHash: treeHash,
            confirmedTranscriptHash: transcriptHash,
            lastCommit: commit
        )
    }

    private static func digest<T: Encodable>(_ value: T) -> Data {
        guard let data = try? RelayCodec.encoder(sortedKeys: true).encode(value) else {
            return Data(SHA256.hash(data: Data()))
        }
        return Data(SHA256.hash(data: data))
    }
}

private struct MLSGroupTreeHashPayload: Codable {
    let groupId: UUID
    let inboxId: String
    let epoch: UInt64
    let memberFingerprints: [String]
}

private struct MLSGroupTranscriptHashPayload: Codable {
    let protocolVersion: String
    let cipherSuite: String
    let groupId: UUID
    let inboxId: String
    let title: String
    let epoch: UInt64
    let operation: MLSGroupCommitOperation
    let actorFingerprint: String
    let memberFingerprints: [String]
    let previousTranscriptHash: Data?
    let treeHash: Data
    let committedAt: Date
}

struct FederationDescriptor: Codable, Equatable {
    let mode: FederationMode
    let name: String?
    let description: String?

    init(mode: FederationMode, name: String? = nil, description: String? = nil) {
        self.mode = mode
        self.name = name
        self.description = description
    }
}

enum HiddenRetrievalMode: String, Codable, CaseIterable {
    case coverQuery
}

struct HiddenRetrievalSupport: Codable, Equatable {
    let mode: HiddenRetrievalMode
    let defaultCoverSetSize: Int
    let maxCoverSetSize: Int

    init(
        mode: HiddenRetrievalMode = .coverQuery,
        defaultCoverSetSize: Int = 8,
        maxCoverSetSize: Int = 32
    ) {
        let normalizedMax = max(2, maxCoverSetSize)
        self.mode = mode
        self.maxCoverSetSize = normalizedMax
        self.defaultCoverSetSize = min(max(2, defaultCoverSetSize), normalizedMax)
    }
}

enum DecentralizedWakeMode: String, Codable, CaseIterable {
    case pullOnly
    case longPoll
}

struct DecentralizedWakeSupport: Codable, Equatable {
    let mode: DecentralizedWakeMode
    let minPollIntervalSeconds: Int
    let maxPollIntervalSeconds: Int
    let jitterPermille: Int
    let longPollTimeoutSeconds: Int?

    init(
        mode: DecentralizedWakeMode = .pullOnly,
        minPollIntervalSeconds: Int = 60,
        maxPollIntervalSeconds: Int = 300,
        jitterPermille: Int = 250,
        longPollTimeoutSeconds: Int? = nil
    ) {
        let normalizedMin = max(5, minPollIntervalSeconds)
        let normalizedMax = max(normalizedMin, maxPollIntervalSeconds)
        self.mode = mode
        self.minPollIntervalSeconds = normalizedMin
        self.maxPollIntervalSeconds = normalizedMax
        self.jitterPermille = min(max(0, jitterPermille), 1_000)
        if mode == .longPoll {
            self.longPollTimeoutSeconds = longPollTimeoutSeconds.map { min(max(5, $0), normalizedMax) } ?? normalizedMin
        } else {
            self.longPollTimeoutSeconds = nil
        }
    }
}

struct RelayInfo: Codable, Equatable {
    let kind: RelayKind
    let federation: FederationDescriptor
    let tlsEnabled: Bool?
    let transport: RelayEndpointTransport?
    let temporalBucketSeconds: Int
    let temporalBucketScheduleSeconds: [Int]?
    let attachmentDefaultTTLSeconds: Int?
    let attachmentMaxTTLSeconds: Int?
    let attachmentsEnabled: Bool?
    let hiddenRetrieval: HiddenRetrievalSupport?
    let wakeSupport: DecentralizedWakeSupport?
    let relayName: String?
    let operatorNote: String?
    let softwareVersion: String?
    let groupCreationMode: GroupCreationMode
    let groupSecurityModel: GroupSecurityModel
    let requiresPassword: Bool?
    let federationCoordinatorEndpoints: [RelayEndpoint]?
    let coordinatorReportedRelayCount: Int?
    let coordinatorRegistrationAuthRequired: Bool?
    let curatedStrictPolicyEnabled: Bool?
    let curatedCoordinatorQuorum: Int?
    let curatedRequireSignedDirectory: Bool?
    let federationDirectoryPublicKey: Data?
    let knownOpenPeers: [RelayEndpoint]?
    let advertisedAt: Date

    init(
        kind: RelayKind,
        federation: FederationDescriptor,
        tlsEnabled: Bool? = nil,
        transport: RelayEndpointTransport? = nil,
        temporalBucketSeconds: Int,
        temporalBucketScheduleSeconds: [Int]? = nil,
        attachmentDefaultTTLSeconds: Int? = nil,
        attachmentMaxTTLSeconds: Int? = nil,
        attachmentsEnabled: Bool? = nil,
        hiddenRetrieval: HiddenRetrievalSupport? = nil,
        wakeSupport: DecentralizedWakeSupport? = nil,
        relayName: String? = nil,
        operatorNote: String? = nil,
        softwareVersion: String? = nil,
        groupCreationMode: GroupCreationMode = .allowed,
        groupSecurityModel: GroupSecurityModel = .relayBackedPairwise,
        requiresPassword: Bool? = nil,
        federationCoordinatorEndpoints: [RelayEndpoint]? = nil,
        coordinatorReportedRelayCount: Int? = nil,
        coordinatorRegistrationAuthRequired: Bool? = nil,
        curatedStrictPolicyEnabled: Bool? = nil,
        curatedCoordinatorQuorum: Int? = nil,
        curatedRequireSignedDirectory: Bool? = nil,
        federationDirectoryPublicKey: Data? = nil,
        knownOpenPeers: [RelayEndpoint]? = nil,
        advertisedAt: Date = Date()
    ) {
        self.kind = kind
        self.federation = federation
        self.tlsEnabled = tlsEnabled
        self.transport = transport
        self.temporalBucketSeconds = temporalBucketSeconds
        if let temporalBucketScheduleSeconds {
            let normalized = Array(Set(temporalBucketScheduleSeconds.map { max(0, $0) }.filter { $0 > 0 })).sorted()
            self.temporalBucketScheduleSeconds = normalized.isEmpty ? nil : normalized
        } else {
            self.temporalBucketScheduleSeconds = nil
        }
        self.attachmentDefaultTTLSeconds = attachmentDefaultTTLSeconds
        self.attachmentMaxTTLSeconds = attachmentMaxTTLSeconds
        self.attachmentsEnabled = attachmentsEnabled
        self.hiddenRetrieval = hiddenRetrieval
        self.wakeSupport = wakeSupport
        self.relayName = relayName
        self.operatorNote = operatorNote
        self.softwareVersion = softwareVersion
        self.groupCreationMode = groupCreationMode
        self.groupSecurityModel = groupSecurityModel
        self.requiresPassword = requiresPassword
        self.federationCoordinatorEndpoints = federationCoordinatorEndpoints
        self.coordinatorReportedRelayCount = coordinatorReportedRelayCount
        self.coordinatorRegistrationAuthRequired = coordinatorRegistrationAuthRequired
        self.curatedStrictPolicyEnabled = curatedStrictPolicyEnabled
        self.curatedCoordinatorQuorum = curatedCoordinatorQuorum
        self.curatedRequireSignedDirectory = curatedRequireSignedDirectory
        self.federationDirectoryPublicKey = federationDirectoryPublicKey
        self.knownOpenPeers = knownOpenPeers
        self.advertisedAt = advertisedAt
    }
}

struct RelayConfiguration: Codable, Equatable {
    var kind: RelayKind
    var federation: FederationDescriptor
    var tlsEnabled: Bool?
    var transport: RelayEndpointTransport
    var temporalBucketSeconds: Int
    var temporalBucketScheduleSeconds: [Int]?
    var attachmentDefaultTTLSeconds: Int
    var attachmentMaxTTLSeconds: Int
    var attachmentsEnabled: Bool?
    var hiddenRetrieval: HiddenRetrievalSupport?
    var wakeSupport: DecentralizedWakeSupport?
    var relayName: String?
    var operatorNote: String?
    var softwareVersion: String?
    var groupCreationMode: GroupCreationMode
    var groupSecurityModel: GroupSecurityModel
    var accessPassword: String?
    var coordinatorRegistrationToken: String?
    var federationForwardingAuthToken: String?
    var federationCoordinatorEndpoints: [RelayEndpoint]?
    var coordinatorHeartbeatSeconds: Int?
    var coordinatorDirectoryMaxStalenessSeconds: Int?
    var relayPeerExchangeLimit: Int?
    var coordinatorDirectorySigningPrivateKey: Data?
    var curatedStrictPolicyEnabled: Bool
    var curatedCoordinatorQuorum: Int
    var curatedRequireSignedDirectory: Bool
    var advertisedEndpoint: RelayEndpoint?
    var federationAllowList: [RelayEndpoint]
    var allowPrivateFederationEndpoints: Bool
    var requireInboxAccessControl: Bool?

    init(
        kind: RelayKind = .standard,
        federation: FederationDescriptor = FederationDescriptor(mode: .solo),
        tlsEnabled: Bool? = nil,
        transport: RelayEndpointTransport = .tcp,
        temporalBucketSeconds: Int = 300,
        temporalBucketScheduleSeconds: [Int]? = nil,
        attachmentDefaultTTLSeconds: Int = 3600,
        attachmentMaxTTLSeconds: Int = 21600,
        attachmentsEnabled: Bool = true,
        hiddenRetrieval: HiddenRetrievalSupport? = nil,
        wakeSupport: DecentralizedWakeSupport? = nil,
        relayName: String? = nil,
        operatorNote: String? = nil,
        softwareVersion: String? = nil,
        groupCreationMode: GroupCreationMode = .allowed,
        groupSecurityModel: GroupSecurityModel = .relayBackedPairwise,
        accessPassword: String? = nil,
        coordinatorRegistrationToken: String? = nil,
        federationForwardingAuthToken: String? = nil,
        federationCoordinatorEndpoints: [RelayEndpoint]? = nil,
        coordinatorHeartbeatSeconds: Int? = nil,
        coordinatorDirectoryMaxStalenessSeconds: Int? = 300,
        relayPeerExchangeLimit: Int? = 12,
        coordinatorDirectorySigningPrivateKey: Data? = nil,
        curatedStrictPolicyEnabled: Bool = true,
        curatedCoordinatorQuorum: Int = 1,
        curatedRequireSignedDirectory: Bool = true,
        advertisedEndpoint: RelayEndpoint? = nil,
        federationAllowList: [RelayEndpoint] = [],
        allowPrivateFederationEndpoints: Bool = false,
        requireInboxAccessControl: Bool = true
    ) {
        self.kind = kind
        self.federation = federation
        self.tlsEnabled = tlsEnabled
        self.transport = transport
        self.temporalBucketSeconds = temporalBucketSeconds
        if let temporalBucketScheduleSeconds {
            let normalized = Array(Set(temporalBucketScheduleSeconds.map { max(0, $0) }.filter { $0 > 0 })).sorted()
            self.temporalBucketScheduleSeconds = normalized.isEmpty ? nil : normalized
        } else {
            self.temporalBucketScheduleSeconds = nil
        }
        let normalizedAttachmentDefaultTTL = max(60, attachmentDefaultTTLSeconds)
        self.attachmentDefaultTTLSeconds = normalizedAttachmentDefaultTTL
        self.attachmentMaxTTLSeconds = max(normalizedAttachmentDefaultTTL, attachmentMaxTTLSeconds)
        self.attachmentsEnabled = attachmentsEnabled
        self.hiddenRetrieval = hiddenRetrieval
        self.wakeSupport = wakeSupport
        self.relayName = relayName
        self.operatorNote = operatorNote
        self.softwareVersion = softwareVersion
        self.groupCreationMode = groupCreationMode
        self.groupSecurityModel = groupSecurityModel
        let normalizedAccessPassword = accessPassword?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.accessPassword = normalizedAccessPassword?.isEmpty == false ? normalizedAccessPassword : nil
        let normalizedRegistrationToken = coordinatorRegistrationToken?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.coordinatorRegistrationToken = normalizedRegistrationToken?.isEmpty == false ? normalizedRegistrationToken : nil
        let normalizedForwardingToken = federationForwardingAuthToken?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.federationForwardingAuthToken = normalizedForwardingToken?.isEmpty == false ? normalizedForwardingToken : nil
        self.federationCoordinatorEndpoints = federationCoordinatorEndpoints
        self.coordinatorHeartbeatSeconds = coordinatorHeartbeatSeconds
        self.coordinatorDirectoryMaxStalenessSeconds = coordinatorDirectoryMaxStalenessSeconds
        self.relayPeerExchangeLimit = relayPeerExchangeLimit
        self.coordinatorDirectorySigningPrivateKey = coordinatorDirectorySigningPrivateKey
        self.curatedStrictPolicyEnabled = curatedStrictPolicyEnabled
        self.curatedCoordinatorQuorum = max(1, curatedCoordinatorQuorum)
        self.curatedRequireSignedDirectory = curatedRequireSignedDirectory
        self.advertisedEndpoint = advertisedEndpoint
        self.federationAllowList = federationAllowList
        self.allowPrivateFederationEndpoints = allowPrivateFederationEndpoints
        self.requireInboxAccessControl = requireInboxAccessControl
    }

    func makeInfo(now: Date = Date()) -> RelayInfo {
        let curatedMode = federation.mode == .curated
        let trimmedPassword = accessPassword?.trimmingCharacters(in: .whitespacesAndNewlines)
        let requiresPassword = !(trimmedPassword?.isEmpty ?? true)
        let requiresCoordinatorRegistrationAuth = !(coordinatorRegistrationToken?.isEmpty ?? true)
        return RelayInfo(
            kind: kind,
            federation: federation,
            tlsEnabled: tlsEnabled,
            transport: transport,
            temporalBucketSeconds: temporalBucketSeconds,
            temporalBucketScheduleSeconds: temporalBucketScheduleSeconds,
            attachmentDefaultTTLSeconds: attachmentDefaultTTLSeconds,
            attachmentMaxTTLSeconds: attachmentMaxTTLSeconds,
            attachmentsEnabled: attachmentsEnabled != false,
            hiddenRetrieval: hiddenRetrieval,
            wakeSupport: wakeSupport,
            relayName: relayName,
            operatorNote: operatorNote,
            softwareVersion: softwareVersion,
            groupCreationMode: groupCreationMode,
            groupSecurityModel: groupSecurityModel,
            requiresPassword: requiresPassword,
            federationCoordinatorEndpoints: federationCoordinatorEndpoints,
            coordinatorRegistrationAuthRequired: kind == .coordinator ? requiresCoordinatorRegistrationAuth : nil,
            curatedStrictPolicyEnabled: curatedMode ? curatedStrictPolicyEnabled : nil,
            curatedCoordinatorQuorum: curatedMode ? curatedCoordinatorQuorum : nil,
            curatedRequireSignedDirectory: curatedMode ? curatedRequireSignedDirectory : nil,
            advertisedAt: now
        )
    }
}

struct RelayGroupMember: Codable, Equatable {
    let fingerprint: String
    let joinedAt: Date
    var displayName: String?
    var inboxId: String?
    var relay: RelayEndpoint?
    var signingPublicKey: Data?
    var agreementPublicKey: Data?
}

struct RelayGroupDescriptor: Codable, Equatable {
    let id: UUID
    var title: String
    let inboxId: String
    let createdByFingerprint: String
    var epoch: UInt64
    var members: [RelayGroupMember]
    var mlsEpochState: MLSGroupEpochState
    var mlsEpochHistory: [MLSGroupCommitSummary]
    let createdAt: Date
    var updatedAt: Date

    private enum CodingKeys: String, CodingKey {
        case id
        case title
        case inboxId
        case createdByFingerprint
        case epoch
        case members
        case mlsEpochState
        case mlsEpochHistory
        case createdAt
        case updatedAt
    }

    init(
        id: UUID,
        title: String,
        inboxId: String,
        createdByFingerprint: String,
        epoch: UInt64,
        members: [RelayGroupMember],
        mlsEpochState: MLSGroupEpochState,
        mlsEpochHistory: [MLSGroupCommitSummary]? = nil,
        createdAt: Date,
        updatedAt: Date
    ) {
        self.id = id
        self.title = title
        self.inboxId = inboxId
        self.createdByFingerprint = createdByFingerprint
        self.epoch = epoch
        self.members = members
        self.mlsEpochState = mlsEpochState
        self.mlsEpochHistory = mlsEpochHistory ?? [mlsEpochState.lastCommit]
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        inboxId = try container.decode(String.self, forKey: .inboxId)
        createdByFingerprint = try container.decode(String.self, forKey: .createdByFingerprint)
        epoch = try container.decode(UInt64.self, forKey: .epoch)
        members = try container.decode([RelayGroupMember].self, forKey: .members)
        mlsEpochState = try container.decode(MLSGroupEpochState.self, forKey: .mlsEpochState)
        mlsEpochHistory = try container.decodeIfPresent([MLSGroupCommitSummary].self, forKey: .mlsEpochHistory)
            ?? [mlsEpochState.lastCommit]
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        updatedAt = try container.decode(Date.self, forKey: .updatedAt)
    }
}

struct RelayGroupJoinRequest: Codable, Equatable {
    let id: UUID
    let groupId: UUID
    let requester: RelayGroupMemberProfile
    let requestedAt: Date
}

struct RelayActorProof: Codable, Equatable {
    let fingerprint: String
    let publicSigningKey: Data
    let signedAt: Date
    let nonce: UUID
    let signature: Data

    func isConsistentFingerprint() -> Bool {
        !publicSigningKey.isEmpty
            && fingerprint == Data(SHA256.hash(data: publicSigningKey)).base64EncodedString()
    }

    func verify(signableData: Data) -> Bool {
        guard isConsistentFingerprint() else {
            return false
        }
        return OQSSignatureVerifier.shared.verify(
            signature: signature,
            data: signableData,
            publicKey: publicSigningKey
        )
    }
}

struct RelayGroupMemberProfile: Codable, Equatable {
    let fingerprint: String
    let displayName: String?
    let inboxId: String?
    let relay: RelayEndpoint?
    let signingPublicKey: Data?
    let agreementPublicKey: Data?
}

struct OneTimePrekey: Codable, Equatable {
    let id: UUID
    let publicKey: Data
    let signature: Data

    init(id: UUID = UUID(), publicKey: Data, signature: Data) {
        self.id = id
        self.publicKey = publicKey
        self.signature = signature
    }

}

struct SignedPrekey: Codable, Equatable {
    let id: UUID
    let publicKey: Data
    let issuedAt: Date
    let signature: Data
}

struct PrekeyBundle: Codable, Equatable {
    let version: Int
    let identityFingerprint: String
    let signedPrekey: SignedPrekey
    let oneTimePrekeys: [OneTimePrekey]
    let createdAt: Date

    init(
        version: Int = 1,
        identityFingerprint: String,
        signedPrekey: SignedPrekey,
        oneTimePrekeys: [OneTimePrekey],
        createdAt: Date = Date()
    ) {
        self.version = version
        self.identityFingerprint = identityFingerprint
        self.signedPrekey = signedPrekey
        self.oneTimePrekeys = oneTimePrekeys
        self.createdAt = createdAt
    }
}

struct EncryptedPayload: Codable, Equatable {
    let nonce: Data
    let ciphertext: Data
    let tag: Data
}

struct GroupRatchetSecretShare: Codable, Equatable {
    let recipientFingerprint: String
    let kemCiphertext: Data
    let encryptedSecret: EncryptedPayload
}

struct GroupRatchetEpochSecretDistribution: Codable, Equatable {
    let version: Int
    let groupId: UUID
    let epoch: UInt64
    let operation: MLSGroupCommitOperation
    let memberFingerprints: [String]
    let shares: [GroupRatchetSecretShare]

    var isStructurallyValid: Bool {
        let normalizedMembers = memberFingerprints.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let shareRecipients = shares.map {
            $0.recipientFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return version == 1
            && !normalizedMembers.isEmpty
            && !normalizedMembers.contains(where: { $0.isEmpty })
            && Set(normalizedMembers).count == normalizedMembers.count
            && !shareRecipients.contains(where: { $0.isEmpty })
            && Set(shareRecipients).count == shareRecipients.count
            && Set(shareRecipients) == Set(normalizedMembers)
            && shares.allSatisfy { share in
                !share.kemCiphertext.isEmpty
                    && !share.encryptedSecret.ciphertext.isEmpty
                    && share.encryptedSecret.nonce.count == 12
                    && share.encryptedSecret.tag.count == 16
            }
    }
}

struct GroupRatchetEnvelope: Codable, Equatable {
    let id: UUID
    let groupId: UUID
    let epoch: UInt64
    let transcriptHash: Data
    let senderFingerprint: String
    let sentAt: Date
    let messageCounter: UInt64
    let payload: EncryptedPayload
    let signature: Data

    init(
        id: UUID = UUID(),
        groupId: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        senderFingerprint: String,
        sentAt: Date,
        messageCounter: UInt64,
        payload: EncryptedPayload,
        signature: Data
    ) {
        self.id = id
        self.groupId = groupId
        self.epoch = epoch
        self.transcriptHash = transcriptHash
        self.senderFingerprint = senderFingerprint
        self.sentAt = sentAt
        self.messageCounter = messageCounter
        self.payload = payload
        self.signature = signature
    }

    func verifySignature(publicSigningKey: Data) -> Bool {
        guard senderFingerprint == Data(SHA256.hash(data: publicSigningKey)).base64EncodedString(),
              let data = try? GroupProofCodec.encode(
                GroupRatchetSignaturePayload(
                    version: 1,
                    groupId: groupId,
                    epoch: epoch,
                    transcriptHash: transcriptHash,
                    senderFingerprint: senderFingerprint,
                    sentAt: sentAt,
                    messageCounter: messageCounter,
                    payload: payload
                )
              ) else {
            return false
        }
        return OQSSignatureVerifier.shared.verify(signature: signature, data: data, publicKey: publicSigningKey)
    }
}

struct Envelope: Codable, Equatable {
    let id: UUID
    let conversationId: String
    let sessionId: String?
    let senderFingerprint: String
    let sentAt: Date
    let messageCounter: UInt64
    let kemCiphertext: Data?
    let payload: EncryptedPayload
    let signature: Data

    init(
        id: UUID = UUID(),
        conversationId: String,
        sessionId: String? = nil,
        senderFingerprint: String,
        sentAt: Date,
        messageCounter: UInt64,
        kemCiphertext: Data?,
        payload: EncryptedPayload,
        signature: Data
    ) {
        self.id = id
        self.conversationId = conversationId
        self.sessionId = sessionId
        self.senderFingerprint = senderFingerprint
        self.sentAt = sentAt
        self.messageCounter = messageCounter
        self.kemCiphertext = kemCiphertext
        self.payload = payload
        self.signature = signature
    }
}

enum RelayEndpointTransport: String, Codable, CaseIterable, Hashable {
    case tcp
    case http
    case websocket
}

struct RelayEndpoint: Codable, Equatable, Hashable {
    let host: String
    let port: UInt16
    let useTLS: Bool
    let transport: RelayEndpointTransport

    init(
        host: String,
        port: UInt16,
        useTLS: Bool = false,
        transport: RelayEndpointTransport = .tcp
    ) {
        self.host = host
        self.port = port
        self.useTLS = useTLS
        self.transport = transport
    }

    private enum CodingKeys: String, CodingKey {
        case host
        case port
        case useTLS
        case transport
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        host = try container.decode(String.self, forKey: .host)
        port = try container.decode(UInt16.self, forKey: .port)
        useTLS = try container.decodeIfPresent(Bool.self, forKey: .useTLS) ?? false
        transport = try container.decodeIfPresent(RelayEndpointTransport.self, forKey: .transport) ?? .tcp
    }
}

struct DeliverRequest: Codable, Equatable {
    let inboxId: String
    let routingToken: String?
    let envelope: Envelope
    let destinationRelay: RelayEndpoint?
}

struct FetchRequest: Codable, Equatable {
    let inboxId: String
    let routingToken: String?
    let maxCount: Int?
    let longPollTimeoutSeconds: Int?
    let accessProof: RelayActorProof?

    init(
        inboxId: String,
        routingToken: String? = nil,
        maxCount: Int? = nil,
        longPollTimeoutSeconds: Int? = nil,
        accessProof: RelayActorProof? = nil
    ) {
        self.inboxId = inboxId
        self.routingToken = routingToken
        self.maxCount = maxCount
        self.longPollTimeoutSeconds = longPollTimeoutSeconds
        self.accessProof = accessProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            InboxFetchProofPayload(
                inboxId: inboxId,
                routingToken: routingToken,
                maxCount: maxCount,
                longPollTimeoutSeconds: longPollTimeoutSeconds,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

struct RegisterInboxRequest: Codable, Equatable {
    let inboxId: String
    let accessPublicKey: Data
    let contactOffer: ContactOffer?
    let accessProof: RelayActorProof?

    init(
        inboxId: String,
        accessPublicKey: Data,
        contactOffer: ContactOffer? = nil,
        accessProof: RelayActorProof? = nil
    ) {
        self.inboxId = inboxId
        self.accessPublicKey = accessPublicKey
        self.contactOffer = contactOffer
        self.accessProof = accessProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            InboxRegistrationProofPayload(
                inboxId: inboxId,
                accessPublicKey: accessPublicKey,
                contactOffer: contactOffer,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

struct AcknowledgeMessagesRequest: Codable, Equatable {
    let inboxId: String
    let messageIds: [UUID]
    let accessProof: RelayActorProof?

    init(inboxId: String, messageIds: [UUID], accessProof: RelayActorProof? = nil) {
        self.inboxId = inboxId
        self.messageIds = messageIds
        self.accessProof = accessProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            InboxAcknowledgementProofPayload(
                inboxId: inboxId,
                messageIds: messageIds,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

struct DeliverGroupMessageRequest: Codable, Equatable {
    let groupId: UUID
    let groupInboxId: String
    let envelope: GroupRatchetEnvelope
    let destinationRelay: RelayEndpoint?
}

struct FetchGroupMessagesRequest: Codable, Equatable {
    let groupId: UUID
    let groupInboxId: String
    let maxCount: Int?
    let longPollTimeoutSeconds: Int?
    let actorFingerprint: String
    let actorProof: RelayActorProof?

    init(
        groupId: UUID,
        groupInboxId: String,
        maxCount: Int? = nil,
        longPollTimeoutSeconds: Int? = nil,
        actorFingerprint: String,
        actorProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.groupInboxId = groupInboxId
        self.maxCount = maxCount
        self.longPollTimeoutSeconds = longPollTimeoutSeconds
        self.actorFingerprint = actorFingerprint
        self.actorProof = actorProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            GroupMessageFetchProofPayload(
                groupId: groupId,
                groupInboxId: groupInboxId,
                maxCount: maxCount,
                longPollTimeoutSeconds: longPollTimeoutSeconds,
                actorFingerprint: actorFingerprint,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

struct AcknowledgeGroupMessagesRequest: Codable, Equatable {
    let groupId: UUID
    let groupInboxId: String
    let messageIds: [UUID]
    let actorFingerprint: String
    let actorProof: RelayActorProof?

    init(
        groupId: UUID,
        groupInboxId: String,
        messageIds: [UUID],
        actorFingerprint: String,
        actorProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.groupInboxId = groupInboxId
        self.messageIds = messageIds
        self.actorFingerprint = actorFingerprint
        self.actorProof = actorProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            GroupMessageAcknowledgementProofPayload(
                groupId: groupId,
                groupInboxId: groupInboxId,
                messageIds: messageIds,
                actorFingerprint: actorFingerprint,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

enum RelayRequestType: String, Codable {
    case deliver
    case registerInbox
    case fetch
    case acknowledgeMessages
    case deliverGroupMessage
    case fetchGroupMessages
    case acknowledgeGroupMessages
    case health
    case info
    case announce
    case listAnnouncements
    case sendPairRequest
    case fetchPairRequests
    case uploadAttachment
    case fetchAttachment
    case uploadPrekeys
    case fetchPrekeyBundle
    case createGroup
    case getGroup
    case listGroups
    case updateGroup
    case deleteGroup
    case requestGroupJoin
    case listGroupJoinRequests
    case approveGroupJoin
    case rejectGroupJoin
    case registerFederationNode
    case listFederationNodes
    case publishOpenFederationDHTRecord
    case listOpenFederationDHTRecords
}

struct FederationNodeRegistrationRequest: Codable, Equatable {
    let endpoint: RelayEndpoint
    let relayInfo: RelayInfo
    let ttlSeconds: Int?

    init(endpoint: RelayEndpoint, relayInfo: RelayInfo, ttlSeconds: Int? = nil) {
        self.endpoint = endpoint
        self.relayInfo = relayInfo
        self.ttlSeconds = ttlSeconds
    }
}

struct ListFederationNodesRequest: Codable, Equatable {
    let mode: FederationMode?
    let federationName: String?
    let onlyHealthy: Bool?
    let maxStalenessSeconds: Int?
    let requireSignedSnapshot: Bool?

    init(
        mode: FederationMode? = nil,
        federationName: String? = nil,
        onlyHealthy: Bool? = nil,
        maxStalenessSeconds: Int? = nil,
        requireSignedSnapshot: Bool? = nil
    ) {
        self.mode = mode
        self.federationName = federationName
        self.onlyHealthy = onlyHealthy
        self.maxStalenessSeconds = maxStalenessSeconds
        self.requireSignedSnapshot = requireSignedSnapshot
    }
}

struct FederationNodeRecord: Codable, Equatable {
    let endpoint: RelayEndpoint
    let relayInfo: RelayInfo
    let lastHeartbeatAt: Date
    let expiresAt: Date
}

struct FederationDirectorySnapshot: Codable, Equatable {
    let version: Int
    let mode: FederationMode
    let federationName: String?
    let issuedAt: Date
    let validUntil: Date
    let maxStalenessSeconds: Int
    let nodes: [FederationNodeRecord]
    let signatureAlgorithm: String?
    let signature: Data?

    init(
        version: Int = 1,
        mode: FederationMode,
        federationName: String?,
        issuedAt: Date,
        validUntil: Date,
        maxStalenessSeconds: Int,
        nodes: [FederationNodeRecord],
        signatureAlgorithm: String? = nil,
        signature: Data? = nil
    ) {
        self.version = version
        self.mode = mode
        self.federationName = federationName
        self.issuedAt = issuedAt
        self.validUntil = validUntil
        self.maxStalenessSeconds = max(1, maxStalenessSeconds)
        self.nodes = nodes
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }
}

struct PublishOpenFederationDHTRecordRequest: Codable, Equatable {
    let namespace: String
    let record: OpenFederationDHTRecord
}

struct ListOpenFederationDHTRecordsRequest: Codable, Equatable {
    let namespace: String
    let limit: Int?
}

struct RelayRequest: Codable, Equatable {
    let type: RelayRequestType
    let authToken: String?
    let deliver: DeliverRequest?
    let registerInbox: RegisterInboxRequest?
    let fetch: FetchRequest?
    let acknowledgeMessages: AcknowledgeMessagesRequest?
    let deliverGroupMessage: DeliverGroupMessageRequest?
    let fetchGroupMessages: FetchGroupMessagesRequest?
    let acknowledgeGroupMessages: AcknowledgeGroupMessagesRequest?
    let announce: AnnounceRequest?
    let listAnnouncements: ListAnnouncementsRequest?
    let sendPairRequest: SendPairRequest?
    let fetchPairRequests: FetchPairRequestsRequest?
    let uploadAttachment: UploadAttachmentRequest?
    let fetchAttachment: FetchAttachmentRequest?
    let uploadPrekeys: UploadPrekeyBundleRequest?
    let fetchPrekeyBundle: FetchPrekeyBundleRequest?
    let createGroup: CreateGroupRequest?
    let getGroup: GetGroupRequest?
    let listGroups: ListGroupsRequest?
    let updateGroup: UpdateGroupRequest?
    let deleteGroup: DeleteGroupRequest?
    let requestGroupJoin: RequestGroupJoinRequest?
    let listGroupJoinRequests: ListGroupJoinRequestsRequest?
    let approveGroupJoin: ApproveGroupJoinRequest?
    let rejectGroupJoin: RejectGroupJoinRequest?
    let registerFederationNode: FederationNodeRegistrationRequest?
    let listFederationNodes: ListFederationNodesRequest?
    let publishOpenFederationDHTRecord: PublishOpenFederationDHTRecordRequest?
    let listOpenFederationDHTRecords: ListOpenFederationDHTRecordsRequest?

    init(
        type: RelayRequestType,
        authToken: String? = nil,
        deliver: DeliverRequest? = nil,
        registerInbox: RegisterInboxRequest? = nil,
        fetch: FetchRequest? = nil,
        acknowledgeMessages: AcknowledgeMessagesRequest? = nil,
        deliverGroupMessage: DeliverGroupMessageRequest? = nil,
        fetchGroupMessages: FetchGroupMessagesRequest? = nil,
        acknowledgeGroupMessages: AcknowledgeGroupMessagesRequest? = nil,
        announce: AnnounceRequest? = nil,
        listAnnouncements: ListAnnouncementsRequest? = nil,
        sendPairRequest: SendPairRequest? = nil,
        fetchPairRequests: FetchPairRequestsRequest? = nil,
        uploadAttachment: UploadAttachmentRequest? = nil,
        fetchAttachment: FetchAttachmentRequest? = nil,
        uploadPrekeys: UploadPrekeyBundleRequest? = nil,
        fetchPrekeyBundle: FetchPrekeyBundleRequest? = nil,
        createGroup: CreateGroupRequest? = nil,
        getGroup: GetGroupRequest? = nil,
        listGroups: ListGroupsRequest? = nil,
        updateGroup: UpdateGroupRequest? = nil,
        deleteGroup: DeleteGroupRequest? = nil,
        requestGroupJoin: RequestGroupJoinRequest? = nil,
        listGroupJoinRequests: ListGroupJoinRequestsRequest? = nil,
        approveGroupJoin: ApproveGroupJoinRequest? = nil,
        rejectGroupJoin: RejectGroupJoinRequest? = nil,
        registerFederationNode: FederationNodeRegistrationRequest? = nil,
        listFederationNodes: ListFederationNodesRequest? = nil,
        publishOpenFederationDHTRecord: PublishOpenFederationDHTRecordRequest? = nil,
        listOpenFederationDHTRecords: ListOpenFederationDHTRecordsRequest? = nil
    ) {
        self.type = type
        self.authToken = authToken
        self.deliver = deliver
        self.registerInbox = registerInbox
        self.fetch = fetch
        self.acknowledgeMessages = acknowledgeMessages
        self.deliverGroupMessage = deliverGroupMessage
        self.fetchGroupMessages = fetchGroupMessages
        self.acknowledgeGroupMessages = acknowledgeGroupMessages
        self.announce = announce
        self.listAnnouncements = listAnnouncements
        self.sendPairRequest = sendPairRequest
        self.fetchPairRequests = fetchPairRequests
        self.uploadAttachment = uploadAttachment
        self.fetchAttachment = fetchAttachment
        self.uploadPrekeys = uploadPrekeys
        self.fetchPrekeyBundle = fetchPrekeyBundle
        self.createGroup = createGroup
        self.getGroup = getGroup
        self.listGroups = listGroups
        self.updateGroup = updateGroup
        self.deleteGroup = deleteGroup
        self.requestGroupJoin = requestGroupJoin
        self.listGroupJoinRequests = listGroupJoinRequests
        self.approveGroupJoin = approveGroupJoin
        self.rejectGroupJoin = rejectGroupJoin
        self.registerFederationNode = registerFederationNode
        self.listFederationNodes = listFederationNodes
        self.publishOpenFederationDHTRecord = publishOpenFederationDHTRecord
        self.listOpenFederationDHTRecords = listOpenFederationDHTRecords
    }

    static func deliver(_ request: DeliverRequest) -> RelayRequest {
        RelayRequest(
            type: .deliver,
            deliver: request,
            fetch: nil,
            announce: nil,
            listAnnouncements: nil,
            sendPairRequest: nil,
            fetchPairRequests: nil,
            uploadAttachment: nil,
            fetchAttachment: nil,
            uploadPrekeys: nil,
            fetchPrekeyBundle: nil,
            createGroup: nil,
            getGroup: nil,
            listGroups: nil,
            updateGroup: nil
        )
    }

    static func registerInbox(_ request: RegisterInboxRequest) -> RelayRequest {
        RelayRequest(type: .registerInbox, registerInbox: request)
    }

    static func fetch(_ request: FetchRequest) -> RelayRequest {
        RelayRequest(
            type: .fetch,
            deliver: nil,
            fetch: request,
            announce: nil,
            listAnnouncements: nil,
            sendPairRequest: nil,
            fetchPairRequests: nil,
            uploadAttachment: nil,
            fetchAttachment: nil,
            uploadPrekeys: nil,
            fetchPrekeyBundle: nil,
            createGroup: nil,
            getGroup: nil,
            listGroups: nil,
            updateGroup: nil
        )
    }

    static func acknowledgeMessages(_ request: AcknowledgeMessagesRequest) -> RelayRequest {
        RelayRequest(type: .acknowledgeMessages, acknowledgeMessages: request)
    }

    static func deliverGroupMessage(_ request: DeliverGroupMessageRequest) -> RelayRequest {
        RelayRequest(type: .deliverGroupMessage, deliverGroupMessage: request)
    }

    static func fetchGroupMessages(_ request: FetchGroupMessagesRequest) -> RelayRequest {
        RelayRequest(type: .fetchGroupMessages, fetchGroupMessages: request)
    }

    static func acknowledgeGroupMessages(_ request: AcknowledgeGroupMessagesRequest) -> RelayRequest {
        RelayRequest(type: .acknowledgeGroupMessages, acknowledgeGroupMessages: request)
    }

    static func health() -> RelayRequest {
        RelayRequest(
            type: .health,
            deliver: nil,
            fetch: nil,
            announce: nil,
            listAnnouncements: nil,
            sendPairRequest: nil,
            fetchPairRequests: nil,
            uploadAttachment: nil,
            fetchAttachment: nil,
            uploadPrekeys: nil,
            fetchPrekeyBundle: nil,
            createGroup: nil,
            getGroup: nil,
            listGroups: nil,
            updateGroup: nil
        )
    }

    static func info() -> RelayRequest {
        RelayRequest(
            type: .info,
            deliver: nil,
            fetch: nil,
            announce: nil,
            listAnnouncements: nil,
            sendPairRequest: nil,
            fetchPairRequests: nil,
            uploadAttachment: nil,
            fetchAttachment: nil,
            uploadPrekeys: nil,
            fetchPrekeyBundle: nil,
            createGroup: nil,
            getGroup: nil,
            listGroups: nil,
            updateGroup: nil
        )
    }

    static func announce(_ request: AnnounceRequest) -> RelayRequest {
        RelayRequest(
            type: .announce,
            deliver: nil,
            fetch: nil,
            announce: request,
            listAnnouncements: nil,
            sendPairRequest: nil,
            fetchPairRequests: nil,
            uploadAttachment: nil,
            fetchAttachment: nil,
            uploadPrekeys: nil,
            fetchPrekeyBundle: nil,
            createGroup: nil,
            getGroup: nil,
            listGroups: nil,
            updateGroup: nil
        )
    }

    static func listAnnouncements(_ request: ListAnnouncementsRequest) -> RelayRequest {
        RelayRequest(
            type: .listAnnouncements,
            deliver: nil,
            fetch: nil,
            announce: nil,
            listAnnouncements: request,
            sendPairRequest: nil,
            fetchPairRequests: nil,
            uploadAttachment: nil,
            fetchAttachment: nil,
            uploadPrekeys: nil,
            fetchPrekeyBundle: nil,
            createGroup: nil,
            getGroup: nil,
            listGroups: nil,
            updateGroup: nil
        )
    }

    static func sendPairRequest(_ request: SendPairRequest) -> RelayRequest {
        RelayRequest(
            type: .sendPairRequest,
            deliver: nil,
            fetch: nil,
            announce: nil,
            listAnnouncements: nil,
            sendPairRequest: request,
            fetchPairRequests: nil,
            uploadAttachment: nil,
            fetchAttachment: nil,
            uploadPrekeys: nil,
            fetchPrekeyBundle: nil
        )
    }

    static func fetchPairRequests(_ request: FetchPairRequestsRequest) -> RelayRequest {
        RelayRequest(
            type: .fetchPairRequests,
            deliver: nil,
            fetch: nil,
            announce: nil,
            listAnnouncements: nil,
            sendPairRequest: nil,
            fetchPairRequests: request,
            uploadAttachment: nil,
            fetchAttachment: nil,
            uploadPrekeys: nil,
            fetchPrekeyBundle: nil
        )
    }

    static func uploadAttachment(_ request: UploadAttachmentRequest) -> RelayRequest {
        RelayRequest(
            type: .uploadAttachment,
            deliver: nil,
            fetch: nil,
            announce: nil,
            listAnnouncements: nil,
            sendPairRequest: nil,
            fetchPairRequests: nil,
            uploadAttachment: request,
            fetchAttachment: nil,
            uploadPrekeys: nil,
            fetchPrekeyBundle: nil,
            createGroup: nil,
            getGroup: nil,
            listGroups: nil,
            updateGroup: nil
        )
    }

    static func fetchAttachment(_ request: FetchAttachmentRequest) -> RelayRequest {
        RelayRequest(
            type: .fetchAttachment,
            deliver: nil,
            fetch: nil,
            announce: nil,
            listAnnouncements: nil,
            sendPairRequest: nil,
            fetchPairRequests: nil,
            uploadAttachment: nil,
            fetchAttachment: request,
            uploadPrekeys: nil,
            fetchPrekeyBundle: nil,
            createGroup: nil,
            getGroup: nil,
            listGroups: nil,
            updateGroup: nil
        )
    }

    static func uploadPrekeys(_ request: UploadPrekeyBundleRequest) -> RelayRequest {
        RelayRequest(
            type: .uploadPrekeys,
            deliver: nil,
            fetch: nil,
            announce: nil,
            listAnnouncements: nil,
            sendPairRequest: nil,
            fetchPairRequests: nil,
            uploadAttachment: nil,
            fetchAttachment: nil,
            uploadPrekeys: request,
            fetchPrekeyBundle: nil,
            createGroup: nil,
            getGroup: nil,
            listGroups: nil,
            updateGroup: nil
        )
    }

    static func fetchPrekeyBundle(_ request: FetchPrekeyBundleRequest) -> RelayRequest {
        RelayRequest(
            type: .fetchPrekeyBundle,
            deliver: nil,
            fetch: nil,
            announce: nil,
            listAnnouncements: nil,
            sendPairRequest: nil,
            fetchPairRequests: nil,
            uploadAttachment: nil,
            fetchAttachment: nil,
            uploadPrekeys: nil,
            fetchPrekeyBundle: request,
            createGroup: nil,
            getGroup: nil,
            listGroups: nil,
            updateGroup: nil
        )
    }

    static func createGroup(_ request: CreateGroupRequest) -> RelayRequest {
        RelayRequest(
            type: .createGroup,
            deliver: nil,
            fetch: nil,
            announce: nil,
            listAnnouncements: nil,
            sendPairRequest: nil,
            fetchPairRequests: nil,
            uploadAttachment: nil,
            fetchAttachment: nil,
            uploadPrekeys: nil,
            fetchPrekeyBundle: nil,
            createGroup: request,
            getGroup: nil,
            listGroups: nil,
            updateGroup: nil
        )
    }

    static func getGroup(_ request: GetGroupRequest) -> RelayRequest {
        RelayRequest(
            type: .getGroup,
            deliver: nil,
            fetch: nil,
            announce: nil,
            listAnnouncements: nil,
            sendPairRequest: nil,
            fetchPairRequests: nil,
            uploadAttachment: nil,
            fetchAttachment: nil,
            uploadPrekeys: nil,
            fetchPrekeyBundle: nil,
            createGroup: nil,
            getGroup: request,
            listGroups: nil,
            updateGroup: nil
        )
    }

    static func listGroups(_ request: ListGroupsRequest) -> RelayRequest {
        RelayRequest(
            type: .listGroups,
            deliver: nil,
            fetch: nil,
            announce: nil,
            listAnnouncements: nil,
            sendPairRequest: nil,
            fetchPairRequests: nil,
            uploadAttachment: nil,
            fetchAttachment: nil,
            uploadPrekeys: nil,
            fetchPrekeyBundle: nil,
            createGroup: nil,
            getGroup: nil,
            listGroups: request,
            updateGroup: nil
        )
    }

    static func updateGroup(_ request: UpdateGroupRequest) -> RelayRequest {
        RelayRequest(
            type: .updateGroup,
            deliver: nil,
            fetch: nil,
            announce: nil,
            listAnnouncements: nil,
            sendPairRequest: nil,
            fetchPairRequests: nil,
            uploadAttachment: nil,
            fetchAttachment: nil,
            uploadPrekeys: nil,
            fetchPrekeyBundle: nil,
            createGroup: nil,
            getGroup: nil,
            listGroups: nil,
            updateGroup: request
        )
    }

    static func deleteGroup(_ request: DeleteGroupRequest) -> RelayRequest {
        RelayRequest(type: .deleteGroup, deleteGroup: request)
    }

    static func requestGroupJoin(_ request: RequestGroupJoinRequest) -> RelayRequest {
        RelayRequest(type: .requestGroupJoin, requestGroupJoin: request)
    }

    static func listGroupJoinRequests(_ request: ListGroupJoinRequestsRequest) -> RelayRequest {
        RelayRequest(type: .listGroupJoinRequests, listGroupJoinRequests: request)
    }

    static func approveGroupJoin(_ request: ApproveGroupJoinRequest) -> RelayRequest {
        RelayRequest(type: .approveGroupJoin, approveGroupJoin: request)
    }

    static func rejectGroupJoin(_ request: RejectGroupJoinRequest) -> RelayRequest {
        RelayRequest(type: .rejectGroupJoin, rejectGroupJoin: request)
    }

    static func registerFederationNode(_ request: FederationNodeRegistrationRequest) -> RelayRequest {
        RelayRequest(type: .registerFederationNode, registerFederationNode: request)
    }

    static func listFederationNodes(_ request: ListFederationNodesRequest) -> RelayRequest {
        RelayRequest(type: .listFederationNodes, listFederationNodes: request)
    }

    static func publishOpenFederationDHTRecord(_ request: PublishOpenFederationDHTRecordRequest) -> RelayRequest {
        RelayRequest(type: .publishOpenFederationDHTRecord, publishOpenFederationDHTRecord: request)
    }

    static func listOpenFederationDHTRecords(_ request: ListOpenFederationDHTRecordsRequest) -> RelayRequest {
        RelayRequest(type: .listOpenFederationDHTRecords, listOpenFederationDHTRecords: request)
    }

    func withAuthToken(_ token: String?) -> RelayRequest {
        RelayRequest(
            type: type,
            authToken: token,
            deliver: deliver,
            registerInbox: registerInbox,
            fetch: fetch,
            acknowledgeMessages: acknowledgeMessages,
            deliverGroupMessage: deliverGroupMessage,
            fetchGroupMessages: fetchGroupMessages,
            acknowledgeGroupMessages: acknowledgeGroupMessages,
            announce: announce,
            listAnnouncements: listAnnouncements,
            sendPairRequest: sendPairRequest,
            fetchPairRequests: fetchPairRequests,
            uploadAttachment: uploadAttachment,
            fetchAttachment: fetchAttachment,
            uploadPrekeys: uploadPrekeys,
            fetchPrekeyBundle: fetchPrekeyBundle,
            createGroup: createGroup,
            getGroup: getGroup,
            listGroups: listGroups,
            updateGroup: updateGroup,
            deleteGroup: deleteGroup,
            requestGroupJoin: requestGroupJoin,
            listGroupJoinRequests: listGroupJoinRequests,
            approveGroupJoin: approveGroupJoin,
            rejectGroupJoin: rejectGroupJoin,
            registerFederationNode: registerFederationNode,
            listFederationNodes: listFederationNodes,
            publishOpenFederationDHTRecord: publishOpenFederationDHTRecord,
            listOpenFederationDHTRecords: listOpenFederationDHTRecords
        )
    }
}

private struct InboxRegistrationProofPayload: Codable {
    let inboxId: String
    let accessPublicKey: Data
    let contactOffer: ContactOffer?
    let signedAt: Date
    let nonce: UUID
}

private struct InboxFetchProofPayload: Codable {
    let inboxId: String
    let routingToken: String?
    let maxCount: Int?
    let longPollTimeoutSeconds: Int?
    let signedAt: Date
    let nonce: UUID
}

private struct InboxAcknowledgementProofPayload: Codable {
    let inboxId: String
    let messageIds: [UUID]
    let signedAt: Date
    let nonce: UUID
}

private struct GroupMessageFetchProofPayload: Codable {
    let groupId: UUID
    let groupInboxId: String
    let maxCount: Int?
    let longPollTimeoutSeconds: Int?
    let actorFingerprint: String
    let signedAt: Date
    let nonce: UUID
}

private struct GroupMessageAcknowledgementProofPayload: Codable {
    let groupId: UUID
    let groupInboxId: String
    let messageIds: [UUID]
    let actorFingerprint: String
    let signedAt: Date
    let nonce: UUID
}

private struct GroupRatchetSignaturePayload: Codable {
    let version: Int
    let groupId: UUID
    let epoch: UInt64
    let transcriptHash: Data
    let senderFingerprint: String
    let sentAt: Date
    let messageCounter: UInt64
    let payload: EncryptedPayload
}

enum RelayResponseType: String, Codable {
    case ok
    case delivered
    case messages
    case groupMessages
    case announcements
    case pairRequests
    case attachment
    case info
    case prekeyBundle
    case group
    case groups
    case groupJoinRequests
    case federationNodes
    case openFederationDHTRecords
    case error
}

struct DeliverResponse: Codable, Equatable {
    let storedCount: Int
}

struct RelayResponse: Codable, Equatable {
    let type: RelayResponseType
    let delivered: DeliverResponse?
    let messages: [Envelope]?
    let groupMessages: [GroupRatchetEnvelope]?
    let announcements: [PairingAnnouncement]?
    let pairRequests: [PairingRequest]?
    let attachment: AttachmentChunk?
    let relayInfo: RelayInfo?
    let prekeyBundle: PrekeyBundle?
    let group: RelayGroupDescriptor?
    let groups: [RelayGroupDescriptor]?
    let groupJoinRequests: [RelayGroupJoinRequest]?
    let federationNodes: [FederationNodeRecord]?
    let federationSnapshot: FederationDirectorySnapshot?
    let openFederationDHTRecords: [OpenFederationDHTRecord]?
    let error: String?

    init(
        type: RelayResponseType,
        delivered: DeliverResponse? = nil,
        messages: [Envelope]? = nil,
        groupMessages: [GroupRatchetEnvelope]? = nil,
        announcements: [PairingAnnouncement]? = nil,
        pairRequests: [PairingRequest]? = nil,
        attachment: AttachmentChunk? = nil,
        relayInfo: RelayInfo? = nil,
        prekeyBundle: PrekeyBundle? = nil,
        group: RelayGroupDescriptor? = nil,
        groups: [RelayGroupDescriptor]? = nil,
        groupJoinRequests: [RelayGroupJoinRequest]? = nil,
        federationNodes: [FederationNodeRecord]? = nil,
        federationSnapshot: FederationDirectorySnapshot? = nil,
        openFederationDHTRecords: [OpenFederationDHTRecord]? = nil,
        error: String? = nil
    ) {
        self.type = type
        self.delivered = delivered
        self.messages = messages
        self.groupMessages = groupMessages
        self.announcements = announcements
        self.pairRequests = pairRequests
        self.attachment = attachment
        self.relayInfo = relayInfo
        self.prekeyBundle = prekeyBundle
        self.group = group
        self.groups = groups
        self.groupJoinRequests = groupJoinRequests
        self.federationNodes = federationNodes
        self.federationSnapshot = federationSnapshot
        self.openFederationDHTRecords = openFederationDHTRecords
        self.error = error
    }

    static func ok() -> RelayResponse {
        RelayResponse(
            type: .ok,
            delivered: nil,
            messages: nil,
            announcements: nil,
            pairRequests: nil,
            attachment: nil,
            relayInfo: nil,
            prekeyBundle: nil,
            group: nil,
            groups: nil,
            error: nil
        )
    }

    static func delivered(count: Int) -> RelayResponse {
        RelayResponse(
            type: .delivered,
            delivered: DeliverResponse(storedCount: count),
            messages: nil,
            announcements: nil,
            pairRequests: nil,
            attachment: nil,
            relayInfo: nil,
            prekeyBundle: nil,
            group: nil,
            groups: nil,
            error: nil
        )
    }

    static func messages(_ envelopes: [Envelope]) -> RelayResponse {
        RelayResponse(
            type: .messages,
            delivered: nil,
            messages: envelopes,
            announcements: nil,
            pairRequests: nil,
            attachment: nil,
            relayInfo: nil,
            prekeyBundle: nil,
            group: nil,
            groups: nil,
            error: nil
        )
    }

    static func groupMessages(_ envelopes: [GroupRatchetEnvelope]) -> RelayResponse {
        RelayResponse(type: .groupMessages, groupMessages: envelopes)
    }

    static func announcements(_ list: [PairingAnnouncement]) -> RelayResponse {
        RelayResponse(
            type: .announcements,
            delivered: nil,
            messages: nil,
            announcements: list,
            pairRequests: nil,
            attachment: nil,
            relayInfo: nil,
            prekeyBundle: nil,
            group: nil,
            groups: nil,
            error: nil
        )
    }

    static func pairRequests(_ list: [PairingRequest]) -> RelayResponse {
        RelayResponse(
            type: .pairRequests,
            delivered: nil,
            messages: nil,
            announcements: nil,
            pairRequests: list,
            attachment: nil,
            relayInfo: nil,
            prekeyBundle: nil,
            group: nil,
            groups: nil,
            error: nil
        )
    }

    static func attachment(_ chunk: AttachmentChunk) -> RelayResponse {
        RelayResponse(
            type: .attachment,
            delivered: nil,
            messages: nil,
            announcements: nil,
            pairRequests: nil,
            attachment: chunk,
            relayInfo: nil,
            prekeyBundle: nil,
            group: nil,
            groups: nil,
            error: nil
        )
    }

    static func info(_ info: RelayInfo) -> RelayResponse {
        RelayResponse(
            type: .info,
            delivered: nil,
            messages: nil,
            announcements: nil,
            pairRequests: nil,
            attachment: nil,
            relayInfo: info,
            prekeyBundle: nil,
            group: nil,
            groups: nil,
            error: nil
        )
    }

    static func prekeyBundle(_ bundle: PrekeyBundle?) -> RelayResponse {
        RelayResponse(
            type: .prekeyBundle,
            delivered: nil,
            messages: nil,
            announcements: nil,
            pairRequests: nil,
            attachment: nil,
            relayInfo: nil,
            prekeyBundle: bundle,
            group: nil,
            groups: nil,
            error: nil
        )
    }

    static func group(_ group: RelayGroupDescriptor?) -> RelayResponse {
        RelayResponse(
            type: .group,
            delivered: nil,
            messages: nil,
            announcements: nil,
            pairRequests: nil,
            attachment: nil,
            relayInfo: nil,
            prekeyBundle: nil,
            group: group,
            groups: nil,
            error: nil
        )
    }

    static func groups(_ groups: [RelayGroupDescriptor]) -> RelayResponse {
        RelayResponse(
            type: .groups,
            delivered: nil,
            messages: nil,
            announcements: nil,
            pairRequests: nil,
            attachment: nil,
            relayInfo: nil,
            prekeyBundle: nil,
            group: nil,
            groups: groups,
            groupJoinRequests: nil,
            error: nil
        )
    }

    static func groupJoinRequests(_ requests: [RelayGroupJoinRequest]) -> RelayResponse {
        RelayResponse(type: .groupJoinRequests, groupJoinRequests: requests)
    }

    static func federationNodes(
        _ nodes: [FederationNodeRecord],
        snapshot: FederationDirectorySnapshot? = nil
    ) -> RelayResponse {
        RelayResponse(type: .federationNodes, federationNodes: nodes, federationSnapshot: snapshot)
    }

    static func openFederationDHTRecords(_ records: [OpenFederationDHTRecord]) -> RelayResponse {
        RelayResponse(type: .openFederationDHTRecords, openFederationDHTRecords: records)
    }

    static func error(_ message: String) -> RelayResponse {
        RelayResponse(
            type: .error,
            delivered: nil,
            messages: nil,
            announcements: nil,
            pairRequests: nil,
            attachment: nil,
            relayInfo: nil,
            prekeyBundle: nil,
            group: nil,
            groups: nil,
            error: message
        )
    }
}

struct CreateGroupRequest: Codable, Equatable {
    let groupId: UUID?
    let title: String
    let creatorFingerprint: String
    let memberFingerprints: [String]
    let creatorProfile: RelayGroupMemberProfile?
    let memberProfiles: [RelayGroupMemberProfile]?
    let initialRatchetSecretDistribution: GroupRatchetEpochSecretDistribution?
    let creatorProof: RelayActorProof?

    init(
        groupId: UUID? = nil,
        title: String,
        creatorFingerprint: String,
        memberFingerprints: [String],
        creatorProfile: RelayGroupMemberProfile? = nil,
        memberProfiles: [RelayGroupMemberProfile]? = nil,
        initialRatchetSecretDistribution: GroupRatchetEpochSecretDistribution? = nil,
        creatorProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.title = title
        self.creatorFingerprint = creatorFingerprint
        self.memberFingerprints = memberFingerprints
        self.creatorProfile = creatorProfile
        self.memberProfiles = memberProfiles
        self.initialRatchetSecretDistribution = initialRatchetSecretDistribution
        self.creatorProof = creatorProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            CreateGroupProofPayload(
                groupId: groupId,
                title: title,
                creatorFingerprint: creatorFingerprint,
                memberFingerprints: memberFingerprints,
                creatorProfile: creatorProfile,
                memberProfiles: memberProfiles,
                initialRatchetSecretDistribution: initialRatchetSecretDistribution,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

struct GetGroupRequest: Codable, Equatable {
    let groupId: UUID
    let memberFingerprint: String?
    let memberProof: RelayActorProof?

    init(
        groupId: UUID,
        memberFingerprint: String? = nil,
        memberProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.memberFingerprint = memberFingerprint
        self.memberProof = memberProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            GetGroupProofPayload(
                groupId: groupId,
                memberFingerprint: memberFingerprint,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

struct ListGroupsRequest: Codable, Equatable {
    let memberFingerprint: String
    let limit: Int?
    let memberProof: RelayActorProof?

    init(
        memberFingerprint: String,
        limit: Int? = nil,
        memberProof: RelayActorProof? = nil
    ) {
        self.memberFingerprint = memberFingerprint
        self.limit = limit
        self.memberProof = memberProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            ListGroupsProofPayload(
                memberFingerprint: memberFingerprint,
                limit: limit,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

struct UpdateGroupRequest: Codable, Equatable {
    let groupId: UUID
    let actorFingerprint: String
    let title: String?
    let addMemberFingerprints: [String]
    let addMemberProfiles: [RelayGroupMemberProfile]?
    let removeMemberFingerprints: [String]
    let actorProof: RelayActorProof?
    let groupCommit: SignedGroupCommit?

    init(
        groupId: UUID,
        actorFingerprint: String,
        title: String? = nil,
        addMemberFingerprints: [String] = [],
        addMemberProfiles: [RelayGroupMemberProfile]? = nil,
        removeMemberFingerprints: [String] = [],
        actorProof: RelayActorProof? = nil,
        groupCommit: SignedGroupCommit? = nil
    ) {
        self.groupId = groupId
        self.actorFingerprint = actorFingerprint
        self.title = title
        self.addMemberFingerprints = addMemberFingerprints
        self.addMemberProfiles = addMemberProfiles
        self.removeMemberFingerprints = removeMemberFingerprints
        self.actorProof = actorProof
        self.groupCommit = groupCommit
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            UpdateGroupProofPayload(
                groupId: groupId,
                actorFingerprint: actorFingerprint,
                title: title,
                addMemberFingerprints: addMemberFingerprints,
                addMemberProfiles: addMemberProfiles,
                removeMemberFingerprints: removeMemberFingerprints,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }

    var normalizedTitle: String? {
        guard let title = title?.trimmingCharacters(in: .whitespacesAndNewlines),
              !title.isEmpty else {
            return nil
        }
        return title
    }

    var normalizedAddMemberFingerprints: [String] {
        Array(Set(addMemberFingerprints.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty })).sorted()
    }

    var normalizedAddMemberProfiles: [RelayGroupMemberProfile] {
        (addMemberProfiles ?? [])
            .filter { !$0.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            .sorted { $0.fingerprint < $1.fingerprint }
    }

    var normalizedRemoveMemberFingerprints: [String] {
        Array(Set(removeMemberFingerprints.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty })).sorted()
    }
}

struct SignedGroupCommit: Codable, Equatable {
    let operation: MLSGroupCommitOperation
    let groupId: UUID
    let actorFingerprint: String
    let baseEpoch: UInt64
    let previousTranscriptHash: Data
    let title: String?
    let addMemberFingerprints: [String]
    let addMemberProfiles: [RelayGroupMemberProfile]?
    let removeMemberFingerprints: [String]
    let ratchetSecretDistribution: GroupRatchetEpochSecretDistribution?
    let actorProof: RelayActorProof?

    init(
        operation: MLSGroupCommitOperation,
        groupId: UUID,
        actorFingerprint: String,
        baseEpoch: UInt64,
        previousTranscriptHash: Data,
        title: String? = nil,
        addMemberFingerprints: [String] = [],
        addMemberProfiles: [RelayGroupMemberProfile]? = nil,
        removeMemberFingerprints: [String] = [],
        ratchetSecretDistribution: GroupRatchetEpochSecretDistribution? = nil,
        actorProof: RelayActorProof? = nil
    ) {
        self.operation = operation
        self.groupId = groupId
        self.actorFingerprint = actorFingerprint
        self.baseEpoch = baseEpoch
        self.previousTranscriptHash = previousTranscriptHash
        self.title = title
        self.addMemberFingerprints = addMemberFingerprints
        self.addMemberProfiles = addMemberProfiles
        self.removeMemberFingerprints = removeMemberFingerprints
        self.ratchetSecretDistribution = ratchetSecretDistribution
        self.actorProof = actorProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            SignedGroupCommitProofPayload(
                operation: operation,
                groupId: groupId,
                actorFingerprint: actorFingerprint,
                baseEpoch: baseEpoch,
                previousTranscriptHash: previousTranscriptHash,
                title: title,
                addMemberFingerprints: addMemberFingerprints,
                addMemberProfiles: addMemberProfiles,
                removeMemberFingerprints: removeMemberFingerprints,
                ratchetSecretDistribution: ratchetSecretDistribution,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

struct DeleteGroupRequest: Codable, Equatable {
    let groupId: UUID
    let actorFingerprint: String
    let actorProof: RelayActorProof?

    init(
        groupId: UUID,
        actorFingerprint: String,
        actorProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.actorFingerprint = actorFingerprint
        self.actorProof = actorProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            DeleteGroupProofPayload(
                groupId: groupId,
                actorFingerprint: actorFingerprint,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

struct RequestGroupJoinRequest: Codable, Equatable {
    let groupId: UUID
    let requesterProfile: RelayGroupMemberProfile
    let requesterProof: RelayActorProof?

    init(
        groupId: UUID,
        requesterProfile: RelayGroupMemberProfile,
        requesterProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.requesterProfile = requesterProfile
        self.requesterProof = requesterProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            RequestGroupJoinProofPayload(
                groupId: groupId,
                requesterProfile: requesterProfile,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

struct ListGroupJoinRequestsRequest: Codable, Equatable {
    let groupId: UUID
    let actorFingerprint: String
    let limit: Int?
    let actorProof: RelayActorProof?

    init(
        groupId: UUID,
        actorFingerprint: String,
        limit: Int? = nil,
        actorProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.actorFingerprint = actorFingerprint
        self.limit = limit
        self.actorProof = actorProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            ListGroupJoinProofPayload(
                groupId: groupId,
                actorFingerprint: actorFingerprint,
                limit: limit,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

struct ApproveGroupJoinRequest: Codable, Equatable {
    let groupId: UUID
    let actorFingerprint: String
    let joinRequestId: UUID
    let groupCommit: SignedGroupCommit
    let actorProof: RelayActorProof?

    init(
        groupId: UUID,
        actorFingerprint: String,
        joinRequestId: UUID,
        groupCommit: SignedGroupCommit,
        actorProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.actorFingerprint = actorFingerprint
        self.joinRequestId = joinRequestId
        self.groupCommit = groupCommit
        self.actorProof = actorProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            ApproveGroupJoinProofPayload(
                groupId: groupId,
                actorFingerprint: actorFingerprint,
                joinRequestId: joinRequestId,
                groupCommit: groupCommit,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

struct RejectGroupJoinRequest: Codable, Equatable {
    let groupId: UUID
    let actorFingerprint: String
    let joinRequestId: UUID
    let actorProof: RelayActorProof?

    init(
        groupId: UUID,
        actorFingerprint: String,
        joinRequestId: UUID,
        actorProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.actorFingerprint = actorFingerprint
        self.joinRequestId = joinRequestId
        self.actorProof = actorProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            RejectGroupJoinProofPayload(
                groupId: groupId,
                actorFingerprint: actorFingerprint,
                joinRequestId: joinRequestId,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

private enum GroupProofCodec {
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        try RelayCodec.encoder(sortedKeys: true).encode(value)
    }
}

private struct CreateGroupProofPayload: Codable {
    let groupId: UUID?
    let title: String
    let creatorFingerprint: String
    let memberFingerprints: [String]
    let creatorProfile: RelayGroupMemberProfile?
    let memberProfiles: [RelayGroupMemberProfile]?
    let initialRatchetSecretDistribution: GroupRatchetEpochSecretDistribution?
    let signedAt: Date
    let nonce: UUID
}

private struct RequestGroupJoinProofPayload: Codable {
    let groupId: UUID
    let requesterProfile: RelayGroupMemberProfile
    let signedAt: Date
    let nonce: UUID
}

private struct ListGroupJoinProofPayload: Codable {
    let groupId: UUID
    let actorFingerprint: String
    let limit: Int?
    let signedAt: Date
    let nonce: UUID
}

private struct GetGroupProofPayload: Codable {
    let groupId: UUID
    let memberFingerprint: String?
    let signedAt: Date
    let nonce: UUID
}

private struct ApproveGroupJoinProofPayload: Codable {
    let groupId: UUID
    let actorFingerprint: String
    let joinRequestId: UUID
    let groupCommit: SignedGroupCommit
    let signedAt: Date
    let nonce: UUID
}

private struct RejectGroupJoinProofPayload: Codable {
    let groupId: UUID
    let actorFingerprint: String
    let joinRequestId: UUID
    let signedAt: Date
    let nonce: UUID
}

private struct UpdateGroupProofPayload: Codable {
    let groupId: UUID
    let actorFingerprint: String
    let title: String?
    let addMemberFingerprints: [String]
    let addMemberProfiles: [RelayGroupMemberProfile]?
    let removeMemberFingerprints: [String]
    let signedAt: Date
    let nonce: UUID
}

private struct SignedGroupCommitProofPayload: Codable {
    let operation: MLSGroupCommitOperation
    let groupId: UUID
    let actorFingerprint: String
    let baseEpoch: UInt64
    let previousTranscriptHash: Data
    let title: String?
    let addMemberFingerprints: [String]
    let addMemberProfiles: [RelayGroupMemberProfile]?
    let removeMemberFingerprints: [String]
    let ratchetSecretDistribution: GroupRatchetEpochSecretDistribution?
    let signedAt: Date
    let nonce: UUID
}

private struct DeleteGroupProofPayload: Codable {
    let groupId: UUID
    let actorFingerprint: String
    let signedAt: Date
    let nonce: UUID
}

private struct ListGroupsProofPayload: Codable {
    let memberFingerprint: String
    let limit: Int?
    let signedAt: Date
    let nonce: UUID
}

struct PairingAnnouncement: Codable, Equatable {
    let id: UUID
    let offer: ContactOffer
    let announcedAt: Date
    let expiresAt: Date
}

struct PairingRequest: Codable, Equatable {
    let id: UUID
    let from: ContactOffer
    let sentAt: Date
}

struct ContactOffer: Codable, Equatable {
    let version: Int
    let displayName: String
    let inboxId: String
    let relay: RelayEndpoint
    let signingPublicKey: Data
    let agreementPublicKey: Data
    let inboxAccessPublicKey: Data?
    let fingerprint: String
    let signature: Data

    func isConsistentFingerprint() -> Bool {
        !signingPublicKey.isEmpty
            && fingerprint == Data(SHA256.hash(data: signingPublicKey)).base64EncodedString()
    }

    func verifySignature() -> Bool {
        guard isConsistentFingerprint(),
              let signableData = try? RelayCodec.encoder(sortedKeys: true).encode(
                UnsignedContactOffer(
                    version: version,
                    displayName: displayName,
                    inboxId: inboxId,
                    relay: relay,
                    signingPublicKey: signingPublicKey,
                    agreementPublicKey: agreementPublicKey,
                    inboxAccessPublicKey: inboxAccessPublicKey,
                    fingerprint: fingerprint
                )
              ) else {
            return false
        }
        return OQSSignatureVerifier.shared.verify(
            signature: signature,
            data: signableData,
            publicKey: signingPublicKey
        )
    }
}

private struct UnsignedContactOffer: Codable {
    let version: Int
    let displayName: String
    let inboxId: String
    let relay: RelayEndpoint
    let signingPublicKey: Data
    let agreementPublicKey: Data
    let inboxAccessPublicKey: Data?
    let fingerprint: String
}

struct AnnounceRequest: Codable, Equatable {
    let offer: ContactOffer
    let ttlSeconds: Int?
}

struct ListAnnouncementsRequest: Codable, Equatable {
    let limit: Int?
}

struct SendPairRequest: Codable, Equatable {
    let targetFingerprint: String
    let offer: ContactOffer
    let actorProof: RelayActorProof?

    init(
        targetFingerprint: String,
        offer: ContactOffer,
        actorProof: RelayActorProof? = nil
    ) {
        self.targetFingerprint = targetFingerprint
        self.offer = offer
        self.actorProof = actorProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            SendPairRequestProofPayload(
                targetFingerprint: targetFingerprint,
                offer: offer,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

private struct SendPairRequestProofPayload: Codable {
    let targetFingerprint: String
    let offer: ContactOffer
    let signedAt: Date
    let nonce: UUID
}

struct FetchPairRequestsRequest: Codable, Equatable {
    let fingerprint: String
    let maxCount: Int?
    let actorProof: RelayActorProof?

    init(
        fingerprint: String,
        maxCount: Int? = nil,
        actorProof: RelayActorProof? = nil
    ) {
        self.fingerprint = fingerprint
        self.maxCount = maxCount
        self.actorProof = actorProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            FetchPairRequestsProofPayload(
                fingerprint: fingerprint,
                maxCount: maxCount,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

private struct FetchPairRequestsProofPayload: Codable {
    let fingerprint: String
    let maxCount: Int?
    let signedAt: Date
    let nonce: UUID
}

struct UploadAttachmentRequest: Codable, Equatable {
    let attachmentId: UUID
    let chunkIndex: Int
    let payload: EncryptedPayload
    let ttlSeconds: Int?
}

struct FetchAttachmentRequest: Codable, Equatable {
    let attachmentId: UUID
    let chunkIndex: Int
}

struct UploadPrekeyBundleRequest: Codable, Equatable {
    let fingerprint: String
    let bundle: PrekeyBundle
    let ttlSeconds: Int?
    let actorProof: RelayActorProof?

    init(
        fingerprint: String,
        bundle: PrekeyBundle,
        ttlSeconds: Int? = nil,
        actorProof: RelayActorProof? = nil
    ) {
        self.fingerprint = fingerprint
        self.bundle = bundle
        self.ttlSeconds = ttlSeconds
        self.actorProof = actorProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try RelayCodec.encoder(sortedKeys: true).encode(
            UploadPrekeyBundleProofPayload(
                fingerprint: fingerprint,
                bundle: bundle,
                ttlSeconds: ttlSeconds,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

private struct UploadPrekeyBundleProofPayload: Codable {
    let fingerprint: String
    let bundle: PrekeyBundle
    let ttlSeconds: Int?
    let signedAt: Date
    let nonce: UUID
}

struct FetchPrekeyBundleRequest: Codable, Equatable {
    let fingerprint: String

    init(fingerprint: String) {
        self.fingerprint = fingerprint
    }
}

struct AttachmentChunk: Codable, Equatable {
    let attachmentId: UUID
    let chunkIndex: Int
    let payload: EncryptedPayload
}

enum RelayCodec {
    static func encoder(sortedKeys: Bool = false) -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        if sortedKeys {
            encoder.outputFormatting = [.sortedKeys]
        }
        return encoder
    }

    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
