import Foundation

public enum RelayEndpointTransport: String, Codable, CaseIterable {
    case tcp
    case http
    case websocket
}

public struct RelayEndpoint: Codable, Equatable {
    public var host: String
    public var port: UInt16
    public var useTLS: Bool
    public var transport: RelayEndpointTransport
    public var tlsCertificateFingerprintSHA256: Data?
    public var directorySigningPublicKey: Data?

    public init(
        host: String,
        port: UInt16,
        useTLS: Bool = false,
        transport: RelayEndpointTransport = .tcp,
        tlsCertificateFingerprintSHA256: Data? = nil,
        directorySigningPublicKey: Data? = nil
    ) {
        self.host = host
        self.port = port
        self.useTLS = useTLS
        self.transport = transport
        self.tlsCertificateFingerprintSHA256 = tlsCertificateFingerprintSHA256
        self.directorySigningPublicKey = directorySigningPublicKey
    }

    private enum CodingKeys: String, CodingKey {
        case host
        case port
        case useTLS
        case transport
        case tlsCertificateFingerprintSHA256
        case directorySigningPublicKey
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        host = try container.decode(String.self, forKey: .host)
        port = try container.decode(UInt16.self, forKey: .port)
        useTLS = try container.decodeIfPresent(Bool.self, forKey: .useTLS) ?? false
        transport = try container.decodeIfPresent(RelayEndpointTransport.self, forKey: .transport) ?? .tcp
        tlsCertificateFingerprintSHA256 = try container.decodeIfPresent(Data.self, forKey: .tlsCertificateFingerprintSHA256)
        directorySigningPublicKey = try container.decodeIfPresent(Data.self, forKey: .directorySigningPublicKey)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(host, forKey: .host)
        try container.encode(port, forKey: .port)
        try container.encode(useTLS, forKey: .useTLS)
        try container.encode(transport, forKey: .transport)
        try container.encodeIfPresent(tlsCertificateFingerprintSHA256, forKey: .tlsCertificateFingerprintSHA256)
        try container.encodeIfPresent(directorySigningPublicKey, forKey: .directorySigningPublicKey)
    }
}

public enum RelayKind: String, Codable, CaseIterable {
    case standard
    case discovery
    case bridge
    case archive
    case privateRelay
    case coordinator
}

public enum FederationMode: String, Codable, CaseIterable {
    case solo
    case manual
    case curated
    case open
}

public struct FederationDescriptor: Codable, Equatable {
    public var mode: FederationMode
    public var name: String?
    public var description: String?

    public init(mode: FederationMode, name: String? = nil, description: String? = nil) {
        self.mode = mode
        self.name = name
        self.description = description
    }
}

public enum HiddenRetrievalMode: String, Codable, CaseIterable {
    case coverQuery
    case replicatedXorPIR
}

public struct HiddenRetrievalPIRReplica: Codable, Equatable {
    public var replicaId: String
    public var operatorId: String
    public var endpoint: RelayEndpoint

    public init(
        replicaId: String,
        operatorId: String,
        endpoint: RelayEndpoint
    ) {
        self.replicaId = replicaId.trimmingCharacters(in: .whitespacesAndNewlines)
        self.operatorId = operatorId.trimmingCharacters(in: .whitespacesAndNewlines)
        self.endpoint = endpoint
    }
}

public struct HiddenRetrievalSupport: Codable, Equatable {
    public var mode: HiddenRetrievalMode
    public var defaultCoverSetSize: Int
    public var maxCoverSetSize: Int
    public var replicatedXorPIRReplicas: [HiddenRetrievalPIRReplica]?

    public init(
        mode: HiddenRetrievalMode = .coverQuery,
        defaultCoverSetSize: Int = 8,
        maxCoverSetSize: Int = 32,
        replicatedXorPIRReplicas: [HiddenRetrievalPIRReplica]? = nil
    ) {
        let normalizedMax = max(2, maxCoverSetSize)
        self.mode = mode
        self.maxCoverSetSize = normalizedMax
        self.defaultCoverSetSize = min(max(2, defaultCoverSetSize), normalizedMax)
        self.replicatedXorPIRReplicas = replicatedXorPIRReplicas?.map {
            HiddenRetrievalPIRReplica(
                replicaId: $0.replicaId,
                operatorId: $0.operatorId,
                endpoint: $0.endpoint
            )
        }
    }
}

public struct OpenFederationDiscoverySupport: Codable, Equatable {
    public var dhtNodeEnabled: Bool
    public var peerExchangeEnabled: Bool
    public var peerExchangeLimit: Int
    public var requirePublicEndpoint: Bool
    public var maxDHTRecords: Int
    public var maxDHTRecordsPerHost: Int
    public var maxDHTQueryRecords: Int

    public init(
        dhtNodeEnabled: Bool = false,
        peerExchangeEnabled: Bool = false,
        peerExchangeLimit: Int = 0,
        requirePublicEndpoint: Bool = true,
        maxDHTRecords: Int = 256,
        maxDHTRecordsPerHost: Int = 4,
        maxDHTQueryRecords: Int = 256
    ) {
        self.dhtNodeEnabled = dhtNodeEnabled
        self.peerExchangeEnabled = peerExchangeEnabled
        self.peerExchangeLimit = max(0, peerExchangeLimit)
        self.requirePublicEndpoint = requirePublicEndpoint
        self.maxDHTRecords = max(1, maxDHTRecords)
        self.maxDHTRecordsPerHost = max(1, maxDHTRecordsPerHost)
        self.maxDHTQueryRecords = max(1, maxDHTQueryRecords)
    }
}

public struct RelayInfo: Codable, Equatable {
    public var kind: RelayKind
    public var federation: FederationDescriptor
    public var temporalBucketSeconds: Int
    public var temporalBucketScheduleSeconds: [Int]?
    public var attachmentDefaultTTLSeconds: Int?
    public var attachmentMaxTTLSeconds: Int?
    public var attachmentsEnabled: Bool?
    public var attachmentStorageBackend: String?
    public var hiddenRetrieval: HiddenRetrievalSupport?
    public var onionTransport: OnionTransportSupport?
    public var mixnetTransport: MixnetTransportSupport?
    public var wakeSupport: DecentralizedWakeSupport?
    public var relayName: String?
    public var operatorNote: String?
    public var softwareVersion: String?
    public var groupCreationMode: GroupCreationMode?
    public var groupSecurityModel: GroupSecurityModel?
    public var requiresPassword: Bool?
    public var tlsEnabled: Bool?
    public var transport: RelayEndpointTransport?
    public var federationCoordinatorEndpoints: [RelayEndpoint]?
    public var coordinatorReportedRelayCount: Int?
    public var coordinatorRegistrationAuthRequired: Bool?
    public var curatedStrictPolicyEnabled: Bool?
    public var curatedCoordinatorQuorum: Int?
    public var curatedRequireSignedDirectory: Bool?
    public var federationDirectoryPublicKey: Data?
    public var knownOpenPeers: [RelayEndpoint]?
    public var openFederationDiscovery: OpenFederationDiscoverySupport?
    public var advertisedAt: Date

    public init(
        kind: RelayKind,
        federation: FederationDescriptor,
        temporalBucketSeconds: Int,
        temporalBucketScheduleSeconds: [Int]? = nil,
        attachmentDefaultTTLSeconds: Int? = nil,
        attachmentMaxTTLSeconds: Int? = nil,
        attachmentsEnabled: Bool? = nil,
        attachmentStorageBackend: String? = nil,
        hiddenRetrieval: HiddenRetrievalSupport? = nil,
        onionTransport: OnionTransportSupport? = nil,
        mixnetTransport: MixnetTransportSupport? = nil,
        wakeSupport: DecentralizedWakeSupport? = nil,
        relayName: String? = nil,
        operatorNote: String? = nil,
        softwareVersion: String? = nil,
        groupCreationMode: GroupCreationMode? = nil,
        groupSecurityModel: GroupSecurityModel? = nil,
        requiresPassword: Bool? = nil,
        tlsEnabled: Bool? = nil,
        transport: RelayEndpointTransport? = nil,
        federationCoordinatorEndpoints: [RelayEndpoint]? = nil,
        coordinatorReportedRelayCount: Int? = nil,
        coordinatorRegistrationAuthRequired: Bool? = nil,
        curatedStrictPolicyEnabled: Bool? = nil,
        curatedCoordinatorQuorum: Int? = nil,
        curatedRequireSignedDirectory: Bool? = nil,
        federationDirectoryPublicKey: Data? = nil,
        knownOpenPeers: [RelayEndpoint]? = nil,
        openFederationDiscovery: OpenFederationDiscoverySupport? = nil,
        advertisedAt: Date = Date()
    ) {
        self.kind = kind
        self.federation = federation
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
        self.attachmentStorageBackend = attachmentStorageBackend
        self.hiddenRetrieval = hiddenRetrieval
        self.onionTransport = onionTransport
        self.mixnetTransport = mixnetTransport
        self.wakeSupport = wakeSupport
        self.relayName = relayName
        self.operatorNote = operatorNote
        self.softwareVersion = softwareVersion
        self.groupCreationMode = groupCreationMode
        self.groupSecurityModel = groupSecurityModel
        self.requiresPassword = requiresPassword
        self.tlsEnabled = tlsEnabled
        self.transport = transport
        self.federationCoordinatorEndpoints = federationCoordinatorEndpoints
        self.coordinatorReportedRelayCount = coordinatorReportedRelayCount
        self.coordinatorRegistrationAuthRequired = coordinatorRegistrationAuthRequired
        self.curatedStrictPolicyEnabled = curatedStrictPolicyEnabled
        self.curatedCoordinatorQuorum = curatedCoordinatorQuorum
        self.curatedRequireSignedDirectory = curatedRequireSignedDirectory
        self.federationDirectoryPublicKey = federationDirectoryPublicKey
        self.knownOpenPeers = knownOpenPeers
        self.openFederationDiscovery = openFederationDiscovery
        self.advertisedAt = advertisedAt
    }
}

public struct RelayConfiguration: Codable, Equatable {
    public var kind: RelayKind
    public var federation: FederationDescriptor
    public var temporalBucketSeconds: Int
    public var temporalBucketScheduleSeconds: [Int]?
    public var attachmentDefaultTTLSeconds: Int
    public var attachmentMaxTTLSeconds: Int
    public var attachmentsEnabled: Bool?
    public var attachmentStorageBackend: String?
    public var hiddenRetrieval: HiddenRetrievalSupport?
    public var onionTransport: OnionTransportSupport?
    public var mixnetTransport: MixnetTransportSupport?
    public var wakeSupport: DecentralizedWakeSupport?
    public var relayName: String?
    public var operatorNote: String?
    public var softwareVersion: String?
    public var groupCreationMode: GroupCreationMode
    public var groupSecurityModel: GroupSecurityModel
    public var accessPassword: String?
    public var coordinatorRegistrationToken: String?
    public var federationForwardingAuthToken: String?
    public var tlsEnabled: Bool
    public var advertisedTLSEnabled: Bool?
    public var transport: RelayEndpointTransport
    public var tlsIdentityPKCS12Path: String?
    public var tlsIdentityPassword: String?
    public var federationCoordinatorEndpoints: [RelayEndpoint]?
    public var coordinatorHeartbeatSeconds: Int?
    public var coordinatorDirectoryMaxStalenessSeconds: Int?
    public var relayPeerExchangeLimit: Int?
    public var openFederationDHTEnabled: Bool
    public var openFederationDHTMaxRecords: Int
    public var openFederationDHTMaxRecordsPerHost: Int
    public var openFederationDHTMaxQueryRecords: Int
    public var coordinatorDirectorySigningPrivateKey: Data?
    public var curatedStrictPolicyEnabled: Bool
    public var curatedCoordinatorQuorum: Int
    public var curatedRequireSignedDirectory: Bool
    public var advertisedEndpoint: RelayEndpoint?
    public var federationAllowList: [RelayEndpoint]
    public var allowPrivateFederationEndpoints: Bool

    public init(
        kind: RelayKind = .standard,
        federation: FederationDescriptor = FederationDescriptor(mode: .solo),
        temporalBucketSeconds: Int = 300,
        temporalBucketScheduleSeconds: [Int]? = nil,
        attachmentDefaultTTLSeconds: Int = 3600,
        attachmentMaxTTLSeconds: Int = 21600,
        attachmentsEnabled: Bool = true,
        attachmentStorageBackend: String? = nil,
        hiddenRetrieval: HiddenRetrievalSupport? = nil,
        onionTransport: OnionTransportSupport? = nil,
        mixnetTransport: MixnetTransportSupport? = nil,
        wakeSupport: DecentralizedWakeSupport? = nil,
        relayName: String? = nil,
        operatorNote: String? = nil,
        softwareVersion: String? = nil,
        groupCreationMode: GroupCreationMode = .allowed,
        groupSecurityModel: GroupSecurityModel = .relayBackedPairwise,
        accessPassword: String? = nil,
        coordinatorRegistrationToken: String? = nil,
        federationForwardingAuthToken: String? = nil,
        tlsEnabled: Bool = false,
        advertisedTLSEnabled: Bool? = nil,
        transport: RelayEndpointTransport = .tcp,
        tlsIdentityPKCS12Path: String? = nil,
        tlsIdentityPassword: String? = nil,
        federationCoordinatorEndpoints: [RelayEndpoint]? = nil,
        coordinatorHeartbeatSeconds: Int? = nil,
        coordinatorDirectoryMaxStalenessSeconds: Int? = 300,
        relayPeerExchangeLimit: Int? = 12,
        openFederationDHTEnabled: Bool = false,
        openFederationDHTMaxRecords: Int = 256,
        openFederationDHTMaxRecordsPerHost: Int = 4,
        openFederationDHTMaxQueryRecords: Int = 256,
        coordinatorDirectorySigningPrivateKey: Data? = nil,
        curatedStrictPolicyEnabled: Bool = true,
        curatedCoordinatorQuorum: Int = 1,
        curatedRequireSignedDirectory: Bool = true,
        advertisedEndpoint: RelayEndpoint? = nil,
        federationAllowList: [RelayEndpoint] = [],
        allowPrivateFederationEndpoints: Bool = false
    ) {
        self.kind = kind
        self.federation = federation
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
        let normalizedAttachmentStorageBackend = attachmentStorageBackend?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.attachmentStorageBackend = normalizedAttachmentStorageBackend?.isEmpty == false ? normalizedAttachmentStorageBackend : nil
        self.hiddenRetrieval = hiddenRetrieval
        self.onionTransport = onionTransport
        self.mixnetTransport = mixnetTransport
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
        self.tlsEnabled = tlsEnabled
        self.advertisedTLSEnabled = advertisedTLSEnabled
        self.transport = transport
        self.tlsIdentityPKCS12Path = tlsIdentityPKCS12Path
        self.tlsIdentityPassword = tlsIdentityPassword
        self.federationCoordinatorEndpoints = federationCoordinatorEndpoints
        self.coordinatorHeartbeatSeconds = coordinatorHeartbeatSeconds
        self.coordinatorDirectoryMaxStalenessSeconds = coordinatorDirectoryMaxStalenessSeconds
        self.relayPeerExchangeLimit = relayPeerExchangeLimit
        self.openFederationDHTEnabled = openFederationDHTEnabled
        self.openFederationDHTMaxRecords = max(1, openFederationDHTMaxRecords)
        self.openFederationDHTMaxRecordsPerHost = max(1, openFederationDHTMaxRecordsPerHost)
        self.openFederationDHTMaxQueryRecords = max(1, openFederationDHTMaxQueryRecords)
        self.coordinatorDirectorySigningPrivateKey = coordinatorDirectorySigningPrivateKey
        self.curatedStrictPolicyEnabled = curatedStrictPolicyEnabled
        self.curatedCoordinatorQuorum = max(1, curatedCoordinatorQuorum)
        self.curatedRequireSignedDirectory = curatedRequireSignedDirectory
        self.advertisedEndpoint = advertisedEndpoint
        self.federationAllowList = federationAllowList
        self.allowPrivateFederationEndpoints = allowPrivateFederationEndpoints
    }

    public func makeInfo(now: Date = Date()) -> RelayInfo {
        let trimmedPassword = accessPassword?.trimmingCharacters(in: .whitespacesAndNewlines)
        let requiresPassword = !(trimmedPassword?.isEmpty ?? true)
        let requiresCoordinatorRegistrationAuth = !(coordinatorRegistrationToken?.isEmpty ?? true)
        let curatedMode = federation.mode == .curated
        return RelayInfo(
            kind: kind,
            federation: federation,
            temporalBucketSeconds: temporalBucketSeconds,
            temporalBucketScheduleSeconds: temporalBucketScheduleSeconds,
            attachmentDefaultTTLSeconds: attachmentDefaultTTLSeconds,
            attachmentMaxTTLSeconds: attachmentMaxTTLSeconds,
            attachmentsEnabled: attachmentsEnabled != false,
            attachmentStorageBackend: attachmentStorageBackend,
            hiddenRetrieval: advertisedHiddenRetrieval,
            onionTransport: advertisedOnionTransport,
            mixnetTransport: advertisedMixnetTransport,
            wakeSupport: wakeSupport,
            relayName: relayName,
            operatorNote: operatorNote,
            softwareVersion: softwareVersion,
            groupCreationMode: groupCreationMode,
            groupSecurityModel: groupSecurityModel,
            requiresPassword: requiresPassword,
            tlsEnabled: advertisedTLSEnabled ?? tlsEnabled,
            transport: transport,
            federationCoordinatorEndpoints: federationCoordinatorEndpoints,
            coordinatorRegistrationAuthRequired: kind == .coordinator ? requiresCoordinatorRegistrationAuth : nil,
            curatedStrictPolicyEnabled: curatedMode ? curatedStrictPolicyEnabled : nil,
            curatedCoordinatorQuorum: curatedMode ? curatedCoordinatorQuorum : nil,
            curatedRequireSignedDirectory: curatedMode ? curatedRequireSignedDirectory : nil,
            federationDirectoryPublicKey: nil,
            knownOpenPeers: nil,
            openFederationDiscovery: advertisedOpenFederationDiscovery,
            advertisedAt: now
        )
    }

    public var advertisedOpenFederationDiscovery: OpenFederationDiscoverySupport? {
        guard federation.mode == .open, kind != .coordinator else {
            return nil
        }
        let peerLimit = max(0, relayPeerExchangeLimit ?? 0)
        guard openFederationDHTEnabled || peerLimit > 0 else {
            return nil
        }
        return OpenFederationDiscoverySupport(
            dhtNodeEnabled: openFederationDHTEnabled,
            peerExchangeEnabled: peerLimit > 0,
            peerExchangeLimit: peerLimit,
            requirePublicEndpoint: !allowPrivateFederationEndpoints,
            maxDHTRecords: openFederationDHTMaxRecords,
            maxDHTRecordsPerHost: openFederationDHTMaxRecordsPerHost,
            maxDHTQueryRecords: openFederationDHTMaxQueryRecords
        )
    }

    private var advertisedHiddenRetrieval: HiddenRetrievalSupport? {
        guard let hiddenRetrieval else {
            return nil
        }
        guard hiddenRetrieval.mode == .replicatedXorPIR else {
            return hiddenRetrieval
        }
        return HiddenRetrievalPIRReplicaSetValidator.isUsable(hiddenRetrieval) ? hiddenRetrieval : nil
    }

    private var advertisedOnionTransport: OnionTransportSupport? {
        guard let onionTransport else {
            return nil
        }
        return OnionTransportPolicyValidator.isUsable(onionTransport) ? onionTransport : nil
    }

    private var advertisedMixnetTransport: MixnetTransportSupport? {
        guard let mixnetTransport else {
            return nil
        }
        return MixnetRoutePolicyValidator.isUsable(
            mixnetSupport: mixnetTransport,
            onionSupport: advertisedOnionTransport
        ) ? mixnetTransport : nil
    }
}

public enum RelayRequestType: String, Codable {
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
    case listGroupInvitations
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

public struct DeliverRequest: Codable, Equatable {
    public let inboxId: String
    public let routingToken: String?
    public let envelope: Envelope
    public let destinationRelay: RelayEndpoint?

    public init(
        inboxId: String,
        routingToken: String? = nil,
        envelope: Envelope,
        destinationRelay: RelayEndpoint? = nil
    ) {
        self.inboxId = inboxId
        self.routingToken = routingToken
        self.envelope = envelope
        self.destinationRelay = destinationRelay
    }
}

public struct FetchRequest: Codable, Equatable {
    public let inboxId: String
    public let routingToken: String?
    public let maxCount: Int?
    public let longPollTimeoutSeconds: Int?
    public let accessProof: RelayActorProof?

    public init(
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

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try NoctweaveCoder.encode(
            InboxFetchProofPayload(
                inboxId: inboxId,
                routingToken: routingToken,
                maxCount: maxCount,
                longPollTimeoutSeconds: longPollTimeoutSeconds,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            ),
            sortedKeys: true
        )
    }
}

public struct RegisterInboxRequest: Codable, Equatable {
    public let inboxId: String
    public let accessPublicKey: Data
    public let contactOffer: ContactOffer?
    public let accessProof: RelayActorProof?

    public init(
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

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try NoctweaveCoder.encode(
            InboxRegistrationProofPayload(
                inboxId: inboxId,
                accessPublicKey: accessPublicKey,
                contactOffer: contactOffer,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            ),
            sortedKeys: true
        )
    }
}

public struct AcknowledgeMessagesRequest: Codable, Equatable {
    public let inboxId: String
    public let messageIds: [UUID]
    public let accessProof: RelayActorProof?

    public init(
        inboxId: String,
        messageIds: [UUID],
        accessProof: RelayActorProof? = nil
    ) {
        self.inboxId = inboxId
        self.messageIds = messageIds
        self.accessProof = accessProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try NoctweaveCoder.encode(
            InboxAcknowledgementProofPayload(
                inboxId: inboxId,
                messageIds: messageIds,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            ),
            sortedKeys: true
        )
    }
}

public struct DeliverGroupMessageRequest: Codable, Equatable {
    public let groupId: UUID
    public let groupInboxId: String
    public let envelope: GroupRatchetEnvelope
    public let destinationRelay: RelayEndpoint?

    public init(
        groupId: UUID,
        groupInboxId: String,
        envelope: GroupRatchetEnvelope,
        destinationRelay: RelayEndpoint? = nil
    ) {
        self.groupId = groupId
        self.groupInboxId = groupInboxId
        self.envelope = envelope
        self.destinationRelay = destinationRelay
    }
}

public struct FetchGroupMessagesRequest: Codable, Equatable {
    public let groupId: UUID
    public let groupInboxId: String
    public let maxCount: Int?
    public let longPollTimeoutSeconds: Int?
    public let actorFingerprint: String
    public let actorProof: RelayActorProof?

    public init(
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

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try NoctweaveCoder.encode(
            GroupMessageFetchProofPayload(
                groupId: groupId,
                groupInboxId: groupInboxId,
                maxCount: maxCount,
                longPollTimeoutSeconds: longPollTimeoutSeconds,
                actorFingerprint: actorFingerprint,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            ),
            sortedKeys: true
        )
    }
}

public struct AcknowledgeGroupMessagesRequest: Codable, Equatable {
    public let groupId: UUID
    public let groupInboxId: String
    public let messageIds: [UUID]
    public let actorFingerprint: String
    public let actorProof: RelayActorProof?

    public init(
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

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try NoctweaveCoder.encode(
            GroupMessageAcknowledgementProofPayload(
                groupId: groupId,
                groupInboxId: groupInboxId,
                messageIds: messageIds,
                actorFingerprint: actorFingerprint,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            ),
            sortedKeys: true
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

public struct AnnounceRequest: Codable, Equatable {
    public let offer: ContactOffer
    public let ttlSeconds: Int?

    public init(offer: ContactOffer, ttlSeconds: Int? = nil) {
        self.offer = offer
        self.ttlSeconds = ttlSeconds
    }
}

public struct ListAnnouncementsRequest: Codable, Equatable {
    public let limit: Int?

    public init(limit: Int? = nil) {
        self.limit = limit
    }
}

public struct SendPairRequest: Codable, Equatable {
    public let targetFingerprint: String
    public let offer: ContactOffer
    public let actorProof: RelayActorProof?

    public init(
        targetFingerprint: String,
        offer: ContactOffer,
        actorProof: RelayActorProof? = nil
    ) {
        self.targetFingerprint = targetFingerprint
        self.offer = offer
        self.actorProof = actorProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try NoctweaveCoder.encode(
            SendPairRequestProofPayload(
                targetFingerprint: targetFingerprint,
                offer: offer,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            ),
            sortedKeys: true
        )
    }
}

private struct SendPairRequestProofPayload: Codable {
    let targetFingerprint: String
    let offer: ContactOffer
    let signedAt: Date
    let nonce: UUID
}

public struct FetchPairRequestsRequest: Codable, Equatable {
    public let fingerprint: String
    public let maxCount: Int?
    public let actorProof: RelayActorProof?

    public init(
        fingerprint: String,
        maxCount: Int? = nil,
        actorProof: RelayActorProof? = nil
    ) {
        self.fingerprint = fingerprint
        self.maxCount = maxCount
        self.actorProof = actorProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try NoctweaveCoder.encode(
            FetchPairRequestsProofPayload(
                fingerprint: fingerprint,
                maxCount: maxCount,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            ),
            sortedKeys: true
        )
    }
}

private struct FetchPairRequestsProofPayload: Codable {
    let fingerprint: String
    let maxCount: Int?
    let signedAt: Date
    let nonce: UUID
}

public struct UploadAttachmentRequest: Codable, Equatable {
    public let attachmentId: UUID
    public let chunkIndex: Int
    public let payload: EncryptedPayload
    public let ttlSeconds: Int?

    public init(
        attachmentId: UUID,
        chunkIndex: Int,
        payload: EncryptedPayload,
        ttlSeconds: Int? = nil
    ) {
        self.attachmentId = attachmentId
        self.chunkIndex = chunkIndex
        self.payload = payload
        self.ttlSeconds = ttlSeconds
    }
}

public struct FetchAttachmentRequest: Codable, Equatable {
    public let attachmentId: UUID
    public let chunkIndex: Int

    public init(attachmentId: UUID, chunkIndex: Int) {
        self.attachmentId = attachmentId
        self.chunkIndex = chunkIndex
    }
}

public struct UploadPrekeyBundleRequest: Codable, Equatable {
    public let fingerprint: String
    public let bundle: PrekeyBundle
    public let ttlSeconds: Int?
    public let actorProof: RelayActorProof?

    public init(
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

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try NoctweaveCoder.encode(
            UploadPrekeyBundleProofPayload(
                fingerprint: fingerprint,
                bundle: bundle,
                ttlSeconds: ttlSeconds,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            ),
            sortedKeys: true
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

public struct FetchPrekeyBundleRequest: Codable, Equatable {
    public let fingerprint: String

    public init(fingerprint: String) {
        self.fingerprint = fingerprint
    }
}

public struct FederationNodeRegistrationRequest: Codable, Equatable {
    public let endpoint: RelayEndpoint
    public let relayInfo: RelayInfo
    public let ttlSeconds: Int?

    public init(endpoint: RelayEndpoint, relayInfo: RelayInfo, ttlSeconds: Int? = nil) {
        self.endpoint = endpoint
        self.relayInfo = relayInfo
        self.ttlSeconds = ttlSeconds
    }
}

public struct ListFederationNodesRequest: Codable, Equatable {
    public let mode: FederationMode?
    public let federationName: String?
    public let onlyHealthy: Bool?
    public let maxStalenessSeconds: Int?
    public let requireSignedSnapshot: Bool?

    public init(
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

public struct FederationNodeRecord: Codable, Equatable {
    public let endpoint: RelayEndpoint
    public let relayInfo: RelayInfo
    public let lastHeartbeatAt: Date
    public let expiresAt: Date

    public init(
        endpoint: RelayEndpoint,
        relayInfo: RelayInfo,
        lastHeartbeatAt: Date,
        expiresAt: Date
    ) {
        self.endpoint = endpoint
        self.relayInfo = relayInfo
        self.lastHeartbeatAt = lastHeartbeatAt
        self.expiresAt = expiresAt
    }
}

public struct FederationDirectorySnapshot: Codable, Equatable {
    public let version: Int
    public let mode: FederationMode
    public let federationName: String?
    public let issuedAt: Date
    public let validUntil: Date
    public let maxStalenessSeconds: Int
    public let nodes: [FederationNodeRecord]
    public let signatureAlgorithm: String?
    public let signature: Data?

    public init(
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

public struct PublishOpenFederationDHTRecordRequest: Codable, Equatable {
    public let namespace: String
    public let record: OpenFederationDHTRecord

    public init(namespace: String, record: OpenFederationDHTRecord) {
        self.namespace = namespace
        self.record = record
    }
}

public struct ListOpenFederationDHTRecordsRequest: Codable, Equatable {
    public let namespace: String
    public let limit: Int?

    public init(namespace: String, limit: Int? = nil) {
        self.namespace = namespace
        self.limit = limit
    }
}

public struct RelayRequest: Codable, Equatable {
    public let type: RelayRequestType
    public let authToken: String?
    public let deliver: DeliverRequest?
    public let registerInbox: RegisterInboxRequest?
    public let fetch: FetchRequest?
    public let acknowledgeMessages: AcknowledgeMessagesRequest?
    public let deliverGroupMessage: DeliverGroupMessageRequest?
    public let fetchGroupMessages: FetchGroupMessagesRequest?
    public let acknowledgeGroupMessages: AcknowledgeGroupMessagesRequest?
    public let announce: AnnounceRequest?
    public let listAnnouncements: ListAnnouncementsRequest?
    public let sendPairRequest: SendPairRequest?
    public let fetchPairRequests: FetchPairRequestsRequest?
    public let uploadAttachment: UploadAttachmentRequest?
    public let fetchAttachment: FetchAttachmentRequest?
    public let uploadPrekeys: UploadPrekeyBundleRequest?
    public let fetchPrekeyBundle: FetchPrekeyBundleRequest?
    public let createGroup: CreateGroupRequest?
    public let getGroup: GetGroupRequest?
    public let listGroups: ListGroupsRequest?
    public let listGroupInvitations: ListGroupInvitationsRequest?
    public let updateGroup: UpdateGroupRequest?
    public let deleteGroup: DeleteGroupRequest?
    public let requestGroupJoin: RequestGroupJoinRequest?
    public let listGroupJoinRequests: ListGroupJoinRequestsRequest?
    public let approveGroupJoin: ApproveGroupJoinRequest?
    public let rejectGroupJoin: RejectGroupJoinRequest?
    public let registerFederationNode: FederationNodeRegistrationRequest?
    public let listFederationNodes: ListFederationNodesRequest?
    public let publishOpenFederationDHTRecord: PublishOpenFederationDHTRecordRequest?
    public let listOpenFederationDHTRecords: ListOpenFederationDHTRecordsRequest?

    public init(
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
        listGroupInvitations: ListGroupInvitationsRequest? = nil,
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
        self.listGroupInvitations = listGroupInvitations
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

    public static func deliver(_ request: DeliverRequest) -> RelayRequest {
        RelayRequest(type: .deliver, deliver: request)
    }

    public static func registerInbox(_ request: RegisterInboxRequest) -> RelayRequest {
        RelayRequest(type: .registerInbox, registerInbox: request)
    }

    public static func fetch(_ request: FetchRequest) -> RelayRequest {
        RelayRequest(type: .fetch, fetch: request)
    }

    public static func acknowledgeMessages(_ request: AcknowledgeMessagesRequest) -> RelayRequest {
        RelayRequest(type: .acknowledgeMessages, acknowledgeMessages: request)
    }

    public static func deliverGroupMessage(_ request: DeliverGroupMessageRequest) -> RelayRequest {
        RelayRequest(type: .deliverGroupMessage, deliverGroupMessage: request)
    }

    public static func fetchGroupMessages(_ request: FetchGroupMessagesRequest) -> RelayRequest {
        RelayRequest(type: .fetchGroupMessages, fetchGroupMessages: request)
    }

    public static func acknowledgeGroupMessages(_ request: AcknowledgeGroupMessagesRequest) -> RelayRequest {
        RelayRequest(type: .acknowledgeGroupMessages, acknowledgeGroupMessages: request)
    }

    public static func health() -> RelayRequest {
        RelayRequest(type: .health)
    }

    public static func info() -> RelayRequest {
        RelayRequest(type: .info)
    }

    public static func announce(_ request: AnnounceRequest) -> RelayRequest {
        RelayRequest(type: .announce, announce: request)
    }

    public static func listAnnouncements(_ request: ListAnnouncementsRequest) -> RelayRequest {
        RelayRequest(type: .listAnnouncements, listAnnouncements: request)
    }

    public static func sendPairRequest(_ request: SendPairRequest) -> RelayRequest {
        RelayRequest(type: .sendPairRequest, sendPairRequest: request)
    }

    public static func fetchPairRequests(_ request: FetchPairRequestsRequest) -> RelayRequest {
        RelayRequest(type: .fetchPairRequests, fetchPairRequests: request)
    }

    public static func uploadAttachment(_ request: UploadAttachmentRequest) -> RelayRequest {
        RelayRequest(type: .uploadAttachment, uploadAttachment: request)
    }

    public static func fetchAttachment(_ request: FetchAttachmentRequest) -> RelayRequest {
        RelayRequest(type: .fetchAttachment, fetchAttachment: request)
    }

    public static func uploadPrekeys(_ request: UploadPrekeyBundleRequest) -> RelayRequest {
        RelayRequest(type: .uploadPrekeys, uploadPrekeys: request)
    }

    public static func fetchPrekeyBundle(_ request: FetchPrekeyBundleRequest) -> RelayRequest {
        RelayRequest(type: .fetchPrekeyBundle, fetchPrekeyBundle: request)
    }

    public static func createGroup(_ request: CreateGroupRequest) -> RelayRequest {
        RelayRequest(type: .createGroup, createGroup: request)
    }

    public static func getGroup(_ request: GetGroupRequest) -> RelayRequest {
        RelayRequest(type: .getGroup, getGroup: request)
    }

    public static func listGroups(_ request: ListGroupsRequest) -> RelayRequest {
        RelayRequest(type: .listGroups, listGroups: request)
    }

    public static func listGroupInvitations(_ request: ListGroupInvitationsRequest) -> RelayRequest {
        RelayRequest(type: .listGroupInvitations, listGroupInvitations: request)
    }

    public static func updateGroup(_ request: UpdateGroupRequest) -> RelayRequest {
        RelayRequest(type: .updateGroup, updateGroup: request)
    }

    public static func deleteGroup(_ request: DeleteGroupRequest) -> RelayRequest {
        RelayRequest(type: .deleteGroup, deleteGroup: request)
    }

    public static func requestGroupJoin(_ request: RequestGroupJoinRequest) -> RelayRequest {
        RelayRequest(type: .requestGroupJoin, requestGroupJoin: request)
    }

    public static func listGroupJoinRequests(_ request: ListGroupJoinRequestsRequest) -> RelayRequest {
        RelayRequest(type: .listGroupJoinRequests, listGroupJoinRequests: request)
    }

    public static func approveGroupJoin(_ request: ApproveGroupJoinRequest) -> RelayRequest {
        RelayRequest(type: .approveGroupJoin, approveGroupJoin: request)
    }

    public static func rejectGroupJoin(_ request: RejectGroupJoinRequest) -> RelayRequest {
        RelayRequest(type: .rejectGroupJoin, rejectGroupJoin: request)
    }

    public static func registerFederationNode(_ request: FederationNodeRegistrationRequest) -> RelayRequest {
        RelayRequest(type: .registerFederationNode, registerFederationNode: request)
    }

    public static func listFederationNodes(_ request: ListFederationNodesRequest) -> RelayRequest {
        RelayRequest(type: .listFederationNodes, listFederationNodes: request)
    }

    public static func publishOpenFederationDHTRecord(_ request: PublishOpenFederationDHTRecordRequest) -> RelayRequest {
        RelayRequest(type: .publishOpenFederationDHTRecord, publishOpenFederationDHTRecord: request)
    }

    public static func listOpenFederationDHTRecords(_ request: ListOpenFederationDHTRecordsRequest) -> RelayRequest {
        RelayRequest(type: .listOpenFederationDHTRecords, listOpenFederationDHTRecords: request)
    }

    public func withAuthToken(_ token: String?) -> RelayRequest {
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
            listGroupInvitations: listGroupInvitations,
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

public enum RelayResponseType: String, Codable {
    case ok
    case delivered
    case messages
    case groupMessages
    case announcements
    case pairRequests
    case attachment
    case prekeyBundle
    case group
    case groups
    case groupInvitations
    case groupJoinRequests
    case federationNodes
    case info
    case openFederationDHTRecords
    case error
}

public struct DeliverResponse: Codable, Equatable {
    public let storedCount: Int

    public init(storedCount: Int) {
        self.storedCount = storedCount
    }
}

public struct RelayResponse: Codable, Equatable {
    public let type: RelayResponseType
    public let delivered: DeliverResponse?
    public let messages: [Envelope]?
    public let groupMessages: [GroupRatchetEnvelope]?
    public let announcements: [PairingAnnouncement]?
    public let pairRequests: [PairingRequest]?
    public let attachment: AttachmentChunk?
    public let prekeyBundle: PrekeyBundle?
    public let group: RelayGroupDescriptor?
    public let groups: [RelayGroupDescriptor]?
    public let groupInvitations: [RelayGroupInvitation]?
    public let groupJoinRequests: [RelayGroupJoinRequest]?
    public let federationNodes: [FederationNodeRecord]?
    public let federationSnapshot: FederationDirectorySnapshot?
    public let relayInfo: RelayInfo?
    public let openFederationDHTRecords: [OpenFederationDHTRecord]?
    public let error: String?

    public init(
        type: RelayResponseType,
        delivered: DeliverResponse? = nil,
        messages: [Envelope]? = nil,
        groupMessages: [GroupRatchetEnvelope]? = nil,
        announcements: [PairingAnnouncement]? = nil,
        pairRequests: [PairingRequest]? = nil,
        attachment: AttachmentChunk? = nil,
        prekeyBundle: PrekeyBundle? = nil,
        group: RelayGroupDescriptor? = nil,
        groups: [RelayGroupDescriptor]? = nil,
        groupInvitations: [RelayGroupInvitation]? = nil,
        groupJoinRequests: [RelayGroupJoinRequest]? = nil,
        federationNodes: [FederationNodeRecord]? = nil,
        federationSnapshot: FederationDirectorySnapshot? = nil,
        relayInfo: RelayInfo? = nil,
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
        self.prekeyBundle = prekeyBundle
        self.group = group
        self.groups = groups
        self.groupInvitations = groupInvitations
        self.groupJoinRequests = groupJoinRequests
        self.federationNodes = federationNodes
        self.federationSnapshot = federationSnapshot
        self.relayInfo = relayInfo
        self.openFederationDHTRecords = openFederationDHTRecords
        self.error = error
    }

    public static func ok() -> RelayResponse {
        RelayResponse(type: .ok)
    }

    public static func delivered(count: Int) -> RelayResponse {
        RelayResponse(type: .delivered, delivered: DeliverResponse(storedCount: count))
    }

    public static func messages(_ envelopes: [Envelope]) -> RelayResponse {
        RelayResponse(type: .messages, messages: envelopes)
    }

    public static func groupMessages(_ envelopes: [GroupRatchetEnvelope]) -> RelayResponse {
        RelayResponse(type: .groupMessages, groupMessages: envelopes)
    }

    public static func announcements(_ list: [PairingAnnouncement]) -> RelayResponse {
        RelayResponse(type: .announcements, announcements: list)
    }

    public static func pairRequests(_ list: [PairingRequest]) -> RelayResponse {
        RelayResponse(type: .pairRequests, pairRequests: list)
    }

    public static func attachment(_ chunk: AttachmentChunk) -> RelayResponse {
        RelayResponse(type: .attachment, attachment: chunk)
    }

    public static func prekeyBundle(_ bundle: PrekeyBundle?) -> RelayResponse {
        RelayResponse(type: .prekeyBundle, prekeyBundle: bundle)
    }

    public static func group(_ group: RelayGroupDescriptor?) -> RelayResponse {
        RelayResponse(type: .group, group: group)
    }

    public static func groups(_ groups: [RelayGroupDescriptor]) -> RelayResponse {
        RelayResponse(type: .groups, groups: groups)
    }

    public static func groupInvitations(_ invitations: [RelayGroupInvitation]) -> RelayResponse {
        RelayResponse(type: .groupInvitations, groupInvitations: invitations)
    }

    public static func groupJoinRequests(_ requests: [RelayGroupJoinRequest]) -> RelayResponse {
        RelayResponse(type: .groupJoinRequests, groupJoinRequests: requests)
    }

    public static func federationNodes(
        _ nodes: [FederationNodeRecord],
        snapshot: FederationDirectorySnapshot? = nil
    ) -> RelayResponse {
        RelayResponse(type: .federationNodes, federationNodes: nodes, federationSnapshot: snapshot)
    }

    public static func info(_ info: RelayInfo) -> RelayResponse {
        RelayResponse(type: .info, relayInfo: info)
    }

    public static func openFederationDHTRecords(_ records: [OpenFederationDHTRecord]) -> RelayResponse {
        RelayResponse(type: .openFederationDHTRecords, openFederationDHTRecords: records)
    }

    public static func error(_ message: String) -> RelayResponse {
        RelayResponse(type: .error, error: message)
    }
}

public struct AttachmentChunk: Codable, Equatable {
    public let attachmentId: UUID
    public let chunkIndex: Int
    public let payload: EncryptedPayload

    public init(attachmentId: UUID, chunkIndex: Int, payload: EncryptedPayload) {
        self.attachmentId = attachmentId
        self.chunkIndex = chunkIndex
        self.payload = payload
    }
}
