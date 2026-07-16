import CryptoKit
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
    public var protocolCapabilities: RelayCapabilityManifestV2?
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
        protocolCapabilities: RelayCapabilityManifestV2? = nil,
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
        self.temporalBucketSeconds = min(max(temporalBucketSeconds, 0), 86_400)
        if let temporalBucketScheduleSeconds {
            let normalized = Array(
                Set(temporalBucketScheduleSeconds.filter { (1...86_400).contains($0) })
            ).sorted().prefix(16).map { $0 }
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
        self.protocolCapabilities = protocolCapabilities?.isStructurallyValid == true
            ? protocolCapabilities
            : nil
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
    public var experimentalRouteCapabilitiesEnabled: Bool?
    public var rendezvousTransportEnabled: Bool?

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
        groupSecurityModel: GroupSecurityModel = .mlsDerivedTree,
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
        allowPrivateFederationEndpoints: Bool = false,
        experimentalRouteCapabilitiesEnabled: Bool = false,
        rendezvousTransportEnabled: Bool = false
    ) {
        self.kind = kind
        self.federation = federation
        self.temporalBucketSeconds = min(max(0, temporalBucketSeconds), 86_400)
        if let temporalBucketScheduleSeconds {
            let normalized = Array(
                Set(temporalBucketScheduleSeconds.map { min(max(0, $0), 86_400) }.filter { $0 > 0 })
                    .sorted()
                    .prefix(16)
            )
            self.temporalBucketScheduleSeconds = normalized.isEmpty ? nil : normalized
        } else {
            self.temporalBucketScheduleSeconds = nil
        }
        let maximumAttachmentTTL = 30 * 24 * 60 * 60
        let normalizedAttachmentDefaultTTL = min(max(60, attachmentDefaultTTLSeconds), maximumAttachmentTTL)
        self.attachmentDefaultTTLSeconds = normalizedAttachmentDefaultTTL
        self.attachmentMaxTTLSeconds = min(
            max(normalizedAttachmentDefaultTTL, attachmentMaxTTLSeconds),
            maximumAttachmentTTL
        )
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
        self.federationCoordinatorEndpoints = federationCoordinatorEndpoints.map { Array($0.prefix(16)) }
        self.coordinatorHeartbeatSeconds = coordinatorHeartbeatSeconds.map { min(max($0, 15), 3_600) }
        self.coordinatorDirectoryMaxStalenessSeconds = coordinatorDirectoryMaxStalenessSeconds.map { min(max($0, 30), 86_400) }
        self.relayPeerExchangeLimit = relayPeerExchangeLimit.map { min(max($0, 0), 128) }
        self.openFederationDHTEnabled = openFederationDHTEnabled
        self.openFederationDHTMaxRecords = min(max(1, openFederationDHTMaxRecords), 256)
        self.openFederationDHTMaxRecordsPerHost = min(max(1, openFederationDHTMaxRecordsPerHost), 16)
        self.openFederationDHTMaxQueryRecords = min(max(1, openFederationDHTMaxQueryRecords), 512)
        self.coordinatorDirectorySigningPrivateKey = coordinatorDirectorySigningPrivateKey.flatMap {
            $0.count <= 16_384 ? $0 : nil
        }
        self.curatedStrictPolicyEnabled = curatedStrictPolicyEnabled
        self.curatedCoordinatorQuorum = min(max(1, curatedCoordinatorQuorum), 16)
        self.curatedRequireSignedDirectory = curatedRequireSignedDirectory
        self.advertisedEndpoint = advertisedEndpoint
        self.federationAllowList = Array(federationAllowList.prefix(256))
        self.allowPrivateFederationEndpoints = allowPrivateFederationEndpoints
        self.experimentalRouteCapabilitiesEnabled = experimentalRouteCapabilitiesEnabled ? true : nil
        self.rendezvousTransportEnabled = rendezvousTransportEnabled ? true : nil
    }

    public var opaqueRouteCapabilitiesEnabled: Bool {
        experimentalRouteCapabilitiesEnabled == true
    }

    public var isRendezvousTransportEnabled: Bool {
        rendezvousTransportEnabled == true
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
            protocolCapabilities: .advertised(
                attachmentsEnabled: attachmentsEnabled != false,
                wakeEnabled: wakeSupport != nil,
                hiddenRetrievalEnabled: advertisedHiddenRetrieval != nil,
                onionEnabled: advertisedOnionTransport != nil,
                mixnetEnabled: advertisedMixnetTransport != nil,
                rendezvousTransportEnabled: isRendezvousTransportEnabled
            ),
            groupCreationMode: .disabled,
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
    case retireInbox
    case createInboxRouteCapability
    case revokeInboxRouteCapability
    case registerRendezvousTransportV2
    case appendRendezvousTransportV2
    case syncRendezvousTransportV2
    case deleteRendezvousTransportV2
    case fetch
    case registerMailboxConsumer
    case syncMailbox
    case commitMailboxCursor
    case revokeMailboxConsumer
    case health
    case info
    case uploadAttachment
    case fetchAttachment
    case registerFederationNode
    case listFederationNodes
    case publishOpenFederationDHTRecord
    case listOpenFederationDHTRecords

}

public struct DeliverRequest: Codable, Equatable {
    /// Present only for the transitional pre-v2 inbox-addressed path.
    /// Capability-addressed delivery deliberately omits the inbox identifier.
    public let inboxId: String?
    public let routingToken: String?
    public let inboxCapability: InboxRouteCapabilityV2?
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
        self.inboxCapability = nil
        self.envelope = envelope
        self.destinationRelay = destinationRelay
    }

    /// Constructs the future fail-closed delivery shape. Client relationship
    /// publication is intentionally not wired yet; callers must obtain the
    /// opaque capability through a separately authenticated private exchange.
    public init(
        inboxCapability: InboxRouteCapabilityV2,
        envelope: Envelope,
        destinationRelay: RelayEndpoint? = nil
    ) {
        self.inboxId = nil
        self.routingToken = nil
        self.inboxCapability = inboxCapability
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
        return try NoctweaveCoder.encode(
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
    public static let privacyMinimizedVersion = 2

    public let inboxId: String
    public let accessPublicKey: Data
    public let registrationVersion: Int
    public let accessProof: RelayActorProof?

    public init(
        inboxId: String,
        accessPublicKey: Data,
        registrationVersion: Int = privacyMinimizedVersion,
        accessProof: RelayActorProof? = nil
    ) {
        self.inboxId = inboxId
        self.accessPublicKey = accessPublicKey
        self.registrationVersion = registrationVersion
        self.accessProof = accessProof
    }

    public static func privacyMinimizedV2(
        inboxId: String,
        accessPublicKey: Data,
        accessProof: RelayActorProof? = nil
    ) -> RegisterInboxRequest {
        RegisterInboxRequest(
            inboxId: inboxId,
            accessPublicKey: accessPublicKey,
            registrationVersion: privacyMinimizedVersion,
            accessProof: accessProof
        )
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        return try NoctweaveCoder.encode(
            InboxRegistrationProofPayloadV2(
                inboxId: inboxId,
                accessPublicKey: accessPublicKey,
                registrationVersion: registrationVersion,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            ),
            sortedKeys: true
        )
    }
}

/// Permanently removes the live state for one route-level inbox generation.
///
/// The proof is made by the inbox access key. Relays retain a compact,
/// non-expiring non-resurrection record after the registration, stream
/// consumers, and queued envelopes have been deleted.
public struct RetireInboxRequest: Codable, Equatable {
    public static let protocolVersion = 1
    public static let signatureDomain = "org.noctweave.relay.retire-inbox"

    public let inboxId: String
    public let accessProof: RelayActorProof?

    public init(inboxId: String, accessProof: RelayActorProof? = nil) {
        self.inboxId = inboxId
        self.accessProof = accessProof
    }

    /// Produces the exact, self-contained request that a burn journal can
    /// persist before deleting the inbox access private key.
    public static func make(
        inboxId: String,
        accessSigningKey: SigningKeyPair,
        signedAt: Date = Date(),
        nonce: UUID = UUID()
    ) throws -> RetireInboxRequest {
        guard InboxAddress.isBound(inboxId, to: accessSigningKey.publicKeyData) else {
            throw RetireInboxRequestError.inboxAccessKeyMismatch
        }
        let proofTemplate = RelayActorProof(
            fingerprint: CryptoBox.fingerprint(for: accessSigningKey.publicKeyData),
            publicSigningKey: accessSigningKey.publicKeyData,
            signedAt: signedAt,
            nonce: nonce,
            signature: Data()
        )
        let unsigned = RetireInboxRequest(inboxId: inboxId, accessProof: proofTemplate)
        let proof = try RelayActorProof.make(
            signingKey: accessSigningKey,
            signableData: unsigned.signableData(for: proofTemplate),
            signedAt: signedAt,
            nonce: nonce
        )
        return RetireInboxRequest(inboxId: inboxId, accessProof: proof)
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try NoctweaveCoder.encode(
            InboxRetirementProofPayload(
                domain: Self.signatureDomain,
                version: Self.protocolVersion,
                inboxId: inboxId,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            ),
            sortedKeys: true
        )
    }

    func requestDigest() throws -> Data {
        Data(SHA256.hash(data: try NoctweaveCoder.encode(self, sortedKeys: true)))
    }
}

public enum RetireInboxRequestError: Error, Equatable {
    case inboxAccessKeyMismatch
}

public enum InboxRouteCapabilityMutationRequestError: Error, Equatable {
    case invalidMutationState
}

public struct CreateInboxRouteCapabilityRequest: Codable, Equatable {
    public static let protocolVersion = 3
    public static let maximumMutationSequence: UInt64 = UInt64(UInt32.max)
    public static let signatureDomain = "org.noctweave.relay.inbox-route-capability-mutation"

    static func nextMutationSequence(after current: UInt64) -> UInt64 {
        guard current < maximumMutationSequence else { return 0 }
        return current + 1
    }

    public let inboxId: String
    public let capability: InboxRouteCapabilityV2
    public let relayScope: Data
    public let mutationSequence: UInt64
    public let authorityProof: RelayActorProof?

    public init(
        inboxId: String,
        capability: InboxRouteCapabilityV2,
        relayScope: Data,
        mutationSequence: UInt64,
        authorityProof: RelayActorProof? = nil
    ) {
        self.inboxId = inboxId
        self.capability = capability
        self.relayScope = relayScope
        self.mutationSequence = mutationSequence
        self.authorityProof = authorityProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try inboxRouteCapabilityMutationSignableData(
            operation: "create",
            inboxId: inboxId,
            capability: capability,
            relayScope: relayScope,
            mutationSequence: mutationSequence,
            proof: proof
        )
    }

    public func mutationDigest() throws -> Data {
        try inboxRouteCapabilityMutationDigest(
            operation: "create",
            inboxId: inboxId,
            capability: capability,
            relayScope: relayScope,
            mutationSequence: mutationSequence
        )
    }
}

public struct RevokeInboxRouteCapabilityRequest: Codable, Equatable {
    public static let protocolVersion = CreateInboxRouteCapabilityRequest.protocolVersion
    public static let signatureDomain = CreateInboxRouteCapabilityRequest.signatureDomain

    public let inboxId: String
    public let capability: InboxRouteCapabilityV2
    public let relayScope: Data
    public let mutationSequence: UInt64
    public let authorityProof: RelayActorProof?

    public init(
        inboxId: String,
        capability: InboxRouteCapabilityV2,
        relayScope: Data,
        mutationSequence: UInt64,
        authorityProof: RelayActorProof? = nil
    ) {
        self.inboxId = inboxId
        self.capability = capability
        self.relayScope = relayScope
        self.mutationSequence = mutationSequence
        self.authorityProof = authorityProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try inboxRouteCapabilityMutationSignableData(
            operation: "revoke",
            inboxId: inboxId,
            capability: capability,
            relayScope: relayScope,
            mutationSequence: mutationSequence,
            proof: proof
        )
    }

    public func mutationDigest() throws -> Data {
        try inboxRouteCapabilityMutationDigest(
            operation: "revoke",
            inboxId: inboxId,
            capability: capability,
            relayScope: relayScope,
            mutationSequence: mutationSequence
        )
    }
}

private func inboxRouteCapabilityMutationSignableData(
    operation: String,
    inboxId: String,
    capability: InboxRouteCapabilityV2,
    relayScope: Data,
    mutationSequence: UInt64,
    proof: RelayActorProof
) throws -> Data {
    guard relayScope.count == 32,
          relayScope.contains(where: { $0 != 0 }),
          mutationSequence > 0,
          mutationSequence <= CreateInboxRouteCapabilityRequest.maximumMutationSequence else {
        throw InboxRouteCapabilityMutationRequestError.invalidMutationState
    }
    return try NoctweaveCoder.encode(
        InboxRouteCapabilityMutationProofPayload(
            domain: CreateInboxRouteCapabilityRequest.signatureDomain,
            version: CreateInboxRouteCapabilityRequest.protocolVersion,
            operation: operation,
            inboxId: inboxId,
            capabilityDigest: capability.relayRegistryDigest,
            relayScope: relayScope,
            mutationSequence: mutationSequence,
            signedAt: proof.signedAt,
            nonce: proof.nonce
        ),
        sortedKeys: true
    )
}

private func inboxRouteCapabilityMutationDigest(
    operation: String,
    inboxId: String,
    capability: InboxRouteCapabilityV2,
    relayScope: Data,
    mutationSequence: UInt64
) throws -> Data {
    guard relayScope.count == 32,
          relayScope.contains(where: { $0 != 0 }),
          mutationSequence > 0,
          mutationSequence <= CreateInboxRouteCapabilityRequest.maximumMutationSequence else {
        throw InboxRouteCapabilityMutationRequestError.invalidMutationState
    }
    let payload = try NoctweaveCoder.encode(
        InboxRouteCapabilityMutationStatePayload(
            domain: "\(CreateInboxRouteCapabilityRequest.signatureDomain)/state",
            version: CreateInboxRouteCapabilityRequest.protocolVersion,
            operation: operation,
            inboxId: inboxId,
            capabilityDigest: capability.relayRegistryDigest,
            relayScope: relayScope,
            mutationSequence: mutationSequence
        ),
        sortedKeys: true
    )
    return Data(SHA256.hash(data: payload))
}

public struct RegisterMailboxConsumerRequest: Codable, Equatable {
    public let inboxId: String
    public let consumerId: MailboxConsumerId
    public let consumerSigningPublicKey: Data
    public let sponsorConsumerId: MailboxConsumerId?
    public let startingSequence: UInt64?
    public let authorityProof: RelayActorProof?
    public let consumerProof: RelayActorProof?
    public let sponsorProof: RelayActorProof?

    public init(
        inboxId: String,
        consumerId: MailboxConsumerId,
        consumerSigningPublicKey: Data,
        sponsorConsumerId: MailboxConsumerId? = nil,
        startingSequence: UInt64? = nil,
        authorityProof: RelayActorProof? = nil,
        consumerProof: RelayActorProof? = nil,
        sponsorProof: RelayActorProof? = nil
    ) {
        self.inboxId = inboxId
        self.consumerId = consumerId
        self.consumerSigningPublicKey = consumerSigningPublicKey
        self.sponsorConsumerId = sponsorConsumerId
        self.startingSequence = startingSequence
        self.authorityProof = authorityProof
        self.consumerProof = consumerProof
        self.sponsorProof = sponsorProof
    }

    public func authoritySignableData(for proof: RelayActorProof) throws -> Data {
        try signableData(operation: "register-authority", proof: proof)
    }

    public func consumerSignableData(for proof: RelayActorProof) throws -> Data {
        try signableData(operation: "register-possession", proof: proof)
    }

    public func sponsorSignableData(for proof: RelayActorProof) throws -> Data {
        try signableData(operation: "register-sponsor", proof: proof)
    }

    private func signableData(operation: String, proof: RelayActorProof) throws -> Data {
        try NoctweaveCoder.encode(
            MailboxConsumerProofPayload(
                operation: operation,
                inboxId: inboxId,
                consumerId: consumerId,
                consumerSigningPublicKey: consumerSigningPublicKey,
                sponsorConsumerId: sponsorConsumerId,
                cursor: nil,
                sequence: startingSequence,
                maxCount: nil,
                longPollTimeoutSeconds: nil,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            ),
            sortedKeys: true
        )
    }
}

public struct SyncMailboxRequest: Codable, Equatable {
    public let inboxId: String
    public let consumerId: MailboxConsumerId
    public let cursor: MailboxCursor?
    public let maxCount: Int?
    public let longPollTimeoutSeconds: Int?
    public let consumerProof: RelayActorProof?

    public init(
        inboxId: String,
        consumerId: MailboxConsumerId,
        cursor: MailboxCursor? = nil,
        maxCount: Int? = nil,
        longPollTimeoutSeconds: Int? = nil,
        consumerProof: RelayActorProof? = nil
    ) {
        self.inboxId = inboxId
        self.consumerId = consumerId
        self.cursor = cursor
        self.maxCount = maxCount
        self.longPollTimeoutSeconds = longPollTimeoutSeconds
        self.consumerProof = consumerProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try NoctweaveCoder.encode(
            MailboxConsumerProofPayload(
                operation: "sync",
                inboxId: inboxId,
                consumerId: consumerId,
                consumerSigningPublicKey: nil,
                sponsorConsumerId: nil,
                cursor: cursor,
                sequence: nil,
                maxCount: maxCount,
                longPollTimeoutSeconds: longPollTimeoutSeconds,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            ),
            sortedKeys: true
        )
    }
}

public struct CommitMailboxCursorRequest: Codable, Equatable {
    public let inboxId: String
    public let consumerId: MailboxConsumerId
    public let cursor: MailboxCursor
    public let sequence: UInt64
    public let consumerProof: RelayActorProof?

    public init(
        inboxId: String,
        consumerId: MailboxConsumerId,
        cursor: MailboxCursor,
        sequence: UInt64,
        consumerProof: RelayActorProof? = nil
    ) {
        self.inboxId = inboxId
        self.consumerId = consumerId
        self.cursor = cursor
        self.sequence = sequence
        self.consumerProof = consumerProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try NoctweaveCoder.encode(
            MailboxConsumerProofPayload(
                operation: "commit",
                inboxId: inboxId,
                consumerId: consumerId,
                consumerSigningPublicKey: nil,
                sponsorConsumerId: nil,
                cursor: cursor,
                sequence: sequence,
                maxCount: nil,
                longPollTimeoutSeconds: nil,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            ),
            sortedKeys: true
        )
    }
}

public struct RevokeMailboxConsumerRequest: Codable, Equatable {
    public let inboxId: String
    public let consumerId: MailboxConsumerId
    public let authorityProof: RelayActorProof?

    public init(
        inboxId: String,
        consumerId: MailboxConsumerId,
        authorityProof: RelayActorProof? = nil
    ) {
        self.inboxId = inboxId
        self.consumerId = consumerId
        self.authorityProof = authorityProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try NoctweaveCoder.encode(
            MailboxConsumerProofPayload(
                operation: "revoke-authority",
                inboxId: inboxId,
                consumerId: consumerId,
                consumerSigningPublicKey: nil,
                sponsorConsumerId: nil,
                cursor: nil,
                sequence: nil,
                maxCount: nil,
                longPollTimeoutSeconds: nil,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            ),
            sortedKeys: true
        )
    }
}

private struct MailboxConsumerProofPayload: Codable {
    let operation: String
    let inboxId: String
    let consumerId: MailboxConsumerId
    let consumerSigningPublicKey: Data?
    let sponsorConsumerId: MailboxConsumerId?
    let cursor: MailboxCursor?
    let sequence: UInt64?
    let maxCount: Int?
    let longPollTimeoutSeconds: Int?
    let signedAt: Date
    let nonce: UUID
}

private struct InboxRegistrationProofPayloadV2: Codable {
    let inboxId: String
    let accessPublicKey: Data
    let registrationVersion: Int
    let signedAt: Date
    let nonce: UUID
}

private struct InboxRetirementProofPayload: Codable {
    let domain: String
    let version: Int
    let inboxId: String
    let signedAt: Date
    let nonce: UUID
}

private struct InboxRouteCapabilityMutationProofPayload: Codable {
    let domain: String
    let version: Int
    let operation: String
    let inboxId: String
    let capabilityDigest: Data
    let relayScope: Data
    let mutationSequence: UInt64
    let signedAt: Date
    let nonce: UUID
}

private struct InboxRouteCapabilityMutationStatePayload: Codable {
    let domain: String
    let version: Int
    let operation: String
    let inboxId: String
    let capabilityDigest: Data
    let relayScope: Data
    let mutationSequence: UInt64
}

private struct InboxFetchProofPayload: Codable {
    let inboxId: String
    let routingToken: String?
    let maxCount: Int?
    let longPollTimeoutSeconds: Int?
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

/// Relay-visible bounds for the identity-blind rendezvous transport. The relay
/// stores opaque, already-encrypted frame bytes and never decodes the enclosed
/// `RendezvousFrameV2`.
public enum RendezvousRelayTransportV2 {
    public static let version = 2
    public static let capabilityBytes = 32
    public static let laneIDBytes = 32
    public static let frameIDBytes = 16
    public static let laneCount = 2
    public static let maximumLifetimeSeconds: TimeInterval = 10 * 60
    public static let maximumFramesPerLane: UInt64 = 32
    public static let maximumCiphertextBytesPerLane = 2_097_152
    public static let maximumSyncFrames = 32
    public static let allowedCiphertextByteCounts = [4_096, 16_384, 65_536]

    static func isCanonicalTimestamp(_ date: Date) -> Bool {
        let seconds = date.timeIntervalSince1970
        return seconds.isFinite && floor(seconds) == seconds
    }

    static func isValidOpaqueValue(_ value: Data, byteCount: Int) -> Bool {
        value.count == byteCount && value.contains { $0 != 0 }
    }
}

public struct RendezvousRelayRouteCapabilityV2: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: Data

    public init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public static func generate() -> RendezvousRelayRouteCapabilityV2 {
        RendezvousRelayRouteCapabilityV2(
            rawValue: SymmetricKey(size: .bits256).dataRepresentation
        )
    }

    public var isStructurallyValid: Bool {
        RendezvousRelayTransportV2.isValidOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes
        )
    }
}

public struct RendezvousRelayPublishCapabilityV2: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: Data

    public init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public static func generate() -> RendezvousRelayPublishCapabilityV2 {
        RendezvousRelayPublishCapabilityV2(
            rawValue: SymmetricKey(size: .bits256).dataRepresentation
        )
    }

    public var isStructurallyValid: Bool {
        RendezvousRelayTransportV2.isValidOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes
        )
    }
}

public struct RendezvousRelayReadCapabilityV2: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: Data

    public init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public static func generate() -> RendezvousRelayReadCapabilityV2 {
        RendezvousRelayReadCapabilityV2(
            rawValue: SymmetricKey(size: .bits256).dataRepresentation
        )
    }

    public var isStructurallyValid: Bool {
        RendezvousRelayTransportV2.isValidOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes
        )
    }
}

public struct RendezvousRelayDeleteCapabilityV2: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: Data

    public init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public static func generate() -> RendezvousRelayDeleteCapabilityV2 {
        RendezvousRelayDeleteCapabilityV2(
            rawValue: SymmetricKey(size: .bits256).dataRepresentation
        )
    }

    public var isStructurallyValid: Bool {
        RendezvousRelayTransportV2.isValidOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes
        )
    }
}

public struct RendezvousRelayLaneIDV2: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: Data

    public init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public static func generate() -> RendezvousRelayLaneIDV2 {
        RendezvousRelayLaneIDV2(
            rawValue: SymmetricKey(size: .bits256).dataRepresentation
        )
    }

    public var isStructurallyValid: Bool {
        RendezvousRelayTransportV2.isValidOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.laneIDBytes
        )
    }
}

public struct RendezvousRelayFrameIDV2: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: Data

    public init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public static func generate() -> RendezvousRelayFrameIDV2 {
        RendezvousRelayFrameIDV2(
            rawValue: Data(SymmetricKey(size: .bits256).dataRepresentation.prefix(
                RendezvousRelayTransportV2.frameIDBytes
            ))
        )
    }

    public var isStructurallyValid: Bool {
        RendezvousRelayTransportV2.isValidOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.frameIDBytes
        )
    }
}

public struct RendezvousRelayLaneRegistrationV2: Codable, Equatable {
    public let laneId: RendezvousRelayLaneIDV2
    public let publishCapability: RendezvousRelayPublishCapabilityV2
    public let readCapability: RendezvousRelayReadCapabilityV2
    public let deleteCapability: RendezvousRelayDeleteCapabilityV2

    public init(
        laneId: RendezvousRelayLaneIDV2,
        publishCapability: RendezvousRelayPublishCapabilityV2,
        readCapability: RendezvousRelayReadCapabilityV2,
        deleteCapability: RendezvousRelayDeleteCapabilityV2
    ) {
        self.laneId = laneId
        self.publishCapability = publishCapability
        self.readCapability = readCapability
        self.deleteCapability = deleteCapability
    }

    public var isStructurallyValid: Bool {
        laneId.isStructurallyValid
            && publishCapability.isStructurallyValid
            && readCapability.isStructurallyValid
            && deleteCapability.isStructurallyValid
    }
}

public struct RegisterRendezvousTransportV2Request: Codable, Equatable {
    public let version: Int
    public let routeCapability: RendezvousRelayRouteCapabilityV2
    public let expiresAt: Date
    public let lanes: [RendezvousRelayLaneRegistrationV2]

    public init(
        version: Int = RendezvousRelayTransportV2.version,
        routeCapability: RendezvousRelayRouteCapabilityV2,
        expiresAt: Date,
        lanes: [RendezvousRelayLaneRegistrationV2]
    ) {
        self.version = version
        self.routeCapability = routeCapability
        self.expiresAt = expiresAt
        self.lanes = lanes
    }

    public func isStructurallyValid(at now: Date = Date()) -> Bool {
        guard version == RendezvousRelayTransportV2.version,
              routeCapability.isStructurallyValid,
              RendezvousRelayTransportV2.isCanonicalTimestamp(expiresAt),
              now.timeIntervalSince1970.isFinite,
              expiresAt > now,
              expiresAt <= Date(
                timeIntervalSince1970: floor(now.timeIntervalSince1970)
                    + RendezvousRelayTransportV2.maximumLifetimeSeconds
              ),
              lanes.count == RendezvousRelayTransportV2.laneCount,
              lanes.allSatisfy(\.isStructurallyValid),
              Set(lanes.map(\.laneId)).count == RendezvousRelayTransportV2.laneCount else {
            return false
        }
        let authorityValues = [routeCapability.rawValue] + lanes.flatMap {
            [
                $0.publishCapability.rawValue,
                $0.readCapability.rawValue,
                $0.deleteCapability.rawValue
            ]
        }
        return Set(authorityValues).count == authorityValues.count
    }
}

/// Opaque frame bytes. The outer lane sequence is relay-enforced; the encrypted
/// inner frame retains its own authenticated session sequence.
public struct RendezvousRelayCiphertextFrameV2: Codable, Equatable {
    public let frameId: RendezvousRelayFrameIDV2
    public let sequence: UInt64
    public let ciphertext: Data

    public init(
        frameId: RendezvousRelayFrameIDV2,
        sequence: UInt64,
        ciphertext: Data
    ) {
        self.frameId = frameId
        self.sequence = sequence
        self.ciphertext = ciphertext
    }

    public var isStructurallyValid: Bool {
        frameId.isStructurallyValid
            && sequence > 0
            && sequence <= RendezvousRelayTransportV2.maximumFramesPerLane
            && RendezvousRelayTransportV2.allowedCiphertextByteCounts.contains(ciphertext.count)
    }

    var ciphertextDigest: Data {
        Data(SHA256.hash(data: ciphertext))
    }
}

public struct AppendRendezvousTransportV2Request: Codable, Equatable {
    public let routeCapability: RendezvousRelayRouteCapabilityV2
    public let laneId: RendezvousRelayLaneIDV2
    public let publishCapability: RendezvousRelayPublishCapabilityV2
    public let frame: RendezvousRelayCiphertextFrameV2

    public init(
        routeCapability: RendezvousRelayRouteCapabilityV2,
        laneId: RendezvousRelayLaneIDV2,
        publishCapability: RendezvousRelayPublishCapabilityV2,
        frame: RendezvousRelayCiphertextFrameV2
    ) {
        self.routeCapability = routeCapability
        self.laneId = laneId
        self.publishCapability = publishCapability
        self.frame = frame
    }

    public var isStructurallyValid: Bool {
        routeCapability.isStructurallyValid
            && laneId.isStructurallyValid
            && publishCapability.isStructurallyValid
            && frame.isStructurallyValid
    }
}

public struct SyncRendezvousTransportV2Request: Codable, Equatable {
    public let routeCapability: RendezvousRelayRouteCapabilityV2
    public let laneId: RendezvousRelayLaneIDV2
    public let readCapability: RendezvousRelayReadCapabilityV2
    public let afterSequence: UInt64
    public let maxCount: Int?

    public init(
        routeCapability: RendezvousRelayRouteCapabilityV2,
        laneId: RendezvousRelayLaneIDV2,
        readCapability: RendezvousRelayReadCapabilityV2,
        afterSequence: UInt64 = 0,
        maxCount: Int? = nil
    ) {
        self.routeCapability = routeCapability
        self.laneId = laneId
        self.readCapability = readCapability
        self.afterSequence = afterSequence
        self.maxCount = maxCount
    }

    public var isStructurallyValid: Bool {
        routeCapability.isStructurallyValid
            && laneId.isStructurallyValid
            && readCapability.isStructurallyValid
            && afterSequence <= RendezvousRelayTransportV2.maximumFramesPerLane
            && maxCount.map { (1...RendezvousRelayTransportV2.maximumSyncFrames).contains($0) } ?? true
    }
}

public struct DeleteRendezvousTransportV2Request: Codable, Equatable {
    public let routeCapability: RendezvousRelayRouteCapabilityV2
    public let laneId: RendezvousRelayLaneIDV2
    public let deleteCapability: RendezvousRelayDeleteCapabilityV2

    public init(
        routeCapability: RendezvousRelayRouteCapabilityV2,
        laneId: RendezvousRelayLaneIDV2,
        deleteCapability: RendezvousRelayDeleteCapabilityV2
    ) {
        self.routeCapability = routeCapability
        self.laneId = laneId
        self.deleteCapability = deleteCapability
    }

    public var isStructurallyValid: Bool {
        routeCapability.isStructurallyValid
            && laneId.isStructurallyValid
            && deleteCapability.isStructurallyValid
    }
}

public struct RendezvousRelaySyncBatchV2: Codable, Equatable {
    public let frames: [RendezvousRelayCiphertextFrameV2]
    public let highWatermark: UInt64
    public let nextSequence: UInt64
    public let hasMore: Bool

    public init(
        frames: [RendezvousRelayCiphertextFrameV2],
        highWatermark: UInt64,
        nextSequence: UInt64,
        hasMore: Bool
    ) {
        self.frames = frames
        self.highWatermark = highWatermark
        self.nextSequence = nextSequence
        self.hasMore = hasMore
    }
}

public struct RelayRequest: Codable, Equatable {
    public let type: RelayRequestType
    public let authToken: String?
    public let deliver: DeliverRequest?
    public let registerInbox: RegisterInboxRequest?
    public let retireInbox: RetireInboxRequest?
    public let createInboxRouteCapability: CreateInboxRouteCapabilityRequest?
    public let revokeInboxRouteCapability: RevokeInboxRouteCapabilityRequest?
    public let registerRendezvousTransportV2: RegisterRendezvousTransportV2Request?
    public let appendRendezvousTransportV2: AppendRendezvousTransportV2Request?
    public let syncRendezvousTransportV2: SyncRendezvousTransportV2Request?
    public let deleteRendezvousTransportV2: DeleteRendezvousTransportV2Request?
    public let fetch: FetchRequest?
    public let registerMailboxConsumer: RegisterMailboxConsumerRequest?
    public let syncMailbox: SyncMailboxRequest?
    public let commitMailboxCursor: CommitMailboxCursorRequest?
    public let revokeMailboxConsumer: RevokeMailboxConsumerRequest?
    public let uploadAttachment: UploadAttachmentRequest?
    public let fetchAttachment: FetchAttachmentRequest?
    public let registerFederationNode: FederationNodeRegistrationRequest?
    public let listFederationNodes: ListFederationNodesRequest?
    public let publishOpenFederationDHTRecord: PublishOpenFederationDHTRecordRequest?
    public let listOpenFederationDHTRecords: ListOpenFederationDHTRecordsRequest?

    public init(
        type: RelayRequestType,
        authToken: String? = nil,
        deliver: DeliverRequest? = nil,
        registerInbox: RegisterInboxRequest? = nil,
        retireInbox: RetireInboxRequest? = nil,
        createInboxRouteCapability: CreateInboxRouteCapabilityRequest? = nil,
        revokeInboxRouteCapability: RevokeInboxRouteCapabilityRequest? = nil,
        registerRendezvousTransportV2: RegisterRendezvousTransportV2Request? = nil,
        appendRendezvousTransportV2: AppendRendezvousTransportV2Request? = nil,
        syncRendezvousTransportV2: SyncRendezvousTransportV2Request? = nil,
        deleteRendezvousTransportV2: DeleteRendezvousTransportV2Request? = nil,
        fetch: FetchRequest? = nil,
        registerMailboxConsumer: RegisterMailboxConsumerRequest? = nil,
        syncMailbox: SyncMailboxRequest? = nil,
        commitMailboxCursor: CommitMailboxCursorRequest? = nil,
        revokeMailboxConsumer: RevokeMailboxConsumerRequest? = nil,
        uploadAttachment: UploadAttachmentRequest? = nil,
        fetchAttachment: FetchAttachmentRequest? = nil,
        registerFederationNode: FederationNodeRegistrationRequest? = nil,
        listFederationNodes: ListFederationNodesRequest? = nil,
        publishOpenFederationDHTRecord: PublishOpenFederationDHTRecordRequest? = nil,
        listOpenFederationDHTRecords: ListOpenFederationDHTRecordsRequest? = nil
    ) {
        self.type = type
        self.authToken = authToken
        self.deliver = deliver
        self.registerInbox = registerInbox
        self.retireInbox = retireInbox
        self.createInboxRouteCapability = createInboxRouteCapability
        self.revokeInboxRouteCapability = revokeInboxRouteCapability
        self.registerRendezvousTransportV2 = registerRendezvousTransportV2
        self.appendRendezvousTransportV2 = appendRendezvousTransportV2
        self.syncRendezvousTransportV2 = syncRendezvousTransportV2
        self.deleteRendezvousTransportV2 = deleteRendezvousTransportV2
        self.fetch = fetch
        self.registerMailboxConsumer = registerMailboxConsumer
        self.syncMailbox = syncMailbox
        self.commitMailboxCursor = commitMailboxCursor
        self.revokeMailboxConsumer = revokeMailboxConsumer
        self.uploadAttachment = uploadAttachment
        self.fetchAttachment = fetchAttachment
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

    public static func retireInbox(_ request: RetireInboxRequest) -> RelayRequest {
        RelayRequest(type: .retireInbox, retireInbox: request)
    }

    public static func createInboxRouteCapability(
        _ request: CreateInboxRouteCapabilityRequest
    ) -> RelayRequest {
        RelayRequest(
            type: .createInboxRouteCapability,
            createInboxRouteCapability: request
        )
    }

    public static func revokeInboxRouteCapability(
        _ request: RevokeInboxRouteCapabilityRequest
    ) -> RelayRequest {
        RelayRequest(
            type: .revokeInboxRouteCapability,
            revokeInboxRouteCapability: request
        )
    }

    public static func registerRendezvousTransportV2(
        _ request: RegisterRendezvousTransportV2Request
    ) -> RelayRequest {
        RelayRequest(
            type: .registerRendezvousTransportV2,
            registerRendezvousTransportV2: request
        )
    }

    public static func appendRendezvousTransportV2(
        _ request: AppendRendezvousTransportV2Request
    ) -> RelayRequest {
        RelayRequest(
            type: .appendRendezvousTransportV2,
            appendRendezvousTransportV2: request
        )
    }

    public static func syncRendezvousTransportV2(
        _ request: SyncRendezvousTransportV2Request
    ) -> RelayRequest {
        RelayRequest(
            type: .syncRendezvousTransportV2,
            syncRendezvousTransportV2: request
        )
    }

    public static func deleteRendezvousTransportV2(
        _ request: DeleteRendezvousTransportV2Request
    ) -> RelayRequest {
        RelayRequest(
            type: .deleteRendezvousTransportV2,
            deleteRendezvousTransportV2: request
        )
    }

    public static func fetch(_ request: FetchRequest) -> RelayRequest {
        RelayRequest(type: .fetch, fetch: request)
    }

    public static func registerMailboxConsumer(_ request: RegisterMailboxConsumerRequest) -> RelayRequest {
        RelayRequest(type: .registerMailboxConsumer, registerMailboxConsumer: request)
    }

    public static func syncMailbox(_ request: SyncMailboxRequest) -> RelayRequest {
        RelayRequest(type: .syncMailbox, syncMailbox: request)
    }

    public static func commitMailboxCursor(_ request: CommitMailboxCursorRequest) -> RelayRequest {
        RelayRequest(type: .commitMailboxCursor, commitMailboxCursor: request)
    }

    public static func revokeMailboxConsumer(_ request: RevokeMailboxConsumerRequest) -> RelayRequest {
        RelayRequest(type: .revokeMailboxConsumer, revokeMailboxConsumer: request)
    }

    public static func health() -> RelayRequest {
        RelayRequest(type: .health)
    }

    public static func info() -> RelayRequest {
        RelayRequest(type: .info)
    }

    public static func uploadAttachment(_ request: UploadAttachmentRequest) -> RelayRequest {
        RelayRequest(type: .uploadAttachment, uploadAttachment: request)
    }

    public static func fetchAttachment(_ request: FetchAttachmentRequest) -> RelayRequest {
        RelayRequest(type: .fetchAttachment, fetchAttachment: request)
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
            retireInbox: retireInbox,
            createInboxRouteCapability: createInboxRouteCapability,
            revokeInboxRouteCapability: revokeInboxRouteCapability,
            registerRendezvousTransportV2: registerRendezvousTransportV2,
            appendRendezvousTransportV2: appendRendezvousTransportV2,
            syncRendezvousTransportV2: syncRendezvousTransportV2,
            deleteRendezvousTransportV2: deleteRendezvousTransportV2,
            fetch: fetch,
            registerMailboxConsumer: registerMailboxConsumer,
            syncMailbox: syncMailbox,
            commitMailboxCursor: commitMailboxCursor,
            revokeMailboxConsumer: revokeMailboxConsumer,
            uploadAttachment: uploadAttachment,
            fetchAttachment: fetchAttachment,
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
    case mailboxSync
    case mailboxConsumer
    case rendezvousSyncV2
    case attachment
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

/// Relay-local, inbox-generation-scoped authority returned after an
/// authenticated inbox registration. It is not an account or provider ID and
/// is removed with the inbox generation.
public struct InboxRegistrationReceiptV3: Codable, Equatable {
    public let routeMutationScope: Data
    public let nextRouteMutationSequence: UInt64

    public init(
        routeMutationScope: Data,
        nextRouteMutationSequence: UInt64
    ) {
        self.routeMutationScope = routeMutationScope
        self.nextRouteMutationSequence = nextRouteMutationSequence
    }
}

public struct RelayResponse: Codable, Equatable {
    public let type: RelayResponseType
    public let delivered: DeliverResponse?
    public let inboxRegistration: InboxRegistrationReceiptV3?
    public let messages: [Envelope]?
    public let mailboxSync: MailboxSyncBatch?
    public let mailboxConsumer: MailboxConsumerRegistration?
    public let rendezvousSyncV2: RendezvousRelaySyncBatchV2?
    public let attachment: AttachmentChunk?
    public let federationNodes: [FederationNodeRecord]?
    public let federationSnapshot: FederationDirectorySnapshot?
    public let relayInfo: RelayInfo?
    public let openFederationDHTRecords: [OpenFederationDHTRecord]?
    public let error: String?

    public init(
        type: RelayResponseType,
        delivered: DeliverResponse? = nil,
        inboxRegistration: InboxRegistrationReceiptV3? = nil,
        messages: [Envelope]? = nil,
        mailboxSync: MailboxSyncBatch? = nil,
        mailboxConsumer: MailboxConsumerRegistration? = nil,
        rendezvousSyncV2: RendezvousRelaySyncBatchV2? = nil,
        attachment: AttachmentChunk? = nil,
        federationNodes: [FederationNodeRecord]? = nil,
        federationSnapshot: FederationDirectorySnapshot? = nil,
        relayInfo: RelayInfo? = nil,
        openFederationDHTRecords: [OpenFederationDHTRecord]? = nil,
        error: String? = nil
    ) {
        self.type = type
        self.delivered = delivered
        self.inboxRegistration = inboxRegistration
        self.messages = messages
        self.mailboxSync = mailboxSync
        self.mailboxConsumer = mailboxConsumer
        self.rendezvousSyncV2 = rendezvousSyncV2
        self.attachment = attachment
        self.federationNodes = federationNodes
        self.federationSnapshot = federationSnapshot
        self.relayInfo = relayInfo
        self.openFederationDHTRecords = openFederationDHTRecords
        self.error = error
    }

    public static func ok(
        inboxRegistration: InboxRegistrationReceiptV3? = nil
    ) -> RelayResponse {
        RelayResponse(type: .ok, inboxRegistration: inboxRegistration)
    }

    public static func delivered(count: Int) -> RelayResponse {
        RelayResponse(type: .delivered, delivered: DeliverResponse(storedCount: count))
    }

    public static func messages(_ envelopes: [Envelope]) -> RelayResponse {
        RelayResponse(type: .messages, messages: envelopes)
    }

    public static func mailboxSync(_ batch: MailboxSyncBatch) -> RelayResponse {
        RelayResponse(type: .mailboxSync, mailboxSync: batch)
    }

    public static func mailboxConsumer(_ consumer: MailboxConsumerRegistration) -> RelayResponse {
        RelayResponse(type: .mailboxConsumer, mailboxConsumer: consumer)
    }

    public static func rendezvousSyncV2(_ batch: RendezvousRelaySyncBatchV2) -> RelayResponse {
        RelayResponse(type: .rendezvousSyncV2, rendezvousSyncV2: batch)
    }

    public static func attachment(_ chunk: AttachmentChunk) -> RelayResponse {
        RelayResponse(type: .attachment, attachment: chunk)
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
