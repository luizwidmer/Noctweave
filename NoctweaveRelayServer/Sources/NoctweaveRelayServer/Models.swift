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
    case manual
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
    case replicatedXorPIR
}

struct HiddenRetrievalPIRReplica: Codable, Equatable {
    let replicaId: String
    let operatorId: String
    let endpoint: RelayEndpoint

    init(replicaId: String, operatorId: String, endpoint: RelayEndpoint) {
        self.replicaId = replicaId.trimmingCharacters(in: .whitespacesAndNewlines)
        self.operatorId = operatorId.trimmingCharacters(in: .whitespacesAndNewlines)
        self.endpoint = endpoint
    }
}

struct HiddenRetrievalSupport: Codable, Equatable {
    let mode: HiddenRetrievalMode
    let defaultCoverSetSize: Int
    let maxCoverSetSize: Int
    let replicatedXorPIRReplicas: [HiddenRetrievalPIRReplica]?

    init(
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

struct OpenFederationDiscoverySupport: Codable, Equatable {
    let dhtNodeEnabled: Bool
    let peerExchangeEnabled: Bool
    let peerExchangeLimit: Int
    let requirePublicEndpoint: Bool
    let maxDHTRecords: Int
    let maxDHTRecordsPerHost: Int
    let maxDHTQueryRecords: Int

    init(
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

enum HiddenRetrievalPIRReplicaSetIssue: String, Codable, Equatable, Hashable {
    case hiddenRetrievalUnavailable
    case unsupportedMode
    case insufficientReplicas
    case blankReplicaId
    case blankOperatorId
    case duplicateReplicaId
    case duplicateOperatorId
    case duplicateHost
    case duplicateEndpoint
    case insecureEndpoint
}

enum HiddenRetrievalPIRReplicaSetValidator {
    static func issues(
        for support: HiddenRetrievalSupport?,
        minimumReplicaCount: Int = 2,
        requireTLS: Bool = true
    ) -> [HiddenRetrievalPIRReplicaSetIssue] {
        guard let support else {
            return [.hiddenRetrievalUnavailable]
        }
        guard support.mode == .replicatedXorPIR else {
            return [.unsupportedMode]
        }

        let replicas = support.replicatedXorPIRReplicas ?? []
        var issues: [HiddenRetrievalPIRReplicaSetIssue] = []
        if replicas.count < max(2, minimumReplicaCount) {
            issues.append(.insufficientReplicas)
        }

        let replicaIds = replicas.map { $0.replicaId.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        let operatorIds = replicas.map { $0.operatorId.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        let hosts = replicas.map { $0.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        let endpoints = replicas.map { normalizedEndpointKey($0.endpoint) }

        if replicaIds.contains(where: \.isEmpty) {
            issues.append(.blankReplicaId)
        }
        if operatorIds.contains(where: \.isEmpty) {
            issues.append(.blankOperatorId)
        }
        if Set(replicaIds).count != replicaIds.count {
            issues.append(.duplicateReplicaId)
        }
        if Set(operatorIds).count != operatorIds.count {
            issues.append(.duplicateOperatorId)
        }
        if Set(hosts).count != hosts.count {
            issues.append(.duplicateHost)
        }
        if Set(endpoints).count != endpoints.count {
            issues.append(.duplicateEndpoint)
        }
        if requireTLS, replicas.contains(where: { !$0.endpoint.useTLS }) {
            issues.append(.insecureEndpoint)
        }

        return Array(Set(issues)).sorted { $0.rawValue < $1.rawValue }
    }

    static func isUsable(
        _ support: HiddenRetrievalSupport?,
        minimumReplicaCount: Int = 2,
        requireTLS: Bool = true
    ) -> Bool {
        issues(
            for: support,
            minimumReplicaCount: minimumReplicaCount,
            requireTLS: requireTLS
        ).isEmpty
    }

    private static func normalizedEndpointKey(_ endpoint: RelayEndpoint) -> String {
        [
            endpoint.transport.rawValue,
            endpoint.useTLS ? "tls" : "plain",
            endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
            String(endpoint.port)
        ].joined(separator: "://")
    }
}

struct OnionTransportSupport: Codable, Equatable {
    let enabled: Bool
    let maxHops: Int
    let requiresFixedSizePackets: Bool

    init(enabled: Bool = true, maxHops: Int = 3, requiresFixedSizePackets: Bool = true) {
        self.enabled = enabled
        self.maxHops = min(max(1, maxHops), 8)
        self.requiresFixedSizePackets = requiresFixedSizePackets
    }
}

enum OnionTransportPolicyIssue: String, Codable, Equatable, CaseIterable {
    case notAdvertised
    case disabled
    case insufficientHops
}

enum OnionTransportPolicyValidator {
    static func issues(
        for support: OnionTransportSupport?,
        minimumHops: Int = 2
    ) -> [OnionTransportPolicyIssue] {
        guard let support else {
            return [.notAdvertised]
        }

        var issues: [OnionTransportPolicyIssue] = []
        if !support.enabled {
            issues.append(.disabled)
        }
        if support.maxHops < max(2, minimumHops) {
            issues.append(.insufficientHops)
        }
        return issues
    }

    static func isUsable(
        _ support: OnionTransportSupport?,
        minimumHops: Int = 2
    ) -> Bool {
        issues(for: support, minimumHops: minimumHops).isEmpty
    }
}

struct MixnetTransportSupport: Codable, Equatable {
    let enabled: Bool
    let batchIntervalSeconds: Int
    let minBatchSize: Int
    let coverPacketsPerBatch: Int
    let maxDelaySeconds: Int

    init(
        enabled: Bool = true,
        batchIntervalSeconds: Int = 30,
        minBatchSize: Int = 8,
        coverPacketsPerBatch: Int = 2,
        maxDelaySeconds: Int = 120
    ) {
        self.enabled = enabled
        self.batchIntervalSeconds = min(max(5, batchIntervalSeconds), 3_600)
        self.minBatchSize = min(max(1, minBatchSize), 256)
        self.coverPacketsPerBatch = min(max(0, coverPacketsPerBatch), 256)
        self.maxDelaySeconds = min(max(0, maxDelaySeconds), 3_600)
    }
}

enum MixnetRoutePolicyIssue: String, Codable, Equatable, CaseIterable {
    case notAdvertised
    case disabled
    case missingOnionTransport
    case onionTransportDisabled
    case insufficientOnionHops
    case fixedSizePacketsNotRequired
    case insufficientBatchSize
    case coverTrafficDisabled
    case batchIntervalTooShort
    case releaseDelayDisabled
}

enum MixnetRoutePolicyValidator {
    static func issues(
        for mixnetSupport: MixnetTransportSupport?,
        onionSupport: OnionTransportSupport?,
        minimumBatchSize: Int = 4,
        minimumCoverPackets: Int = 1,
        minimumOnionHops: Int = 2,
        minimumBatchIntervalSeconds: Int = 10
    ) -> [MixnetRoutePolicyIssue] {
        guard let mixnetSupport else {
            return [.notAdvertised]
        }

        var issues: [MixnetRoutePolicyIssue] = []
        if !mixnetSupport.enabled {
            issues.append(.disabled)
        }
        if mixnetSupport.minBatchSize < max(2, minimumBatchSize) {
            issues.append(.insufficientBatchSize)
        }
        if mixnetSupport.coverPacketsPerBatch < max(1, minimumCoverPackets) {
            issues.append(.coverTrafficDisabled)
        }
        if mixnetSupport.batchIntervalSeconds < max(5, minimumBatchIntervalSeconds) {
            issues.append(.batchIntervalTooShort)
        }
        if mixnetSupport.maxDelaySeconds <= 0 {
            issues.append(.releaseDelayDisabled)
        }

        guard let onionSupport else {
            issues.append(.missingOnionTransport)
            return issues
        }
        if !onionSupport.enabled {
            issues.append(.onionTransportDisabled)
        }
        if onionSupport.maxHops < max(2, minimumOnionHops) {
            issues.append(.insufficientOnionHops)
        }
        if !onionSupport.requiresFixedSizePackets {
            issues.append(.fixedSizePacketsNotRequired)
        }
        return issues
    }

    static func isUsable(
        mixnetSupport: MixnetTransportSupport?,
        onionSupport: OnionTransportSupport?,
        minimumBatchSize: Int = 4,
        minimumCoverPackets: Int = 1,
        minimumOnionHops: Int = 2,
        minimumBatchIntervalSeconds: Int = 10
    ) -> Bool {
        issues(
            for: mixnetSupport,
            onionSupport: onionSupport,
            minimumBatchSize: minimumBatchSize,
            minimumCoverPackets: minimumCoverPackets,
            minimumOnionHops: minimumOnionHops,
            minimumBatchIntervalSeconds: minimumBatchIntervalSeconds
        ).isEmpty
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
    let attachmentStorageBackend: String?
    let hiddenRetrieval: HiddenRetrievalSupport?
    let onionTransport: OnionTransportSupport?
    let mixnetTransport: MixnetTransportSupport?
    let wakeSupport: DecentralizedWakeSupport?
    let relayName: String?
    let operatorNote: String?
    let softwareVersion: String?
    let protocolCapabilities: RelayCapabilityManifestV2?
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
    let openFederationDiscovery: OpenFederationDiscoverySupport?
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
        attachmentStorageBackend: String? = nil,
        hiddenRetrieval: HiddenRetrievalSupport? = nil,
        onionTransport: OnionTransportSupport? = nil,
        mixnetTransport: MixnetTransportSupport? = nil,
        wakeSupport: DecentralizedWakeSupport? = nil,
        relayName: String? = nil,
        operatorNote: String? = nil,
        softwareVersion: String? = nil,
        protocolCapabilities: RelayCapabilityManifestV2? = nil,
        groupCreationMode: GroupCreationMode = .allowed,
        groupSecurityModel: GroupSecurityModel = .mlsDerivedTree,
        requiresPassword: Bool? = nil,
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
        self.tlsEnabled = tlsEnabled
        self.transport = transport
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
    var attachmentStorageBackend: String?
    var hiddenRetrieval: HiddenRetrievalSupport?
    var onionTransport: OnionTransportSupport?
    var mixnetTransport: MixnetTransportSupport?
    var wakeSupport: DecentralizedWakeSupport?
    var relayName: String?
    var operatorNote: String?
    var softwareVersion: String?
    var groupCreationMode: GroupCreationMode
    var groupSecurityModel: GroupSecurityModel
    var accessPassword: String?
    var coordinatorRegistrationToken: String?
    var federationCoordinatorEndpoints: [RelayEndpoint]?
    var coordinatorHeartbeatSeconds: Int?
    var coordinatorDirectoryMaxStalenessSeconds: Int?
    var relayPeerExchangeLimit: Int?
    var openFederationDHTEnabled: Bool
    var openFederationDHTMaxRecords: Int
    var openFederationDHTMaxRecordsPerHost: Int
    var openFederationDHTMaxQueryRecords: Int
    var coordinatorDirectorySigningPrivateKey: Data?
    var curatedStrictPolicyEnabled: Bool
    var curatedCoordinatorQuorum: Int
    var curatedRequireSignedDirectory: Bool
    var advertisedEndpoint: RelayEndpoint?
    var federationAllowList: [RelayEndpoint]
    var allowPrivateFederationEndpoints: Bool
    var opaqueRouteRuntimeEnabled: Bool
    var rendezvousTransportEnabled: Bool

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
        opaqueRouteRuntimeEnabled: Bool = true,
        rendezvousTransportEnabled: Bool = false
    ) {
        self.kind = kind
        self.federation = federation
        self.tlsEnabled = tlsEnabled
        self.transport = transport
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
        self.opaqueRouteRuntimeEnabled = opaqueRouteRuntimeEnabled
        self.rendezvousTransportEnabled = rendezvousTransportEnabled
    }

    var isOpaqueRouteRuntimeEnabled: Bool {
        opaqueRouteRuntimeEnabled
    }

    var isRendezvousTransportEnabled: Bool {
        rendezvousTransportEnabled
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
                opaqueRouteRuntimeEnabled: isOpaqueRouteRuntimeEnabled,
                rendezvousTransportEnabled: isRendezvousTransportEnabled
            ),
            groupCreationMode: .disabled,
            groupSecurityModel: groupSecurityModel,
            requiresPassword: requiresPassword,
            federationCoordinatorEndpoints: federationCoordinatorEndpoints,
            coordinatorRegistrationAuthRequired: kind == .coordinator ? requiresCoordinatorRegistrationAuth : nil,
            curatedStrictPolicyEnabled: curatedMode ? curatedStrictPolicyEnabled : nil,
            curatedCoordinatorQuorum: curatedMode ? curatedCoordinatorQuorum : nil,
            curatedRequireSignedDirectory: curatedMode ? curatedRequireSignedDirectory : nil,
            openFederationDiscovery: advertisedOpenFederationDiscovery,
            advertisedAt: now
        )
    }

    var advertisedOpenFederationDiscovery: OpenFederationDiscoverySupport? {
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


struct EncryptedPayload: Codable, Equatable {
    let nonce: Data
    let ciphertext: Data
    let tag: Data
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


enum RendezvousRelayTransportV2 {
    static let version = 2
    static let capabilityBytes = 32
    static let laneIDBytes = 32
    static let frameIDBytes = 16
    static let laneCount = 2
    static let maximumLifetimeSeconds: TimeInterval = 10 * 60
    static let maximumFramesPerLane: UInt64 = 32
    static let maximumCiphertextBytesPerLane = 2_097_152
    static let maximumSyncFrames = 32
    static let allowedCiphertextByteCounts = [4_096, 16_384, 65_536]

    static func isCanonicalTimestamp(_ date: Date) -> Bool {
        let seconds = date.timeIntervalSince1970
        return seconds.isFinite && floor(seconds) == seconds
    }

    static func isValidOpaqueValue(_ value: Data, byteCount: Int) -> Bool {
        value.count == byteCount && value.contains { $0 != 0 }
    }
}

struct RendezvousRelayRouteCapabilityV2: RawRepresentable, Codable, Equatable, Hashable {
    let rawValue: Data

    init(rawValue: Data) { self.rawValue = rawValue }

    var isStructurallyValid: Bool {
        RendezvousRelayTransportV2.isValidOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes
        )
    }
}

struct RendezvousRelayPublishCapabilityV2: RawRepresentable, Codable, Equatable, Hashable {
    let rawValue: Data

    init(rawValue: Data) { self.rawValue = rawValue }

    var isStructurallyValid: Bool {
        RendezvousRelayTransportV2.isValidOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes
        )
    }
}

struct RendezvousRelayReadCapabilityV2: RawRepresentable, Codable, Equatable, Hashable {
    let rawValue: Data

    init(rawValue: Data) { self.rawValue = rawValue }

    var isStructurallyValid: Bool {
        RendezvousRelayTransportV2.isValidOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes
        )
    }
}

struct RendezvousRelayDeleteCapabilityV2: RawRepresentable, Codable, Equatable, Hashable {
    let rawValue: Data

    init(rawValue: Data) { self.rawValue = rawValue }

    var isStructurallyValid: Bool {
        RendezvousRelayTransportV2.isValidOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes
        )
    }
}

struct RendezvousRelayLaneIDV2: RawRepresentable, Codable, Equatable, Hashable {
    let rawValue: Data

    init(rawValue: Data) { self.rawValue = rawValue }

    var isStructurallyValid: Bool {
        RendezvousRelayTransportV2.isValidOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.laneIDBytes
        )
    }
}

struct RendezvousRelayFrameIDV2: RawRepresentable, Codable, Equatable, Hashable {
    let rawValue: Data

    init(rawValue: Data) { self.rawValue = rawValue }

    var isStructurallyValid: Bool {
        RendezvousRelayTransportV2.isValidOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.frameIDBytes
        )
    }
}

struct RendezvousRelayLaneRegistrationV2: Codable, Equatable {
    let laneId: RendezvousRelayLaneIDV2
    let publishCapability: RendezvousRelayPublishCapabilityV2
    let readCapability: RendezvousRelayReadCapabilityV2
    let deleteCapability: RendezvousRelayDeleteCapabilityV2

    init(
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

    var isStructurallyValid: Bool {
        laneId.isStructurallyValid
            && publishCapability.isStructurallyValid
            && readCapability.isStructurallyValid
            && deleteCapability.isStructurallyValid
    }
}

struct RegisterRendezvousTransportV2Request: Codable, Equatable {
    let version: Int
    let routeCapability: RendezvousRelayRouteCapabilityV2
    let expiresAt: Date
    let lanes: [RendezvousRelayLaneRegistrationV2]

    init(
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

    func isStructurallyValid(at now: Date = Date()) -> Bool {
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

struct RendezvousRelayCiphertextFrameV2: Codable, Equatable {
    let frameId: RendezvousRelayFrameIDV2
    let sequence: UInt64
    let ciphertext: Data

    init(
        frameId: RendezvousRelayFrameIDV2,
        sequence: UInt64,
        ciphertext: Data
    ) {
        self.frameId = frameId
        self.sequence = sequence
        self.ciphertext = ciphertext
    }

    var isStructurallyValid: Bool {
        frameId.isStructurallyValid
            && sequence > 0
            && sequence <= RendezvousRelayTransportV2.maximumFramesPerLane
            && RendezvousRelayTransportV2.allowedCiphertextByteCounts.contains(ciphertext.count)
    }

    var ciphertextDigest: Data {
        Data(SHA256.hash(data: ciphertext))
    }
}

struct AppendRendezvousTransportV2Request: Codable, Equatable {
    let routeCapability: RendezvousRelayRouteCapabilityV2
    let laneId: RendezvousRelayLaneIDV2
    let publishCapability: RendezvousRelayPublishCapabilityV2
    let frame: RendezvousRelayCiphertextFrameV2

    init(
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

    var isStructurallyValid: Bool {
        routeCapability.isStructurallyValid
            && laneId.isStructurallyValid
            && publishCapability.isStructurallyValid
            && frame.isStructurallyValid
    }
}

struct SyncRendezvousTransportV2Request: Codable, Equatable {
    let routeCapability: RendezvousRelayRouteCapabilityV2
    let laneId: RendezvousRelayLaneIDV2
    let readCapability: RendezvousRelayReadCapabilityV2
    let afterSequence: UInt64
    let maxCount: Int?

    init(
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

    var isStructurallyValid: Bool {
        routeCapability.isStructurallyValid
            && laneId.isStructurallyValid
            && readCapability.isStructurallyValid
            && afterSequence <= RendezvousRelayTransportV2.maximumFramesPerLane
            && maxCount.map { (1...RendezvousRelayTransportV2.maximumSyncFrames).contains($0) } ?? true
    }
}

struct DeleteRendezvousTransportV2Request: Codable, Equatable {
    let routeCapability: RendezvousRelayRouteCapabilityV2
    let laneId: RendezvousRelayLaneIDV2
    let deleteCapability: RendezvousRelayDeleteCapabilityV2

    init(
        routeCapability: RendezvousRelayRouteCapabilityV2,
        laneId: RendezvousRelayLaneIDV2,
        deleteCapability: RendezvousRelayDeleteCapabilityV2
    ) {
        self.routeCapability = routeCapability
        self.laneId = laneId
        self.deleteCapability = deleteCapability
    }

    var isStructurallyValid: Bool {
        routeCapability.isStructurallyValid
            && laneId.isStructurallyValid
            && deleteCapability.isStructurallyValid
    }
}

struct RendezvousRelaySyncBatchV2: Codable, Equatable {
    let frames: [RendezvousRelayCiphertextFrameV2]
    let highWatermark: UInt64
    let nextSequence: UInt64
    let hasMore: Bool

    init(
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

enum RelayRequestType: String, Codable {
    case createOpaqueRouteV2
    case renewOpaqueRouteV2
    case teardownOpaqueRouteV2
    case appendOpaqueRouteV2
    case syncOpaqueRouteV2
    case commitOpaqueRouteV2
    case registerRendezvousTransportV2
    case appendRendezvousTransportV2
    case syncRendezvousTransportV2
    case deleteRendezvousTransportV2
    case health
    case info
    case uploadAttachment
    case fetchAttachment
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
    let createOpaqueRouteV2: OpaqueRouteCreateSubmissionV2?
    let renewOpaqueRouteV2: OpaqueRouteRenewSubmissionV2?
    let teardownOpaqueRouteV2: OpaqueRouteTeardownSubmissionV2?
    let appendOpaqueRouteV2: OpaqueRouteAppendSubmissionV2?
    let syncOpaqueRouteV2: OpaqueRouteSyncSubmissionV2?
    let commitOpaqueRouteV2: OpaqueRouteCommitSubmissionV2?
    let registerRendezvousTransportV2: RegisterRendezvousTransportV2Request?
    let appendRendezvousTransportV2: AppendRendezvousTransportV2Request?
    let syncRendezvousTransportV2: SyncRendezvousTransportV2Request?
    let deleteRendezvousTransportV2: DeleteRendezvousTransportV2Request?
    let uploadAttachment: UploadAttachmentRequest?
    let fetchAttachment: FetchAttachmentRequest?
    let registerFederationNode: FederationNodeRegistrationRequest?
    let listFederationNodes: ListFederationNodesRequest?
    let publishOpenFederationDHTRecord: PublishOpenFederationDHTRecordRequest?
    let listOpenFederationDHTRecords: ListOpenFederationDHTRecordsRequest?

    init(
        type: RelayRequestType,
        authToken: String? = nil,
        createOpaqueRouteV2: OpaqueRouteCreateSubmissionV2? = nil,
        renewOpaqueRouteV2: OpaqueRouteRenewSubmissionV2? = nil,
        teardownOpaqueRouteV2: OpaqueRouteTeardownSubmissionV2? = nil,
        appendOpaqueRouteV2: OpaqueRouteAppendSubmissionV2? = nil,
        syncOpaqueRouteV2: OpaqueRouteSyncSubmissionV2? = nil,
        commitOpaqueRouteV2: OpaqueRouteCommitSubmissionV2? = nil,
        registerRendezvousTransportV2: RegisterRendezvousTransportV2Request? = nil,
        appendRendezvousTransportV2: AppendRendezvousTransportV2Request? = nil,
        syncRendezvousTransportV2: SyncRendezvousTransportV2Request? = nil,
        deleteRendezvousTransportV2: DeleteRendezvousTransportV2Request? = nil,
        uploadAttachment: UploadAttachmentRequest? = nil,
        fetchAttachment: FetchAttachmentRequest? = nil,
        registerFederationNode: FederationNodeRegistrationRequest? = nil,
        listFederationNodes: ListFederationNodesRequest? = nil,
        publishOpenFederationDHTRecord: PublishOpenFederationDHTRecordRequest? = nil,
        listOpenFederationDHTRecords: ListOpenFederationDHTRecordsRequest? = nil
    ) {
        self.type = type
        self.authToken = authToken
        self.createOpaqueRouteV2 = createOpaqueRouteV2
        self.renewOpaqueRouteV2 = renewOpaqueRouteV2
        self.teardownOpaqueRouteV2 = teardownOpaqueRouteV2
        self.appendOpaqueRouteV2 = appendOpaqueRouteV2
        self.syncOpaqueRouteV2 = syncOpaqueRouteV2
        self.commitOpaqueRouteV2 = commitOpaqueRouteV2
        self.registerRendezvousTransportV2 = registerRendezvousTransportV2
        self.appendRendezvousTransportV2 = appendRendezvousTransportV2
        self.syncRendezvousTransportV2 = syncRendezvousTransportV2
        self.deleteRendezvousTransportV2 = deleteRendezvousTransportV2
        self.uploadAttachment = uploadAttachment
        self.fetchAttachment = fetchAttachment
        self.registerFederationNode = registerFederationNode
        self.listFederationNodes = listFederationNodes
        self.publishOpenFederationDHTRecord = publishOpenFederationDHTRecord
        self.listOpenFederationDHTRecords = listOpenFederationDHTRecords
    }

    static func createOpaqueRouteV2(_ submission: OpaqueRouteCreateSubmissionV2) -> RelayRequest {
        RelayRequest(type: .createOpaqueRouteV2, createOpaqueRouteV2: submission)
    }

    static func renewOpaqueRouteV2(_ submission: OpaqueRouteRenewSubmissionV2) -> RelayRequest {
        RelayRequest(type: .renewOpaqueRouteV2, renewOpaqueRouteV2: submission)
    }

    static func teardownOpaqueRouteV2(_ submission: OpaqueRouteTeardownSubmissionV2) -> RelayRequest {
        RelayRequest(type: .teardownOpaqueRouteV2, teardownOpaqueRouteV2: submission)
    }

    static func appendOpaqueRouteV2(_ submission: OpaqueRouteAppendSubmissionV2) -> RelayRequest {
        RelayRequest(type: .appendOpaqueRouteV2, appendOpaqueRouteV2: submission)
    }

    static func syncOpaqueRouteV2(_ submission: OpaqueRouteSyncSubmissionV2) -> RelayRequest {
        RelayRequest(type: .syncOpaqueRouteV2, syncOpaqueRouteV2: submission)
    }

    static func commitOpaqueRouteV2(_ submission: OpaqueRouteCommitSubmissionV2) -> RelayRequest {
        RelayRequest(type: .commitOpaqueRouteV2, commitOpaqueRouteV2: submission)
    }

    static func registerRendezvousTransportV2(
        _ request: RegisterRendezvousTransportV2Request
    ) -> RelayRequest {
        RelayRequest(
            type: .registerRendezvousTransportV2,
            registerRendezvousTransportV2: request
        )
    }

    static func appendRendezvousTransportV2(
        _ request: AppendRendezvousTransportV2Request
    ) -> RelayRequest {
        RelayRequest(
            type: .appendRendezvousTransportV2,
            appendRendezvousTransportV2: request
        )
    }

    static func syncRendezvousTransportV2(
        _ request: SyncRendezvousTransportV2Request
    ) -> RelayRequest {
        RelayRequest(
            type: .syncRendezvousTransportV2,
            syncRendezvousTransportV2: request
        )
    }

    static func deleteRendezvousTransportV2(
        _ request: DeleteRendezvousTransportV2Request
    ) -> RelayRequest {
        RelayRequest(
            type: .deleteRendezvousTransportV2,
            deleteRendezvousTransportV2: request
        )
    }

    static func health() -> RelayRequest {
        RelayRequest(type: .health)
    }

    static func info() -> RelayRequest {
        RelayRequest(type: .info)
    }

    static func uploadAttachment(_ request: UploadAttachmentRequest) -> RelayRequest {
        RelayRequest(type: .uploadAttachment, uploadAttachment: request)
    }

    static func fetchAttachment(_ request: FetchAttachmentRequest) -> RelayRequest {
        RelayRequest(type: .fetchAttachment, fetchAttachment: request)
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
            createOpaqueRouteV2: createOpaqueRouteV2,
            renewOpaqueRouteV2: renewOpaqueRouteV2,
            teardownOpaqueRouteV2: teardownOpaqueRouteV2,
            appendOpaqueRouteV2: appendOpaqueRouteV2,
            syncOpaqueRouteV2: syncOpaqueRouteV2,
            commitOpaqueRouteV2: commitOpaqueRouteV2,
            registerRendezvousTransportV2: registerRendezvousTransportV2,
            appendRendezvousTransportV2: appendRendezvousTransportV2,
            syncRendezvousTransportV2: syncRendezvousTransportV2,
            deleteRendezvousTransportV2: deleteRendezvousTransportV2,
            uploadAttachment: uploadAttachment,
            fetchAttachment: fetchAttachment,
            registerFederationNode: registerFederationNode,
            listFederationNodes: listFederationNodes,
            publishOpenFederationDHTRecord: publishOpenFederationDHTRecord,
            listOpenFederationDHTRecords: listOpenFederationDHTRecords
        )
    }
}



enum RelayResponseType: String, Codable {
    case ok
    case rendezvousSyncV2
    case opaqueRouteV2
    case opaqueRouteAppendV2
    case opaqueRouteSyncV2
    case opaqueRouteCommitV2
    case attachment
    case info
    case federationNodes
    case openFederationDHTRecords
    case error
}

struct RelayResponse: Codable, Equatable {
    let type: RelayResponseType
    let rendezvousSyncV2: RendezvousRelaySyncBatchV2?
    let opaqueRouteV2: OpaqueReceiveRouteV2?
    let opaqueRouteAppendV2: OpaqueRouteAppendReceiptV2?
    let opaqueRouteSyncV2: OpaqueRouteSyncResponseV2?
    let opaqueRouteCommitV2: OpaqueRouteCommitResponseV2?
    let attachment: AttachmentChunk?
    let relayInfo: RelayInfo?
    let federationNodes: [FederationNodeRecord]?
    let federationSnapshot: FederationDirectorySnapshot?
    let openFederationDHTRecords: [OpenFederationDHTRecord]?
    let error: String?

    init(
        type: RelayResponseType,
        rendezvousSyncV2: RendezvousRelaySyncBatchV2? = nil,
        opaqueRouteV2: OpaqueReceiveRouteV2? = nil,
        opaqueRouteAppendV2: OpaqueRouteAppendReceiptV2? = nil,
        opaqueRouteSyncV2: OpaqueRouteSyncResponseV2? = nil,
        opaqueRouteCommitV2: OpaqueRouteCommitResponseV2? = nil,
        attachment: AttachmentChunk? = nil,
        relayInfo: RelayInfo? = nil,
        federationNodes: [FederationNodeRecord]? = nil,
        federationSnapshot: FederationDirectorySnapshot? = nil,
        openFederationDHTRecords: [OpenFederationDHTRecord]? = nil,
        error: String? = nil
    ) {
        self.type = type
        self.rendezvousSyncV2 = rendezvousSyncV2
        self.opaqueRouteV2 = opaqueRouteV2
        self.opaqueRouteAppendV2 = opaqueRouteAppendV2
        self.opaqueRouteSyncV2 = opaqueRouteSyncV2
        self.opaqueRouteCommitV2 = opaqueRouteCommitV2
        self.attachment = attachment
        self.relayInfo = relayInfo
        self.federationNodes = federationNodes
        self.federationSnapshot = federationSnapshot
        self.openFederationDHTRecords = openFederationDHTRecords
        self.error = error
    }

    static func ok() -> RelayResponse {
        RelayResponse(type: .ok)
    }

    static func rendezvousSyncV2(_ batch: RendezvousRelaySyncBatchV2) -> RelayResponse {
        RelayResponse(type: .rendezvousSyncV2, rendezvousSyncV2: batch)
    }

    static func opaqueRouteV2(_ route: OpaqueReceiveRouteV2) -> RelayResponse {
        RelayResponse(type: .opaqueRouteV2, opaqueRouteV2: route)
    }

    static func opaqueRouteAppendV2(_ receipt: OpaqueRouteAppendReceiptV2) -> RelayResponse {
        RelayResponse(type: .opaqueRouteAppendV2, opaqueRouteAppendV2: receipt)
    }

    static func opaqueRouteSyncV2(_ response: OpaqueRouteSyncResponseV2) -> RelayResponse {
        RelayResponse(type: .opaqueRouteSyncV2, opaqueRouteSyncV2: response)
    }

    static func opaqueRouteCommitV2(_ response: OpaqueRouteCommitResponseV2) -> RelayResponse {
        RelayResponse(type: .opaqueRouteCommitV2, opaqueRouteCommitV2: response)
    }

    static func attachment(_ chunk: AttachmentChunk) -> RelayResponse {
        RelayResponse(type: .attachment, attachment: chunk)
    }

    static func info(_ info: RelayInfo) -> RelayResponse {
        RelayResponse(type: .info, relayInfo: info)
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
        RelayResponse(type: .error, error: message)
    }
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
