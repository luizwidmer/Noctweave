import Foundation
import Crypto

enum RelayKind: String, Codable, CaseIterable {
    case standard
    case discovery
    case bridge
    case privateRelay
    case coordinator
}

enum FederationMode: String, Codable, CaseIterable {
    case solo
    case manual
    case curated
    case open
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
    let relayName: String?
    let operatorNote: String?
    let softwareVersion: String?
    let protocolCapabilities: RelayCapabilityManifestV2?
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
        relayName: String? = nil,
        operatorNote: String? = nil,
        softwareVersion: String? = nil,
        protocolCapabilities: RelayCapabilityManifestV2? = nil,
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
        self.relayName = relayName
        self.operatorNote = operatorNote
        self.softwareVersion = softwareVersion
        self.protocolCapabilities = protocolCapabilities?.isStructurallyValid == true
            ? protocolCapabilities
            : nil
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
    var relayName: String?
    var operatorNote: String?
    var softwareVersion: String?
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
        relayName: String? = nil,
        operatorNote: String? = nil,
        softwareVersion: String? = nil,
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
        self.relayName = relayName
        self.operatorNote = operatorNote
        self.softwareVersion = softwareVersion
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
            relayName: relayName,
            operatorNote: operatorNote,
            softwareVersion: softwareVersion,
            protocolCapabilities: .advertised(
                attachmentsEnabled: attachmentsEnabled != false,
                hiddenRetrievalEnabled: advertisedHiddenRetrieval != nil,
                onionEnabled: advertisedOnionTransport != nil,
                mixnetEnabled: advertisedMixnetTransport != nil,
                opaqueRouteRuntimeEnabled: isOpaqueRouteRuntimeEnabled,
                openDiscoveryEnabled: advertisedOpenFederationDiscovery?.dhtNodeEnabled == true,
                rendezvousTransportEnabled: isRendezvousTransportEnabled
            ),
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
    static let allowedCiphertextByteCounts = [4_096, 16_384, 65_536, 131_072]

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

    init(from decoder: Decoder) throws {
        rawValue = try rendezvousRelayDecodeOpaqueRawValue(
            from: decoder,
            byteCount: RendezvousRelayTransportV2.capabilityBytes,
            description: "Invalid rendezvous route capability"
        )
    }

    func encode(to encoder: Encoder) throws {
        try rendezvousRelayEncodeOpaqueRawValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes,
            description: "Invalid rendezvous route capability",
            to: encoder
        )
    }

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

    init(from decoder: Decoder) throws {
        rawValue = try rendezvousRelayDecodeOpaqueRawValue(
            from: decoder,
            byteCount: RendezvousRelayTransportV2.capabilityBytes,
            description: "Invalid rendezvous publish capability"
        )
    }

    func encode(to encoder: Encoder) throws {
        try rendezvousRelayEncodeOpaqueRawValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes,
            description: "Invalid rendezvous publish capability",
            to: encoder
        )
    }

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

    init(from decoder: Decoder) throws {
        rawValue = try rendezvousRelayDecodeOpaqueRawValue(
            from: decoder,
            byteCount: RendezvousRelayTransportV2.capabilityBytes,
            description: "Invalid rendezvous read capability"
        )
    }

    func encode(to encoder: Encoder) throws {
        try rendezvousRelayEncodeOpaqueRawValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes,
            description: "Invalid rendezvous read capability",
            to: encoder
        )
    }

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

    init(from decoder: Decoder) throws {
        rawValue = try rendezvousRelayDecodeOpaqueRawValue(
            from: decoder,
            byteCount: RendezvousRelayTransportV2.capabilityBytes,
            description: "Invalid rendezvous delete capability"
        )
    }

    func encode(to encoder: Encoder) throws {
        try rendezvousRelayEncodeOpaqueRawValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes,
            description: "Invalid rendezvous delete capability",
            to: encoder
        )
    }

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

    init(from decoder: Decoder) throws {
        rawValue = try rendezvousRelayDecodeOpaqueRawValue(
            from: decoder,
            byteCount: RendezvousRelayTransportV2.laneIDBytes,
            description: "Invalid rendezvous lane identifier"
        )
    }

    func encode(to encoder: Encoder) throws {
        try rendezvousRelayEncodeOpaqueRawValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.laneIDBytes,
            description: "Invalid rendezvous lane identifier",
            to: encoder
        )
    }

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

    init(from decoder: Decoder) throws {
        rawValue = try rendezvousRelayDecodeOpaqueRawValue(
            from: decoder,
            byteCount: RendezvousRelayTransportV2.frameIDBytes,
            description: "Invalid rendezvous frame identifier"
        )
    }

    func encode(to encoder: Encoder) throws {
        try rendezvousRelayEncodeOpaqueRawValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.frameIDBytes,
            description: "Invalid rendezvous frame identifier",
            to: encoder
        )
    }

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

    private enum CodingKeys: String, CodingKey {
        case laneId
        case publishCapability
        case readCapability
        case deleteCapability
    }

    init(from decoder: Decoder) throws {
        try rendezvousRelayRequireExactObject(
            decoder,
            keys: ["laneId", "publishCapability", "readCapability", "deleteCapability"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        laneId = try container.decode(RendezvousRelayLaneIDV2.self, forKey: .laneId)
        publishCapability = try container.decode(
            RendezvousRelayPublishCapabilityV2.self,
            forKey: .publishCapability
        )
        readCapability = try container.decode(
            RendezvousRelayReadCapabilityV2.self,
            forKey: .readCapability
        )
        deleteCapability = try container.decode(
            RendezvousRelayDeleteCapabilityV2.self,
            forKey: .deleteCapability
        )
        guard isStructurallyValid else {
            throw rendezvousRelayDecodingError(decoder, "Invalid rendezvous lane registration")
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw rendezvousRelayEncodingError(
                self,
                encoder,
                "Invalid rendezvous lane registration"
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(laneId, forKey: .laneId)
        try container.encode(publishCapability, forKey: .publishCapability)
        try container.encode(readCapability, forKey: .readCapability)
        try container.encode(deleteCapability, forKey: .deleteCapability)
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

    private var isStaticallyStructurallyValid: Bool {
        guard version == RendezvousRelayTransportV2.version,
              routeCapability.isStructurallyValid,
              RendezvousRelayTransportV2.isCanonicalTimestamp(expiresAt),
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

    func isStructurallyValid(at now: Date = Date()) -> Bool {
        isStaticallyStructurallyValid
            && now.timeIntervalSince1970.isFinite
            && expiresAt > now
            && expiresAt <= Date(
                timeIntervalSince1970: floor(now.timeIntervalSince1970)
                    + RendezvousRelayTransportV2.maximumLifetimeSeconds
            )
    }

    private enum CodingKeys: String, CodingKey {
        case version
        case routeCapability
        case expiresAt
        case lanes
    }

    init(from decoder: Decoder) throws {
        try rendezvousRelayRequireExactObject(
            decoder,
            keys: ["version", "routeCapability", "expiresAt", "lanes"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        routeCapability = try container.decode(
            RendezvousRelayRouteCapabilityV2.self,
            forKey: .routeCapability
        )
        expiresAt = try container.decode(Date.self, forKey: .expiresAt)
        lanes = try container.decode(
            [RendezvousRelayLaneRegistrationV2].self,
            forKey: .lanes
        )
        guard isStaticallyStructurallyValid else {
            throw rendezvousRelayDecodingError(decoder, "Invalid rendezvous registration")
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStaticallyStructurallyValid else {
            throw rendezvousRelayEncodingError(
                self,
                encoder,
                "Invalid rendezvous registration"
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(routeCapability, forKey: .routeCapability)
        try container.encode(expiresAt, forKey: .expiresAt)
        try container.encode(lanes, forKey: .lanes)
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

    private enum CodingKeys: String, CodingKey {
        case frameId
        case sequence
        case ciphertext
    }

    init(from decoder: Decoder) throws {
        try rendezvousRelayRequireExactObject(
            decoder,
            keys: ["frameId", "sequence", "ciphertext"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        frameId = try container.decode(RendezvousRelayFrameIDV2.self, forKey: .frameId)
        sequence = try container.decode(UInt64.self, forKey: .sequence)
        ciphertext = try container.decode(Data.self, forKey: .ciphertext)
        guard isStructurallyValid else {
            throw rendezvousRelayDecodingError(decoder, "Invalid rendezvous ciphertext frame")
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw rendezvousRelayEncodingError(
                self,
                encoder,
                "Invalid rendezvous ciphertext frame"
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(frameId, forKey: .frameId)
        try container.encode(sequence, forKey: .sequence)
        try container.encode(ciphertext, forKey: .ciphertext)
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

    private enum CodingKeys: String, CodingKey {
        case routeCapability
        case laneId
        case publishCapability
        case frame
    }

    init(from decoder: Decoder) throws {
        try rendezvousRelayRequireExactObject(
            decoder,
            keys: ["routeCapability", "laneId", "publishCapability", "frame"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        routeCapability = try container.decode(
            RendezvousRelayRouteCapabilityV2.self,
            forKey: .routeCapability
        )
        laneId = try container.decode(RendezvousRelayLaneIDV2.self, forKey: .laneId)
        publishCapability = try container.decode(
            RendezvousRelayPublishCapabilityV2.self,
            forKey: .publishCapability
        )
        frame = try container.decode(RendezvousRelayCiphertextFrameV2.self, forKey: .frame)
        guard isStructurallyValid else {
            throw rendezvousRelayDecodingError(decoder, "Invalid rendezvous append request")
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw rendezvousRelayEncodingError(
                self,
                encoder,
                "Invalid rendezvous append request"
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(routeCapability, forKey: .routeCapability)
        try container.encode(laneId, forKey: .laneId)
        try container.encode(publishCapability, forKey: .publishCapability)
        try container.encode(frame, forKey: .frame)
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

    private enum CodingKeys: String, CodingKey {
        case routeCapability
        case laneId
        case readCapability
        case afterSequence
        case maxCount
    }

    init(from decoder: Decoder) throws {
        try rendezvousRelayRequireExactObject(
            decoder,
            keys: ["routeCapability", "laneId", "readCapability", "afterSequence", "maxCount"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        routeCapability = try container.decode(
            RendezvousRelayRouteCapabilityV2.self,
            forKey: .routeCapability
        )
        laneId = try container.decode(RendezvousRelayLaneIDV2.self, forKey: .laneId)
        readCapability = try container.decode(
            RendezvousRelayReadCapabilityV2.self,
            forKey: .readCapability
        )
        afterSequence = try container.decode(UInt64.self, forKey: .afterSequence)
        maxCount = try container.decodeIfPresent(Int.self, forKey: .maxCount)
        guard isStructurallyValid else {
            throw rendezvousRelayDecodingError(decoder, "Invalid rendezvous sync request")
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw rendezvousRelayEncodingError(
                self,
                encoder,
                "Invalid rendezvous sync request"
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(routeCapability, forKey: .routeCapability)
        try container.encode(laneId, forKey: .laneId)
        try container.encode(readCapability, forKey: .readCapability)
        try container.encode(afterSequence, forKey: .afterSequence)
        if let maxCount {
            try container.encode(maxCount, forKey: .maxCount)
        } else {
            try container.encodeNil(forKey: .maxCount)
        }
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

    private enum CodingKeys: String, CodingKey {
        case routeCapability
        case laneId
        case deleteCapability
    }

    init(from decoder: Decoder) throws {
        try rendezvousRelayRequireExactObject(
            decoder,
            keys: ["routeCapability", "laneId", "deleteCapability"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        routeCapability = try container.decode(
            RendezvousRelayRouteCapabilityV2.self,
            forKey: .routeCapability
        )
        laneId = try container.decode(RendezvousRelayLaneIDV2.self, forKey: .laneId)
        deleteCapability = try container.decode(
            RendezvousRelayDeleteCapabilityV2.self,
            forKey: .deleteCapability
        )
        guard isStructurallyValid else {
            throw rendezvousRelayDecodingError(decoder, "Invalid rendezvous delete request")
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw rendezvousRelayEncodingError(
                self,
                encoder,
                "Invalid rendezvous delete request"
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(routeCapability, forKey: .routeCapability)
        try container.encode(laneId, forKey: .laneId)
        try container.encode(deleteCapability, forKey: .deleteCapability)
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

    var isStructurallyValid: Bool {
        guard frames.count <= RendezvousRelayTransportV2.maximumSyncFrames,
              frames.allSatisfy(\.isStructurallyValid),
              Set(frames.map(\.frameId)).count == frames.count,
              frames.reduce(0, { $0 + $1.ciphertext.count })
                <= RendezvousRelayTransportV2.maximumCiphertextBytesPerLane,
              highWatermark <= RendezvousRelayTransportV2.maximumFramesPerLane,
              nextSequence <= highWatermark,
              hasMore == (nextSequence < highWatermark) else {
            return false
        }
        guard let first = frames.first, let last = frames.last else {
            return nextSequence == highWatermark
        }
        guard last.sequence == nextSequence else { return false }
        return zip(frames, frames.dropFirst()).allSatisfy { previous, current in
            previous.sequence < UInt64.max && current.sequence == previous.sequence + 1
        } && first.sequence <= nextSequence
    }

    private enum CodingKeys: String, CodingKey {
        case frames
        case highWatermark
        case nextSequence
        case hasMore
    }

    init(from decoder: Decoder) throws {
        try rendezvousRelayRequireExactObject(
            decoder,
            keys: ["frames", "highWatermark", "nextSequence", "hasMore"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        frames = try container.decode([RendezvousRelayCiphertextFrameV2].self, forKey: .frames)
        highWatermark = try container.decode(UInt64.self, forKey: .highWatermark)
        nextSequence = try container.decode(UInt64.self, forKey: .nextSequence)
        hasMore = try container.decode(Bool.self, forKey: .hasMore)
        guard isStructurallyValid else {
            throw rendezvousRelayDecodingError(decoder, "Invalid rendezvous sync batch")
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw rendezvousRelayEncodingError(
                self,
                encoder,
                "Invalid rendezvous sync batch"
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(frames, forKey: .frames)
        try container.encode(highWatermark, forKey: .highWatermark)
        try container.encode(nextSequence, forKey: .nextSequence)
        try container.encode(hasMore, forKey: .hasMore)
    }
}

private struct RendezvousRelayCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private func rendezvousRelayKey(_ value: String) -> RendezvousRelayCodingKey {
    RendezvousRelayCodingKey(stringValue: value)!
}

private func rendezvousRelayRequireExactObject(
    _ decoder: Decoder,
    keys: Set<String>
) throws {
    let container = try decoder.container(keyedBy: RendezvousRelayCodingKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == keys else {
        throw rendezvousRelayDecodingError(
            decoder,
            "Rendezvous relay fields must match nw.rendezvous-transport@2 exactly"
        )
    }
}

private func rendezvousRelayDecodeOpaqueRawValue(
    from decoder: Decoder,
    byteCount: Int,
    description: String
) throws -> Data {
    try rendezvousRelayRequireExactObject(decoder, keys: ["rawValue"])
    let container = try decoder.container(keyedBy: RendezvousRelayCodingKey.self)
    let value = try container.decode(Data.self, forKey: rendezvousRelayKey("rawValue"))
    guard RendezvousRelayTransportV2.isValidOpaqueValue(value, byteCount: byteCount) else {
        throw rendezvousRelayDecodingError(decoder, description)
    }
    return value
}

private func rendezvousRelayEncodeOpaqueRawValue(
    _ value: Data,
    byteCount: Int,
    description: String,
    to encoder: Encoder
) throws {
    guard RendezvousRelayTransportV2.isValidOpaqueValue(value, byteCount: byteCount) else {
        throw rendezvousRelayEncodingError(value, encoder, description)
    }
    var container = encoder.container(keyedBy: RendezvousRelayCodingKey.self)
    try container.encode(value, forKey: rendezvousRelayKey("rawValue"))
}

private func rendezvousRelayDecodingError(
    _ decoder: Decoder,
    _ description: String
) -> DecodingError {
    .dataCorrupted(
        DecodingError.Context(
            codingPath: decoder.codingPath,
            debugDescription: description
        )
    )
}

private func rendezvousRelayEncodingError(
    _ value: Any,
    _ encoder: Encoder,
    _ description: String
) -> EncodingError {
    .invalidValue(
        value,
        EncodingError.Context(
            codingPath: encoder.codingPath,
            debugDescription: description
        )
    )
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
