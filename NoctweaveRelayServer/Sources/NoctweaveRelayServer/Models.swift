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

enum MLSGroupEpochHistoryIssue: String, Codable, Equatable, Hashable {
    case unsupportedProtocolVersion
    case unsupportedCipherSuite
    case emptyHistory
    case duplicateEpoch
    case invalidInitialEpoch
    case nonContiguousEpoch
    case brokenTranscriptLink
    case currentStateMismatch
    case currentCommitMissing
}

enum MLSGroupEpochHistoryValidator {
    static func issues(
        currentState: MLSGroupEpochState,
        history: [MLSGroupCommitSummary],
        allowTruncatedHistory: Bool = true
    ) -> [MLSGroupEpochHistoryIssue] {
        var issues = Set<MLSGroupEpochHistoryIssue>()
        if currentState.protocolVersion != MLSGroupEpochState.currentProtocolVersion {
            issues.insert(.unsupportedProtocolVersion)
        }
        if currentState.cipherSuite != MLSGroupEpochState.currentCipherSuite {
            issues.insert(.unsupportedCipherSuite)
        }
        guard !history.isEmpty else {
            issues.insert(.emptyHistory)
            issues.insert(.currentCommitMissing)
            return Array(issues).sortedByRawValue()
        }

        let sorted = history.sorted { $0.epoch < $1.epoch }
        if Set(sorted.map(\.epoch)).count != sorted.count {
            issues.insert(.duplicateEpoch)
        }

        if let first = sorted.first {
            if first.epoch == 0 {
                if first.operation != .create || first.previousTranscriptHash != nil {
                    issues.insert(.invalidInitialEpoch)
                }
            } else if !allowTruncatedHistory {
                issues.insert(.invalidInitialEpoch)
            }
        }

        for (previous, current) in zip(sorted, sorted.dropFirst()) {
            if previous.epoch == UInt64.max || current.epoch != previous.epoch + 1 {
                issues.insert(.nonContiguousEpoch)
            }
            if current.previousTranscriptHash != previous.transcriptHash {
                issues.insert(.brokenTranscriptLink)
            }
        }

        guard let last = sorted.last else {
            return Array(issues).sortedByRawValue()
        }
        if last != currentState.lastCommit {
            issues.insert(.currentCommitMissing)
        }
        if currentState.epoch != currentState.lastCommit.epoch ||
            currentState.confirmedTranscriptHash != currentState.lastCommit.transcriptHash ||
            last.epoch != currentState.epoch ||
            last.transcriptHash != currentState.confirmedTranscriptHash {
            issues.insert(.currentStateMismatch)
        }

        return Array(issues).sortedByRawValue()
    }

    static func isValid(
        currentState: MLSGroupEpochState,
        history: [MLSGroupCommitSummary],
        allowTruncatedHistory: Bool = true
    ) -> Bool {
        issues(
            currentState: currentState,
            history: history,
            allowTruncatedHistory: allowTruncatedHistory
        ).isEmpty
    }
}

private extension Array where Element == MLSGroupEpochHistoryIssue {
    func sortedByRawValue() -> [MLSGroupEpochHistoryIssue] {
        sorted { $0.rawValue < $1.rawValue }
    }
}

struct MLSGroupEpochState: Codable, Equatable {
    static let currentProtocolVersion = "noctweave-pq-group-experimental-2"
    static let currentCipherSuite = "Noctweave-PQ-Group-Experimental-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-2"

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
    ) throws -> MLSGroupEpochState {
        guard epoch < UInt64.max else {
            throw MLSGroupEpochError.exhausted
        }
        return MLSGroupEpochState.make(
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

private enum MLSGroupEpochError: Error {
    case exhausted
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
    var federationForwardingAuthToken: String?
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
    var requireInboxAccessControl: Bool?
    var experimentalRouteCapabilitiesEnabled: Bool?
    var rendezvousTransportEnabled: Bool?

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
        federationForwardingAuthToken: String? = nil,
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
        requireInboxAccessControl: Bool = true,
        experimentalRouteCapabilitiesEnabled: Bool = false,
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
        let normalizedForwardingToken = federationForwardingAuthToken?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.federationForwardingAuthToken = normalizedForwardingToken?.isEmpty == false ? normalizedForwardingToken : nil
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
        self.requireInboxAccessControl = requireInboxAccessControl
        self.experimentalRouteCapabilitiesEnabled = experimentalRouteCapabilitiesEnabled ? true : nil
        self.rendezvousTransportEnabled = rendezvousTransportEnabled ? true : nil
    }

    var opaqueRouteCapabilitiesEnabled: Bool {
        experimentalRouteCapabilitiesEnabled == true
    }

    var isRendezvousTransportEnabled: Bool {
        rendezvousTransportEnabled == true
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
    let invitedFingerprint: String?
    let requestedAt: Date

    init(
        id: UUID = UUID(),
        groupId: UUID,
        requester: RelayGroupMemberProfile,
        invitedFingerprint: String? = nil,
        requestedAt: Date = Date()
    ) {
        self.id = id
        self.groupId = groupId
        self.requester = requester
        self.invitedFingerprint = invitedFingerprint
        self.requestedAt = requestedAt
    }
}

struct RelayGroupInvitation: Codable, Equatable {
    let id: UUID
    let groupId: UUID
    let title: String
    let createdByFingerprint: String
    let invitedFingerprint: String
    let inboxId: String
    let epoch: UInt64
    let createdAt: Date
    let updatedAt: Date
    let invitedAt: Date

    init(
        id: UUID = UUID(),
        groupId: UUID,
        title: String,
        createdByFingerprint: String,
        invitedFingerprint: String,
        inboxId: String,
        epoch: UInt64,
        createdAt: Date,
        updatedAt: Date,
        invitedAt: Date = Date()
    ) {
        self.id = id
        self.groupId = groupId
        self.title = title
        self.createdByFingerprint = createdByFingerprint
        self.invitedFingerprint = invitedFingerprint
        self.inboxId = inboxId
        self.epoch = epoch
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.invitedAt = invitedAt
    }
}

struct RelayActorProof: Codable, Equatable {
    static let maximumAgeSeconds: TimeInterval = 300

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
    static let currentVersion = 2
    static let maximumOneTimePrekeys = 64
    static let maximumAge: TimeInterval = 8 * 86_400
    static let maximumFutureClockSkew: TimeInterval = 5 * 60
    let version: Int
    let identityFingerprint: String
    let signedPrekey: SignedPrekey
    let oneTimePrekeys: [OneTimePrekey]
    let createdAt: Date

    init(
        version: Int = PrekeyBundle.currentVersion,
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

    func isStructurallyValid(now: Date = Date()) -> Bool {
        guard version == Self.currentVersion,
              let fingerprintData = Data(base64Encoded: identityFingerprint),
              fingerprintData.count == 32,
              fingerprintData.base64EncodedString() == identityFingerprint,
              signedPrekey.publicKey.count == 1_184,
              signedPrekey.signature.count == 3_309,
              signedPrekey.issuedAt.timeIntervalSince1970.isFinite,
              oneTimePrekeys.count <= Self.maximumOneTimePrekeys,
              oneTimePrekeys.allSatisfy({ $0.publicKey.count == 1_184 && $0.signature.count == 3_309 }),
              Set(oneTimePrekeys.map(\.id)).count == oneTimePrekeys.count,
              !oneTimePrekeys.contains(where: { $0.id == signedPrekey.id }),
              createdAt.timeIntervalSince1970.isFinite else {
            return false
        }
        let oldestAllowed = now.addingTimeInterval(-Self.maximumAge)
        let newestAllowed = now.addingTimeInterval(Self.maximumFutureClockSkew)
        return (oldestAllowed...newestAllowed).contains(signedPrekey.issuedAt)
            && (oldestAllowed...newestAllowed).contains(createdAt)
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
    private static let applicationEnvelopeVersion = 2
    private static let minimumCiphertextBytes = 512
    private static let maximumCiphertextBytes = 65_536

    let id: UUID
    let protocolVersion: String
    let cipherSuite: String
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
        protocolVersion: String = MLSGroupEpochState.currentProtocolVersion,
        cipherSuite: String = MLSGroupEpochState.currentCipherSuite,
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
        self.protocolVersion = protocolVersion
        self.cipherSuite = cipherSuite
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
        let ciphertextBytes = payload.ciphertext.count
        guard protocolVersion == MLSGroupEpochState.currentProtocolVersion,
              cipherSuite == MLSGroupEpochState.currentCipherSuite,
              transcriptHash.count == 32,
              sentAt.timeIntervalSince1970.isFinite,
              payload.nonce.count == 12,
              payload.tag.count == 16,
              (Self.minimumCiphertextBytes...Self.maximumCiphertextBytes).contains(ciphertextBytes),
              ciphertextBytes > 0,
              (ciphertextBytes & (ciphertextBytes - 1)) == 0,
              signature.count == OQSSignatureVerifier.mlDSA65SignatureBytes,
              senderFingerprint == Data(SHA256.hash(data: publicSigningKey)).base64EncodedString(),
              let data = try? GroupProofCodec.encode(
                GroupRatchetSignaturePayload(
                    version: Self.applicationEnvelopeVersion,
                    id: id,
                    protocolVersion: protocolVersion,
                    cipherSuite: cipherSuite,
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

enum PrekeyKind: String, Codable, Equatable {
    case signed
    case oneTime
}

struct PrekeyReference: Codable, Equatable {
    let kind: PrekeyKind
    let id: UUID
}

struct RootRatchet: Codable, Equatable {
    let counter: UInt64
    let kemCiphertext: Data
    let sentAt: Date
}

enum MessageAuthenticatedContextPurpose: String, Codable, Equatable {
    case group
    case directV4
}

struct RelationshipInstallationHandle: RawRepresentable, Codable, Equatable {
    let rawValue: String

    init(rawValue: String) {
        self.rawValue = rawValue
    }
}

struct DirectMessageAuthenticatedContextV4: Codable, Equatable {
    let version: Int
    /// Authenticated direct plaintext discriminator. The relay remains
    /// ciphertext-blind, but it must preserve this field byte-for-byte when
    /// decoding and re-encoding an envelope for persistence or delivery.
    let payloadFormat: String
    let cipherSuite: String
    let negotiatedCapabilitiesDigest: Data
    let eventId: UUID
    let senderInstallationHandle: RelationshipInstallationHandle
    let senderCertificateDigest: Data
    let recipientInstallationHandle: RelationshipInstallationHandle
    let senderManifestEpoch: UInt64
    let recipientManifestEpoch: UInt64
    let recipientCertificateDigest: Data
}

struct GroupMessageAuthenticatedContext: Codable, Equatable {
    let protocolVersion: String
    let cipherSuite: String
    let groupId: UUID
    let epoch: UInt64
    let senderFingerprint: String
    let transcriptHash: Data
}

struct MessageAuthenticatedContext: Codable, Equatable {
    let purpose: MessageAuthenticatedContextPurpose
    let group: GroupMessageAuthenticatedContext?
    let directV4: DirectMessageAuthenticatedContextV4?

    init(
        purpose: MessageAuthenticatedContextPurpose,
        group: GroupMessageAuthenticatedContext?,
        directV4: DirectMessageAuthenticatedContextV4? = nil
    ) {
        self.purpose = purpose
        self.group = group
        self.directV4 = directV4
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
    let prekey: PrekeyReference?
    let rootRatchet: RootRatchet?
    let authenticatedContext: MessageAuthenticatedContext?
    let payload: EncryptedPayload
    let signature: Data

    init(
        id: UUID = UUID(),
        conversationId: String,
        sessionId: String? = nil,
        senderFingerprint: String,
        sentAt: Date,
        messageCounter: UInt64,
        kemCiphertext: Data? = nil,
        prekey: PrekeyReference? = nil,
        rootRatchet: RootRatchet? = nil,
        authenticatedContext: MessageAuthenticatedContext? = nil,
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
        self.prekey = prekey
        self.rootRatchet = rootRatchet
        self.authenticatedContext = authenticatedContext
        self.payload = payload
        self.signature = signature
    }

    var isStructurallyValid: Bool {
        let ciphertextBytes = payload.ciphertext.count
        guard !conversationId.isEmpty,
              conversationId.utf8.count <= 256,
              sessionId?.utf8.count ?? 0 <= 128,
              Self.isCanonicalFingerprint(senderFingerprint),
              sentAt.timeIntervalSince1970.isFinite,
              payload.nonce.count == 12,
              payload.tag.count == 16,
              (512...65_536).contains(ciphertextBytes),
              ciphertextBytes > 0,
              (ciphertextBytes & (ciphertextBytes - 1)) == 0,
              signature.count == OQSSignatureVerifier.mlDSA65SignatureBytes,
              kemCiphertext?.count ?? 1_088 == 1_088,
              rootRatchet?.kemCiphertext.count ?? 1_088 == 1_088,
              rootRatchet?.sentAt.timeIntervalSince1970.isFinite ?? true else {
            return false
        }
        if let context = authenticatedContext {
            switch context.purpose {
            case .group:
                guard let group = context.group,
                      context.directV4 == nil,
                      group.protocolVersion == MLSGroupEpochState.currentProtocolVersion,
                      group.cipherSuite == MLSGroupEpochState.currentCipherSuite,
                      group.senderFingerprint == senderFingerprint,
                      group.transcriptHash.count == 32 else {
                    return false
                }
            case .directV4:
                guard context.group == nil,
                      let direct = context.directV4,
                      direct.version == 4,
                      direct.payloadFormat == "nw.wire-payload.v2",
                      direct.cipherSuite
                        == "nw.direct-v4.ml-kem-768.ml-dsa-65.hkdf-sha256.hmac-sha256.aes-256-gcm",
                      direct.negotiatedCapabilitiesDigest.count == 32,
                      Self.isCanonicalFingerprint(direct.senderInstallationHandle.rawValue),
                      direct.senderCertificateDigest.count == 32,
                      Self.isCanonicalFingerprint(direct.recipientInstallationHandle.rawValue),
                      direct.recipientCertificateDigest.count == 32,
                      direct.senderInstallationHandle.rawValue == senderFingerprint else {
                    return false
                }
            }
        }
        return true
    }

    private static func isCanonicalFingerprint(_ value: String) -> Bool {
        guard let decoded = Data(base64Encoded: value), decoded.count == 32 else { return false }
        return decoded.base64EncodedString() == value
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

struct InboxRouteCapabilityV2: Codable, Equatable, Hashable {
    static let relayRegistryDigestDomain = "org.noctweave.relay.inbox-route-capability/v2"

    let rawValue: Data

    private enum CodingKeys: String, CodingKey {
        case rawValue
    }

    init(rawValue: Data) {
        self.rawValue = rawValue
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decoded = try container.decode(Data.self, forKey: .rawValue)
        let capability = InboxRouteCapabilityV2(rawValue: decoded)
        guard capability.isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawValue,
                in: container,
                debugDescription: "Inbox route capability must be a nonzero 32-byte bearer"
            )
        }
        self = capability
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rawValue, forKey: .rawValue)
    }

    var isStructurallyValid: Bool {
        rawValue.count == 32 && rawValue.contains(where: { $0 != 0 })
    }

    var relayRegistryDigest: Data {
        var material = Data(Self.relayRegistryDigestDomain.utf8)
        material.append(0)
        material.append(rawValue)
        return Data(SHA256.hash(data: material))
    }
}

struct DeliverRequest: Codable, Equatable {
    /// Transitional pre-v2 inbox addressing. Capability-addressed delivery
    /// deliberately leaves this and `routingToken` absent.
    let inboxId: String?
    let routingToken: String?
    let inboxCapability: InboxRouteCapabilityV2?
    let envelope: Envelope
    let destinationRelay: RelayEndpoint?

    init(
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

    init(
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
    static let privacyMinimizedVersion = 2

    let inboxId: String
    let accessPublicKey: Data
    let registrationVersion: Int
    let accessProof: RelayActorProof?

    init(
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

    static func privacyMinimizedV2(
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

    func signableData(for proof: RelayActorProof) throws -> Data {
        return try GroupProofCodec.encode(
            InboxRegistrationProofPayloadV2(
                inboxId: inboxId,
                accessPublicKey: accessPublicKey,
                registrationVersion: registrationVersion,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

struct RetireInboxRequest: Codable, Equatable {
    static let protocolVersion = 1
    static let signatureDomain = "org.noctweave.relay.retire-inbox"

    let inboxId: String
    let accessProof: RelayActorProof?

    init(inboxId: String, accessProof: RelayActorProof? = nil) {
        self.inboxId = inboxId
        self.accessProof = accessProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
            InboxRetirementProofPayload(
                domain: Self.signatureDomain,
                version: Self.protocolVersion,
                inboxId: inboxId,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }

    func requestDigest() throws -> Data {
        Data(SHA256.hash(data: try GroupProofCodec.encode(self)))
    }
}

struct CreateInboxRouteCapabilityRequest: Codable, Equatable {
    static let protocolVersion = 3
    static let maximumMutationSequence: UInt64 = UInt64(UInt32.max)
    static let signatureDomain = "org.noctweave.relay.inbox-route-capability-mutation"

    static func nextMutationSequence(after current: UInt64) -> UInt64 {
        guard current < maximumMutationSequence else { return 0 }
        return current + 1
    }

    let inboxId: String
    let capability: InboxRouteCapabilityV2
    let relayScope: Data
    let mutationSequence: UInt64
    let authorityProof: RelayActorProof?

    init(
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

    func signableData(for proof: RelayActorProof) throws -> Data {
        try inboxRouteCapabilityMutationSignableData(
            operation: "create",
            inboxId: inboxId,
            capability: capability,
            relayScope: relayScope,
            mutationSequence: mutationSequence,
            proof: proof
        )
    }

    func mutationDigest() throws -> Data {
        try inboxRouteCapabilityMutationDigest(
            operation: "create",
            inboxId: inboxId,
            capability: capability,
            relayScope: relayScope,
            mutationSequence: mutationSequence
        )
    }
}

private enum InboxRouteCapabilityMutationRequestError: Error {
    case invalidMutationState
}

struct RevokeInboxRouteCapabilityRequest: Codable, Equatable {
    let inboxId: String
    let capability: InboxRouteCapabilityV2
    let relayScope: Data
    let mutationSequence: UInt64
    let authorityProof: RelayActorProof?

    init(
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

    func signableData(for proof: RelayActorProof) throws -> Data {
        try inboxRouteCapabilityMutationSignableData(
            operation: "revoke",
            inboxId: inboxId,
            capability: capability,
            relayScope: relayScope,
            mutationSequence: mutationSequence,
            proof: proof
        )
    }

    func mutationDigest() throws -> Data {
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
    return try GroupProofCodec.encode(
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
        )
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
    let payload = try GroupProofCodec.encode(
        InboxRouteCapabilityMutationStatePayload(
            domain: "\(CreateInboxRouteCapabilityRequest.signatureDomain)/state",
            version: CreateInboxRouteCapabilityRequest.protocolVersion,
            operation: operation,
            inboxId: inboxId,
            capabilityDigest: capability.relayRegistryDigest,
            relayScope: relayScope,
            mutationSequence: mutationSequence
        )
    )
    return Data(SHA256.hash(data: payload))
}

struct RegisterMailboxConsumerRequest: Codable, Equatable {
    let inboxId: String
    let consumerId: MailboxConsumerId
    let consumerSigningPublicKey: Data
    let sponsorConsumerId: MailboxConsumerId?
    let startingSequence: UInt64?
    let authorityProof: RelayActorProof?
    let consumerProof: RelayActorProof?
    let sponsorProof: RelayActorProof?

    init(
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

    func authoritySignableData(for proof: RelayActorProof) throws -> Data {
        try signableData(operation: "register-authority", proof: proof)
    }

    func consumerSignableData(for proof: RelayActorProof) throws -> Data {
        try signableData(operation: "register-possession", proof: proof)
    }

    func sponsorSignableData(for proof: RelayActorProof) throws -> Data {
        try signableData(operation: "register-sponsor", proof: proof)
    }

    private func signableData(operation: String, proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
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
            )
        )
    }
}

struct SyncMailboxRequest: Codable, Equatable {
    let inboxId: String
    let consumerId: MailboxConsumerId
    let cursor: MailboxCursor?
    let maxCount: Int?
    let longPollTimeoutSeconds: Int?
    let consumerProof: RelayActorProof?

    init(
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

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
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
            )
        )
    }
}

struct CommitMailboxCursorRequest: Codable, Equatable {
    let inboxId: String
    let consumerId: MailboxConsumerId
    let cursor: MailboxCursor
    let sequence: UInt64
    let consumerProof: RelayActorProof?

    init(
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

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
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
            )
        )
    }
}

struct RevokeMailboxConsumerRequest: Codable, Equatable {
    let inboxId: String
    let consumerId: MailboxConsumerId
    let authorityProof: RelayActorProof?

    init(
        inboxId: String,
        consumerId: MailboxConsumerId,
        authorityProof: RelayActorProof? = nil
    ) {
        self.inboxId = inboxId
        self.consumerId = consumerId
        self.authorityProof = authorityProof
    }

    func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofCodec.encode(
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
            )
        )
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
    let retireInbox: RetireInboxRequest?
    let createInboxRouteCapability: CreateInboxRouteCapabilityRequest?
    let revokeInboxRouteCapability: RevokeInboxRouteCapabilityRequest?
    let registerRendezvousTransportV2: RegisterRendezvousTransportV2Request?
    let appendRendezvousTransportV2: AppendRendezvousTransportV2Request?
    let syncRendezvousTransportV2: SyncRendezvousTransportV2Request?
    let deleteRendezvousTransportV2: DeleteRendezvousTransportV2Request?
    let fetch: FetchRequest?
    let registerMailboxConsumer: RegisterMailboxConsumerRequest?
    let syncMailbox: SyncMailboxRequest?
    let commitMailboxCursor: CommitMailboxCursorRequest?
    let revokeMailboxConsumer: RevokeMailboxConsumerRequest?
    let uploadAttachment: UploadAttachmentRequest?
    let fetchAttachment: FetchAttachmentRequest?
    let registerFederationNode: FederationNodeRegistrationRequest?
    let listFederationNodes: ListFederationNodesRequest?
    let publishOpenFederationDHTRecord: PublishOpenFederationDHTRecordRequest?
    let listOpenFederationDHTRecords: ListOpenFederationDHTRecordsRequest?

    init(
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

    static func deliver(_ request: DeliverRequest) -> RelayRequest {
        RelayRequest(type: .deliver, deliver: request)
    }

    static func registerInbox(_ request: RegisterInboxRequest) -> RelayRequest {
        RelayRequest(type: .registerInbox, registerInbox: request)
    }

    static func retireInbox(_ request: RetireInboxRequest) -> RelayRequest {
        RelayRequest(type: .retireInbox, retireInbox: request)
    }

    static func createInboxRouteCapability(
        _ request: CreateInboxRouteCapabilityRequest
    ) -> RelayRequest {
        RelayRequest(
            type: .createInboxRouteCapability,
            createInboxRouteCapability: request
        )
    }

    static func revokeInboxRouteCapability(
        _ request: RevokeInboxRouteCapabilityRequest
    ) -> RelayRequest {
        RelayRequest(
            type: .revokeInboxRouteCapability,
            revokeInboxRouteCapability: request
        )
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

    static func fetch(_ request: FetchRequest) -> RelayRequest {
        RelayRequest(type: .fetch, fetch: request)
    }

    static func registerMailboxConsumer(_ request: RegisterMailboxConsumerRequest) -> RelayRequest {
        RelayRequest(type: .registerMailboxConsumer, registerMailboxConsumer: request)
    }

    static func syncMailbox(_ request: SyncMailboxRequest) -> RelayRequest {
        RelayRequest(type: .syncMailbox, syncMailbox: request)
    }

    static func commitMailboxCursor(_ request: CommitMailboxCursorRequest) -> RelayRequest {
        RelayRequest(type: .commitMailboxCursor, commitMailboxCursor: request)
    }

    static func revokeMailboxConsumer(_ request: RevokeMailboxConsumerRequest) -> RelayRequest {
        RelayRequest(type: .revokeMailboxConsumer, revokeMailboxConsumer: request)
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

private struct GroupRatchetSignaturePayload: Codable {
    let version: Int
    let id: UUID
    let protocolVersion: String
    let cipherSuite: String
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
    case mailboxSync
    case mailboxConsumer
    case rendezvousSyncV2
    case attachment
    case info
    case federationNodes
    case openFederationDHTRecords
    case error
}

struct DeliverResponse: Codable, Equatable {
    let storedCount: Int
}

struct InboxRegistrationReceiptV3: Codable, Equatable {
    let routeMutationScope: Data
    let nextRouteMutationSequence: UInt64
}

struct RelayResponse: Codable, Equatable {
    let type: RelayResponseType
    let delivered: DeliverResponse?
    let inboxRegistration: InboxRegistrationReceiptV3?
    let messages: [Envelope]?
    let mailboxSync: MailboxSyncBatch?
    let mailboxConsumer: MailboxConsumerRegistration?
    let rendezvousSyncV2: RendezvousRelaySyncBatchV2?
    let attachment: AttachmentChunk?
    let relayInfo: RelayInfo?
    let federationNodes: [FederationNodeRecord]?
    let federationSnapshot: FederationDirectorySnapshot?
    let openFederationDHTRecords: [OpenFederationDHTRecord]?
    let error: String?

    init(
        type: RelayResponseType,
        delivered: DeliverResponse? = nil,
        inboxRegistration: InboxRegistrationReceiptV3? = nil,
        messages: [Envelope]? = nil,
        mailboxSync: MailboxSyncBatch? = nil,
        mailboxConsumer: MailboxConsumerRegistration? = nil,
        rendezvousSyncV2: RendezvousRelaySyncBatchV2? = nil,
        attachment: AttachmentChunk? = nil,
        relayInfo: RelayInfo? = nil,
        federationNodes: [FederationNodeRecord]? = nil,
        federationSnapshot: FederationDirectorySnapshot? = nil,
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
        self.relayInfo = relayInfo
        self.federationNodes = federationNodes
        self.federationSnapshot = federationSnapshot
        self.openFederationDHTRecords = openFederationDHTRecords
        self.error = error
    }

    static func ok(
        inboxRegistration: InboxRegistrationReceiptV3? = nil
    ) -> RelayResponse {
        RelayResponse(type: .ok, inboxRegistration: inboxRegistration)
    }

    static func delivered(count: Int) -> RelayResponse {
        RelayResponse(type: .delivered, delivered: DeliverResponse(storedCount: count))
    }

    static func messages(_ envelopes: [Envelope]) -> RelayResponse {
        RelayResponse(type: .messages, messages: envelopes)
    }

    static func mailboxSync(_ batch: MailboxSyncBatch) -> RelayResponse {
        RelayResponse(type: .mailboxSync, mailboxSync: batch)
    }

    static func mailboxConsumer(_ consumer: MailboxConsumerRegistration) -> RelayResponse {
        RelayResponse(type: .mailboxConsumer, mailboxConsumer: consumer)
    }

    static func rendezvousSyncV2(_ batch: RendezvousRelaySyncBatchV2) -> RelayResponse {
        RelayResponse(type: .rendezvousSyncV2, rendezvousSyncV2: batch)
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

private enum GroupProofCodec {
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        try RelayCodec.encoder(sortedKeys: true).encode(value)
    }
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

struct ContactOffer: Codable, Equatable {
    private static let mlDSA65PublicKeyBytes = 1_952
    private static let mlKEM768PublicKeyBytes = 1_184
    private static let mlDSA65SignatureBytes = 3_309
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
        guard isStructurallyValid(),
              isConsistentFingerprint(),
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

    func isStructurallyValid() -> Bool {
        let normalizedDisplayName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedHost = relay.host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (version == 2 && inboxAccessPublicKey == nil) || (version == 3 && inboxAccessPublicKey != nil),
              !normalizedDisplayName.isEmpty,
              normalizedDisplayName.utf8.count <= 512,
              !inboxId.isEmpty,
              inboxId.utf8.count <= 128,
              !normalizedHost.isEmpty,
              normalizedHost == relay.host,
              normalizedHost.utf8.count <= 253,
              relay.port > 0,
              signingPublicKey.count == Self.mlDSA65PublicKeyBytes,
              agreementPublicKey.count == Self.mlKEM768PublicKeyBytes,
              fingerprint.utf8.count <= 128,
              signature.count == Self.mlDSA65SignatureBytes else {
            return false
        }
        if let inboxAccessPublicKey {
            guard inboxAccessPublicKey.count == Self.mlDSA65PublicKeyBytes,
                  InboxAddress.isValid(inboxId),
                  InboxAddress.isBound(inboxId, to: inboxAccessPublicKey) else {
                return false
            }
        }
        return true
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
