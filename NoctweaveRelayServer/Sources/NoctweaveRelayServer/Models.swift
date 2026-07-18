import Foundation
import Crypto

private struct ExactModelCodingKey: CodingKey {
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

func requireExactModelFields<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ keyType: Key.Type,
    context: String
) throws where Key.AllCases: Collection {
    let strict = try decoder.container(keyedBy: ExactModelCodingKey.self)
    guard Set(strict.allKeys.map(\.stringValue))
            == Set(keyType.allCases.map(\.stringValue)) else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "\(context) fields must match the current schema exactly"
            )
        )
    }
}

func invalidModelEncoding(
    _ value: Any,
    _ encoder: Encoder,
    context: String
) -> EncodingError {
    .invalidValue(
        value,
        .init(
            codingPath: encoder.codingPath,
            debugDescription: "\(context) is structurally invalid"
        )
    )
}

private func isBoundedModelText(
    _ value: String,
    maximumUTF8Bytes: Int,
    allowEmpty: Bool = false
) -> Bool {
    (allowEmpty || !value.isEmpty)
        && value == value.trimmingCharacters(in: .whitespacesAndNewlines)
        && value.utf8.count <= maximumUTF8Bytes
        && value.unicodeScalars.allSatisfy {
            !CharacterSet.controlCharacters.contains($0)
        }
}

private func canonicalModelDate(_ value: Date) -> Date {
    let seconds = value.timeIntervalSince1970
    guard seconds.isFinite else { return value }
    return Date(timeIntervalSince1970: floor(seconds))
}

private func isCanonicalModelTimestamp(_ value: Date) -> Bool {
    let seconds = value.timeIntervalSince1970
    return seconds.isFinite
        && seconds >= 0
        && seconds <= 4_102_444_800
        && floor(seconds) == seconds
}

private func relayEndpointModelKey(_ endpoint: RelayEndpoint) -> String {
    [
        endpoint.host.lowercased(),
        String(endpoint.port),
        endpoint.useTLS ? "1" : "0",
        endpoint.transport.rawValue
    ].joined(separator: "\u{0}")
}

private func isValidRelayEndpointModelList(
    _ endpoints: [RelayEndpoint],
    maximumCount: Int
) -> Bool {
    endpoints.count <= maximumCount
        && endpoints.allSatisfy(\.isStructurallyValid)
        && Set(endpoints.map(relayEndpointModelKey)).count == endpoints.count
}

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

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case mode
        case name
        case description
    }

    init(mode: FederationMode, name: String? = nil, description: String? = nil) {
        self.mode = mode
        self.name = name
        self.description = description
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Federation descriptor")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            mode: try values.decode(FederationMode.self, forKey: .mode),
            name: try values.decodeIfPresent(String.self, forKey: .name),
            description: try values.decodeIfPresent(String.self, forKey: .description)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .mode,
                in: values,
                debugDescription: "Federation descriptor is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Federation descriptor")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(mode, forKey: .mode)
        try values.encode(name, forKey: .name)
        try values.encode(description, forKey: .description)
    }

    var isStructurallyValid: Bool {
        (name.map { isBoundedModelText($0, maximumUTF8Bytes: 1_024) } ?? true)
            && (description.map {
                isBoundedModelText($0, maximumUTF8Bytes: 1_024)
            } ?? true)
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

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case replicaId
        case operatorId
        case endpoint
    }

    init(replicaId: String, operatorId: String, endpoint: RelayEndpoint) {
        self.replicaId = replicaId.trimmingCharacters(in: .whitespacesAndNewlines)
        self.operatorId = operatorId.trimmingCharacters(in: .whitespacesAndNewlines)
        self.endpoint = endpoint
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "PIR replica")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let replicaId = try values.decode(String.self, forKey: .replicaId)
        let operatorId = try values.decode(String.self, forKey: .operatorId)
        self.init(
            replicaId: replicaId,
            operatorId: operatorId,
            endpoint: try values.decode(RelayEndpoint.self, forKey: .endpoint)
        )
        guard self.replicaId == replicaId,
              self.operatorId == operatorId,
              isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .replicaId,
                in: values,
                debugDescription: "PIR replica is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "PIR replica")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(replicaId, forKey: .replicaId)
        try values.encode(operatorId, forKey: .operatorId)
        try values.encode(endpoint, forKey: .endpoint)
    }

    var isStructurallyValid: Bool {
        isBoundedModelText(replicaId, maximumUTF8Bytes: 1_024)
            && isBoundedModelText(operatorId, maximumUTF8Bytes: 1_024)
            && endpoint.isStructurallyValid
    }
}

struct HiddenRetrievalSupport: Codable, Equatable {
    let mode: HiddenRetrievalMode
    let defaultCoverSetSize: Int
    let maxCoverSetSize: Int
    let replicatedXorPIRReplicas: [HiddenRetrievalPIRReplica]?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case mode
        case defaultCoverSetSize
        case maxCoverSetSize
        case replicatedXorPIRReplicas
    }

    init(
        mode: HiddenRetrievalMode = .coverQuery,
        defaultCoverSetSize: Int = 8,
        maxCoverSetSize: Int = 32,
        replicatedXorPIRReplicas: [HiddenRetrievalPIRReplica]? = nil
    ) {
        let normalizedMax = min(max(2, maxCoverSetSize), 4_096)
        self.mode = mode
        self.maxCoverSetSize = normalizedMax
        self.defaultCoverSetSize = min(max(2, defaultCoverSetSize), normalizedMax)
        self.replicatedXorPIRReplicas = replicatedXorPIRReplicas.map { replicas in
            Array(replicas.prefix(256)).map {
                HiddenRetrievalPIRReplica(
                    replicaId: $0.replicaId,
                    operatorId: $0.operatorId,
                    endpoint: $0.endpoint
                )
            }
        }
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Hidden retrieval support")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let mode = try values.decode(HiddenRetrievalMode.self, forKey: .mode)
        let defaultCoverSetSize = try values.decode(Int.self, forKey: .defaultCoverSetSize)
        let maxCoverSetSize = try values.decode(Int.self, forKey: .maxCoverSetSize)
        let replicas = try values.decodeIfPresent(
            [HiddenRetrievalPIRReplica].self,
            forKey: .replicatedXorPIRReplicas
        )
        self.init(
            mode: mode,
            defaultCoverSetSize: defaultCoverSetSize,
            maxCoverSetSize: maxCoverSetSize,
            replicatedXorPIRReplicas: replicas
        )
        guard self.defaultCoverSetSize == defaultCoverSetSize,
              self.maxCoverSetSize == maxCoverSetSize,
              replicatedXorPIRReplicas == replicas,
              isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .mode,
                in: values,
                debugDescription: "Hidden retrieval support is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Hidden retrieval support")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(mode, forKey: .mode)
        try values.encode(defaultCoverSetSize, forKey: .defaultCoverSetSize)
        try values.encode(maxCoverSetSize, forKey: .maxCoverSetSize)
        try values.encode(replicatedXorPIRReplicas, forKey: .replicatedXorPIRReplicas)
    }

    var isStructurallyValid: Bool {
        guard (2...4_096).contains(defaultCoverSetSize),
              (defaultCoverSetSize...4_096).contains(maxCoverSetSize) else {
            return false
        }
        guard let replicas = replicatedXorPIRReplicas else {
            return mode != .replicatedXorPIR
        }
        guard !replicas.isEmpty,
              replicas.count <= 256,
              replicas.allSatisfy(\.isStructurallyValid) else {
            return false
        }
        let replicaIDs = replicas.map { $0.replicaId.lowercased() }
        let operatorIDs = replicas.map { $0.operatorId.lowercased() }
        let endpointKeys = replicas.map { relayEndpointModelKey($0.endpoint) }
        return Set(replicaIDs).count == replicas.count
            && Set(operatorIDs).count == replicas.count
            && Set(endpointKeys).count == replicas.count
            && (mode != .replicatedXorPIR || replicas.count >= 2)
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

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case dhtNodeEnabled
        case peerExchangeEnabled
        case peerExchangeLimit
        case requirePublicEndpoint
        case maxDHTRecords
        case maxDHTRecordsPerHost
        case maxDHTQueryRecords
    }

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

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Open discovery support")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let peerLimit = try values.decode(Int.self, forKey: .peerExchangeLimit)
        let maximumRecords = try values.decode(Int.self, forKey: .maxDHTRecords)
        let maximumRecordsPerHost = try values.decode(Int.self, forKey: .maxDHTRecordsPerHost)
        let maximumQueryRecords = try values.decode(Int.self, forKey: .maxDHTQueryRecords)
        self.init(
            dhtNodeEnabled: try values.decode(Bool.self, forKey: .dhtNodeEnabled),
            peerExchangeEnabled: try values.decode(Bool.self, forKey: .peerExchangeEnabled),
            peerExchangeLimit: peerLimit,
            requirePublicEndpoint: try values.decode(Bool.self, forKey: .requirePublicEndpoint),
            maxDHTRecords: maximumRecords,
            maxDHTRecordsPerHost: maximumRecordsPerHost,
            maxDHTQueryRecords: maximumQueryRecords
        )
        guard peerExchangeLimit == peerLimit,
              maxDHTRecords == maximumRecords,
              maxDHTRecordsPerHost == maximumRecordsPerHost,
              maxDHTQueryRecords == maximumQueryRecords,
              isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .peerExchangeLimit,
                in: values,
                debugDescription: "Open discovery support is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Open discovery support")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(dhtNodeEnabled, forKey: .dhtNodeEnabled)
        try values.encode(peerExchangeEnabled, forKey: .peerExchangeEnabled)
        try values.encode(peerExchangeLimit, forKey: .peerExchangeLimit)
        try values.encode(requirePublicEndpoint, forKey: .requirePublicEndpoint)
        try values.encode(maxDHTRecords, forKey: .maxDHTRecords)
        try values.encode(maxDHTRecordsPerHost, forKey: .maxDHTRecordsPerHost)
        try values.encode(maxDHTQueryRecords, forKey: .maxDHTQueryRecords)
    }

    var isStructurallyValid: Bool {
        (0...128).contains(peerExchangeLimit)
            && (1...256).contains(maxDHTRecords)
            && (1...16).contains(maxDHTRecordsPerHost)
            && maxDHTRecordsPerHost <= maxDHTRecords
            && (1...512).contains(maxDHTQueryRecords)
            && (peerExchangeEnabled || peerExchangeLimit == 0)
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

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case enabled
        case maxHops
        case requiresFixedSizePackets
    }

    init(enabled: Bool = true, maxHops: Int = 3, requiresFixedSizePackets: Bool = true) {
        self.enabled = enabled
        self.maxHops = min(max(1, maxHops), 8)
        self.requiresFixedSizePackets = requiresFixedSizePackets
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Onion support")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let maxHops = try values.decode(Int.self, forKey: .maxHops)
        self.init(
            enabled: try values.decode(Bool.self, forKey: .enabled),
            maxHops: maxHops,
            requiresFixedSizePackets: try values.decode(
                Bool.self,
                forKey: .requiresFixedSizePackets
            )
        )
        guard self.maxHops == maxHops, isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .maxHops,
                in: values,
                debugDescription: "Onion support is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Onion support")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(enabled, forKey: .enabled)
        try values.encode(maxHops, forKey: .maxHops)
        try values.encode(requiresFixedSizePackets, forKey: .requiresFixedSizePackets)
    }

    var isStructurallyValid: Bool {
        (1...8).contains(maxHops)
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

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case enabled
        case batchIntervalSeconds
        case minBatchSize
        case coverPacketsPerBatch
        case maxDelaySeconds
    }

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

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Mixnet support")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let batchInterval = try values.decode(Int.self, forKey: .batchIntervalSeconds)
        let minimumBatch = try values.decode(Int.self, forKey: .minBatchSize)
        let coverPackets = try values.decode(Int.self, forKey: .coverPacketsPerBatch)
        let maximumDelay = try values.decode(Int.self, forKey: .maxDelaySeconds)
        self.init(
            enabled: try values.decode(Bool.self, forKey: .enabled),
            batchIntervalSeconds: batchInterval,
            minBatchSize: minimumBatch,
            coverPacketsPerBatch: coverPackets,
            maxDelaySeconds: maximumDelay
        )
        guard batchIntervalSeconds == batchInterval,
              minBatchSize == minimumBatch,
              coverPacketsPerBatch == coverPackets,
              maxDelaySeconds == maximumDelay,
              isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .batchIntervalSeconds,
                in: values,
                debugDescription: "Mixnet support is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Mixnet support")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(enabled, forKey: .enabled)
        try values.encode(batchIntervalSeconds, forKey: .batchIntervalSeconds)
        try values.encode(minBatchSize, forKey: .minBatchSize)
        try values.encode(coverPacketsPerBatch, forKey: .coverPacketsPerBatch)
        try values.encode(maxDelaySeconds, forKey: .maxDelaySeconds)
    }

    var isStructurallyValid: Bool {
        (5...3_600).contains(batchIntervalSeconds)
            && (1...256).contains(minBatchSize)
            && (0...256).contains(coverPacketsPerBatch)
            && (0...3_600).contains(maxDelaySeconds)
    }
}

enum DecentralizedWakeMode: String, Codable, CaseIterable {
    case pullOnly
    case longPoll
}

struct DecentralizedWakeSupport: Codable, Equatable {
    static let absoluteMaximumPollIntervalSeconds = 86_400

    let mode: DecentralizedWakeMode
    let minPollIntervalSeconds: Int
    let maxPollIntervalSeconds: Int
    let jitterPermille: Int
    let longPollTimeoutSeconds: Int?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case mode
        case minPollIntervalSeconds
        case maxPollIntervalSeconds
        case jitterPermille
        case longPollTimeoutSeconds
    }

    init(
        mode: DecentralizedWakeMode = .pullOnly,
        minPollIntervalSeconds: Int = 60,
        maxPollIntervalSeconds: Int = 300,
        jitterPermille: Int = 250,
        longPollTimeoutSeconds: Int? = nil
    ) {
        let normalizedMinimum = min(
            Self.absoluteMaximumPollIntervalSeconds,
            max(5, minPollIntervalSeconds)
        )
        let normalizedMaximum = min(
            Self.absoluteMaximumPollIntervalSeconds,
            max(normalizedMinimum, maxPollIntervalSeconds)
        )
        self.mode = mode
        self.minPollIntervalSeconds = normalizedMinimum
        self.maxPollIntervalSeconds = normalizedMaximum
        self.jitterPermille = min(max(0, jitterPermille), 1_000)
        if mode == .longPoll {
            self.longPollTimeoutSeconds = longPollTimeoutSeconds.map {
                min(max(5, $0), normalizedMaximum)
            } ?? normalizedMinimum
        } else {
            self.longPollTimeoutSeconds = nil
        }
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Wake support")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let mode = try values.decode(DecentralizedWakeMode.self, forKey: .mode)
        let minimum = try values.decode(Int.self, forKey: .minPollIntervalSeconds)
        let maximum = try values.decode(Int.self, forKey: .maxPollIntervalSeconds)
        let jitter = try values.decode(Int.self, forKey: .jitterPermille)
        let timeout = try values.decodeIfPresent(Int.self, forKey: .longPollTimeoutSeconds)
        self.init(
            mode: mode,
            minPollIntervalSeconds: minimum,
            maxPollIntervalSeconds: maximum,
            jitterPermille: jitter,
            longPollTimeoutSeconds: timeout
        )
        guard minPollIntervalSeconds == minimum,
              maxPollIntervalSeconds == maximum,
              jitterPermille == jitter,
              longPollTimeoutSeconds == timeout,
              isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .mode,
                in: values,
                debugDescription: "Wake support is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Wake support")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(mode, forKey: .mode)
        try values.encode(minPollIntervalSeconds, forKey: .minPollIntervalSeconds)
        try values.encode(maxPollIntervalSeconds, forKey: .maxPollIntervalSeconds)
        try values.encode(jitterPermille, forKey: .jitterPermille)
        try values.encode(longPollTimeoutSeconds, forKey: .longPollTimeoutSeconds)
    }

    var isStructurallyValid: Bool {
        (5...Self.absoluteMaximumPollIntervalSeconds).contains(minPollIntervalSeconds)
            && (minPollIntervalSeconds...Self.absoluteMaximumPollIntervalSeconds)
                .contains(maxPollIntervalSeconds)
            && (0...1_000).contains(jitterPermille)
            && (mode == .longPoll
                ? longPollTimeoutSeconds.map {
                    (5...maxPollIntervalSeconds).contains($0)
                } == true
                : longPollTimeoutSeconds == nil)
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
    let wakeSupport: DecentralizedWakeSupport?
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
        wakeSupport: DecentralizedWakeSupport? = nil,
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
        self.wakeSupport = wakeSupport
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
        self.advertisedAt = canonicalModelDate(advertisedAt)
    }

    var isStructurallyValid: Bool {
        guard federation.isStructurallyValid,
              (0...86_400).contains(temporalBucketSeconds),
              isCanonicalModelTimestamp(advertisedAt),
              attachmentStorageBackend.map({
                  isBoundedModelText($0, maximumUTF8Bytes: 1_024)
              }) ?? true,
              relayName.map({ isBoundedModelText($0, maximumUTF8Bytes: 1_024) }) ?? true,
              operatorNote.map({ isBoundedModelText($0, maximumUTF8Bytes: 1_024) }) ?? true,
              softwareVersion.map({ isBoundedModelText($0, maximumUTF8Bytes: 1_024) }) ?? true,
              hiddenRetrieval?.isStructurallyValid != false,
              onionTransport?.isStructurallyValid != false,
              mixnetTransport?.isStructurallyValid != false,
              wakeSupport?.isStructurallyValid != false,
              protocolCapabilities?.isStructurallyValid != false,
              openFederationDiscovery?.isStructurallyValid != false else {
            return false
        }
        if let schedule = temporalBucketScheduleSeconds {
            guard !schedule.isEmpty,
                  schedule.count <= 16,
                  schedule == Array(Set(schedule)).sorted(),
                  schedule.allSatisfy({ (1...86_400).contains($0) }) else {
                return false
            }
        }
        if let attachmentDefaultTTLSeconds,
           !(60...2_592_000).contains(attachmentDefaultTTLSeconds) {
            return false
        }
        if let attachmentMaxTTLSeconds,
           !(60...2_592_000).contains(attachmentMaxTTLSeconds) {
            return false
        }
        if let attachmentDefaultTTLSeconds,
           let attachmentMaxTTLSeconds,
           attachmentMaxTTLSeconds < attachmentDefaultTTLSeconds {
            return false
        }
        if let federationCoordinatorEndpoints,
           !isValidRelayEndpointModelList(federationCoordinatorEndpoints, maximumCount: 16) {
            return false
        }
        if let coordinatorReportedRelayCount,
           !(0...1_000_000).contains(coordinatorReportedRelayCount) {
            return false
        }
        if let curatedCoordinatorQuorum,
           !(1...16).contains(curatedCoordinatorQuorum) {
            return false
        }
        if let federationDirectoryPublicKey,
           federationDirectoryPublicKey.count != OQSSignatureVerifier.mlDSA65PublicKeyBytes {
            return false
        }
        if let knownOpenPeers,
           !isValidRelayEndpointModelList(knownOpenPeers, maximumCount: 128) {
            return false
        }
        return true
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case kind
        case federation
        case temporalBucketSeconds
        case temporalBucketScheduleSeconds
        case attachmentDefaultTTLSeconds
        case attachmentMaxTTLSeconds
        case attachmentsEnabled
        case attachmentStorageBackend
        case hiddenRetrieval
        case onionTransport
        case mixnetTransport
        case wakeSupport
        case relayName
        case operatorNote
        case softwareVersion
        case protocolCapabilities
        case requiresPassword
        case tlsEnabled
        case transport
        case federationCoordinatorEndpoints
        case coordinatorReportedRelayCount
        case coordinatorRegistrationAuthRequired
        case curatedStrictPolicyEnabled
        case curatedCoordinatorQuorum
        case curatedRequireSignedDirectory
        case federationDirectoryPublicKey
        case knownOpenPeers
        case openFederationDiscovery
        case advertisedAt
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Relay information")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        kind = try values.decode(RelayKind.self, forKey: .kind)
        federation = try values.decode(FederationDescriptor.self, forKey: .federation)
        temporalBucketSeconds = try values.decode(Int.self, forKey: .temporalBucketSeconds)
        temporalBucketScheduleSeconds = try values.decodeIfPresent(
            [Int].self,
            forKey: .temporalBucketScheduleSeconds
        )
        attachmentDefaultTTLSeconds = try values.decodeIfPresent(
            Int.self,
            forKey: .attachmentDefaultTTLSeconds
        )
        attachmentMaxTTLSeconds = try values.decodeIfPresent(
            Int.self,
            forKey: .attachmentMaxTTLSeconds
        )
        attachmentsEnabled = try values.decodeIfPresent(Bool.self, forKey: .attachmentsEnabled)
        attachmentStorageBackend = try values.decodeIfPresent(
            String.self,
            forKey: .attachmentStorageBackend
        )
        hiddenRetrieval = try values.decodeIfPresent(
            HiddenRetrievalSupport.self,
            forKey: .hiddenRetrieval
        )
        onionTransport = try values.decodeIfPresent(
            OnionTransportSupport.self,
            forKey: .onionTransport
        )
        mixnetTransport = try values.decodeIfPresent(
            MixnetTransportSupport.self,
            forKey: .mixnetTransport
        )
        wakeSupport = try values.decodeIfPresent(
            DecentralizedWakeSupport.self,
            forKey: .wakeSupport
        )
        relayName = try values.decodeIfPresent(String.self, forKey: .relayName)
        operatorNote = try values.decodeIfPresent(String.self, forKey: .operatorNote)
        softwareVersion = try values.decodeIfPresent(String.self, forKey: .softwareVersion)
        protocolCapabilities = try values.decodeIfPresent(
            RelayCapabilityManifestV2.self,
            forKey: .protocolCapabilities
        )
        requiresPassword = try values.decodeIfPresent(Bool.self, forKey: .requiresPassword)
        tlsEnabled = try values.decodeIfPresent(Bool.self, forKey: .tlsEnabled)
        transport = try values.decodeIfPresent(RelayEndpointTransport.self, forKey: .transport)
        federationCoordinatorEndpoints = try values.decodeIfPresent(
            [RelayEndpoint].self,
            forKey: .federationCoordinatorEndpoints
        )
        coordinatorReportedRelayCount = try values.decodeIfPresent(
            Int.self,
            forKey: .coordinatorReportedRelayCount
        )
        coordinatorRegistrationAuthRequired = try values.decodeIfPresent(
            Bool.self,
            forKey: .coordinatorRegistrationAuthRequired
        )
        curatedStrictPolicyEnabled = try values.decodeIfPresent(
            Bool.self,
            forKey: .curatedStrictPolicyEnabled
        )
        curatedCoordinatorQuorum = try values.decodeIfPresent(
            Int.self,
            forKey: .curatedCoordinatorQuorum
        )
        curatedRequireSignedDirectory = try values.decodeIfPresent(
            Bool.self,
            forKey: .curatedRequireSignedDirectory
        )
        federationDirectoryPublicKey = try values.decodeIfPresent(
            Data.self,
            forKey: .federationDirectoryPublicKey
        )
        knownOpenPeers = try values.decodeIfPresent(
            [RelayEndpoint].self,
            forKey: .knownOpenPeers
        )
        openFederationDiscovery = try values.decodeIfPresent(
            OpenFederationDiscoverySupport.self,
            forKey: .openFederationDiscovery
        )
        advertisedAt = try values.decode(Date.self, forKey: .advertisedAt)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .kind,
                in: values,
                debugDescription: "Relay information is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Relay information")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(kind, forKey: .kind)
        try values.encode(federation, forKey: .federation)
        try values.encode(temporalBucketSeconds, forKey: .temporalBucketSeconds)
        try values.encode(temporalBucketScheduleSeconds, forKey: .temporalBucketScheduleSeconds)
        try values.encode(attachmentDefaultTTLSeconds, forKey: .attachmentDefaultTTLSeconds)
        try values.encode(attachmentMaxTTLSeconds, forKey: .attachmentMaxTTLSeconds)
        try values.encode(attachmentsEnabled, forKey: .attachmentsEnabled)
        try values.encode(attachmentStorageBackend, forKey: .attachmentStorageBackend)
        try values.encode(hiddenRetrieval, forKey: .hiddenRetrieval)
        try values.encode(onionTransport, forKey: .onionTransport)
        try values.encode(mixnetTransport, forKey: .mixnetTransport)
        try values.encode(wakeSupport, forKey: .wakeSupport)
        try values.encode(relayName, forKey: .relayName)
        try values.encode(operatorNote, forKey: .operatorNote)
        try values.encode(softwareVersion, forKey: .softwareVersion)
        try values.encode(protocolCapabilities, forKey: .protocolCapabilities)
        try values.encode(requiresPassword, forKey: .requiresPassword)
        try values.encode(tlsEnabled, forKey: .tlsEnabled)
        try values.encode(transport, forKey: .transport)
        try values.encode(federationCoordinatorEndpoints, forKey: .federationCoordinatorEndpoints)
        try values.encode(coordinatorReportedRelayCount, forKey: .coordinatorReportedRelayCount)
        try values.encode(
            coordinatorRegistrationAuthRequired,
            forKey: .coordinatorRegistrationAuthRequired
        )
        try values.encode(curatedStrictPolicyEnabled, forKey: .curatedStrictPolicyEnabled)
        try values.encode(curatedCoordinatorQuorum, forKey: .curatedCoordinatorQuorum)
        try values.encode(curatedRequireSignedDirectory, forKey: .curatedRequireSignedDirectory)
        try values.encode(federationDirectoryPublicKey, forKey: .federationDirectoryPublicKey)
        try values.encode(knownOpenPeers, forKey: .knownOpenPeers)
        try values.encode(openFederationDiscovery, forKey: .openFederationDiscovery)
        try values.encode(advertisedAt, forKey: .advertisedAt)
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
    static let nonceByteCount = 12
    static let tagByteCount = 16
    static let maximumEncodedBytes = 128 * 1_024

    let nonce: Data
    let ciphertext: Data
    let tag: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case nonce
        case ciphertext
        case tag
    }

    init(nonce: Data, ciphertext: Data, tag: Data) {
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }

    init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: EncryptedPayloadCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Encrypted payload fields must match the current schema exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        nonce = try values.decode(Data.self, forKey: .nonce)
        ciphertext = try values.decode(Data.self, forKey: .ciphertext)
        tag = try values.decode(Data.self, forKey: .tag)
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Encrypted attachment payload has invalid cryptographic field lengths"
                )
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "Encrypted attachment payload has invalid cryptographic field lengths"
                )
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(nonce, forKey: .nonce)
        try values.encode(ciphertext, forKey: .ciphertext)
        try values.encode(tag, forKey: .tag)
    }

    var isStructurallyValid: Bool {
        nonce.count == Self.nonceByteCount
            && tag.count == Self.tagByteCount
            && !ciphertext.isEmpty
            && ciphertext.count
                <= Self.maximumEncodedBytes - Self.nonceByteCount - Self.tagByteCount
    }
}

private struct EncryptedPayloadCodingKey: CodingKey {
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
    let tlsCertificateFingerprintSHA256: Data?
    let directorySigningPublicKey: Data?

    init(
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

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case host
        case port
        case useTLS
        case transport
        case tlsCertificateFingerprintSHA256
        case directorySigningPublicKey
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Relay endpoint")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            host: try values.decode(String.self, forKey: .host),
            port: try values.decode(UInt16.self, forKey: .port),
            useTLS: try values.decode(Bool.self, forKey: .useTLS),
            transport: try values.decode(RelayEndpointTransport.self, forKey: .transport),
            tlsCertificateFingerprintSHA256: try values.decodeIfPresent(
                Data.self,
                forKey: .tlsCertificateFingerprintSHA256
            ),
            directorySigningPublicKey: try values.decodeIfPresent(
                Data.self,
                forKey: .directorySigningPublicKey
            )
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .host,
                in: values,
                debugDescription: "Relay endpoint is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Relay endpoint")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(host, forKey: .host)
        try values.encode(port, forKey: .port)
        try values.encode(useTLS, forKey: .useTLS)
        try values.encode(transport, forKey: .transport)
        try values.encode(
            tlsCertificateFingerprintSHA256,
            forKey: .tlsCertificateFingerprintSHA256
        )
        try values.encode(directorySigningPublicKey, forKey: .directorySigningPublicKey)
    }

    var isStructurallyValid: Bool {
        isBoundedModelText(host, maximumUTF8Bytes: 255)
            && port > 0
            && (tlsCertificateFingerprintSHA256.map { $0.count == 32 } ?? true)
            && (directorySigningPublicKey.map {
                $0.count == OQSSignatureVerifier.mlDSA65PublicKeyBytes
            } ?? true)
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

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case endpoint
        case relayInfo
        case lastHeartbeatAt
        case expiresAt
    }

    init(
        endpoint: RelayEndpoint,
        relayInfo: RelayInfo,
        lastHeartbeatAt: Date,
        expiresAt: Date
    ) {
        self.endpoint = endpoint
        self.relayInfo = relayInfo
        self.lastHeartbeatAt = canonicalModelDate(lastHeartbeatAt)
        self.expiresAt = canonicalModelDate(expiresAt)
    }

    init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: FederationNodeRecordCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Federation node fields must match the current schema exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            endpoint: try values.decode(RelayEndpoint.self, forKey: .endpoint),
            relayInfo: try values.decode(RelayInfo.self, forKey: .relayInfo),
            lastHeartbeatAt: try values.decode(Date.self, forKey: .lastHeartbeatAt),
            expiresAt: try values.decode(Date.self, forKey: .expiresAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .endpoint,
                in: values,
                debugDescription: "Federation node record is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "Federation node record is structurally invalid"
                )
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(endpoint, forKey: .endpoint)
        try values.encode(relayInfo, forKey: .relayInfo)
        try values.encode(lastHeartbeatAt, forKey: .lastHeartbeatAt)
        try values.encode(expiresAt, forKey: .expiresAt)
    }

    var isStructurallyValid: Bool {
        endpoint.isStructurallyValid
            && relayInfo.isStructurallyValid
            && isCanonicalModelTimestamp(lastHeartbeatAt)
            && isCanonicalModelTimestamp(expiresAt)
            && expiresAt > lastHeartbeatAt
            && expiresAt.timeIntervalSince(lastHeartbeatAt) <= 900
    }
}

private struct FederationNodeRecordCodingKey: CodingKey {
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

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case mode
        case federationName
        case issuedAt
        case validUntil
        case maxStalenessSeconds
        case nodes
        case signatureAlgorithm
        case signature
    }

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
        self.issuedAt = canonicalModelDate(issuedAt)
        self.validUntil = canonicalModelDate(validUntil)
        self.maxStalenessSeconds = min(max(1, maxStalenessSeconds), 86_400)
        self.nodes = Array(nodes.prefix(10_000))
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Federation directory snapshot")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        version = try values.decode(Int.self, forKey: .version)
        mode = try values.decode(FederationMode.self, forKey: .mode)
        federationName = try values.decodeIfPresent(String.self, forKey: .federationName)
        issuedAt = try values.decode(Date.self, forKey: .issuedAt)
        validUntil = try values.decode(Date.self, forKey: .validUntil)
        maxStalenessSeconds = try values.decode(Int.self, forKey: .maxStalenessSeconds)
        nodes = try values.decode([FederationNodeRecord].self, forKey: .nodes)
        signatureAlgorithm = try values.decodeIfPresent(String.self, forKey: .signatureAlgorithm)
        signature = try values.decodeIfPresent(Data.self, forKey: .signature)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: values,
                debugDescription: "Federation directory snapshot is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Federation directory snapshot")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(mode, forKey: .mode)
        try values.encode(federationName, forKey: .federationName)
        try values.encode(issuedAt, forKey: .issuedAt)
        try values.encode(validUntil, forKey: .validUntil)
        try values.encode(maxStalenessSeconds, forKey: .maxStalenessSeconds)
        try values.encode(nodes, forKey: .nodes)
        try values.encode(signatureAlgorithm, forKey: .signatureAlgorithm)
        try values.encode(signature, forKey: .signature)
    }

    var isStructurallyValid: Bool {
        guard version == 1,
              federationName.map({
                  isBoundedModelText($0, maximumUTF8Bytes: 1_024)
              }) ?? true,
              isCanonicalModelTimestamp(issuedAt),
              isCanonicalModelTimestamp(validUntil),
              validUntil > issuedAt,
              (1...86_400).contains(maxStalenessSeconds),
              validUntil.timeIntervalSince(issuedAt) <= TimeInterval(maxStalenessSeconds),
              nodes.count <= 10_000,
              nodes.allSatisfy(\.isStructurallyValid) else {
            return false
        }
        let endpointKeys = nodes.map { relayEndpointModelKey($0.endpoint) }
        guard Set(endpointKeys).count == nodes.count else { return false }
        switch (signatureAlgorithm, signature) {
        case (nil, nil):
            return true
        case (FederationDirectorySignature.algorithm?, let signature?):
            return signature.count == OQSSignatureVerifier.mlDSA65SignatureBytes
        default:
            return false
        }
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
    static let idempotencyKeyBytes = 32

    let attachmentId: UUID
    let chunkIndex: Int
    let payload: EncryptedPayload
    let ttlSeconds: Int?
    let idempotencyKey: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case attachmentId
        case chunkIndex
        case payload
        case ttlSeconds
        case idempotencyKey
    }

    init(
        attachmentId: UUID,
        chunkIndex: Int,
        payload: EncryptedPayload,
        ttlSeconds: Int? = nil,
        idempotencyKey: Data
    ) {
        self.attachmentId = attachmentId
        self.chunkIndex = chunkIndex
        self.payload = payload
        self.ttlSeconds = ttlSeconds
        self.idempotencyKey = idempotencyKey
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Attachment upload request")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            attachmentId: try values.decode(UUID.self, forKey: .attachmentId),
            chunkIndex: try values.decode(Int.self, forKey: .chunkIndex),
            payload: try values.decode(EncryptedPayload.self, forKey: .payload),
            ttlSeconds: try values.decodeIfPresent(Int.self, forKey: .ttlSeconds),
            idempotencyKey: try values.decode(Data.self, forKey: .idempotencyKey)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .chunkIndex,
                in: values,
                debugDescription: "Attachment upload request is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Attachment upload request")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(attachmentId, forKey: .attachmentId)
        try values.encode(chunkIndex, forKey: .chunkIndex)
        try values.encode(payload, forKey: .payload)
        try values.encode(ttlSeconds, forKey: .ttlSeconds)
        try values.encode(idempotencyKey, forKey: .idempotencyKey)
    }

    var isStructurallyValid: Bool {
        let payloadBytes = payload.nonce.count + payload.ciphertext.count + payload.tag.count
        return (0..<AttachmentChunk.maximumChunkCount).contains(chunkIndex)
            && payload.isStructurallyValid
            && payloadBytes <= AttachmentChunk.maximumPayloadBytes
            && (ttlSeconds.map { (60...2_592_000).contains($0) } ?? true)
            && idempotencyKey.count == Self.idempotencyKeyBytes
    }
}

struct FetchAttachmentRequest: Codable, Equatable {
    let attachmentId: UUID
    let chunkIndex: Int

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case attachmentId
        case chunkIndex
    }

    init(attachmentId: UUID, chunkIndex: Int) {
        self.attachmentId = attachmentId
        self.chunkIndex = chunkIndex
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Attachment fetch request")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            attachmentId: try values.decode(UUID.self, forKey: .attachmentId),
            chunkIndex: try values.decode(Int.self, forKey: .chunkIndex)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .chunkIndex,
                in: values,
                debugDescription: "Attachment fetch request is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Attachment fetch request")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(attachmentId, forKey: .attachmentId)
        try values.encode(chunkIndex, forKey: .chunkIndex)
    }

    var isStructurallyValid: Bool {
        (0..<AttachmentChunk.maximumChunkCount).contains(chunkIndex)
    }
}

struct AttachmentChunk: Codable, Equatable {
    static let maximumChunkCount = 512
    static let maximumPayloadBytes = 128 * 1_024

    let attachmentId: UUID
    let chunkIndex: Int
    let payload: EncryptedPayload

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case attachmentId
        case chunkIndex
        case payload
    }

    init(attachmentId: UUID, chunkIndex: Int, payload: EncryptedPayload) {
        self.attachmentId = attachmentId
        self.chunkIndex = chunkIndex
        self.payload = payload
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Attachment chunk")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            attachmentId: try values.decode(UUID.self, forKey: .attachmentId),
            chunkIndex: try values.decode(Int.self, forKey: .chunkIndex),
            payload: try values.decode(EncryptedPayload.self, forKey: .payload)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .chunkIndex,
                in: values,
                debugDescription: "Attachment chunk is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Attachment chunk")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(attachmentId, forKey: .attachmentId)
        try values.encode(chunkIndex, forKey: .chunkIndex)
        try values.encode(payload, forKey: .payload)
    }

    var isStructurallyValid: Bool {
        let payloadBytes = payload.nonce.count + payload.ciphertext.count + payload.tag.count
        return (0..<Self.maximumChunkCount).contains(chunkIndex)
            && payload.isStructurallyValid
            && payloadBytes <= Self.maximumPayloadBytes
    }
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
