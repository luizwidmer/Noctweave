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

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard relayIsBoundedRequiredText(host, maximumBytes: 255),
                  port > 0,
                  tlsCertificateFingerprintSHA256.map({ $0.count == 32 }) ?? true else {
                return false
            }
            if let directorySigningPublicKey {
                return try SigningKeyPair.isValidPublicKeyThrowing(
                    directorySigningPublicKey
                )
            }
            return true
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case host
        case port
        case useTLS
        case transport
        case tlsCertificateFingerprintSHA256
        case directorySigningPublicKey
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: RelayEndpointCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Relay endpoint fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        host = try container.decode(String.self, forKey: .host)
        port = try container.decode(UInt16.self, forKey: .port)
        useTLS = try container.decode(Bool.self, forKey: .useTLS)
        transport = try container.decode(RelayEndpointTransport.self, forKey: .transport)
        tlsCertificateFingerprintSHA256 = try container.decodeIfPresent(Data.self, forKey: .tlsCertificateFingerprintSHA256)
        directorySigningPublicKey = try container.decodeIfPresent(Data.self, forKey: .directorySigningPublicKey)
        guard try isStructurallyValidThrowing else {
            throw relayWireError(decoder, "Relay endpoint is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw relayWireError(encoder, "Relay endpoint is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(host, forKey: .host)
        try container.encode(port, forKey: .port)
        try container.encode(useTLS, forKey: .useTLS)
        try container.encode(transport, forKey: .transport)
        if let tlsCertificateFingerprintSHA256 {
            try container.encode(
                tlsCertificateFingerprintSHA256,
                forKey: .tlsCertificateFingerprintSHA256
            )
        } else {
            try container.encodeNil(forKey: .tlsCertificateFingerprintSHA256)
        }
        if let directorySigningPublicKey {
            try container.encode(directorySigningPublicKey, forKey: .directorySigningPublicKey)
        } else {
            try container.encodeNil(forKey: .directorySigningPublicKey)
        }
    }
}

private struct RelayEndpointCodingKey: CodingKey {
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

public enum RelayKind: String, Codable, CaseIterable {
    case standard
    case passthrough
    case host
    // Decode-only legacy federation topology values.
    case discovery
    case bridge
    case privateRelay
    case coordinator

    public static var allCases: [RelayKind] {
        [.standard, .passthrough, .host]
    }

    public var isCurrentTopologyRole: Bool {
        Self.allCases.contains(self)
    }
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

    public var isStructurallyValid: Bool {
        relayIsBoundedText(name, maximumBytes: 1_024)
            && relayIsBoundedText(description, maximumBytes: 1_024)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case mode
        case name
        case description
    }

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mode = try container.decode(FederationMode.self, forKey: .mode)
        name = try container.decodeIfPresent(String.self, forKey: .name)
        description = try container.decodeIfPresent(String.self, forKey: .description)
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Federation descriptor is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Federation descriptor is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(mode, forKey: .mode)
        try container.encode(name, forKey: .name)
        try container.encode(description, forKey: .description)
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

    public var isStructurallyValid: Bool {
        relayIsBoundedRequiredText(replicaId, maximumBytes: 1_024)
            && relayIsBoundedRequiredText(operatorId, maximumBytes: 1_024)
            && endpoint.isStructurallyValidRelationshipRouteEndpointV2
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case replicaId
        case operatorId
        case endpoint
    }

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        replicaId = try container.decode(String.self, forKey: .replicaId)
        operatorId = try container.decode(String.self, forKey: .operatorId)
        endpoint = try container.decode(RelayEndpoint.self, forKey: .endpoint)
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Hidden retrieval replica is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Hidden retrieval replica is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(replicaId, forKey: .replicaId)
        try container.encode(operatorId, forKey: .operatorId)
        try container.encode(endpoint, forKey: .endpoint)
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

    public var isStructurallyValid: Bool {
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
        let endpointKeys = replicas.map { relayEndpointStructuralKey($0.endpoint) }
        return Set(replicaIDs).count == replicas.count
            && Set(operatorIDs).count == replicas.count
            && Set(endpointKeys).count == replicas.count
            && (mode != .replicatedXorPIR || replicas.count >= 2)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case mode
        case defaultCoverSetSize
        case maxCoverSetSize
        case replicatedXorPIRReplicas
    }

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mode = try container.decode(HiddenRetrievalMode.self, forKey: .mode)
        defaultCoverSetSize = try container.decode(Int.self, forKey: .defaultCoverSetSize)
        maxCoverSetSize = try container.decode(Int.self, forKey: .maxCoverSetSize)
        replicatedXorPIRReplicas = try container.decodeIfPresent(
            [HiddenRetrievalPIRReplica].self,
            forKey: .replicatedXorPIRReplicas
        )
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Hidden retrieval support is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Hidden retrieval support is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(mode, forKey: .mode)
        try container.encode(defaultCoverSetSize, forKey: .defaultCoverSetSize)
        try container.encode(maxCoverSetSize, forKey: .maxCoverSetSize)
        try container.encode(replicatedXorPIRReplicas, forKey: .replicatedXorPIRReplicas)
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
        self.peerExchangeLimit = min(max(0, peerExchangeLimit), 128)
        self.requirePublicEndpoint = requirePublicEndpoint
        self.maxDHTRecords = min(max(1, maxDHTRecords), 256)
        self.maxDHTRecordsPerHost = min(
            min(max(1, maxDHTRecordsPerHost), 16),
            self.maxDHTRecords
        )
        self.maxDHTQueryRecords = min(max(1, maxDHTQueryRecords), 512)
    }

    public var isStructurallyValid: Bool {
        (0...128).contains(peerExchangeLimit)
            && (1...256).contains(maxDHTRecords)
            && (1...16).contains(maxDHTRecordsPerHost)
            && maxDHTRecordsPerHost <= maxDHTRecords
            && (1...512).contains(maxDHTQueryRecords)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case dhtNodeEnabled
        case peerExchangeEnabled
        case peerExchangeLimit
        case requirePublicEndpoint
        case maxDHTRecords
        case maxDHTRecordsPerHost
        case maxDHTQueryRecords
    }

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        dhtNodeEnabled = try container.decode(Bool.self, forKey: .dhtNodeEnabled)
        peerExchangeEnabled = try container.decode(Bool.self, forKey: .peerExchangeEnabled)
        peerExchangeLimit = try container.decode(Int.self, forKey: .peerExchangeLimit)
        requirePublicEndpoint = try container.decode(Bool.self, forKey: .requirePublicEndpoint)
        maxDHTRecords = try container.decode(Int.self, forKey: .maxDHTRecords)
        maxDHTRecordsPerHost = try container.decode(Int.self, forKey: .maxDHTRecordsPerHost)
        maxDHTQueryRecords = try container.decode(Int.self, forKey: .maxDHTQueryRecords)
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Open federation discovery support is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Open federation discovery support is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(dhtNodeEnabled, forKey: .dhtNodeEnabled)
        try container.encode(peerExchangeEnabled, forKey: .peerExchangeEnabled)
        try container.encode(peerExchangeLimit, forKey: .peerExchangeLimit)
        try container.encode(requirePublicEndpoint, forKey: .requirePublicEndpoint)
        try container.encode(maxDHTRecords, forKey: .maxDHTRecords)
        try container.encode(maxDHTRecordsPerHost, forKey: .maxDHTRecordsPerHost)
        try container.encode(maxDHTQueryRecords, forKey: .maxDHTQueryRecords)
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
    public var iceService: RelayICEServiceDescriptorV1?
    public var relayName: String?
    public var operatorNote: String?
    public var softwareVersion: String?
    public var protocolCapabilities: RelayCapabilityManifestV2?
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
    public var relayIdentity: SignedRelayIdentityClaimV1?
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
        iceService: RelayICEServiceDescriptorV1? = nil,
        relayName: String? = nil,
        operatorNote: String? = nil,
        softwareVersion: String? = nil,
        protocolCapabilities: RelayCapabilityManifestV2? = nil,
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
        relayIdentity: SignedRelayIdentityClaimV1? = nil,
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
        self.iceService = iceService
        self.relayName = relayName
        self.operatorNote = operatorNote
        self.softwareVersion = softwareVersion
        self.protocolCapabilities = protocolCapabilities?.isStructurallyValid == true
            ? protocolCapabilities
            : nil
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
        self.relayIdentity = relayIdentity
        self.advertisedAt = relayCanonicalizedDate(advertisedAt)
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
        guard federation.isStructurallyValid,
              (0...86_400).contains(temporalBucketSeconds),
              relayIsCanonicalTimestamp(advertisedAt),
              relayIsBoundedText(attachmentStorageBackend, maximumBytes: 1_024),
              relayIsBoundedText(relayName, maximumBytes: 1_024),
              relayIsBoundedText(operatorNote, maximumBytes: 1_024),
              relayIsBoundedText(softwareVersion, maximumBytes: 1_024),
              hiddenRetrieval?.isStructurallyValid != false,
              onionTransport?.isStructurallyValid != false,
              mixnetTransport?.isStructurallyValid != false,
              relayIsValidWakeSupport(wakeSupport),
              iceService?.isStructurallyValid != false,
              protocolCapabilities?.isStructurallyValid != false,
              openFederationDiscovery?.isStructurallyValid != false,
              try relayIdentityIsValid else {
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
        if let endpoints = federationCoordinatorEndpoints,
           try !relayIsValidEndpointListThrowing(endpoints, maximumCount: 16) {
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
           try !SigningKeyPair.isValidPublicKeyThrowing(federationDirectoryPublicKey) {
            return false
        }
        if let knownOpenPeers,
           try !relayIsValidEndpointListThrowing(knownOpenPeers, maximumCount: 128) {
            return false
        }
        return true
        }
    }

    private var relayIdentityIsValid: Bool {
        get throws {
            guard let relayIdentity else {
                return true
            }
            guard let protocolCapabilities,
                  try relayIdentity.verifyThrowing(at: advertisedAt),
                  relayIdentity.claim.relayKind == kind,
                  relayIdentity.claim.federationMode == federation.mode,
                  relayIdentity.claim.federationName == federation.name,
                  relayIdentity.claim.capabilityDigest
                    == (try RelayIdentityClaimV1.capabilityDigest(for: protocolCapabilities)) else {
                return false
            }
            return true
        }
    }

    public var authenticatedRelayID: RelayIdentityIDV1? {
        guard let relayIdentity,
              (try? relayIdentity.verifyThrowing(at: advertisedAt)) == true else {
            return nil
        }
        return relayIdentity.claim.relayID
    }

    public var authenticatedNoctwebSuffix: NoctwebRelaySuffixV1? {
        guard authenticatedRelayID != nil else {
            return nil
        }
        return relayIdentity?.claim.noctwebSuffix
    }

    public func authenticated(
        by keyMaterial: RelayIdentityKeyMaterialV1,
        sequence: Int,
        advertisedEndpoints: [RelayEndpoint],
        noctwebSuffix: NoctwebRelaySuffixV1?,
        hostSigningPublicKey: Data? = nil,
        lifetime: TimeInterval = 24 * 60 * 60,
        precomputedIdentity: SignedRelayIdentityClaimV1? = nil
    ) throws -> RelayInfo {
        guard let protocolCapabilities else {
            throw CryptoError.invalidPayload
        }
        var result = self
        if let precomputedIdentity {
            let capabilityDigest = try RelayIdentityClaimV1.capabilityDigest(
                for: protocolCapabilities
            )
            guard try precomputedIdentity.verifyThrowing(
                at: advertisedAt
            ),
            precomputedIdentity.claim.relayID == keyMaterial.relayID,
            precomputedIdentity.claim.relayKind == kind,
            precomputedIdentity.claim.federationMode == federation.mode,
            precomputedIdentity.claim.federationName == federation.name,
            precomputedIdentity.claim.noctwebSuffix == noctwebSuffix,
            precomputedIdentity.claim.hostSigningPublicKey
                == hostSigningPublicKey,
            precomputedIdentity.claim.capabilityDigest
                == capabilityDigest else {
                throw CryptoError.invalidPayload
            }
            result.relayIdentity = precomputedIdentity
        } else {
            result.relayIdentity = try keyMaterial.makeSignedClaim(
                sequence: sequence,
                relayKind: kind,
                federation: federation,
                advertisedEndpoints: advertisedEndpoints,
                noctwebSuffix: noctwebSuffix,
                hostSigningPublicKey: hostSigningPublicKey,
                capabilities: protocolCapabilities,
                issuedAt: advertisedAt,
                lifetime: lifetime
            )
        }
        guard try result.isStructurallyValidThrowing else {
            throw CryptoError.invalidPayload
        }
        return result
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
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
        case iceService
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
        case relayIdentity
        case advertisedAt
    }

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        kind = try container.decode(RelayKind.self, forKey: .kind)
        federation = try container.decode(FederationDescriptor.self, forKey: .federation)
        temporalBucketSeconds = try container.decode(Int.self, forKey: .temporalBucketSeconds)
        temporalBucketScheduleSeconds = try container.decodeIfPresent(
            [Int].self,
            forKey: .temporalBucketScheduleSeconds
        )
        attachmentDefaultTTLSeconds = try container.decodeIfPresent(
            Int.self,
            forKey: .attachmentDefaultTTLSeconds
        )
        attachmentMaxTTLSeconds = try container.decodeIfPresent(
            Int.self,
            forKey: .attachmentMaxTTLSeconds
        )
        attachmentsEnabled = try container.decodeIfPresent(Bool.self, forKey: .attachmentsEnabled)
        attachmentStorageBackend = try container.decodeIfPresent(
            String.self,
            forKey: .attachmentStorageBackend
        )
        hiddenRetrieval = try container.decodeIfPresent(HiddenRetrievalSupport.self, forKey: .hiddenRetrieval)
        onionTransport = try container.decodeIfPresent(OnionTransportSupport.self, forKey: .onionTransport)
        mixnetTransport = try container.decodeIfPresent(MixnetTransportSupport.self, forKey: .mixnetTransport)
        wakeSupport = try container.decodeIfPresent(DecentralizedWakeSupport.self, forKey: .wakeSupport)
        iceService = try container.decodeIfPresent(
            RelayICEServiceDescriptorV1.self,
            forKey: .iceService
        )
        relayName = try container.decodeIfPresent(String.self, forKey: .relayName)
        operatorNote = try container.decodeIfPresent(String.self, forKey: .operatorNote)
        softwareVersion = try container.decodeIfPresent(String.self, forKey: .softwareVersion)
        protocolCapabilities = try container.decodeIfPresent(
            RelayCapabilityManifestV2.self,
            forKey: .protocolCapabilities
        )
        requiresPassword = try container.decodeIfPresent(Bool.self, forKey: .requiresPassword)
        tlsEnabled = try container.decodeIfPresent(Bool.self, forKey: .tlsEnabled)
        transport = try container.decodeIfPresent(RelayEndpointTransport.self, forKey: .transport)
        federationCoordinatorEndpoints = try container.decodeIfPresent(
            [RelayEndpoint].self,
            forKey: .federationCoordinatorEndpoints
        )
        coordinatorReportedRelayCount = try container.decodeIfPresent(
            Int.self,
            forKey: .coordinatorReportedRelayCount
        )
        coordinatorRegistrationAuthRequired = try container.decodeIfPresent(
            Bool.self,
            forKey: .coordinatorRegistrationAuthRequired
        )
        curatedStrictPolicyEnabled = try container.decodeIfPresent(
            Bool.self,
            forKey: .curatedStrictPolicyEnabled
        )
        curatedCoordinatorQuorum = try container.decodeIfPresent(
            Int.self,
            forKey: .curatedCoordinatorQuorum
        )
        curatedRequireSignedDirectory = try container.decodeIfPresent(
            Bool.self,
            forKey: .curatedRequireSignedDirectory
        )
        federationDirectoryPublicKey = try container.decodeIfPresent(
            Data.self,
            forKey: .federationDirectoryPublicKey
        )
        knownOpenPeers = try container.decodeIfPresent([RelayEndpoint].self, forKey: .knownOpenPeers)
        openFederationDiscovery = try container.decodeIfPresent(
            OpenFederationDiscoverySupport.self,
            forKey: .openFederationDiscovery
        )
        relayIdentity = try container.decodeIfPresent(
            SignedRelayIdentityClaimV1.self,
            forKey: .relayIdentity
        )
        advertisedAt = try container.decode(Date.self, forKey: .advertisedAt)
        guard try isStructurallyValidThrowing else {
            throw relayWireError(decoder, "Relay information is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw relayWireError(encoder, "Relay information is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(kind, forKey: .kind)
        try container.encode(federation, forKey: .federation)
        try container.encode(temporalBucketSeconds, forKey: .temporalBucketSeconds)
        try container.encode(temporalBucketScheduleSeconds, forKey: .temporalBucketScheduleSeconds)
        try container.encode(attachmentDefaultTTLSeconds, forKey: .attachmentDefaultTTLSeconds)
        try container.encode(attachmentMaxTTLSeconds, forKey: .attachmentMaxTTLSeconds)
        try container.encode(attachmentsEnabled, forKey: .attachmentsEnabled)
        try container.encode(attachmentStorageBackend, forKey: .attachmentStorageBackend)
        try container.encode(hiddenRetrieval, forKey: .hiddenRetrieval)
        try container.encode(onionTransport, forKey: .onionTransport)
        try container.encode(mixnetTransport, forKey: .mixnetTransport)
        try container.encode(wakeSupport, forKey: .wakeSupport)
        try container.encode(iceService, forKey: .iceService)
        try container.encode(relayName, forKey: .relayName)
        try container.encode(operatorNote, forKey: .operatorNote)
        try container.encode(softwareVersion, forKey: .softwareVersion)
        try container.encode(protocolCapabilities, forKey: .protocolCapabilities)
        try container.encode(requiresPassword, forKey: .requiresPassword)
        try container.encode(tlsEnabled, forKey: .tlsEnabled)
        try container.encode(transport, forKey: .transport)
        try container.encode(federationCoordinatorEndpoints, forKey: .federationCoordinatorEndpoints)
        try container.encode(coordinatorReportedRelayCount, forKey: .coordinatorReportedRelayCount)
        try container.encode(
            coordinatorRegistrationAuthRequired,
            forKey: .coordinatorRegistrationAuthRequired
        )
        try container.encode(curatedStrictPolicyEnabled, forKey: .curatedStrictPolicyEnabled)
        try container.encode(curatedCoordinatorQuorum, forKey: .curatedCoordinatorQuorum)
        try container.encode(curatedRequireSignedDirectory, forKey: .curatedRequireSignedDirectory)
        try container.encode(federationDirectoryPublicKey, forKey: .federationDirectoryPublicKey)
        try container.encode(knownOpenPeers, forKey: .knownOpenPeers)
        try container.encode(openFederationDiscovery, forKey: .openFederationDiscovery)
        try container.encode(relayIdentity, forKey: .relayIdentity)
        try container.encode(advertisedAt, forKey: .advertisedAt)
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
    public var iceService: RelayICEServiceDescriptorV1?
    /// Application-neutral low-latency service policy. Optional storage keeps
    /// older encoded relay configurations compatible; nil means enabled.
    public var realtimeRoutesEnabled: Bool?
    public var sharedLogsEnabled: Bool?
    public var ephemeralPresenceEnabled: Bool?
    public var mediaBlobsEnabled: Bool?
    public var relayName: String?
    public var operatorNote: String?
    public var softwareVersion: String?
    public var accessPassword: String?
    public var coordinatorRegistrationToken: String?
    public var tlsEnabled: Bool
    public var advertisedTLSEnabled: Bool?
    /// True only when an operator has explicitly configured a trusted
    /// reverse proxy to terminate client TLS before the local listener.
    public var trustedReverseProxyTLS: Bool
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
    public var noctwebRelaySuffix: NoctwebRelaySuffixV1?
    /// Enables bounded Noctweb object and name hosting on a standard relay.
    /// Dedicated host relays always enable this capability.
    public var netHostEnabled: Bool?
    public var federationAllowList: [RelayEndpoint]
    public var allowPrivateFederationEndpoints: Bool
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
        iceService: RelayICEServiceDescriptorV1? = nil,
        realtimeRoutesEnabled: Bool = true,
        sharedLogsEnabled: Bool = true,
        ephemeralPresenceEnabled: Bool = true,
        mediaBlobsEnabled: Bool = true,
        relayName: String? = nil,
        operatorNote: String? = nil,
        softwareVersion: String? = nil,
        accessPassword: String? = nil,
        coordinatorRegistrationToken: String? = nil,
        tlsEnabled: Bool = false,
        advertisedTLSEnabled: Bool? = nil,
        trustedReverseProxyTLS: Bool = false,
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
        noctwebRelaySuffix: NoctwebRelaySuffixV1? = nil,
        netHostEnabled: Bool = false,
        federationAllowList: [RelayEndpoint] = [],
        allowPrivateFederationEndpoints: Bool = false,
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
        self.iceService = iceService?.isStructurallyValid == true ? iceService : nil
        self.realtimeRoutesEnabled = realtimeRoutesEnabled ? nil : false
        self.sharedLogsEnabled = sharedLogsEnabled ? nil : false
        self.ephemeralPresenceEnabled = ephemeralPresenceEnabled ? nil : false
        self.mediaBlobsEnabled = mediaBlobsEnabled ? nil : false
        self.relayName = relayName
        self.operatorNote = operatorNote
        self.softwareVersion = softwareVersion
        let normalizedAccessPassword = accessPassword?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.accessPassword = normalizedAccessPassword?.isEmpty == false ? normalizedAccessPassword : nil
        let normalizedRegistrationToken = coordinatorRegistrationToken?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.coordinatorRegistrationToken = normalizedRegistrationToken?.isEmpty == false ? normalizedRegistrationToken : nil
        self.tlsEnabled = tlsEnabled
        self.advertisedTLSEnabled = advertisedTLSEnabled
        self.trustedReverseProxyTLS = trustedReverseProxyTLS
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
        self.noctwebRelaySuffix = noctwebRelaySuffix
        self.netHostEnabled = kind == .host || netHostEnabled ? true : nil
        self.federationAllowList = Array(federationAllowList.prefix(256))
        self.allowPrivateFederationEndpoints = allowPrivateFederationEndpoints
        self.rendezvousTransportEnabled = rendezvousTransportEnabled ? true : nil
    }

    public var isRendezvousTransportEnabled: Bool {
        rendezvousTransportEnabled == true
    }

    public var isNetHostEnabled: Bool {
        kind == .host || netHostEnabled == true
    }

    public var areRealtimeRoutesEnabled: Bool {
        kind == .standard && realtimeRoutesEnabled != false
    }

    public var areSharedLogsEnabled: Bool {
        kind == .standard && sharedLogsEnabled != false
    }

    public var isEphemeralPresenceEnabled: Bool {
        kind == .standard && ephemeralPresenceEnabled != false
    }

    public var areMediaBlobsEnabled: Bool {
        kind == .standard
            && attachmentsEnabled != false
            && mediaBlobsEnabled != false
    }

    public var transportConfidentiality: RelayTransportConfidentialityConfiguration {
        RelayTransportConfidentialityConfiguration(
            listenerTLS: tlsEnabled,
            trustedReverseProxyTLS: trustedReverseProxyTLS
        )
    }

    public func effectiveTransportConfidentiality(
        isLiteralLoopbackSource: Bool
    ) -> EffectiveTransportConfidentiality {
        transportConfidentiality.effectiveTransport(
            isLiteralLoopbackSource: isLiteralLoopbackSource
        )
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
            iceService: iceService,
            relayName: relayName,
            operatorNote: operatorNote,
            softwareVersion: softwareVersion,
            protocolCapabilities: .advertised(
                relayKind: kind,
                attachmentsEnabled: attachmentsEnabled != false,
                wakeEnabled: wakeSupport != nil,
                hiddenRetrievalEnabled: advertisedHiddenRetrieval != nil,
                onionEnabled: advertisedOnionTransport != nil,
                mixnetEnabled: advertisedMixnetTransport != nil,
                openDiscoveryEnabled: advertisedOpenFederationDiscovery?.dhtNodeEnabled == true,
                rendezvousTransportEnabled: isRendezvousTransportEnabled,
                federationForwardingEnabled: kind == .standard && federation.mode != .solo,
                netHostEnabled: isNetHostEnabled,
                iceServiceEnabled: iceService != nil,
                realtimeRoutesEnabled: areRealtimeRoutesEnabled,
                sharedLogsEnabled: areSharedLogsEnabled,
                ephemeralPresenceEnabled: isEphemeralPresenceEnabled,
                mediaBlobsEnabled: areMediaBlobsEnabled
            ),
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

public enum RelayModuleID: String, Codable, CaseIterable {
    case core = "nw.core"
    case opaqueRoute = "nw.opaque-route"
    case rendezvousTransport = "nw.rendezvous-transport"
    case blobs = "nw.blobs"
    case realtimeRoute = "nw.realtime-route"
    case sharedLog = "nw.shared-log"
    case ephemeralPresence = "nw.ephemeral-presence"
    case mediaBlobs = "nw.media-blobs"
    case iceService = "nw.ice-service"
    case federation = "nw.federation"
    case federationForward = "nw.federation-forward"
    case openDiscovery = "nw.open-discovery"
    case netPassthrough = "nw.net-passthrough"
    case netHost = "nw.net-host"

    public var currentVersion: Int {
        switch self {
        case .core, .opaqueRoute, .rendezvousTransport:
            return 2
        case .blobs, .realtimeRoute, .sharedLog, .ephemeralPresence, .mediaBlobs, .iceService,
             .federation, .federationForward, .openDiscovery, .netPassthrough, .netHost:
            return 1
        }
    }
}

public enum RelayMethodID: String, Codable, CaseIterable {
    case health
    case info
    case create
    case renew
    case teardown
    case append
    case sync
    case commit
    case register
    case delete
    case upload
    case fetch
    case list
    case namespace
    case claim
    case rotate
    case publishDHT = "publish-dht"
    case listDHT = "list-dht"
    case forward
    case deliver
    case put
    case bind
    case get
    case resolve
    case has
    case release
    case subscribe
    case unsubscribe
    case acquire
    case renewLease = "renew-lease"
}

public struct RelayOperationBinding: Codable, Equatable, Hashable {
    public let module: RelayModuleID
    public let version: Int
    public let method: RelayMethodID

    public init(module: RelayModuleID, version: Int, method: RelayMethodID) {
        self.module = module
        self.version = version
        self.method = method
    }

    public var isCurrent: Bool {
        version == module.currentVersion && Self.allowedMethods[module]?.contains(method) == true
    }

    private static let allowedMethods: [RelayModuleID: Set<RelayMethodID>] = [
        .core: [.health, .info],
        .opaqueRoute: [.create, .renew, .teardown, .append, .sync, .commit],
        .rendezvousTransport: [.register, .append, .sync, .delete],
        .blobs: [.upload, .fetch],
        .realtimeRoute: [.create, .append, .subscribe, .sync, .unsubscribe],
        .sharedLog: [.create, .append, .sync],
        .ephemeralPresence: [.acquire, .renewLease, .release, .list],
        .mediaBlobs: [.create, .upload, .fetch, .release],
        .iceService: [.acquire],
        .federation: [
            .register,
            .list,
            .namespace,
            .claim,
            .rotate,
            .release
        ],
        .federationForward: [.forward, .deliver, .get, .resolve],
        .openDiscovery: [.publishDHT, .listDHT],
        .netPassthrough: [.forward],
        .netHost: [.put, .bind, .get, .resolve, .has, .release]
    ]
}

public struct CreateOpaqueRouteRelayRequestV2: Codable, Equatable {
    public let request: OpaqueRouteCreateRequestV2
    public let renewCapability: RouteRenewCapabilityV2

    public init(
        request: OpaqueRouteCreateRequestV2,
        renewCapability: RouteRenewCapabilityV2
    ) {
        self.request = request
        self.renewCapability = renewCapability
    }

    public var isStructurallyValid: Bool {
        request.isStructurallyValid && renewCapability.isStructurallyValid
    }
}

public struct RenewOpaqueRouteRelayRequestV2: Codable, Equatable {
    public let request: OpaqueRouteRenewRequestV2
    public let renewCapability: RouteRenewCapabilityV2

    public init(
        request: OpaqueRouteRenewRequestV2,
        renewCapability: RouteRenewCapabilityV2
    ) {
        self.request = request
        self.renewCapability = renewCapability
    }

    public var isStructurallyValid: Bool {
        request.isStructurallyValid && renewCapability.isStructurallyValid
    }
}

public struct TeardownOpaqueRouteRelayRequestV2: Codable, Equatable {
    public let request: OpaqueRouteTeardownRequestV2
    public let teardownCapability: RouteTeardownCapabilityV2

    public init(
        request: OpaqueRouteTeardownRequestV2,
        teardownCapability: RouteTeardownCapabilityV2
    ) {
        self.request = request
        self.teardownCapability = teardownCapability
    }

    public var isStructurallyValid: Bool {
        request.isStructurallyValid && teardownCapability.isStructurallyValid
    }
}

public struct AppendOpaqueRouteRelayRequestV2: Codable, Equatable {
    public let packet: OpaqueRoutePacketV2
    public let sendCapability: RouteSendCapabilityV2

    public init(packet: OpaqueRoutePacketV2, sendCapability: RouteSendCapabilityV2) {
        self.packet = packet
        self.sendCapability = sendCapability
    }

    public var isStructurallyValid: Bool {
        packet.isStructurallyValid && sendCapability.isStructurallyValid
    }
}

public struct SyncOpaqueRouteRelayRequestV2: Codable, Equatable {
    public let request: OpaqueRouteSyncRequestV2
    public let readCredential: RouteReadCredentialV2

    public init(request: OpaqueRouteSyncRequestV2, readCredential: RouteReadCredentialV2) {
        self.request = request
        self.readCredential = readCredential
    }

    public var isStructurallyValid: Bool {
        request.isStructurallyValid && readCredential.isStructurallyValid
    }
}

public struct CommitOpaqueRouteRelayRequestV2: Codable, Equatable {
    public let request: OpaqueRouteCommitRequestV2
    public let readCredential: RouteReadCredentialV2

    public init(request: OpaqueRouteCommitRequestV2, readCredential: RouteReadCredentialV2) {
        self.request = request
        self.readCredential = readCredential
    }

    public var isStructurallyValid: Bool {
        request.isStructurallyValid && readCredential.isStructurallyValid
    }
}

public struct UploadAttachmentRequest: Codable, Equatable {
    public static let idempotencyKeyBytes = 32

    public let attachmentId: UUID
    public let chunkIndex: Int
    public let payload: EncryptedPayload
    public let ttlSeconds: Int?
    public let idempotencyKey: Data

    public init(
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

    public var isStructurallyValid: Bool {
        let payloadBytes = payload.nonce.count + payload.ciphertext.count + payload.tag.count
        return (0..<AttachmentChunk.maximumChunkCount).contains(chunkIndex)
            && payload.isStructurallyValid
            && payloadBytes <= AttachmentChunk.maximumPayloadBytes
            && (ttlSeconds.map { (60...2_592_000).contains($0) } ?? true)
            && idempotencyKey.count == Self.idempotencyKeyBytes
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case attachmentId
        case chunkIndex
        case payload
        case ttlSeconds
        case idempotencyKey
    }

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        attachmentId = try container.decode(UUID.self, forKey: .attachmentId)
        chunkIndex = try container.decode(Int.self, forKey: .chunkIndex)
        payload = try container.decode(EncryptedPayload.self, forKey: .payload)
        ttlSeconds = try container.decodeIfPresent(Int.self, forKey: .ttlSeconds)
        idempotencyKey = try container.decode(Data.self, forKey: .idempotencyKey)
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Attachment upload request is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Attachment upload request is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(attachmentId, forKey: .attachmentId)
        try container.encode(chunkIndex, forKey: .chunkIndex)
        try container.encode(payload, forKey: .payload)
        try container.encode(ttlSeconds, forKey: .ttlSeconds)
        try container.encode(idempotencyKey, forKey: .idempotencyKey)
    }
}

public struct FetchAttachmentRequest: Codable, Equatable {
    public let attachmentId: UUID
    public let chunkIndex: Int

    public init(attachmentId: UUID, chunkIndex: Int) {
        self.attachmentId = attachmentId
        self.chunkIndex = chunkIndex
    }

    public var isStructurallyValid: Bool {
        (0..<AttachmentChunk.maximumChunkCount).contains(chunkIndex)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case attachmentId
        case chunkIndex
    }

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        attachmentId = try container.decode(UUID.self, forKey: .attachmentId)
        chunkIndex = try container.decode(Int.self, forKey: .chunkIndex)
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Attachment fetch request is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Attachment fetch request is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(attachmentId, forKey: .attachmentId)
        try container.encode(chunkIndex, forKey: .chunkIndex)
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

    public var isStructurallyValid: Bool {
        endpoint.isStructurallyValid
            && relayInfo.isStructurallyValid
            && (ttlSeconds.map { (1...900).contains($0) } ?? true)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case endpoint
        case relayInfo
        case ttlSeconds
    }

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        endpoint = try container.decode(RelayEndpoint.self, forKey: .endpoint)
        relayInfo = try container.decode(RelayInfo.self, forKey: .relayInfo)
        ttlSeconds = try container.decodeIfPresent(Int.self, forKey: .ttlSeconds)
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Federation node registration request is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Federation node registration request is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(endpoint, forKey: .endpoint)
        try container.encode(relayInfo, forKey: .relayInfo)
        try container.encode(ttlSeconds, forKey: .ttlSeconds)
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

    public var isStructurallyValid: Bool {
        relayIsBoundedText(federationName, maximumBytes: 1_024)
            && (maxStalenessSeconds.map { (1...86_400).contains($0) } ?? true)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case mode
        case federationName
        case onlyHealthy
        case maxStalenessSeconds
        case requireSignedSnapshot
    }

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mode = try container.decodeIfPresent(FederationMode.self, forKey: .mode)
        federationName = try container.decodeIfPresent(String.self, forKey: .federationName)
        onlyHealthy = try container.decodeIfPresent(Bool.self, forKey: .onlyHealthy)
        maxStalenessSeconds = try container.decodeIfPresent(Int.self, forKey: .maxStalenessSeconds)
        requireSignedSnapshot = try container.decodeIfPresent(
            Bool.self,
            forKey: .requireSignedSnapshot
        )
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Federation node list request is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Federation node list request is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(mode, forKey: .mode)
        try container.encode(federationName, forKey: .federationName)
        try container.encode(onlyHealthy, forKey: .onlyHealthy)
        try container.encode(maxStalenessSeconds, forKey: .maxStalenessSeconds)
        try container.encode(requireSignedSnapshot, forKey: .requireSignedSnapshot)
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
        self.lastHeartbeatAt = relayCanonicalizedDate(lastHeartbeatAt)
        self.expiresAt = relayCanonicalizedDate(expiresAt)
    }

    public var isStructurallyValid: Bool {
        endpoint.isStructurallyValidRelationshipRouteEndpointV2
            && relayInfo.isStructurallyValid
            && relayIsCanonicalTimestamp(lastHeartbeatAt)
            && relayIsCanonicalTimestamp(expiresAt)
            && expiresAt > lastHeartbeatAt
            && expiresAt.timeIntervalSince(lastHeartbeatAt) <= 900
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case endpoint
        case relayInfo
        case lastHeartbeatAt
        case expiresAt
    }

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        endpoint = try container.decode(RelayEndpoint.self, forKey: .endpoint)
        relayInfo = try container.decode(RelayInfo.self, forKey: .relayInfo)
        lastHeartbeatAt = try container.decode(Date.self, forKey: .lastHeartbeatAt)
        expiresAt = try container.decode(Date.self, forKey: .expiresAt)
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Federation node record is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Federation node record is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(endpoint, forKey: .endpoint)
        try container.encode(relayInfo, forKey: .relayInfo)
        try container.encode(lastHeartbeatAt, forKey: .lastHeartbeatAt)
        try container.encode(expiresAt, forKey: .expiresAt)
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
        self.issuedAt = relayCanonicalizedDate(issuedAt)
        self.validUntil = relayCanonicalizedDate(validUntil)
        self.maxStalenessSeconds = min(max(1, maxStalenessSeconds), 86_400)
        self.nodes = Array(nodes.prefix(10_000))
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }

    public var isStructurallyValid: Bool {
        guard version == 1,
              relayIsBoundedText(federationName, maximumBytes: 1_024),
              relayIsCanonicalTimestamp(issuedAt),
              relayIsCanonicalTimestamp(validUntil),
              validUntil > issuedAt,
              (1...86_400).contains(maxStalenessSeconds),
              validUntil.timeIntervalSince(issuedAt) <= TimeInterval(maxStalenessSeconds),
              nodes.count <= 10_000,
              nodes.allSatisfy(\.isStructurallyValid) else {
            return false
        }
        let endpointKeys = nodes.map { relayEndpointStructuralKey($0.endpoint) }
        guard Set(endpointKeys).count == nodes.count else { return false }
        switch (signatureAlgorithm, signature) {
        case (nil, nil):
            return true
        case (FederationDirectorySignature.algorithm?, let signature?):
            return signature.count == NoctweaveSignedGroupV2.signatureBytes
        default:
            return false
        }
    }

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

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        mode = try container.decode(FederationMode.self, forKey: .mode)
        federationName = try container.decodeIfPresent(String.self, forKey: .federationName)
        issuedAt = try container.decode(Date.self, forKey: .issuedAt)
        validUntil = try container.decode(Date.self, forKey: .validUntil)
        maxStalenessSeconds = try container.decode(Int.self, forKey: .maxStalenessSeconds)
        nodes = try container.decode([FederationNodeRecord].self, forKey: .nodes)
        signatureAlgorithm = try container.decodeIfPresent(String.self, forKey: .signatureAlgorithm)
        signature = try container.decodeIfPresent(Data.self, forKey: .signature)
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Federation directory snapshot is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Federation directory snapshot is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(mode, forKey: .mode)
        try container.encode(federationName, forKey: .federationName)
        try container.encode(issuedAt, forKey: .issuedAt)
        try container.encode(validUntil, forKey: .validUntil)
        try container.encode(maxStalenessSeconds, forKey: .maxStalenessSeconds)
        try container.encode(nodes, forKey: .nodes)
        try container.encode(signatureAlgorithm, forKey: .signatureAlgorithm)
        try container.encode(signature, forKey: .signature)
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
    /// The outer transport layer wraps an already-padded encrypted rendezvous
    /// frame. Its largest bucket therefore needs room for the inner 64 KiB
    /// bucket plus authenticated transport framing.
    public static let allowedCiphertextByteCounts = [4_096, 16_384, 65_536, 131_072]

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

    public init(from decoder: Decoder) throws {
        rawValue = try decodeRendezvousRelayOpaqueValue(
            from: decoder,
            byteCount: RendezvousRelayTransportV2.capabilityBytes
        )
    }

    public func encode(to encoder: Encoder) throws {
        try encodeRendezvousRelayOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes,
            to: encoder
        )
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

    public init(from decoder: Decoder) throws {
        rawValue = try decodeRendezvousRelayOpaqueValue(
            from: decoder,
            byteCount: RendezvousRelayTransportV2.capabilityBytes
        )
    }

    public func encode(to encoder: Encoder) throws {
        try encodeRendezvousRelayOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes,
            to: encoder
        )
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

    public init(from decoder: Decoder) throws {
        rawValue = try decodeRendezvousRelayOpaqueValue(
            from: decoder,
            byteCount: RendezvousRelayTransportV2.capabilityBytes
        )
    }

    public func encode(to encoder: Encoder) throws {
        try encodeRendezvousRelayOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes,
            to: encoder
        )
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

    public init(from decoder: Decoder) throws {
        rawValue = try decodeRendezvousRelayOpaqueValue(
            from: decoder,
            byteCount: RendezvousRelayTransportV2.capabilityBytes
        )
    }

    public func encode(to encoder: Encoder) throws {
        try encodeRendezvousRelayOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.capabilityBytes,
            to: encoder
        )
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

    public init(from decoder: Decoder) throws {
        rawValue = try decodeRendezvousRelayOpaqueValue(
            from: decoder,
            byteCount: RendezvousRelayTransportV2.laneIDBytes
        )
    }

    public func encode(to encoder: Encoder) throws {
        try encodeRendezvousRelayOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.laneIDBytes,
            to: encoder
        )
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

    public init(from decoder: Decoder) throws {
        rawValue = try decodeRendezvousRelayOpaqueValue(
            from: decoder,
            byteCount: RendezvousRelayTransportV2.frameIDBytes
        )
    }

    public func encode(to encoder: Encoder) throws {
        try encodeRendezvousRelayOpaqueValue(
            rawValue,
            byteCount: RendezvousRelayTransportV2.frameIDBytes,
            to: encoder
        )
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

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(
            decoder,
            keys: ["laneId", "publishCapability", "readCapability", "deleteCapability"]
        )
        let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
        self.init(
            laneId: try container.decode(
                RendezvousRelayLaneIDV2.self,
                forKey: relayWireKey("laneId")
            ),
            publishCapability: try container.decode(
                RendezvousRelayPublishCapabilityV2.self,
                forKey: relayWireKey("publishCapability")
            ),
            readCapability: try container.decode(
                RendezvousRelayReadCapabilityV2.self,
                forKey: relayWireKey("readCapability")
            ),
            deleteCapability: try container.decode(
                RendezvousRelayDeleteCapabilityV2.self,
                forKey: relayWireKey("deleteCapability")
            )
        )
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Rendezvous relay lane registration is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Rendezvous relay lane registration is invalid")
        }
        var container = encoder.container(keyedBy: RelayWireCodingKey.self)
        try container.encode(laneId, forKey: relayWireKey("laneId"))
        try container.encode(publishCapability, forKey: relayWireKey("publishCapability"))
        try container.encode(readCapability, forKey: relayWireKey("readCapability"))
        try container.encode(deleteCapability, forKey: relayWireKey("deleteCapability"))
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

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(
            decoder,
            keys: ["version", "routeCapability", "expiresAt", "lanes"]
        )
        let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
        self.init(
            version: try container.decode(Int.self, forKey: relayWireKey("version")),
            routeCapability: try container.decode(
                RendezvousRelayRouteCapabilityV2.self,
                forKey: relayWireKey("routeCapability")
            ),
            expiresAt: try container.decode(Date.self, forKey: relayWireKey("expiresAt")),
            lanes: try container.decode(
                [RendezvousRelayLaneRegistrationV2].self,
                forKey: relayWireKey("lanes")
            )
        )
        guard hasValidStaticStructure else {
            throw relayWireError(decoder, "Rendezvous relay registration is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard hasValidStaticStructure else {
            throw relayWireError(encoder, "Rendezvous relay registration is invalid")
        }
        var container = encoder.container(keyedBy: RelayWireCodingKey.self)
        try container.encode(version, forKey: relayWireKey("version"))
        try container.encode(routeCapability, forKey: relayWireKey("routeCapability"))
        try container.encode(expiresAt, forKey: relayWireKey("expiresAt"))
        try container.encode(lanes, forKey: relayWireKey("lanes"))
    }

    public func isStructurallyValid(at now: Date = Date()) -> Bool {
        guard hasValidStaticStructure,
              now.timeIntervalSince1970.isFinite,
              expiresAt > now,
              expiresAt <= Date(
                timeIntervalSince1970: floor(now.timeIntervalSince1970)
                    + RendezvousRelayTransportV2.maximumLifetimeSeconds
              ) else {
            return false
        }
        return true
    }

    private var hasValidStaticStructure: Bool {
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

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: ["frameId", "sequence", "ciphertext"])
        let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
        self.init(
            frameId: try container.decode(
                RendezvousRelayFrameIDV2.self,
                forKey: relayWireKey("frameId")
            ),
            sequence: try container.decode(UInt64.self, forKey: relayWireKey("sequence")),
            ciphertext: try container.decode(Data.self, forKey: relayWireKey("ciphertext"))
        )
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Rendezvous relay ciphertext frame is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Rendezvous relay ciphertext frame is invalid")
        }
        var container = encoder.container(keyedBy: RelayWireCodingKey.self)
        try container.encode(frameId, forKey: relayWireKey("frameId"))
        try container.encode(sequence, forKey: relayWireKey("sequence"))
        try container.encode(ciphertext, forKey: relayWireKey("ciphertext"))
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

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(
            decoder,
            keys: ["routeCapability", "laneId", "publishCapability", "frame"]
        )
        let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
        self.init(
            routeCapability: try container.decode(
                RendezvousRelayRouteCapabilityV2.self,
                forKey: relayWireKey("routeCapability")
            ),
            laneId: try container.decode(
                RendezvousRelayLaneIDV2.self,
                forKey: relayWireKey("laneId")
            ),
            publishCapability: try container.decode(
                RendezvousRelayPublishCapabilityV2.self,
                forKey: relayWireKey("publishCapability")
            ),
            frame: try container.decode(
                RendezvousRelayCiphertextFrameV2.self,
                forKey: relayWireKey("frame")
            )
        )
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Rendezvous relay append request is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Rendezvous relay append request is invalid")
        }
        var container = encoder.container(keyedBy: RelayWireCodingKey.self)
        try container.encode(routeCapability, forKey: relayWireKey("routeCapability"))
        try container.encode(laneId, forKey: relayWireKey("laneId"))
        try container.encode(publishCapability, forKey: relayWireKey("publishCapability"))
        try container.encode(frame, forKey: relayWireKey("frame"))
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

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(
            decoder,
            keys: ["routeCapability", "laneId", "readCapability", "afterSequence", "maxCount"]
        )
        let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
        self.init(
            routeCapability: try container.decode(
                RendezvousRelayRouteCapabilityV2.self,
                forKey: relayWireKey("routeCapability")
            ),
            laneId: try container.decode(
                RendezvousRelayLaneIDV2.self,
                forKey: relayWireKey("laneId")
            ),
            readCapability: try container.decode(
                RendezvousRelayReadCapabilityV2.self,
                forKey: relayWireKey("readCapability")
            ),
            afterSequence: try container.decode(
                UInt64.self,
                forKey: relayWireKey("afterSequence")
            ),
            maxCount: try container.decodeIfPresent(
                Int.self,
                forKey: relayWireKey("maxCount")
            )
        )
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Rendezvous relay sync request is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Rendezvous relay sync request is invalid")
        }
        var container = encoder.container(keyedBy: RelayWireCodingKey.self)
        try container.encode(routeCapability, forKey: relayWireKey("routeCapability"))
        try container.encode(laneId, forKey: relayWireKey("laneId"))
        try container.encode(readCapability, forKey: relayWireKey("readCapability"))
        try container.encode(afterSequence, forKey: relayWireKey("afterSequence"))
        try relayEncodeOptional(maxCount, key: "maxCount", into: &container)
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

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(
            decoder,
            keys: ["routeCapability", "laneId", "deleteCapability"]
        )
        let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
        self.init(
            routeCapability: try container.decode(
                RendezvousRelayRouteCapabilityV2.self,
                forKey: relayWireKey("routeCapability")
            ),
            laneId: try container.decode(
                RendezvousRelayLaneIDV2.self,
                forKey: relayWireKey("laneId")
            ),
            deleteCapability: try container.decode(
                RendezvousRelayDeleteCapabilityV2.self,
                forKey: relayWireKey("deleteCapability")
            )
        )
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Rendezvous relay delete request is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Rendezvous relay delete request is invalid")
        }
        var container = encoder.container(keyedBy: RelayWireCodingKey.self)
        try container.encode(routeCapability, forKey: relayWireKey("routeCapability"))
        try container.encode(laneId, forKey: relayWireKey("laneId"))
        try container.encode(deleteCapability, forKey: relayWireKey("deleteCapability"))
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

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(
            decoder,
            keys: ["frames", "highWatermark", "nextSequence", "hasMore"]
        )
        let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
        self.init(
            frames: try container.decode(
                [RendezvousRelayCiphertextFrameV2].self,
                forKey: relayWireKey("frames")
            ),
            highWatermark: try container.decode(
                UInt64.self,
                forKey: relayWireKey("highWatermark")
            ),
            nextSequence: try container.decode(
                UInt64.self,
                forKey: relayWireKey("nextSequence")
            ),
            hasMore: try container.decode(Bool.self, forKey: relayWireKey("hasMore"))
        )
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Rendezvous relay sync batch is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Rendezvous relay sync batch is invalid")
        }
        var container = encoder.container(keyedBy: RelayWireCodingKey.self)
        try container.encode(frames, forKey: relayWireKey("frames"))
        try container.encode(highWatermark, forKey: relayWireKey("highWatermark"))
        try container.encode(nextSequence, forKey: relayWireKey("nextSequence"))
        try container.encode(hasMore, forKey: relayWireKey("hasMore"))
    }

    public var isStructurallyValid: Bool {
        let sequences = frames.map(\.sequence)
        return frames.count <= RendezvousRelayTransportV2.maximumSyncFrames
            && frames.allSatisfy(\.isStructurallyValid)
            && Set(frames.map(\.frameId)).count == frames.count
            && sequences == sequences.sorted()
            && Set(sequences).count == sequences.count
            && highWatermark <= RendezvousRelayTransportV2.maximumFramesPerLane
            && nextSequence <= highWatermark
            && sequences.allSatisfy { $0 <= highWatermark }
            && (frames.last?.sequence == nextSequence || frames.isEmpty)
            && hasMore == (nextSequence < highWatermark)
    }
}

public enum RelayRequestBody: Equatable {
    case empty
    case createOpaqueRoute(CreateOpaqueRouteRelayRequestV2)
    case renewOpaqueRoute(RenewOpaqueRouteRelayRequestV2)
    case teardownOpaqueRoute(TeardownOpaqueRouteRelayRequestV2)
    case appendOpaqueRoute(AppendOpaqueRouteRelayRequestV2)
    case syncOpaqueRoute(SyncOpaqueRouteRelayRequestV2)
    case commitOpaqueRoute(CommitOpaqueRouteRelayRequestV2)
    case registerRendezvous(RegisterRendezvousTransportV2Request)
    case appendRendezvous(AppendRendezvousTransportV2Request)
    case syncRendezvous(SyncRendezvousTransportV2Request)
    case deleteRendezvous(DeleteRendezvousTransportV2Request)
    case createRealtimeRoute(RealtimeRouteCreateRequestV1)
    case appendRealtimeRoute(RealtimeRouteAppendRequestV1)
    case subscribeRealtimeRoute(RealtimeRouteSubscribeRequestV1)
    case syncRealtimeRoute(RealtimeRouteSyncRequestV1)
    case unsubscribeRealtimeRoute(RealtimeRouteUnsubscribeRequestV1)
    case createSharedLog(SharedLogCreateRequestV1)
    case appendSharedLog(SharedLogAppendRequestV1)
    case syncSharedLog(SharedLogSyncRequestV1)
    case acquirePresence(PresenceLeaseAcquireRequestV1)
    case renewPresence(PresenceLeaseRenewRequestV1)
    case releasePresence(PresenceLeaseReleaseRequestV1)
    case listPresence(PresenceLeaseListRequestV1)
    case createMediaBlob(MediaBlobCreateRequestV1)
    case uploadMediaBlob(MediaBlobUploadRequestV1)
    case fetchMediaBlob(MediaBlobFetchRequestV1)
    case releaseMediaBlob(MediaBlobReleaseRequestV1)
    case acquireICECredentials(RelayICECredentialRequestV1)
    case uploadAttachment(UploadAttachmentRequest)
    case fetchAttachment(FetchAttachmentRequest)
    case registerFederationNode(FederationNodeRegistrationRequest)
    case listFederationNodes(ListFederationNodesRequest)
    case getNoctwebNamespaceSnapshot(NoctwebNamespaceSnapshotRequestV1)
    case claimNoctwebNamespace(NoctwebNamespaceClaimRequestV1)
    case rotateNoctwebNamespace(NoctwebNamespaceRotationRequestV1)
    case releaseNoctwebNamespace(NoctwebNamespaceReleaseV1)
    case forwardOpaqueRoute(FederatedOpaqueRouteForwardRequestV1)
    case deliverOpaqueRoute(FederatedOpaqueRouteDeliveryV1)
    case getFederatedNetHostObject(FederatedNetHostReadRequestV1)
    case resolveFederatedNetHostName(
        FederatedNetHostNameReadRequestV1
    )
    case publishDHTRecord(PublishOpenFederationDHTRecordRequest)
    case listDHTRecords(ListOpenFederationDHTRecordsRequest)
    case netPassthrough(NoctweaveNetPassthroughRequest)
    case putNetHostObject(NoctweaveNetHostPutRequest)
    case bindNetHostName(NoctweaveNetHostNameBindingRequestV1)
    case getNetHostObject(NoctweaveNetHostObjectRequest)
    case resolveNetHostName(NoctweaveNetHostNameRequestV1)
    case hasNetHostObject(NoctweaveNetHostObjectRequest)
    case releaseNetHostObject(NoctweaveNetHostReleaseRequest)

    public var binding: RelayOperationBinding {
        switch self {
        case .empty:
            preconditionFailure("An empty relay body requires an explicit core operation")
        case .createOpaqueRoute:
            return RelayOperationBinding(module: .opaqueRoute, version: 2, method: .create)
        case .renewOpaqueRoute:
            return RelayOperationBinding(module: .opaqueRoute, version: 2, method: .renew)
        case .teardownOpaqueRoute:
            return RelayOperationBinding(module: .opaqueRoute, version: 2, method: .teardown)
        case .appendOpaqueRoute:
            return RelayOperationBinding(module: .opaqueRoute, version: 2, method: .append)
        case .syncOpaqueRoute:
            return RelayOperationBinding(module: .opaqueRoute, version: 2, method: .sync)
        case .commitOpaqueRoute:
            return RelayOperationBinding(module: .opaqueRoute, version: 2, method: .commit)
        case .registerRendezvous:
            return RelayOperationBinding(module: .rendezvousTransport, version: 2, method: .register)
        case .appendRendezvous:
            return RelayOperationBinding(module: .rendezvousTransport, version: 2, method: .append)
        case .syncRendezvous:
            return RelayOperationBinding(module: .rendezvousTransport, version: 2, method: .sync)
        case .deleteRendezvous:
            return RelayOperationBinding(module: .rendezvousTransport, version: 2, method: .delete)
        case .createRealtimeRoute: return RelayOperationBinding(module: .realtimeRoute, version: 1, method: .create)
        case .appendRealtimeRoute: return RelayOperationBinding(module: .realtimeRoute, version: 1, method: .append)
        case .subscribeRealtimeRoute: return RelayOperationBinding(module: .realtimeRoute, version: 1, method: .subscribe)
        case .syncRealtimeRoute: return RelayOperationBinding(module: .realtimeRoute, version: 1, method: .sync)
        case .unsubscribeRealtimeRoute: return RelayOperationBinding(module: .realtimeRoute, version: 1, method: .unsubscribe)
        case .createSharedLog: return RelayOperationBinding(module: .sharedLog, version: 1, method: .create)
        case .appendSharedLog: return RelayOperationBinding(module: .sharedLog, version: 1, method: .append)
        case .syncSharedLog: return RelayOperationBinding(module: .sharedLog, version: 1, method: .sync)
        case .acquirePresence: return RelayOperationBinding(module: .ephemeralPresence, version: 1, method: .acquire)
        case .renewPresence: return RelayOperationBinding(module: .ephemeralPresence, version: 1, method: .renewLease)
        case .releasePresence: return RelayOperationBinding(module: .ephemeralPresence, version: 1, method: .release)
        case .listPresence: return RelayOperationBinding(module: .ephemeralPresence, version: 1, method: .list)
        case .createMediaBlob: return RelayOperationBinding(module: .mediaBlobs, version: 1, method: .create)
        case .uploadMediaBlob: return RelayOperationBinding(module: .mediaBlobs, version: 1, method: .upload)
        case .fetchMediaBlob: return RelayOperationBinding(module: .mediaBlobs, version: 1, method: .fetch)
        case .releaseMediaBlob: return RelayOperationBinding(module: .mediaBlobs, version: 1, method: .release)
        case .acquireICECredentials:
            return RelayOperationBinding(module: .iceService, version: 1, method: .acquire)
        case .uploadAttachment:
            return RelayOperationBinding(module: .blobs, version: 1, method: .upload)
        case .fetchAttachment:
            return RelayOperationBinding(module: .blobs, version: 1, method: .fetch)
        case .registerFederationNode:
            return RelayOperationBinding(module: .federation, version: 1, method: .register)
        case .listFederationNodes:
            return RelayOperationBinding(module: .federation, version: 1, method: .list)
        case .getNoctwebNamespaceSnapshot:
            return RelayOperationBinding(
                module: .federation,
                version: 1,
                method: .namespace
            )
        case .claimNoctwebNamespace:
            return RelayOperationBinding(
                module: .federation,
                version: 1,
                method: .claim
            )
        case .rotateNoctwebNamespace:
            return RelayOperationBinding(
                module: .federation,
                version: 1,
                method: .rotate
            )
        case .releaseNoctwebNamespace:
            return RelayOperationBinding(
                module: .federation,
                version: 1,
                method: .release
            )
        case .forwardOpaqueRoute:
            return RelayOperationBinding(module: .federationForward, version: 1, method: .forward)
        case .deliverOpaqueRoute:
            return RelayOperationBinding(module: .federationForward, version: 1, method: .deliver)
        case .getFederatedNetHostObject:
            return RelayOperationBinding(module: .federationForward, version: 1, method: .get)
        case .resolveFederatedNetHostName:
            return RelayOperationBinding(
                module: .federationForward,
                version: 1,
                method: .resolve
            )
        case .publishDHTRecord:
            return RelayOperationBinding(module: .openDiscovery, version: 1, method: .publishDHT)
        case .listDHTRecords:
            return RelayOperationBinding(module: .openDiscovery, version: 1, method: .listDHT)
        case .netPassthrough:
            return RelayOperationBinding(module: .netPassthrough, version: 1, method: .forward)
        case .putNetHostObject:
            return RelayOperationBinding(module: .netHost, version: 1, method: .put)
        case .bindNetHostName:
            return RelayOperationBinding(
                module: .netHost,
                version: 1,
                method: .bind
            )
        case .getNetHostObject:
            return RelayOperationBinding(module: .netHost, version: 1, method: .get)
        case .resolveNetHostName:
            return RelayOperationBinding(
                module: .netHost,
                version: 1,
                method: .resolve
            )
        case .hasNetHostObject:
            return RelayOperationBinding(module: .netHost, version: 1, method: .has)
        case .releaseNetHostObject:
            return RelayOperationBinding(module: .netHost, version: 1, method: .release)
        }
    }

    fileprivate static func decode(
        for binding: RelayOperationBinding,
        from decoder: Decoder
    ) throws -> RelayRequestBody {
        switch (binding.module, binding.method) {
        case (.core, .health), (.core, .info):
            try relayRequireExactObject(decoder, keys: [])
            return .empty
        case (.opaqueRoute, .create):
            return .createOpaqueRoute(try relayDecodeExact(
                CreateOpaqueRouteRelayRequestV2.self,
                from: decoder,
                keys: ["request", "renewCapability"]
            ))
        case (.opaqueRoute, .renew):
            return .renewOpaqueRoute(try relayDecodeExact(
                RenewOpaqueRouteRelayRequestV2.self,
                from: decoder,
                keys: ["request", "renewCapability"]
            ))
        case (.opaqueRoute, .teardown):
            return .teardownOpaqueRoute(try relayDecodeExact(
                TeardownOpaqueRouteRelayRequestV2.self,
                from: decoder,
                keys: ["request", "teardownCapability"]
            ))
        case (.opaqueRoute, .append):
            return .appendOpaqueRoute(try relayDecodeExact(
                AppendOpaqueRouteRelayRequestV2.self,
                from: decoder,
                keys: ["packet", "sendCapability"]
            ))
        case (.opaqueRoute, .sync):
            return .syncOpaqueRoute(try relayDecodeExact(
                SyncOpaqueRouteRelayRequestV2.self,
                from: decoder,
                keys: ["request", "readCredential"]
            ))
        case (.opaqueRoute, .commit):
            return .commitOpaqueRoute(try relayDecodeExact(
                CommitOpaqueRouteRelayRequestV2.self,
                from: decoder,
                keys: ["request", "readCredential"]
            ))
        case (.rendezvousTransport, .register):
            return .registerRendezvous(try relayDecodeExact(
                RegisterRendezvousTransportV2Request.self,
                from: decoder,
                keys: ["version", "routeCapability", "expiresAt", "lanes"]
            ))
        case (.rendezvousTransport, .append):
            return .appendRendezvous(try relayDecodeExact(
                AppendRendezvousTransportV2Request.self,
                from: decoder,
                keys: ["routeCapability", "laneId", "publishCapability", "frame"]
            ))
        case (.rendezvousTransport, .sync):
            return .syncRendezvous(try relayDecodeExact(
                SyncRendezvousTransportV2Request.self,
                from: decoder,
                keys: ["routeCapability", "laneId", "readCapability", "afterSequence", "maxCount"]
            ))
        case (.rendezvousTransport, .delete):
            return .deleteRendezvous(try relayDecodeExact(
                DeleteRendezvousTransportV2Request.self,
                from: decoder,
                keys: ["routeCapability", "laneId", "deleteCapability"]
            ))
        case (.realtimeRoute, .create): return .createRealtimeRoute(try relayDecodeSingle(RealtimeRouteCreateRequestV1.self, from: decoder, key: "request"))
        case (.realtimeRoute, .append): return .appendRealtimeRoute(try relayDecodeSingle(RealtimeRouteAppendRequestV1.self, from: decoder, key: "request"))
        case (.realtimeRoute, .subscribe): return .subscribeRealtimeRoute(try relayDecodeSingle(RealtimeRouteSubscribeRequestV1.self, from: decoder, key: "request"))
        case (.realtimeRoute, .sync): return .syncRealtimeRoute(try relayDecodeSingle(RealtimeRouteSyncRequestV1.self, from: decoder, key: "request"))
        case (.realtimeRoute, .unsubscribe): return .unsubscribeRealtimeRoute(try relayDecodeSingle(RealtimeRouteUnsubscribeRequestV1.self, from: decoder, key: "request"))
        case (.sharedLog, .create): return .createSharedLog(try relayDecodeSingle(SharedLogCreateRequestV1.self, from: decoder, key: "request"))
        case (.sharedLog, .append): return .appendSharedLog(try relayDecodeSingle(SharedLogAppendRequestV1.self, from: decoder, key: "request"))
        case (.sharedLog, .sync): return .syncSharedLog(try relayDecodeSingle(SharedLogSyncRequestV1.self, from: decoder, key: "request"))
        case (.ephemeralPresence, .acquire): return .acquirePresence(try relayDecodeSingle(PresenceLeaseAcquireRequestV1.self, from: decoder, key: "request"))
        case (.ephemeralPresence, .renewLease): return .renewPresence(try relayDecodeSingle(PresenceLeaseRenewRequestV1.self, from: decoder, key: "request"))
        case (.ephemeralPresence, .release): return .releasePresence(try relayDecodeSingle(PresenceLeaseReleaseRequestV1.self, from: decoder, key: "request"))
        case (.ephemeralPresence, .list): return .listPresence(try relayDecodeSingle(PresenceLeaseListRequestV1.self, from: decoder, key: "request"))
        case (.mediaBlobs, .create): return .createMediaBlob(try relayDecodeSingle(MediaBlobCreateRequestV1.self, from: decoder, key: "request"))
        case (.mediaBlobs, .upload): return .uploadMediaBlob(try relayDecodeSingle(MediaBlobUploadRequestV1.self, from: decoder, key: "request"))
        case (.mediaBlobs, .fetch): return .fetchMediaBlob(try relayDecodeSingle(MediaBlobFetchRequestV1.self, from: decoder, key: "request"))
        case (.mediaBlobs, .release): return .releaseMediaBlob(try relayDecodeSingle(MediaBlobReleaseRequestV1.self, from: decoder, key: "request"))
        case (.iceService, .acquire):
            return .acquireICECredentials(try relayDecodeSingle(
                RelayICECredentialRequestV1.self,
                from: decoder,
                key: "request"
            ))
        case (.blobs, .upload):
            return .uploadAttachment(try relayDecodeExact(
                UploadAttachmentRequest.self,
                from: decoder,
                keys: ["attachmentId", "chunkIndex", "payload", "ttlSeconds", "idempotencyKey"]
            ))
        case (.blobs, .fetch):
            return .fetchAttachment(try relayDecodeExact(
                FetchAttachmentRequest.self,
                from: decoder,
                keys: ["attachmentId", "chunkIndex"]
            ))
        case (.federation, .register):
            return .registerFederationNode(try relayDecodeExact(
                FederationNodeRegistrationRequest.self,
                from: decoder,
                keys: ["endpoint", "relayInfo", "ttlSeconds"]
            ))
        case (.federation, .list):
            return .listFederationNodes(try relayDecodeExact(
                ListFederationNodesRequest.self,
                from: decoder,
                keys: ["mode", "federationName", "onlyHealthy", "maxStalenessSeconds", "requireSignedSnapshot"]
            ))
        case (.federation, .namespace):
            return .getNoctwebNamespaceSnapshot(try relayDecodeExact(
                NoctwebNamespaceSnapshotRequestV1.self,
                from: decoder,
                keys: ["version", "federationMode", "federationName"]
            ))
        case (.federation, .claim):
            return .claimNoctwebNamespace(try relayDecodeExact(
                NoctwebNamespaceClaimRequestV1.self,
                from: decoder,
                keys: ["identity"]
            ))
        case (.federation, .rotate):
            return .rotateNoctwebNamespace(try relayDecodeExact(
                NoctwebNamespaceRotationRequestV1.self,
                from: decoder,
                keys: ["rotation", "newIdentity"]
            ))
        case (.federation, .release):
            return .releaseNoctwebNamespace(try relayDecodeExact(
                NoctwebNamespaceReleaseV1.self,
                from: decoder,
                keys: [
                    "version",
                    "suffix",
                    "ownerRelayID",
                    "sequence",
                    "issuedAt",
                    "signatureAlgorithm",
                    "signature"
                ]
            ))
        case (.federationForward, .forward):
            return .forwardOpaqueRoute(try relayDecodeExact(
                FederatedOpaqueRouteForwardRequestV1.self,
                from: decoder,
                keys: ["destinationRelayID", "destination", "append"]
            ))
        case (.federationForward, .deliver):
            return .deliverOpaqueRoute(try relayDecodeExact(
                FederatedOpaqueRouteDeliveryV1.self,
                from: decoder,
                keys: [
                    "version", "deliveryID", "sourceIdentity",
                    "destinationRelayID", "append", "issuedAt", "expiresAt",
                    "signatureAlgorithm", "signature"
                ]
            ))
        case (.federationForward, .get):
            return .getFederatedNetHostObject(try relayDecodeExact(
                FederatedNetHostReadRequestV1.self,
                from: decoder,
                keys: ["destinationRelayID", "destination", "request"]
            ))
        case (.federationForward, .resolve):
            return .resolveFederatedNetHostName(try relayDecodeExact(
                FederatedNetHostNameReadRequestV1.self,
                from: decoder,
                keys: ["destinationRelayID", "destination", "request"]
            ))
        case (.openDiscovery, .publishDHT):
            return .publishDHTRecord(try relayDecodeExact(
                PublishOpenFederationDHTRecordRequest.self,
                from: decoder,
                keys: ["namespace", "record"]
            ))
        case (.openDiscovery, .listDHT):
            return .listDHTRecords(try relayDecodeExact(
                ListOpenFederationDHTRecordsRequest.self,
                from: decoder,
                keys: ["namespace", "limit"]
            ))
        case (.netPassthrough, .forward):
            return .netPassthrough(try relayDecodeExact(
                NoctweaveNetPassthroughRequest.self,
                from: decoder,
                keys: ["destination", "payload"]
            ))
        case (.netHost, .put):
            return .putNetHostObject(try relayDecodeExact(
                NoctweaveNetHostPutRequest.self,
                from: decoder,
                keys: ["objectID", "payload", "ttlSeconds", "releaseCapabilityDigest", "idempotencyKey"]
            ))
        case (.netHost, .bind):
            return .bindNetHostName(try relayDecodeExact(
                NoctweaveNetHostNameBindingRequestV1.self,
                from: decoder,
                keys: [
                    "version",
                    "relaySuffix",
                    "siteLabel",
                    "objectID",
                    "publisherID",
                    "headID",
                    "revision",
                    "previousObjectID",
                    "idempotencyKey"
                ]
            ))
        case (.netHost, .get):
            return .getNetHostObject(try relayDecodeExact(
                NoctweaveNetHostObjectRequest.self,
                from: decoder,
                keys: ["objectID"]
            ))
        case (.netHost, .resolve):
            return .resolveNetHostName(try relayDecodeExact(
                NoctweaveNetHostNameRequestV1.self,
                from: decoder,
                keys: ["version", "relaySuffix", "siteLabel"]
            ))
        case (.netHost, .has):
            return .hasNetHostObject(try relayDecodeExact(
                NoctweaveNetHostObjectRequest.self,
                from: decoder,
                keys: ["objectID"]
            ))
        case (.netHost, .release):
            return .releaseNetHostObject(try relayDecodeExact(
                NoctweaveNetHostReleaseRequest.self,
                from: decoder,
                keys: ["objectID", "releaseCapability"]
            ))
        default:
            throw relayWireError(decoder, "Relay module, version, and method do not identify a current request body")
        }
    }

    fileprivate func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RelayWireCodingKey.self)
        switch self {
        case .empty:
            break
        case .createOpaqueRoute(let value):
            try container.encode(value.request, forKey: relayWireKey("request"))
            try container.encode(value.renewCapability, forKey: relayWireKey("renewCapability"))
        case .renewOpaqueRoute(let value):
            try container.encode(value.request, forKey: relayWireKey("request"))
            try container.encode(value.renewCapability, forKey: relayWireKey("renewCapability"))
        case .teardownOpaqueRoute(let value):
            try container.encode(value.request, forKey: relayWireKey("request"))
            try container.encode(value.teardownCapability, forKey: relayWireKey("teardownCapability"))
        case .appendOpaqueRoute(let value):
            try container.encode(value.packet, forKey: relayWireKey("packet"))
            try container.encode(value.sendCapability, forKey: relayWireKey("sendCapability"))
        case .syncOpaqueRoute(let value):
            try container.encode(value.request, forKey: relayWireKey("request"))
            try container.encode(value.readCredential, forKey: relayWireKey("readCredential"))
        case .commitOpaqueRoute(let value):
            try container.encode(value.request, forKey: relayWireKey("request"))
            try container.encode(value.readCredential, forKey: relayWireKey("readCredential"))
        case .registerRendezvous(let value):
            try container.encode(value.version, forKey: relayWireKey("version"))
            try container.encode(value.routeCapability, forKey: relayWireKey("routeCapability"))
            try container.encode(value.expiresAt, forKey: relayWireKey("expiresAt"))
            try container.encode(value.lanes, forKey: relayWireKey("lanes"))
        case .appendRendezvous(let value):
            try container.encode(value.routeCapability, forKey: relayWireKey("routeCapability"))
            try container.encode(value.laneId, forKey: relayWireKey("laneId"))
            try container.encode(value.publishCapability, forKey: relayWireKey("publishCapability"))
            try container.encode(value.frame, forKey: relayWireKey("frame"))
        case .syncRendezvous(let value):
            try container.encode(value.routeCapability, forKey: relayWireKey("routeCapability"))
            try container.encode(value.laneId, forKey: relayWireKey("laneId"))
            try container.encode(value.readCapability, forKey: relayWireKey("readCapability"))
            try container.encode(value.afterSequence, forKey: relayWireKey("afterSequence"))
            try relayEncodeOptional(value.maxCount, key: "maxCount", into: &container)
        case .deleteRendezvous(let value):
            try container.encode(value.routeCapability, forKey: relayWireKey("routeCapability"))
            try container.encode(value.laneId, forKey: relayWireKey("laneId"))
            try container.encode(value.deleteCapability, forKey: relayWireKey("deleteCapability"))
        case .createRealtimeRoute(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .appendRealtimeRoute(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .subscribeRealtimeRoute(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .syncRealtimeRoute(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .unsubscribeRealtimeRoute(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .createSharedLog(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .appendSharedLog(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .syncSharedLog(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .acquirePresence(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .renewPresence(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .releasePresence(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .listPresence(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .createMediaBlob(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .uploadMediaBlob(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .fetchMediaBlob(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .releaseMediaBlob(let value): try container.encode(value, forKey: relayWireKey("request"))
        case .acquireICECredentials(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .uploadAttachment(let value):
            guard value.isStructurallyValid else {
                throw relayWireError(encoder, "Attachment upload request is invalid")
            }
            try container.encode(value.attachmentId, forKey: relayWireKey("attachmentId"))
            try container.encode(value.chunkIndex, forKey: relayWireKey("chunkIndex"))
            try container.encode(value.payload, forKey: relayWireKey("payload"))
            try relayEncodeOptional(value.ttlSeconds, key: "ttlSeconds", into: &container)
            try container.encode(value.idempotencyKey, forKey: relayWireKey("idempotencyKey"))
        case .fetchAttachment(let value):
            guard value.isStructurallyValid else {
                throw relayWireError(encoder, "Attachment fetch request is invalid")
            }
            try container.encode(value.attachmentId, forKey: relayWireKey("attachmentId"))
            try container.encode(value.chunkIndex, forKey: relayWireKey("chunkIndex"))
        case .registerFederationNode(let value):
            guard value.isStructurallyValid else {
                throw relayWireError(encoder, "Federation node registration request is invalid")
            }
            try container.encode(value.endpoint, forKey: relayWireKey("endpoint"))
            try container.encode(value.relayInfo, forKey: relayWireKey("relayInfo"))
            try relayEncodeOptional(value.ttlSeconds, key: "ttlSeconds", into: &container)
        case .listFederationNodes(let value):
            guard value.isStructurallyValid else {
                throw relayWireError(encoder, "Federation node list request is invalid")
            }
            try relayEncodeOptional(value.mode, key: "mode", into: &container)
            try relayEncodeOptional(value.federationName, key: "federationName", into: &container)
            try relayEncodeOptional(value.onlyHealthy, key: "onlyHealthy", into: &container)
            try relayEncodeOptional(value.maxStalenessSeconds, key: "maxStalenessSeconds", into: &container)
            try relayEncodeOptional(value.requireSignedSnapshot, key: "requireSignedSnapshot", into: &container)
        case .getNoctwebNamespaceSnapshot(let value):
            try container.encode(value.version, forKey: relayWireKey("version"))
            try container.encode(
                value.federationMode,
                forKey: relayWireKey("federationMode")
            )
            try relayEncodeOptional(
                value.federationName,
                key: "federationName",
                into: &container
            )
        case .claimNoctwebNamespace(let value):
            try container.encode(
                value.identity,
                forKey: relayWireKey("identity")
            )
        case .rotateNoctwebNamespace(let value):
            try container.encode(
                value.rotation,
                forKey: relayWireKey("rotation")
            )
            try container.encode(
                value.newIdentity,
                forKey: relayWireKey("newIdentity")
            )
        case .releaseNoctwebNamespace(let value):
            try container.encode(value.version, forKey: relayWireKey("version"))
            try container.encode(value.suffix, forKey: relayWireKey("suffix"))
            try container.encode(
                value.ownerRelayID,
                forKey: relayWireKey("ownerRelayID")
            )
            try container.encode(
                value.sequence,
                forKey: relayWireKey("sequence")
            )
            try container.encode(
                value.issuedAt,
                forKey: relayWireKey("issuedAt")
            )
            try container.encode(
                value.signatureAlgorithm,
                forKey: relayWireKey("signatureAlgorithm")
            )
            try container.encode(value.signature, forKey: relayWireKey("signature"))
        case .forwardOpaqueRoute(let value):
            try container.encode(value.destinationRelayID, forKey: relayWireKey("destinationRelayID"))
            try container.encode(value.destination, forKey: relayWireKey("destination"))
            try container.encode(value.append, forKey: relayWireKey("append"))
        case .deliverOpaqueRoute(let value):
            try container.encode(value.version, forKey: relayWireKey("version"))
            try container.encode(value.deliveryID, forKey: relayWireKey("deliveryID"))
            try container.encode(value.sourceIdentity, forKey: relayWireKey("sourceIdentity"))
            try container.encode(value.destinationRelayID, forKey: relayWireKey("destinationRelayID"))
            try container.encode(value.append, forKey: relayWireKey("append"))
            try container.encode(value.issuedAt, forKey: relayWireKey("issuedAt"))
            try container.encode(value.expiresAt, forKey: relayWireKey("expiresAt"))
            try container.encode(value.signatureAlgorithm, forKey: relayWireKey("signatureAlgorithm"))
            try container.encode(value.signature, forKey: relayWireKey("signature"))
        case .getFederatedNetHostObject(let value):
            try container.encode(value.destinationRelayID, forKey: relayWireKey("destinationRelayID"))
            try container.encode(value.destination, forKey: relayWireKey("destination"))
            try container.encode(value.request, forKey: relayWireKey("request"))
        case .resolveFederatedNetHostName(let value):
            try container.encode(
                value.destinationRelayID,
                forKey: relayWireKey("destinationRelayID")
            )
            try container.encode(
                value.destination,
                forKey: relayWireKey("destination")
            )
            try container.encode(
                value.request,
                forKey: relayWireKey("request")
            )
        case .publishDHTRecord(let value):
            try container.encode(value.namespace, forKey: relayWireKey("namespace"))
            try container.encode(value.record, forKey: relayWireKey("record"))
        case .listDHTRecords(let value):
            try container.encode(value.namespace, forKey: relayWireKey("namespace"))
            try relayEncodeOptional(value.limit, key: "limit", into: &container)
        case .netPassthrough(let value):
            try container.encode(value.destination, forKey: relayWireKey("destination"))
            try container.encode(value.payload, forKey: relayWireKey("payload"))
        case .putNetHostObject(let value):
            try container.encode(value.objectID, forKey: relayWireKey("objectID"))
            try container.encode(value.payload, forKey: relayWireKey("payload"))
            try relayEncodeOptional(value.ttlSeconds, key: "ttlSeconds", into: &container)
            try container.encode(value.releaseCapabilityDigest, forKey: relayWireKey("releaseCapabilityDigest"))
            try container.encode(value.idempotencyKey, forKey: relayWireKey("idempotencyKey"))
        case .bindNetHostName(let value):
            try container.encode(value.version, forKey: relayWireKey("version"))
            try container.encode(
                value.relaySuffix,
                forKey: relayWireKey("relaySuffix")
            )
            try container.encode(
                value.siteLabel,
                forKey: relayWireKey("siteLabel")
            )
            try container.encode(value.objectID, forKey: relayWireKey("objectID"))
            try container.encode(
                value.publisherID,
                forKey: relayWireKey("publisherID")
            )
            try relayEncodeOptional(
                value.headID,
                key: "headID",
                into: &container
            )
            try container.encode(
                value.revision,
                forKey: relayWireKey("revision")
            )
            try relayEncodeOptional(
                value.previousObjectID,
                key: "previousObjectID",
                into: &container
            )
            try container.encode(
                value.idempotencyKey,
                forKey: relayWireKey("idempotencyKey")
            )
        case .getNetHostObject(let value), .hasNetHostObject(let value):
            try container.encode(value.objectID, forKey: relayWireKey("objectID"))
        case .resolveNetHostName(let value):
            try container.encode(value.version, forKey: relayWireKey("version"))
            try container.encode(
                value.relaySuffix,
                forKey: relayWireKey("relaySuffix")
            )
            try container.encode(
                value.siteLabel,
                forKey: relayWireKey("siteLabel")
            )
        case .releaseNetHostObject(let value):
            try container.encode(value.objectID, forKey: relayWireKey("objectID"))
            try container.encode(value.releaseCapability, forKey: relayWireKey("releaseCapability"))
        }
    }
}

public struct RelayRequest: Codable, Equatable {
    public let requestID: UUID
    public let module: RelayModuleID
    public let version: Int
    public let method: RelayMethodID
    public let body: RelayRequestBody
    public let authToken: String?

    public var binding: RelayOperationBinding {
        RelayOperationBinding(module: module, version: version, method: method)
    }

    private init(
        requestID: UUID = UUID(),
        binding: RelayOperationBinding,
        body: RelayRequestBody,
        authToken: String? = nil
    ) {
        self.requestID = requestID
        module = binding.module
        version = binding.version
        method = binding.method
        self.body = body
        self.authToken = authToken
    }

    public static func health(requestID: UUID = UUID()) -> RelayRequest {
        RelayRequest(
            requestID: requestID,
            binding: RelayOperationBinding(module: .core, version: 2, method: .health),
            body: .empty
        )
    }

    public static func info(requestID: UUID = UUID()) -> RelayRequest {
        RelayRequest(
            requestID: requestID,
            binding: RelayOperationBinding(module: .core, version: 2, method: .info),
            body: .empty
        )
    }

    public static func createOpaqueRouteV2(_ request: CreateOpaqueRouteRelayRequestV2) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.createOpaqueRoute(request)), body: .createOpaqueRoute(request))
    }

    public static func renewOpaqueRouteV2(_ request: RenewOpaqueRouteRelayRequestV2) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.renewOpaqueRoute(request)), body: .renewOpaqueRoute(request))
    }

    public static func teardownOpaqueRouteV2(_ request: TeardownOpaqueRouteRelayRequestV2) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.teardownOpaqueRoute(request)), body: .teardownOpaqueRoute(request))
    }

    public static func appendOpaqueRouteV2(_ request: AppendOpaqueRouteRelayRequestV2) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.appendOpaqueRoute(request)), body: .appendOpaqueRoute(request))
    }

    public static func syncOpaqueRouteV2(_ request: SyncOpaqueRouteRelayRequestV2) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.syncOpaqueRoute(request)), body: .syncOpaqueRoute(request))
    }

    public static func commitOpaqueRouteV2(_ request: CommitOpaqueRouteRelayRequestV2) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.commitOpaqueRoute(request)), body: .commitOpaqueRoute(request))
    }

    public static func registerRendezvousTransportV2(_ request: RegisterRendezvousTransportV2Request) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.registerRendezvous(request)), body: .registerRendezvous(request))
    }

    public static func appendRendezvousTransportV2(_ request: AppendRendezvousTransportV2Request) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.appendRendezvous(request)), body: .appendRendezvous(request))
    }

    public static func syncRendezvousTransportV2(_ request: SyncRendezvousTransportV2Request) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.syncRendezvous(request)), body: .syncRendezvous(request))
    }

    public static func deleteRendezvousTransportV2(_ request: DeleteRendezvousTransportV2Request) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.deleteRendezvous(request)), body: .deleteRendezvous(request))
    }

    public static func createRealtimeRouteV1(_ request: RealtimeRouteCreateRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.createRealtimeRoute(request)), body: .createRealtimeRoute(request)) }
    public static func appendRealtimeRouteV1(_ request: RealtimeRouteAppendRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.appendRealtimeRoute(request)), body: .appendRealtimeRoute(request)) }
    public static func subscribeRealtimeRouteV1(_ request: RealtimeRouteSubscribeRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.subscribeRealtimeRoute(request)), body: .subscribeRealtimeRoute(request)) }
    public static func syncRealtimeRouteV1(_ request: RealtimeRouteSyncRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.syncRealtimeRoute(request)), body: .syncRealtimeRoute(request)) }
    public static func unsubscribeRealtimeRouteV1(_ request: RealtimeRouteUnsubscribeRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.unsubscribeRealtimeRoute(request)), body: .unsubscribeRealtimeRoute(request)) }
    public static func createSharedLogV1(_ request: SharedLogCreateRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.createSharedLog(request)), body: .createSharedLog(request)) }
    public static func appendSharedLogV1(_ request: SharedLogAppendRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.appendSharedLog(request)), body: .appendSharedLog(request)) }
    public static func syncSharedLogV1(_ request: SharedLogSyncRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.syncSharedLog(request)), body: .syncSharedLog(request)) }
    public static func acquirePresenceV1(_ request: PresenceLeaseAcquireRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.acquirePresence(request)), body: .acquirePresence(request)) }
    public static func renewPresenceV1(_ request: PresenceLeaseRenewRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.renewPresence(request)), body: .renewPresence(request)) }
    public static func releasePresenceV1(_ request: PresenceLeaseReleaseRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.releasePresence(request)), body: .releasePresence(request)) }
    public static func listPresenceV1(_ request: PresenceLeaseListRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.listPresence(request)), body: .listPresence(request)) }
    public static func createMediaBlobV1(_ request: MediaBlobCreateRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.createMediaBlob(request)), body: .createMediaBlob(request)) }
    public static func uploadMediaBlobV1(_ request: MediaBlobUploadRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.uploadMediaBlob(request)), body: .uploadMediaBlob(request)) }
    public static func fetchMediaBlobV1(_ request: MediaBlobFetchRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.fetchMediaBlob(request)), body: .fetchMediaBlob(request)) }
    public static func releaseMediaBlobV1(_ request: MediaBlobReleaseRequestV1) -> RelayRequest { RelayRequest(binding: requestBodyBinding(.releaseMediaBlob(request)), body: .releaseMediaBlob(request)) }

    public static func acquireICECredentialsV1(
        _ request: RelayICECredentialRequestV1 = .fresh(),
        authToken: String? = nil
    ) -> RelayRequest {
        RelayRequest(
            binding: requestBodyBinding(.acquireICECredentials(request)),
            body: .acquireICECredentials(request),
            authToken: authToken
        )
    }

    public static func uploadAttachment(_ request: UploadAttachmentRequest) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.uploadAttachment(request)), body: .uploadAttachment(request))
    }

    public static func fetchAttachment(_ request: FetchAttachmentRequest) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.fetchAttachment(request)), body: .fetchAttachment(request))
    }

    public static func registerFederationNode(_ request: FederationNodeRegistrationRequest) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.registerFederationNode(request)), body: .registerFederationNode(request))
    }

    public static func listFederationNodes(_ request: ListFederationNodesRequest) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.listFederationNodes(request)), body: .listFederationNodes(request))
    }

    public static func getNoctwebNamespaceSnapshotV1(
        _ request: NoctwebNamespaceSnapshotRequestV1
    ) -> RelayRequest {
        RelayRequest(
            binding: requestBodyBinding(
                .getNoctwebNamespaceSnapshot(request)
            ),
            body: .getNoctwebNamespaceSnapshot(request)
        )
    }

    public static func claimNoctwebNamespaceV1(
        _ request: NoctwebNamespaceClaimRequestV1
    ) -> RelayRequest {
        RelayRequest(
            binding: requestBodyBinding(
                .claimNoctwebNamespace(request)
            ),
            body: .claimNoctwebNamespace(request)
        )
    }

    public static func rotateNoctwebNamespaceV1(
        _ request: NoctwebNamespaceRotationRequestV1
    ) -> RelayRequest {
        RelayRequest(
            binding: requestBodyBinding(
                .rotateNoctwebNamespace(request)
            ),
            body: .rotateNoctwebNamespace(request)
        )
    }

    public static func releaseNoctwebNamespaceV1(
        _ request: NoctwebNamespaceReleaseV1
    ) -> RelayRequest {
        RelayRequest(
            binding: requestBodyBinding(
                .releaseNoctwebNamespace(request)
            ),
            body: .releaseNoctwebNamespace(request)
        )
    }

    public static func forwardOpaqueRouteV1(
        _ request: FederatedOpaqueRouteForwardRequestV1
    ) -> RelayRequest {
        RelayRequest(
            binding: requestBodyBinding(.forwardOpaqueRoute(request)),
            body: .forwardOpaqueRoute(request)
        )
    }

    public static func deliverOpaqueRouteV1(
        _ request: FederatedOpaqueRouteDeliveryV1
    ) -> RelayRequest {
        RelayRequest(
            binding: requestBodyBinding(.deliverOpaqueRoute(request)),
            body: .deliverOpaqueRoute(request)
        )
    }

    public static func getFederatedNetHostObjectV1(
        _ request: FederatedNetHostReadRequestV1
    ) -> RelayRequest {
        RelayRequest(
            binding: requestBodyBinding(.getFederatedNetHostObject(request)),
            body: .getFederatedNetHostObject(request)
        )
    }

    public static func resolveFederatedNetHostNameV1(
        _ request: FederatedNetHostNameReadRequestV1
    ) -> RelayRequest {
        RelayRequest(
            binding: requestBodyBinding(
                .resolveFederatedNetHostName(request)
            ),
            body: .resolveFederatedNetHostName(request)
        )
    }

    public static func publishOpenFederationDHTRecord(_ request: PublishOpenFederationDHTRecordRequest) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.publishDHTRecord(request)), body: .publishDHTRecord(request))
    }

    public static func listOpenFederationDHTRecords(_ request: ListOpenFederationDHTRecordsRequest) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.listDHTRecords(request)), body: .listDHTRecords(request))
    }

    public static func netPassthrough(_ request: NoctweaveNetPassthroughRequest) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.netPassthrough(request)), body: .netPassthrough(request))
    }

    public static func putNetHostObject(_ request: NoctweaveNetHostPutRequest) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.putNetHostObject(request)), body: .putNetHostObject(request))
    }

    public static func bindNetHostName(
        _ request: NoctweaveNetHostNameBindingRequestV1,
        authToken: String? = nil
    ) -> RelayRequest {
        RelayRequest(
            binding: requestBodyBinding(.bindNetHostName(request)),
            body: .bindNetHostName(request),
            authToken: authToken
        )
    }

    public static func getNetHostObject(_ request: NoctweaveNetHostObjectRequest) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.getNetHostObject(request)), body: .getNetHostObject(request))
    }

    public static func resolveNetHostName(
        _ request: NoctweaveNetHostNameRequestV1
    ) -> RelayRequest {
        RelayRequest(
            binding: requestBodyBinding(.resolveNetHostName(request)),
            body: .resolveNetHostName(request)
        )
    }

    public static func hasNetHostObject(_ request: NoctweaveNetHostObjectRequest) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.hasNetHostObject(request)), body: .hasNetHostObject(request))
    }

    public static func releaseNetHostObject(_ request: NoctweaveNetHostReleaseRequest) -> RelayRequest {
        RelayRequest(binding: requestBodyBinding(.releaseNetHostObject(request)), body: .releaseNetHostObject(request))
    }

    public func withAuthToken(_ token: String?) -> RelayRequest {
        RelayRequest(requestID: requestID, binding: binding, body: body, authToken: token)
    }

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(
            decoder,
            keys: ["requestID", "module", "version", "method", "body", "authToken"]
        )
        let container = try decoder.container(keyedBy: RelayRequestCodingKeys.self)
        requestID = try container.decode(UUID.self, forKey: .requestID)
        module = try container.decode(RelayModuleID.self, forKey: .module)
        version = try container.decode(Int.self, forKey: .version)
        method = try container.decode(RelayMethodID.self, forKey: .method)
        authToken = try container.decodeIfPresent(String.self, forKey: .authToken)
        let binding = RelayOperationBinding(module: module, version: version, method: method)
        guard binding.isCurrent else {
            throw relayWireError(decoder, "Relay request uses an unsupported module, version, or method")
        }
        body = try RelayRequestBody.decode(for: binding, from: container.superDecoder(forKey: .body))
        if case .empty = body {
            guard module == .core else {
                throw relayWireError(decoder, "Empty request body is valid only for nw.core")
            }
        } else if body.binding != binding {
            throw relayWireError(decoder, "Relay request body does not match its module binding")
        }
        guard authToken.map({ !$0.isEmpty && $0.utf8.count <= RelayClient.maxAuthenticationBytes }) ?? true else {
            throw relayWireError(decoder, "Relay authentication token is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard binding.isCurrent else {
            throw relayWireError(encoder, "Cannot encode a non-current relay request")
        }
        guard authToken.map({ !$0.isEmpty && $0.utf8.count <= RelayClient.maxAuthenticationBytes }) ?? true else {
            throw relayWireError(encoder, "Relay authentication token is invalid")
        }
        var container = encoder.container(keyedBy: RelayRequestCodingKeys.self)
        try container.encode(requestID, forKey: .requestID)
        try container.encode(module, forKey: .module)
        try container.encode(version, forKey: .version)
        try container.encode(method, forKey: .method)
        try body.encode(to: container.superEncoder(forKey: .body))
        if let authToken {
            try container.encode(authToken, forKey: .authToken)
        } else {
            try container.encodeNil(forKey: .authToken)
        }
    }

    private enum RelayRequestCodingKeys: String, CodingKey {
        case requestID
        case module
        case version
        case method
        case body
        case authToken
    }
}

public enum RelayResponseStatus: String, Codable {
    case success
    case error
}

public enum RelayErrorCode: String, Codable, CaseIterable {
    case authenticationRequired = "authentication-required"
    case rateLimited = "rate-limited"
    case invalidRequest = "invalid-request"
    case unavailable
    case notFound = "not-found"
    case conflict
    case capacity
    case internalFailure = "internal-failure"
}

public struct RelayErrorBody: Codable, Equatable {
    public static let maximumMessageBytes = 512

    public let code: RelayErrorCode
    public let message: String
    public let retryable: Bool

    public init(code: RelayErrorCode, message: String, retryable: Bool = false) {
        self.code = code
        self.message = relayBoundedErrorMessage(message)
        self.retryable = retryable
    }

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: ["code", "message", "retryable"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        code = try container.decode(RelayErrorCode.self, forKey: .code)
        message = try container.decode(String.self, forKey: .message)
        retryable = try container.decode(Bool.self, forKey: .retryable)
        guard !message.isEmpty, message.utf8.count <= Self.maximumMessageBytes else {
            throw relayWireError(decoder, "Relay error message is outside protocol bounds")
        }
    }

    private enum CodingKeys: String, CodingKey {
        case code
        case message
        case retryable
    }
}

public struct FederationNodesResponseBody: Equatable {
    public static let maximumNodes = 10_000

    public let nodes: [FederationNodeRecord]
    public let snapshot: FederationDirectorySnapshot?

    public init(nodes: [FederationNodeRecord], snapshot: FederationDirectorySnapshot? = nil) {
        self.nodes = nodes
        self.snapshot = snapshot
    }

    public var isStructurallyValid: Bool {
        guard nodes.count <= Self.maximumNodes,
              nodes.allSatisfy(\.isStructurallyValid) else {
            return false
        }
        let endpointKeys = nodes.map { relayEndpointStructuralKey($0.endpoint) }
        return Set(endpointKeys).count == nodes.count
            && snapshot?.isStructurallyValid != false
            && (snapshot == nil || snapshot?.nodes == nodes)
    }
}

public enum RelaySuccessBody: Equatable {
    case empty
    case relayInfo(RelayInfo)
    case opaqueRoute(OpaqueReceiveRouteV2)
    case opaqueRouteAppend(OpaqueRouteAppendReceiptV2)
    case opaqueRouteSync(OpaqueRouteSyncResponseV2)
    case opaqueRouteCommit(OpaqueRouteCommitResponseV2)
    case rendezvousSync(RendezvousRelaySyncBatchV2)
    case realtimeRouteCreated(RealtimeRouteCreatedV1)
    case realtimeRouteAppend(RealtimeRouteAppendReceiptV1)
    case realtimeRouteSubscription(RealtimeRouteSubscriptionV1)
    case realtimeRouteSync(OpaqueRelaySyncBatchV1)
    case sharedLogCreated(SharedLogCreatedV1)
    case sharedLogAppend(SharedLogAppendReceiptV1)
    case sharedLogSync(OpaqueRelaySyncBatchV1)
    case presenceLease(PresenceLeaseV1)
    case presenceLeases([PresenceLeaseV1])
    case mediaBlobCreated(MediaBlobCreatedV1)
    case mediaBlobChunk(MediaBlobChunkV1)
    case iceCredentials(RelayICECredentialsV1)
    case attachment(AttachmentChunk)
    case federationNodes(FederationNodesResponseBody)
    case noctwebNamespaceSnapshot(NoctwebNamespaceSnapshotV1)
    case noctwebNamespaceRecord(NoctwebNamespaceRecordV1)
    case dhtRecords([OpenFederationDHTRecord])
    case netPassthrough(NoctweaveNetPassthroughResponse)
    case netHostReceipt(NoctweaveNetHostingReceipt)
    case netHostObject(NoctweaveNetHostFetchResponse)
    case federatedNetHostObject(FederatedNetHostObjectResponseV1)
    case netHostNameResolution(NoctweaveNetHostNameResolutionV1)
    case federatedNetHostNameResolution(FederatedNetHostNameResponseV1)
    case netHostPresence(NoctweaveNetHostPresence)
    case netHostRelease(NoctweaveNetHostReleaseReceipt)

    fileprivate func supports(_ binding: RelayOperationBinding) -> Bool {
        switch self {
        case .empty:
            return binding == RelayOperationBinding(module: .core, version: 2, method: .health)
                || binding == RelayOperationBinding(module: .rendezvousTransport, version: 2, method: .register)
                || binding == RelayOperationBinding(module: .rendezvousTransport, version: 2, method: .append)
                || binding == RelayOperationBinding(module: .rendezvousTransport, version: 2, method: .delete)
                || binding == RelayOperationBinding(module: .openDiscovery, version: 1, method: .publishDHT)
                || binding == RelayOperationBinding(module: .realtimeRoute, version: 1, method: .unsubscribe)
                || binding == RelayOperationBinding(module: .ephemeralPresence, version: 1, method: .release)
                || binding == RelayOperationBinding(module: .mediaBlobs, version: 1, method: .release)
        case .relayInfo:
            return binding == RelayOperationBinding(module: .core, version: 2, method: .info)
        case .opaqueRoute:
            return binding.module == .opaqueRoute
                && binding.version == 2
                && [.create, .renew, .teardown].contains(binding.method)
        case .opaqueRouteAppend:
            return binding == RelayOperationBinding(module: .opaqueRoute, version: 2, method: .append)
                || binding == RelayOperationBinding(module: .federationForward, version: 1, method: .forward)
                || binding == RelayOperationBinding(module: .federationForward, version: 1, method: .deliver)
        case .opaqueRouteSync:
            return binding == RelayOperationBinding(module: .opaqueRoute, version: 2, method: .sync)
        case .opaqueRouteCommit:
            return binding == RelayOperationBinding(module: .opaqueRoute, version: 2, method: .commit)
        case .rendezvousSync:
            return binding == RelayOperationBinding(module: .rendezvousTransport, version: 2, method: .sync)
        case .realtimeRouteCreated:
            return binding == RelayOperationBinding(module: .realtimeRoute, version: 1, method: .create)
        case .realtimeRouteAppend:
            return binding == RelayOperationBinding(module: .realtimeRoute, version: 1, method: .append)
        case .realtimeRouteSubscription:
            return binding == RelayOperationBinding(module: .realtimeRoute, version: 1, method: .subscribe)
        case .realtimeRouteSync:
            return binding == RelayOperationBinding(module: .realtimeRoute, version: 1, method: .sync)
        case .sharedLogCreated:
            return binding == RelayOperationBinding(module: .sharedLog, version: 1, method: .create)
        case .sharedLogAppend:
            return binding == RelayOperationBinding(module: .sharedLog, version: 1, method: .append)
        case .sharedLogSync:
            return binding == RelayOperationBinding(module: .sharedLog, version: 1, method: .sync)
        case .presenceLease:
            return binding == RelayOperationBinding(module: .ephemeralPresence, version: 1, method: .acquire)
                || binding == RelayOperationBinding(module: .ephemeralPresence, version: 1, method: .renewLease)
        case .presenceLeases:
            return binding == RelayOperationBinding(module: .ephemeralPresence, version: 1, method: .list)
        case .mediaBlobCreated:
            return binding == RelayOperationBinding(module: .mediaBlobs, version: 1, method: .create)
        case .mediaBlobChunk:
            return binding == RelayOperationBinding(module: .mediaBlobs, version: 1, method: .upload)
                || binding == RelayOperationBinding(module: .mediaBlobs, version: 1, method: .fetch)
        case .iceCredentials:
            return binding == RelayOperationBinding(module: .iceService, version: 1, method: .acquire)
        case .attachment:
            return binding.module == .blobs && binding.version == 1 && [.upload, .fetch].contains(binding.method)
        case .federationNodes:
            return binding.module == .federation && binding.version == 1 && [.register, .list].contains(binding.method)
        case .noctwebNamespaceSnapshot:
            return binding == RelayOperationBinding(
                module: .federation,
                version: 1,
                method: .namespace
            )
        case .noctwebNamespaceRecord:
            return binding.module == .federation
                && binding.version == 1
                && [.claim, .rotate, .release].contains(
                    binding.method
                )
        case .dhtRecords:
            return binding == RelayOperationBinding(module: .openDiscovery, version: 1, method: .listDHT)
        case .netPassthrough:
            return binding == RelayOperationBinding(module: .netPassthrough, version: 1, method: .forward)
        case .netHostReceipt:
            return binding == RelayOperationBinding(module: .netHost, version: 1, method: .put)
        case .netHostObject:
            return binding == RelayOperationBinding(module: .netHost, version: 1, method: .get)
        case .federatedNetHostObject:
            return binding == RelayOperationBinding(module: .federationForward, version: 1, method: .get)
        case .netHostNameResolution:
            return binding == RelayOperationBinding(
                module: .netHost,
                version: 1,
                method: .bind
            ) || binding == RelayOperationBinding(
                module: .netHost,
                version: 1,
                method: .resolve
            )
        case .federatedNetHostNameResolution:
            return binding == RelayOperationBinding(
                module: .federationForward,
                version: 1,
                method: .resolve
            )
        case .netHostPresence:
            return binding == RelayOperationBinding(module: .netHost, version: 1, method: .has)
        case .netHostRelease:
            return binding == RelayOperationBinding(module: .netHost, version: 1, method: .release)
        }
    }

    fileprivate static func decode(
        for binding: RelayOperationBinding,
        from decoder: Decoder
    ) throws -> RelaySuccessBody {
        switch (binding.module, binding.method) {
        case (.core, .health),
             (.rendezvousTransport, .register),
             (.rendezvousTransport, .append),
             (.rendezvousTransport, .delete),
             (.openDiscovery, .publishDHT),
             (.realtimeRoute, .unsubscribe),
             (.ephemeralPresence, .release),
             (.mediaBlobs, .release):
            try relayRequireExactObject(decoder, keys: [])
            return .empty
        case (.core, .info):
            try relayRequireExactObject(decoder, keys: ["relayInfo"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .relayInfo(try container.decode(RelayInfo.self, forKey: relayWireKey("relayInfo")))
        case (.opaqueRoute, .create), (.opaqueRoute, .renew), (.opaqueRoute, .teardown):
            try relayRequireExactObject(decoder, keys: ["route"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .opaqueRoute(try container.decode(OpaqueReceiveRouteV2.self, forKey: relayWireKey("route")))
        case (.opaqueRoute, .append):
            try relayRequireExactObject(decoder, keys: ["receipt"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .opaqueRouteAppend(try container.decode(OpaqueRouteAppendReceiptV2.self, forKey: relayWireKey("receipt")))
        case (.federationForward, .forward), (.federationForward, .deliver):
            try relayRequireExactObject(decoder, keys: ["receipt"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .opaqueRouteAppend(try container.decode(
                OpaqueRouteAppendReceiptV2.self,
                forKey: relayWireKey("receipt")
            ))
        case (.opaqueRoute, .sync):
            try relayRequireExactObject(decoder, keys: ["batch"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .opaqueRouteSync(try container.decode(OpaqueRouteSyncResponseV2.self, forKey: relayWireKey("batch")))
        case (.opaqueRoute, .commit):
            try relayRequireExactObject(decoder, keys: ["commit"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .opaqueRouteCommit(try container.decode(OpaqueRouteCommitResponseV2.self, forKey: relayWireKey("commit")))
        case (.rendezvousTransport, .sync):
            try relayRequireExactObject(decoder, keys: ["batch"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .rendezvousSync(try container.decode(RendezvousRelaySyncBatchV2.self, forKey: relayWireKey("batch")))
        case (.realtimeRoute, .create):
            try relayRequireExactObject(decoder, keys: ["route"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .realtimeRouteCreated(try container.decode(RealtimeRouteCreatedV1.self, forKey: relayWireKey("route")))
        case (.realtimeRoute, .append):
            try relayRequireExactObject(decoder, keys: ["receipt"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .realtimeRouteAppend(try container.decode(RealtimeRouteAppendReceiptV1.self, forKey: relayWireKey("receipt")))
        case (.realtimeRoute, .subscribe):
            try relayRequireExactObject(decoder, keys: ["subscription"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .realtimeRouteSubscription(try container.decode(RealtimeRouteSubscriptionV1.self, forKey: relayWireKey("subscription")))
        case (.realtimeRoute, .sync):
            try relayRequireExactObject(decoder, keys: ["batch"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .realtimeRouteSync(try container.decode(OpaqueRelaySyncBatchV1.self, forKey: relayWireKey("batch")))
        case (.sharedLog, .create):
            try relayRequireExactObject(decoder, keys: ["log"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .sharedLogCreated(try container.decode(SharedLogCreatedV1.self, forKey: relayWireKey("log")))
        case (.sharedLog, .append):
            try relayRequireExactObject(decoder, keys: ["receipt"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .sharedLogAppend(try container.decode(SharedLogAppendReceiptV1.self, forKey: relayWireKey("receipt")))
        case (.sharedLog, .sync):
            try relayRequireExactObject(decoder, keys: ["batch"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .sharedLogSync(try container.decode(OpaqueRelaySyncBatchV1.self, forKey: relayWireKey("batch")))
        case (.ephemeralPresence, .acquire), (.ephemeralPresence, .renewLease):
            try relayRequireExactObject(decoder, keys: ["lease"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .presenceLease(try container.decode(PresenceLeaseV1.self, forKey: relayWireKey("lease")))
        case (.ephemeralPresence, .list):
            try relayRequireExactObject(decoder, keys: ["leases"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .presenceLeases(try container.decode([PresenceLeaseV1].self, forKey: relayWireKey("leases")))
        case (.mediaBlobs, .create):
            try relayRequireExactObject(decoder, keys: ["blob"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .mediaBlobCreated(try container.decode(MediaBlobCreatedV1.self, forKey: relayWireKey("blob")))
        case (.mediaBlobs, .upload), (.mediaBlobs, .fetch):
            try relayRequireExactObject(decoder, keys: ["chunk"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .mediaBlobChunk(try container.decode(MediaBlobChunkV1.self, forKey: relayWireKey("chunk")))
        case (.iceService, .acquire):
            try relayRequireExactObject(decoder, keys: ["credentials"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .iceCredentials(try container.decode(
                RelayICECredentialsV1.self,
                forKey: relayWireKey("credentials")
            ))
        case (.blobs, .upload), (.blobs, .fetch):
            try relayRequireExactObject(decoder, keys: ["chunk"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .attachment(try container.decode(AttachmentChunk.self, forKey: relayWireKey("chunk")))
        case (.federation, .register), (.federation, .list):
            try relayRequireExactObject(decoder, keys: ["nodes", "snapshot"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            let body = FederationNodesResponseBody(
                nodes: try container.decode([FederationNodeRecord].self, forKey: relayWireKey("nodes")),
                snapshot: try container.decodeIfPresent(FederationDirectorySnapshot.self, forKey: relayWireKey("snapshot"))
            )
            guard body.isStructurallyValid else {
                throw relayWireError(decoder, "Federation node response is invalid")
            }
            return .federationNodes(body)
        case (.federation, .namespace):
            try relayRequireExactObject(
                decoder,
                keys: ["namespaceSnapshot"]
            )
            let container = try decoder.container(
                keyedBy: RelayWireCodingKey.self
            )
            return .noctwebNamespaceSnapshot(try container.decode(
                NoctwebNamespaceSnapshotV1.self,
                forKey: relayWireKey("namespaceSnapshot")
            ))
        case (.federation, .claim),
             (.federation, .rotate),
             (.federation, .release):
            try relayRequireExactObject(
                decoder,
                keys: ["namespaceRecord"]
            )
            let container = try decoder.container(
                keyedBy: RelayWireCodingKey.self
            )
            return .noctwebNamespaceRecord(try container.decode(
                NoctwebNamespaceRecordV1.self,
                forKey: relayWireKey("namespaceRecord")
            ))
        case (.openDiscovery, .listDHT):
            try relayRequireExactObject(decoder, keys: ["records"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .dhtRecords(try container.decode([OpenFederationDHTRecord].self, forKey: relayWireKey("records")))
        case (.netPassthrough, .forward):
            try relayRequireExactObject(decoder, keys: ["passthrough"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .netPassthrough(try container.decode(
                NoctweaveNetPassthroughResponse.self,
                forKey: relayWireKey("passthrough")
            ))
        case (.netHost, .put):
            try relayRequireExactObject(decoder, keys: ["receipt"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .netHostReceipt(try container.decode(
                NoctweaveNetHostingReceipt.self,
                forKey: relayWireKey("receipt")
            ))
        case (.netHost, .get):
            try relayRequireExactObject(decoder, keys: ["object"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .netHostObject(try container.decode(
                NoctweaveNetHostFetchResponse.self,
                forKey: relayWireKey("object")
            ))
        case (.federationForward, .get):
            try relayRequireExactObject(decoder, keys: ["federatedObject"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .federatedNetHostObject(try container.decode(
                FederatedNetHostObjectResponseV1.self,
                forKey: relayWireKey("federatedObject")
            ))
        case (.netHost, .bind), (.netHost, .resolve):
            try relayRequireExactObject(
                decoder,
                keys: ["nameResolution"]
            )
            let container = try decoder.container(
                keyedBy: RelayWireCodingKey.self
            )
            return .netHostNameResolution(try container.decode(
                NoctweaveNetHostNameResolutionV1.self,
                forKey: relayWireKey("nameResolution")
            ))
        case (.federationForward, .resolve):
            try relayRequireExactObject(
                decoder,
                keys: ["federatedNameResolution"]
            )
            let container = try decoder.container(
                keyedBy: RelayWireCodingKey.self
            )
            return .federatedNetHostNameResolution(
                try container.decode(
                    FederatedNetHostNameResponseV1.self,
                    forKey: relayWireKey("federatedNameResolution")
                )
            )
        case (.netHost, .has):
            try relayRequireExactObject(decoder, keys: ["presence"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .netHostPresence(try container.decode(
                NoctweaveNetHostPresence.self,
                forKey: relayWireKey("presence")
            ))
        case (.netHost, .release):
            try relayRequireExactObject(decoder, keys: ["release"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .netHostRelease(try container.decode(
                NoctweaveNetHostReleaseReceipt.self,
                forKey: relayWireKey("release")
            ))
        default:
            throw relayWireError(decoder, "Relay operation does not define a success body")
        }
    }

    fileprivate func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RelayWireCodingKey.self)
        switch self {
        case .empty:
            break
        case .relayInfo(let value):
            try container.encode(value, forKey: relayWireKey("relayInfo"))
        case .opaqueRoute(let value):
            try container.encode(value, forKey: relayWireKey("route"))
        case .opaqueRouteAppend(let value):
            try container.encode(value, forKey: relayWireKey("receipt"))
        case .opaqueRouteSync(let value):
            try container.encode(value, forKey: relayWireKey("batch"))
        case .opaqueRouteCommit(let value):
            try container.encode(value, forKey: relayWireKey("commit"))
        case .rendezvousSync(let value):
            try container.encode(value, forKey: relayWireKey("batch"))
        case .realtimeRouteCreated(let value):
            try container.encode(value, forKey: relayWireKey("route"))
        case .realtimeRouteAppend(let value):
            try container.encode(value, forKey: relayWireKey("receipt"))
        case .realtimeRouteSubscription(let value):
            try container.encode(value, forKey: relayWireKey("subscription"))
        case .realtimeRouteSync(let value), .sharedLogSync(let value):
            try container.encode(value, forKey: relayWireKey("batch"))
        case .sharedLogCreated(let value):
            try container.encode(value, forKey: relayWireKey("log"))
        case .sharedLogAppend(let value):
            try container.encode(value, forKey: relayWireKey("receipt"))
        case .presenceLease(let value):
            try container.encode(value, forKey: relayWireKey("lease"))
        case .presenceLeases(let value):
            try container.encode(value, forKey: relayWireKey("leases"))
        case .mediaBlobCreated(let value):
            try container.encode(value, forKey: relayWireKey("blob"))
        case .mediaBlobChunk(let value):
            try container.encode(value, forKey: relayWireKey("chunk"))
        case .iceCredentials(let value):
            try container.encode(value, forKey: relayWireKey("credentials"))
        case .attachment(let value):
            try container.encode(value, forKey: relayWireKey("chunk"))
        case .federationNodes(let value):
            guard value.isStructurallyValid else {
                throw relayWireError(encoder, "Federation node response is invalid")
            }
            try container.encode(value.nodes, forKey: relayWireKey("nodes"))
            try relayEncodeOptional(value.snapshot, key: "snapshot", into: &container)
        case .noctwebNamespaceSnapshot(let value):
            try container.encode(
                value,
                forKey: relayWireKey("namespaceSnapshot")
            )
        case .noctwebNamespaceRecord(let value):
            try container.encode(
                value,
                forKey: relayWireKey("namespaceRecord")
            )
        case .dhtRecords(let value):
            try container.encode(value, forKey: relayWireKey("records"))
        case .netPassthrough(let value):
            try container.encode(value, forKey: relayWireKey("passthrough"))
        case .netHostReceipt(let value):
            try container.encode(value, forKey: relayWireKey("receipt"))
        case .netHostObject(let value):
            try container.encode(value, forKey: relayWireKey("object"))
        case .federatedNetHostObject(let value):
            try container.encode(value, forKey: relayWireKey("federatedObject"))
        case .netHostNameResolution(let value):
            try container.encode(
                value,
                forKey: relayWireKey("nameResolution")
            )
        case .federatedNetHostNameResolution(let value):
            try container.encode(
                value,
                forKey: relayWireKey("federatedNameResolution")
            )
        case .netHostPresence(let value):
            try container.encode(value, forKey: relayWireKey("presence"))
        case .netHostRelease(let value):
            try container.encode(value, forKey: relayWireKey("release"))
        }
    }
}

public struct RelayResponse: Codable, Equatable {
    public let requestID: UUID
    public let module: RelayModuleID
    public let version: Int
    public let method: RelayMethodID
    public let status: RelayResponseStatus
    public let successBody: RelaySuccessBody?
    public let error: RelayErrorBody?

    public var binding: RelayOperationBinding {
        RelayOperationBinding(module: module, version: version, method: method)
    }

    private init(
        request: RelayRequest,
        status: RelayResponseStatus,
        successBody: RelaySuccessBody?,
        error: RelayErrorBody?
    ) {
        requestID = request.requestID
        module = request.module
        version = request.version
        method = request.method
        self.status = status
        self.successBody = successBody
        self.error = error
    }

    public static func success(_ body: RelaySuccessBody, respondingTo request: RelayRequest) -> RelayResponse {
        precondition(body.supports(request.binding), "Success body does not match relay request binding")
        return RelayResponse(request: request, status: .success, successBody: body, error: nil)
    }

    public static func error(
        _ message: String,
        code: RelayErrorCode = .invalidRequest,
        retryable: Bool = false,
        respondingTo request: RelayRequest
    ) -> RelayResponse {
        RelayResponse(
            request: request,
            status: .error,
            successBody: nil,
            error: RelayErrorBody(code: code, message: message, retryable: retryable)
        )
    }

    public func isResponse(to request: RelayRequest) -> Bool {
        requestID == request.requestID && binding == request.binding
    }

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(
            decoder,
            keys: ["requestID", "module", "version", "method", "status", "body", "error"]
        )
        let container = try decoder.container(keyedBy: RelayResponseCodingKeys.self)
        requestID = try container.decode(UUID.self, forKey: .requestID)
        module = try container.decode(RelayModuleID.self, forKey: .module)
        version = try container.decode(Int.self, forKey: .version)
        method = try container.decode(RelayMethodID.self, forKey: .method)
        status = try container.decode(RelayResponseStatus.self, forKey: .status)
        let binding = RelayOperationBinding(module: module, version: version, method: method)
        guard binding.isCurrent else {
            throw relayWireError(decoder, "Relay response uses an unsupported module, version, or method")
        }
        switch status {
        case .success:
            guard try container.decodeNil(forKey: .error) else {
                throw relayWireError(decoder, "Successful relay response must contain a null error")
            }
            successBody = try RelaySuccessBody.decode(
                for: binding,
                from: container.superDecoder(forKey: .body)
            )
            error = nil
        case .error:
            guard try container.decodeNil(forKey: .body) else {
                throw relayWireError(decoder, "Error relay response must contain a null body")
            }
            successBody = nil
            error = try container.decode(RelayErrorBody.self, forKey: .error)
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard binding.isCurrent else {
            throw relayWireError(encoder, "Cannot encode a non-current relay response")
        }
        var container = encoder.container(keyedBy: RelayResponseCodingKeys.self)
        try container.encode(requestID, forKey: .requestID)
        try container.encode(module, forKey: .module)
        try container.encode(version, forKey: .version)
        try container.encode(method, forKey: .method)
        try container.encode(status, forKey: .status)
        switch status {
        case .success:
            guard let successBody, error == nil, successBody.supports(binding) else {
                throw relayWireError(encoder, "Invalid success response state")
            }
            try successBody.encode(to: container.superEncoder(forKey: .body))
            try container.encodeNil(forKey: .error)
        case .error:
            guard successBody == nil, let error else {
                throw relayWireError(encoder, "Invalid error response state")
            }
            try container.encodeNil(forKey: .body)
            try container.encode(error, forKey: .error)
        }
    }

    private enum RelayResponseCodingKeys: String, CodingKey {
        case requestID
        case module
        case version
        case method
        case status
        case body
        case error
    }
}

private func requestBodyBinding(_ body: RelayRequestBody) -> RelayOperationBinding {
    body.binding
}

private struct RelayWireCodingKey: CodingKey {
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

private func relayWireKey(_ value: String) -> RelayWireCodingKey {
    RelayWireCodingKey(stringValue: value)!
}

private func relayRequireExactObject(_ decoder: Decoder, keys: Set<String>) throws {
    let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == keys else {
        throw relayWireError(decoder, "Relay object fields do not match the current protocol exactly")
    }
}

private func relayDecodeExact<T: Decodable>(
    _ type: T.Type,
    from decoder: Decoder,
    keys: Set<String>
) throws -> T {
    try relayRequireExactObject(decoder, keys: keys)
    return try T(from: decoder)
}

private func relayDecodeSingle<T: Decodable>(
    _ type: T.Type,
    from decoder: Decoder,
    key: String
) throws -> T {
    try relayRequireExactObject(decoder, keys: [key])
    let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
    return try container.decode(T.self, forKey: relayWireKey(key))
}

private func relayEncodeOptional<T: Encodable>(
    _ value: T?,
    key: String,
    into container: inout KeyedEncodingContainer<RelayWireCodingKey>
) throws {
    if let value {
        try container.encode(value, forKey: relayWireKey(key))
    } else {
        try container.encodeNil(forKey: relayWireKey(key))
    }
}

private func decodeRendezvousRelayOpaqueValue(
    from decoder: Decoder,
    byteCount: Int
) throws -> Data {
    try relayRequireExactObject(decoder, keys: ["rawValue"])
    let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
    let value = try container.decode(Data.self, forKey: relayWireKey("rawValue"))
    guard RendezvousRelayTransportV2.isValidOpaqueValue(value, byteCount: byteCount) else {
        throw relayWireError(decoder, "Rendezvous relay opaque value is invalid")
    }
    return value
}

private func encodeRendezvousRelayOpaqueValue(
    _ value: Data,
    byteCount: Int,
    to encoder: Encoder
) throws {
    guard RendezvousRelayTransportV2.isValidOpaqueValue(value, byteCount: byteCount) else {
        throw relayWireError(encoder, "Rendezvous relay opaque value is invalid")
    }
    var container = encoder.container(keyedBy: RelayWireCodingKey.self)
    try container.encode(value, forKey: relayWireKey("rawValue"))
}

private func relayIsBoundedRequiredText(_ value: String, maximumBytes: Int) -> Bool {
    let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
    return !normalized.isEmpty
        && normalized == value
        && value.utf8.count <= maximumBytes
        && value.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
}

private func relayIsBoundedText(_ value: String?, maximumBytes: Int) -> Bool {
    value.map { relayIsBoundedRequiredText($0, maximumBytes: maximumBytes) } ?? true
}

private func relayCanonicalizedDate(_ value: Date) -> Date {
    let seconds = value.timeIntervalSince1970
    guard seconds.isFinite else { return value }
    return Date(timeIntervalSince1970: floor(seconds))
}

private func relayIsCanonicalTimestamp(_ value: Date) -> Bool {
    let seconds = value.timeIntervalSince1970
    return seconds.isFinite
        && seconds >= 0
        && seconds <= 4_102_444_800
        && floor(seconds) == seconds
}

private func relayEndpointStructuralKey(_ endpoint: RelayEndpoint) -> String {
    [
        endpoint.host.lowercased(),
        String(endpoint.port),
        endpoint.useTLS ? "1" : "0",
        endpoint.transport.rawValue
    ].joined(separator: "\u{0}")
}

private func relayIsValidEndpointList(
    _ endpoints: [RelayEndpoint],
    maximumCount: Int
) -> Bool {
    (try? relayIsValidEndpointListThrowing(endpoints, maximumCount: maximumCount)) == true
}

private func relayIsValidEndpointListThrowing(
    _ endpoints: [RelayEndpoint],
    maximumCount: Int
) throws -> Bool {
    guard endpoints.count <= maximumCount,
          Set(endpoints.map(relayEndpointStructuralKey)).count == endpoints.count else {
        return false
    }
    for endpoint in endpoints {
        guard try endpoint.isStructurallyValidRelationshipRouteEndpointV2Throwing else {
            return false
        }
    }
    return true
}

private func relayIsValidWakeSupport(_ support: DecentralizedWakeSupport?) -> Bool {
    guard let support else { return true }
    guard (5...DecentralizedWakeSupport.absoluteMaximumPollIntervalSeconds)
        .contains(support.minPollIntervalSeconds),
          (support.minPollIntervalSeconds...DecentralizedWakeSupport.absoluteMaximumPollIntervalSeconds)
        .contains(support.maxPollIntervalSeconds),
          (0...1_000).contains(support.jitterPermille) else {
        return false
    }
    switch support.mode {
    case .pullOnly:
        return support.longPollTimeoutSeconds == nil
    case .longPoll:
        guard let timeout = support.longPollTimeoutSeconds else { return false }
        return (5...support.maxPollIntervalSeconds).contains(timeout)
    }
}

private func relayBoundedErrorMessage(_ message: String) -> String {
    let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty, trimmed.utf8.count <= RelayErrorBody.maximumMessageBytes else {
        return "Relay request failed"
    }
    return trimmed
}

private func relayWireError(_ decoder: Decoder, _ description: String) -> DecodingError {
    DecodingError.dataCorrupted(
        DecodingError.Context(codingPath: decoder.codingPath, debugDescription: description)
    )
}

private func relayWireError(_ encoder: Encoder, _ description: String) -> EncodingError {
    EncodingError.invalidValue(
        description,
        EncodingError.Context(codingPath: encoder.codingPath, debugDescription: description)
    )
}

public struct AttachmentChunk: Codable, Equatable {
    public static let maximumChunkCount = 512
    public static let maximumPayloadBytes = 128 * 1_024

    public let attachmentId: UUID
    public let chunkIndex: Int
    public let payload: EncryptedPayload

    public init(attachmentId: UUID, chunkIndex: Int, payload: EncryptedPayload) {
        self.attachmentId = attachmentId
        self.chunkIndex = chunkIndex
        self.payload = payload
    }

    public var isStructurallyValid: Bool {
        let payloadBytes = payload.nonce.count + payload.ciphertext.count + payload.tag.count
        return (0..<Self.maximumChunkCount).contains(chunkIndex)
            && payload.isStructurallyValid
            && payloadBytes <= Self.maximumPayloadBytes
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case attachmentId
        case chunkIndex
        case payload
    }

    public init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        attachmentId = try container.decode(UUID.self, forKey: .attachmentId)
        chunkIndex = try container.decode(Int.self, forKey: .chunkIndex)
        payload = try container.decode(EncryptedPayload.self, forKey: .payload)
        guard isStructurallyValid else {
            throw relayWireError(decoder, "Attachment chunk is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayWireError(encoder, "Attachment chunk is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(attachmentId, forKey: .attachmentId)
        try container.encode(chunkIndex, forKey: .chunkIndex)
        try container.encode(payload, forKey: .payload)
    }
}
