import Foundation
@preconcurrency import NIOConcurrencyHelpers

enum OperatorConfigurationError: LocalizedError, Equatable {
    case invalidField(String)
    case unsupportedTransition(String)
    case persistenceUnavailable

    var errorDescription: String? {
        switch self {
        case .invalidField(let field):
            return "Invalid operator configuration: \(field)."
        case .unsupportedTransition(let reason):
            return reason
        case .persistenceUnavailable:
            return "Operator configuration persistence is unavailable in memory-only mode."
        }
    }
}

struct OperatorEditableConfiguration: Codable, Equatable {
    static let maximumTextBytes = 1_024
    static let maximumEndpointCount = 256

    var relayName: String
    var operatorNote: String
    var advertisedEndpoint: String
    var federationMode: String
    var federationName: String
    var federationDescription: String
    var federationAllowList: [String]
    var federationCoordinatorEndpoints: [String]
    var temporalBucketSeconds: Int
    var temporalBucketScheduleSeconds: [Int]
    var attachmentsEnabled: Bool
    var attachmentDefaultTTLSeconds: Int
    var attachmentMaxTTLSeconds: Int
    var attachmentStorageMode: String?
    var ipfsAPIEndpoint: String?
    var ipfsGatewayEndpoint: String?
    var ipfsTimeoutSeconds: Int?
    var hiddenRetrievalEnabled: Bool?
    var hiddenRetrievalMode: String?
    var hiddenRetrievalCoverSize: Int?
    var hiddenRetrievalMaxCoverSize: Int?
    var hiddenRetrievalReplicas: [String]?
    var onionTransportEnabled: Bool?
    var onionTransportMaxHops: Int?
    var onionTransportRequiresFixedSizePackets: Bool?
    var mixnetTransportEnabled: Bool?
    var mixnetBatchIntervalSeconds: Int?
    var mixnetMinBatchSize: Int?
    var mixnetCoverPacketsPerBatch: Int?
    var mixnetMaxDelaySeconds: Int?
    var relayPeerExchangeLimit: Int
    var openFederationDHTEnabled: Bool
    var openFederationDHTMaxRecords: Int?
    var openFederationDHTMaxRecordsPerHost: Int?
    var openFederationDHTMaxQueryRecords: Int?
    var coordinatorHeartbeatSeconds: Int?
    var coordinatorDirectoryMaxStalenessSeconds: Int?
    var curatedStrictPolicyEnabled: Bool?
    var curatedCoordinatorQuorum: Int?
    var curatedRequireSignedDirectory: Bool?
    var allowPrivateFederationEndpoints: Bool?
    var opaqueRouteRuntimeEnabled: Bool

    init(configuration: RelayConfiguration, serverConfiguration: ServerConfig? = nil) {
        relayName = configuration.relayName ?? ""
        operatorNote = configuration.operatorNote ?? ""
        advertisedEndpoint = configuration.advertisedEndpoint.map(operatorRelayEndpointString) ?? ""
        federationMode = configuration.federation.mode.rawValue
        federationName = configuration.federation.name ?? ""
        federationDescription = configuration.federation.description ?? ""
        federationAllowList = configuration.federationAllowList.map(operatorRelayEndpointString)
        federationCoordinatorEndpoints = (configuration.federationCoordinatorEndpoints ?? []).map(operatorRelayEndpointString)
        temporalBucketSeconds = configuration.temporalBucketSeconds
        temporalBucketScheduleSeconds = configuration.temporalBucketScheduleSeconds ?? []
        attachmentsEnabled = configuration.attachmentsEnabled != false
        attachmentDefaultTTLSeconds = configuration.attachmentDefaultTTLSeconds
        attachmentMaxTTLSeconds = configuration.attachmentMaxTTLSeconds
        attachmentStorageMode = serverConfiguration?.attachmentStorageMode.rawValue
            ?? configuration.attachmentStorageBackend
            ?? AttachmentStorageMode.inline.rawValue
        ipfsAPIEndpoint = serverConfiguration?.ipfsAPIEndpoint?.absoluteString ?? "http://127.0.0.1:5001"
        ipfsGatewayEndpoint = serverConfiguration?.ipfsGatewayEndpoint?.absoluteString ?? ""
        ipfsTimeoutSeconds = serverConfiguration?.ipfsTimeoutSeconds ?? 10
        hiddenRetrievalEnabled = configuration.hiddenRetrieval != nil
        hiddenRetrievalMode = configuration.hiddenRetrieval?.mode.rawValue ?? HiddenRetrievalMode.coverQuery.rawValue
        hiddenRetrievalCoverSize = configuration.hiddenRetrieval?.defaultCoverSetSize ?? 8
        hiddenRetrievalMaxCoverSize = configuration.hiddenRetrieval?.maxCoverSetSize ?? 32
        hiddenRetrievalReplicas = (configuration.hiddenRetrieval?.replicatedXorPIRReplicas ?? []).map {
            "\($0.replicaId),\($0.operatorId),\(operatorRelayEndpointString($0.endpoint))"
        }
        onionTransportEnabled = configuration.onionTransport?.enabled ?? false
        onionTransportMaxHops = configuration.onionTransport?.maxHops ?? 3
        onionTransportRequiresFixedSizePackets = configuration.onionTransport?.requiresFixedSizePackets ?? true
        mixnetTransportEnabled = configuration.mixnetTransport?.enabled ?? false
        mixnetBatchIntervalSeconds = configuration.mixnetTransport?.batchIntervalSeconds ?? 30
        mixnetMinBatchSize = configuration.mixnetTransport?.minBatchSize ?? 8
        mixnetCoverPacketsPerBatch = configuration.mixnetTransport?.coverPacketsPerBatch ?? 2
        mixnetMaxDelaySeconds = configuration.mixnetTransport?.maxDelaySeconds ?? 120
        relayPeerExchangeLimit = configuration.federation.mode == .open
            ? (configuration.relayPeerExchangeLimit ?? 0)
            : 0
        openFederationDHTEnabled = configuration.federation.mode == .open
            && configuration.openFederationDHTEnabled
        openFederationDHTMaxRecords = configuration.openFederationDHTMaxRecords
        openFederationDHTMaxRecordsPerHost = configuration.openFederationDHTMaxRecordsPerHost
        openFederationDHTMaxQueryRecords = configuration.openFederationDHTMaxQueryRecords
        coordinatorHeartbeatSeconds = configuration.coordinatorHeartbeatSeconds ?? 45
        coordinatorDirectoryMaxStalenessSeconds = configuration.coordinatorDirectoryMaxStalenessSeconds ?? 300
        curatedStrictPolicyEnabled = configuration.curatedStrictPolicyEnabled
        curatedCoordinatorQuorum = configuration.curatedCoordinatorQuorum
        curatedRequireSignedDirectory = configuration.curatedRequireSignedDirectory
        allowPrivateFederationEndpoints = configuration.allowPrivateFederationEndpoints
        opaqueRouteRuntimeEnabled = configuration.isOpaqueRouteRuntimeEnabled
    }

    func validatedConfiguration(from current: RelayConfiguration) throws -> RelayConfiguration {
        let normalizedName = try boundedText(relayName, field: "relayName", allowEmpty: true)
        let normalizedNote = try boundedText(operatorNote, field: "operatorNote", allowEmpty: true)
        let normalizedFederationName = try boundedText(federationName, field: "federationName", allowEmpty: true)
        let normalizedFederationDescription = try boundedText(
            federationDescription,
            field: "federationDescription",
            allowEmpty: true
        )
        guard let mode = FederationMode(rawValue: federationMode) else {
            throw OperatorConfigurationError.invalidField("federationMode")
        }
        if mode == .manual, current.kind != .standard {
            throw OperatorConfigurationError.unsupportedTransition(
                "Manual federation is available only to standard relays."
            )
        }
        if mode == .curated,
           current.coordinatorRegistrationToken?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
            throw OperatorConfigurationError.unsupportedTransition(
                "Curated federation requires a coordinator registration token supplied through the environment or command line."
            )
        }

        let endpoint = try optionalEndpoint(advertisedEndpoint, field: "advertisedEndpoint")
        let allowList = try endpointList(
            federationAllowList,
            field: "federationAllowList",
            maximum: Self.maximumEndpointCount
        )
        let coordinators = try endpointList(
            federationCoordinatorEndpoints,
            field: "federationCoordinatorEndpoints",
            maximum: 16
        )
        if mode == .curated, coordinators.isEmpty {
            throw OperatorConfigurationError.unsupportedTransition(
                "Curated federation requires at least one coordinator endpoint."
            )
        }

        guard (0...86_400).contains(temporalBucketSeconds) else {
            throw OperatorConfigurationError.invalidField("temporalBucketSeconds")
        }
        let bucketSchedule = Array(
            Set(temporalBucketScheduleSeconds.filter { (1...86_400).contains($0) })
        ).sorted()
        guard bucketSchedule.count == temporalBucketScheduleSeconds.count,
              bucketSchedule.count <= 16 else {
            throw OperatorConfigurationError.invalidField("temporalBucketScheduleSeconds")
        }
        let maximumAttachmentTTL = 6 * 60 * 60
        guard (60...maximumAttachmentTTL).contains(attachmentDefaultTTLSeconds),
              (attachmentDefaultTTLSeconds...maximumAttachmentTTL).contains(attachmentMaxTTLSeconds) else {
            throw OperatorConfigurationError.invalidField("attachment retention")
        }
        guard (0...128).contains(relayPeerExchangeLimit) else {
            throw OperatorConfigurationError.invalidField("relayPeerExchangeLimit")
        }
        if mode != .open, (openFederationDHTEnabled || relayPeerExchangeLimit > 0) {
            throw OperatorConfigurationError.unsupportedTransition(
                "DHT and peer exchange are available only in open federation mode."
            )
        }

        let hiddenRetrieval = try validatedHiddenRetrieval(current: current)
        let onionTransport = try validatedOnionTransport(current: current)
        let mixnetTransport = try validatedMixnetTransport(current: current, onionTransport: onionTransport)
        let dhtMaxRecords = openFederationDHTMaxRecords ?? current.openFederationDHTMaxRecords
        let dhtMaxPerHost = openFederationDHTMaxRecordsPerHost ?? current.openFederationDHTMaxRecordsPerHost
        let dhtMaxQuery = openFederationDHTMaxQueryRecords ?? current.openFederationDHTMaxQueryRecords
        guard (1...256).contains(dhtMaxRecords),
              (1...16).contains(dhtMaxPerHost),
              (1...512).contains(dhtMaxQuery) else {
            throw OperatorConfigurationError.invalidField("open federation DHT bounds")
        }
        let heartbeat = coordinatorHeartbeatSeconds ?? current.coordinatorHeartbeatSeconds ?? 45
        let staleness = coordinatorDirectoryMaxStalenessSeconds ?? current.coordinatorDirectoryMaxStalenessSeconds ?? 300
        let quorum = curatedCoordinatorQuorum ?? current.curatedCoordinatorQuorum
        guard (15...3_600).contains(heartbeat),
              (30...86_400).contains(staleness),
              (1...16).contains(quorum) else {
            throw OperatorConfigurationError.invalidField("federation timing or quorum")
        }
        try validateRestartControlledSettings()

        return RelayConfiguration(
            kind: current.kind,
            federation: FederationDescriptor(
                mode: mode,
                name: normalizedFederationName.nilIfEmpty,
                description: normalizedFederationDescription.nilIfEmpty
            ),
            tlsEnabled: endpoint?.useTLS,
            transport: endpoint?.transport ?? current.transport,
            temporalBucketSeconds: temporalBucketSeconds,
            temporalBucketScheduleSeconds: bucketSchedule,
            attachmentDefaultTTLSeconds: attachmentDefaultTTLSeconds,
            attachmentMaxTTLSeconds: attachmentMaxTTLSeconds,
            attachmentsEnabled: attachmentsEnabled,
            attachmentStorageBackend: current.attachmentStorageBackend,
            hiddenRetrieval: hiddenRetrieval,
            onionTransport: onionTransport,
            mixnetTransport: mixnetTransport,
            relayName: normalizedName.nilIfEmpty,
            operatorNote: normalizedNote.nilIfEmpty,
            softwareVersion: current.softwareVersion,
            accessPassword: current.accessPassword,
            coordinatorRegistrationToken: current.coordinatorRegistrationToken,
            federationCoordinatorEndpoints: coordinators,
            coordinatorHeartbeatSeconds: heartbeat,
            coordinatorDirectoryMaxStalenessSeconds: staleness,
            relayPeerExchangeLimit: mode == .open ? relayPeerExchangeLimit : 0,
            openFederationDHTEnabled: mode == .open && openFederationDHTEnabled,
            openFederationDHTMaxRecords: dhtMaxRecords,
            openFederationDHTMaxRecordsPerHost: dhtMaxPerHost,
            openFederationDHTMaxQueryRecords: dhtMaxQuery,
            coordinatorDirectorySigningPrivateKey: current.coordinatorDirectorySigningPrivateKey,
            curatedStrictPolicyEnabled: curatedStrictPolicyEnabled ?? current.curatedStrictPolicyEnabled,
            curatedCoordinatorQuorum: quorum,
            curatedRequireSignedDirectory: curatedRequireSignedDirectory ?? current.curatedRequireSignedDirectory,
            advertisedEndpoint: endpoint,
            federationAllowList: mode == .solo ? [] : allowList,
            allowPrivateFederationEndpoints: allowPrivateFederationEndpoints ?? current.allowPrivateFederationEndpoints,
            opaqueRouteRuntimeEnabled: opaqueRouteRuntimeEnabled,
            rendezvousTransportEnabled: current.isRendezvousTransportEnabled
        )
    }

    func applyPersistedOverrides(to config: inout ServerConfig) throws {
        let current = RelayConfiguration(
            kind: config.relayKind,
            federation: FederationDescriptor(
                mode: config.federationMode,
                name: config.federationName,
                description: config.federationDescription
            ),
            tlsEnabled: config.advertisedEndpoint?.useTLS,
            transport: config.advertisedEndpoint?.transport ?? config.relayTransport,
            temporalBucketSeconds: config.temporalBucketSeconds,
            temporalBucketScheduleSeconds: config.temporalBucketScheduleSeconds,
            attachmentDefaultTTLSeconds: config.attachmentDefaultTTLSeconds,
            attachmentMaxTTLSeconds: config.attachmentMaxTTLSeconds,
            attachmentsEnabled: config.attachmentsEnabled,
            attachmentStorageBackend: config.attachmentStorageMode.rawValue,
            hiddenRetrieval: config.hiddenRetrieval,
            onionTransport: config.onionTransport,
            mixnetTransport: config.mixnetTransport,
            relayName: config.relayName,
            operatorNote: config.operatorNote,
            softwareVersion: ServerConfig.advertisedSoftwareVersion,
            accessPassword: config.accessPassword,
            coordinatorRegistrationToken: config.coordinatorRegistrationToken,
            federationCoordinatorEndpoints: config.federationCoordinatorEndpoints,
            coordinatorHeartbeatSeconds: config.coordinatorHeartbeatSeconds,
            coordinatorDirectoryMaxStalenessSeconds: config.coordinatorDirectoryMaxStalenessSeconds,
            relayPeerExchangeLimit: config.relayPeerExchangeLimit,
            openFederationDHTEnabled: config.openFederationDHTEnabled,
            openFederationDHTMaxRecords: config.openFederationDHTMaxRecords,
            openFederationDHTMaxRecordsPerHost: config.openFederationDHTMaxRecordsPerHost,
            openFederationDHTMaxQueryRecords: config.openFederationDHTMaxQueryRecords,
            coordinatorDirectorySigningPrivateKey: config.coordinatorDirectorySigningPrivateKey,
            curatedStrictPolicyEnabled: config.curatedStrictPolicyEnabled,
            curatedCoordinatorQuorum: config.curatedCoordinatorQuorum,
            curatedRequireSignedDirectory: config.curatedRequireSignedDirectory,
            advertisedEndpoint: config.advertisedEndpoint,
            federationAllowList: config.federationAllowList,
            allowPrivateFederationEndpoints: config.allowPrivateFederationEndpoints,
            opaqueRouteRuntimeEnabled: config.opaqueRouteRuntimeEnabled,
            rendezvousTransportEnabled: config.rendezvousTransportEnabled
        )
        let updated = try validatedConfiguration(from: current)
        config.federationMode = updated.federation.mode
        config.federationName = updated.federation.name
        config.federationDescription = updated.federation.description
        config.temporalBucketSeconds = updated.temporalBucketSeconds
        config.temporalBucketScheduleSeconds = updated.temporalBucketScheduleSeconds ?? []
        config.attachmentDefaultTTLSeconds = updated.attachmentDefaultTTLSeconds
        config.attachmentMaxTTLSeconds = updated.attachmentMaxTTLSeconds
        config.attachmentsEnabled = updated.attachmentsEnabled != false
        config.attachmentStorageMode = AttachmentStorageMode(rawValue: attachmentStorageMode ?? "") ?? config.attachmentStorageMode
        config.ipfsAPIEndpoint = URL(string: ipfsAPIEndpoint ?? "") ?? config.ipfsAPIEndpoint
        let gateway = (ipfsGatewayEndpoint ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        config.ipfsGatewayEndpoint = gateway.isEmpty ? nil : URL(string: gateway)
        config.ipfsTimeoutSeconds = ipfsTimeoutSeconds ?? config.ipfsTimeoutSeconds
        config.hiddenRetrieval = updated.hiddenRetrieval
        config.onionTransport = updated.onionTransport
        config.mixnetTransport = updated.mixnetTransport
        config.relayName = updated.relayName
        config.operatorNote = updated.operatorNote
        config.federationCoordinatorEndpoints = updated.federationCoordinatorEndpoints ?? []
        config.coordinatorHeartbeatSeconds = updated.coordinatorHeartbeatSeconds ?? config.coordinatorHeartbeatSeconds
        config.coordinatorDirectoryMaxStalenessSeconds = updated.coordinatorDirectoryMaxStalenessSeconds ?? config.coordinatorDirectoryMaxStalenessSeconds
        config.relayPeerExchangeLimit = updated.relayPeerExchangeLimit ?? 0
        config.openFederationDHTEnabled = updated.openFederationDHTEnabled
        config.openFederationDHTMaxRecords = updated.openFederationDHTMaxRecords
        config.openFederationDHTMaxRecordsPerHost = updated.openFederationDHTMaxRecordsPerHost
        config.openFederationDHTMaxQueryRecords = updated.openFederationDHTMaxQueryRecords
        config.curatedStrictPolicyEnabled = updated.curatedStrictPolicyEnabled
        config.curatedCoordinatorQuorum = updated.curatedCoordinatorQuorum
        config.curatedRequireSignedDirectory = updated.curatedRequireSignedDirectory
        config.advertisedEndpoint = updated.advertisedEndpoint
        config.federationAllowList = updated.federationAllowList
        config.allowPrivateFederationEndpoints = updated.allowPrivateFederationEndpoints
        config.opaqueRouteRuntimeEnabled = updated.isOpaqueRouteRuntimeEnabled
        config.rendezvousTransportEnabled = updated.isRendezvousTransportEnabled
    }

    var restartControlledSignature: String {
        [
            attachmentStorageMode ?? AttachmentStorageMode.inline.rawValue,
            ipfsAPIEndpoint ?? "",
            ipfsGatewayEndpoint ?? "",
            String(ipfsTimeoutSeconds ?? 10)
        ].joined(separator: "|")
    }

    private func validateRestartControlledSettings() throws {
        guard let storageMode = AttachmentStorageMode(rawValue: attachmentStorageMode ?? AttachmentStorageMode.inline.rawValue) else {
            throw OperatorConfigurationError.invalidField("attachmentStorageMode")
        }
        guard (1...300).contains(ipfsTimeoutSeconds ?? 10) else {
            throw OperatorConfigurationError.invalidField("ipfsTimeoutSeconds")
        }
        if storageMode == .ipfs {
            guard let api = URL(string: ipfsAPIEndpoint ?? ""), IPFSAttachmentBlobStore.isValidEndpoint(api) else {
                throw OperatorConfigurationError.invalidField("ipfsAPIEndpoint")
            }
            let gateway = (ipfsGatewayEndpoint ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            if !gateway.isEmpty {
                guard let url = URL(string: gateway), IPFSAttachmentBlobStore.isValidEndpoint(url) else {
                    throw OperatorConfigurationError.invalidField("ipfsGatewayEndpoint")
                }
            }
        }
    }

    private func validatedHiddenRetrieval(current: RelayConfiguration) throws -> HiddenRetrievalSupport? {
        guard hiddenRetrievalEnabled ?? (current.hiddenRetrieval != nil) else { return nil }
        guard let mode = HiddenRetrievalMode(rawValue: hiddenRetrievalMode ?? HiddenRetrievalMode.coverQuery.rawValue) else {
            throw OperatorConfigurationError.invalidField("hiddenRetrievalMode")
        }
        let cover = hiddenRetrievalCoverSize ?? current.hiddenRetrieval?.defaultCoverSetSize ?? 8
        let maximum = hiddenRetrievalMaxCoverSize ?? current.hiddenRetrieval?.maxCoverSetSize ?? 32
        guard (2...4_096).contains(cover), (cover...4_096).contains(maximum) else {
            throw OperatorConfigurationError.invalidField("hidden retrieval cover sizes")
        }
        let replicas = try (hiddenRetrievalReplicas ?? []).map { value -> HiddenRetrievalPIRReplica in
            let fields = value.split(separator: ",", maxSplits: 2).map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            guard fields.count == 3, !fields[0].isEmpty, !fields[1].isEmpty,
                  let endpoint = parseOperatorRelayEndpoint(fields[2]) else {
                throw OperatorConfigurationError.invalidField("hiddenRetrievalReplicas")
            }
            return HiddenRetrievalPIRReplica(replicaId: fields[0], operatorId: fields[1], endpoint: endpoint)
        }
        let support = HiddenRetrievalSupport(
            mode: mode,
            defaultCoverSetSize: cover,
            maxCoverSetSize: maximum,
            replicatedXorPIRReplicas: replicas.isEmpty ? nil : replicas
        )
        if mode == .replicatedXorPIR, !HiddenRetrievalPIRReplicaSetValidator.isUsable(support) {
            throw OperatorConfigurationError.invalidField("replicated XOR-PIR replicas")
        }
        return support
    }

    private func validatedOnionTransport(current: RelayConfiguration) throws -> OnionTransportSupport? {
        guard onionTransportEnabled ?? (current.onionTransport?.enabled == true) else { return nil }
        let hops = onionTransportMaxHops ?? current.onionTransport?.maxHops ?? 3
        guard (2...8).contains(hops) else {
            throw OperatorConfigurationError.invalidField("onionTransportMaxHops")
        }
        return OnionTransportSupport(
            enabled: true,
            maxHops: hops,
            requiresFixedSizePackets: onionTransportRequiresFixedSizePackets ?? true
        )
    }

    private func validatedMixnetTransport(
        current: RelayConfiguration,
        onionTransport: OnionTransportSupport?
    ) throws -> MixnetTransportSupport? {
        guard mixnetTransportEnabled ?? (current.mixnetTransport?.enabled == true) else { return nil }
        let support = MixnetTransportSupport(
            enabled: true,
            batchIntervalSeconds: mixnetBatchIntervalSeconds ?? 30,
            minBatchSize: mixnetMinBatchSize ?? 8,
            coverPacketsPerBatch: mixnetCoverPacketsPerBatch ?? 2,
            maxDelaySeconds: mixnetMaxDelaySeconds ?? 120
        )
        guard MixnetRoutePolicyValidator.isUsable(
            mixnetSupport: support,
            onionSupport: onionTransport
        ) else {
            throw OperatorConfigurationError.invalidField("mixnet policy requires usable onion routing, fixed packets, batching, cover traffic, and delay")
        }
        return support
    }

    private func boundedText(_ value: String, field: String, allowEmpty: Bool) throws -> String {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (allowEmpty || !normalized.isEmpty),
              normalized.utf8.count <= Self.maximumTextBytes,
              !normalized.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw OperatorConfigurationError.invalidField(field)
        }
        return normalized
    }

    private func optionalEndpoint(_ value: String, field: String) throws -> RelayEndpoint? {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return nil }
        guard let endpoint = parseOperatorRelayEndpoint(normalized) else {
            throw OperatorConfigurationError.invalidField(field)
        }
        return endpoint
    }

    private func endpointList(_ values: [String], field: String, maximum: Int) throws -> [RelayEndpoint] {
        guard values.count <= maximum else {
            throw OperatorConfigurationError.invalidField(field)
        }
        var seen = Set<RelayEndpoint>()
        var endpoints: [RelayEndpoint] = []
        for value in values {
            guard let endpoint = parseOperatorRelayEndpoint(value), seen.insert(endpoint).inserted else {
                throw OperatorConfigurationError.invalidField(field)
            }
            endpoints.append(endpoint)
        }
        return endpoints
    }
}

final class RelayConfigurationStore: @unchecked Sendable {
    private let lock = NIOLock()
    private var value: RelayConfiguration

    init(_ configuration: RelayConfiguration) {
        value = configuration
    }

    func snapshot() -> RelayConfiguration {
        lock.withLock { value }
    }

    func replace(with configuration: RelayConfiguration) {
        lock.withLock { value = configuration }
    }
}

struct OperatorConfigurationPersistence {
    let fileURL: URL?

    var isAvailable: Bool { fileURL != nil }

    func load() throws -> OperatorEditableConfiguration? {
        guard let fileURL, FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        let attributes = try FileManager.default.attributesOfItem(atPath: fileURL.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              let byteCount = (attributes[.size] as? NSNumber)?.intValue,
              (1...128 * 1_024).contains(byteCount) else {
            throw OperatorConfigurationError.invalidField("persisted operator configuration")
        }
        let data = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
        return try decodeOperatorJSON(OperatorEditableConfiguration.self, from: data)
    }

    func save(_ configuration: OperatorEditableConfiguration) throws {
        guard let fileURL else {
            throw OperatorConfigurationError.persistenceUnavailable
        }
        let data = try operatorJSONEncoder().encode(configuration)
        guard data.count <= 128 * 1_024 else {
            throw OperatorConfigurationError.invalidField("persisted operator configuration")
        }
        try data.write(to: fileURL, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }
}

func parseOperatorRelayEndpoint(_ value: String) -> RelayEndpoint? {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty, trimmed.utf8.count <= 2_048 else { return nil }
    if let components = URLComponents(string: trimmed), let scheme = components.scheme, !scheme.isEmpty {
        guard let host = components.host,
              isValidOperatorRelayHost(host),
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/" else {
            return nil
        }
        let lowered = scheme.lowercased()
        let defaultPort: Int
        switch lowered {
        case "https", "wss": defaultPort = 443
        case "http", "ws": defaultPort = 80
        case "tcp", "tls": defaultPort = 9339
        default: return nil
        }
        guard let port = UInt16(exactly: components.port ?? defaultPort), port > 0 else { return nil }
        switch lowered {
        case "http": return RelayEndpoint(host: host, port: port, useTLS: false, transport: .http)
        case "https": return RelayEndpoint(host: host, port: port, useTLS: true, transport: .http)
        case "ws": return RelayEndpoint(host: host, port: port, useTLS: false, transport: .websocket)
        case "wss": return RelayEndpoint(host: host, port: port, useTLS: true, transport: .websocket)
        case "tcp": return RelayEndpoint(host: host, port: port, useTLS: false, transport: .tcp)
        case "tls": return RelayEndpoint(host: host, port: port, useTLS: true, transport: .tcp)
        default: return nil
        }
    }
    let parts = trimmed.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
    guard parts.count == 2,
          isValidOperatorRelayHost(String(parts[0])),
          let port = UInt16(parts[1]), port > 0 else {
        return nil
    }
    return RelayEndpoint(host: String(parts[0]), port: port)
}

func operatorRelayEndpointString(_ endpoint: RelayEndpoint) -> String {
    let scheme: String
    switch (endpoint.transport, endpoint.useTLS) {
    case (.tcp, false): scheme = "tcp"
    case (.tcp, true): scheme = "tls"
    case (.http, false): scheme = "http"
    case (.http, true): scheme = "https"
    case (.websocket, false): scheme = "ws"
    case (.websocket, true): scheme = "wss"
    }
    let host = endpoint.host.contains(":") ? "[\(endpoint.host)]" : endpoint.host
    return "\(scheme)://\(host):\(endpoint.port)"
}

private func isValidOperatorRelayHost(_ host: String) -> Bool {
    let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
    return !trimmed.isEmpty
        && trimmed == host
        && !trimmed.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) })
        && !trimmed.contains("/")
        && !trimmed.contains("?")
        && !trimmed.contains("#")
        && !trimmed.contains("@")
}

private func operatorJSONEncoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    return encoder
}

func operatorJSONDecoder() -> JSONDecoder {
    let decoder = JSONDecoder()
    return decoder
}

func decodeOperatorJSON<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
    try RelayCodec.preflightJSON(data)
    return try operatorJSONDecoder().decode(type, from: data)
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
