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
    var groupCreationMode: String
    var relayPeerExchangeLimit: Int
    var openFederationDHTEnabled: Bool
    var wakeMode: String
    var wakeMinPollSeconds: Int
    var wakeMaxPollSeconds: Int
    var wakeJitterPermille: Int
    var wakeLongPollTimeoutSeconds: Int

    init(configuration: RelayConfiguration) {
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
        groupCreationMode = configuration.groupCreationMode.rawValue
        relayPeerExchangeLimit = configuration.federation.mode == .open
            ? (configuration.relayPeerExchangeLimit ?? 0)
            : 0
        openFederationDHTEnabled = configuration.federation.mode == .open
            && configuration.openFederationDHTEnabled
        wakeMode = configuration.wakeSupport?.mode.rawValue ?? "disabled"
        wakeMinPollSeconds = configuration.wakeSupport?.minPollIntervalSeconds ?? 60
        wakeMaxPollSeconds = configuration.wakeSupport?.maxPollIntervalSeconds ?? 300
        wakeJitterPermille = configuration.wakeSupport?.jitterPermille ?? 250
        wakeLongPollTimeoutSeconds = configuration.wakeSupport?.longPollTimeoutSeconds ?? 30
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
        guard let groupMode = GroupCreationMode(rawValue: groupCreationMode) else {
            throw OperatorConfigurationError.invalidField("groupCreationMode")
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

        let wakeSupport: DecentralizedWakeSupport?
        if wakeMode == "disabled" {
            wakeSupport = nil
        } else {
            guard let parsedWakeMode = DecentralizedWakeMode(rawValue: wakeMode),
                  (5...86_400).contains(wakeMinPollSeconds),
                  (wakeMinPollSeconds...86_400).contains(wakeMaxPollSeconds),
                  (0...1_000).contains(wakeJitterPermille),
                  (5...300).contains(wakeLongPollTimeoutSeconds) else {
                throw OperatorConfigurationError.invalidField("wake policy")
            }
            wakeSupport = DecentralizedWakeSupport(
                mode: parsedWakeMode,
                minPollIntervalSeconds: wakeMinPollSeconds,
                maxPollIntervalSeconds: wakeMaxPollSeconds,
                jitterPermille: wakeJitterPermille,
                longPollTimeoutSeconds: parsedWakeMode == .longPoll ? wakeLongPollTimeoutSeconds : nil
            )
        }

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
            hiddenRetrieval: current.hiddenRetrieval,
            onionTransport: current.onionTransport,
            mixnetTransport: current.mixnetTransport,
            wakeSupport: wakeSupport,
            relayName: normalizedName.nilIfEmpty,
            operatorNote: normalizedNote.nilIfEmpty,
            softwareVersion: current.softwareVersion,
            groupCreationMode: groupMode,
            groupSecurityModel: current.groupSecurityModel,
            accessPassword: current.accessPassword,
            coordinatorRegistrationToken: current.coordinatorRegistrationToken,
            federationForwardingAuthToken: current.federationForwardingAuthToken,
            federationCoordinatorEndpoints: coordinators,
            coordinatorHeartbeatSeconds: current.coordinatorHeartbeatSeconds,
            coordinatorDirectoryMaxStalenessSeconds: current.coordinatorDirectoryMaxStalenessSeconds,
            relayPeerExchangeLimit: mode == .open ? relayPeerExchangeLimit : 0,
            openFederationDHTEnabled: mode == .open && openFederationDHTEnabled,
            openFederationDHTMaxRecords: current.openFederationDHTMaxRecords,
            openFederationDHTMaxRecordsPerHost: current.openFederationDHTMaxRecordsPerHost,
            openFederationDHTMaxQueryRecords: current.openFederationDHTMaxQueryRecords,
            coordinatorDirectorySigningPrivateKey: current.coordinatorDirectorySigningPrivateKey,
            curatedStrictPolicyEnabled: current.curatedStrictPolicyEnabled,
            curatedCoordinatorQuorum: current.curatedCoordinatorQuorum,
            curatedRequireSignedDirectory: current.curatedRequireSignedDirectory,
            advertisedEndpoint: endpoint,
            federationAllowList: mode == .solo ? [] : allowList,
            allowPrivateFederationEndpoints: current.allowPrivateFederationEndpoints,
            requireInboxAccessControl: current.requireInboxAccessControl ?? true
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
            wakeSupport: config.wakeSupport,
            relayName: config.relayName,
            operatorNote: config.operatorNote,
            softwareVersion: ServerConfig.advertisedSoftwareVersion,
            groupCreationMode: config.groupCreationMode,
            groupSecurityModel: config.groupSecurityModel,
            accessPassword: config.accessPassword,
            coordinatorRegistrationToken: config.coordinatorRegistrationToken,
            federationForwardingAuthToken: config.federationForwardingAuthToken,
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
            allowPrivateFederationEndpoints: config.allowPrivateFederationEndpoints
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
        config.wakeSupport = updated.wakeSupport
        config.relayName = updated.relayName
        config.operatorNote = updated.operatorNote
        config.groupCreationMode = updated.groupCreationMode
        config.federationCoordinatorEndpoints = updated.federationCoordinatorEndpoints ?? []
        config.relayPeerExchangeLimit = updated.relayPeerExchangeLimit ?? 0
        config.openFederationDHTEnabled = updated.openFederationDHTEnabled
        config.advertisedEndpoint = updated.advertisedEndpoint
        config.federationAllowList = updated.federationAllowList
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
        return try operatorJSONDecoder().decode(OperatorEditableConfiguration.self, from: data)
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

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
