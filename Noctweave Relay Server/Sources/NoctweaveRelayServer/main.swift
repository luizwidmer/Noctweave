import Foundation
@preconcurrency import NIOCore
@preconcurrency import NIOPosix

struct ServerConfig {
    var host: String
    var port: Int
    var httpPort: Int?
    var dataDir: URL?
    var memoryOnly: Bool
    var maxInboxMessages: Int?
    var maxMessageBytes: Int?
    var maxLineBytes: Int?
    var forwardingRequestTimeoutSeconds: Int
    var relayKind: RelayKind
    var relayTransport: RelayEndpointTransport
    var federationMode: FederationMode
    var federationName: String?
    var federationDescription: String?
    var advertiseTLS: Bool?
    var temporalBucketSeconds: Int
    var temporalBucketScheduleSeconds: [Int]
    var attachmentDefaultTTLSeconds: Int
    var attachmentMaxTTLSeconds: Int
    var attachmentsEnabled: Bool
    var attachmentStorageMode: AttachmentStorageMode
    var ipfsAPIEndpoint: URL?
    var ipfsGatewayEndpoint: URL?
    var ipfsTimeoutSeconds: Int
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
    var federationCoordinatorEndpoints: [RelayEndpoint]
    var coordinatorHeartbeatSeconds: Int
    var coordinatorDirectoryMaxStalenessSeconds: Int
    var relayPeerExchangeLimit: Int
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

    static func parse() -> ServerConfig {
        let environment = ProcessInfo.processInfo.environment
        var host = "0.0.0.0"
        var port = 9339
        var httpPort: Int?
        var dataDir: URL? = URL(fileURLWithPath: "/data", isDirectory: true)
        var memoryOnly = false
        var maxInboxMessages: Int? = 1000
        var maxMessageBytes: Int? = 512 * 1024
        var maxLineBytes: Int? = 640 * 1024
        var forwardingRequestTimeoutSeconds: Int = 8
        var relayKind: RelayKind = .standard
        var relayTransport: RelayEndpointTransport = .tcp
        var federationMode: FederationMode = .solo
        var federationName: String?
        var federationDescription: String?
        var advertiseTLS: Bool?
        var temporalBucketSeconds: Int = 300
        var temporalBucketScheduleSeconds: [Int] = []
        var attachmentDefaultTTLSeconds: Int = 3600
        var attachmentMaxTTLSeconds: Int = 21600
        var attachmentsEnabled = true
        var attachmentStorageMode = AttachmentStorageMode(rawValue: environment["NOCTYRA_ATTACHMENT_STORAGE"] ?? "") ?? .inline
        var ipfsAPIEndpoint = URL(string: environment["NOCTYRA_IPFS_API_ENDPOINT"] ?? "http://127.0.0.1:5001")
        var ipfsGatewayEndpoint = URL(string: environment["NOCTYRA_IPFS_GATEWAY_ENDPOINT"] ?? "")
        var ipfsTimeoutSeconds = Int(environment["NOCTYRA_IPFS_TIMEOUT_SECONDS"] ?? "") ?? 10
        var hiddenRetrievalEnabled = false
        var hiddenRetrievalMode = HiddenRetrievalMode(
            rawValue: environment["NOCTYRA_HIDDEN_RETRIEVAL_MODE"] ?? ""
        ) ?? .coverQuery
        var hiddenRetrievalDefaultCoverSetSize = 8
        var hiddenRetrievalMaxCoverSetSize = 32
        var hiddenRetrievalReplicas = parseHiddenRetrievalReplicas(
            environment["NOCTYRA_HIDDEN_RETRIEVAL_REPLICAS"] ?? ""
        )
        var onionTransportEnabled = parseBoolFlag(
            environment["NOCTYRA_ONION_TRANSPORT"] ?? "false",
            defaultValue: false
        )
        var onionTransportMaxHops = Int(environment["NOCTYRA_ONION_MAX_HOPS"] ?? "") ?? 3
        var onionTransportRequiresFixedSizePackets = parseBoolFlag(
            environment["NOCTYRA_ONION_FIXED_SIZE_PACKETS"] ?? "true",
            defaultValue: true
        )
        var mixnetTransportEnabled = parseBoolFlag(
            environment["NOCTYRA_MIXNET_TRANSPORT"] ?? "false",
            defaultValue: false
        )
        var mixnetBatchIntervalSeconds = Int(environment["NOCTYRA_MIXNET_BATCH_INTERVAL_SECONDS"] ?? "") ?? 30
        var mixnetMinBatchSize = Int(environment["NOCTYRA_MIXNET_MIN_BATCH_SIZE"] ?? "") ?? 8
        var mixnetCoverPacketsPerBatch = Int(environment["NOCTYRA_MIXNET_COVER_PACKETS_PER_BATCH"] ?? "") ?? 2
        var mixnetMaxDelaySeconds = Int(environment["NOCTYRA_MIXNET_MAX_DELAY_SECONDS"] ?? "") ?? 120
        var wakeMode: DecentralizedWakeMode?
        var wakeMinPollSeconds = 60
        var wakeMaxPollSeconds = 300
        var wakeJitterPermille = 250
        var wakeLongPollTimeoutSeconds: Int?
        var relayName: String?
        var operatorNote: String?
        var softwareVersion: String?
        var groupCreationMode: GroupCreationMode = .allowed
        var groupSecurityModel: GroupSecurityModel = .relayBackedPairwise
        var accessPassword: String? = environment["NOCTYRA_RELAY_PASSWORD"]
        var coordinatorRegistrationToken: String? = environment["NOCTYRA_COORDINATOR_REGISTRATION_TOKEN"]
        var federationForwardingAuthToken: String? = environment["NOCTYRA_FEDERATION_FORWARDING_TOKEN"]
        var federationCoordinatorEndpoints: [RelayEndpoint] = []
        var coordinatorHeartbeatSeconds: Int = 45
        var coordinatorDirectoryMaxStalenessSeconds: Int = 300
        var relayPeerExchangeLimit: Int = Int(environment["NOCTYRA_RELAY_PEER_EXCHANGE_LIMIT"] ?? "") ?? 12
        var openFederationDHTEnabled = parseBoolFlag(
            environment["NOCTYRA_OPEN_FEDERATION_DHT_NODE"] ?? "false",
            defaultValue: false
        )
        var openFederationDHTMaxRecords = Int(environment["NOCTYRA_OPEN_FEDERATION_DHT_MAX_RECORDS"] ?? "") ?? 256
        var openFederationDHTMaxRecordsPerHost = Int(environment["NOCTYRA_OPEN_FEDERATION_DHT_MAX_RECORDS_PER_HOST"] ?? "") ?? 4
        var openFederationDHTMaxQueryRecords = Int(environment["NOCTYRA_OPEN_FEDERATION_DHT_MAX_QUERY_RECORDS"] ?? "") ?? 256
        var coordinatorDirectorySigningPrivateKey: Data? = environment["NOCTYRA_COORDINATOR_SIGNING_KEY"]
            .flatMap { Data(base64Encoded: $0) }
        var curatedStrictPolicyEnabled = true
        var curatedCoordinatorQuorum = 1
        var curatedRequireSignedDirectory = true
        var advertisedEndpoint: RelayEndpoint?
        var federationAllowList: [RelayEndpoint] = []
        var allowPrivateFederationEndpoints = false

        var iterator = CommandLine.arguments.dropFirst().makeIterator()
        while let arg = iterator.next() {
            switch arg {
            case "--host":
                host = iterator.next() ?? host
            case "--port":
                if let value = iterator.next(), let parsed = Int(value) {
                    port = parsed
                }
            case "--http-port":
                if let value = iterator.next(), let parsed = Int(value), parsed > 0 {
                    httpPort = parsed
                }
            case "--data-dir":
                if let value = iterator.next() {
                    dataDir = URL(fileURLWithPath: value, isDirectory: true)
                }
            case "--memory-only":
                memoryOnly = true
            case "--max-inbox":
                if let value = iterator.next(), let parsed = Int(value) {
                    maxInboxMessages = parsed > 0 ? parsed : nil
                }
            case "--max-message-bytes":
                if let value = iterator.next(), let parsed = Int(value) {
                    maxMessageBytes = parsed > 0 ? parsed : nil
                }
            case "--max-line-bytes":
                if let value = iterator.next(), let parsed = Int(value) {
                    maxLineBytes = parsed > 0 ? parsed : nil
                }
            case "--forwarding-timeout-seconds":
                if let value = iterator.next(), let parsed = Int(value) {
                    forwardingRequestTimeoutSeconds = max(1, parsed)
                }
            case "--relay-kind":
                if let value = iterator.next(), let parsed = RelayKind(rawValue: value) {
                    relayKind = parsed
                }
            case "--transport":
                if let value = iterator.next(), let parsed = RelayEndpointTransport(rawValue: value) {
                    relayTransport = parsed
                }
            case "--federation-mode":
                if let value = iterator.next(), let parsed = FederationMode(rawValue: value) {
                    federationMode = parsed
                }
            case "--federation-name":
                federationName = iterator.next()
            case "--federation-description":
                federationDescription = iterator.next()
            case "--advertise-tls":
                if let value = iterator.next() {
                    advertiseTLS = parseBoolFlag(value, defaultValue: true)
                } else {
                    advertiseTLS = true
                }
            case "--temporal-bucket-seconds":
                if let value = iterator.next(), let parsed = Int(value) {
                    temporalBucketSeconds = max(0, parsed)
                }
            case "--temporal-bucket-minutes":
                if let value = iterator.next(), let parsed = Int(value) {
                    temporalBucketSeconds = max(0, parsed * 60)
                }
            case "--temporal-bucket-schedule-seconds":
                if let value = iterator.next() {
                    temporalBucketScheduleSeconds = value
                        .split(separator: ",")
                        .compactMap { Int(String($0).trimmingCharacters(in: .whitespacesAndNewlines)) }
                        .map { max(0, $0) }
                }
            case "--temporal-bucket-schedule-minutes":
                if let value = iterator.next() {
                    temporalBucketScheduleSeconds = value
                        .split(separator: ",")
                        .compactMap { Int(String($0).trimmingCharacters(in: .whitespacesAndNewlines)) }
                        .map { max(0, $0) * 60 }
                }
            case "--attachment-default-ttl-seconds":
                if let value = iterator.next(), let parsed = Int(value) {
                    attachmentDefaultTTLSeconds = max(60, parsed)
                }
            case "--attachment-default-ttl-minutes":
                if let value = iterator.next(), let parsed = Int(value) {
                    attachmentDefaultTTLSeconds = max(1, parsed) * 60
                }
            case "--attachment-max-ttl-seconds":
                if let value = iterator.next(), let parsed = Int(value) {
                    attachmentMaxTTLSeconds = max(60, parsed)
                }
            case "--attachments-enabled":
                if let value = iterator.next() {
                    attachmentsEnabled = parseBoolFlag(value, defaultValue: true)
                }
            case "--attachment-storage":
                if let value = iterator.next(),
                   let parsed = AttachmentStorageMode(rawValue: value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()) {
                    attachmentStorageMode = parsed
                }
            case "--ipfs-api-endpoint":
                if let value = iterator.next() {
                    ipfsAPIEndpoint = URL(string: value)
                }
            case "--ipfs-gateway-endpoint":
                if let value = iterator.next() {
                    ipfsGatewayEndpoint = URL(string: value)
                }
            case "--ipfs-timeout-seconds":
                if let value = iterator.next(), let parsed = Int(value) {
                    ipfsTimeoutSeconds = max(1, parsed)
                }
            case "--hidden-retrieval":
                if let value = iterator.next() {
                    hiddenRetrievalEnabled = parseBoolFlag(value, defaultValue: true)
                } else {
                    hiddenRetrievalEnabled = true
                }
            case "--hidden-retrieval-mode":
                if let value = iterator.next(),
                   let parsed = HiddenRetrievalMode(rawValue: value) {
                    hiddenRetrievalMode = parsed
                    hiddenRetrievalEnabled = true
                }
            case "--hidden-retrieval-cover-size":
                if let value = iterator.next(), let parsed = Int(value) {
                    hiddenRetrievalDefaultCoverSetSize = max(1, parsed)
                }
            case "--hidden-retrieval-max-cover-size":
                if let value = iterator.next(), let parsed = Int(value) {
                    hiddenRetrievalMaxCoverSetSize = max(1, parsed)
                }
            case "--hidden-retrieval-replica":
                if let value = iterator.next() {
                    hiddenRetrievalReplicas.append(contentsOf: parseHiddenRetrievalReplicas(value))
                    hiddenRetrievalMode = .replicatedXorPIR
                    hiddenRetrievalEnabled = true
                }
            case "--onion-transport":
                if let value = iterator.next() {
                    onionTransportEnabled = parseBoolFlag(value, defaultValue: true)
                } else {
                    onionTransportEnabled = true
                }
            case "--onion-max-hops":
                if let value = iterator.next(), let parsed = Int(value) {
                    onionTransportMaxHops = parsed
                    onionTransportEnabled = true
                }
            case "--onion-fixed-size-packets":
                if let value = iterator.next() {
                    onionTransportRequiresFixedSizePackets = parseBoolFlag(value, defaultValue: true)
                    onionTransportEnabled = true
                }
            case "--mixnet-transport":
                if let value = iterator.next() {
                    mixnetTransportEnabled = parseBoolFlag(value, defaultValue: true)
                } else {
                    mixnetTransportEnabled = true
                }
            case "--mixnet-batch-interval-seconds":
                if let value = iterator.next(), let parsed = Int(value) {
                    mixnetBatchIntervalSeconds = parsed
                    mixnetTransportEnabled = true
                }
            case "--mixnet-min-batch-size":
                if let value = iterator.next(), let parsed = Int(value) {
                    mixnetMinBatchSize = parsed
                    mixnetTransportEnabled = true
                }
            case "--mixnet-cover-packets-per-batch":
                if let value = iterator.next(), let parsed = Int(value) {
                    mixnetCoverPacketsPerBatch = parsed
                    mixnetTransportEnabled = true
                }
            case "--mixnet-max-delay-seconds":
                if let value = iterator.next(), let parsed = Int(value) {
                    mixnetMaxDelaySeconds = parsed
                    mixnetTransportEnabled = true
                }
            case "--wake-mode":
                if let value = iterator.next(),
                   let parsed = DecentralizedWakeMode(rawValue: value) {
                    wakeMode = parsed
                }
            case "--wake-min-poll-seconds":
                if let value = iterator.next(), let parsed = Int(value) {
                    wakeMinPollSeconds = max(5, parsed)
                }
            case "--wake-max-poll-seconds":
                if let value = iterator.next(), let parsed = Int(value) {
                    wakeMaxPollSeconds = max(5, parsed)
                }
            case "--wake-jitter-permille":
                if let value = iterator.next(), let parsed = Int(value) {
                    wakeJitterPermille = min(max(0, parsed), 1_000)
                }
            case "--wake-long-poll-timeout-seconds":
                if let value = iterator.next(), let parsed = Int(value) {
                    wakeLongPollTimeoutSeconds = max(5, parsed)
                }
            case "--attachment-max-ttl-minutes":
                if let value = iterator.next(), let parsed = Int(value) {
                    attachmentMaxTTLSeconds = max(1, parsed) * 60
                }
            case "--relay-name":
                relayName = iterator.next()
            case "--operator-note":
                operatorNote = iterator.next()
            case "--software-version":
                softwareVersion = iterator.next()
            case "--group-creation-mode":
                if let value = iterator.next(),
                   let parsed = GroupCreationMode(rawValue: value) {
                    groupCreationMode = parsed
                }
            case "--group-security-model":
                if let value = iterator.next(),
                   let parsed = GroupSecurityModel(rawValue: value) {
                    groupSecurityModel = parsed
                }
            case "--access-password":
                accessPassword = iterator.next()
            case "--coordinator-registration-token":
                coordinatorRegistrationToken = iterator.next()
            case "--federation-forwarding-auth-token":
                federationForwardingAuthToken = iterator.next()
            case "--federation-coordinator":
                if let value = iterator.next() {
                    let entries = value.split(separator: ",").map { String($0) }
                    for entry in entries {
                        if let endpoint = parseRelayEndpoint(entry) {
                            federationCoordinatorEndpoints.append(endpoint)
                        }
                    }
                }
            case "--coordinator-heartbeat-seconds":
                if let value = iterator.next(), let parsed = Int(value) {
                    coordinatorHeartbeatSeconds = max(15, parsed)
                }
            case "--coordinator-directory-max-staleness-seconds":
                if let value = iterator.next(), let parsed = Int(value) {
                    coordinatorDirectoryMaxStalenessSeconds = max(30, parsed)
                }
            case "--relay-peer-exchange-limit":
                if let value = iterator.next(), let parsed = Int(value) {
                    relayPeerExchangeLimit = max(0, parsed)
                }
            case "--open-federation-dht-node":
                if let value = iterator.next() {
                    openFederationDHTEnabled = parseBoolFlag(value, defaultValue: true)
                } else {
                    openFederationDHTEnabled = true
                }
            case "--open-federation-dht-max-records":
                if let value = iterator.next(), let parsed = Int(value) {
                    openFederationDHTMaxRecords = max(1, parsed)
                }
            case "--open-federation-dht-max-records-per-host":
                if let value = iterator.next(), let parsed = Int(value) {
                    openFederationDHTMaxRecordsPerHost = max(1, parsed)
                }
            case "--open-federation-dht-max-query-records":
                if let value = iterator.next(), let parsed = Int(value) {
                    openFederationDHTMaxQueryRecords = max(1, parsed)
                }
            case "--coordinator-directory-signing-key":
                if let value = iterator.next(),
                   let decoded = Data(base64Encoded: value) {
                    coordinatorDirectorySigningPrivateKey = decoded
                }
            case "--curated-strict-policy":
                if let value = iterator.next() {
                    curatedStrictPolicyEnabled = parseBoolFlag(value, defaultValue: true)
                } else {
                    curatedStrictPolicyEnabled = true
                }
            case "--curated-coordinator-quorum":
                if let value = iterator.next(), let parsed = Int(value) {
                    curatedCoordinatorQuorum = max(1, parsed)
                }
            case "--curated-require-signed-directory":
                if let value = iterator.next() {
                    curatedRequireSignedDirectory = parseBoolFlag(value, defaultValue: true)
                } else {
                    curatedRequireSignedDirectory = true
                }
            case "--advertised-endpoint":
                if let value = iterator.next() {
                    advertisedEndpoint = parseRelayEndpoint(value)
                }
            case "--federation-allow":
                if let value = iterator.next() {
                    let entries = value.split(separator: ",").map { String($0) }
                    for entry in entries {
                        if let endpoint = parseRelayEndpoint(entry) {
                            federationAllowList.append(endpoint)
                        }
                    }
                }
            case "--allow-private-federation-endpoints":
                if let value = iterator.next() {
                    allowPrivateFederationEndpoints = parseBoolFlag(value, defaultValue: true)
                } else {
                    allowPrivateFederationEndpoints = true
                }
            default:
                break
            }
        }

        if memoryOnly {
            dataDir = nil
        }

        let hiddenRetrieval = hiddenRetrievalEnabled
            ? HiddenRetrievalSupport(
                mode: hiddenRetrievalMode,
                defaultCoverSetSize: hiddenRetrievalDefaultCoverSetSize,
                maxCoverSetSize: hiddenRetrievalMaxCoverSetSize,
                replicatedXorPIRReplicas: hiddenRetrievalReplicas.isEmpty ? nil : hiddenRetrievalReplicas
            )
            : nil
        let onionTransport = onionTransportEnabled
            ? OnionTransportSupport(
                enabled: true,
                maxHops: onionTransportMaxHops,
                requiresFixedSizePackets: onionTransportRequiresFixedSizePackets
            )
            : nil
        let mixnetTransport = mixnetTransportEnabled
            ? MixnetTransportSupport(
                enabled: true,
                batchIntervalSeconds: mixnetBatchIntervalSeconds,
                minBatchSize: mixnetMinBatchSize,
                coverPacketsPerBatch: mixnetCoverPacketsPerBatch,
                maxDelaySeconds: mixnetMaxDelaySeconds
            )
            : nil
        let wakeSupport = wakeMode.map { mode in
            DecentralizedWakeSupport(
                mode: mode,
                minPollIntervalSeconds: wakeMinPollSeconds,
                maxPollIntervalSeconds: wakeMaxPollSeconds,
                jitterPermille: wakeJitterPermille,
                longPollTimeoutSeconds: wakeLongPollTimeoutSeconds
            )
        }

        return ServerConfig(
            host: host,
            port: port,
            httpPort: httpPort,
            dataDir: dataDir,
            memoryOnly: memoryOnly,
            maxInboxMessages: maxInboxMessages,
            maxMessageBytes: maxMessageBytes,
            maxLineBytes: maxLineBytes,
            forwardingRequestTimeoutSeconds: forwardingRequestTimeoutSeconds,
            relayKind: relayKind,
            relayTransport: relayTransport,
            federationMode: federationMode,
            federationName: federationName,
            federationDescription: federationDescription,
            advertiseTLS: advertiseTLS,
            temporalBucketSeconds: temporalBucketSeconds,
            temporalBucketScheduleSeconds: temporalBucketScheduleSeconds,
            attachmentDefaultTTLSeconds: attachmentDefaultTTLSeconds,
            attachmentMaxTTLSeconds: attachmentMaxTTLSeconds,
            attachmentsEnabled: attachmentsEnabled,
            attachmentStorageMode: attachmentStorageMode,
            ipfsAPIEndpoint: ipfsAPIEndpoint,
            ipfsGatewayEndpoint: ipfsGatewayEndpoint,
            ipfsTimeoutSeconds: ipfsTimeoutSeconds,
            hiddenRetrieval: hiddenRetrieval,
            onionTransport: onionTransport,
            mixnetTransport: mixnetTransport,
            wakeSupport: wakeSupport,
            relayName: relayName,
            operatorNote: operatorNote,
            softwareVersion: softwareVersion,
            groupCreationMode: groupCreationMode,
            groupSecurityModel: groupSecurityModel,
            accessPassword: accessPassword,
            coordinatorRegistrationToken: coordinatorRegistrationToken,
            federationForwardingAuthToken: federationForwardingAuthToken,
            federationCoordinatorEndpoints: federationCoordinatorEndpoints,
            coordinatorHeartbeatSeconds: coordinatorHeartbeatSeconds,
            coordinatorDirectoryMaxStalenessSeconds: coordinatorDirectoryMaxStalenessSeconds,
            relayPeerExchangeLimit: relayPeerExchangeLimit,
            openFederationDHTEnabled: openFederationDHTEnabled,
            openFederationDHTMaxRecords: openFederationDHTMaxRecords,
            openFederationDHTMaxRecordsPerHost: openFederationDHTMaxRecordsPerHost,
            openFederationDHTMaxQueryRecords: openFederationDHTMaxQueryRecords,
            coordinatorDirectorySigningPrivateKey: coordinatorDirectorySigningPrivateKey,
            curatedStrictPolicyEnabled: curatedStrictPolicyEnabled,
            curatedCoordinatorQuorum: curatedCoordinatorQuorum,
            curatedRequireSignedDirectory: curatedRequireSignedDirectory,
            advertisedEndpoint: advertisedEndpoint,
            federationAllowList: federationAllowList,
            allowPrivateFederationEndpoints: allowPrivateFederationEndpoints
        )
    }
}

private func parseBoolFlag(_ value: String, defaultValue: Bool) -> Bool {
    switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
    case "1", "true", "yes", "on", "enabled":
        return true
    case "0", "false", "no", "off", "disabled":
        return false
    default:
        return defaultValue
    }
}

private func parseRelayEndpoint(_ value: String) -> RelayEndpoint? {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }
    if let components = URLComponents(string: trimmed), let scheme = components.scheme, !scheme.isEmpty {
        guard let host = components.host else { return nil }
        guard let port = UInt16(exactly: components.port ?? 9339) else { return nil }
        switch scheme.lowercased() {
        case "http":
            return RelayEndpoint(host: host, port: port, useTLS: false, transport: .http)
        case "https":
            return RelayEndpoint(host: host, port: port, useTLS: true, transport: .http)
        case "ws":
            return RelayEndpoint(host: host, port: port, useTLS: false, transport: .websocket)
        case "wss":
            return RelayEndpoint(host: host, port: port, useTLS: true, transport: .websocket)
        case "tls":
            return RelayEndpoint(host: host, port: port, useTLS: true, transport: .tcp)
        case "tcp":
            return RelayEndpoint(host: host, port: port, useTLS: false, transport: .tcp)
        default:
            return nil
        }
    }
    let parts = trimmed.split(separator: ":")
    guard parts.count >= 2 else { return nil }
    let host = parts.dropLast().joined(separator: ":")
    guard let port = UInt16(parts.last ?? "") else { return nil }
    return RelayEndpoint(host: host, port: port)
}

private func parseHiddenRetrievalReplicas(_ value: String) -> [HiddenRetrievalPIRReplica] {
    value
        .split(separator: ";")
        .compactMap { rawEntry in
            let fields = rawEntry
                .split(separator: ",", maxSplits: 2)
                .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            guard fields.count == 3,
                  !fields[0].isEmpty,
                  !fields[1].isEmpty,
                  let endpoint = parseRelayEndpoint(fields[2]) else {
                return nil
            }
            return HiddenRetrievalPIRReplica(
                replicaId: fields[0],
                operatorId: fields[1],
                endpoint: endpoint
            )
        }
}

let config = ServerConfig.parse()
let fileURL: URL?
if let dataDir = config.dataDir {
    try FileManager.default.createDirectory(
        at: dataDir,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    fileURL = dataDir.appendingPathComponent("relay_store.sqlite")
} else {
    fileURL = nil
}
let attachmentBlobStore: AttachmentBlobStore?
switch config.attachmentStorageMode {
case .inline:
    attachmentBlobStore = nil
case .ipfs:
    guard let apiEndpoint = config.ipfsAPIEndpoint else {
        print("[relay] --attachment-storage ipfs requires --ipfs-api-endpoint")
        exit(2)
    }
    attachmentBlobStore = IPFSAttachmentBlobStore(
        apiEndpoint: apiEndpoint,
        gatewayEndpoint: config.ipfsGatewayEndpoint,
        timeoutSeconds: TimeInterval(config.ipfsTimeoutSeconds)
    )
    print("[relay] Attachment chunks will be offloaded to IPFS through \(apiEndpoint.absoluteString)")
}
let store = RelayStore(
    fileURL: fileURL,
    maxInboxMessages: config.maxInboxMessages,
    attachmentBlobStore: attachmentBlobStore,
    temporalBucketSeconds: config.temporalBucketSeconds,
    temporalBucketScheduleSeconds: config.temporalBucketScheduleSeconds
)
store.load()

let advertisedEndpointTLS = config.advertisedEndpoint?.useTLS ?? false
if config.advertiseTLS == true && !advertisedEndpointTLS {
    print("[relay] Ignoring --advertise-tls without a TLS advertised endpoint; set --advertised-endpoint to https/wss/tls to advertise TLS.")
}
let effectiveAdvertiseTLS: Bool? = advertisedEndpointTLS

var relayConfiguration = RelayConfiguration(
    kind: config.relayKind,
    federation: FederationDescriptor(
        mode: config.federationMode,
        name: config.federationName,
        description: config.federationDescription
    ),
    tlsEnabled: effectiveAdvertiseTLS,
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
    softwareVersion: config.softwareVersion,
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
if relayConfiguration.kind == .coordinator {
    if relayConfiguration.coordinatorDirectorySigningPrivateKey == nil,
       let dataDir = config.dataDir {
        let keyURL = dataDir.appendingPathComponent("coordinator_directory_signing_key")
        let existing = try? Data(contentsOf: keyURL)
        let normalized = FederationDirectorySignature.privateKeyData(from: existing)
        guard !normalized.isEmpty else {
            print("[relay] Coordinator mode requires runtime liboqs support for ML-DSA-65 directory signing.")
            exit(2)
        }
        if existing != normalized {
            try normalized.write(to: keyURL, options: [.atomic])
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: keyURL.path
            )
        }
        relayConfiguration.coordinatorDirectorySigningPrivateKey = normalized
    }
    let normalizedSigningKey = FederationDirectorySignature.privateKeyData(
        from: relayConfiguration.coordinatorDirectorySigningPrivateKey
    )
    guard !normalizedSigningKey.isEmpty else {
        print("[relay] Coordinator mode requires runtime liboqs support for ML-DSA-65 directory signing.")
        exit(2)
    }
    relayConfiguration.coordinatorDirectorySigningPrivateKey = normalizedSigningKey
    if config.dataDir == nil, config.coordinatorDirectorySigningPrivateKey == nil {
        print("[relay] Warning: coordinator signing key is ephemeral in memory-only mode; provide --coordinator-directory-signing-key for stable trust.")
    }
}

let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
defer { try? group.syncShutdownGracefully() }

let bootstrap = ServerBootstrap(group: group)
    .serverChannelOption(ChannelOptions.backlog, value: 256)
    .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
    .childChannelInitializer { channel in
            channel.pipeline.addHandler(LineFrameHandler(maxLength: config.maxLineBytes)).flatMap {
                channel.pipeline.addHandler(RelayHandler(
                    store: store,
                    maxMessageBytes: config.maxMessageBytes,
                    maxLineBytes: config.maxLineBytes,
                    localEndpoint: RelayEndpoint(host: config.host, port: UInt16(config.port)),
                    relayConfiguration: relayConfiguration,
                    forwardingRequestTimeoutSeconds: config.forwardingRequestTimeoutSeconds
                ))
            }
        }
    .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
    .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 16)
    .childChannelOption(ChannelOptions.recvAllocator, value: AdaptiveRecvByteBufferAllocator())

do {
    let rawChannel = try bootstrap.bind(host: config.host, port: config.port).wait()
    let rawAddress = rawChannel.localAddress?.description ?? "unknown"
    print("[relay] Listening (tcp) on \(rawAddress)")

    var closeFutures: [EventLoopFuture<Void>] = [rawChannel.closeFuture]

    if let httpPort = config.httpPort {
        if httpPort == config.port {
            print("[relay] --http-port must differ from --port")
            exit(2)
        }
        let forwardHost: String
        let trimmedHost = config.host.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedHost == "::" {
            forwardHost = "::1"
        } else if trimmedHost.isEmpty || trimmedHost == "0.0.0.0" {
            forwardHost = "127.0.0.1"
        } else {
            forwardHost = trimmedHost
        }
        let forwarder = LocalRelayForwarder(
            relayHost: forwardHost,
            relayPort: config.port,
            maxLineBytes: config.maxLineBytes,
            requestTimeoutSeconds: config.forwardingRequestTimeoutSeconds
        )
        let bridgeBootstrap = makeHTTPRelayBridgeBootstrap(
            group: group,
            forwarder: forwarder,
            maxMessageBytes: config.maxMessageBytes
        )
        let httpChannel = try bridgeBootstrap.bind(host: config.host, port: httpPort).wait()
        let httpAddress = httpChannel.localAddress?.description ?? "unknown"
        print("[relay] Listening (http/ws) on \(httpAddress) path=/relay")
        closeFutures.append(httpChannel.closeFuture)
    }

    try EventLoopFuture.andAllSucceed(closeFutures, on: group.next()).wait()
} catch {
    print("[relay] Server error: \(error)")
}
