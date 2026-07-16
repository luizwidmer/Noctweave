import Foundation
@preconcurrency import NIOCore
@preconcurrency import NIOPosix

struct ServerConfig {
    static let advertisedSoftwareVersion = "NoctweaveRelayServer/0.1.0"
    static let maximumTemporalBucketSeconds = 24 * 60 * 60
    static let maximumAttachmentTTLSeconds = 30 * 24 * 60 * 60
    static let usage = """
    NoctweaveRelayServer — ciphertext relay and federation node

    Usage:
      NoctweaveRelayServer [options]

    Common options:
      --host <address>                 Bind address (default: 0.0.0.0)
      --port <port>                    Raw TCP port (default: 9339)
      --http-port <port>               Optional HTTP/WebSocket bridge port
      --admin-port <port>              Optional authenticated operator Web UI
      --admin-host <address>           Admin bind address (default: 127.0.0.1)
      --admin-token <token>            Admin bearer token (minimum 16 bytes)
      --memory-only                    Keep relay state in memory
      --data-dir <path>                SQLite state directory (default: /data)
      --relay-name <name>              Operator-visible relay name
      --federation-mode <mode>         solo, manual, curated, or open
      --advertised-endpoint <endpoint> Public tcp/tls/http/https/ws/wss endpoint
      --access-password <password>     Require relay client authentication
      --attachments-enabled <bool>     Enable or disable attachment chunks
      --attachment-storage <mode>      inline or ipfs
      --rendezvous-transport <bool>    Enable experimental identity-blind rendezvous transport
      --temporal-bucket-seconds <n>    Metadata timing bucket; 0 disables it
      --help, -h                       Show this help without starting a relay
      --version                        Print the relay software version

    Environment variables and the complete option reference are documented in
    NoctweaveRelayServer/README.md. Prefer environment variables over command-line
    arguments for passwords and federation tokens.
    """

    static func shouldShowHelp(arguments: [String]) -> Bool {
        arguments.contains("--help") || arguments.contains("-h")
    }

    static func shouldShowVersion(arguments: [String]) -> Bool {
        arguments.contains("--version")
    }

    var host: String
    var port: Int
    var httpPort: Int?
    var adminHost: String
    var adminPort: Int?
    var adminToken: String?
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
    var rendezvousTransportEnabled: Bool

    static func parse(
        arguments: [String] = Array(CommandLine.arguments.dropFirst()),
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> ServerConfig {
        var host = "0.0.0.0"
        var port = 9339
        var httpPort: Int?
        var adminHost = environment["NOCTWEAVE_ADMIN_HOST"] ?? "127.0.0.1"
        var adminPort = Int(environment["NOCTWEAVE_ADMIN_PORT"] ?? "").flatMap { $0 > 0 ? $0 : nil }
        var adminToken = environment["NOCTWEAVE_ADMIN_TOKEN"]
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
        var attachmentStorageMode = AttachmentStorageMode(rawValue: environment["NOCTWEAVE_ATTACHMENT_STORAGE"] ?? "") ?? .inline
        var ipfsAPIEndpoint = URL(string: environment["NOCTWEAVE_IPFS_API_ENDPOINT"] ?? "http://127.0.0.1:5001")
        var ipfsGatewayEndpoint = URL(string: environment["NOCTWEAVE_IPFS_GATEWAY_ENDPOINT"] ?? "")
        var ipfsTimeoutSeconds = Int(environment["NOCTWEAVE_IPFS_TIMEOUT_SECONDS"] ?? "") ?? 10
        var hiddenRetrievalEnabled = false
        var hiddenRetrievalMode = HiddenRetrievalMode(
            rawValue: environment["NOCTWEAVE_HIDDEN_RETRIEVAL_MODE"] ?? ""
        ) ?? .coverQuery
        var hiddenRetrievalDefaultCoverSetSize = 8
        var hiddenRetrievalMaxCoverSetSize = 32
        var hiddenRetrievalReplicas = parseHiddenRetrievalReplicas(
            environment["NOCTWEAVE_HIDDEN_RETRIEVAL_REPLICAS"] ?? ""
        )
        var onionTransportEnabled = parseBoolFlag(
            environment["NOCTWEAVE_ONION_TRANSPORT"] ?? "false",
            defaultValue: false
        )
        var onionTransportMaxHops = Int(environment["NOCTWEAVE_ONION_MAX_HOPS"] ?? "") ?? 3
        var onionTransportRequiresFixedSizePackets = parseBoolFlag(
            environment["NOCTWEAVE_ONION_FIXED_SIZE_PACKETS"] ?? "true",
            defaultValue: true
        )
        var mixnetTransportEnabled = parseBoolFlag(
            environment["NOCTWEAVE_MIXNET_TRANSPORT"] ?? "false",
            defaultValue: false
        )
        var mixnetBatchIntervalSeconds = Int(environment["NOCTWEAVE_MIXNET_BATCH_INTERVAL_SECONDS"] ?? "") ?? 30
        var mixnetMinBatchSize = Int(environment["NOCTWEAVE_MIXNET_MIN_BATCH_SIZE"] ?? "") ?? 8
        var mixnetCoverPacketsPerBatch = Int(environment["NOCTWEAVE_MIXNET_COVER_PACKETS_PER_BATCH"] ?? "") ?? 2
        var mixnetMaxDelaySeconds = Int(environment["NOCTWEAVE_MIXNET_MAX_DELAY_SECONDS"] ?? "") ?? 120
        var wakeMode: DecentralizedWakeMode?
        var wakeMinPollSeconds = 60
        var wakeMaxPollSeconds = 300
        var wakeJitterPermille = 250
        var wakeLongPollTimeoutSeconds: Int?
        var relayName: String?
        var operatorNote: String?
        var groupCreationMode: GroupCreationMode = .allowed
        var groupSecurityModel: GroupSecurityModel = .mlsDerivedTree
        var accessPassword: String? = environment["NOCTWEAVE_RELAY_PASSWORD"]
        var coordinatorRegistrationToken: String? = environment["NOCTWEAVE_COORDINATOR_REGISTRATION_TOKEN"]
        var federationForwardingAuthToken: String? = environment["NOCTWEAVE_FEDERATION_FORWARDING_TOKEN"]
        var federationCoordinatorEndpoints: [RelayEndpoint] = []
        var coordinatorHeartbeatSeconds: Int = 45
        var coordinatorDirectoryMaxStalenessSeconds: Int = 300
        var relayPeerExchangeLimit: Int = Int(environment["NOCTWEAVE_RELAY_PEER_EXCHANGE_LIMIT"] ?? "") ?? 12
        var openFederationDHTEnabled = parseBoolFlag(
            environment["NOCTWEAVE_OPEN_FEDERATION_DHT_NODE"] ?? "false",
            defaultValue: false
        )
        var openFederationDHTMaxRecords = Int(environment["NOCTWEAVE_OPEN_FEDERATION_DHT_MAX_RECORDS"] ?? "") ?? 256
        var openFederationDHTMaxRecordsPerHost = Int(environment["NOCTWEAVE_OPEN_FEDERATION_DHT_MAX_RECORDS_PER_HOST"] ?? "") ?? 4
        var openFederationDHTMaxQueryRecords = Int(environment["NOCTWEAVE_OPEN_FEDERATION_DHT_MAX_QUERY_RECORDS"] ?? "") ?? 256
        var coordinatorDirectorySigningPrivateKey: Data? = environment["NOCTWEAVE_COORDINATOR_SIGNING_KEY"]
            .flatMap { Data(base64Encoded: $0) }
        var curatedStrictPolicyEnabled = true
        var curatedCoordinatorQuorum = 1
        var curatedRequireSignedDirectory = true
        var advertisedEndpoint: RelayEndpoint?
        var federationAllowList: [RelayEndpoint] = []
        var allowPrivateFederationEndpoints = false
        var rendezvousTransportEnabled = parseBoolFlag(
            environment["NOCTWEAVE_RENDEZVOUS_TRANSPORT"] ?? "false",
            defaultValue: false
        )
        var iterator = arguments.makeIterator()
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
            case "--admin-host":
                adminHost = iterator.next() ?? adminHost
            case "--admin-port":
                if let value = iterator.next(), let parsed = Int(value), parsed > 0 {
                    adminPort = parsed
                }
            case "--admin-token":
                adminToken = iterator.next()
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
                    maxMessageBytes = parsed > 0 ? parsed : 512 * 1024
                }
            case "--max-line-bytes":
                if let value = iterator.next(), let parsed = Int(value) {
                    maxLineBytes = parsed > 0 ? parsed : 640 * 1024
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
                    temporalBucketSeconds = min(max(0, parsed), 24 * 60) * 60
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
                        .map { min(max(0, $0), 24 * 60) * 60 }
                }
            case "--attachment-default-ttl-seconds":
                if let value = iterator.next(), let parsed = Int(value) {
                    attachmentDefaultTTLSeconds = max(60, parsed)
                }
            case "--attachment-default-ttl-minutes":
                if let value = iterator.next(), let parsed = Int(value) {
                    attachmentDefaultTTLSeconds = min(max(1, parsed), 30 * 24 * 60) * 60
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
                    attachmentMaxTTLSeconds = min(max(1, parsed), 30 * 24 * 60) * 60
                }
            case "--relay-name":
                relayName = iterator.next()
            case "--operator-note":
                operatorNote = iterator.next()
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
            case "--rendezvous-transport":
                if let value = iterator.next() {
                    rendezvousTransportEnabled = parseBoolFlag(value, defaultValue: true)
                } else {
                    rendezvousTransportEnabled = true
                }
            default:
                break
            }
        }

        if memoryOnly {
            dataDir = nil
        }
        if adminPort == nil,
           adminToken?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false {
            adminPort = 9090
        }
        adminToken = adminToken?.trimmingCharacters(in: .whitespacesAndNewlines)

        port = min(max(port, 1), Int(UInt16.max))
        httpPort = httpPort.map { min(max($0, 1), Int(UInt16.max)) }
        adminPort = adminPort.map { min(max($0, 1), Int(UInt16.max)) }
        maxInboxMessages = maxInboxMessages.map { min(max($0, 1), 1_000_000) }
        forwardingRequestTimeoutSeconds = min(max(forwardingRequestTimeoutSeconds, 1), 300)
        temporalBucketSeconds = min(max(temporalBucketSeconds, 0), maximumTemporalBucketSeconds)
        temporalBucketScheduleSeconds = Array(
            Set(temporalBucketScheduleSeconds.filter { (1...maximumTemporalBucketSeconds).contains($0) })
        ).sorted().prefix(16).map { $0 }
        attachmentMaxTTLSeconds = min(
            max(attachmentMaxTTLSeconds, 60),
            maximumAttachmentTTLSeconds
        )
        attachmentDefaultTTLSeconds = min(
            max(attachmentDefaultTTLSeconds, 60),
            attachmentMaxTTLSeconds
        )
        ipfsTimeoutSeconds = min(max(ipfsTimeoutSeconds, 1), 300)
        hiddenRetrievalMaxCoverSetSize = min(max(hiddenRetrievalMaxCoverSetSize, 1), 512)
        hiddenRetrievalDefaultCoverSetSize = min(
            max(hiddenRetrievalDefaultCoverSetSize, 1),
            hiddenRetrievalMaxCoverSetSize
        )
        hiddenRetrievalReplicas = Array(hiddenRetrievalReplicas.prefix(16))
        onionTransportMaxHops = min(max(onionTransportMaxHops, 1), 8)
        mixnetBatchIntervalSeconds = min(max(mixnetBatchIntervalSeconds, 5), 3_600)
        mixnetMinBatchSize = min(max(mixnetMinBatchSize, 1), 256)
        mixnetCoverPacketsPerBatch = min(max(mixnetCoverPacketsPerBatch, 0), 256)
        mixnetMaxDelaySeconds = min(max(mixnetMaxDelaySeconds, 0), 3_600)
        wakeMinPollSeconds = min(max(wakeMinPollSeconds, 5), 86_400)
        wakeMaxPollSeconds = min(max(wakeMaxPollSeconds, wakeMinPollSeconds), 86_400)
        wakeLongPollTimeoutSeconds = wakeLongPollTimeoutSeconds.map { min(max($0, 5), 300) }
        coordinatorHeartbeatSeconds = min(max(coordinatorHeartbeatSeconds, 15), 3_600)
        coordinatorDirectoryMaxStalenessSeconds = min(
            max(coordinatorDirectoryMaxStalenessSeconds, coordinatorHeartbeatSeconds),
            86_400
        )
        relayPeerExchangeLimit = min(max(relayPeerExchangeLimit, 0), 128)
        openFederationDHTMaxRecords = min(max(openFederationDHTMaxRecords, 1), 256)
        openFederationDHTMaxRecordsPerHost = min(
            max(openFederationDHTMaxRecordsPerHost, 1),
            min(16, openFederationDHTMaxRecords)
        )
        openFederationDHTMaxQueryRecords = min(
            max(openFederationDHTMaxQueryRecords, 1),
            min(512, openFederationDHTMaxRecords)
        )
        curatedCoordinatorQuorum = min(max(curatedCoordinatorQuorum, 1), 16)
        federationCoordinatorEndpoints = Array(federationCoordinatorEndpoints.prefix(16))
        federationAllowList = Array(federationAllowList.prefix(256))
        if let key = coordinatorDirectorySigningPrivateKey, key.count > 16_384 {
            coordinatorDirectorySigningPrivateKey = nil
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

        let normalizedMaxMessageBytes = min(max(1_024, maxMessageBytes ?? (512 * 1024)), 8 * 1024 * 1024)
        let normalizedMaxLineBytes = min(
            max(maxLineBytes ?? (640 * 1024), normalizedMaxMessageBytes + (128 * 1024)),
            10 * 1024 * 1024
        )

        return ServerConfig(
            host: host,
            port: port,
            httpPort: httpPort,
            adminHost: adminHost,
            adminPort: adminPort,
            adminToken: adminToken,
            dataDir: dataDir,
            memoryOnly: memoryOnly,
            maxInboxMessages: maxInboxMessages,
            maxMessageBytes: normalizedMaxMessageBytes,
            maxLineBytes: normalizedMaxLineBytes,
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
            allowPrivateFederationEndpoints: allowPrivateFederationEndpoints,
            rendezvousTransportEnabled: rendezvousTransportEnabled
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
        guard let host = components.host,
              isValidRelayHost(host),
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/" else {
            return nil
        }
        let loweredScheme = scheme.lowercased()
        let defaultPort: Int
        switch loweredScheme {
        case "https", "wss":
            defaultPort = 443
        case "http", "ws":
            defaultPort = 80
        default:
            defaultPort = 9339
        }
        guard let port = UInt16(exactly: components.port ?? defaultPort), port > 0 else { return nil }
        switch loweredScheme {
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
    if trimmed.hasPrefix("["), let close = trimmed.firstIndex(of: "]") {
        let host = String(trimmed[trimmed.index(after: trimmed.startIndex)..<close])
        let remainder = String(trimmed[trimmed.index(after: close)...])
        guard isValidRelayHost(host), remainder.hasPrefix(":"),
              let port = UInt16(remainder.dropFirst()), port > 0 else {
            return nil
        }
        return RelayEndpoint(host: host, port: port)
    }
    guard trimmed.filter({ $0 == ":" }).count == 1 else { return nil }
    let parts = trimmed.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
    guard parts.count == 2,
          isValidRelayHost(String(parts[0])),
          let port = UInt16(parts[1]), port > 0 else {
        return nil
    }
    return RelayEndpoint(host: String(parts[0]), port: port)
}

private func isValidRelayHost(_ host: String) -> Bool {
    let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
    return !trimmed.isEmpty
        && trimmed == host
        && !trimmed.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) })
        && !trimmed.contains("/")
        && !trimmed.contains("?")
        && !trimmed.contains("#")
        && !trimmed.contains("@")
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

let startupArguments = Array(CommandLine.arguments.dropFirst())
if ServerConfig.shouldShowHelp(arguments: startupArguments) {
    print(ServerConfig.usage)
    exit(0)
}
if ServerConfig.shouldShowVersion(arguments: startupArguments) {
    print(ServerConfig.advertisedSoftwareVersion)
    exit(0)
}
var config = ServerConfig.parse(arguments: startupArguments)
let operatorConfigurationPersistence = OperatorConfigurationPersistence(
    fileURL: config.dataDir?.appendingPathComponent("operator-config.json")
)
do {
    if let persistedOperatorConfiguration = try operatorConfigurationPersistence.load() {
        try persistedOperatorConfiguration.applyPersistedOverrides(to: &config)
        print("[relay] Loaded persisted operator configuration")
    }
} catch {
    print("[relay] Refusing to start because operator-config.json is invalid.")
    exit(2)
}
if config.federationMode == .manual {
    guard config.relayKind == .standard else {
        print("[relay] manual federation requires --relay-kind standard")
        exit(2)
    }
}
if config.federationMode == .curated,
   config.coordinatorRegistrationToken?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
    print("[relay] curated federation requires --coordinator-registration-token or NOCTWEAVE_COORDINATOR_REGISTRATION_TOKEN")
    exit(2)
}
for (label, secret, minimum) in [
    ("relay password", config.accessPassword, 12),
    ("coordinator registration token", config.coordinatorRegistrationToken, 16),
    ("federation forwarding token", config.federationForwardingAuthToken, 16),
    ("admin token", config.adminToken, 16)
] {
    if let secret, !secret.isEmpty, !(minimum...4_096).contains(secret.utf8.count) {
        print("[relay] \(label) must contain between \(minimum) and 4096 UTF-8 bytes")
        exit(2)
    }
}
if config.adminPort != nil,
   config.adminToken?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
    print("[relay] --admin-port requires --admin-token or NOCTWEAVE_ADMIN_TOKEN")
    exit(2)
}
let fileURL: URL?
if let dataDir = config.dataDir {
    do {
        try FileManager.default.createDirectory(
            at: dataDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    } catch {
        print("[relay] Unable to prepare the configured data directory.")
        exit(2)
    }
    fileURL = dataDir.appendingPathComponent("relay_store.sqlite")
} else {
    fileURL = nil
}
let attachmentBlobStore: AttachmentBlobStore?
switch config.attachmentStorageMode {
case .inline:
    attachmentBlobStore = nil
case .ipfs:
    guard let apiEndpoint = config.ipfsAPIEndpoint,
          IPFSAttachmentBlobStore.isValidEndpoint(apiEndpoint),
          config.ipfsGatewayEndpoint.map(IPFSAttachmentBlobStore.isValidEndpoint) ?? true,
          (1...300).contains(config.ipfsTimeoutSeconds) else {
        print("[relay] IPFS endpoints must be root HTTP(S) URLs without credentials/query data, and timeout must be 1...300 seconds")
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
do {
    try store.load()
} catch {
    print("[relay] Refusing to start because the persisted store could not be opened.")
    exit(2)
}

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
    allowPrivateFederationEndpoints: config.allowPrivateFederationEndpoints,
    rendezvousTransportEnabled: config.rendezvousTransportEnabled
)
if relayConfiguration.kind == .coordinator {
    if relayConfiguration.coordinatorDirectorySigningPrivateKey == nil,
       let dataDir = config.dataDir {
        let keyURL = dataDir.appendingPathComponent("coordinator_directory_signing_key")
        let existing: Data?
        if FileManager.default.fileExists(atPath: keyURL.path) {
            do {
                let attributes = try FileManager.default.attributesOfItem(atPath: keyURL.path)
                guard attributes[.type] as? FileAttributeType == .typeRegular,
                      let byteCount = (attributes[.size] as? NSNumber)?.intValue,
                      (1...16_384).contains(byteCount) else {
                    throw CocoaError(.fileReadCorruptFile)
                }
                let data = try Data(contentsOf: keyURL)
                guard data.count <= 16_384 else {
                    throw CocoaError(.fileReadTooLarge)
                }
                existing = data
            } catch {
                print("[relay] Refusing to replace an unreadable coordinator signing key file.")
                exit(2)
            }
        } else {
            existing = nil
        }
        let normalized = FederationDirectorySignature.privateKeyData(from: existing)
        guard !normalized.isEmpty else {
            print("[relay] Coordinator mode requires runtime liboqs support for ML-DSA-65 directory signing.")
            exit(2)
        }
        if existing != normalized {
            do {
                try normalized.write(to: keyURL, options: [.atomic])
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: keyURL.path
                )
            } catch {
                print("[relay] Unable to persist the coordinator signing key securely.")
                exit(2)
            }
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

let relayConfigurationStore = RelayConfigurationStore(relayConfiguration)
let relayStartedAt = Date()

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
                    relayConfiguration: relayConfigurationStore.snapshot(),
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
            store: store,
            maxMessageBytes: config.maxMessageBytes
        )
        let httpChannel = try bridgeBootstrap.bind(host: config.host, port: httpPort).wait()
        let httpAddress = httpChannel.localAddress?.description ?? "unknown"
        print("[relay] Listening (http/ws) on \(httpAddress) path=/relay")
        closeFutures.append(httpChannel.closeFuture)
    }

    if let adminPort = config.adminPort, let adminToken = config.adminToken {
        if adminPort == config.port || adminPort == config.httpPort {
            print("[relay] --admin-port must differ from relay listener ports")
            exit(2)
        }
        let bootstrapSummary: [String: String] = [
            "Raw TCP": "\(config.host):\(config.port)",
            "HTTP / WebSocket": config.httpPort.map { "\(config.host):\($0)" } ?? "Disabled",
            "Admin listener": "\(config.adminHost):\(adminPort)",
            "Message ceiling": "\(config.maxMessageBytes ?? 0) bytes",
            "Inbox ceiling": config.maxInboxMessages.map(String.init) ?? "Disabled",
            "Attachment backend": config.attachmentStorageMode.rawValue,
            "Secrets": "Environment / command line"
        ]
        let controlPlane = OperatorControlPlane(
            configurationStore: relayConfigurationStore,
            persistence: operatorConfigurationPersistence,
            relayStore: store,
            startedAt: relayStartedAt,
            bootstrap: bootstrapSummary,
            storageDescription: config.memoryOnly ? "Memory only" : "SQLite",
            transportDescription: config.httpPort == nil ? "TCP" : "TCP + HTTP / WS",
            editableConfiguration: OperatorEditableConfiguration(
                configuration: relayConfigurationStore.snapshot(),
                serverConfiguration: config
            )
        )
        let adminBootstrap = makeOperatorHTTPBootstrap(
            group: group,
            controlPlane: controlPlane,
            authenticationToken: adminToken
        )
        let adminChannel = try adminBootstrap.bind(host: config.adminHost, port: adminPort).wait()
        let adminAddress = adminChannel.localAddress?.description ?? "unknown"
        print("[relay] Operator Web UI listening on \(adminAddress) path=/admin/")
        closeFutures.append(adminChannel.closeFuture)
    }

    try EventLoopFuture.andAllSucceed(closeFutures, on: group.next()).wait()
} catch {
    print("[relay] Server error: \(error)")
    exit(1)
}
