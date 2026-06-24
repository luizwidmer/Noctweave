import Foundation
@preconcurrency import NIOCore
import NIOPosix

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
    var relayName: String?
    var operatorNote: String?
    var softwareVersion: String?
    var groupCreationMode: GroupCreationMode
    var accessPassword: String?
    var coordinatorRegistrationToken: String?
    var federationForwardingAuthToken: String?
    var federationCoordinatorEndpoints: [RelayEndpoint]
    var coordinatorHeartbeatSeconds: Int
    var coordinatorDirectoryMaxStalenessSeconds: Int
    var relayPeerExchangeLimit: Int
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
        var relayName: String?
        var operatorNote: String?
        var softwareVersion: String?
        var groupCreationMode: GroupCreationMode = .allowed
        var accessPassword: String? = environment["NOCTYRA_RELAY_PASSWORD"]
        var coordinatorRegistrationToken: String? = environment["NOCTYRA_COORDINATOR_REGISTRATION_TOKEN"]
        var federationForwardingAuthToken: String? = environment["NOCTYRA_FEDERATION_FORWARDING_TOKEN"]
        var federationCoordinatorEndpoints: [RelayEndpoint] = []
        var coordinatorHeartbeatSeconds: Int = 45
        var coordinatorDirectoryMaxStalenessSeconds: Int = 300
        var relayPeerExchangeLimit: Int = 12
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
            relayName: relayName,
            operatorNote: operatorNote,
            softwareVersion: softwareVersion,
            groupCreationMode: groupCreationMode,
            accessPassword: accessPassword,
            coordinatorRegistrationToken: coordinatorRegistrationToken,
            federationForwardingAuthToken: federationForwardingAuthToken,
            federationCoordinatorEndpoints: federationCoordinatorEndpoints,
            coordinatorHeartbeatSeconds: coordinatorHeartbeatSeconds,
            coordinatorDirectoryMaxStalenessSeconds: coordinatorDirectoryMaxStalenessSeconds,
            relayPeerExchangeLimit: relayPeerExchangeLimit,
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
let store = RelayStore(
    fileURL: fileURL,
    maxInboxMessages: config.maxInboxMessages,
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
    relayName: config.relayName,
    operatorNote: config.operatorNote,
    softwareVersion: config.softwareVersion,
    groupCreationMode: config.groupCreationMode,
    accessPassword: config.accessPassword,
    coordinatorRegistrationToken: config.coordinatorRegistrationToken,
    federationForwardingAuthToken: config.federationForwardingAuthToken,
    federationCoordinatorEndpoints: config.federationCoordinatorEndpoints,
    coordinatorHeartbeatSeconds: config.coordinatorHeartbeatSeconds,
    coordinatorDirectoryMaxStalenessSeconds: config.coordinatorDirectoryMaxStalenessSeconds,
    relayPeerExchangeLimit: config.relayPeerExchangeLimit,
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
            channel.pipeline.addHandler(ByteToMessageHandler(LineDecoder(maxLength: config.maxLineBytes))).flatMap {
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
