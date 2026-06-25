import Foundation

public enum RelayServerOrigin: String, Codable {
    case manual
    case master
}

public struct RelayServerRecord: Codable, Identifiable, Equatable {
    public let id: UUID
    public var name: String
    public var endpoint: RelayEndpoint
    public var note: String?
    public var relayPassword: String?
    public var region: String?
    public var tags: [String]?
    public var website: String?
    public var advertisedInfo: RelayInfo?
    public var lastInfoFetchedAt: Date?
    public var origin: RelayServerOrigin
    public var sourceId: UUID?
    public var addedAt: Date

    public init(
        id: UUID = UUID(),
        name: String,
        endpoint: RelayEndpoint,
        note: String? = nil,
        relayPassword: String? = nil,
        region: String? = nil,
        tags: [String]? = nil,
        website: String? = nil,
        advertisedInfo: RelayInfo? = nil,
        lastInfoFetchedAt: Date? = nil,
        origin: RelayServerOrigin = .manual,
        sourceId: UUID? = nil,
        addedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.endpoint = endpoint
        self.note = note
        self.relayPassword = relayPassword
        self.region = region
        self.tags = tags
        self.website = website
        self.advertisedInfo = advertisedInfo
        self.lastInfoFetchedAt = lastInfoFetchedAt
        self.origin = origin
        self.sourceId = sourceId
        self.addedAt = addedAt
    }
}

public struct MasterServerSource: Codable, Identifiable, Equatable {
    public let id: UUID
    public var name: String
    public var url: String
    public var isEnabled: Bool
    public var lastFetchedAt: Date?

    public init(
        id: UUID = UUID(),
        name: String,
        url: String,
        isEnabled: Bool = true,
        lastFetchedAt: Date? = nil
    ) {
        self.id = id
        self.name = name
        self.url = url
        self.isEnabled = isEnabled
        self.lastFetchedAt = lastFetchedAt
    }
}

public struct MasterServerEntry: Codable, Equatable {
    public let name: String?
    public let host: String
    public let port: UInt16
    public let note: String?
    public let region: String?
    public let tags: [String]?
    public let website: String?
    public let relayKind: RelayKind?
    public let federationMode: FederationMode?
    public let federationName: String?
    public let federationDescription: String?
    public let temporalBucketSeconds: Int?
    public let temporalBucketScheduleSeconds: [Int]?
    public let attachmentDefaultTTLSeconds: Int?
    public let attachmentMaxTTLSeconds: Int?
    public let hiddenRetrieval: HiddenRetrievalSupport?
    public let operatorNote: String?
    public let softwareVersion: String?
    public let groupCreationMode: GroupCreationMode?
    public let groupSecurityModel: GroupSecurityModel?
    public let requiresPassword: Bool?
    public let useTLS: Bool?
    public let transport: RelayEndpointTransport?
    public let tlsCertificateFingerprintSHA256: Data?
    public let federationCoordinatorEndpoints: [RelayEndpoint]?
    public let coordinatorReportedRelayCount: Int?
    public let curatedStrictPolicyEnabled: Bool?
    public let curatedCoordinatorQuorum: Int?
    public let curatedRequireSignedDirectory: Bool?

    public init(
        name: String? = nil,
        host: String,
        port: UInt16,
        note: String? = nil,
        region: String? = nil,
        tags: [String]? = nil,
        website: String? = nil,
        relayKind: RelayKind? = nil,
        federationMode: FederationMode? = nil,
        federationName: String? = nil,
        federationDescription: String? = nil,
        temporalBucketSeconds: Int? = nil,
        temporalBucketScheduleSeconds: [Int]? = nil,
        attachmentDefaultTTLSeconds: Int? = nil,
        attachmentMaxTTLSeconds: Int? = nil,
        hiddenRetrieval: HiddenRetrievalSupport? = nil,
        operatorNote: String? = nil,
        softwareVersion: String? = nil,
        groupCreationMode: GroupCreationMode? = nil,
        groupSecurityModel: GroupSecurityModel? = nil,
        requiresPassword: Bool? = nil,
        useTLS: Bool? = nil,
        transport: RelayEndpointTransport? = nil,
        tlsCertificateFingerprintSHA256: Data? = nil,
        federationCoordinatorEndpoints: [RelayEndpoint]? = nil,
        coordinatorReportedRelayCount: Int? = nil,
        curatedStrictPolicyEnabled: Bool? = nil,
        curatedCoordinatorQuorum: Int? = nil,
        curatedRequireSignedDirectory: Bool? = nil
    ) {
        self.name = name
        self.host = host
        self.port = port
        self.note = note
        self.region = region
        self.tags = tags
        self.website = website
        self.relayKind = relayKind
        self.federationMode = federationMode
        self.federationName = federationName
        self.federationDescription = federationDescription
        self.temporalBucketSeconds = temporalBucketSeconds
        self.temporalBucketScheduleSeconds = temporalBucketScheduleSeconds
        self.attachmentDefaultTTLSeconds = attachmentDefaultTTLSeconds
        self.attachmentMaxTTLSeconds = attachmentMaxTTLSeconds
        self.hiddenRetrieval = hiddenRetrieval
        self.operatorNote = operatorNote
        self.softwareVersion = softwareVersion
        self.groupCreationMode = groupCreationMode
        self.groupSecurityModel = groupSecurityModel
        self.requiresPassword = requiresPassword
        self.useTLS = useTLS
        self.transport = transport
        self.tlsCertificateFingerprintSHA256 = tlsCertificateFingerprintSHA256
        self.federationCoordinatorEndpoints = federationCoordinatorEndpoints
        self.coordinatorReportedRelayCount = coordinatorReportedRelayCount
        self.curatedStrictPolicyEnabled = curatedStrictPolicyEnabled
        self.curatedCoordinatorQuorum = curatedCoordinatorQuorum
        self.curatedRequireSignedDirectory = curatedRequireSignedDirectory
    }
}

public struct MasterServerList: Codable, Equatable {
    public let servers: [MasterServerEntry]

    public init(servers: [MasterServerEntry]) {
        self.servers = servers
    }
}

public extension RelayServerRecord {
    init(entry: MasterServerEntry, sourceId: UUID) {
        let serverName = entry.name ?? "\(entry.host):\(entry.port)"
        let advertisedInfo = RelayServerRecord.makeAdvertisedInfo(from: entry)
        self.init(
            name: serverName,
            endpoint: RelayEndpoint(
                host: entry.host,
                port: entry.port,
                useTLS: entry.useTLS ?? false,
                transport: entry.transport ?? .tcp,
                tlsCertificateFingerprintSHA256: entry.tlsCertificateFingerprintSHA256
            ),
            note: entry.note,
            relayPassword: nil,
            region: entry.region,
            tags: entry.tags,
            website: entry.website,
            advertisedInfo: advertisedInfo,
            lastInfoFetchedAt: advertisedInfo == nil ? nil : Date(),
            origin: .master,
            sourceId: sourceId
        )
    }
}

public extension RelayServerRecord {
    var displayName: String {
        if let relayName = advertisedInfo?.relayName?.trimmingCharacters(in: .whitespacesAndNewlines),
           !relayName.isEmpty {
            return relayName
        }
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            return name
        }
        return "\(endpoint.host):\(endpoint.port)"
    }
}

private extension RelayServerRecord {
    static func makeAdvertisedInfo(from entry: MasterServerEntry) -> RelayInfo? {
        let hasMetadata = entry.relayKind != nil
            || entry.federationMode != nil
            || entry.federationName != nil
            || entry.federationDescription != nil
            || entry.temporalBucketSeconds != nil
            || entry.temporalBucketScheduleSeconds != nil
            || entry.attachmentDefaultTTLSeconds != nil
            || entry.attachmentMaxTTLSeconds != nil
            || entry.hiddenRetrieval != nil
            || entry.operatorNote != nil
            || entry.softwareVersion != nil
            || entry.groupCreationMode != nil
            || entry.groupSecurityModel != nil
            || entry.requiresPassword != nil
            || entry.useTLS != nil
            || entry.transport != nil
            || entry.tlsCertificateFingerprintSHA256 != nil
            || entry.federationCoordinatorEndpoints != nil
            || entry.coordinatorReportedRelayCount != nil
            || entry.curatedStrictPolicyEnabled != nil
            || entry.curatedCoordinatorQuorum != nil
            || entry.curatedRequireSignedDirectory != nil
        guard hasMetadata else { return nil }
        let federation = FederationDescriptor(
            mode: entry.federationMode ?? .solo,
            name: entry.federationName,
            description: entry.federationDescription
        )
        return RelayInfo(
            kind: entry.relayKind ?? .standard,
            federation: federation,
            temporalBucketSeconds: entry.temporalBucketSeconds ?? 300,
            temporalBucketScheduleSeconds: entry.temporalBucketScheduleSeconds,
            attachmentDefaultTTLSeconds: entry.attachmentDefaultTTLSeconds,
            attachmentMaxTTLSeconds: entry.attachmentMaxTTLSeconds,
            hiddenRetrieval: entry.hiddenRetrieval,
            operatorNote: entry.operatorNote,
            softwareVersion: entry.softwareVersion,
            groupCreationMode: entry.groupCreationMode,
            groupSecurityModel: entry.groupSecurityModel,
            requiresPassword: entry.requiresPassword,
            tlsEnabled: entry.useTLS,
            transport: entry.transport,
            federationCoordinatorEndpoints: entry.federationCoordinatorEndpoints,
            coordinatorReportedRelayCount: entry.coordinatorReportedRelayCount,
            curatedStrictPolicyEnabled: entry.curatedStrictPolicyEnabled,
            curatedCoordinatorQuorum: entry.curatedCoordinatorQuorum,
            curatedRequireSignedDirectory: entry.curatedRequireSignedDirectory
        )
    }
}
