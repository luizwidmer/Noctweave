import Foundation

public enum RelayCapabilityStatusV2: String, Codable, Equatable, CaseIterable {
    case experimental
    case provisional
    case stable
    case deprecated
}

/// Canonical advertised limits for `nw.opaque-route@2`. The in-process relay
/// and Linux relay publish this exact registry so clients never infer runtime
/// bounds from implementation-specific defaults.
public enum OpaqueRouteRelayCapabilityLimitsV2 {
    public static let cursorBytes: UInt64 = UInt64(
        NoctweaveOpaqueRouteRelayStoreV2.cursorBytes
    )
    public static let maxPage: UInt64 = UInt64(
        NoctweaveOpaqueRouteRelayStoreV2.maximumSyncPage
    )
    public static let maxPacketBytes: UInt64 = UInt64(
        OpaqueRoutePaddingBucketV2.bytes65536.rawValue
    )
    public static let maxPacketsPerRoute: UInt64 = UInt64(
        OpaqueRouteQuotaBucketV2.packets1024.rawValue
    )
    public static let maxRetentionSeconds: UInt64 = UInt64(
        OpaqueRouteRetentionBucketV2.sevenDays.rawValue
    )
    public static let maxRoutes: UInt64 = UInt64(
        NoctweaveOpaqueRouteRelayStoreV2.maximumRoutes
    )

    public static let registry: [String: UInt64] = [
        "cursorBytes": cursorBytes,
        "maxPage": maxPage,
        "maxPacketBytes": maxPacketBytes,
        "maxPacketsPerRoute": maxPacketsPerRoute,
        "maxRetentionSeconds": maxRetentionSeconds,
        "maxRoutes": maxRoutes,
    ]
}

public enum RealtimeRelayCapabilityLimitsV1 {
    public static let registry: [String: UInt64] = [
        "maxRecordBytes": UInt64(RealtimeRelayLimitsV1.maximumRecordBytes),
        "maxPage": UInt64(RealtimeRelayLimitsV1.maximumRecordsPerPage),
        "maxRecords": UInt64(RealtimeRelayLimitsV1.maximumRealtimeRecords),
        "maxLifetimeSeconds": UInt64(RealtimeRelayLimitsV1.maximumRealtimeLifetime),
        "immediate": 1
    ]
}

public enum SharedLogRelayCapabilityLimitsV1 {
    public static let registry: [String: UInt64] = [
        "maxRecordBytes": UInt64(RealtimeRelayLimitsV1.maximumRecordBytes),
        "maxPage": UInt64(RealtimeRelayLimitsV1.maximumRecordsPerPage),
        "maxRecords": UInt64(RealtimeRelayLimitsV1.maximumSharedLogRecords),
        "maxRetentionSeconds": UInt64(RealtimeRelayLimitsV1.maximumSharedLogLifetime)
    ]
}

public enum PresenceRelayCapabilityLimitsV1 {
    public static let registry: [String: UInt64] = [
        "maxPayloadBytes": UInt64(RealtimeRelayLimitsV1.maximumPresencePayloadBytes),
        "minLeaseSeconds": UInt64(RealtimeRelayLimitsV1.minimumPresenceLeaseSeconds),
        "maxLeaseSeconds": UInt64(RealtimeRelayLimitsV1.maximumPresenceLeaseSeconds)
    ]
}

public enum MediaBlobRelayCapabilityLimitsV1 {
    public static let registry: [String: UInt64] = [
        "maxChunkBytes": UInt64(RealtimeRelayLimitsV1.maximumMediaBlobChunkBytes),
        "maxChunks": UInt64(RealtimeRelayLimitsV1.maximumMediaBlobChunks),
        "maxBlobBytes": UInt64(RealtimeRelayLimitsV1.maximumMediaBlobBytes),
        "minRetentionSeconds": UInt64(RealtimeRelayLimitsV1.minimumMediaRetentionSeconds),
        "maxRetentionSeconds": UInt64(RealtimeRelayLimitsV1.maximumMediaRetentionSeconds),
        "requiresCapability": 1
    ]
}

/// One relay-side protocol module. This is intentionally narrower than an
/// endpoint capability manifest: relays advertise only operations they
/// actually terminate, never encrypted application semantics they cannot see.
public struct RelayModuleCapabilityV2: Codable, Equatable {
    public let module: String
    public let versions: [UInt16]
    public let status: RelayCapabilityStatusV2
    public let limits: [String: UInt64]

    public init(
        module: String,
        versions: [UInt16],
        status: RelayCapabilityStatusV2,
        limits: [String: UInt64] = [:]
    ) {
        self.module = module
        self.versions = Array(Set(versions)).sorted()
        self.status = status
        self.limits = limits
    }

    public var isStructurallyValid: Bool {
        let normalized = module.trimmingCharacters(in: .whitespacesAndNewlines)
        let canonicalVersions = Array(Set(versions)).sorted()
        return !normalized.isEmpty
            && normalized == module
            && module.hasPrefix("nw.")
            && module.utf8.count <= NoctweaveArchitectureV2.maximumModuleNameBytes
            && !versions.isEmpty
            && versions.count <= NoctweaveArchitectureV2.maximumModuleVersions
            && versions.allSatisfy { $0 > 0 }
            && versions == canonicalVersions
            && limits.count <= 32
            && limits.allSatisfy { key, _ in
                let normalizedKey = key.trimmingCharacters(in: .whitespacesAndNewlines)
                return !normalizedKey.isEmpty
                    && normalizedKey == key
                    && key.utf8.count <= 96
                    && key.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
            }
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case module
        case versions
        case status
        case limits
    }

    public init(from decoder: Decoder) throws {
        try relayCapabilitiesRequireExactObject(
            decoder,
            keys: CodingKeys.allCases.map(\.rawValue)
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        module = try container.decode(String.self, forKey: .module)
        versions = try container.decode([UInt16].self, forKey: .versions)
        status = try container.decode(RelayCapabilityStatusV2.self, forKey: .status)
        limits = try container.decode([String: UInt64].self, forKey: .limits)
        guard isStructurallyValid else {
            throw relayCapabilitiesDecodingError(decoder, "Relay module capability is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayCapabilitiesEncodingError(encoder, "Relay module capability is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(module, forKey: .module)
        try container.encode(versions, forKey: .versions)
        try container.encode(status, forKey: .status)
        try container.encode(limits, forKey: .limits)
    }
}

public struct RelayCapabilityManifestV2: Codable, Equatable {
    public let architectureVersion: Int
    public let modules: [RelayModuleCapabilityV2]

    public init(
        architectureVersion: Int = NoctweaveArchitectureV2.version,
        modules: [RelayModuleCapabilityV2]
    ) {
        self.architectureVersion = architectureVersion
        self.modules = modules.sorted { $0.module < $1.module }
    }

    public var isStructurallyValid: Bool {
        architectureVersion == NoctweaveArchitectureV2.version
            && !modules.isEmpty
            && modules.count <= NoctweaveArchitectureV2.maximumModules
            && Set(modules.map(\.module)).count == modules.count
            && modules.map(\.module) == modules.map(\.module).sorted()
            && modules.allSatisfy(\.isStructurallyValid)
            && supports(module: "nw.core", version: 2)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case architectureVersion
        case modules
    }

    public init(from decoder: Decoder) throws {
        try relayCapabilitiesRequireExactObject(
            decoder,
            keys: CodingKeys.allCases.map(\.rawValue)
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        architectureVersion = try container.decode(Int.self, forKey: .architectureVersion)
        modules = try container.decode([RelayModuleCapabilityV2].self, forKey: .modules)
        guard isStructurallyValid else {
            throw relayCapabilitiesDecodingError(decoder, "Relay capability manifest is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw relayCapabilitiesEncodingError(encoder, "Relay capability manifest is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(architectureVersion, forKey: .architectureVersion)
        try container.encode(modules, forKey: .modules)
    }

    public func supports(module: String, version: UInt16) -> Bool {
        modules.contains { $0.module == module && $0.versions.contains(version) }
    }

    public static func advertised(
        relayKind: RelayKind = .standard,
        attachmentsEnabled: Bool,
        wakeEnabled: Bool,
        hiddenRetrievalEnabled: Bool,
        onionEnabled: Bool,
        mixnetEnabled: Bool,
        openDiscoveryEnabled: Bool = false,
        rendezvousTransportEnabled: Bool = false,
        federationForwardingEnabled: Bool = false,
        netHostEnabled: Bool = false,
        iceServiceEnabled: Bool = false,
        realtimeRoutesEnabled: Bool = true,
        sharedLogsEnabled: Bool = true,
        ephemeralPresenceEnabled: Bool = true,
        mediaBlobsEnabled: Bool = true
    ) -> RelayCapabilityManifestV2 {
        var modules = [
            RelayModuleCapabilityV2(module: "nw.core", versions: [2], status: .provisional)
        ]
        if relayKind == .passthrough {
            modules.append(
                RelayModuleCapabilityV2(
                    module: "nw.net-passthrough",
                    versions: [1],
                    status: .provisional,
                    limits: [
                        "maxHops": 1,
                        "maxRequestBytes": UInt64(NoctweaveNetLimits.maximumPassthroughPayloadBytes),
                        "maxResponseBytes": UInt64(NoctweaveNetLimits.maximumPassthroughPayloadBytes)
                    ]
                )
            )
            return RelayCapabilityManifestV2(modules: modules)
        }
        if relayKind == .host {
            modules.append(
                RelayModuleCapabilityV2(
                    module: "nw.net-host",
                    versions: [1],
                    status: .provisional,
                    limits: [
                        "maxObjectBytes": UInt64(NoctweaveNetLimits.maximumHostObjectBytes),
                        "maxRetentionSeconds": UInt64(NoctweaveNetLimits.maximumHostRetentionSeconds)
                    ]
                )
            )
            return RelayCapabilityManifestV2(modules: modules)
        }
        modules.append(
            RelayModuleCapabilityV2(
                module: "nw.opaque-route",
                versions: [2],
                status: .provisional,
                limits: OpaqueRouteRelayCapabilityLimitsV2.registry
            )
        )
        if relayKind == .standard, realtimeRoutesEnabled {
            modules.append(RelayModuleCapabilityV2(module: "nw.realtime-route", versions: [1], status: .provisional, limits: RealtimeRelayCapabilityLimitsV1.registry))
        }
        if relayKind == .standard, sharedLogsEnabled {
            modules.append(RelayModuleCapabilityV2(module: "nw.shared-log", versions: [1], status: .provisional, limits: SharedLogRelayCapabilityLimitsV1.registry))
        }
        if relayKind == .standard, ephemeralPresenceEnabled {
            modules.append(RelayModuleCapabilityV2(module: "nw.ephemeral-presence", versions: [1], status: .provisional, limits: PresenceRelayCapabilityLimitsV1.registry))
        }
        if relayKind == .standard, mediaBlobsEnabled {
            modules.append(RelayModuleCapabilityV2(module: "nw.media-blobs", versions: [1], status: .provisional, limits: MediaBlobRelayCapabilityLimitsV1.registry))
        }
        if iceServiceEnabled {
            modules.append(
                RelayModuleCapabilityV2(
                    module: "nw.ice-service",
                    versions: [1],
                    status: .provisional,
                    limits: [
                        "maxURLs": UInt64(RelayICEServiceV1.maximumURLs),
                        "minCredentialLifetimeSeconds": UInt64(
                            RelayICEServiceV1.minimumCredentialLifetimeSeconds
                        ),
                        "maxCredentialLifetimeSeconds": UInt64(
                            RelayICEServiceV1.maximumCredentialLifetimeSeconds
                        )
                    ]
                )
            )
        }
        modules.append(
            RelayModuleCapabilityV2(module: "nw.federation", versions: [1], status: .provisional)
        )
        if federationForwardingEnabled {
            modules.append(
                RelayModuleCapabilityV2(
                    module: "nw.federation-forward",
                    versions: [1],
                    status: .provisional,
                    limits: [
                        "maxHops": 1,
                        "maxDeliveryLifetimeSeconds": UInt64(
                            FederationForwardingV1.maximumDeliveryLifetime
                        ),
                        "maxPacketBytes": OpaqueRouteRelayCapabilityLimitsV2.maxPacketBytes
                    ]
                )
            )
        }
        if netHostEnabled {
            modules.append(
                RelayModuleCapabilityV2(
                    module: "nw.net-host",
                    versions: [1],
                    status: .provisional,
                    limits: [
                        "maxObjectBytes": UInt64(
                            NoctweaveNetLimits.maximumHostObjectBytes
                        ),
                        "maxRetentionSeconds": UInt64(
                            NoctweaveNetLimits.maximumHostRetentionSeconds
                        ),
                    ]
                )
            )
        }
        if attachmentsEnabled {
            modules.append(RelayModuleCapabilityV2(module: "nw.blobs", versions: [1], status: .provisional))
        }
        if wakeEnabled {
            modules.append(RelayModuleCapabilityV2(module: "nw.wake", versions: [1], status: .experimental))
        }
        if hiddenRetrievalEnabled {
            modules.append(
                RelayModuleCapabilityV2(
                    module: "nw.privacy.hidden-retrieval",
                    versions: [1],
                    status: .experimental
                )
            )
        }
        if onionEnabled {
            modules.append(
                RelayModuleCapabilityV2(module: "nw.privacy.onion", versions: [1], status: .experimental)
            )
        }
        if mixnetEnabled {
            modules.append(
                RelayModuleCapabilityV2(module: "nw.privacy.mixnet", versions: [1], status: .experimental)
            )
        }
        if openDiscoveryEnabled {
            modules.append(
                RelayModuleCapabilityV2(
                    module: "nw.open-discovery",
                    versions: [1],
                    status: .experimental
                )
            )
        }
        if rendezvousTransportEnabled {
            modules.append(
                RelayModuleCapabilityV2(
                    module: "nw.rendezvous-transport",
                    versions: [2],
                    status: .provisional,
                    limits: [
                        "maxLifetimeSeconds": 600,
                        "maxLanes": 2,
                        "maxFramesPerLane": 32,
                        "maxCiphertextBytesPerLane": 2_097_152
                    ]
                )
            )
        }
        return RelayCapabilityManifestV2(modules: modules)
    }
}

private struct RelayCapabilitiesCodingKey: CodingKey {
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

private func relayCapabilitiesRequireExactObject(
    _ decoder: Decoder,
    keys: [String]
) throws {
    let container = try decoder.container(keyedBy: RelayCapabilitiesCodingKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == Set(keys) else {
        throw relayCapabilitiesDecodingError(
            decoder,
            "Relay capability fields must match the current protocol exactly"
        )
    }
}

private func relayCapabilitiesDecodingError(
    _ decoder: Decoder,
    _ description: String
) -> DecodingError {
    DecodingError.dataCorrupted(
        .init(codingPath: decoder.codingPath, debugDescription: description)
    )
}

private func relayCapabilitiesEncodingError(
    _ encoder: Encoder,
    _ description: String
) -> EncodingError {
    EncodingError.invalidValue(
        description,
        .init(codingPath: encoder.codingPath, debugDescription: description)
    )
}
