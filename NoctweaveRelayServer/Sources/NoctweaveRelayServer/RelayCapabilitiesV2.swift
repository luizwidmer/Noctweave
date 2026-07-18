import Foundation

/// Canonical advertised limits for `nw.opaque-route@2`. Keep this registry
/// byte-for-byte equivalent to the public Core registry.
enum OpaqueRouteRelayCapabilityLimitsV2 {
    static let cursorBytes: UInt64 = UInt64(NoctweaveOpaqueRouteRelayStoreV2.cursorBytes)
    static let maxPage: UInt64 = UInt64(NoctweaveOpaqueRouteRelayStoreV2.maximumSyncPage)
    static let maxPacketBytes: UInt64 = UInt64(OpaqueRoutePaddingBucketV2.bytes65536.rawValue)
    static let maxPacketsPerRoute: UInt64 = UInt64(OpaqueRouteQuotaBucketV2.packets1024.rawValue)
    static let maxRetentionSeconds: UInt64 = UInt64(OpaqueRouteRetentionBucketV2.sevenDays.rawValue)
    static let maxRoutes: UInt64 = UInt64(NoctweaveOpaqueRouteRelayStoreV2.maximumRoutes)

    static let registry: [String: UInt64] = [
        "cursorBytes": cursorBytes,
        "maxPage": maxPage,
        "maxPacketBytes": maxPacketBytes,
        "maxPacketsPerRoute": maxPacketsPerRoute,
        "maxRetentionSeconds": maxRetentionSeconds,
        "maxRoutes": maxRoutes,
    ]
}

enum RelayCapabilityStatusV2: String, Codable, Equatable, CaseIterable {
    case experimental
    case provisional
    case stable
    case deprecated
}

struct RelayModuleCapabilityV2: Codable, Equatable {
    let module: String
    let versions: [UInt16]
    let status: RelayCapabilityStatusV2
    let limits: [String: UInt64]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case module
        case versions
        case status
        case limits
    }

    init(
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

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Relay module capability")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let decodedModule = try values.decode(String.self, forKey: .module)
        let decodedVersions = try values.decode([UInt16].self, forKey: .versions)
        self.init(
            module: decodedModule,
            versions: decodedVersions,
            status: try values.decode(RelayCapabilityStatusV2.self, forKey: .status),
            limits: try values.decode([String: UInt64].self, forKey: .limits)
        )
        guard module == decodedModule,
              versions == decodedVersions,
              isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .module,
                in: values,
                debugDescription: "Relay module capability is not canonical or structurally valid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Relay module capability")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(module, forKey: .module)
        try values.encode(versions, forKey: .versions)
        try values.encode(status, forKey: .status)
        try values.encode(limits, forKey: .limits)
    }

    var isStructurallyValid: Bool {
        let normalized = module.trimmingCharacters(in: .whitespacesAndNewlines)
        return !normalized.isEmpty
            && normalized == module
            && module.hasPrefix("nw.")
            && module.utf8.count <= 96
            && !versions.isEmpty
            && versions.count <= 8
            && versions.allSatisfy { $0 > 0 }
            && limits.count <= 32
            && limits.allSatisfy { key, _ in
                let normalizedKey = key.trimmingCharacters(in: .whitespacesAndNewlines)
                return !normalizedKey.isEmpty
                    && normalizedKey == key
                    && key.utf8.count <= 96
                    && key.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
            }
    }
}

struct RelayCapabilityManifestV2: Codable, Equatable {
    static let architectureVersion = 2
    static let maximumModules = 64
    static let maximumEndpoints = 16
    static let maximumCursorBytes = 512

    let architectureVersion: Int
    let modules: [RelayModuleCapabilityV2]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case architectureVersion
        case modules
    }

    init(architectureVersion: Int = Self.architectureVersion, modules: [RelayModuleCapabilityV2]) {
        self.architectureVersion = architectureVersion
        self.modules = modules.sorted { $0.module < $1.module }
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Relay capability manifest")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let decodedModules = try values.decode([RelayModuleCapabilityV2].self, forKey: .modules)
        self.init(
            architectureVersion: try values.decode(Int.self, forKey: .architectureVersion),
            modules: decodedModules
        )
        guard modules == decodedModules, isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .modules,
                in: values,
                debugDescription: "Relay capability manifest is not canonical or structurally valid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Relay capability manifest")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(architectureVersion, forKey: .architectureVersion)
        try values.encode(modules, forKey: .modules)
    }

    var isStructurallyValid: Bool {
        architectureVersion == Self.architectureVersion
            && !modules.isEmpty
            && modules.count <= Self.maximumModules
            && Set(modules.map(\.module)).count == modules.count
            && modules.allSatisfy(\.isStructurallyValid)
            && supports(module: "nw.core", version: 2)
    }

    func supports(module: String, version: UInt16) -> Bool {
        modules.contains { $0.module == module && $0.versions.contains(version) }
    }

    static func advertised(
        attachmentsEnabled: Bool,
        hiddenRetrievalEnabled: Bool,
        onionEnabled: Bool,
        mixnetEnabled: Bool,
        opaqueRouteRuntimeEnabled: Bool = true,
        openDiscoveryEnabled: Bool = false,
        rendezvousTransportEnabled: Bool = false
    ) -> RelayCapabilityManifestV2 {
        var modules = [
            RelayModuleCapabilityV2(module: "nw.core", versions: [2], status: .provisional),
            RelayModuleCapabilityV2(module: "nw.federation", versions: [1], status: .provisional)
        ]
        if attachmentsEnabled {
            modules.append(RelayModuleCapabilityV2(module: "nw.blobs", versions: [1], status: .provisional))
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
        if opaqueRouteRuntimeEnabled {
            modules.append(
                RelayModuleCapabilityV2(
                    module: "nw.opaque-route",
                    versions: [2],
                    status: .provisional,
                    limits: OpaqueRouteRelayCapabilityLimitsV2.registry
                )
            )
        }
        return RelayCapabilityManifestV2(modules: modules)
    }
}
