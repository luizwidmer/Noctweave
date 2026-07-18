import Foundation

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
                !key.isEmpty
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

    init(architectureVersion: Int = Self.architectureVersion, modules: [RelayModuleCapabilityV2]) {
        self.architectureVersion = architectureVersion
        self.modules = modules.sorted { $0.module < $1.module }
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
        rendezvousTransportEnabled: Bool = false
    ) -> RelayCapabilityManifestV2 {
        var modules = [
            RelayModuleCapabilityV2(module: "nw.core", versions: [2], status: .stable),
            RelayModuleCapabilityV2(module: "nw.federation", versions: [1], status: .stable)
        ]
        if attachmentsEnabled {
            modules.append(RelayModuleCapabilityV2(module: "nw.blobs", versions: [1], status: .stable))
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
        if rendezvousTransportEnabled {
            modules.append(
                RelayModuleCapabilityV2(
                    module: "nw.rendezvous-transport",
                    versions: [2],
                    status: .experimental,
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
                    status: .stable,
                    limits: [
                        "cursorBytes": 68,
                        "maxPage": 256,
                        "maxPacketBytes": 65_536,
                        "maxPacketsPerRoute": 1_024,
                        "maxRetentionSeconds": 604_800
                    ]
                )
            )
        }
        return RelayCapabilityManifestV2(modules: modules)
    }
}
