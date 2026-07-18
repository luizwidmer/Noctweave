import Foundation

public enum RelayCapabilityStatusV2: String, Codable, Equatable, CaseIterable {
    case experimental
    case provisional
    case stable
    case deprecated
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
        return !normalized.isEmpty
            && normalized == module
            && module.hasPrefix("nw.")
            && module.utf8.count <= NoctweaveArchitectureV2.maximumModuleNameBytes
            && !versions.isEmpty
            && versions.count <= NoctweaveArchitectureV2.maximumModuleVersions
            && versions.allSatisfy { $0 > 0 }
            && limits.count <= 32
            && limits.allSatisfy { key, _ in
                !key.isEmpty
                    && key.utf8.count <= 96
                    && key.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
            }
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
            && modules.allSatisfy(\.isStructurallyValid)
            && supports(module: "nw.core", version: 2)
    }

    public func supports(module: String, version: UInt16) -> Bool {
        modules.contains { $0.module == module && $0.versions.contains(version) }
    }

    public static func advertised(
        attachmentsEnabled: Bool,
        wakeEnabled: Bool,
        hiddenRetrievalEnabled: Bool,
        onionEnabled: Bool,
        mixnetEnabled: Bool,
        rendezvousTransportEnabled: Bool = false
    ) -> RelayCapabilityManifestV2 {
        var modules = [
            RelayModuleCapabilityV2(module: "nw.core", versions: [2], status: .provisional),
            RelayModuleCapabilityV2(
                module: "nw.opaque-route",
                versions: [2],
                status: .stable,
                limits: [
                    "maxCursorBytes": UInt64(NoctweaveOpaqueRouteRelayStoreV2.cursorBytes),
                    "maxPage": UInt64(NoctweaveOpaqueRouteRelayStoreV2.maximumSyncPage),
                    "maxRoutes": UInt64(NoctweaveOpaqueRouteRelayStoreV2.maximumRoutes)
                ]
            ),
            RelayModuleCapabilityV2(module: "nw.federation", versions: [1], status: .provisional)
        ]
        if attachmentsEnabled {
            modules.append(RelayModuleCapabilityV2(module: "nw.blobs", versions: [1], status: .stable))
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
        return RelayCapabilityManifestV2(modules: modules)
    }
}
