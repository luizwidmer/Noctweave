import CryptoKit
import Foundation

public enum NoctweaveArchitectureV2 {
    public static let version = 2
    public static let maximumDeliveryStates = 4_096
    public static let deliveryStateRecentWindow = 3_072
    public static let maximumModules = 64
    public static let maximumModuleNameBytes = 96
    public static let maximumModuleVersions = 8
    public static let maximumContentTypeBytes = 96
    public static let maximumContentTypeCapabilities = 128
    public static let maximumContentTypeMajorVersions = 8
    public static let maximumContentParameters = 32
    public static let maximumContentParameterBytes = 256
    public static let maximumContentPayloadBytes = PaddedMessagePlaintext.maximumPaddedBytes
    public static let maximumFallbackBytes = 2_048
    public static let maximumRoutes = 8
    public static let maximumIntentDependencies = 32
    public static let maximumIntentAttempts = 64
    public static let maximumPendingDirectDeliveries = 1_024
    public static let maximumProtocolIntents = 1_024
    public static let protocolIntentRecentWindow = 768
    public static let maximumInboundEnvelopeReceipts = 4_096
    public static let inboundEnvelopeReceiptRecentWindow = 3_072
    public static let maximumQuarantinedTransportEnvelopes = 512
    public static let maximumQuarantinedControlEvents = 128
    public static let maximumRelationshipEvents = 4_096
    public static let relationshipEventRecentWindow = 3_072
    public static let maximumGroupEpochIntents = 256
    public static let groupEpochIntentRecentWindow = 192
    public static let maximumGroupEvents = 4_096
    public static let groupEventRecentWindow = 3_072
    public static let maximumPendingGroupPublications = 1_024
    public static let maximumProcessedGroupEnvelopes = 4_096
    public static let processedGroupEnvelopeRecentWindow = 3_072
}

/// Bounded replay receipt for one successfully verified and durably processed
/// direct envelope. The source scope and logical event ID catch one relationship
/// reusing an event ID with a different envelope ID without treating unrelated
/// contacts as a global namespace; the digest catches mutation under the same
/// envelope ID. Receipts are a recent replay cache, not message history: once
/// compacted out, an old replay is decrypted again and rejected by the ratchet
/// instead of being skipped without verification.
public struct InboundEnvelopeReceiptV2: Codable, Equatable, Identifiable {
    public var id: UUID { envelopeId }
    public let sourceScopeId: UUID
    public let logicalEventId: UUID
    public let envelopeId: UUID
    public let envelopeDigest: Data
    public let processedAt: Date

    public init(
        sourceScopeId: UUID,
        logicalEventId: UUID,
        envelopeId: UUID,
        envelopeDigest: Data,
        processedAt: Date = Date()
    ) {
        self.sourceScopeId = sourceScopeId
        self.logicalEventId = logicalEventId
        self.envelopeId = envelopeId
        self.envelopeDigest = envelopeDigest
        self.processedAt = processedAt
    }

    public var isStructurallyValid: Bool {
        envelopeDigest.count == 32 && processedAt.timeIntervalSince1970.isFinite
    }

    func isReplayCandidate(
        sourceScopeId: UUID,
        logicalEventId: UUID,
        envelopeId: UUID
    ) -> Bool {
        (self.sourceScopeId == sourceScopeId && self.logicalEventId == logicalEventId)
            || self.envelopeId == envelopeId
    }

    func isExactReplay(
        sourceScopeId: UUID,
        logicalEventId: UUID,
        envelopeId: UUID,
        envelopeDigest: Data
    ) -> Bool {
        self.logicalEventId == logicalEventId
            && self.envelopeId == envelopeId
            && self.sourceScopeId == sourceScopeId
            && self.envelopeDigest == envelopeDigest
    }

    private enum CodingKeys: String, CodingKey {
        case sourceScopeId
        case logicalEventId
        case envelopeId
        case envelopeDigest
        case processedAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sourceScopeId = try container.decode(UUID.self, forKey: .sourceScopeId)
        logicalEventId = try container.decode(UUID.self, forKey: .logicalEventId)
        envelopeId = try container.decode(UUID.self, forKey: .envelopeId)
        envelopeDigest = try container.decode(Data.self, forKey: .envelopeDigest)
        processedAt = try container.decode(Date.self, forKey: .processedAt)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(sourceScopeId, forKey: .sourceScopeId)
        try container.encode(logicalEventId, forKey: .logicalEventId)
        try container.encode(envelopeId, forKey: .envelopeId)
        try container.encode(envelopeDigest, forKey: .envelopeDigest)
        try container.encode(processedAt, forKey: .processedAt)
    }
}

public enum TransportQuarantineReasonV2: String, Codable, Equatable, CaseIterable {
    case unknownSender
    case incompatibleProtocol
    case invalidAttribution
    case invalidCiphertext
    case replayConflict
    case unsupportedPayload
}

/// Bounded local dead-letter receipt for a permanently invalid opaque-route
/// event. It contains no plaintext or sender key material. Persisting this
/// receipt before committing the route cursor prevents one hostile packet from
/// permanently blocking every later packet in the ordered stream.
public struct QuarantinedTransportEnvelopeV2: Codable, Equatable, Identifiable {
    public var id: UUID { envelopeId }
    public let streamDigest: Data
    public let sequence: UInt64
    public let envelopeId: UUID
    public let envelopeDigest: Data
    public let reason: TransportQuarantineReasonV2
    public let quarantinedAt: Date

    public init(
        streamDigest: Data,
        sequence: UInt64,
        envelopeId: UUID,
        envelopeDigest: Data,
        reason: TransportQuarantineReasonV2,
        quarantinedAt: Date = Date()
    ) {
        self.streamDigest = streamDigest
        self.sequence = sequence
        self.envelopeId = envelopeId
        self.envelopeDigest = envelopeDigest
        self.reason = reason
        self.quarantinedAt = quarantinedAt
    }

    public var isStructurallyValid: Bool {
        streamDigest.count == 32
            && sequence > 0
            && envelopeDigest.count == 32
            && quarantinedAt.timeIntervalSince1970.isFinite
    }
}

public enum ProtocolExtensionStatus: String, Codable, Equatable, CaseIterable {
    case experimental
    case provisional
    case stable
    case deprecated
}

public struct ProtocolModuleCapability: Codable, Equatable {
    public let module: String
    public let versions: [UInt16]
    public let status: ProtocolExtensionStatus
    public let limits: [String: UInt64]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case module
        case versions
        case status
        case limits
    }

    public init(
        module: String,
        versions: [UInt16],
        status: ProtocolExtensionStatus,
        limits: [String: UInt64] = [:]
    ) {
        self.module = module
        self.versions = Array(Set(versions)).sorted()
        self.status = status
        self.limits = limits
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: ArchitectureV2CodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Protocol module fields must match the current schema exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedVersions = try container.decode([UInt16].self, forKey: .versions)
        self.init(
            module: try container.decode(String.self, forKey: .module),
            versions: decodedVersions,
            status: try container.decode(ProtocolExtensionStatus.self, forKey: .status),
            limits: try container.decode([String: UInt64].self, forKey: .limits)
        )
        guard versions == decodedVersions, isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .module,
                in: container,
                debugDescription: "Invalid protocol module capability"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid protocol module capability"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(module, forKey: .module)
        try container.encode(versions, forKey: .versions)
        try container.encode(status, forKey: .status)
        try container.encode(limits, forKey: .limits)
    }

    public var isStructurallyValid: Bool {
        let normalized = module.trimmingCharacters(in: .whitespacesAndNewlines)
        return !normalized.isEmpty
            && normalized == module
            && module.utf8.count <= NoctweaveArchitectureV2.maximumModuleNameBytes
            && module.hasPrefix("nw.")
            && !versions.isEmpty
            && versions.count <= NoctweaveArchitectureV2.maximumModuleVersions
            && versions.allSatisfy { $0 > 0 }
            && limits.count <= 32
            && limits.allSatisfy { key, _ in
                !key.isEmpty && key.utf8.count <= 96
            }
    }
}

/// A namespaced application-content family understood by one relationship
/// endpoint. Major versions are compatibility boundaries; minor revisions stay
/// within the semantics of their advertised major version. This registry does
/// not grant control-message authority.
public struct ContentTypeCapabilityV2: Codable, Equatable, Hashable {
    public let authority: String
    public let name: String
    public let majorVersions: [UInt16]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case authority
        case name
        case majorVersions
    }

    public init(authority: String, name: String, majorVersions: [UInt16]) {
        self.authority = authority
        self.name = name
        self.majorVersions = Array(Set(majorVersions)).sorted()
    }

    public init(_ contentType: ContentTypeId) {
        self.init(
            authority: contentType.authority,
            name: contentType.name,
            majorVersions: [contentType.major]
        )
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: ArchitectureV2CodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Content capability fields must match the current schema exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedMajorVersions = try container.decode(
            [UInt16].self,
            forKey: .majorVersions
        )
        self.init(
            authority: try container.decode(String.self, forKey: .authority),
            name: try container.decode(String.self, forKey: .name),
            majorVersions: decodedMajorVersions
        )
        guard majorVersions == decodedMajorVersions, isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .authority,
                in: container,
                debugDescription: "Invalid content type capability"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid content type capability"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(authority, forKey: .authority)
        try container.encode(name, forKey: .name)
        try container.encode(majorVersions, forKey: .majorVersions)
    }

    public var isStructurallyValid: Bool {
        let representative = ContentTypeId(
            authority: authority,
            name: name,
            major: majorVersions.first ?? 0
        )
        return representative.isStructurallyValid
            && !majorVersions.isEmpty
            && majorVersions.count
                <= NoctweaveArchitectureV2.maximumContentTypeMajorVersions
            && majorVersions.allSatisfy { $0 > 0 }
    }

    public func supports(_ contentType: ContentTypeId) -> Bool {
        contentType.isStructurallyValid
            && authority == contentType.authority
            && name == contentType.name
            && majorVersions.contains(contentType.major)
    }
}

public struct ProtocolCapabilityManifest: Codable, Equatable {
    /// Complete registry of module identifiers understood by this release.
    /// Presence here is descriptive only: it does not claim that an endpoint
    /// has wired or enabled the module.
    public static let knownModuleCatalog: [ProtocolModuleCapability] = [
        ProtocolModuleCapability(module: "nw.core", versions: [2], status: .stable),
        ProtocolModuleCapability(module: "nw.direct", versions: [4], status: .stable),
        ProtocolModuleCapability(module: "nw.opaque-route", versions: [2], status: .stable),
        ProtocolModuleCapability(module: "nw.rendezvous-transport", versions: [2], status: .stable),
        ProtocolModuleCapability(module: "nw.blobs", versions: [1], status: .stable),
        ProtocolModuleCapability(module: "nw.groups", versions: [2], status: .experimental),
        ProtocolModuleCapability(module: "nw.wake", versions: [1], status: .experimental),
        ProtocolModuleCapability(module: "nw.federation", versions: [1], status: .stable),
        ProtocolModuleCapability(
            module: "nw.privacy.hidden-retrieval",
            versions: [1],
            status: .experimental
        ),
        ProtocolModuleCapability(module: "nw.privacy.onion", versions: [1], status: .experimental),
        ProtocolModuleCapability(module: "nw.privacy.mixnet", versions: [1], status: .experimental)
    ]

    /// Capabilities implemented by the direct-v4 baseline. Prekeys, content
    /// events, and the single relationship endpoint are implementation details
    /// of `nw.direct`, not separately negotiable product modules.
    public static let defaultActiveEndpointModules: [ProtocolModuleCapability] = [
        ProtocolModuleCapability(
            module: "nw.core",
            versions: [2],
            status: .stable,
            limits: [
                "maxContentParameterBytes": UInt64(
                    NoctweaveArchitectureV2.maximumContentParameterBytes
                ),
                "maxContentParameters": UInt64(
                    NoctweaveArchitectureV2.maximumContentParameters
                ),
                "maxContentPayloadBytes": UInt64(
                    NoctweaveArchitectureV2.maximumContentPayloadBytes
                ),
                "maxFallbackBytes": UInt64(
                    NoctweaveArchitectureV2.maximumFallbackBytes
                )
            ]
        ),
        ProtocolModuleCapability(
            module: "nw.direct",
            versions: [4],
            status: .stable,
            limits: [
                "maxCiphertextBytes": UInt64(PaddedMessagePlaintext.maximumPaddedBytes),
                "maxPrekeyAgeSeconds": UInt64(PrekeyBundle.maximumAge)
            ]
        )
    ]

    public static let defaultContentTypes: [ContentTypeCapabilityV2] = [
        ContentTypeCapabilityV2(.text),
        ContentTypeCapabilityV2(.attachment),
        ContentTypeCapabilityV2(.reaction),
        ContentTypeCapabilityV2(.retraction),
        ContentTypeCapabilityV2(.deliveryReceipt),
        ContentTypeCapabilityV2(.readReceipt)
    ]

    public let architectureVersion: Int
    public let modules: [ProtocolModuleCapability]
    public let contentTypes: [ContentTypeCapabilityV2]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case architectureVersion
        case modules
        case contentTypes
    }

    public init(
        architectureVersion: Int = NoctweaveArchitectureV2.version,
        modules: [ProtocolModuleCapability] = ProtocolCapabilityManifest.defaultActiveEndpointModules,
        contentTypes: [ContentTypeCapabilityV2] = ProtocolCapabilityManifest.defaultContentTypes
    ) {
        self.architectureVersion = architectureVersion
        self.modules = modules.sorted { $0.module < $1.module }
        self.contentTypes = contentTypes.sorted {
            ($0.authority, $0.name) < ($1.authority, $1.name)
        }
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: ArchitectureV2CodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Protocol capability fields must match the current schema exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedModules = try container.decode(
            [ProtocolModuleCapability].self,
            forKey: .modules
        )
        let decodedContentTypes = try container.decode(
            [ContentTypeCapabilityV2].self,
            forKey: .contentTypes
        )
        self.init(
            architectureVersion: try container.decode(Int.self, forKey: .architectureVersion),
            modules: decodedModules,
            contentTypes: decodedContentTypes
        )
        guard modules == decodedModules,
              contentTypes == decodedContentTypes,
              isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .modules,
                in: container,
                debugDescription: "Invalid protocol capability manifest"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid protocol capability manifest"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(architectureVersion, forKey: .architectureVersion)
        try container.encode(modules, forKey: .modules)
        try container.encode(contentTypes, forKey: .contentTypes)
    }

    public var isStructurallyValid: Bool {
        architectureVersion == NoctweaveArchitectureV2.version
            && !modules.isEmpty
            && modules.count <= NoctweaveArchitectureV2.maximumModules
            && Set(modules.map(\.module)).count == modules.count
            && modules.allSatisfy(\.isStructurallyValid)
            && !contentTypes.isEmpty
            && contentTypes.count
                <= NoctweaveArchitectureV2.maximumContentTypeCapabilities
            && Set(contentTypes.map { "\($0.authority)\u{0}\($0.name)" }).count
                == contentTypes.count
            && contentTypes.allSatisfy(\.isStructurallyValid)
            && supports(module: "nw.core", version: 2)
            && supportsContentFamily(
                authority: ContentTypeId.text.authority,
                name: ContentTypeId.text.name
            )
    }

    public func supports(module: String, version: UInt16) -> Bool {
        modules.contains { $0.module == module && $0.versions.contains(version) }
    }

    public func supports(contentType: ContentTypeId) -> Bool {
        contentTypes.contains { $0.supports(contentType) }
    }

    public func supportsContentFamily(authority: String, name: String) -> Bool {
        contentTypes.contains { $0.authority == authority && $0.name == name }
    }

    public func negotiated(with peer: ProtocolCapabilityManifest) -> ProtocolCapabilityManifest? {
        guard isStructurallyValid, peer.isStructurallyValid else { return nil }
        let peerByModule = Dictionary(uniqueKeysWithValues: peer.modules.map { ($0.module, $0) })
        let negotiated = modules.compactMap { local -> ProtocolModuleCapability? in
            guard let remote = peerByModule[local.module] else { return nil }
            let shared = Array(Set(local.versions).intersection(remote.versions)).sorted()
            guard !shared.isEmpty else { return nil }
            return ProtocolModuleCapability(
                module: local.module,
                versions: [shared.last!],
                status: local.status,
                limits: local.limits.merging(remote.limits) { min($0, $1) }
            )
        }
        let peerContentTypes = Dictionary(
            uniqueKeysWithValues: peer.contentTypes.map {
                ("\($0.authority)\u{0}\($0.name)", $0)
            }
        )
        let negotiatedContentTypes = contentTypes.compactMap {
            local -> ContentTypeCapabilityV2? in
            let key = "\(local.authority)\u{0}\(local.name)"
            guard let remote = peerContentTypes[key] else { return nil }
            let shared = Array(
                Set(local.majorVersions).intersection(remote.majorVersions)
            ).sorted()
            guard !shared.isEmpty else { return nil }
            return ContentTypeCapabilityV2(
                authority: local.authority,
                name: local.name,
                majorVersions: [shared.last!]
            )
        }
        let result = ProtocolCapabilityManifest(
            modules: negotiated,
            contentTypes: negotiatedContentTypes
        )
        return result.supports(module: "nw.core", version: 2)
            && result.supportsContentFamily(
                authority: ContentTypeId.text.authority,
                name: ContentTypeId.text.name
            ) ? result : nil
    }
}

public struct RelationshipEndpointHandle: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public static func generate(
        relationshipId: UUID,
        nonce: UUID = UUID()
    ) -> RelationshipEndpointHandle {
        var material = Data("Noctweave/relationship-endpoint-handle/v2".utf8)
        material.append(0)
        material.append(Data(relationshipId.uuidString.lowercased().utf8))
        material.append(0)
        material.append(Data(nonce.uuidString.lowercased().utf8))
        return RelationshipEndpointHandle(
            rawValue: Data(SHA256.hash(data: material)).base64EncodedString()
        )
    }

    public var isStructurallyValid: Bool {
        guard let decoded = Data(base64Encoded: rawValue), decoded.count == 32 else { return false }
        return decoded.base64EncodedString() == rawValue
    }
}

public struct LocalRelationshipEndpointV2: Codable, Equatable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var signingKey: SigningKeyPair
    public var agreementKey: AgreementKeyPair
    public var prekeys: PrekeyState
    public let createdAt: Date

    public init(
        signingKey: SigningKeyPair,
        agreementKey: AgreementKeyPair,
        prekeys: PrekeyState,
        createdAt: Date = Date()
    ) {
        self.signingKey = signingKey
        self.agreementKey = agreementKey
        self.prekeys = prekeys
        self.createdAt = createdAt
    }

    public static func generate(
        createdAt: Date = Date()
    ) throws -> LocalRelationshipEndpointV2 {
        let signingKey = try SigningKeyPair.generate()
        let agreementKey = try AgreementKeyPair.generate()
        let endpointAuthority = try RelationshipAuthorityV2(
            relationshipPseudonym: "Noctweave endpoint",
            signingKey: signingKey,
            agreementKey: agreementKey,
            createdAt: createdAt
        )
        return LocalRelationshipEndpointV2(
            signingKey: signingKey,
            agreementKey: agreementKey,
            prekeys: try PrekeyState.generate(
                authority: endpointAuthority,
                issuedAt: createdAt
            ),
            createdAt: createdAt
        )
    }

    /// Proactively renews this relationship endpoint's short-lived bootstrap
    /// key while leaving its endpoint keys and established sessions unchanged.
    @discardableResult
    public mutating func renewSignedPrekeyIfNeeded(at date: Date = Date()) throws -> Bool {
        try prekeys.rotateSignedPrekeyIfNeeded(
            endpointSigningKey: signingKey,
            now: date
        )
    }

    public static func == (
        lhs: LocalRelationshipEndpointV2,
        rhs: LocalRelationshipEndpointV2
    ) -> Bool {
        lhs.signingKey.privateKeyData == rhs.signingKey.privateKeyData
            && lhs.signingKey.publicKeyData == rhs.signingKey.publicKeyData
            && lhs.agreementKey.privateKeyData == rhs.agreementKey.privateKeyData
            && lhs.agreementKey.publicKeyData == rhs.agreementKey.publicKeyData
            && lhs.prekeys == rhs.prekeys
            && lhs.createdAt == rhs.createdAt
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case signingKey
        case agreementKey
        case prekeys
        case createdAt
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: ArchitectureV2CodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Local relationship endpoint fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        signingKey = try container.decode(SigningKeyPair.self, forKey: .signingKey)
        agreementKey = try container.decode(AgreementKeyPair.self, forKey: .agreementKey)
        prekeys = try container.decode(PrekeyState.self, forKey: .prekeys)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .signingKey,
                in: container,
                debugDescription: "Invalid local relationship endpoint state"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid local relationship endpoint state"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(signingKey, forKey: .signingKey)
        try container.encode(agreementKey, forKey: .agreementKey)
        try container.encode(prekeys, forKey: .prekeys)
        try container.encode(createdAt, forKey: .createdAt)
    }

    public var isStructurallyValid: Bool {
        SigningKeyPair.isValidPublicKey(signingKey.publicKeyData)
            && AgreementKeyPair.isValidPublicKey(agreementKey.publicKeyData)
            && prekeys.isStructurallyValid
            && createdAt.timeIntervalSince1970.isFinite
    }

    public var description: String { "LocalRelationshipEndpointV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

public enum MessageDeliveryState: String, Codable, Equatable, CaseIterable {
    case locallyPersisted
    case relayAccepted
    case peerStored
    case peerRead
}

private struct ArchitectureV2CodingKey: CodingKey {
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
