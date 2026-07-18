import CryptoKit
import Foundation

public enum RelationshipEndpointBindingError: Error, Equatable {
    case invalidStructure
    case endpointMismatch
    case invalidAuthoritySignature
    case invalidPrekeyPackageSignature
}

/// Exact cryptographic profile implemented by direct-v4. This identifier is
/// authenticated as a constant; it is never selected from peer-controlled
/// free-form input and there is no fallback profile.
public enum DirectV4CipherSuite {
    public static let identifier =
        "nw.direct-v4.ml-kem-768.ml-dsa-65.hkdf-sha256.hmac-sha256.aes-256-gcm"
}

public enum DirectV4CapabilityNegotiationError: Error, Equatable {
    case invalidManifest
    case missingRequiredModule(String)
    case noSharedVersion(String)
    case invalidNegotiatedLimit(String)
    case missingRequiredContentType(String)
    case transcriptMismatch
}

public struct DirectV4NegotiatedModule: Codable, Equatable {
    public let module: String
    public let version: UInt16
    public let limits: [String: UInt64]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case module
        case version
        case limits
    }

    public init(module: String, version: UInt16, limits: [String: UInt64]) {
        self.module = module
        self.version = version
        self.limits = limits
    }

    public init(from decoder: Decoder) throws {
        try requireExactFields(decoder, CodingKeys.self, context: "direct capability module")
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            module: try container.decode(String.self, forKey: .module),
            version: try container.decode(UInt16.self, forKey: .version),
            limits: try container.decode([String: UInt64].self, forKey: .limits)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .module,
                in: container,
                debugDescription: "Invalid direct capability module"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid direct capability module"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(module, forKey: .module)
        try container.encode(version, forKey: .version)
        try container.encode(limits, forKey: .limits)
    }

    private var isStructurallyValid: Bool {
        !module.isEmpty
            && module.hasPrefix("nw.")
            && module.utf8.count <= NoctweaveArchitectureV2.maximumModuleNameBytes
            && version > 0
            && limits.count <= 32
            && limits.keys.allSatisfy { !$0.isEmpty && $0.utf8.count <= 96 }
    }
}

/// Canonical result authenticated by every direct-v4 session and envelope.
/// The required surface is intentionally only `nw.core` plus `nw.direct`;
/// internal implementation pieces are not independently negotiable modules.
public struct DirectV4NegotiatedCapabilityManifest: Codable, Equatable {
    public static let version = 1

    public let version: Int
    public let architectureVersion: Int
    public let cipherSuite: String
    public let modules: [DirectV4NegotiatedModule]
    public let contentTypes: [ContentTypeCapabilityV2]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case architectureVersion
        case cipherSuite
        case modules
        case contentTypes
    }

    public init(
        version: Int = DirectV4NegotiatedCapabilityManifest.version,
        architectureVersion: Int = NoctweaveArchitectureV2.version,
        cipherSuite: String = DirectV4CipherSuite.identifier,
        modules: [DirectV4NegotiatedModule],
        contentTypes: [ContentTypeCapabilityV2]
    ) {
        self.version = version
        self.architectureVersion = architectureVersion
        self.cipherSuite = cipherSuite
        self.modules = modules.sorted { $0.module < $1.module }
        self.contentTypes = contentTypes.sorted {
            ($0.authority, $0.name) < ($1.authority, $1.name)
        }
    }

    public init(from decoder: Decoder) throws {
        try requireExactFields(decoder, CodingKeys.self, context: "direct capability manifest")
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedModules = try container.decode(
            [DirectV4NegotiatedModule].self,
            forKey: .modules
        )
        let decodedContentTypes = try container.decode(
            [ContentTypeCapabilityV2].self,
            forKey: .contentTypes
        )
        self.init(
            version: try container.decode(Int.self, forKey: .version),
            architectureVersion: try container.decode(Int.self, forKey: .architectureVersion),
            cipherSuite: try container.decode(String.self, forKey: .cipherSuite),
            modules: decodedModules,
            contentTypes: decodedContentTypes
        )
        guard modules == decodedModules,
              contentTypes == decodedContentTypes,
              isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .modules,
                in: container,
                debugDescription: "Invalid direct capability manifest"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid direct capability manifest"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(architectureVersion, forKey: .architectureVersion)
        try container.encode(cipherSuite, forKey: .cipherSuite)
        try container.encode(modules, forKey: .modules)
        try container.encode(contentTypes, forKey: .contentTypes)
    }

    public static func negotiate(
        local: ProtocolCapabilityManifest,
        peer: ProtocolCapabilityManifest
    ) throws -> DirectV4NegotiatedCapabilityManifest {
        guard local.isStructurallyValid, peer.isStructurallyValid else {
            throw DirectV4CapabilityNegotiationError.invalidManifest
        }
        let localModules = Dictionary(uniqueKeysWithValues: local.modules.map { ($0.module, $0) })
        let peerModules = Dictionary(uniqueKeysWithValues: peer.modules.map { ($0.module, $0) })
        let modules = try requirements.map { requirement -> DirectV4NegotiatedModule in
            guard let localModule = localModules[requirement.module],
                  let peerModule = peerModules[requirement.module] else {
                throw DirectV4CapabilityNegotiationError.missingRequiredModule(
                    requirement.module
                )
            }
            let sharedVersions = Set(localModule.versions)
                .intersection(peerModule.versions)
                .intersection(requirement.supportedVersions)
            guard let version = sharedVersions.max() else {
                throw DirectV4CapabilityNegotiationError.noSharedVersion(requirement.module)
            }
            var limits: [String: UInt64] = [:]
            for (name, profileCeiling) in requirement.limitCeilings {
                limits[name] = min(
                    profileCeiling,
                    min(
                        localModule.limits[name] ?? profileCeiling,
                        peerModule.limits[name] ?? profileCeiling
                    )
                )
            }
            for (name, minimum) in requirement.minimumLimits {
                guard let value = limits[name], value >= minimum else {
                    throw DirectV4CapabilityNegotiationError.invalidNegotiatedLimit(
                        "\(requirement.module).\(name)"
                    )
                }
            }
            return DirectV4NegotiatedModule(
                module: requirement.module,
                version: version,
                limits: limits
            )
        }
        let peerContentTypes = Dictionary(
            uniqueKeysWithValues: peer.contentTypes.map {
                ("\($0.authority)\u{0}\($0.name)", $0)
            }
        )
        let contentTypes = local.contentTypes.compactMap {
            localType -> ContentTypeCapabilityV2? in
            let key = "\(localType.authority)\u{0}\(localType.name)"
            guard let peerType = peerContentTypes[key],
                  let major = Set(localType.majorVersions)
                    .intersection(peerType.majorVersions).max() else {
                return nil
            }
            return ContentTypeCapabilityV2(
                authority: localType.authority,
                name: localType.name,
                majorVersions: [major]
            )
        }
        guard contentTypes.contains(where: {
            $0.authority == ContentTypeId.text.authority
                && $0.name == ContentTypeId.text.name
        }) else {
            throw DirectV4CapabilityNegotiationError.missingRequiredContentType(
                ContentTypeId.text.canonicalName
            )
        }
        let result = DirectV4NegotiatedCapabilityManifest(
            modules: modules,
            contentTypes: contentTypes
        )
        guard result.isStructurallyValid else {
            throw DirectV4CapabilityNegotiationError.invalidManifest
        }
        return result
    }

    public func limit(module: String, name: String) -> UInt64? {
        modules.first(where: { $0.module == module })?.limits[name]
    }

    public func digest() throws -> Data {
        guard isStructurallyValid else {
            throw DirectV4CapabilityNegotiationError.invalidManifest
        }
        return Data(SHA256.hash(data: try NoctweaveCoder.encode(self, sortedKeys: true)))
    }

    private var isStructurallyValid: Bool {
        version == Self.version
            && architectureVersion == NoctweaveArchitectureV2.version
            && cipherSuite == DirectV4CipherSuite.identifier
            && modules.count == Self.requirements.count
            && !contentTypes.isEmpty
            && contentTypes.count
                <= NoctweaveArchitectureV2.maximumContentTypeCapabilities
            && Set(contentTypes.map { "\($0.authority)\u{0}\($0.name)" }).count
                == contentTypes.count
            && contentTypes.allSatisfy(\.isStructurallyValid)
            && contentTypes.contains {
                $0.authority == ContentTypeId.text.authority
                    && $0.name == ContentTypeId.text.name
            }
            && zip(modules, Self.requirements).allSatisfy { module, requirement in
                module.module == requirement.module
                    && requirement.supportedVersions.contains(module.version)
                    && Set(module.limits.keys) == Set(requirement.limitCeilings.keys)
                    && module.limits.allSatisfy { name, value in
                        value <= (requirement.limitCeilings[name] ?? 0)
                            && value >= (requirement.minimumLimits[name] ?? 0)
                    }
            }
    }

    private struct Requirement {
        let module: String
        let supportedVersions: Set<UInt16>
        let limitCeilings: [String: UInt64]
        let minimumLimits: [String: UInt64]
    }

    private static let requirements: [Requirement] = [
        Requirement(
            module: "nw.core",
            supportedVersions: [2],
            limitCeilings: [
                "maxContentParameterBytes": UInt64(
                    NoctweaveArchitectureV2.maximumContentParameterBytes
                ),
                "maxContentParameters": UInt64(
                    NoctweaveArchitectureV2.maximumContentParameters
                ),
                "maxContentPayloadBytes": UInt64(
                    NoctweaveArchitectureV2.maximumContentPayloadBytes
                ),
                "maxFallbackBytes": UInt64(NoctweaveArchitectureV2.maximumFallbackBytes)
            ],
            minimumLimits: [
                "maxContentParameterBytes": 1,
                "maxContentParameters": 1,
                "maxContentPayloadBytes": 1
            ]
        ),
        Requirement(
            module: "nw.direct",
            supportedVersions: [4],
            limitCeilings: [
                "maxCiphertextBytes": UInt64(PaddedMessagePlaintext.maximumPaddedBytes),
                "maxPrekeyAgeSeconds": UInt64(PrekeyBundle.maximumAge)
            ],
            minimumLimits: [
                "maxCiphertextBytes": UInt64(PaddedMessagePlaintext.minimumPaddedBytes),
                "maxPrekeyAgeSeconds": 1
            ]
        )
    ]
}

/// The only public endpoint object in a pairwise relationship. A fresh
/// relationship authority binds exactly one fresh endpoint. The endpoint then
/// signs its renewable prekey package. There is no endpoint set, device list,
/// admission, revocation, generation checkpoint, or account-wide authority.
public struct RelationshipEndpointBindingV4: Codable, Equatable {
    public static let version = 4

    public let version: Int
    public let signingPublicKey: Data
    public let agreementPublicKey: Data
    public let capabilities: ProtocolCapabilityManifest
    public let prekeyBundle: PrekeyBundle
    public let prekeyPackageSignature: Data
    public let issuedAt: Date
    public let authoritySignature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case signingPublicKey
        case agreementPublicKey
        case capabilities
        case prekeyBundle
        case prekeyPackageSignature
        case issuedAt
        case authoritySignature
    }

    public init(
        version: Int = Self.version,
        signingPublicKey: Data,
        agreementPublicKey: Data,
        capabilities: ProtocolCapabilityManifest,
        prekeyBundle: PrekeyBundle,
        prekeyPackageSignature: Data,
        issuedAt: Date,
        authoritySignature: Data
    ) {
        self.version = version
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
        self.capabilities = capabilities
        self.prekeyBundle = prekeyBundle
        self.prekeyPackageSignature = prekeyPackageSignature
        self.issuedAt = issuedAt
        self.authoritySignature = authoritySignature
    }

    public init(from decoder: Decoder) throws {
        try requireExactFields(decoder, CodingKeys.self, context: "relationship endpoint binding")
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try container.decode(Int.self, forKey: .version),
            signingPublicKey: try container.decode(Data.self, forKey: .signingPublicKey),
            agreementPublicKey: try container.decode(Data.self, forKey: .agreementPublicKey),
            capabilities: try container.decode(ProtocolCapabilityManifest.self, forKey: .capabilities),
            prekeyBundle: try container.decode(PrekeyBundle.self, forKey: .prekeyBundle),
            prekeyPackageSignature: try container.decode(Data.self, forKey: .prekeyPackageSignature),
            issuedAt: try container.decode(Date.self, forKey: .issuedAt),
            authoritySignature: try container.decode(Data.self, forKey: .authoritySignature)
        )
        guard hasValidStaticStructure else {
            throw DecodingError.dataCorruptedError(
                forKey: .authoritySignature,
                in: container,
                debugDescription: "Invalid relationship endpoint binding"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard hasValidStaticStructure else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid relationship endpoint binding"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(signingPublicKey, forKey: .signingPublicKey)
        try container.encode(agreementPublicKey, forKey: .agreementPublicKey)
        try container.encode(capabilities, forKey: .capabilities)
        try container.encode(prekeyBundle, forKey: .prekeyBundle)
        try container.encode(prekeyPackageSignature, forKey: .prekeyPackageSignature)
        try container.encode(issuedAt, forKey: .issuedAt)
        try container.encode(authoritySignature, forKey: .authoritySignature)
    }

    public static func create(
        authority: RelationshipAuthorityV2,
        endpoint: LocalRelationshipEndpointV2,
        capabilities: ProtocolCapabilityManifest = ProtocolCapabilityManifest(),
        issuedAt: Date = Date()
    ) throws -> RelationshipEndpointBindingV4 {
        guard capabilities.isStructurallyValid,
              issuedAt.timeIntervalSince1970.isFinite else {
            throw RelationshipEndpointBindingError.invalidStructure
        }
        let payload = RelationshipEndpointAuthorityPayloadV4(
            version: Self.version,
            signingPublicKey: endpoint.signingKey.publicKeyData,
            agreementPublicKey: endpoint.agreementKey.publicKeyData,
            capabilities: capabilities,
            issuedAt: issuedAt
        )
        let authoritySignature = try authority.signingKey.sign(payload.signableData())
        let authorizationDigest = try authorizationDigest(
            payload: payload,
            authoritySignature: authoritySignature
        )
        let bundle = try publicPrekeyBundle(endpoint: endpoint, createdAt: issuedAt)
        let packageSignature = try endpoint.signingKey.sign(
            RelationshipEndpointPrekeyPayloadV4(
                endpointAuthorizationDigest: authorizationDigest,
                bundle: bundle
            ).signableData()
        )
        let result = RelationshipEndpointBindingV4(
            signingPublicKey: payload.signingPublicKey,
            agreementPublicKey: payload.agreementPublicKey,
            capabilities: payload.capabilities,
            prekeyBundle: bundle,
            prekeyPackageSignature: packageSignature,
            issuedAt: payload.issuedAt,
            authoritySignature: authoritySignature
        )
        guard result.hasValidStaticStructure else {
            throw RelationshipEndpointBindingError.invalidStructure
        }
        return result
    }

    /// Stable while this one relationship endpoint remains in use. Renewing
    /// the short-lived signed prekey does not change this authorization digest.
    public var authorizationDigest: Data? {
        try? Self.authorizationDigest(
            payload: authorityPayload,
            authoritySignature: authoritySignature
        )
    }

    public func referenceDigest(for relationshipID: UUID) throws -> Data {
        guard let authorizationDigest else {
            throw RelationshipEndpointBindingError.invalidStructure
        }
        var material = Data("Noctweave/relationship-endpoint-binding-reference/v4".utf8)
        material.append(0)
        material.append(Data(relationshipID.uuidString.lowercased().utf8))
        material.append(0)
        material.append(authorizationDigest)
        return Data(SHA256.hash(data: material))
    }

    public func refreshingPrekeyPackage(
        using endpoint: LocalRelationshipEndpointV2,
        at date: Date = Date()
    ) throws -> RelationshipEndpointBindingV4 {
        guard endpoint.signingKey.publicKeyData == signingPublicKey,
              endpoint.agreementKey.publicKeyData == agreementPublicKey,
              date.timeIntervalSince1970.isFinite,
              date >= issuedAt,
              let authorizationDigest else {
            throw RelationshipEndpointBindingError.endpointMismatch
        }
        let bundle = try Self.publicPrekeyBundle(endpoint: endpoint, createdAt: date)
        let packageSignature = try endpoint.signingKey.sign(
            RelationshipEndpointPrekeyPayloadV4(
                endpointAuthorizationDigest: authorizationDigest,
                bundle: bundle
            ).signableData()
        )
        let result = RelationshipEndpointBindingV4(
            signingPublicKey: signingPublicKey,
            agreementPublicKey: agreementPublicKey,
            capabilities: capabilities,
            prekeyBundle: bundle,
            prekeyPackageSignature: packageSignature,
            issuedAt: issuedAt,
            authoritySignature: authoritySignature
        )
        guard result.hasValidStaticStructure else {
            throw RelationshipEndpointBindingError.invalidStructure
        }
        return result
    }

    @discardableResult
    public func verified(
        authoritySigningPublicKey: Data,
        now: Date = Date()
    ) throws -> RelationshipEndpointBindingV4 {
        guard isStructurallyValid(now: now) else {
            throw RelationshipEndpointBindingError.invalidStructure
        }
        guard let authorityData = try? authorityPayload.signableData(),
              SigningKeyPair.verify(
                  signature: authoritySignature,
                  data: authorityData,
                  publicKeyData: authoritySigningPublicKey
              ) else {
            throw RelationshipEndpointBindingError.invalidAuthoritySignature
        }
        guard let authorizationDigest,
              let prekeyData = try? RelationshipEndpointPrekeyPayloadV4(
                  endpointAuthorizationDigest: authorizationDigest,
                  bundle: prekeyBundle
              ).signableData(),
              SigningKeyPair.verify(
                  signature: prekeyPackageSignature,
                  data: prekeyData,
                  publicKeyData: signingPublicKey
              ) else {
            throw RelationshipEndpointBindingError.invalidPrekeyPackageSignature
        }
        return self
    }

    public func isStructurallyValid(now: Date = Date()) -> Bool {
        hasValidStaticStructure
            && prekeyBundle.isStructurallyValid(now: now)
            && prekeyBundle.signedPrekey.verify(using: signingPublicKey)
            && prekeyBundle.oneTimePrekeys.isEmpty
    }

    private var hasValidStaticStructure: Bool {
        version == Self.version
            && SigningKeyPair.isValidPublicKey(signingPublicKey)
            && AgreementKeyPair.isValidPublicKey(agreementPublicKey)
            && capabilities.isStructurallyValid
            && prekeyBundle.relationshipSigningKeyDigest
                == CryptoBox.fingerprint(for: signingPublicKey)
            && prekeyBundle.oneTimePrekeys.isEmpty
            && prekeyBundle.signedPrekey.verify(using: signingPublicKey)
            && prekeyBundle.createdAt.timeIntervalSince1970.isFinite
            && issuedAt.timeIntervalSince1970.isFinite
            && prekeyBundle.createdAt >= issuedAt
            && prekeyPackageSignature.count == 3_309
            && authoritySignature.count == 3_309
            && authorizationDigest?.count == 32
    }

    private var authorityPayload: RelationshipEndpointAuthorityPayloadV4 {
        RelationshipEndpointAuthorityPayloadV4(
            version: version,
            signingPublicKey: signingPublicKey,
            agreementPublicKey: agreementPublicKey,
            capabilities: capabilities,
            issuedAt: issuedAt
        )
    }

    private static func authorizationDigest(
        payload: RelationshipEndpointAuthorityPayloadV4,
        authoritySignature: Data
    ) throws -> Data {
        Data(SHA256.hash(data: try NoctweaveCoder.encode(
            RelationshipEndpointAuthorizationReferenceV4(
                endpoint: payload,
                authoritySignature: authoritySignature
            ),
            sortedKeys: true
        )))
    }

    private static func publicPrekeyBundle(
        endpoint: LocalRelationshipEndpointV2,
        createdAt: Date
    ) throws -> PrekeyBundle {
        let endpointAuthority = try RelationshipAuthorityV2(
            relationshipPseudonym: "Noctweave relationship endpoint",
            signingKey: endpoint.signingKey,
            agreementKey: endpoint.agreementKey,
            createdAt: endpoint.createdAt
        )
        let complete = try endpoint.prekeys.bundle(
            authority: endpointAuthority,
            createdAt: createdAt
        )
        return PrekeyBundle(
            relationshipSigningKeyDigest: complete.relationshipSigningKeyDigest,
            signedPrekey: complete.signedPrekey,
            oneTimePrekeys: [],
            createdAt: complete.createdAt
        )
    }
}

public struct DirectEndpointSessionIdentity: Codable, Equatable, Hashable {
    public let relationshipID: UUID
    public let localEndpointHandle: RelationshipEndpointHandle
    public let localBindingReferenceDigest: Data
    public let peerEndpointHandle: RelationshipEndpointHandle
    public let peerBindingReferenceDigest: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case relationshipID
        case localEndpointHandle
        case localBindingReferenceDigest
        case peerEndpointHandle
        case peerBindingReferenceDigest
    }

    public init(
        relationshipID: UUID,
        localEndpointHandle: RelationshipEndpointHandle,
        localBindingReferenceDigest: Data,
        peerEndpointHandle: RelationshipEndpointHandle,
        peerBindingReferenceDigest: Data
    ) {
        self.relationshipID = relationshipID
        self.localEndpointHandle = localEndpointHandle
        self.localBindingReferenceDigest = localBindingReferenceDigest
        self.peerEndpointHandle = peerEndpointHandle
        self.peerBindingReferenceDigest = peerBindingReferenceDigest
    }

    public init(from decoder: Decoder) throws {
        try requireExactFields(decoder, CodingKeys.self, context: "direct endpoint session")
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            relationshipID: try container.decode(UUID.self, forKey: .relationshipID),
            localEndpointHandle: try container.decode(RelationshipEndpointHandle.self, forKey: .localEndpointHandle),
            localBindingReferenceDigest: try container.decode(Data.self, forKey: .localBindingReferenceDigest),
            peerEndpointHandle: try container.decode(RelationshipEndpointHandle.self, forKey: .peerEndpointHandle),
            peerBindingReferenceDigest: try container.decode(Data.self, forKey: .peerBindingReferenceDigest)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .localBindingReferenceDigest,
                in: container,
                debugDescription: "Invalid direct endpoint session"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid direct endpoint session"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(relationshipID, forKey: .relationshipID)
        try container.encode(localEndpointHandle, forKey: .localEndpointHandle)
        try container.encode(localBindingReferenceDigest, forKey: .localBindingReferenceDigest)
        try container.encode(peerEndpointHandle, forKey: .peerEndpointHandle)
        try container.encode(peerBindingReferenceDigest, forKey: .peerBindingReferenceDigest)
    }

    public var isStructurallyValid: Bool {
        localEndpointHandle.isStructurallyValid
            && peerEndpointHandle.isStructurallyValid
            && localEndpointHandle != peerEndpointHandle
            && localBindingReferenceDigest.count == 32
            && peerBindingReferenceDigest.count == 32
            && localBindingReferenceDigest != peerBindingReferenceDigest
    }
}

/// Relationship-local transcript binding for the two fresh endpoints. Binding
/// references are blinded by the relationship ID before appearing on a direct
/// envelope, so even identical bytes cannot become a cross-contact identifier.
public struct PairwiseEndpointBindingV4: Codable, Equatable {
    public let relationshipId: UUID
    public let localEndpointHandle: RelationshipEndpointHandle
    public let peerEndpointHandle: RelationshipEndpointHandle
    public let localBindingReferenceDigest: Data
    public let peerBindingReferenceDigest: Data
    public let cipherSuite: String
    public let negotiatedCapabilitiesDigest: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case relationshipId
        case localEndpointHandle
        case peerEndpointHandle
        case localBindingReferenceDigest
        case peerBindingReferenceDigest
        case cipherSuite
        case negotiatedCapabilitiesDigest
    }

    public init(
        relationshipId: UUID,
        localEndpointHandle: RelationshipEndpointHandle,
        peerEndpointHandle: RelationshipEndpointHandle,
        localBindingReferenceDigest: Data,
        peerBindingReferenceDigest: Data,
        cipherSuite: String,
        negotiatedCapabilitiesDigest: Data
    ) {
        self.relationshipId = relationshipId
        self.localEndpointHandle = localEndpointHandle
        self.peerEndpointHandle = peerEndpointHandle
        self.localBindingReferenceDigest = localBindingReferenceDigest
        self.peerBindingReferenceDigest = peerBindingReferenceDigest
        self.cipherSuite = cipherSuite
        self.negotiatedCapabilitiesDigest = negotiatedCapabilitiesDigest
    }

    public init(from decoder: Decoder) throws {
        try requireExactFields(decoder, CodingKeys.self, context: "pairwise endpoint transcript")
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            relationshipId: try container.decode(UUID.self, forKey: .relationshipId),
            localEndpointHandle: try container.decode(RelationshipEndpointHandle.self, forKey: .localEndpointHandle),
            peerEndpointHandle: try container.decode(RelationshipEndpointHandle.self, forKey: .peerEndpointHandle),
            localBindingReferenceDigest: try container.decode(Data.self, forKey: .localBindingReferenceDigest),
            peerBindingReferenceDigest: try container.decode(Data.self, forKey: .peerBindingReferenceDigest),
            cipherSuite: try container.decode(String.self, forKey: .cipherSuite),
            negotiatedCapabilitiesDigest: try container.decode(Data.self, forKey: .negotiatedCapabilitiesDigest)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .localBindingReferenceDigest,
                in: container,
                debugDescription: "Invalid pairwise endpoint transcript"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid pairwise endpoint transcript"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(relationshipId, forKey: .relationshipId)
        try container.encode(localEndpointHandle, forKey: .localEndpointHandle)
        try container.encode(peerEndpointHandle, forKey: .peerEndpointHandle)
        try container.encode(localBindingReferenceDigest, forKey: .localBindingReferenceDigest)
        try container.encode(peerBindingReferenceDigest, forKey: .peerBindingReferenceDigest)
        try container.encode(cipherSuite, forKey: .cipherSuite)
        try container.encode(negotiatedCapabilitiesDigest, forKey: .negotiatedCapabilitiesDigest)
    }

    public static func create(
        relationshipId: UUID,
        localEndpointHandle: RelationshipEndpointHandle,
        peerEndpointHandle: RelationshipEndpointHandle,
        localEndpoint: RelationshipEndpointBindingV4,
        peerEndpoint: RelationshipEndpointBindingV4
    ) throws -> PairwiseEndpointBindingV4 {
        let negotiation = try DirectV4NegotiatedCapabilityManifest.negotiate(
            local: localEndpoint.capabilities,
            peer: peerEndpoint.capabilities
        )
        return PairwiseEndpointBindingV4(
            relationshipId: relationshipId,
            localEndpointHandle: localEndpointHandle,
            peerEndpointHandle: peerEndpointHandle,
            localBindingReferenceDigest: try localEndpoint.referenceDigest(for: relationshipId),
            peerBindingReferenceDigest: try peerEndpoint.referenceDigest(for: relationshipId),
            cipherSuite: negotiation.cipherSuite,
            negotiatedCapabilitiesDigest: try negotiation.digest()
        )
    }

    public var isStructurallyValid: Bool {
        localEndpointHandle.isStructurallyValid
            && peerEndpointHandle.isStructurallyValid
            && localEndpointHandle != peerEndpointHandle
            && localBindingReferenceDigest.count == 32
            && peerBindingReferenceDigest.count == 32
            && localBindingReferenceDigest != peerBindingReferenceDigest
            && cipherSuite == DirectV4CipherSuite.identifier
            && negotiatedCapabilitiesDigest.count == 32
    }

    public func validatedNegotiation(
        localEndpoint: RelationshipEndpointBindingV4,
        peerEndpoint: RelationshipEndpointBindingV4
    ) throws -> DirectV4NegotiatedCapabilityManifest {
        let negotiation = try DirectV4NegotiatedCapabilityManifest.negotiate(
            local: localEndpoint.capabilities,
            peer: peerEndpoint.capabilities
        )
        let localReference = try localEndpoint.referenceDigest(for: relationshipId)
        let peerReference = try peerEndpoint.referenceDigest(for: relationshipId)
        let negotiationDigest = try negotiation.digest()
        guard localBindingReferenceDigest == localReference,
              peerBindingReferenceDigest == peerReference,
              cipherSuite == negotiation.cipherSuite,
              negotiatedCapabilitiesDigest == negotiationDigest else {
            throw DirectV4CapabilityNegotiationError.transcriptMismatch
        }
        return negotiation
    }
}

private struct RelationshipEndpointAuthorityPayloadV4: Codable {
    let version: Int
    let signingPublicKey: Data
    let agreementPublicKey: Data
    let capabilities: ProtocolCapabilityManifest
    let issuedAt: Date

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

private struct RelationshipEndpointAuthorizationReferenceV4: Codable {
    let endpoint: RelationshipEndpointAuthorityPayloadV4
    let authoritySignature: Data
}

private struct RelationshipEndpointPrekeyPayloadV4: Codable {
    let purpose = "Noctweave/relationship-endpoint-prekey-package/v4"
    let endpointAuthorizationDigest: Data
    let bundle: PrekeyBundle

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

private struct RelationshipEndpointCodingKey: CodingKey {
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

private func requireExactFields<Keys: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _: Keys.Type,
    context: String
) throws where Keys.AllCases: Collection {
    let strict = try decoder.container(keyedBy: RelationshipEndpointCodingKey.self)
    let expected = Set(Keys.allCases.map(\.stringValue))
    guard Set(strict.allKeys.map(\.stringValue)) == expected else {
        throw DecodingError.dataCorrupted(
            DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: "Fields must match the current \(context) schema exactly"
            )
        )
    }
}
