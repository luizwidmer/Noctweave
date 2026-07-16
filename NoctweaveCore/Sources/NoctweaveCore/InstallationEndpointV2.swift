import CryptoKit
import Foundation

public enum CertifiedInstallationEndpointError: Error, Equatable {
    case invalidStructure
    case invalidManifest
    case installationNotAuthorized
    case invalidAuthoritySignature
    case invalidPossessionSignature
    case invalidPrekeyPackageSignature
}

/// Exact cryptographic profile implemented by direct-v4. This identifier is
/// authenticated as a constant; it is never selected from peer-controlled
/// free-form input and there is no legacy fallback.
public enum DirectV4CipherSuite {
    public static let identifier =
        "nw.direct-v4.ml-kem-768.ml-dsa-65.hkdf-sha256.hmac-sha256.aes-256-gcm"
}

public enum DirectV4CapabilityNegotiationError: Error, Equatable {
    case invalidManifest
    case missingRequiredModule(String)
    case noSharedVersion(String)
    case invalidNegotiatedLimit(String)
    case transcriptMismatch
}

public struct DirectV4NegotiatedModule: Codable, Equatable {
    public let module: String
    public let version: UInt16
    public let limits: [String: UInt64]

    public init(module: String, version: UInt16, limits: [String: UInt64]) {
        self.module = module
        self.version = version
        self.limits = limits
    }
}

/// Canonical, endpoint-to-endpoint result used as direct-v4 transcript input.
/// Only direct-message semantics are included; optional modules and extension
/// status labels cannot create asymmetric results or leak endpoint graphs.
public struct DirectV4NegotiatedCapabilityManifest: Codable, Equatable {
    public static let version = 1

    public let version: Int
    public let architectureVersion: Int
    public let cipherSuite: String
    public let modules: [DirectV4NegotiatedModule]

    public init(
        version: Int = DirectV4NegotiatedCapabilityManifest.version,
        architectureVersion: Int = NoctweaveArchitectureV2.version,
        cipherSuite: String = DirectV4CipherSuite.identifier,
        modules: [DirectV4NegotiatedModule]
    ) {
        self.version = version
        self.architectureVersion = architectureVersion
        self.cipherSuite = cipherSuite
        self.modules = modules.sorted { $0.module < $1.module }
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
                throw DirectV4CapabilityNegotiationError.noSharedVersion(
                    requirement.module
                )
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
        return DirectV4NegotiatedCapabilityManifest(modules: modules)
    }

    public func limit(module: String, name: String) -> UInt64? {
        modules.first(where: { $0.module == module })?.limits[name]
    }

    public func digest() throws -> Data {
        guard version == Self.version,
              architectureVersion == NoctweaveArchitectureV2.version,
              cipherSuite == DirectV4CipherSuite.identifier,
              !modules.contains(where: {
                  $0.module == RelayCompatibilityProfile.legacyFingerprint
              }),
              modules.map(\.module) == Self.requirements.map(\.module) else {
            throw DirectV4CapabilityNegotiationError.invalidManifest
        }
        return Data(SHA256.hash(data: try NoctweaveCoder.encode(self, sortedKeys: true)))
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
                "maxCiphertextBytes": UInt64(PaddedMessagePlaintext.maximumPaddedBytes)
            ],
            minimumLimits: [
                "maxCiphertextBytes": UInt64(PaddedMessagePlaintext.minimumPaddedBytes)
            ]
        ),
        Requirement(
            module: "nw.endpoints",
            supportedVersions: [2],
            // Direct-v4 currently sends to one certified preferred endpoint.
            // The 16-entry installation-manifest bound is only a structural
            // storage ceiling, not negotiated multi-endpoint delivery support.
            limitCeilings: ["maxActiveEndpoints": 1],
            minimumLimits: ["maxActiveEndpoints": 1]
        ),
        Requirement(
            module: "nw.events",
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
                "maxFallbackBytes": UInt64(
                    NoctweaveArchitectureV2.maximumFallbackBytes
                )
            ],
            minimumLimits: [
                "maxContentParameterBytes": 1,
                "maxContentParameters": 1,
                "maxContentPayloadBytes": 1
            ]
        ),
        Requirement(
            module: "nw.prekeys",
            supportedVersions: [2],
            limitCeilings: [
                "maxPrekeyAgeSeconds": UInt64(PrekeyBundle.maximumAge)
            ],
            minimumLimits: ["maxPrekeyAgeSeconds": 1]
        )
    ]
}

public struct InstallationManifestCheckpointV4: Codable, Equatable {
    public let version: Int
    public let identityGenerationId: UUID
    public let identityFingerprint: String
    public let epoch: UInt64
    public let manifestDigest: Data
    public let issuedAt: Date
    public let signature: Data

    public static func create(
        manifest: InstallationManifest,
        identity: Identity
    ) throws -> InstallationManifestCheckpointV4 {
        guard manifest.verify(identityPublicKey: identity.signingKey.publicKeyData),
              let digest = manifest.digest else {
            throw CertifiedInstallationEndpointError.invalidManifest
        }
        let payload = InstallationManifestCheckpointPayloadV4(
            version: CertifiedInstallationEndpoint.version,
            identityGenerationId: manifest.identityGenerationId,
            identityFingerprint: identity.fingerprint,
            epoch: manifest.epoch,
            manifestDigest: digest,
            issuedAt: manifest.issuedAt
        )
        return InstallationManifestCheckpointV4(
            version: payload.version,
            identityGenerationId: payload.identityGenerationId,
            identityFingerprint: payload.identityFingerprint,
            epoch: payload.epoch,
            manifestDigest: payload.manifestDigest,
            issuedAt: payload.issuedAt,
            signature: try identity.signingKey.sign(payload.signableData())
        )
    }

    public func verify(identityPublicKey: Data) -> Bool {
        guard version == CertifiedInstallationEndpoint.version,
              identityFingerprint == CryptoBox.fingerprint(for: identityPublicKey),
              manifestDigest.count == 32,
              issuedAt.timeIntervalSince1970.isFinite,
              signature.count == 3_309,
              let data = try? payload.signableData() else {
            return false
        }
        return SigningKeyPair.verify(
            signature: signature,
            data: data,
            publicKeyData: identityPublicKey
        )
    }

    private var payload: InstallationManifestCheckpointPayloadV4 {
        InstallationManifestCheckpointPayloadV4(
            version: version,
            identityGenerationId: identityGenerationId,
            identityFingerprint: identityFingerprint,
            epoch: epoch,
            manifestDigest: manifestDigest,
            issuedAt: issuedAt
        )
    }
}

/// Compact encrypted-control payload used to invalidate a previously learned
/// preferred endpoint without publishing the full endpoint-set graph. This is
/// a peer invalidation record, not proof that local route, self-sync, group,
/// and retained-key teardown obligations have completed.
public struct InstallationEndpointRevocationV4: Codable, Equatable {
    public let identityGenerationId: UUID
    public let installationId: UUID
    public let certificateDigest: Data
    public let manifestEpoch: UInt64
    public let manifestDigest: Data
    public let issuedAt: Date
    public let signature: Data

    public static func create(
        endpoint: CertifiedInstallationEndpoint,
        revokedManifest: InstallationManifest,
        identity: Identity
    ) throws -> InstallationEndpointRevocationV4 {
        guard revokedManifest.verify(identityPublicKey: identity.signingKey.publicKeyData),
              revokedManifest.identityGenerationId == endpoint.identityGenerationId,
              revokedManifest.epoch > endpoint.manifestEpoch,
              let record = revokedManifest.installations.first(where: {
                  $0.id == endpoint.installationId
              }),
              record.revokedEpoch != nil,
              let certificateDigest = endpoint.authorizationDigest,
              let manifestDigest = revokedManifest.digest else {
            throw CertifiedInstallationEndpointError.invalidManifest
        }
        let payload = InstallationEndpointRevocationPayloadV4(
            identityGenerationId: endpoint.identityGenerationId,
            installationId: endpoint.installationId,
            certificateDigest: certificateDigest,
            manifestEpoch: revokedManifest.epoch,
            manifestDigest: manifestDigest,
            issuedAt: revokedManifest.issuedAt
        )
        return InstallationEndpointRevocationV4(
            identityGenerationId: payload.identityGenerationId,
            installationId: payload.installationId,
            certificateDigest: payload.certificateDigest,
            manifestEpoch: payload.manifestEpoch,
            manifestDigest: payload.manifestDigest,
            issuedAt: payload.issuedAt,
            signature: try identity.signingKey.sign(payload.signableData())
        )
    }

    public func verify(
        endpoint: CertifiedInstallationEndpoint,
        identityPublicKey: Data
    ) -> Bool {
        guard endpoint.identityGenerationId == identityGenerationId,
              endpoint.installationId == installationId,
              endpoint.authorizationDigest == certificateDigest,
              manifestEpoch > endpoint.manifestEpoch,
              manifestDigest.count == 32,
              issuedAt >= endpoint.issuedAt,
              signature.count == 3_309,
              let data = try? payload.signableData() else {
            return false
        }
        return SigningKeyPair.verify(
            signature: signature,
            data: data,
            publicKeyData: identityPublicKey
        )
    }

    private var payload: InstallationEndpointRevocationPayloadV4 {
        InstallationEndpointRevocationPayloadV4(
            identityGenerationId: identityGenerationId,
            installationId: installationId,
            certificateDigest: certificateDigest,
            manifestEpoch: manifestEpoch,
            manifestDigest: manifestDigest,
            issuedAt: issuedAt
        )
    }
}

/// The short-lived, endpoint-authorized part of a certified endpoint. It is
/// bound to the stable generation-scoped authorization digest but can be
/// replaced by the endpoint without changing manifest membership or invoking
/// any recovery/account authority.
public struct EndpointSignedPrekeyPackageV4: Codable, Equatable {
    public let endpointAuthorizationDigest: Data
    public let bundle: PrekeyBundle
    public let signature: Data

    public init(
        endpointAuthorizationDigest: Data,
        bundle: PrekeyBundle,
        signature: Data
    ) {
        self.endpointAuthorizationDigest = endpointAuthorizationDigest
        self.bundle = bundle
        self.signature = signature
    }

    public static func create(
        endpointAuthorizationDigest: Data,
        bundle: PrekeyBundle,
        endpointSigningKey: SigningKeyPair
    ) throws -> EndpointSignedPrekeyPackageV4 {
        guard endpointAuthorizationDigest.count == 32,
              bundle.isStructurallyValid(now: bundle.createdAt),
              bundle.identityFingerprint == CryptoBox.fingerprint(
                  for: endpointSigningKey.publicKeyData
              ),
              bundle.signedPrekey.verify(using: endpointSigningKey.publicKeyData),
              bundle.oneTimePrekeys.allSatisfy({
                  $0.verify(using: endpointSigningKey.publicKeyData)
              }) else {
            throw CertifiedInstallationEndpointError.invalidStructure
        }
        let unsigned = EndpointSignedPrekeyPackagePayloadV4(
            endpointAuthorizationDigest: endpointAuthorizationDigest,
            bundle: bundle
        )
        return EndpointSignedPrekeyPackageV4(
            endpointAuthorizationDigest: endpointAuthorizationDigest,
            bundle: bundle,
            signature: try endpointSigningKey.sign(unsigned.signableData())
        )
    }

    public func verify(
        endpointSigningPublicKey: Data,
        expectedAuthorizationDigest: Data,
        now: Date = Date()
    ) -> Bool {
        guard endpointAuthorizationDigest == expectedAuthorizationDigest,
              endpointAuthorizationDigest.count == 32,
              bundle.isStructurallyValid(now: now),
              bundle.identityFingerprint == CryptoBox.fingerprint(
                  for: endpointSigningPublicKey
              ),
              bundle.signedPrekey.verify(using: endpointSigningPublicKey),
              bundle.oneTimePrekeys.allSatisfy({
                  $0.verify(using: endpointSigningPublicKey)
              }),
              signature.count == 3_309,
              let data = try? payload.signableData() else {
            return false
        }
        return SigningKeyPair.verify(
            signature: signature,
            data: data,
            publicKeyData: endpointSigningPublicKey
        )
    }

    private var payload: EndpointSignedPrekeyPackagePayloadV4 {
        EndpointSignedPrekeyPackagePayloadV4(
            endpointAuthorizationDigest: endpointAuthorizationDigest,
            bundle: bundle
        )
    }
}

/// Compatibility-named generation-scoped endpoint authorization projected into
/// pairwise handles and relationship-blinded references before direct use. The
/// disposable identity-generation key authorizes one endpoint and that
/// endpoint's local key proves possession; neither is a durable device,
/// account, recovery authority, or global endpoint registry. Contact offers
/// carry a compact signed generation checkpoint.
public struct CertifiedInstallationEndpoint: Codable, Equatable {
    public static let version = 4

    public let identityGenerationId: UUID
    public let identityAuthorityPublicKey: Data
    public let manifestEpoch: UInt64
    public let manifestDigest: Data
    public let installationId: UUID
    public let signingPublicKey: Data
    public let agreementPublicKey: Data
    public let capabilities: ProtocolCapabilityManifest
    public let prekeyBundle: PrekeyBundle
    public let prekeyPackageSignature: Data
    public let issuedAt: Date
    public let authoritySignature: Data
    public let possessionSignature: Data

    public init(
        identityGenerationId: UUID,
        identityAuthorityPublicKey: Data,
        manifestEpoch: UInt64,
        manifestDigest: Data,
        installationId: UUID,
        signingPublicKey: Data,
        agreementPublicKey: Data,
        capabilities: ProtocolCapabilityManifest,
        prekeyBundle: PrekeyBundle,
        prekeyPackageSignature: Data = Data(),
        issuedAt: Date,
        authoritySignature: Data,
        possessionSignature: Data
    ) {
        self.identityGenerationId = identityGenerationId
        self.identityAuthorityPublicKey = identityAuthorityPublicKey
        self.manifestEpoch = manifestEpoch
        self.manifestDigest = manifestDigest
        self.installationId = installationId
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
        self.capabilities = capabilities
        self.prekeyBundle = prekeyBundle
        self.prekeyPackageSignature = prekeyPackageSignature
        self.issuedAt = issuedAt
        self.authoritySignature = authoritySignature
        self.possessionSignature = possessionSignature
    }

    public static func create(
        identity: Identity,
        installation: LocalInstallationState,
        manifest: InstallationManifest,
        issuedAt: Date = Date()
    ) throws -> CertifiedInstallationEndpoint {
        guard let manifestDigest = manifest.digest,
              manifest.verify(identityPublicKey: identity.signingKey.publicKeyData),
              manifest.identityGenerationId == installation.identityGenerationId,
              let record = manifest.activeInstallations.first(where: { $0.id == installation.id }),
              record.signingPublicKey == installation.signingKey.publicKeyData,
              record.agreementPublicKey == installation.agreementKey.publicKeyData else {
            throw CertifiedInstallationEndpointError.installationNotAuthorized
        }
        let installationIdentity = try Identity(
            displayName: "Noctweave installation",
            signingKey: installation.signingKey,
            agreementKey: installation.agreementKey,
            createdAt: installation.createdAt
        )
        let completeBundle = try installation.prekeys.bundle(identity: installationIdentity)
        // Reusable contact offers advertise only the rotation-friendly signed
        // prekey. One-time prekeys require an atomic relay claim API and must
        // not be copied into a shareable code where multiple peers can race.
        let prekeyBundle = PrekeyBundle(
            identityFingerprint: completeBundle.identityFingerprint,
            signedPrekey: completeBundle.signedPrekey,
            oneTimePrekeys: [],
            createdAt: completeBundle.createdAt
        )
        let payload = CertifiedInstallationEndpointPayload(
            version: version,
            identityGenerationId: installation.identityGenerationId,
            identityAuthorityPublicKey: identity.signingKey.publicKeyData,
            manifestEpoch: manifest.epoch,
            manifestDigest: manifestDigest,
            installationId: installation.id,
            signingPublicKey: installation.signingKey.publicKeyData,
            agreementPublicKey: installation.agreementKey.publicKeyData,
            capabilities: record.capabilities,
            issuedAt: issuedAt
        )
        let authoritySignature = try identity.signingKey.sign(payload.signableData())
        let possessionPayload = CertifiedInstallationEndpointPossessionPayload(
            endpoint: payload,
            authoritySignature: authoritySignature
        )
        let possessionSignature = try installation.signingKey.sign(
            possessionPayload.signableData()
        )
        guard let authorizationDigest = authorizationDigest(
            payload: payload,
            authoritySignature: authoritySignature,
            possessionSignature: possessionSignature
        ) else {
            throw CertifiedInstallationEndpointError.invalidStructure
        }
        let signedPackage = try EndpointSignedPrekeyPackageV4.create(
            endpointAuthorizationDigest: authorizationDigest,
            bundle: prekeyBundle,
            endpointSigningKey: installation.signingKey
        )
        return CertifiedInstallationEndpoint(
            identityGenerationId: installation.identityGenerationId,
            identityAuthorityPublicKey: identity.signingKey.publicKeyData,
            manifestEpoch: manifest.epoch,
            manifestDigest: manifestDigest,
            installationId: installation.id,
            signingPublicKey: installation.signingKey.publicKeyData,
            agreementPublicKey: installation.agreementKey.publicKeyData,
            capabilities: record.capabilities,
            prekeyBundle: prekeyBundle,
            prekeyPackageSignature: signedPackage.signature,
            issuedAt: issuedAt,
            authoritySignature: authoritySignature,
            possessionSignature: possessionSignature
        )
    }

    public var digest: Data? {
        guard let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else { return nil }
        return Data(SHA256.hash(data: encoded))
    }

    /// Stable for the lifetime of one manifest-authorized endpoint. Prekey
    /// renewal does not change this digest, pairwise handles, or established
    /// session identity.
    public var authorizationDigest: Data? {
        Self.authorizationDigest(
            payload: payload,
            authoritySignature: authoritySignature,
            possessionSignature: possessionSignature
        )
    }

    public var endpointSignedPrekeyPackage: EndpointSignedPrekeyPackageV4? {
        guard let authorizationDigest else { return nil }
        return EndpointSignedPrekeyPackageV4(
            endpointAuthorizationDigest: authorizationDigest,
            bundle: prekeyBundle,
            signature: prekeyPackageSignature
        )
    }

    public func hasValidAuthorizationSignatures(identityPublicKey: Data) -> Bool {
        guard identityAuthorityPublicKey == identityPublicKey,
              let authorityData = try? payload.signableData(),
              SigningKeyPair.verify(
                  signature: authoritySignature,
                  data: authorityData,
                  publicKeyData: identityPublicKey
              ) else {
            return false
        }
        let possession = CertifiedInstallationEndpointPossessionPayload(
            endpoint: payload,
            authoritySignature: authoritySignature
        )
        guard let possessionData = try? possession.signableData() else { return false }
        return SigningKeyPair.verify(
            signature: possessionSignature,
            data: possessionData,
            publicKeyData: signingPublicKey
        )
    }

    /// Replaces only the endpoint-signed prekey package. Stable generation
    /// authorization and endpoint-possession proofs are preserved verbatim.
    public func refreshingPrekeyPackage(
        using installation: LocalInstallationState,
        at date: Date = Date()
    ) throws -> CertifiedInstallationEndpoint {
        guard installation.id == installationId,
              installation.identityGenerationId == identityGenerationId,
              installation.signingKey.publicKeyData == signingPublicKey,
              installation.agreementKey.publicKeyData == agreementPublicKey,
              let authorizationDigest else {
            throw CertifiedInstallationEndpointError.installationNotAuthorized
        }
        let endpointIdentity = try Identity(
            displayName: "Noctweave endpoint",
            signingKey: installation.signingKey,
            agreementKey: installation.agreementKey,
            createdAt: installation.createdAt
        )
        let completeBundle = try installation.prekeys.bundle(
            identity: endpointIdentity,
            createdAt: date
        )
        let bundle = PrekeyBundle(
            identityFingerprint: completeBundle.identityFingerprint,
            signedPrekey: completeBundle.signedPrekey,
            oneTimePrekeys: [],
            createdAt: completeBundle.createdAt
        )
        let package = try EndpointSignedPrekeyPackageV4.create(
            endpointAuthorizationDigest: authorizationDigest,
            bundle: bundle,
            endpointSigningKey: installation.signingKey
        )
        return CertifiedInstallationEndpoint(
            identityGenerationId: identityGenerationId,
            identityAuthorityPublicKey: identityAuthorityPublicKey,
            manifestEpoch: manifestEpoch,
            manifestDigest: manifestDigest,
            installationId: installationId,
            signingPublicKey: signingPublicKey,
            agreementPublicKey: agreementPublicKey,
            capabilities: capabilities,
            prekeyBundle: bundle,
            prekeyPackageSignature: package.signature,
            issuedAt: issuedAt,
            authoritySignature: authoritySignature,
            possessionSignature: possessionSignature
        )
    }

    public var signingFingerprint: String {
        CryptoBox.fingerprint(for: signingPublicKey)
    }

    public func verified(
        identityPublicKey: Data,
        manifest: InstallationManifest,
        now: Date = Date()
    ) throws -> CertifiedInstallationEndpoint {
        guard isStructurallyValid(now: now) else {
            throw CertifiedInstallationEndpointError.invalidStructure
        }
        guard manifest.verify(identityPublicKey: identityPublicKey),
              identityAuthorityPublicKey == identityPublicKey,
              manifest.identityGenerationId == identityGenerationId,
              manifest.epoch == manifestEpoch,
              manifest.digest == manifestDigest else {
            throw CertifiedInstallationEndpointError.invalidManifest
        }
        guard let record = manifest.activeInstallations.first(where: { $0.id == installationId }),
              record.signingPublicKey == signingPublicKey,
              record.agreementPublicKey == agreementPublicKey,
              record.capabilities == capabilities else {
            throw CertifiedInstallationEndpointError.installationNotAuthorized
        }
        guard let authorityData = try? payload.signableData(),
              SigningKeyPair.verify(
                  signature: authoritySignature,
                  data: authorityData,
                  publicKeyData: identityPublicKey
              ) else {
            throw CertifiedInstallationEndpointError.invalidAuthoritySignature
        }
        let possession = CertifiedInstallationEndpointPossessionPayload(
            endpoint: payload,
            authoritySignature: authoritySignature
        )
        guard let possessionData = try? possession.signableData(),
              SigningKeyPair.verify(
                  signature: possessionSignature,
                  data: possessionData,
                  publicKeyData: signingPublicKey
              ) else {
            throw CertifiedInstallationEndpointError.invalidPossessionSignature
        }
        return self
    }

    public func verified(
        identityPublicKey: Data,
        checkpoint: InstallationManifestCheckpointV4,
        now: Date = Date()
    ) throws -> CertifiedInstallationEndpoint {
        guard isStructurallyValid(now: now) else {
            throw CertifiedInstallationEndpointError.invalidStructure
        }
        guard identityAuthorityPublicKey == identityPublicKey,
              checkpoint.verify(identityPublicKey: identityPublicKey),
              checkpoint.identityGenerationId == identityGenerationId,
              checkpoint.epoch == manifestEpoch,
              checkpoint.manifestDigest == manifestDigest else {
            throw CertifiedInstallationEndpointError.invalidManifest
        }
        guard let authorityData = try? payload.signableData(),
              SigningKeyPair.verify(
                  signature: authoritySignature,
                  data: authorityData,
                  publicKeyData: identityPublicKey
              ) else {
            throw CertifiedInstallationEndpointError.invalidAuthoritySignature
        }
        let possession = CertifiedInstallationEndpointPossessionPayload(
            endpoint: payload,
            authoritySignature: authoritySignature
        )
        guard let possessionData = try? possession.signableData(),
              SigningKeyPair.verify(
                  signature: possessionSignature,
                  data: possessionData,
                  publicKeyData: signingPublicKey
              ) else {
            throw CertifiedInstallationEndpointError.invalidPossessionSignature
        }
        return self
    }

    public func isStructurallyValid(now: Date = Date()) -> Bool {
        guard let authorizationDigest,
              manifestDigest.count == 32,
              SigningKeyPair.isValidPublicKey(identityAuthorityPublicKey),
              SigningKeyPair.isValidPublicKey(signingPublicKey),
              AgreementKeyPair.isValidPublicKey(agreementPublicKey),
              capabilities.isStructurallyValid,
              endpointSignedPrekeyPackage?.verify(
                  endpointSigningPublicKey: signingPublicKey,
                  expectedAuthorizationDigest: authorizationDigest,
                  now: now
              ) == true,
              issuedAt.timeIntervalSince1970.isFinite,
              authoritySignature.count == 3_309,
              possessionSignature.count == 3_309 else {
            return false
        }
        return true
    }

    private var payload: CertifiedInstallationEndpointPayload {
        CertifiedInstallationEndpointPayload(
            version: Self.version,
            identityGenerationId: identityGenerationId,
            identityAuthorityPublicKey: identityAuthorityPublicKey,
            manifestEpoch: manifestEpoch,
            manifestDigest: manifestDigest,
            installationId: installationId,
            signingPublicKey: signingPublicKey,
            agreementPublicKey: agreementPublicKey,
            capabilities: capabilities,
            issuedAt: issuedAt
        )
    }

    private static func authorizationDigest(
        payload: CertifiedInstallationEndpointPayload,
        authoritySignature: Data,
        possessionSignature: Data
    ) -> Data? {
        let reference = CertifiedInstallationEndpointAuthorizationReference(
            endpoint: payload,
            authoritySignature: authoritySignature,
            possessionSignature: possessionSignature
        )
        guard let encoded = try? NoctweaveCoder.encode(reference, sortedKeys: true) else {
            return nil
        }
        return Data(SHA256.hash(data: encoded))
    }
}

public struct DirectEndpointSessionIdentity: Codable, Equatable, Hashable {
    public let contactId: UUID
    public let localInstallationId: UUID
    public let localInstallationHandle: RelationshipInstallationHandle
    public let localCertificateReferenceDigest: Data
    public let localManifestEpoch: UInt64
    public let peerInstallationId: UUID
    public let peerInstallationHandle: RelationshipInstallationHandle
    public let peerCertificateReferenceDigest: Data
    public let peerManifestEpoch: UInt64

    public init(
        contactId: UUID,
        localInstallationId: UUID,
        localInstallationHandle: RelationshipInstallationHandle,
        localCertificateReferenceDigest: Data,
        localManifestEpoch: UInt64,
        peerInstallationId: UUID,
        peerInstallationHandle: RelationshipInstallationHandle,
        peerCertificateReferenceDigest: Data,
        peerManifestEpoch: UInt64
    ) {
        self.contactId = contactId
        self.localInstallationId = localInstallationId
        self.localInstallationHandle = localInstallationHandle
        self.localCertificateReferenceDigest = localCertificateReferenceDigest
        self.localManifestEpoch = localManifestEpoch
        self.peerInstallationId = peerInstallationId
        self.peerInstallationHandle = peerInstallationHandle
        self.peerCertificateReferenceDigest = peerCertificateReferenceDigest
        self.peerManifestEpoch = peerManifestEpoch
    }

    public var isStructurallyValid: Bool {
        localInstallationHandle.isStructurallyValid
            && peerInstallationHandle.isStructurallyValid
            && localCertificateReferenceDigest.count == 32
            && peerCertificateReferenceDigest.count == 32
    }
}

/// Deterministic pairwise projection of two identity generations. The full
/// endpoint certificate never appears on the relay-visible direct wire;
/// its stable authorization digest is domain-separated by this relationship
/// before use as a certificate reference. Short-lived prekey renewal does not
/// change that reference. One bounded generation gets stable sessions, while
/// the same endpoint has unlinkable handles per contact and burn changes all
/// generation-derived values.
public struct PairwiseInstallationBindingV4: Codable, Equatable {
    public let relationshipId: UUID
    public let localInstallationHandle: RelationshipInstallationHandle
    public let peerInstallationHandle: RelationshipInstallationHandle
    public let localCertificateReferenceDigest: Data
    public let peerCertificateReferenceDigest: Data
    public let cipherSuite: String
    public let negotiatedCapabilitiesDigest: Data

    public init(
        relationshipId: UUID,
        localInstallationHandle: RelationshipInstallationHandle,
        peerInstallationHandle: RelationshipInstallationHandle,
        localCertificateReferenceDigest: Data,
        peerCertificateReferenceDigest: Data,
        cipherSuite: String,
        negotiatedCapabilitiesDigest: Data
    ) {
        self.relationshipId = relationshipId
        self.localInstallationHandle = localInstallationHandle
        self.peerInstallationHandle = peerInstallationHandle
        self.localCertificateReferenceDigest = localCertificateReferenceDigest
        self.peerCertificateReferenceDigest = peerCertificateReferenceDigest
        self.cipherSuite = cipherSuite
        self.negotiatedCapabilitiesDigest = negotiatedCapabilitiesDigest
    }

    public static func derive(
        localIdentityGenerationId: UUID,
        localIdentitySigningPublicKey: Data,
        localEndpoint: CertifiedInstallationEndpoint,
        peerIdentityGenerationId: UUID,
        peerIdentitySigningPublicKey: Data,
        peerEndpoint: CertifiedInstallationEndpoint
    ) throws -> PairwiseInstallationBindingV4 {
        guard localEndpoint.identityGenerationId == localIdentityGenerationId,
              peerEndpoint.identityGenerationId == peerIdentityGenerationId,
              SigningKeyPair.isValidPublicKey(localIdentitySigningPublicKey),
              SigningKeyPair.isValidPublicKey(peerIdentitySigningPublicKey),
              let localDigest = localEndpoint.authorizationDigest,
              let peerDigest = peerEndpoint.authorizationDigest else {
            throw CryptoError.invalidPayload
        }
        let negotiation = try DirectV4NegotiatedCapabilityManifest.negotiate(
            local: localEndpoint.capabilities,
            peer: peerEndpoint.capabilities
        )
        let negotiationDigest = try negotiation.digest()
        let localIdentity = identityDescriptor(
            generationId: localIdentityGenerationId
        )
        let peerIdentity = identityDescriptor(
            generationId: peerIdentityGenerationId
        )
        let ordered = [localIdentity, peerIdentity].sorted { $0.lexicographicallyPrecedes($1) }
        var relationshipMaterial = Data("Noctweave/pairwise-relationship/v4".utf8)
        relationshipMaterial.append(ordered[0])
        relationshipMaterial.append(ordered[1])
        let relationshipDigest = Array(SHA256.hash(data: relationshipMaterial))
        let relationshipId = UUID(uuid: (
            relationshipDigest[0], relationshipDigest[1], relationshipDigest[2], relationshipDigest[3],
            relationshipDigest[4], relationshipDigest[5], relationshipDigest[6], relationshipDigest[7],
            relationshipDigest[8], relationshipDigest[9], relationshipDigest[10], relationshipDigest[11],
            relationshipDigest[12], relationshipDigest[13], relationshipDigest[14], relationshipDigest[15]
        ))
        return PairwiseInstallationBindingV4(
            relationshipId: relationshipId,
            localInstallationHandle: installationHandle(
                relationshipId: relationshipId,
                generationId: localIdentityGenerationId,
                endpoint: localEndpoint
            ),
            peerInstallationHandle: installationHandle(
                relationshipId: relationshipId,
                generationId: peerIdentityGenerationId,
                endpoint: peerEndpoint
            ),
            localCertificateReferenceDigest: certificateReference(
                relationshipId: relationshipId,
                certificateDigest: localDigest
            ),
            peerCertificateReferenceDigest: certificateReference(
                relationshipId: relationshipId,
                certificateDigest: peerDigest
            ),
            cipherSuite: negotiation.cipherSuite,
            negotiatedCapabilitiesDigest: negotiationDigest
        )
    }

    public var isStructurallyValid: Bool {
        localInstallationHandle.isStructurallyValid
            && peerInstallationHandle.isStructurallyValid
            && localCertificateReferenceDigest.count == 32
            && peerCertificateReferenceDigest.count == 32
            && cipherSuite == DirectV4CipherSuite.identifier
            && negotiatedCapabilitiesDigest.count == 32
    }

    public func validatedNegotiation(
        localEndpoint: CertifiedInstallationEndpoint,
        peerEndpoint: CertifiedInstallationEndpoint
    ) throws -> DirectV4NegotiatedCapabilityManifest {
        let negotiation = try DirectV4NegotiatedCapabilityManifest.negotiate(
            local: localEndpoint.capabilities,
            peer: peerEndpoint.capabilities
        )
        let digest = try negotiation.digest()
        guard cipherSuite == negotiation.cipherSuite,
              negotiatedCapabilitiesDigest == digest else {
            throw DirectV4CapabilityNegotiationError.transcriptMismatch
        }
        return negotiation
    }

    private static func identityDescriptor(generationId: UUID) -> Data {
        Data(generationId.uuidString.lowercased().utf8)
    }

    private static func installationHandle(
        relationshipId: UUID,
        generationId: UUID,
        endpoint: CertifiedInstallationEndpoint
    ) -> RelationshipInstallationHandle {
        var material = Data("Noctweave/pairwise-installation-handle/v4".utf8)
        material.append(Data(relationshipId.uuidString.lowercased().utf8))
        material.append(Data(generationId.uuidString.lowercased().utf8))
        material.append(Data(endpoint.installationId.uuidString.lowercased().utf8))
        material.append(endpoint.signingPublicKey)
        return RelationshipInstallationHandle(
            rawValue: Data(SHA256.hash(data: material)).base64EncodedString()
        )
    }

    private static func certificateReference(
        relationshipId: UUID,
        certificateDigest: Data
    ) -> Data {
        var material = Data("Noctweave/pairwise-certificate-reference/v4".utf8)
        material.append(Data(relationshipId.uuidString.lowercased().utf8))
        material.append(certificateDigest)
        return Data(SHA256.hash(data: material))
    }
}

private struct CertifiedInstallationEndpointPayload: Codable {
    let version: Int
    let identityGenerationId: UUID
    let identityAuthorityPublicKey: Data
    let manifestEpoch: UInt64
    let manifestDigest: Data
    let installationId: UUID
    let signingPublicKey: Data
    let agreementPublicKey: Data
    let capabilities: ProtocolCapabilityManifest
    let issuedAt: Date

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

private struct CertifiedInstallationEndpointAuthorizationReference: Codable {
    let endpoint: CertifiedInstallationEndpointPayload
    let authoritySignature: Data
    let possessionSignature: Data
}

private struct EndpointSignedPrekeyPackagePayloadV4: Codable {
    let purpose = "Noctweave/endpoint-signed-prekey-package/v4"
    let endpointAuthorizationDigest: Data
    let bundle: PrekeyBundle

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

private struct InstallationManifestCheckpointPayloadV4: Codable {
    let version: Int
    let identityGenerationId: UUID
    let identityFingerprint: String
    let epoch: UInt64
    let manifestDigest: Data
    let issuedAt: Date

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

private struct InstallationEndpointRevocationPayloadV4: Codable {
    let identityGenerationId: UUID
    let installationId: UUID
    let certificateDigest: Data
    let manifestEpoch: UInt64
    let manifestDigest: Data
    let issuedAt: Date

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

private struct CertifiedInstallationEndpointPossessionPayload: Encodable {
    let purpose = "Noctweave/certified-installation-endpoint-possession/v4"
    let endpoint: CertifiedInstallationEndpointPayload
    let authoritySignature: Data

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}
