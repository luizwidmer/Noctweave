import CryptoKit
import Foundation

/// Signed-state foundations for installation-aware groups. These types are
/// intentionally not wired into the legacy relay-backed group runtime yet.
public enum NoctweaveSignedGroupV2 {
    public static let version = 2
    public static let experimentalProfile = GroupProtocolProfile.noctweavePQExperimentalV2
    public static let experimentalCipherSuite =
        "Noctweave-PQ-Group-Experimental-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-2"
    public static let maximumKeyPackageBytes = 64 * 1_024
    public static let maximumStateBytes = 8 * 1_024 * 1_024
    public static let maximumWelcomeLifetimeSeconds: TimeInterval = 7 * 24 * 60 * 60
    public static let maximumKeyPackageLifetimeSeconds: TimeInterval = 30 * 24 * 60 * 60
    public static let maximumClockSkewSeconds: TimeInterval = 5 * 60
    public static let signatureBytes = 3_309
}

public enum SignedGroupV2Error: Error, Equatable {
    case invalidStructure
    case unsupportedProfile
    case invalidContext
    case invalidManifest
    case installationNotAuthorized
    case invalidAuthoritySignature
    case invalidInstallationSignature
    case invalidClientSignature
    case invalidStateSignature
    case invalidCommitSignature
    case staleEpoch
    case transcriptMismatch
    case unknownAuthor
    case unauthorized
    case invalidTransition
    case wouldRemoveLastOwner
    case activeLeafLimitExceeded
    case keyPackageMismatch
    case invalidWelcomeSignature
    case genesisTrustRequired
    case groupDeleted
}

/// An opaque client handle that is unique to one group. It deliberately does
/// not reuse a relationship-scoped or globally stable installation identifier.
public struct GroupScopedClientHandleV2: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    /// Generates a group-only handle with no endpoint-derived input. The
    /// endpoint binding, when one is locally verified, remains outside the
    /// shared group transcript.
    public static func generate() -> GroupScopedClientHandleV2 {
        var generator = SystemRandomNumberGenerator()
        while true {
            let bytes = Data((0..<32).map { _ in
                UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
            })
            if bytes.contains(where: { $0 != 0 }) {
                return GroupScopedClientHandleV2(rawValue: bytes.base64EncodedString())
            }
        }
    }

    /// Legacy source-compatible spelling. Endpoint inputs are intentionally
    /// ignored so the resulting handle remains group-only and unlinkable.
    public static func generate(
        groupId: UUID,
        installationId: UUID,
        nonce: UUID = UUID()
    ) -> GroupScopedClientHandleV2 {
        _ = groupId
        _ = installationId
        _ = nonce
        return generate()
    }

    public var isStructurallyValid: Bool {
        guard let decoded = Data(base64Encoded: rawValue), decoded.count == 32 else {
            return false
        }
        return decoded.base64EncodedString() == rawValue
    }
}

/// Privacy-minimized material committed for a new group client. It contains
/// no identity-generation ID, endpoint ID, endpoint public key, manifest, full
/// endpoint capability manifest, inbox, route, or relay identifier.
public struct GroupClientAdmissionProjectionV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let version: Int
    public let groupId: UUID
    public let groupUserId: UUID
    public let clientHandle: GroupScopedClientHandleV2
    public let selection: GroupProtocolSelectionV2
    public let groupSigningPublicKey: Data
    public let groupAgreementPublicKey: Data
    public let issuedAt: Date
    public let expiresAt: Date
    public let clientPossessionSignature: Data

    public init(
        id: UUID,
        version: Int = NoctweaveSignedGroupV2.version,
        groupId: UUID,
        groupUserId: UUID,
        clientHandle: GroupScopedClientHandleV2,
        selection: GroupProtocolSelectionV2,
        groupSigningPublicKey: Data,
        groupAgreementPublicKey: Data,
        issuedAt: Date,
        expiresAt: Date,
        clientPossessionSignature: Data
    ) {
        self.id = id
        self.version = version
        self.groupId = groupId
        self.groupUserId = groupUserId
        self.clientHandle = clientHandle
        self.selection = selection
        self.groupSigningPublicKey = groupSigningPublicKey
        self.groupAgreementPublicKey = groupAgreementPublicKey
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.clientPossessionSignature = clientPossessionSignature
    }

    public static func create(
        id: UUID = UUID(),
        groupId: UUID,
        groupUserId: UUID,
        clientHandle: GroupScopedClientHandleV2 = .generate(),
        selection: GroupProtocolSelectionV2 = .currentExperimental,
        groupSigningKey: SigningKeyPair,
        groupAgreementKey: AgreementKeyPair,
        issuedAt: Date = Date(),
        expiresAt: Date
    ) throws -> GroupClientAdmissionProjectionV2 {
        var projection = GroupClientAdmissionProjectionV2(
            id: id,
            groupId: groupId,
            groupUserId: groupUserId,
            clientHandle: clientHandle,
            selection: selection,
            groupSigningPublicKey: groupSigningKey.publicKeyData,
            groupAgreementPublicKey: groupAgreementKey.publicKeyData,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            clientPossessionSignature: Data()
        )
        guard projection.isStructurallyValid(excludingSignature: true),
              let digest = projection.payloadDigest else {
            throw SignedGroupV2Error.invalidStructure
        }
        projection = GroupClientAdmissionProjectionV2(
            id: projection.id,
            groupId: projection.groupId,
            groupUserId: projection.groupUserId,
            clientHandle: projection.clientHandle,
            selection: projection.selection,
            groupSigningPublicKey: projection.groupSigningPublicKey,
            groupAgreementPublicKey: projection.groupAgreementPublicKey,
            issuedAt: projection.issuedAt,
            expiresAt: projection.expiresAt,
            clientPossessionSignature: try groupSigningKey.sign(
                try GroupAdmissionProjectionSignatureContextV2(
                    groupId: groupId,
                    groupUserId: groupUserId,
                    clientHandle: clientHandle,
                    payloadDigest: digest
                ).signableData()
            )
        )
        return try projection.verified(
            forGroupId: groupId,
            groupUserId: groupUserId,
            selection: selection,
            now: issuedAt
        )
    }

    public var digest: Data? {
        guard isStructurallyValid,
              let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else {
            return nil
        }
        return Data(SHA256.hash(data: encoded))
    }

    public var isStructurallyValid: Bool {
        isStructurallyValid(excludingSignature: false)
    }

    public func verified(
        forGroupId expectedGroupId: UUID,
        groupUserId expectedGroupUserId: UUID,
        selection expectedSelection: GroupProtocolSelectionV2,
        now: Date = Date()
    ) throws -> GroupClientAdmissionProjectionV2 {
        guard isStructurallyValid else { throw SignedGroupV2Error.invalidStructure }
        guard groupId == expectedGroupId,
              groupUserId == expectedGroupUserId,
              selection == expectedSelection else {
            throw SignedGroupV2Error.invalidContext
        }
        guard now.timeIntervalSince1970.isFinite,
              issuedAt <= now.addingTimeInterval(NoctweaveSignedGroupV2.maximumClockSkewSeconds),
              now < expiresAt,
              let digest = payloadDigest,
              SigningKeyPair.verify(
                  signature: clientPossessionSignature,
                  data: try GroupAdmissionProjectionSignatureContextV2(
                      groupId: groupId,
                      groupUserId: groupUserId,
                      clientHandle: clientHandle,
                      payloadDigest: digest
                  ).signableData(),
                  publicKeyData: groupSigningPublicKey
              ) else {
            throw SignedGroupV2Error.invalidClientSignature
        }
        return self
    }

    fileprivate var payloadDigest: Data? {
        try? SignedGroupV2Hash.digest(payload)
    }

    fileprivate var payload: GroupClientAdmissionProjectionPayloadV2 {
        GroupClientAdmissionProjectionPayloadV2(
            version: version,
            id: id,
            groupId: groupId,
            groupUserId: groupUserId,
            clientHandle: clientHandle,
            selection: selection,
            groupSigningPublicKey: groupSigningPublicKey,
            groupAgreementPublicKey: groupAgreementPublicKey,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
    }

    private func isStructurallyValid(excludingSignature: Bool) -> Bool {
        version == NoctweaveSignedGroupV2.version
            && clientHandle.isStructurallyValid
            && selection.isStructurallyValid
            && selection == .currentExperimental
            && SigningKeyPair.isValidPublicKey(groupSigningPublicKey)
            && AgreementKeyPair.isValidPublicKey(groupAgreementPublicKey)
            && issuedAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && expiresAt > issuedAt
            && expiresAt.timeIntervalSince(issuedAt)
                <= NoctweaveSignedGroupV2.maximumKeyPackageLifetimeSeconds
            && (excludingSignature
                || clientPossessionSignature.count == NoctweaveSignedGroupV2.signatureBytes)
    }
}

/// Adding a second client under an existing group user requires consent from
/// one currently active client of that same user. An admin's commit signature
/// alone cannot manufacture a sibling and impersonate that user.
public struct GroupSiblingClientConsentV2: Codable, Equatable {
    public let version: Int
    public let groupId: UUID
    public let groupUserId: UUID
    public let newClientHandle: GroupScopedClientHandleV2
    public let projectionDigest: Data
    public let consentingClientHandle: GroupScopedClientHandleV2
    public let baseEpoch: UInt64
    public let nextEpoch: UInt64
    public let signedAt: Date
    public let signature: Data

    public init(
        version: Int = NoctweaveSignedGroupV2.version,
        groupId: UUID,
        groupUserId: UUID,
        newClientHandle: GroupScopedClientHandleV2,
        projectionDigest: Data,
        consentingClientHandle: GroupScopedClientHandleV2,
        baseEpoch: UInt64,
        nextEpoch: UInt64,
        signedAt: Date,
        signature: Data
    ) {
        self.version = version
        self.groupId = groupId
        self.groupUserId = groupUserId
        self.newClientHandle = newClientHandle
        self.projectionDigest = projectionDigest
        self.consentingClientHandle = consentingClientHandle
        self.baseEpoch = baseEpoch
        self.nextEpoch = nextEpoch
        self.signedAt = signedAt
        self.signature = signature
    }

    public static func create(
        projection: GroupClientAdmissionProjectionV2,
        currentState: SignedGroupStateV2,
        consentingClientHandle: GroupScopedClientHandleV2,
        signingKey: SigningKeyPair,
        signedAt: Date = Date()
    ) throws -> GroupSiblingClientConsentV2 {
        guard let projectionDigest = projection.digest,
              currentState.epoch < UInt64.max,
              let leaf = currentState.activeClientLeaves.first(where: {
                  $0.clientHandle == consentingClientHandle
              }),
              leaf.userId == projection.groupUserId,
              leaf.signingPublicKey == signingKey.publicKeyData else {
            throw SignedGroupV2Error.unauthorized
        }
        var consent = GroupSiblingClientConsentV2(
            groupId: currentState.groupId,
            groupUserId: projection.groupUserId,
            newClientHandle: projection.clientHandle,
            projectionDigest: projectionDigest,
            consentingClientHandle: consentingClientHandle,
            baseEpoch: currentState.epoch,
            nextEpoch: currentState.epoch + 1,
            signedAt: signedAt,
            signature: Data()
        )
        consent = GroupSiblingClientConsentV2(
            groupId: consent.groupId,
            groupUserId: consent.groupUserId,
            newClientHandle: consent.newClientHandle,
            projectionDigest: consent.projectionDigest,
            consentingClientHandle: consent.consentingClientHandle,
            baseEpoch: consent.baseEpoch,
            nextEpoch: consent.nextEpoch,
            signedAt: consent.signedAt,
            signature: try signingKey.sign(try consent.signatureContext().signableData())
        )
        return try consent.verified(projection: projection, currentState: currentState)
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveSignedGroupV2.version
            && newClientHandle.isStructurallyValid
            && projectionDigest.count == 32
            && consentingClientHandle.isStructurallyValid
            && baseEpoch > 0
            && baseEpoch < UInt64.max
            && nextEpoch == baseEpoch + 1
            && signedAt.timeIntervalSince1970.isFinite
            && signature.count == NoctweaveSignedGroupV2.signatureBytes
    }

    public func verified(
        projection: GroupClientAdmissionProjectionV2,
        currentState: SignedGroupStateV2
    ) throws -> GroupSiblingClientConsentV2 {
        guard isStructurallyValid,
              projection.groupId == groupId,
              projection.groupUserId == groupUserId,
              projection.clientHandle == newClientHandle,
              projection.digest == projectionDigest,
              currentState.groupId == groupId,
              currentState.epoch == baseEpoch,
              let leaf = currentState.activeClientLeaves.first(where: {
                  $0.clientHandle == consentingClientHandle
              }),
              leaf.userId == groupUserId,
              signedAt >= currentState.signedAt,
              SigningKeyPair.verify(
                  signature: signature,
                  data: try signatureContext().signableData(),
                  publicKeyData: leaf.signingPublicKey
              ) else {
            throw SignedGroupV2Error.unauthorized
        }
        return self
    }

    private func signatureContext() throws -> GroupSiblingConsentSignatureContextV2 {
        GroupSiblingConsentSignatureContextV2(
            groupId: groupId,
            groupUserId: groupUserId,
            newClientHandle: newClientHandle,
            projectionDigest: projectionDigest,
            consentingClientHandle: consentingClientHandle,
            baseEpoch: baseEpoch,
            nextEpoch: nextEpoch,
            signedAt: signedAt
        )
    }
}

/// A group-scoped client key package. The identity-generation signature
/// authorizes the installation, the installation signature proves possession,
/// and the group-client signature proves possession of the unlinkable group key.
public struct GroupClientKeyPackageV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let version: Int
    public let groupId: UUID
    public let groupUserId: UUID
    public let clientHandle: GroupScopedClientHandleV2
    public let identityGenerationId: UUID
    public let manifestEpoch: UInt64
    public let manifestDigest: Data
    public let installationId: UUID
    public let installationSigningPublicKey: Data
    public let installationAgreementPublicKey: Data
    public let groupSigningPublicKey: Data
    public let groupAgreementPublicKey: Data
    public let capabilities: ProtocolCapabilityManifest
    public let issuedAt: Date
    public let expiresAt: Date
    public let authoritySignature: Data
    public let installationPossessionSignature: Data
    public let groupClientPossessionSignature: Data

    public init(
        id: UUID,
        version: Int = NoctweaveSignedGroupV2.version,
        groupId: UUID,
        groupUserId: UUID,
        clientHandle: GroupScopedClientHandleV2,
        identityGenerationId: UUID,
        manifestEpoch: UInt64,
        manifestDigest: Data,
        installationId: UUID,
        installationSigningPublicKey: Data,
        installationAgreementPublicKey: Data,
        groupSigningPublicKey: Data,
        groupAgreementPublicKey: Data,
        capabilities: ProtocolCapabilityManifest,
        issuedAt: Date,
        expiresAt: Date,
        authoritySignature: Data,
        installationPossessionSignature: Data,
        groupClientPossessionSignature: Data
    ) {
        self.id = id
        self.version = version
        self.groupId = groupId
        self.groupUserId = groupUserId
        self.clientHandle = clientHandle
        self.identityGenerationId = identityGenerationId
        self.manifestEpoch = manifestEpoch
        self.manifestDigest = manifestDigest
        self.installationId = installationId
        self.installationSigningPublicKey = installationSigningPublicKey
        self.installationAgreementPublicKey = installationAgreementPublicKey
        self.groupSigningPublicKey = groupSigningPublicKey
        self.groupAgreementPublicKey = groupAgreementPublicKey
        self.capabilities = capabilities
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.authoritySignature = authoritySignature
        self.installationPossessionSignature = installationPossessionSignature
        self.groupClientPossessionSignature = groupClientPossessionSignature
    }

    public static func create(
        id: UUID = UUID(),
        groupId: UUID,
        groupUserId: UUID,
        clientHandle: GroupScopedClientHandleV2,
        identity: Identity,
        installation: LocalInstallationState,
        manifest: InstallationManifest,
        groupSigningKey: SigningKeyPair,
        groupAgreementKey: AgreementKeyPair,
        issuedAt: Date = Date(),
        expiresAt: Date
    ) throws -> GroupClientKeyPackageV2 {
        guard clientHandle.isStructurallyValid,
              issuedAt.timeIntervalSince1970.isFinite,
              issuedAt >= manifest.issuedAt,
              let manifestDigest = manifest.digest,
              manifest.verify(identityPublicKey: identity.signingKey.publicKeyData),
              manifest.identityGenerationId == installation.identityGenerationId,
              let record = manifest.installations.first(where: { $0.id == installation.id }),
              record.isActive(at: issuedAt, manifestEpoch: manifest.epoch),
              record.signingPublicKey == installation.signingKey.publicKeyData,
              record.agreementPublicKey == installation.agreementKey.publicKeyData else {
            throw SignedGroupV2Error.installationNotAuthorized
        }
        let payload = GroupClientKeyPackagePayloadV2(
            version: NoctweaveSignedGroupV2.version,
            id: id,
            groupId: groupId,
            groupUserId: groupUserId,
            clientHandle: clientHandle,
            identityGenerationId: installation.identityGenerationId,
            manifestEpoch: manifest.epoch,
            manifestDigest: manifestDigest,
            installationId: installation.id,
            installationSigningPublicKey: installation.signingKey.publicKeyData,
            installationAgreementPublicKey: installation.agreementKey.publicKeyData,
            groupSigningPublicKey: groupSigningKey.publicKeyData,
            groupAgreementPublicKey: groupAgreementKey.publicKeyData,
            capabilities: record.capabilities,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
        let payloadDigest = try SignedGroupV2Hash.digest(payload)
        let authoritySignature = try identity.signingKey.sign(
            try GroupKeyPackageAuthorityContextV2(payloadDigest: payloadDigest).signableData()
        )
        let installationSignature = try installation.signingKey.sign(
            try GroupKeyPackageInstallationContextV2(
                payloadDigest: payloadDigest,
                authoritySignatureDigest: SignedGroupV2Hash.digest(authoritySignature)
            ).signableData()
        )
        let groupClientSignature = try groupSigningKey.sign(
            try GroupKeyPackageClientContextV2(
                payloadDigest: payloadDigest,
                authoritySignatureDigest: SignedGroupV2Hash.digest(authoritySignature),
                installationSignatureDigest: SignedGroupV2Hash.digest(installationSignature)
            ).signableData()
        )
        let package = GroupClientKeyPackageV2(
            id: id,
            groupId: groupId,
            groupUserId: groupUserId,
            clientHandle: clientHandle,
            identityGenerationId: installation.identityGenerationId,
            manifestEpoch: manifest.epoch,
            manifestDigest: manifestDigest,
            installationId: installation.id,
            installationSigningPublicKey: installation.signingKey.publicKeyData,
            installationAgreementPublicKey: installation.agreementKey.publicKeyData,
            groupSigningPublicKey: groupSigningKey.publicKeyData,
            groupAgreementPublicKey: groupAgreementKey.publicKeyData,
            capabilities: record.capabilities,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            authoritySignature: authoritySignature,
            installationPossessionSignature: installationSignature,
            groupClientPossessionSignature: groupClientSignature
        )
        guard package.isStructurallyValid else { throw SignedGroupV2Error.invalidStructure }
        return package
    }

    public var digest: Data? {
        guard let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else { return nil }
        return Data(SHA256.hash(data: encoded))
    }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveSignedGroupV2.version,
              clientHandle.isStructurallyValid,
              manifestDigest.count == 32,
              SigningKeyPair.isValidPublicKey(installationSigningPublicKey),
              AgreementKeyPair.isValidPublicKey(installationAgreementPublicKey),
              SigningKeyPair.isValidPublicKey(groupSigningPublicKey),
              AgreementKeyPair.isValidPublicKey(groupAgreementPublicKey),
              capabilities.isStructurallyValid,
              issuedAt.timeIntervalSince1970.isFinite,
              expiresAt.timeIntervalSince1970.isFinite,
              expiresAt > issuedAt,
              expiresAt.timeIntervalSince(issuedAt)
                <= NoctweaveSignedGroupV2.maximumKeyPackageLifetimeSeconds,
              authoritySignature.count == NoctweaveSignedGroupV2.signatureBytes,
              installationPossessionSignature.count == NoctweaveSignedGroupV2.signatureBytes,
              groupClientPossessionSignature.count == NoctweaveSignedGroupV2.signatureBytes,
              let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true),
              encoded.count <= NoctweaveSignedGroupV2.maximumKeyPackageBytes else {
            return false
        }
        return installationSigningPublicKey != groupSigningPublicKey
            && installationAgreementPublicKey != groupAgreementPublicKey
    }

    public func verified(
        forGroupId expectedGroupId: UUID,
        groupUserId expectedGroupUserId: UUID,
        identityPublicKey: Data,
        manifest: InstallationManifest,
        now: Date = Date()
    ) throws -> GroupClientKeyPackageV2 {
        guard isStructurallyValid else { throw SignedGroupV2Error.invalidStructure }
        guard groupId == expectedGroupId, groupUserId == expectedGroupUserId else {
            throw SignedGroupV2Error.invalidContext
        }
        guard now.timeIntervalSince1970.isFinite,
              issuedAt <= now.addingTimeInterval(NoctweaveSignedGroupV2.maximumClockSkewSeconds),
              now < expiresAt else {
            throw SignedGroupV2Error.invalidStructure
        }
        guard issuedAt >= manifest.issuedAt,
              manifest.verify(identityPublicKey: identityPublicKey),
              manifest.identityGenerationId == identityGenerationId,
              manifest.epoch == manifestEpoch,
              manifest.digest == manifestDigest else {
            throw SignedGroupV2Error.invalidManifest
        }
        guard let record = manifest.installations.first(where: { $0.id == installationId }),
              record.isActive(at: now, manifestEpoch: manifest.epoch),
              record.signingPublicKey == installationSigningPublicKey,
              record.agreementPublicKey == installationAgreementPublicKey,
              record.capabilities == capabilities else {
            throw SignedGroupV2Error.installationNotAuthorized
        }
        let payloadDigest = try SignedGroupV2Hash.digest(payload)
        let authorityData = try GroupKeyPackageAuthorityContextV2(
            payloadDigest: payloadDigest
        ).signableData()
        guard SigningKeyPair.verify(
            signature: authoritySignature,
            data: authorityData,
            publicKeyData: identityPublicKey
        ) else {
            throw SignedGroupV2Error.invalidAuthoritySignature
        }
        let installationData = try GroupKeyPackageInstallationContextV2(
            payloadDigest: payloadDigest,
            authoritySignatureDigest: SignedGroupV2Hash.digest(authoritySignature)
        ).signableData()
        guard SigningKeyPair.verify(
            signature: installationPossessionSignature,
            data: installationData,
            publicKeyData: installationSigningPublicKey
        ) else {
            throw SignedGroupV2Error.invalidInstallationSignature
        }
        let clientData = try GroupKeyPackageClientContextV2(
            payloadDigest: payloadDigest,
            authoritySignatureDigest: SignedGroupV2Hash.digest(authoritySignature),
            installationSignatureDigest: SignedGroupV2Hash.digest(installationPossessionSignature)
        ).signableData()
        guard SigningKeyPair.verify(
            signature: groupClientPossessionSignature,
            data: clientData,
            publicKeyData: groupSigningPublicKey
        ) else {
            throw SignedGroupV2Error.invalidClientSignature
        }
        return self
    }

    private var payload: GroupClientKeyPackagePayloadV2 {
        GroupClientKeyPackagePayloadV2(
            version: version,
            id: id,
            groupId: groupId,
            groupUserId: groupUserId,
            clientHandle: clientHandle,
            identityGenerationId: identityGenerationId,
            manifestEpoch: manifestEpoch,
            manifestDigest: manifestDigest,
            installationId: installationId,
            installationSigningPublicKey: installationSigningPublicKey,
            installationAgreementPublicKey: installationAgreementPublicKey,
            groupSigningPublicKey: groupSigningPublicKey,
            groupAgreementPublicKey: groupAgreementPublicKey,
            capabilities: capabilities,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
    }
}

/// Local trust input used when accepting one client into a signed group.
///
/// This value is deliberately not learned from the commit. The caller must
/// supply the identity authority and latest trusted installation manifest from
/// an authenticated contact, invitation, continuity, or self-sync path. That
/// prevents a commit author from inventing a different identity authority for
/// an existing group user while still leaving the signed commit self-contained
/// with respect to the admitted client's key package.
public struct GroupClientAdmissionTrustV2: Equatable {
    public let groupUserId: UUID
    public let identityPublicKey: Data
    public let currentManifest: InstallationManifest

    public init(
        groupUserId: UUID,
        identityPublicKey: Data,
        currentManifest: InstallationManifest
    ) {
        self.groupUserId = groupUserId
        self.identityPublicKey = identityPublicKey
        self.currentManifest = currentManifest
    }

    public var isStructurallyValid: Bool {
        SigningKeyPair.isValidPublicKey(identityPublicKey)
            && currentManifest.verify(identityPublicKey: identityPublicKey)
    }
}

/// External trust required to create or accept the first signed group state.
///
/// None of these values are learned from the candidate state. The caller pins
/// the creator's identity authority, current installation manifest, and full
/// group-scoped key package through an authenticated invitation, contact,
/// continuity, or self-sync path. This prevents an epoch-one state from
/// inventing the authority and client keys that are then used to verify itself.
public struct GroupGenesisTrustV2: Equatable {
    public let creatorUserId: UUID
    public let identityPublicKey: Data
    public let currentManifest: InstallationManifest
    public let creatorKeyPackage: GroupClientKeyPackageV2

    public init(
        creatorUserId: UUID,
        identityPublicKey: Data,
        currentManifest: InstallationManifest,
        creatorKeyPackage: GroupClientKeyPackageV2
    ) {
        self.creatorUserId = creatorUserId
        self.identityPublicKey = identityPublicKey
        self.currentManifest = currentManifest
        self.creatorKeyPackage = creatorKeyPackage
    }

    public var isStructurallyValid: Bool {
        SigningKeyPair.isValidPublicKey(identityPublicKey)
            && creatorKeyPackage.isStructurallyValid
            && creatorKeyPackage.groupUserId == creatorUserId
            && currentManifest.verify(identityPublicKey: identityPublicKey)
            && currentManifest.identityGenerationId == creatorKeyPackage.identityGenerationId
            && currentManifest.epoch == creatorKeyPackage.manifestEpoch
            && currentManifest.digest == creatorKeyPackage.manifestDigest
    }

    public func verified(
        forGroupId expectedGroupId: UUID,
        now: Date = Date()
    ) throws -> GroupClientKeyPackageV2 {
        guard isStructurallyValid else { throw SignedGroupV2Error.invalidManifest }
        return try creatorKeyPackage.verified(
            forGroupId: expectedGroupId,
            groupUserId: creatorUserId,
            identityPublicKey: identityPublicKey,
            manifest: currentManifest,
            now: now
        )
    }
}

public struct GroupClientLeafV2: Codable, Equatable, Identifiable {
    public var id: GroupScopedClientHandleV2 { clientHandle }
    public let userId: UUID
    public let clientHandle: GroupScopedClientHandleV2
    public let keyPackageDigest: Data
    public let signingPublicKey: Data
    public let agreementPublicKey: Data
    public let addedEpoch: UInt64
    public let removedEpoch: UInt64?

    public init(
        userId: UUID,
        clientHandle: GroupScopedClientHandleV2,
        keyPackageDigest: Data,
        signingPublicKey: Data,
        agreementPublicKey: Data,
        addedEpoch: UInt64,
        removedEpoch: UInt64? = nil
    ) {
        self.userId = userId
        self.clientHandle = clientHandle
        self.keyPackageDigest = keyPackageDigest
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
        self.addedEpoch = addedEpoch
        self.removedEpoch = removedEpoch
    }

    public static func fromVerifiedPackage(
        _ package: GroupClientKeyPackageV2,
        addedEpoch: UInt64
    ) throws -> GroupClientLeafV2 {
        guard package.isStructurallyValid, let digest = package.digest else {
            throw SignedGroupV2Error.invalidStructure
        }
        return GroupClientLeafV2(
            userId: package.groupUserId,
            clientHandle: package.clientHandle,
            keyPackageDigest: digest,
            signingPublicKey: package.groupSigningPublicKey,
            agreementPublicKey: package.groupAgreementPublicKey,
            addedEpoch: addedEpoch
        )
    }

    public static func fromVerifiedProjection(
        _ projection: GroupClientAdmissionProjectionV2,
        addedEpoch: UInt64
    ) throws -> GroupClientLeafV2 {
        guard projection.isStructurallyValid, let digest = projection.digest else {
            throw SignedGroupV2Error.invalidStructure
        }
        return GroupClientLeafV2(
            userId: projection.groupUserId,
            clientHandle: projection.clientHandle,
            keyPackageDigest: digest,
            signingPublicKey: projection.groupSigningPublicKey,
            agreementPublicKey: projection.groupAgreementPublicKey,
            addedEpoch: addedEpoch
        )
    }

    public var isStructurallyValid: Bool {
        clientHandle.isStructurallyValid
            && keyPackageDigest.count == 32
            && SigningKeyPair.isValidPublicKey(signingPublicKey)
            && AgreementKeyPair.isValidPublicKey(agreementPublicKey)
            && addedEpoch > 0
            && (removedEpoch.map { $0 > addedEpoch } ?? true)
    }

    public func isActive(at epoch: UInt64) -> Bool {
        isStructurallyValid
            && addedEpoch <= epoch
            && (removedEpoch.map { $0 > epoch } ?? true)
    }
}

public enum SignedGroupCommitOperationV2: String, Codable, Equatable, CaseIterable {
    case addClient
    case removeClient
    case addUser
    case removeUser
    case changeRole
    case changePolicy
    case updateMetadata
    case deleteGroup
}

/// A complete proposed next state. Carrying the full users, leaves, policy, and
/// metadata digest makes omission and mixed-operation attacks fail closed.
public struct SignedGroupCommitV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let version: Int
    public let profile: GroupProtocolProfile
    public let cipherSuite: String
    public let groupId: UUID
    public let operation: SignedGroupCommitOperationV2
    public let baseEpoch: UInt64
    public let nextEpoch: UInt64
    public let previousTranscriptHash: Data
    public let proposedUsers: [GroupUser]
    public let proposedClientLeaves: [GroupClientLeafV2]
    public let admissionProjection: GroupClientAdmissionProjectionV2?
    public let siblingClientConsent: GroupSiblingClientConsentV2?
    public let proposedPermissions: GroupPermissionPolicy
    public let proposedMetadataDigest: Data?
    public let authorClientHandle: GroupScopedClientHandleV2
    public let providerCommitDigest: Data
    public let idempotencyKey: Data
    public let createdAt: Date
    public let signature: Data

    public init(
        id: UUID,
        version: Int = NoctweaveSignedGroupV2.version,
        profile: GroupProtocolProfile,
        cipherSuite: String,
        groupId: UUID,
        operation: SignedGroupCommitOperationV2,
        baseEpoch: UInt64,
        nextEpoch: UInt64,
        previousTranscriptHash: Data,
        proposedUsers: [GroupUser],
        proposedClientLeaves: [GroupClientLeafV2],
        admissionProjection: GroupClientAdmissionProjectionV2? = nil,
        siblingClientConsent: GroupSiblingClientConsentV2? = nil,
        proposedPermissions: GroupPermissionPolicy,
        proposedMetadataDigest: Data?,
        authorClientHandle: GroupScopedClientHandleV2,
        providerCommitDigest: Data,
        idempotencyKey: Data,
        createdAt: Date,
        signature: Data
    ) {
        self.id = id
        self.version = version
        self.profile = profile
        self.cipherSuite = cipherSuite
        self.groupId = groupId
        self.operation = operation
        self.baseEpoch = baseEpoch
        self.nextEpoch = nextEpoch
        self.previousTranscriptHash = previousTranscriptHash
        self.proposedUsers = proposedUsers.sorted { $0.id.uuidString < $1.id.uuidString }
        self.proposedClientLeaves = proposedClientLeaves.sorted {
            $0.clientHandle.rawValue < $1.clientHandle.rawValue
        }
        self.admissionProjection = admissionProjection
        self.siblingClientConsent = siblingClientConsent
        self.proposedPermissions = proposedPermissions
        self.proposedMetadataDigest = proposedMetadataDigest
        self.authorClientHandle = authorClientHandle
        self.providerCommitDigest = providerCommitDigest
        self.idempotencyKey = idempotencyKey
        self.createdAt = createdAt
        self.signature = signature
    }

    /// Creates a group-only commit. Any endpoint authorization or
    /// contact evidence is verified locally before this call and is not copied
    /// into the shared group transcript. Adding a sibling client for an
    /// existing group user additionally requires a signature from one of that
    /// user's currently active group clients.
    public static func create(
        id: UUID = UUID(),
        operation: SignedGroupCommitOperationV2,
        currentState: SignedGroupStateV2,
        proposedUsers: [GroupUser],
        proposedClientLeaves: [GroupClientLeafV2],
        admissionProjection: GroupClientAdmissionProjectionV2? = nil,
        siblingClientConsent: GroupSiblingClientConsentV2? = nil,
        proposedPermissions: GroupPermissionPolicy,
        proposedMetadataDigest: Data?,
        authorClientHandle: GroupScopedClientHandleV2,
        providerCommitDigest: Data,
        idempotencyKey: Data,
        signingKey: SigningKeyPair,
        createdAt: Date = Date()
    ) throws -> SignedGroupCommitV2 {
        guard currentState.epoch < UInt64.max else { throw SignedGroupV2Error.staleEpoch }
        var commit = SignedGroupCommitV2(
            id: id,
            profile: currentState.profile,
            cipherSuite: currentState.cipherSuite,
            groupId: currentState.groupId,
            operation: operation,
            baseEpoch: currentState.epoch,
            nextEpoch: currentState.epoch + 1,
            previousTranscriptHash: currentState.confirmedTranscriptHash,
            proposedUsers: proposedUsers,
            proposedClientLeaves: proposedClientLeaves,
            admissionProjection: admissionProjection,
            siblingClientConsent: siblingClientConsent,
            proposedPermissions: proposedPermissions,
            proposedMetadataDigest: proposedMetadataDigest,
            authorClientHandle: authorClientHandle,
            providerCommitDigest: providerCommitDigest,
            idempotencyKey: idempotencyKey,
            createdAt: createdAt,
            signature: Data()
        )
        try commit.validateTransition(
            from: currentState,
            verifySignature: false
        )
        guard let author = currentState.activeClientLeaves.first(where: {
            $0.clientHandle == authorClientHandle
        }), author.signingPublicKey == signingKey.publicKeyData else {
            throw SignedGroupV2Error.unknownAuthor
        }
        let digest = try commit.commitDigest()
        commit = SignedGroupCommitV2(
            id: commit.id,
            profile: commit.profile,
            cipherSuite: commit.cipherSuite,
            groupId: commit.groupId,
            operation: commit.operation,
            baseEpoch: commit.baseEpoch,
            nextEpoch: commit.nextEpoch,
            previousTranscriptHash: commit.previousTranscriptHash,
            proposedUsers: commit.proposedUsers,
            proposedClientLeaves: commit.proposedClientLeaves,
            admissionProjection: commit.admissionProjection,
            siblingClientConsent: commit.siblingClientConsent,
            proposedPermissions: commit.proposedPermissions,
            proposedMetadataDigest: commit.proposedMetadataDigest,
            authorClientHandle: commit.authorClientHandle,
            providerCommitDigest: commit.providerCommitDigest,
            idempotencyKey: commit.idempotencyKey,
            createdAt: commit.createdAt,
            signature: try signingKey.sign(
                try GroupCommitSignatureContextV2(
                    groupId: commit.groupId,
                    profile: commit.profile,
                    nextEpoch: commit.nextEpoch,
                    commitDigest: digest
                ).signableData()
            )
        )
        return try commit.verifiedTransition(from: currentState)
    }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveSignedGroupV2.version,
              profile == NoctweaveSignedGroupV2.experimentalProfile,
              cipherSuite == NoctweaveSignedGroupV2.experimentalCipherSuite,
              baseEpoch > 0,
              baseEpoch < UInt64.max,
              nextEpoch == baseEpoch + 1,
              previousTranscriptHash.count == 32,
              authorClientHandle.isStructurallyValid,
              providerCommitDigest.count == 32,
              idempotencyKey.count == 32,
              createdAt.timeIntervalSince1970.isFinite,
              admissionProjection?.isStructurallyValid ?? true,
              siblingClientConsent?.isStructurallyValid ?? true,
              signature.count == NoctweaveSignedGroupV2.signatureBytes,
              let encoded = try? NoctweaveCoder.encode(payload, sortedKeys: true),
              encoded.count <= NoctweaveGroupArchitectureV2.maximumCommitBytes else {
            return false
        }
        let admissionFieldsAreValid: Bool
        switch operation {
        case .addClient:
            admissionFieldsAreValid = admissionProjection != nil
                && siblingClientConsent != nil
        case .addUser:
            admissionFieldsAreValid = admissionProjection != nil
                && siblingClientConsent == nil
        case .removeClient, .removeUser, .changeRole, .changePolicy, .updateMetadata:
            admissionFieldsAreValid = admissionProjection == nil
                && siblingClientConsent == nil
        case .deleteGroup:
            admissionFieldsAreValid = false
        }
        guard admissionFieldsAreValid else { return false }
        return (try? SignedGroupStateValidatorV2.validate(
            profile: profile,
            cipherSuite: cipherSuite,
            epoch: nextEpoch,
            users: proposedUsers,
            clientLeaves: proposedClientLeaves,
            permissions: proposedPermissions,
            metadataDigest: proposedMetadataDigest
        )) != nil
    }

    public var digest: Data? {
        try? commitDigest()
    }

    public func verifiedTransition(
        from currentState: SignedGroupStateV2
    ) throws -> SignedGroupCommitV2 {
        try validateTransition(
            from: currentState,
            verifySignature: true
        )
        return self
    }

    fileprivate var payload: GroupCommitPayloadV2 {
        GroupCommitPayloadV2(
            version: version,
            id: id,
            profile: profile,
            cipherSuite: cipherSuite,
            groupId: groupId,
            operation: operation,
            baseEpoch: baseEpoch,
            nextEpoch: nextEpoch,
            previousTranscriptHash: previousTranscriptHash,
            proposedUsers: proposedUsers,
            proposedClientLeaves: proposedClientLeaves,
            admissionProjection: admissionProjection,
            siblingClientConsent: siblingClientConsent,
            proposedPermissions: proposedPermissions,
            proposedMetadataDigest: proposedMetadataDigest,
            authorClientHandle: authorClientHandle,
            providerCommitDigest: providerCommitDigest,
            idempotencyKey: idempotencyKey,
            createdAt: createdAt
        )
    }

    private func commitDigest() throws -> Data {
        try SignedGroupV2Hash.digest(payload)
    }

    private func validateTransition(
        from currentState: SignedGroupStateV2,
        verifySignature: Bool
    ) throws {
        guard currentState.isStructurallyValid else { throw SignedGroupV2Error.invalidStructure }
        guard profile == currentState.profile,
              cipherSuite == currentState.cipherSuite,
              groupId == currentState.groupId else {
            throw SignedGroupV2Error.invalidContext
        }
        guard baseEpoch == currentState.epoch, nextEpoch == currentState.epoch + 1 else {
            throw SignedGroupV2Error.staleEpoch
        }
        guard previousTranscriptHash == currentState.confirmedTranscriptHash else {
            throw SignedGroupV2Error.transcriptMismatch
        }
        guard providerCommitDigest.count == 32,
              idempotencyKey.count == 32,
              createdAt >= currentState.signedAt else {
            throw SignedGroupV2Error.invalidStructure
        }
        try SignedGroupStateValidatorV2.validate(
            profile: profile,
            cipherSuite: cipherSuite,
            epoch: nextEpoch,
            users: proposedUsers,
            clientLeaves: proposedClientLeaves,
            permissions: proposedPermissions,
            metadataDigest: proposedMetadataDigest
        )
        guard let actorLeaf = currentState.activeClientLeaves.first(where: {
            $0.clientHandle == authorClientHandle
        }), let actorUser = currentState.activeUsers.first(where: {
            $0.id == actorLeaf.userId
        }) else {
            throw SignedGroupV2Error.unknownAuthor
        }
        if verifySignature {
            guard isStructurallyValid,
                  let digest,
                  let signatureData = try? GroupCommitSignatureContextV2(
                      groupId: groupId,
                      profile: profile,
                      nextEpoch: nextEpoch,
                      commitDigest: digest
                  ).signableData(),
                  SigningKeyPair.verify(
                      signature: signature,
                      data: signatureData,
                      publicKeyData: actorLeaf.signingPublicKey
                  ) else {
                throw SignedGroupV2Error.invalidCommitSignature
            }
        }
        let verifiedAddedLeaf: GroupClientLeafV2?
        switch operation {
        case .addClient, .addUser:
            guard let admissionProjection else {
                throw SignedGroupV2Error.keyPackageMismatch
            }
            let selection = GroupProtocolSelectionV2(
                profile: currentState.profile,
                cipherSuite: currentState.cipherSuite
            )
            let verifiedProjection = try admissionProjection.verified(
                forGroupId: groupId,
                groupUserId: admissionProjection.groupUserId,
                selection: selection,
                now: createdAt
            )
            switch operation {
            case .addClient:
                guard let siblingClientConsent,
                      siblingClientConsent.signedAt <= createdAt.addingTimeInterval(
                          NoctweaveSignedGroupV2.maximumClockSkewSeconds
                      ) else {
                    throw SignedGroupV2Error.unauthorized
                }
                _ = try siblingClientConsent.verified(
                    projection: verifiedProjection,
                    currentState: currentState
                )
            case .addUser:
                guard siblingClientConsent == nil else {
                    throw SignedGroupV2Error.invalidTransition
                }
            default:
                throw SignedGroupV2Error.invalidTransition
            }
            verifiedAddedLeaf = try GroupClientLeafV2.fromVerifiedProjection(
                verifiedProjection,
                addedEpoch: nextEpoch
            )
        case .removeClient, .removeUser, .changeRole, .changePolicy, .updateMetadata:
            guard admissionProjection == nil,
                  siblingClientConsent == nil else {
                throw SignedGroupV2Error.invalidTransition
            }
            verifiedAddedLeaf = nil
        case .deleteGroup:
            throw SignedGroupV2Error.invalidTransition
        }
        try SignedGroupTransitionValidatorV2.validate(
            operation: operation,
            currentState: currentState,
            proposedUsers: proposedUsers,
            proposedClientLeaves: proposedClientLeaves,
            proposedPermissions: proposedPermissions,
            proposedMetadataDigest: proposedMetadataDigest,
            actorUser: actorUser,
            actorLeaf: actorLeaf,
            verifiedAddedLeaf: verifiedAddedLeaf,
            nextEpoch: nextEpoch
        )
    }
}

/// A deletion is represented by a separately signed terminal operation. It is
/// not encoded as another live membership state, so an implementation cannot
/// accidentally advance from it using an ordinary group commit.
public struct SignedGroupDeletionTombstoneV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let version: Int
    public let operation: SignedGroupCommitOperationV2
    public let selection: GroupProtocolSelectionV2
    public let groupId: UUID
    public let baseEpoch: UInt64
    public let deletedEpoch: UInt64
    public let previousTranscriptHash: Data
    public let authorClientHandle: GroupScopedClientHandleV2
    public let reasonDigest: Data?
    public let idempotencyKey: Data
    public let createdAt: Date
    public let signature: Data

    public init(
        id: UUID,
        version: Int = NoctweaveSignedGroupV2.version,
        operation: SignedGroupCommitOperationV2 = .deleteGroup,
        selection: GroupProtocolSelectionV2,
        groupId: UUID,
        baseEpoch: UInt64,
        deletedEpoch: UInt64,
        previousTranscriptHash: Data,
        authorClientHandle: GroupScopedClientHandleV2,
        reasonDigest: Data?,
        idempotencyKey: Data,
        createdAt: Date,
        signature: Data
    ) {
        self.id = id
        self.version = version
        self.operation = operation
        self.selection = selection
        self.groupId = groupId
        self.baseEpoch = baseEpoch
        self.deletedEpoch = deletedEpoch
        self.previousTranscriptHash = previousTranscriptHash
        self.authorClientHandle = authorClientHandle
        self.reasonDigest = reasonDigest
        self.idempotencyKey = idempotencyKey
        self.createdAt = createdAt
        self.signature = signature
    }

    public static func create(
        id: UUID = UUID(),
        currentState: SignedGroupStateV2,
        authorClientHandle: GroupScopedClientHandleV2,
        reasonDigest: Data? = nil,
        idempotencyKey: Data,
        signingKey: SigningKeyPair,
        createdAt: Date = Date()
    ) throws -> SignedGroupDeletionTombstoneV2 {
        guard currentState.isStructurallyValid,
              currentState.epoch < UInt64.max,
              idempotencyKey.count == 32,
              reasonDigest?.count ?? 32 == 32,
              createdAt >= currentState.signedAt,
              let authorLeaf = currentState.activeClientLeaves.first(where: {
                  $0.clientHandle == authorClientHandle
              }),
              let authorUser = currentState.activeUsers.first(where: {
                  $0.id == authorLeaf.userId
              }),
              currentState.permissions.allows(.deleteGroup, for: authorUser.role),
              authorLeaf.signingPublicKey == signingKey.publicKeyData else {
            throw SignedGroupV2Error.unauthorized
        }
        let selection = GroupProtocolSelectionV2(
            profile: currentState.profile,
            cipherSuite: currentState.cipherSuite
        )
        guard selection.isStructurallyValid else {
            throw SignedGroupV2Error.unsupportedProfile
        }
        var tombstone = SignedGroupDeletionTombstoneV2(
            id: id,
            selection: selection,
            groupId: currentState.groupId,
            baseEpoch: currentState.epoch,
            deletedEpoch: currentState.epoch + 1,
            previousTranscriptHash: currentState.confirmedTranscriptHash,
            authorClientHandle: authorClientHandle,
            reasonDigest: reasonDigest,
            idempotencyKey: idempotencyKey,
            createdAt: createdAt,
            signature: Data()
        )
        let digest = try tombstone.tombstoneDigest()
        tombstone = SignedGroupDeletionTombstoneV2(
            id: tombstone.id,
            selection: tombstone.selection,
            groupId: tombstone.groupId,
            baseEpoch: tombstone.baseEpoch,
            deletedEpoch: tombstone.deletedEpoch,
            previousTranscriptHash: tombstone.previousTranscriptHash,
            authorClientHandle: tombstone.authorClientHandle,
            reasonDigest: tombstone.reasonDigest,
            idempotencyKey: tombstone.idempotencyKey,
            createdAt: tombstone.createdAt,
            signature: try signingKey.sign(
                try GroupDeletionSignatureContextV2(
                    groupId: tombstone.groupId,
                    deletedEpoch: tombstone.deletedEpoch,
                    tombstoneDigest: digest
                ).signableData()
            )
        )
        return try tombstone.verified(against: currentState)
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveSignedGroupV2.version
            && operation == .deleteGroup
            && selection.isStructurallyValid
            && baseEpoch > 0
            && baseEpoch < UInt64.max
            && deletedEpoch == baseEpoch + 1
            && previousTranscriptHash.count == 32
            && authorClientHandle.isStructurallyValid
            && reasonDigest?.count ?? 32 == 32
            && idempotencyKey.count == 32
            && createdAt.timeIntervalSince1970.isFinite
            && signature.count == NoctweaveSignedGroupV2.signatureBytes
    }

    public var digest: Data? {
        try? tombstoneDigest()
    }

    public func verified(
        against currentState: SignedGroupStateV2
    ) throws -> SignedGroupDeletionTombstoneV2 {
        guard isStructurallyValid,
              currentState.isStructurallyValid else {
            throw SignedGroupV2Error.invalidStructure
        }
        guard selection == GroupProtocolSelectionV2(
            profile: currentState.profile,
            cipherSuite: currentState.cipherSuite
        ),
              groupId == currentState.groupId,
              baseEpoch == currentState.epoch,
              deletedEpoch == currentState.epoch + 1,
              previousTranscriptHash == currentState.confirmedTranscriptHash,
              createdAt >= currentState.signedAt else {
            throw SignedGroupV2Error.invalidContext
        }
        guard let authorLeaf = currentState.activeClientLeaves.first(where: {
            $0.clientHandle == authorClientHandle
        }),
              let authorUser = currentState.activeUsers.first(where: {
                  $0.id == authorLeaf.userId
              }),
              currentState.permissions.allows(.deleteGroup, for: authorUser.role),
              let digest,
              SigningKeyPair.verify(
                  signature: signature,
                  data: try GroupDeletionSignatureContextV2(
                      groupId: groupId,
                      deletedEpoch: deletedEpoch,
                      tombstoneDigest: digest
                  ).signableData(),
                  publicKeyData: authorLeaf.signingPublicKey
              ) else {
            throw SignedGroupV2Error.invalidCommitSignature
        }
        return self
    }

    fileprivate var payload: GroupDeletionTombstonePayloadV2 {
        GroupDeletionTombstonePayloadV2(
            version: version,
            id: id,
            operation: operation,
            selection: selection,
            groupId: groupId,
            baseEpoch: baseEpoch,
            deletedEpoch: deletedEpoch,
            previousTranscriptHash: previousTranscriptHash,
            authorClientHandle: authorClientHandle,
            reasonDigest: reasonDigest,
            idempotencyKey: idempotencyKey,
            createdAt: createdAt
        )
    }

    private func tombstoneDigest() throws -> Data {
        try SignedGroupV2Hash.digest(payload)
    }
}

/// Terminal local state retained after a valid deletion. Its transcript binds
/// the prior accepted group transcript and the signed tombstone. There is no
/// conversion back to `SignedGroupStateV2`.
public struct SignedDeletedGroupStateV2: Codable, Equatable, Identifiable {
    public var id: UUID { tombstone.groupId }
    public let version: Int
    public let tombstone: SignedGroupDeletionTombstoneV2
    public let tombstoneDigest: Data
    public let terminalTranscriptHash: Data

    public init(
        version: Int = NoctweaveSignedGroupV2.version,
        tombstone: SignedGroupDeletionTombstoneV2,
        tombstoneDigest: Data,
        terminalTranscriptHash: Data
    ) {
        self.version = version
        self.tombstone = tombstone
        self.tombstoneDigest = tombstoneDigest
        self.terminalTranscriptHash = terminalTranscriptHash
    }

    public static func create(
        tombstone: SignedGroupDeletionTombstoneV2,
        from currentState: SignedGroupStateV2
    ) throws -> SignedDeletedGroupStateV2 {
        _ = try tombstone.verified(against: currentState)
        guard let digest = tombstone.digest else {
            throw SignedGroupV2Error.invalidStructure
        }
        let state = SignedDeletedGroupStateV2(
            tombstone: tombstone,
            tombstoneDigest: digest,
            terminalTranscriptHash: try terminalHash(
                tombstone: tombstone,
                tombstoneDigest: digest
            )
        )
        return try state.verified(previousState: currentState)
    }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveSignedGroupV2.version,
              tombstone.isStructurallyValid,
              tombstone.digest == tombstoneDigest,
              tombstoneDigest.count == 32,
              terminalTranscriptHash.count == 32,
              let expected = try? Self.terminalHash(
                  tombstone: tombstone,
                  tombstoneDigest: tombstoneDigest
              ) else {
            return false
        }
        return expected == terminalTranscriptHash
    }

    public func verified(
        previousState: SignedGroupStateV2
    ) throws -> SignedDeletedGroupStateV2 {
        guard isStructurallyValid else { throw SignedGroupV2Error.invalidStructure }
        _ = try tombstone.verified(against: previousState)
        return self
    }

    /// Any later live state for this group is a resurrection attempt, even if
    /// it carries a numerically higher epoch or a newly generated key set.
    public func rejectResurrection(
        _ candidate: SignedGroupStateV2
    ) throws {
        guard candidate.groupId == tombstone.groupId else {
            throw SignedGroupV2Error.invalidContext
        }
        throw SignedGroupV2Error.groupDeleted
    }

    /// A terminal state cannot consume ordinary live commits.
    public func applying(
        _ commit: SignedGroupCommitV2
    ) throws -> SignedDeletedGroupStateV2 {
        guard commit.groupId == tombstone.groupId else {
            throw SignedGroupV2Error.invalidContext
        }
        throw SignedGroupV2Error.groupDeleted
    }

    private static func terminalHash(
        tombstone: SignedGroupDeletionTombstoneV2,
        tombstoneDigest: Data
    ) throws -> Data {
        try SignedGroupV2Hash.digest(
            GroupDeletionTerminalTranscriptV2(
                selection: tombstone.selection,
                groupId: tombstone.groupId,
                deletedEpoch: tombstone.deletedEpoch,
                previousTranscriptHash: tombstone.previousTranscriptHash,
                tombstoneDigest: tombstoneDigest
            )
        )
    }
}

public struct SignedGroupStateV2: Codable, Equatable, Identifiable {
    public var id: UUID { groupId }
    public let version: Int
    public let profile: GroupProtocolProfile
    public let cipherSuite: String
    public let groupId: UUID
    public let epoch: UInt64
    public let previousTranscriptHash: Data?
    public let users: [GroupUser]
    public let clientLeaves: [GroupClientLeafV2]
    public let permissions: GroupPermissionPolicy
    public let metadataDigest: Data?
    public let authorClientHandle: GroupScopedClientHandleV2
    public let commitDigest: Data
    public let confirmedTranscriptHash: Data
    public let signedAt: Date
    public let signature: Data

    public init(
        version: Int = NoctweaveSignedGroupV2.version,
        profile: GroupProtocolProfile,
        cipherSuite: String,
        groupId: UUID,
        epoch: UInt64,
        previousTranscriptHash: Data?,
        users: [GroupUser],
        clientLeaves: [GroupClientLeafV2],
        permissions: GroupPermissionPolicy,
        metadataDigest: Data?,
        authorClientHandle: GroupScopedClientHandleV2,
        commitDigest: Data,
        confirmedTranscriptHash: Data,
        signedAt: Date,
        signature: Data
    ) {
        self.version = version
        self.profile = profile
        self.cipherSuite = cipherSuite
        self.groupId = groupId
        self.epoch = epoch
        self.previousTranscriptHash = previousTranscriptHash
        self.users = users.sorted { $0.id.uuidString < $1.id.uuidString }
        self.clientLeaves = clientLeaves.sorted {
            $0.clientHandle.rawValue < $1.clientHandle.rawValue
        }
        self.permissions = permissions
        self.metadataDigest = metadataDigest
        self.authorClientHandle = authorClientHandle
        self.commitDigest = commitDigest
        self.confirmedTranscriptHash = confirmedTranscriptHash
        self.signedAt = signedAt
        self.signature = signature
    }

    public static func initial(
        groupId: UUID,
        creator: GroupUser,
        creatorTrust: GroupGenesisTrustV2,
        permissions: GroupPermissionPolicy = .default,
        metadataDigest: Data? = nil,
        providerGenesisDigest: Data,
        signingKey: SigningKeyPair,
        signedAt: Date = Date()
    ) throws -> SignedGroupStateV2 {
        let profile = NoctweaveSignedGroupV2.experimentalProfile
        let cipherSuite = NoctweaveSignedGroupV2.experimentalCipherSuite
        guard creator.id == creatorTrust.creatorUserId,
              creator.role == .owner,
              creator.addedEpoch == 1,
              creator.removedEpoch == nil,
              providerGenesisDigest.count == 32,
              signedAt.timeIntervalSince1970.isFinite else {
            throw SignedGroupV2Error.invalidTransition
        }
        let creatorPackage = try creatorTrust.verified(
            forGroupId: groupId,
            now: signedAt
        )
        guard creatorPackage.groupSigningPublicKey == signingKey.publicKeyData else {
            throw SignedGroupV2Error.unknownAuthor
        }
        let creatorLeaf = try GroupClientLeafV2.fromVerifiedPackage(
            creatorPackage,
            addedEpoch: 1
        )
        let users = [creator]
        let clientLeaves = [creatorLeaf]
        try SignedGroupStateValidatorV2.validate(
            profile: profile,
            cipherSuite: cipherSuite,
            epoch: 1,
            users: users,
            clientLeaves: clientLeaves,
            permissions: permissions,
            metadataDigest: metadataDigest
        )
        let state = try signedState(
            profile: profile,
            cipherSuite: cipherSuite,
            groupId: groupId,
            epoch: 1,
            previousTranscriptHash: nil,
            users: users,
            clientLeaves: clientLeaves,
            permissions: permissions,
            metadataDigest: metadataDigest,
            authorClientHandle: creatorLeaf.clientHandle,
            commitDigest: providerGenesisDigest,
            signingKey: signingKey,
            signedAt: signedAt
        )
        return try state.verified(genesisTrust: creatorTrust)
    }

    public static func applying(
        _ commit: SignedGroupCommitV2,
        to currentState: SignedGroupStateV2,
        signingKey: SigningKeyPair
    ) throws -> SignedGroupStateV2 {
        _ = try commit.verifiedTransition(from: currentState)
        guard let author = currentState.activeClientLeaves.first(where: {
            $0.clientHandle == commit.authorClientHandle
        }), author.signingPublicKey == signingKey.publicKeyData,
              let digest = commit.digest else {
            throw SignedGroupV2Error.unknownAuthor
        }
        let state = try signedState(
            profile: commit.profile,
            cipherSuite: commit.cipherSuite,
            groupId: commit.groupId,
            epoch: commit.nextEpoch,
            previousTranscriptHash: commit.previousTranscriptHash,
            users: commit.proposedUsers,
            clientLeaves: commit.proposedClientLeaves,
            permissions: commit.proposedPermissions,
            metadataDigest: commit.proposedMetadataDigest,
            authorClientHandle: commit.authorClientHandle,
            commitDigest: digest,
            signingKey: signingKey,
            signedAt: commit.createdAt
        )
        return try state.verified(
            previousState: currentState,
            commit: commit
        )
    }

    public var activeUsers: [GroupUser] {
        users.filter { $0.isActive(at: epoch) }
    }

    public var activeClientLeaves: [GroupClientLeafV2] {
        let activeUserIds = Set(activeUsers.map(\.id))
        return clientLeaves.filter { $0.isActive(at: epoch) && activeUserIds.contains($0.userId) }
    }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveSignedGroupV2.version,
              epoch > 0,
              previousTranscriptHash?.count ?? 32 == 32,
              (epoch == 1 ? previousTranscriptHash == nil : previousTranscriptHash != nil),
              authorClientHandle.isStructurallyValid,
              commitDigest.count == 32,
              confirmedTranscriptHash.count == 32,
              signedAt.timeIntervalSince1970.isFinite,
              signature.count == NoctweaveSignedGroupV2.signatureBytes,
              let expectedHash = try? SignedGroupV2Hash.digest(transcriptPayload),
              expectedHash == confirmedTranscriptHash,
              let encoded = try? NoctweaveCoder.encode(transcriptPayload, sortedKeys: true),
              encoded.count <= NoctweaveSignedGroupV2.maximumStateBytes else {
            return false
        }
        return (try? SignedGroupStateValidatorV2.validate(
            profile: profile,
            cipherSuite: cipherSuite,
            epoch: epoch,
            users: users,
            clientLeaves: clientLeaves,
            permissions: permissions,
            metadataDigest: metadataDigest
        )) != nil
    }

    public var digest: Data? {
        guard let data = try? NoctweaveCoder.encode(self, sortedKeys: true) else { return nil }
        return Data(SHA256.hash(data: data))
    }

    public func verified(
        previousState: SignedGroupStateV2? = nil,
        commit: SignedGroupCommitV2? = nil,
        genesisTrust: GroupGenesisTrustV2? = nil
    ) throws -> SignedGroupStateV2 {
        guard isStructurallyValid else { throw SignedGroupV2Error.invalidStructure }
        let authorKey: Data
        if let previousState {
            guard epoch == previousState.epoch + 1,
                  groupId == previousState.groupId,
                  profile == previousState.profile,
                  cipherSuite == previousState.cipherSuite else {
                throw SignedGroupV2Error.staleEpoch
            }
            guard previousTranscriptHash == previousState.confirmedTranscriptHash else {
                throw SignedGroupV2Error.transcriptMismatch
            }
            guard let commit else { throw SignedGroupV2Error.invalidTransition }
            _ = try commit.verifiedTransition(from: previousState)
            guard commit.groupId == groupId,
                  commit.nextEpoch == epoch,
                  commit.proposedUsers == users,
                  commit.proposedClientLeaves == clientLeaves,
                  commit.proposedPermissions == permissions,
                  commit.proposedMetadataDigest == metadataDigest,
                  commit.authorClientHandle == authorClientHandle,
                  commit.digest == commitDigest,
                  commit.createdAt == signedAt else {
                throw SignedGroupV2Error.invalidTransition
            }
            guard let author = previousState.activeClientLeaves.first(where: {
                $0.clientHandle == authorClientHandle
            }) else {
                throw SignedGroupV2Error.unknownAuthor
            }
            authorKey = author.signingPublicKey
        } else {
            guard let genesisTrust else { throw SignedGroupV2Error.genesisTrustRequired }
            guard epoch == 1,
                  previousTranscriptHash == nil,
                  commit == nil,
                  users.count == 1,
                  clientLeaves.count == 1,
                  let creator = users.first,
                  creator.id == genesisTrust.creatorUserId,
                  creator.role == .owner,
                  creator.addedEpoch == 1,
                  creator.removedEpoch == nil else {
                throw SignedGroupV2Error.invalidTransition
            }
            let creatorPackage = try genesisTrust.verified(
                forGroupId: groupId,
                now: signedAt
            )
            let expectedLeaf = try GroupClientLeafV2.fromVerifiedPackage(
                creatorPackage,
                addedEpoch: 1
            )
            guard clientLeaves[0] == expectedLeaf,
                  authorClientHandle == expectedLeaf.clientHandle else {
                throw SignedGroupV2Error.keyPackageMismatch
            }
            authorKey = creatorPackage.groupSigningPublicKey
        }
        let signatureData = try GroupStateSignatureContextV2(
            groupId: groupId,
            profile: profile,
            epoch: epoch,
            transcriptHash: confirmedTranscriptHash,
            commitDigest: commitDigest
        ).signableData()
        guard SigningKeyPair.verify(signature: signature, data: signatureData, publicKeyData: authorKey) else {
            throw SignedGroupV2Error.invalidStateSignature
        }
        return self
    }

    fileprivate var transcriptPayload: GroupStateTranscriptPayloadV2 {
        GroupStateTranscriptPayloadV2(
            version: version,
            profile: profile,
            cipherSuite: cipherSuite,
            groupId: groupId,
            epoch: epoch,
            previousTranscriptHash: previousTranscriptHash,
            users: users,
            clientLeaves: clientLeaves,
            permissions: permissions,
            metadataDigest: metadataDigest,
            authorClientHandle: authorClientHandle,
            commitDigest: commitDigest,
            signedAt: signedAt
        )
    }

    private static func signedState(
        profile: GroupProtocolProfile,
        cipherSuite: String,
        groupId: UUID,
        epoch: UInt64,
        previousTranscriptHash: Data?,
        users: [GroupUser],
        clientLeaves: [GroupClientLeafV2],
        permissions: GroupPermissionPolicy,
        metadataDigest: Data?,
        authorClientHandle: GroupScopedClientHandleV2,
        commitDigest: Data,
        signingKey: SigningKeyPair,
        signedAt: Date
    ) throws -> SignedGroupStateV2 {
        let orderedUsers = users.sorted { $0.id.uuidString < $1.id.uuidString }
        let orderedLeaves = clientLeaves.sorted { $0.clientHandle.rawValue < $1.clientHandle.rawValue }
        try SignedGroupStateValidatorV2.validate(
            profile: profile,
            cipherSuite: cipherSuite,
            epoch: epoch,
            users: orderedUsers,
            clientLeaves: orderedLeaves,
            permissions: permissions,
            metadataDigest: metadataDigest
        )
        let payload = GroupStateTranscriptPayloadV2(
            version: NoctweaveSignedGroupV2.version,
            profile: profile,
            cipherSuite: cipherSuite,
            groupId: groupId,
            epoch: epoch,
            previousTranscriptHash: previousTranscriptHash,
            users: orderedUsers,
            clientLeaves: orderedLeaves,
            permissions: permissions,
            metadataDigest: metadataDigest,
            authorClientHandle: authorClientHandle,
            commitDigest: commitDigest,
            signedAt: signedAt
        )
        let transcriptHash = try SignedGroupV2Hash.digest(payload)
        let signatureData = try GroupStateSignatureContextV2(
            groupId: groupId,
            profile: profile,
            epoch: epoch,
            transcriptHash: transcriptHash,
            commitDigest: commitDigest
        ).signableData()
        return SignedGroupStateV2(
            profile: profile,
            cipherSuite: cipherSuite,
            groupId: groupId,
            epoch: epoch,
            previousTranscriptHash: previousTranscriptHash,
            users: orderedUsers,
            clientLeaves: orderedLeaves,
            permissions: permissions,
            metadataDigest: metadataDigest,
            authorClientHandle: authorClientHandle,
            commitDigest: commitDigest,
            confirmedTranscriptHash: transcriptHash,
            signedAt: signedAt,
            signature: try signingKey.sign(signatureData)
        )
    }
}

public struct SignedGroupWelcomeV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let version: Int
    public let profile: GroupProtocolProfile
    public let cipherSuite: String
    public let groupId: UUID
    public let epoch: UInt64
    public let stateTranscriptHash: Data
    public let commitDigest: Data
    public let authorClientHandle: GroupScopedClientHandleV2
    public let destinationClientHandle: GroupScopedClientHandleV2
    public let destinationKeyPackageDigest: Data
    public let encryptedWelcome: Data
    public let createdAt: Date
    public let expiresAt: Date
    public let signature: Data

    public init(
        id: UUID,
        version: Int = NoctweaveSignedGroupV2.version,
        profile: GroupProtocolProfile,
        cipherSuite: String,
        groupId: UUID,
        epoch: UInt64,
        stateTranscriptHash: Data,
        commitDigest: Data,
        authorClientHandle: GroupScopedClientHandleV2,
        destinationClientHandle: GroupScopedClientHandleV2,
        destinationKeyPackageDigest: Data,
        encryptedWelcome: Data,
        createdAt: Date,
        expiresAt: Date,
        signature: Data
    ) {
        self.id = id
        self.version = version
        self.profile = profile
        self.cipherSuite = cipherSuite
        self.groupId = groupId
        self.epoch = epoch
        self.stateTranscriptHash = stateTranscriptHash
        self.commitDigest = commitDigest
        self.authorClientHandle = authorClientHandle
        self.destinationClientHandle = destinationClientHandle
        self.destinationKeyPackageDigest = destinationKeyPackageDigest
        self.encryptedWelcome = encryptedWelcome
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.signature = signature
    }

    public static func create(
        id: UUID = UUID(),
        state: SignedGroupStateV2,
        destinationClientHandle: GroupScopedClientHandleV2,
        encryptedWelcome: Data,
        signingKey: SigningKeyPair,
        createdAt: Date = Date(),
        expiresAt: Date
    ) throws -> SignedGroupWelcomeV2 {
        guard state.isStructurallyValid,
              let author = state.activeClientLeaves.first(where: {
                  $0.clientHandle == state.authorClientHandle
              }), author.signingPublicKey == signingKey.publicKeyData,
              let destination = state.activeClientLeaves.first(where: {
                  $0.clientHandle == destinationClientHandle
              }) else {
            throw SignedGroupV2Error.unknownAuthor
        }
        var welcome = SignedGroupWelcomeV2(
            id: id,
            profile: state.profile,
            cipherSuite: state.cipherSuite,
            groupId: state.groupId,
            epoch: state.epoch,
            stateTranscriptHash: state.confirmedTranscriptHash,
            commitDigest: state.commitDigest,
            authorClientHandle: state.authorClientHandle,
            destinationClientHandle: destinationClientHandle,
            destinationKeyPackageDigest: destination.keyPackageDigest,
            encryptedWelcome: encryptedWelcome,
            createdAt: createdAt,
            expiresAt: expiresAt,
            signature: Data()
        )
        guard welcome.isStructurallyValid(excludingSignature: true) else {
            throw SignedGroupV2Error.invalidStructure
        }
        welcome = SignedGroupWelcomeV2(
            id: welcome.id,
            profile: welcome.profile,
            cipherSuite: welcome.cipherSuite,
            groupId: welcome.groupId,
            epoch: welcome.epoch,
            stateTranscriptHash: welcome.stateTranscriptHash,
            commitDigest: welcome.commitDigest,
            authorClientHandle: welcome.authorClientHandle,
            destinationClientHandle: welcome.destinationClientHandle,
            destinationKeyPackageDigest: welcome.destinationKeyPackageDigest,
            encryptedWelcome: welcome.encryptedWelcome,
            createdAt: welcome.createdAt,
            expiresAt: welcome.expiresAt,
            signature: try signingKey.sign(try welcome.signatureContext().signableData())
        )
        return try welcome.verified(against: state, now: createdAt)
    }

    public var isStructurallyValid: Bool {
        isStructurallyValid(excludingSignature: false)
    }

    public func verified(
        against state: SignedGroupStateV2,
        now: Date = Date()
    ) throws -> SignedGroupWelcomeV2 {
        guard isStructurallyValid else { throw SignedGroupV2Error.invalidStructure }
        guard now.timeIntervalSince1970.isFinite,
              createdAt <= now.addingTimeInterval(NoctweaveSignedGroupV2.maximumClockSkewSeconds),
              now < expiresAt else {
            throw SignedGroupV2Error.invalidStructure
        }
        guard profile == state.profile,
              cipherSuite == state.cipherSuite,
              groupId == state.groupId,
              epoch == state.epoch,
              stateTranscriptHash == state.confirmedTranscriptHash,
              commitDigest == state.commitDigest else {
            throw SignedGroupV2Error.invalidContext
        }
        guard let destination = state.activeClientLeaves.first(where: {
            $0.clientHandle == destinationClientHandle
        }), destination.keyPackageDigest == destinationKeyPackageDigest else {
            throw SignedGroupV2Error.keyPackageMismatch
        }
        guard let author = state.activeClientLeaves.first(where: {
            $0.clientHandle == authorClientHandle
        }) else {
            throw SignedGroupV2Error.unknownAuthor
        }
        guard SigningKeyPair.verify(
            signature: signature,
            data: try signatureContext().signableData(),
            publicKeyData: author.signingPublicKey
        ) else {
            throw SignedGroupV2Error.invalidWelcomeSignature
        }
        return self
    }

    private func isStructurallyValid(excludingSignature: Bool) -> Bool {
        version == NoctweaveSignedGroupV2.version
            && profile == NoctweaveSignedGroupV2.experimentalProfile
            && cipherSuite == NoctweaveSignedGroupV2.experimentalCipherSuite
            && epoch > 0
            && stateTranscriptHash.count == 32
            && commitDigest.count == 32
            && authorClientHandle.isStructurallyValid
            && destinationClientHandle.isStructurallyValid
            && destinationKeyPackageDigest.count == 32
            && !encryptedWelcome.isEmpty
            && encryptedWelcome.count <= NoctweaveGroupArchitectureV2.maximumWelcomeBytes
            && createdAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && expiresAt > createdAt
            && expiresAt.timeIntervalSince(createdAt)
                <= NoctweaveSignedGroupV2.maximumWelcomeLifetimeSeconds
            && (excludingSignature || signature.count == NoctweaveSignedGroupV2.signatureBytes)
    }

    private func signatureContext() throws -> GroupWelcomeSignatureContextV2 {
        GroupWelcomeSignatureContextV2(
            id: id,
            profile: profile,
            cipherSuite: cipherSuite,
            groupId: groupId,
            epoch: epoch,
            stateTranscriptHash: stateTranscriptHash,
            commitDigest: commitDigest,
            authorClientHandle: authorClientHandle,
            destinationClientHandle: destinationClientHandle,
            destinationKeyPackageDigest: destinationKeyPackageDigest,
            encryptedWelcomeDigest: SignedGroupV2Hash.digest(encryptedWelcome),
            createdAt: createdAt,
            expiresAt: expiresAt
        )
    }
}

private enum SignedGroupStateValidatorV2 {
    static func validate(
        profile: GroupProtocolProfile,
        cipherSuite: String,
        epoch: UInt64,
        users: [GroupUser],
        clientLeaves: [GroupClientLeafV2],
        permissions: GroupPermissionPolicy,
        metadataDigest: Data?
    ) throws {
        guard profile == NoctweaveSignedGroupV2.experimentalProfile,
              cipherSuite == NoctweaveSignedGroupV2.experimentalCipherSuite else {
            throw SignedGroupV2Error.unsupportedProfile
        }
        guard epoch > 0,
              !users.isEmpty,
              users.count <= NoctweaveGroupArchitectureV2.maximumUsers,
              !clientLeaves.isEmpty,
              clientLeaves.count <= NoctweaveGroupArchitectureV2.maximumClientLeaves,
              Set(users.map(\.id)).count == users.count,
              Set(clientLeaves.map(\.clientHandle)).count == clientLeaves.count,
              Set(clientLeaves.map(\.keyPackageDigest)).count == clientLeaves.count,
              Set(clientLeaves.map(\.signingPublicKey)).count == clientLeaves.count,
              Set(clientLeaves.map(\.agreementPublicKey)).count == clientLeaves.count,
              permissions.isStructurallyValid,
              metadataDigest?.count ?? 32 == 32,
              users.allSatisfy({
                  $0.isStructurallyValid
                      && $0.addedEpoch <= epoch
                      && ($0.removedEpoch.map { $0 <= epoch } ?? true)
              }),
              clientLeaves.allSatisfy({
                  $0.isStructurallyValid
                      && $0.addedEpoch <= epoch
                      && ($0.removedEpoch.map { $0 <= epoch } ?? true)
              }) else {
            throw SignedGroupV2Error.invalidStructure
        }
        let usersById = Dictionary(uniqueKeysWithValues: users.map { ($0.id, $0) })
        guard clientLeaves.allSatisfy({ leaf in
            guard let user = usersById[leaf.userId] else { return false }
            return leaf.addedEpoch >= user.addedEpoch
                && (user.removedEpoch.map { removal in
                    leaf.removedEpoch.map { $0 <= removal } ?? false
                } ?? true)
        }) else {
            throw SignedGroupV2Error.invalidStructure
        }
        let activeUsers = users.filter { $0.isActive(at: epoch) }
        let activeUserIds = Set(activeUsers.map(\.id))
        let activeLeaves = clientLeaves.filter {
            $0.isActive(at: epoch) && activeUserIds.contains($0.userId)
        }
        guard activeLeaves.count <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalClientLeaves else {
            throw SignedGroupV2Error.activeLeafLimitExceeded
        }
        guard activeUsers.allSatisfy({ user in
            activeLeaves.contains { $0.userId == user.id }
        }), clientLeaves.filter({ $0.isActive(at: epoch) }).allSatisfy({
            activeUserIds.contains($0.userId)
        }) else {
            throw SignedGroupV2Error.invalidTransition
        }
        let activeOwnerIds = Set(activeUsers.filter { $0.role == .owner }.map(\.id))
        guard !activeOwnerIds.isEmpty,
              activeLeaves.contains(where: { activeOwnerIds.contains($0.userId) }) else {
            throw SignedGroupV2Error.wouldRemoveLastOwner
        }
    }
}

private enum SignedGroupTransitionValidatorV2 {
    static func validate(
        operation: SignedGroupCommitOperationV2,
        currentState: SignedGroupStateV2,
        proposedUsers: [GroupUser],
        proposedClientLeaves: [GroupClientLeafV2],
        proposedPermissions: GroupPermissionPolicy,
        proposedMetadataDigest: Data?,
        actorUser: GroupUser,
        actorLeaf: GroupClientLeafV2,
        verifiedAddedLeaf: GroupClientLeafV2?,
        nextEpoch: UInt64
    ) throws {
        let oldUsers = dictionary(currentState.users, by: { $0.id })
        let newUsers = dictionary(proposedUsers, by: { $0.id })
        let oldLeaves = dictionary(currentState.clientLeaves, by: { $0.clientHandle })
        let newLeaves = dictionary(proposedClientLeaves, by: { $0.clientHandle })
        guard oldUsers.count == currentState.users.count,
              newUsers.count == proposedUsers.count,
              oldLeaves.count == currentState.clientLeaves.count,
              newLeaves.count == proposedClientLeaves.count else {
            throw SignedGroupV2Error.invalidTransition
        }

        switch operation {
        case .addClient:
            try requirePermission(.addClient, state: currentState, actor: actorUser)
            guard proposedUsers == currentState.users,
                  proposedPermissions == currentState.permissions,
                  proposedMetadataDigest == currentState.metadataDigest,
                  Set(oldLeaves.keys).isSubset(of: Set(newLeaves.keys)),
                  newLeaves.count == oldLeaves.count + 1,
                  oldLeaves.allSatisfy({ newLeaves[$0.key] == $0.value }),
                  let added = newLeaves.first(where: { oldLeaves[$0.key] == nil })?.value,
                  added == verifiedAddedLeaf,
                  added.addedEpoch == nextEpoch,
                  added.removedEpoch == nil,
                  currentState.activeUsers.contains(where: { $0.id == added.userId }) else {
                throw SignedGroupV2Error.invalidTransition
            }

        case .removeClient:
            guard proposedUsers == currentState.users,
                  proposedPermissions == currentState.permissions,
                  proposedMetadataDigest == currentState.metadataDigest,
                  Set(oldLeaves.keys) == Set(newLeaves.keys) else {
                throw SignedGroupV2Error.invalidTransition
            }
            let changed = oldLeaves.compactMap { key, old -> (GroupClientLeafV2, GroupClientLeafV2)? in
                guard let new = newLeaves[key], new != old else { return nil }
                return (old, new)
            }
            guard changed.count == 1,
                  isRemoval(from: changed[0].0, to: changed[0].1, at: nextEpoch),
                  changed[0].0.isActive(at: currentState.epoch),
                  let targetUser = currentState.activeUsers.first(where: {
                      $0.id == changed[0].0.userId
                  }) else {
                throw SignedGroupV2Error.invalidTransition
            }
            let isSelf = targetUser.id == actorUser.id
                && changed[0].0.clientHandle == actorLeaf.clientHandle
            if !isSelf {
                try requirePermission(.removeClient, state: currentState, actor: actorUser)
                try requireMayModerate(actor: actorUser, target: targetUser)
            }

        case .addUser:
            try requirePermission(.addClient, state: currentState, actor: actorUser)
            guard proposedPermissions == currentState.permissions,
                  proposedMetadataDigest == currentState.metadataDigest,
                  Set(oldUsers.keys).isSubset(of: Set(newUsers.keys)),
                  newUsers.count == oldUsers.count + 1,
                  oldUsers.allSatisfy({ newUsers[$0.key] == $0.value }),
                  Set(oldLeaves.keys).isSubset(of: Set(newLeaves.keys)),
                  newLeaves.count == oldLeaves.count + 1,
                  oldLeaves.allSatisfy({ newLeaves[$0.key] == $0.value }),
                  let addedUser = newUsers.first(where: { oldUsers[$0.key] == nil })?.value,
                  let addedLeaf = newLeaves.first(where: { oldLeaves[$0.key] == nil })?.value,
                  addedLeaf == verifiedAddedLeaf,
                  addedUser.addedEpoch == nextEpoch,
                  addedUser.removedEpoch == nil,
                  addedLeaf.userId == addedUser.id,
                  addedLeaf.addedEpoch == nextEpoch,
                  addedLeaf.removedEpoch == nil,
                  roleRank(addedUser.role) <= roleRank(actorUser.role) else {
                throw SignedGroupV2Error.invalidTransition
            }

        case .removeUser:
            guard proposedPermissions == currentState.permissions,
                  proposedMetadataDigest == currentState.metadataDigest,
                  Set(oldUsers.keys) == Set(newUsers.keys),
                  Set(oldLeaves.keys) == Set(newLeaves.keys) else {
                throw SignedGroupV2Error.invalidTransition
            }
            let changedUsers = oldUsers.compactMap { key, old -> (GroupUser, GroupUser)? in
                guard let new = newUsers[key], new != old else { return nil }
                return (old, new)
            }
            guard changedUsers.count == 1,
                  isRemoval(from: changedUsers[0].0, to: changedUsers[0].1, at: nextEpoch),
                  changedUsers[0].0.isActive(at: currentState.epoch) else {
                throw SignedGroupV2Error.invalidTransition
            }
            let target = changedUsers[0].0
            for (handle, oldLeaf) in oldLeaves {
                guard let newLeaf = newLeaves[handle] else {
                    throw SignedGroupV2Error.invalidTransition
                }
                if oldLeaf.userId == target.id && oldLeaf.isActive(at: currentState.epoch) {
                    guard isRemoval(from: oldLeaf, to: newLeaf, at: nextEpoch) else {
                        throw SignedGroupV2Error.invalidTransition
                    }
                } else if oldLeaf != newLeaf {
                    throw SignedGroupV2Error.invalidTransition
                }
            }
            if target.id != actorUser.id {
                try requirePermission(.removeClient, state: currentState, actor: actorUser)
                try requireMayModerate(actor: actorUser, target: target)
            }

        case .changeRole:
            try requirePermission(.updatePolicy, state: currentState, actor: actorUser)
            guard proposedPermissions == currentState.permissions,
                  proposedMetadataDigest == currentState.metadataDigest,
                  proposedClientLeaves == currentState.clientLeaves,
                  Set(oldUsers.keys) == Set(newUsers.keys) else {
                throw SignedGroupV2Error.invalidTransition
            }
            let changed = oldUsers.compactMap { key, old -> (GroupUser, GroupUser)? in
                guard let new = newUsers[key], new != old else { return nil }
                return (old, new)
            }
            guard changed.count == 1,
                  changed[0].0.id == changed[0].1.id,
                  changed[0].0.addedEpoch == changed[0].1.addedEpoch,
                  changed[0].0.removedEpoch == changed[0].1.removedEpoch,
                  changed[0].0.role != changed[0].1.role,
                  changed[0].0.isActive(at: currentState.epoch) else {
                throw SignedGroupV2Error.invalidTransition
            }
            try requireMayChangeRole(
                actor: actorUser,
                target: changed[0].0,
                newRole: changed[0].1.role
            )

        case .changePolicy:
            try requirePermission(.updatePolicy, state: currentState, actor: actorUser)
            guard proposedUsers == currentState.users,
                  proposedClientLeaves == currentState.clientLeaves,
                  proposedMetadataDigest == currentState.metadataDigest,
                  proposedPermissions != currentState.permissions,
                  proposedPermissions.isStructurallyValid else {
                throw SignedGroupV2Error.invalidTransition
            }

        case .updateMetadata:
            try requirePermission(.updateMetadata, state: currentState, actor: actorUser)
            guard proposedUsers == currentState.users,
                  proposedClientLeaves == currentState.clientLeaves,
                  proposedPermissions == currentState.permissions,
                  proposedMetadataDigest != currentState.metadataDigest,
                  proposedMetadataDigest?.count ?? 32 == 32 else {
                throw SignedGroupV2Error.invalidTransition
            }

        case .deleteGroup:
            // Deletion is a terminal tombstone, never another live state.
            throw SignedGroupV2Error.invalidTransition
        }
    }

    private static func requirePermission(
        _ permission: GroupPermission,
        state: SignedGroupStateV2,
        actor: GroupUser
    ) throws {
        guard state.permissions.allows(permission, for: actor.role) else {
            throw SignedGroupV2Error.unauthorized
        }
    }

    private static func requireMayModerate(actor: GroupUser, target: GroupUser) throws {
        guard actor.role == .owner || roleRank(actor.role) > roleRank(target.role) else {
            throw SignedGroupV2Error.unauthorized
        }
    }

    /// Self-service role changes are strict demotions only. Changing another
    /// user requires the actor to outrank the target before the change, and the
    /// actor cannot grant a role above their own. The state validator separately
    /// preserves the invariant that at least one active owner remains.
    private static func requireMayChangeRole(
        actor: GroupUser,
        target: GroupUser,
        newRole: GroupRole
    ) throws {
        let actorRank = roleRank(actor.role)
        let targetRank = roleRank(target.role)
        let newRank = roleRank(newRole)
        if actor.id == target.id {
            guard newRank < actorRank else {
                throw SignedGroupV2Error.unauthorized
            }
            return
        }
        guard actorRank > targetRank, newRank <= actorRank else {
            throw SignedGroupV2Error.unauthorized
        }
    }

    private static func roleRank(_ role: GroupRole) -> Int {
        switch role {
        case .member: return 0
        case .admin: return 1
        case .owner: return 2
        }
    }

    private static func isRemoval(
        from old: GroupUser,
        to new: GroupUser,
        at epoch: UInt64
    ) -> Bool {
        old.id == new.id
            && old.role == new.role
            && old.addedEpoch == new.addedEpoch
            && old.removedEpoch == nil
            && new.removedEpoch == epoch
    }

    private static func isRemoval(
        from old: GroupClientLeafV2,
        to new: GroupClientLeafV2,
        at epoch: UInt64
    ) -> Bool {
        old.userId == new.userId
            && old.clientHandle == new.clientHandle
            && old.keyPackageDigest == new.keyPackageDigest
            && old.signingPublicKey == new.signingPublicKey
            && old.agreementPublicKey == new.agreementPublicKey
            && old.addedEpoch == new.addedEpoch
            && old.removedEpoch == nil
            && new.removedEpoch == epoch
    }

    private static func dictionary<Element, Key: Hashable>(
        _ elements: [Element],
        by key: (Element) -> Key
    ) -> [Key: Element] {
        var result: [Key: Element] = [:]
        for element in elements { result[key(element)] = element }
        return result
    }
}

fileprivate struct GroupClientAdmissionProjectionPayloadV2: Encodable {
    let version: Int
    let id: UUID
    let groupId: UUID
    let groupUserId: UUID
    let clientHandle: GroupScopedClientHandleV2
    let selection: GroupProtocolSelectionV2
    let groupSigningPublicKey: Data
    let groupAgreementPublicKey: Data
    let issuedAt: Date
    let expiresAt: Date
}

private struct GroupAdmissionProjectionSignatureContextV2: Encodable {
    let purpose = "Noctweave/group-client-admission-projection/v2"
    let groupId: UUID
    let groupUserId: UUID
    let clientHandle: GroupScopedClientHandleV2
    let payloadDigest: Data

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

private struct GroupSiblingConsentSignatureContextV2: Encodable {
    let purpose = "Noctweave/group-sibling-client-consent/v2"
    let groupId: UUID
    let groupUserId: UUID
    let newClientHandle: GroupScopedClientHandleV2
    let projectionDigest: Data
    let consentingClientHandle: GroupScopedClientHandleV2
    let baseEpoch: UInt64
    let nextEpoch: UInt64
    let signedAt: Date

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

fileprivate struct GroupDeletionTombstonePayloadV2: Encodable {
    let version: Int
    let id: UUID
    let operation: SignedGroupCommitOperationV2
    let selection: GroupProtocolSelectionV2
    let groupId: UUID
    let baseEpoch: UInt64
    let deletedEpoch: UInt64
    let previousTranscriptHash: Data
    let authorClientHandle: GroupScopedClientHandleV2
    let reasonDigest: Data?
    let idempotencyKey: Data
    let createdAt: Date
}

private struct GroupDeletionSignatureContextV2: Encodable {
    let purpose = "Noctweave/group-deletion-tombstone/v2"
    let groupId: UUID
    let deletedEpoch: UInt64
    let tombstoneDigest: Data

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

private struct GroupDeletionTerminalTranscriptV2: Encodable {
    let purpose = "Noctweave/group-deleted-terminal-state/v2"
    let selection: GroupProtocolSelectionV2
    let groupId: UUID
    let deletedEpoch: UInt64
    let previousTranscriptHash: Data
    let tombstoneDigest: Data
}

private struct GroupClientKeyPackagePayloadV2: Encodable {
    let version: Int
    let id: UUID
    let groupId: UUID
    let groupUserId: UUID
    let clientHandle: GroupScopedClientHandleV2
    let identityGenerationId: UUID
    let manifestEpoch: UInt64
    let manifestDigest: Data
    let installationId: UUID
    let installationSigningPublicKey: Data
    let installationAgreementPublicKey: Data
    let groupSigningPublicKey: Data
    let groupAgreementPublicKey: Data
    let capabilities: ProtocolCapabilityManifest
    let issuedAt: Date
    let expiresAt: Date
}

private struct GroupKeyPackageAuthorityContextV2: Encodable {
    let purpose = "Noctweave/group-client-key-package-authority/v2"
    let payloadDigest: Data
    func signableData() throws -> Data { try NoctweaveCoder.encode(self, sortedKeys: true) }
}

private struct GroupKeyPackageInstallationContextV2: Encodable {
    let purpose = "Noctweave/group-client-key-package-installation-possession/v2"
    let payloadDigest: Data
    let authoritySignatureDigest: Data
    func signableData() throws -> Data { try NoctweaveCoder.encode(self, sortedKeys: true) }
}

private struct GroupKeyPackageClientContextV2: Encodable {
    let purpose = "Noctweave/group-client-key-package-group-possession/v2"
    let payloadDigest: Data
    let authoritySignatureDigest: Data
    let installationSignatureDigest: Data
    func signableData() throws -> Data { try NoctweaveCoder.encode(self, sortedKeys: true) }
}

fileprivate struct GroupCommitPayloadV2: Encodable {
    let version: Int
    let id: UUID
    let profile: GroupProtocolProfile
    let cipherSuite: String
    let groupId: UUID
    let operation: SignedGroupCommitOperationV2
    let baseEpoch: UInt64
    let nextEpoch: UInt64
    let previousTranscriptHash: Data
    let proposedUsers: [GroupUser]
    let proposedClientLeaves: [GroupClientLeafV2]
    let admissionProjection: GroupClientAdmissionProjectionV2?
    let siblingClientConsent: GroupSiblingClientConsentV2?
    let proposedPermissions: GroupPermissionPolicy
    let proposedMetadataDigest: Data?
    let authorClientHandle: GroupScopedClientHandleV2
    let providerCommitDigest: Data
    let idempotencyKey: Data
    let createdAt: Date
}

private struct GroupCommitSignatureContextV2: Encodable {
    let purpose = "Noctweave/signed-group-commit/v2"
    let groupId: UUID
    let profile: GroupProtocolProfile
    let nextEpoch: UInt64
    let commitDigest: Data
    func signableData() throws -> Data { try NoctweaveCoder.encode(self, sortedKeys: true) }
}

fileprivate struct GroupStateTranscriptPayloadV2: Encodable {
    let version: Int
    let profile: GroupProtocolProfile
    let cipherSuite: String
    let groupId: UUID
    let epoch: UInt64
    let previousTranscriptHash: Data?
    let users: [GroupUser]
    let clientLeaves: [GroupClientLeafV2]
    let permissions: GroupPermissionPolicy
    let metadataDigest: Data?
    let authorClientHandle: GroupScopedClientHandleV2
    let commitDigest: Data
    let signedAt: Date
}

private struct GroupStateSignatureContextV2: Encodable {
    let purpose = "Noctweave/signed-group-state/v2"
    let groupId: UUID
    let profile: GroupProtocolProfile
    let epoch: UInt64
    let transcriptHash: Data
    let commitDigest: Data
    func signableData() throws -> Data { try NoctweaveCoder.encode(self, sortedKeys: true) }
}

private struct GroupWelcomeSignatureContextV2: Encodable {
    let purpose = "Noctweave/signed-group-welcome/v2"
    let id: UUID
    let profile: GroupProtocolProfile
    let cipherSuite: String
    let groupId: UUID
    let epoch: UInt64
    let stateTranscriptHash: Data
    let commitDigest: Data
    let authorClientHandle: GroupScopedClientHandleV2
    let destinationClientHandle: GroupScopedClientHandleV2
    let destinationKeyPackageDigest: Data
    let encryptedWelcomeDigest: Data
    let createdAt: Date
    let expiresAt: Date
    func signableData() throws -> Data { try NoctweaveCoder.encode(self, sortedKeys: true) }
}

private enum SignedGroupV2Hash {
    static func digest<T: Encodable>(_ value: T) throws -> Data {
        Data(SHA256.hash(data: try NoctweaveCoder.encode(value, sortedKeys: true)))
    }

    static func digest(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}
