import CryptoKit
import Foundation

public enum NoctweaveArchitectureV2 {
    public static let version = 2
    public static let maximumInstallations = 16
    public static let maximumIssuedContactEndpoints = 64
    public static let maximumDeliveryStates = 4_096
    public static let maximumMailboxConsumerHistory = 64
    public static let maximumModules = 64
    public static let maximumModuleNameBytes = 96
    public static let maximumModuleVersions = 8
    public static let maximumContentTypeBytes = 96
    public static let maximumContentParameters = 32
    public static let maximumContentParameterBytes = 256
    public static let maximumContentPayloadBytes = PaddedMessagePlaintext.maximumPaddedBytes
    public static let maximumFallbackBytes = 2_048
    public static let maximumRoutes = 8
    public static let maximumCursorBytes = 512
    public static let maximumIntentDependencies = 32
    public static let maximumIntentAttempts = 64
    public static let maximumPendingDirectDeliveries = 1_024
    public static let maximumProtocolIntents = 1_024
    public static let maximumInboundEnvelopeReceipts = 4_096
    public static let maximumQuarantinedTransportEnvelopes = 512
    public static let maximumQuarantinedControlEvents = 128
    public static let maximumRelationshipEvents = 4_096
    public static let relationshipEventRecentWindow = 3_072
    public static let maximumEndpointAdmissionLifetime: TimeInterval = 10 * 60
    public static let maximumEndpointCleanupObligations = 8
    public static let maximumPendingEndpointRemovals = 64
}

/// Bounded replay receipt for one successfully verified and durably processed
/// direct envelope. The source scope and logical event ID catch one relationship
/// reusing an event ID with a different envelope ID without treating unrelated
/// contacts as a global namespace; the digest catches mutation under the same
/// envelope ID. Receipts are a recent replay cache, not message history: once
/// compacted out, an old replay is decrypted again and rejected by the ratchet
/// instead of being skipped without verification.
public struct InboundEnvelopeReceiptV2: Codable, Equatable, Identifiable {
    /// Sentinel used only when decoding the pre-scope architecture-v2 cache.
    /// Legacy entries remain useful for exact envelope replay, but do not claim
    /// a globally unique logical event ID across unrelated relationships.
    public static let legacyUnscopedSourceId = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!

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
            && (self.sourceScopeId == sourceScopeId
                || self.sourceScopeId == Self.legacyUnscopedSourceId)
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
        sourceScopeId = try container.decodeIfPresent(UUID.self, forKey: .sourceScopeId)
            ?? Self.legacyUnscopedSourceId
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
    case incompatibleProfile
    case invalidAttribution
    case invalidCiphertext
    case replayConflict
    case unsupportedPayload
}

/// Bounded local dead-letter receipt for a permanently invalid relay event.
/// It contains no plaintext or sender key material. Persisting this receipt
/// before committing the mailbox cursor prevents one hostile envelope from
/// permanently blocking every later event in the ordered stream.
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

public struct ProtocolCapabilityManifest: Codable, Equatable {
    /// Complete registry of module identifiers understood by this release.
    /// Presence here is descriptive only: it does not claim that an endpoint
    /// has wired or enabled the module.
    public static let knownModuleCatalog: [ProtocolModuleCapability] = [
        ProtocolModuleCapability(module: "nw.core", versions: [2], status: .provisional),
        ProtocolModuleCapability(module: "nw.mailbox", versions: [2], status: .provisional),
        ProtocolModuleCapability(module: "nw.prekeys", versions: [2], status: .stable),
        ProtocolModuleCapability(module: "nw.events", versions: [2], status: .provisional),
        ProtocolModuleCapability(module: "nw.endpoints", versions: [2], status: .provisional),
        ProtocolModuleCapability(module: "nw.routes", versions: [2, 3], status: .experimental),
        ProtocolModuleCapability(module: "nw.blobs", versions: [1], status: .stable),
        ProtocolModuleCapability(module: "nw.groups", versions: [1], status: .experimental),
        ProtocolModuleCapability(module: "nw.wake", versions: [1], status: .experimental),
        ProtocolModuleCapability(module: "nw.federation", versions: [1], status: .provisional),
        ProtocolModuleCapability(
            module: "nw.privacy.hidden-retrieval",
            versions: [1],
            status: .experimental
        ),
        ProtocolModuleCapability(module: "nw.privacy.onion", versions: [1], status: .experimental),
        ProtocolModuleCapability(module: "nw.privacy.mixnet", versions: [1], status: .experimental)
    ]

    /// Capabilities actually implemented by the current direct-v4 endpoint
    /// path. Optional transport, group, federation, blob, wake, route, and
    /// privacy modules must be added explicitly by a caller that wires them.
    /// Direct-v4 currently addresses one preferred peer endpoint, so it must
    /// not advertise the structural 16-endpoint manifest ceiling as delivery
    /// support.
    public static let defaultActiveEndpointModules: [ProtocolModuleCapability] = [
        ProtocolModuleCapability(
            module: "nw.core",
            versions: [2],
            status: .provisional,
            limits: ["maxCiphertextBytes": UInt64(PaddedMessagePlaintext.maximumPaddedBytes)]
        ),
        ProtocolModuleCapability(
            module: "nw.endpoints",
            versions: [2],
            status: .provisional,
            limits: ["maxActiveEndpoints": 1]
        ),
        ProtocolModuleCapability(
            module: "nw.events",
            versions: [2],
            status: .provisional,
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
            module: "nw.prekeys",
            versions: [2],
            status: .stable,
            limits: ["maxPrekeyAgeSeconds": UInt64(PrekeyBundle.maximumAge)]
        )
    ]

    public let architectureVersion: Int
    public let modules: [ProtocolModuleCapability]

    public init(
        architectureVersion: Int = NoctweaveArchitectureV2.version,
        modules: [ProtocolModuleCapability] = ProtocolCapabilityManifest.defaultActiveEndpointModules
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
        let result = ProtocolCapabilityManifest(modules: negotiated)
        return result.supports(module: "nw.core", version: 2) ? result : nil
    }
}

public enum EndpointAdmissionV2Error: Error, Equatable {
    case invalidCandidate
    case invalidChallenge
    case wrongIdentityGeneration
    case staleEndpointSet
    case notYetValid
    case expired
    case invalidAuthoritySignature
    case invalidEndpointSigningProof
    case invalidKEMKeyConfirmation
    case replayed
}

/// Public material proposed by a fresh cryptographic endpoint. This proposal
/// is not authorization: the current identity-generation authority must issue
/// a short-lived challenge, and the endpoint must answer with both an ML-DSA
/// possession signature and an ML-KEM key confirmation.
public struct EndpointAdmissionCandidateV2: Codable, Equatable, Identifiable {
    public var id: UUID { endpointId }
    public let identityGenerationId: UUID
    public let endpointId: UUID
    public let signingPublicKey: Data
    public let agreementPublicKey: Data
    public let capabilities: ProtocolCapabilityManifest
    public let expiresAt: Date?

    public init(
        identityGenerationId: UUID,
        endpointId: UUID,
        signingPublicKey: Data,
        agreementPublicKey: Data,
        capabilities: ProtocolCapabilityManifest = ProtocolCapabilityManifest(),
        expiresAt: Date? = nil
    ) {
        self.identityGenerationId = identityGenerationId
        self.endpointId = endpointId
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
        self.capabilities = capabilities
        self.expiresAt = expiresAt
    }

    public init(
        endpoint: LocalInstallationState,
        capabilities: ProtocolCapabilityManifest = ProtocolCapabilityManifest(),
        expiresAt: Date? = nil
    ) {
        self.init(
            identityGenerationId: endpoint.identityGenerationId,
            endpointId: endpoint.id,
            signingPublicKey: endpoint.signingKey.publicKeyData,
            agreementPublicKey: endpoint.agreementKey.publicKeyData,
            capabilities: capabilities,
            expiresAt: expiresAt
        )
    }

    public var isStructurallyValid: Bool {
        SigningKeyPair.isValidPublicKey(signingPublicKey)
            && AgreementKeyPair.isValidPublicKey(agreementPublicKey)
            && capabilities.isStructurallyValid
            && (expiresAt?.timeIntervalSince1970.isFinite ?? true)
    }

    func installationRecord(addedEpoch: UInt64, addedAt: Date) -> InstallationRecord {
        InstallationRecord(
            id: endpointId,
            identityGenerationId: identityGenerationId,
            signingPublicKey: signingPublicKey,
            agreementPublicKey: agreementPublicKey,
            capabilities: capabilities,
            addedEpoch: addedEpoch,
            addedAt: addedAt,
            expiresAt: expiresAt
        )
    }
}

/// Identity-authority-signed, purpose-bound challenge for one endpoint and one
/// exact endpoint-set epoch. The ML-KEM ciphertext is encapsulated directly to
/// the proposed endpoint agreement key; there is no classical fallback.
public struct EndpointAdmissionChallengeV2: Codable, Equatable, Identifiable {
    public static let purpose = "Noctweave/identity-endpoint-admission/challenge/v2"

    public var id: Data { nonce }
    public let version: Int
    public let purpose: String
    public let identityGenerationId: UUID
    public let endpointSetEpoch: UInt64
    public let candidate: EndpointAdmissionCandidateV2
    public let nonce: Data
    public let kemCiphertext: Data
    public let issuedAt: Date
    public let expiresAt: Date
    public let authorityFingerprint: String
    public let authoritySignature: Data

    public init(
        version: Int = NoctweaveArchitectureV2.version,
        purpose: String = EndpointAdmissionChallengeV2.purpose,
        identityGenerationId: UUID,
        endpointSetEpoch: UInt64,
        candidate: EndpointAdmissionCandidateV2,
        nonce: Data,
        kemCiphertext: Data,
        issuedAt: Date,
        expiresAt: Date,
        authorityFingerprint: String,
        authoritySignature: Data
    ) {
        self.version = version
        self.purpose = purpose
        self.identityGenerationId = identityGenerationId
        self.endpointSetEpoch = endpointSetEpoch
        self.candidate = candidate
        self.nonce = nonce
        self.kemCiphertext = kemCiphertext
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.authorityFingerprint = authorityFingerprint
        self.authoritySignature = authoritySignature
    }

    public var isStructurallyValid: Bool {
        let lifetime = expiresAt.timeIntervalSince(issuedAt)
        return version == NoctweaveArchitectureV2.version
            && purpose == Self.purpose
            && candidate.isStructurallyValid
            && candidate.identityGenerationId == identityGenerationId
            && nonce.count == 32
            && kemCiphertext.count == 1_088
            && issuedAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && lifetime > 0
            && lifetime <= NoctweaveArchitectureV2.maximumEndpointAdmissionLifetime
            && candidate.expiresAt.map { $0 > issuedAt } ?? true
            && Self.isCanonicalFingerprint(authorityFingerprint)
            && authoritySignature.count == 3_309
    }

    public var digest: Data? {
        guard let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else { return nil }
        return Data(SHA256.hash(data: encoded))
    }

    public func verifyAuthority(
        identityPublicKey: Data,
        at date: Date
    ) -> Bool {
        guard isStructurallyValid,
              date.timeIntervalSince1970.isFinite,
              date >= issuedAt,
              date < expiresAt,
              authorityFingerprint == CryptoBox.fingerprint(for: identityPublicKey),
              let data = try? signaturePayload.signableData() else {
            return false
        }
        return SigningKeyPair.verify(
            signature: authoritySignature,
            data: data,
            publicKeyData: identityPublicKey
        )
    }

    private var signaturePayload: EndpointAdmissionChallengeSignaturePayloadV2 {
        EndpointAdmissionChallengeSignaturePayloadV2(
            version: version,
            purpose: purpose,
            identityGenerationId: identityGenerationId,
            endpointSetEpoch: endpointSetEpoch,
            candidate: candidate,
            nonce: nonce,
            kemCiphertext: kemCiphertext,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            authorityFingerprint: authorityFingerprint
        )
    }

    private static func isCanonicalFingerprint(_ value: String) -> Bool {
        guard let decoded = Data(base64Encoded: value), decoded.count == 32 else { return false }
        return decoded.base64EncodedString() == value
    }
}

/// Sensitive local state retained by the issuing endpoint until a challenge is
/// completed or expires. Only `challenge` is transportable; the shared secret
/// must remain inside encrypted local state.
public struct PendingEndpointAdmissionV2: Equatable {
    public let challenge: EndpointAdmissionChallengeV2
    let keyConfirmationSecret: Data

    init(challenge: EndpointAdmissionChallengeV2, keyConfirmationSecret: Data) {
        self.challenge = challenge
        self.keyConfirmationSecret = keyConfirmationSecret
    }

    public var isStructurallyValid: Bool {
        challenge.isStructurallyValid && keyConfirmationSecret.count == 32
    }

    public static func issue(
        candidate: EndpointAdmissionCandidateV2,
        endpointSetEpoch: UInt64,
        identityAuthorityKey: SigningKeyPair,
        issuedAt: Date = Date(),
        expiresAt: Date,
        nonce: Data? = nil
    ) throws -> PendingEndpointAdmissionV2 {
        let nonce = nonce ?? SymmetricKey(size: .bits256).dataRepresentation
        guard candidate.isStructurallyValid,
              SigningKeyPair.isValidPublicKey(identityAuthorityKey.publicKeyData),
              nonce.count == 32,
              issuedAt.timeIntervalSince1970.isFinite,
              expiresAt.timeIntervalSince1970.isFinite,
              expiresAt > issuedAt,
              expiresAt.timeIntervalSince(issuedAt)
                <= NoctweaveArchitectureV2.maximumEndpointAdmissionLifetime,
              candidate.expiresAt.map({ $0 > issuedAt }) ?? true else {
            throw EndpointAdmissionV2Error.invalidCandidate
        }
        var kemOutput = try AgreementKeyPair.encapsulate(to: candidate.agreementPublicKey)
        defer { kemOutput.sharedSecret.secureWipe() }
        let fingerprint = CryptoBox.fingerprint(for: identityAuthorityKey.publicKeyData)
        let payload = EndpointAdmissionChallengeSignaturePayloadV2(
            version: NoctweaveArchitectureV2.version,
            purpose: EndpointAdmissionChallengeV2.purpose,
            identityGenerationId: candidate.identityGenerationId,
            endpointSetEpoch: endpointSetEpoch,
            candidate: candidate,
            nonce: nonce,
            kemCiphertext: kemOutput.ciphertext,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            authorityFingerprint: fingerprint
        )
        let challenge = EndpointAdmissionChallengeV2(
            identityGenerationId: candidate.identityGenerationId,
            endpointSetEpoch: endpointSetEpoch,
            candidate: candidate,
            nonce: nonce,
            kemCiphertext: kemOutput.ciphertext,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            authorityFingerprint: fingerprint,
            authoritySignature: try identityAuthorityKey.sign(payload.signableData())
        )
        let pending = PendingEndpointAdmissionV2(
            challenge: challenge,
            keyConfirmationSecret: kemOutput.sharedSecret
        )
        guard pending.isStructurallyValid else {
            throw EndpointAdmissionV2Error.invalidChallenge
        }
        return pending
    }
}

/// Endpoint response proving possession of both proposed post-quantum private
/// keys. The signature covers the ML-KEM confirmation and exact challenge.
public struct EndpointAdmissionResponseV2: Codable, Equatable {
    public static let purpose = "Noctweave/identity-endpoint-admission/response/v2"

    public let version: Int
    public let purpose: String
    public let identityGenerationId: UUID
    public let endpointId: UUID
    public let challengeDigest: Data
    public let nonce: Data
    public let respondedAt: Date
    public let kemKeyConfirmation: Data
    public let endpointSignature: Data

    public init(
        version: Int = NoctweaveArchitectureV2.version,
        purpose: String = EndpointAdmissionResponseV2.purpose,
        identityGenerationId: UUID,
        endpointId: UUID,
        challengeDigest: Data,
        nonce: Data,
        respondedAt: Date,
        kemKeyConfirmation: Data,
        endpointSignature: Data
    ) {
        self.version = version
        self.purpose = purpose
        self.identityGenerationId = identityGenerationId
        self.endpointId = endpointId
        self.challengeDigest = challengeDigest
        self.nonce = nonce
        self.respondedAt = respondedAt
        self.kemKeyConfirmation = kemKeyConfirmation
        self.endpointSignature = endpointSignature
    }

    public static func create(
        challenge: EndpointAdmissionChallengeV2,
        endpoint: LocalInstallationState,
        identityAuthorityPublicKey: Data,
        respondedAt: Date = Date()
    ) throws -> EndpointAdmissionResponseV2 {
        guard challenge.verifyAuthority(
            identityPublicKey: identityAuthorityPublicKey,
            at: respondedAt
        ) else {
            throw EndpointAdmissionV2Error.invalidAuthoritySignature
        }
        guard endpoint.identityGenerationId == challenge.identityGenerationId,
              endpoint.id == challenge.candidate.endpointId,
              endpoint.signingKey.publicKeyData == challenge.candidate.signingPublicKey,
              endpoint.agreementKey.publicKeyData == challenge.candidate.agreementPublicKey,
              let challengeDigest = challenge.digest else {
            throw EndpointAdmissionV2Error.invalidCandidate
        }
        var sharedSecret = try endpoint.agreementKey.decapsulate(
            ciphertext: challenge.kemCiphertext
        )
        defer { sharedSecret.secureWipe() }
        let confirmationPayload = EndpointAdmissionKEMConfirmationPayloadV2(
            purpose: Self.purpose,
            identityGenerationId: challenge.identityGenerationId,
            endpointId: endpoint.id,
            challengeDigest: challengeDigest,
            nonce: challenge.nonce,
            respondedAt: respondedAt
        )
        let confirmationData = try confirmationPayload.signableData()
        let confirmation = Data(HMAC<SHA256>.authenticationCode(
            for: confirmationData,
            using: SymmetricKey(data: sharedSecret)
        ))
        let signaturePayload = EndpointAdmissionResponseSignaturePayloadV2(
            confirmation: confirmationPayload,
            kemKeyConfirmation: confirmation
        )
        return EndpointAdmissionResponseV2(
            identityGenerationId: challenge.identityGenerationId,
            endpointId: endpoint.id,
            challengeDigest: challengeDigest,
            nonce: challenge.nonce,
            respondedAt: respondedAt,
            kemKeyConfirmation: confirmation,
            endpointSignature: try endpoint.signingKey.sign(signaturePayload.signableData())
        )
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveArchitectureV2.version
            && purpose == Self.purpose
            && challengeDigest.count == 32
            && nonce.count == 32
            && respondedAt.timeIntervalSince1970.isFinite
            && kemKeyConfirmation.count == 32
            && endpointSignature.count == 3_309
    }

    func verify(
        pending: PendingEndpointAdmissionV2,
        identityAuthorityPublicKey: Data,
        at date: Date
    ) throws {
        let challenge = pending.challenge
        guard isStructurallyValid, pending.isStructurallyValid,
              let expectedChallengeDigest = challenge.digest,
              challengeDigest == expectedChallengeDigest,
              nonce == challenge.nonce,
              identityGenerationId == challenge.identityGenerationId,
              endpointId == challenge.candidate.endpointId else {
            throw EndpointAdmissionV2Error.invalidChallenge
        }
        guard date.timeIntervalSince1970.isFinite,
              respondedAt >= challenge.issuedAt,
              respondedAt <= date else {
            throw EndpointAdmissionV2Error.notYetValid
        }
        guard date < challenge.expiresAt,
              respondedAt < challenge.expiresAt,
              challenge.candidate.expiresAt.map({ date < $0 }) ?? true else {
            throw EndpointAdmissionV2Error.expired
        }
        guard challenge.verifyAuthority(identityPublicKey: identityAuthorityPublicKey, at: date) else {
            throw EndpointAdmissionV2Error.invalidAuthoritySignature
        }
        let confirmationPayload = EndpointAdmissionKEMConfirmationPayloadV2(
            purpose: purpose,
            identityGenerationId: identityGenerationId,
            endpointId: endpointId,
            challengeDigest: challengeDigest,
            nonce: nonce,
            respondedAt: respondedAt
        )
        let confirmationData = try confirmationPayload.signableData()
        guard HMAC<SHA256>.isValidAuthenticationCode(
            kemKeyConfirmation,
            authenticating: confirmationData,
            using: SymmetricKey(data: pending.keyConfirmationSecret)
        ) else {
            throw EndpointAdmissionV2Error.invalidKEMKeyConfirmation
        }
        let signaturePayload = EndpointAdmissionResponseSignaturePayloadV2(
            confirmation: confirmationPayload,
            kemKeyConfirmation: kemKeyConfirmation
        )
        guard SigningKeyPair.verify(
            signature: endpointSignature,
            data: try signaturePayload.signableData(),
            publicKeyData: challenge.candidate.signingPublicKey
        ) else {
            throw EndpointAdmissionV2Error.invalidEndpointSigningProof
        }
    }
}

private struct EndpointAdmissionChallengeSignaturePayloadV2: Codable {
    let version: Int
    let purpose: String
    let identityGenerationId: UUID
    let endpointSetEpoch: UInt64
    let candidate: EndpointAdmissionCandidateV2
    let nonce: Data
    let kemCiphertext: Data
    let issuedAt: Date
    let expiresAt: Date
    let authorityFingerprint: String

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

private struct EndpointAdmissionKEMConfirmationPayloadV2: Codable {
    let purpose: String
    let identityGenerationId: UUID
    let endpointId: UUID
    let challengeDigest: Data
    let nonce: Data
    let respondedAt: Date

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

private struct EndpointAdmissionResponseSignaturePayloadV2: Codable {
    let confirmation: EndpointAdmissionKEMConfirmationPayloadV2
    let kemKeyConfirmation: Data

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

public struct RelationshipInstallationHandle: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public static func generate(
        identityGenerationId: UUID,
        installationId: UUID,
        relationshipId: UUID,
        nonce: UUID = UUID()
    ) -> RelationshipInstallationHandle {
        var material = Data("Noctweave/relationship-installation-handle/v2".utf8)
        material.append(Data(identityGenerationId.uuidString.lowercased().utf8))
        material.append(Data(installationId.uuidString.lowercased().utf8))
        material.append(Data(relationshipId.uuidString.lowercased().utf8))
        material.append(Data(nonce.uuidString.lowercased().utf8))
        return RelationshipInstallationHandle(
            rawValue: Data(SHA256.hash(data: material)).base64EncodedString()
        )
    }

    public var isStructurallyValid: Bool {
        guard let decoded = Data(base64Encoded: rawValue), decoded.count == 32 else { return false }
        return decoded.base64EncodedString() == rawValue
    }
}

public struct InstallationRecord: Codable, Equatable, Identifiable {
    public let id: UUID
    public let identityGenerationId: UUID
    public let signingPublicKey: Data
    public let agreementPublicKey: Data
    public let capabilities: ProtocolCapabilityManifest
    public let addedEpoch: UInt64
    public let addedAt: Date
    public let expiresAt: Date?
    public let revokedEpoch: UInt64?
    public let revokedAt: Date?

    public init(
        id: UUID,
        identityGenerationId: UUID,
        signingPublicKey: Data,
        agreementPublicKey: Data,
        capabilities: ProtocolCapabilityManifest,
        addedEpoch: UInt64,
        addedAt: Date,
        expiresAt: Date? = nil,
        revokedEpoch: UInt64? = nil,
        revokedAt: Date? = nil
    ) {
        self.id = id
        self.identityGenerationId = identityGenerationId
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
        self.capabilities = capabilities
        self.addedEpoch = addedEpoch
        self.addedAt = addedAt
        self.expiresAt = expiresAt
        self.revokedEpoch = revokedEpoch
        self.revokedAt = revokedAt
    }

    public var fingerprint: String {
        CryptoBox.fingerprint(for: signingPublicKey)
    }

    public func isActive(at date: Date = Date(), manifestEpoch: UInt64) -> Bool {
        guard isStructurallyValid,
              addedEpoch <= manifestEpoch,
              revokedEpoch.map({ $0 > manifestEpoch }) ?? true,
              revokedAt == nil else {
            return false
        }
        return expiresAt.map { $0 > date } ?? true
    }

    public var isStructurallyValid: Bool {
        guard SigningKeyPair.isValidPublicKey(signingPublicKey),
              AgreementKeyPair.isValidPublicKey(agreementPublicKey),
              capabilities.isStructurallyValid,
              addedAt.timeIntervalSince1970.isFinite,
              expiresAt?.timeIntervalSince1970.isFinite ?? true,
              revokedAt?.timeIntervalSince1970.isFinite ?? true else {
            return false
        }
        if let expiresAt, expiresAt <= addedAt { return false }
        switch (revokedEpoch, revokedAt) {
        case (nil, nil):
            return true
        case let (.some(epoch), .some(date)):
            return epoch > addedEpoch && date >= addedAt
        default:
            return false
        }
    }

    public func revoked(epoch: UInt64, at date: Date = Date()) -> InstallationRecord? {
        guard revokedEpoch == nil, epoch > addedEpoch, date >= addedAt else { return nil }
        return InstallationRecord(
            id: id,
            identityGenerationId: identityGenerationId,
            signingPublicKey: signingPublicKey,
            agreementPublicKey: agreementPublicKey,
            capabilities: capabilities,
            addedEpoch: addedEpoch,
            addedAt: addedAt,
            expiresAt: expiresAt,
            revokedEpoch: epoch,
            revokedAt: date
        )
    }
}

public struct LocalInstallationState: Codable, Equatable, Identifiable {
    public let id: UUID
    public let identityGenerationId: UUID
    public var signingKey: SigningKeyPair
    public var agreementKey: AgreementKeyPair
    public var prekeys: PrekeyState
    public var cursorsByStream: [String: MailboxCursor]
    public var committedSequencesByStream: [String: UInt64]
    public var pendingMailboxCommitsByStream: [String: PendingMailboxCursorCommit]
    public var mailboxCredentialsByRoute: [String: MailboxRouteCredentialV2]
    /// Compatibility index for pre-route-credential profiles. New code keeps
    /// this synchronized with `mailboxCredentialsByRoute` while an old bound
    /// consumer is migrated through an authenticated sponsor rotation.
    public var mailboxConsumerIdsByRoute: [String: MailboxConsumerId]
    public var relationshipHandles: [UUID: RelationshipInstallationHandle]
    public let createdAt: Date

    public init(
        id: UUID,
        identityGenerationId: UUID,
        signingKey: SigningKeyPair,
        agreementKey: AgreementKeyPair,
        prekeys: PrekeyState,
        cursorsByStream: [String: MailboxCursor] = [:],
        committedSequencesByStream: [String: UInt64] = [:],
        pendingMailboxCommitsByStream: [String: PendingMailboxCursorCommit] = [:],
        mailboxCredentialsByRoute: [String: MailboxRouteCredentialV2] = [:],
        mailboxConsumerIdsByRoute: [String: MailboxConsumerId] = [:],
        relationshipHandles: [UUID: RelationshipInstallationHandle] = [:],
        createdAt: Date = Date()
    ) {
        self.id = id
        self.identityGenerationId = identityGenerationId
        self.signingKey = signingKey
        self.agreementKey = agreementKey
        self.prekeys = prekeys
        self.cursorsByStream = cursorsByStream
        self.committedSequencesByStream = committedSequencesByStream
        self.pendingMailboxCommitsByStream = pendingMailboxCommitsByStream
        self.mailboxCredentialsByRoute = mailboxCredentialsByRoute
        self.mailboxConsumerIdsByRoute = mailboxConsumerIdsByRoute
        self.relationshipHandles = relationshipHandles
        self.createdAt = createdAt
    }

    public static func generate(
        identityGenerationId: UUID,
        id: UUID = UUID(),
        createdAt: Date = Date()
    ) throws -> LocalInstallationState {
        let signingKey = try SigningKeyPair.generate()
        let agreementKey = try AgreementKeyPair.generate()
        let installationIdentity = try Identity(
            displayName: "Noctweave installation",
            signingKey: signingKey,
            agreementKey: agreementKey,
            createdAt: createdAt
        )
        return LocalInstallationState(
            id: id,
            identityGenerationId: identityGenerationId,
            signingKey: signingKey,
            agreementKey: agreementKey,
            prekeys: try PrekeyState.generate(identity: installationIdentity),
            createdAt: createdAt
        )
    }

    public func publicRecord(
        addedEpoch: UInt64,
        capabilities: ProtocolCapabilityManifest = ProtocolCapabilityManifest(),
        expiresAt: Date? = nil
    ) -> InstallationRecord {
        InstallationRecord(
            id: id,
            identityGenerationId: identityGenerationId,
            signingPublicKey: signingKey.publicKeyData,
            agreementPublicKey: agreementKey.publicKeyData,
            capabilities: capabilities,
            addedEpoch: addedEpoch,
            addedAt: createdAt,
            expiresAt: expiresAt
        )
    }

    /// Proactively renews this endpoint's short-lived bootstrap key while
    /// leaving its generation authorization, endpoint keys, routes, cursors,
    /// and established sessions unchanged.
    @discardableResult
    public mutating func renewSignedPrekeyIfNeeded(at date: Date = Date()) throws -> Bool {
        try prekeys.rotateSignedPrekeyIfNeeded(
            endpointSigningKey: signingKey,
            now: date
        )
    }

    public static func == (lhs: LocalInstallationState, rhs: LocalInstallationState) -> Bool {
        lhs.id == rhs.id
            && lhs.identityGenerationId == rhs.identityGenerationId
            && lhs.signingKey.privateKeyData == rhs.signingKey.privateKeyData
            && lhs.signingKey.publicKeyData == rhs.signingKey.publicKeyData
            && lhs.agreementKey.privateKeyData == rhs.agreementKey.privateKeyData
            && lhs.agreementKey.publicKeyData == rhs.agreementKey.publicKeyData
            && lhs.prekeys == rhs.prekeys
            && lhs.cursorsByStream == rhs.cursorsByStream
            && lhs.committedSequencesByStream == rhs.committedSequencesByStream
            && lhs.pendingMailboxCommitsByStream == rhs.pendingMailboxCommitsByStream
            && lhs.mailboxCredentialsByRoute == rhs.mailboxCredentialsByRoute
            && lhs.mailboxConsumerIdsByRoute == rhs.mailboxConsumerIdsByRoute
            && lhs.relationshipHandles == rhs.relationshipHandles
            && lhs.createdAt == rhs.createdAt
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case identityGenerationId
        case signingKey
        case agreementKey
        case prekeys
        case cursorsByStream
        case committedSequencesByStream
        case pendingMailboxCommitsByStream
        case mailboxCredentialsByRoute
        case mailboxConsumerIdsByRoute
        case relationshipHandles
        case createdAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        identityGenerationId = try container.decode(UUID.self, forKey: .identityGenerationId)
        signingKey = try container.decode(SigningKeyPair.self, forKey: .signingKey)
        agreementKey = try container.decode(AgreementKeyPair.self, forKey: .agreementKey)
        prekeys = try container.decode(PrekeyState.self, forKey: .prekeys)
        cursorsByStream = try container.decodeIfPresent(
            [String: MailboxCursor].self,
            forKey: .cursorsByStream
        ) ?? [:]
        committedSequencesByStream = try container.decodeIfPresent(
            [String: UInt64].self,
            forKey: .committedSequencesByStream
        ) ?? [:]
        pendingMailboxCommitsByStream = try container.decodeIfPresent(
            [String: PendingMailboxCursorCommit].self,
            forKey: .pendingMailboxCommitsByStream
        ) ?? [:]
        mailboxCredentialsByRoute = try container.decodeIfPresent(
            [String: MailboxRouteCredentialV2].self,
            forKey: .mailboxCredentialsByRoute
        ) ?? [:]
        mailboxConsumerIdsByRoute = try container.decodeIfPresent(
            [String: MailboxConsumerId].self,
            forKey: .mailboxConsumerIdsByRoute
        ) ?? [:]
        relationshipHandles = try container.decodeIfPresent(
            [UUID: RelationshipInstallationHandle].self,
            forKey: .relationshipHandles
        ) ?? [:]
        createdAt = try container.decode(Date.self, forKey: .createdAt)
    }

    /// Returns a fresh per-route credential. Profiles written before route
    /// credentials retain their former consumer only as a one-time sponsor;
    /// the installation signing key is never used for a newly created route.
    public mutating func ensureMailboxCredential(
        for routeKey: String,
        relay: RelayEndpoint? = nil,
        inboxId: String? = nil,
        at date: Date = Date()
    ) throws -> MailboxRouteCredentialV2 {
        guard !routeKey.isEmpty,
              routeKey.utf8.count <= 1_024,
              (relay == nil) == (inboxId == nil),
              inboxId.map(InboxAddress.isValid) ?? true,
              date.timeIntervalSince1970.isFinite else {
            throw CryptoError.invalidPayload
        }
        if var existing = mailboxCredentialsByRoute[routeKey] {
            guard existing.isStructurallyValid,
                  mailboxConsumerIdsByRoute[routeKey] == existing.consumerId else {
                throw CryptoError.invalidPayload
            }
            if let relay, let inboxId {
                if let existingRoute = existing.routeIdentifier,
                   existingRoute != routeKey {
                    throw CryptoError.invalidPayload
                }
                existing.relay = relay
                existing.inboxId = inboxId.lowercased()
                guard existing.routeIdentifier == routeKey else {
                    throw CryptoError.invalidPayload
                }
                mailboxCredentialsByRoute[routeKey] = existing
            }
            return existing
        }
        guard mailboxCredentialsByRoute.count < NoctweaveArchitectureV2.maximumRoutes else {
            throw CryptoError.invalidPayload
        }
        let credential = try MailboxRouteCredentialV2.generate(
            relay: relay,
            inboxId: inboxId,
            legacySponsorConsumerId: mailboxConsumerIdsByRoute[routeKey],
            createdAt: date
        )
        guard credential.routeIdentifier.map({ $0 == routeKey }) ?? true else {
            throw CryptoError.invalidPayload
        }
        mailboxCredentialsByRoute[routeKey] = credential
        mailboxConsumerIdsByRoute[routeKey] = credential.consumerId
        return credential
    }

    public mutating func completeMailboxCredentialMigration(for routeKey: String) throws {
        guard var credential = mailboxCredentialsByRoute[routeKey],
              credential.isStructurallyValid else {
            throw CryptoError.invalidPayload
        }
        credential.legacySponsorConsumerId = nil
        mailboxCredentialsByRoute[routeKey] = credential
        mailboxConsumerIdsByRoute[routeKey] = credential.consumerId
    }

    public var mailboxStateIsStructurallyValid: Bool {
        mailboxConsumerIdsByRoute.count <= NoctweaveArchitectureV2.maximumRoutes
            && mailboxCredentialsByRoute.count <= NoctweaveArchitectureV2.maximumRoutes
            && mailboxConsumerIdsByRoute.allSatisfy { routeKey, consumerId in
                !routeKey.isEmpty
                    && routeKey.utf8.count <= 1_024
                    && consumerId.isStructurallyValid
            }
            && mailboxCredentialsByRoute.allSatisfy { routeKey, credential in
                !routeKey.isEmpty
                    && routeKey.utf8.count <= 1_024
                    && credential.isStructurallyValid
                    && (credential.routeIdentifier.map { $0 == routeKey } ?? true)
                    && mailboxConsumerIdsByRoute[routeKey] == credential.consumerId
            }
    }
}

/// Relay authentication material scoped to one mailbox route. Neither the
/// consumer ID nor its ML-DSA key is reused for another relay/inbox pair, so
/// colluding routes cannot correlate an endpoint by a stable public key.
public struct MailboxRouteCredentialV2: Codable, Equatable {
    public let consumerId: MailboxConsumerId
    public let signingKey: SigningKeyPair
    public var relay: RelayEndpoint?
    public var inboxId: String?
    public var legacySponsorConsumerId: MailboxConsumerId?
    public let createdAt: Date

    public init(
        consumerId: MailboxConsumerId,
        signingKey: SigningKeyPair,
        relay: RelayEndpoint? = nil,
        inboxId: String? = nil,
        legacySponsorConsumerId: MailboxConsumerId? = nil,
        createdAt: Date = Date()
    ) {
        self.consumerId = consumerId
        self.signingKey = signingKey
        self.relay = relay
        self.inboxId = inboxId?.lowercased()
        self.legacySponsorConsumerId = legacySponsorConsumerId
        self.createdAt = createdAt
    }

    public static func generate(
        relay: RelayEndpoint? = nil,
        inboxId: String? = nil,
        legacySponsorConsumerId: MailboxConsumerId? = nil,
        createdAt: Date = Date()
    ) throws -> MailboxRouteCredentialV2 {
        MailboxRouteCredentialV2(
            consumerId: .generate(),
            signingKey: try SigningKeyPair.generate(),
            relay: relay,
            inboxId: inboxId,
            legacySponsorConsumerId: legacySponsorConsumerId,
            createdAt: createdAt
        )
    }

    public var isStructurallyValid: Bool {
        consumerId.isStructurallyValid
            && SigningKeyPair.isValidPublicKey(signingKey.publicKeyData)
            && ((relay == nil) == (inboxId == nil))
            && (relay.map { !$0.host.isEmpty } ?? true)
            && (inboxId.map(InboxAddress.isValid) ?? true)
            && legacySponsorConsumerId?.isStructurallyValid != false
            && legacySponsorConsumerId != consumerId
            && createdAt.timeIntervalSince1970.isFinite
    }

    public var routeIdentifier: String? {
        guard let relay, let inboxId else { return nil }
        return Self.routeIdentifier(relay: relay, inboxId: inboxId)
    }

    public static func routeIdentifier(relay: RelayEndpoint, inboxId: String) -> String {
        "\(relay.transport.rawValue):\(relay.useTLS ? 1 : 0):\(relay.host.lowercased()):\(relay.port):\(inboxId.lowercased())"
    }

    public static func == (lhs: MailboxRouteCredentialV2, rhs: MailboxRouteCredentialV2) -> Bool {
        lhs.consumerId == rhs.consumerId
            && lhs.signingKey.privateKeyData == rhs.signingKey.privateKeyData
            && lhs.signingKey.publicKeyData == rhs.signingKey.publicKeyData
            && lhs.relay == rhs.relay
            && lhs.inboxId == rhs.inboxId
            && lhs.legacySponsorConsumerId == rhs.legacySponsorConsumerId
            && lhs.createdAt == rhs.createdAt
    }
}

public struct InstallationManifest: Codable, Equatable {
    public let version: Int
    public let identityGenerationId: UUID
    public let identityFingerprint: String
    public let epoch: UInt64
    public let previousManifestDigest: Data?
    public let installations: [InstallationRecord]
    public let issuedAt: Date
    public let signature: Data

    public init(
        version: Int = NoctweaveArchitectureV2.version,
        identityGenerationId: UUID,
        identityFingerprint: String,
        epoch: UInt64,
        previousManifestDigest: Data?,
        installations: [InstallationRecord],
        issuedAt: Date,
        signature: Data
    ) {
        self.version = version
        self.identityGenerationId = identityGenerationId
        self.identityFingerprint = identityFingerprint
        self.epoch = epoch
        self.previousManifestDigest = previousManifestDigest
        self.installations = installations.sorted { $0.id.uuidString < $1.id.uuidString }
        self.issuedAt = issuedAt
        self.signature = signature
    }

    public static func create(
        identityGenerationId: UUID,
        epoch: UInt64,
        previousManifestDigest: Data? = nil,
        installations: [InstallationRecord],
        identity: Identity,
        issuedAt: Date = Date()
    ) throws -> InstallationManifest {
        let ordered = installations.sorted { $0.id.uuidString < $1.id.uuidString }
        let payload = InstallationManifestSignaturePayload(
            version: NoctweaveArchitectureV2.version,
            identityGenerationId: identityGenerationId,
            identityFingerprint: identity.fingerprint,
            epoch: epoch,
            previousManifestDigest: previousManifestDigest,
            installations: ordered,
            issuedAt: issuedAt
        )
        return InstallationManifest(
            identityGenerationId: identityGenerationId,
            identityFingerprint: identity.fingerprint,
            epoch: epoch,
            previousManifestDigest: previousManifestDigest,
            installations: ordered,
            issuedAt: issuedAt,
            signature: try identity.signingKey.sign(NoctweaveCoder.encode(payload, sortedKeys: true))
        )
    }

    public var activeInstallations: [InstallationRecord] {
        installations.filter { $0.isActive(manifestEpoch: epoch) }
    }

    public var digest: Data? {
        guard let data = try? NoctweaveCoder.encode(self, sortedKeys: true) else { return nil }
        return Data(SHA256.hash(data: data))
    }

    public func verify(identityPublicKey: Data) -> Bool {
        guard isStructurallyValid,
              identityFingerprint == CryptoBox.fingerprint(for: identityPublicKey),
              let data = try? NoctweaveCoder.encode(signaturePayload, sortedKeys: true) else {
            return false
        }
        return SigningKeyPair.verify(signature: signature, data: data, publicKeyData: identityPublicKey)
    }

    public var isStructurallyValid: Bool {
        let hasValidHistoryLink = epoch == 0
            ? previousManifestDigest == nil
            : previousManifestDigest?.count == 32
        return version == NoctweaveArchitectureV2.version
            && hasValidHistoryLink
            && !installations.isEmpty
            && installations.count <= NoctweaveArchitectureV2.maximumInstallations
            && Set(installations.map(\.id)).count == installations.count
            && Set(installations.map(\.signingPublicKey)).count == installations.count
            && Set(installations.map(\.agreementPublicKey)).count == installations.count
            && installations.allSatisfy { installation in
                installation.identityGenerationId == identityGenerationId
                    && installation.isStructurallyValid
                    && installation.addedEpoch <= epoch
                    && installation.addedAt <= issuedAt
                    && installation.revokedEpoch.map { $0 <= epoch } ?? true
                    && installation.revokedAt.map { $0 <= issuedAt } ?? true
            }
            && issuedAt.timeIntervalSince1970.isFinite
            && signature.count == 3_309
    }

    func revoking(
        installationId: UUID,
        identity: Identity,
        at date: Date = Date()
    ) throws -> InstallationManifest? {
        guard verify(identityPublicKey: identity.signingKey.publicKeyData),
              date.timeIntervalSince1970.isFinite,
              date >= issuedAt,
              let digest,
              epoch < UInt64.max,
              let index = installations.firstIndex(where: { $0.id == installationId }) else {
            return nil
        }
        if installations[index].revokedEpoch != nil {
            return self
        }
        guard let revoked = installations[index].revoked(epoch: epoch + 1, at: date) else {
            return nil
        }
        var updated = installations
        updated[index] = revoked
        let result = try InstallationManifest.create(
            identityGenerationId: identityGenerationId,
            epoch: epoch + 1,
            previousManifestDigest: digest,
            installations: updated,
            identity: identity,
            issuedAt: date
        )
        return result.isStructurallyValid ? result : nil
    }

    /// Authorizes one independently keyed installation in the next manifest
    /// epoch. Replaying the identical record is idempotent; reusing an ID or
    /// key for different material fails closed.
    func adding(
        installation: InstallationRecord,
        identity: Identity,
        at date: Date = Date()
    ) throws -> InstallationManifest? {
        guard verify(identityPublicKey: identity.signingKey.publicKeyData),
              date.timeIntervalSince1970.isFinite,
              date >= issuedAt,
              let digest,
              epoch < UInt64.max else {
            return nil
        }
        if let existing = installations.first(where: { $0.id == installation.id }) {
            return existing == installation ? self : nil
        }
        let retained = installations.filter { record in
            record.revokedEpoch == nil
                && (record.expiresAt.map { $0 > date } ?? true)
        }
        guard retained.count < NoctweaveArchitectureV2.maximumInstallations,
              installation.isStructurallyValid,
              installation.identityGenerationId == identityGenerationId,
              installation.addedEpoch == epoch + 1,
              installation.addedAt <= date,
              installation.revokedEpoch == nil,
              installation.revokedAt == nil,
              !installations.contains(where: {
                  $0.signingPublicKey == installation.signingPublicKey
                      || $0.agreementPublicKey == installation.agreementPublicKey
              }) else {
            return nil
        }
        let result = try InstallationManifest.create(
            identityGenerationId: identityGenerationId,
            epoch: epoch + 1,
            previousManifestDigest: digest,
            // The previous digest commits removed records, so ordinary endpoint
            // replacement within this generation does not consume a permanent slot.
            installations: retained + [installation],
            identity: identity,
            issuedAt: date
        )
        return result.isStructurallyValid ? result : nil
    }

    private var signaturePayload: InstallationManifestSignaturePayload {
        InstallationManifestSignaturePayload(
            version: version,
            identityGenerationId: identityGenerationId,
            identityFingerprint: identityFingerprint,
            epoch: epoch,
            previousManifestDigest: previousManifestDigest,
            installations: installations,
            issuedAt: issuedAt
        )
    }
}

private struct InstallationManifestSignaturePayload: Codable {
    let version: Int
    let identityGenerationId: UUID
    let identityFingerprint: String
    let epoch: UInt64
    let previousManifestDigest: Data?
    let installations: [InstallationRecord]
    let issuedAt: Date
}

public struct MailboxCursor: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public var isStructurallyValid: Bool {
        !rawValue.isEmpty
            && rawValue.utf8.count <= NoctweaveArchitectureV2.maximumCursorBytes
            && rawValue.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
    }
}

public enum MessageDeliveryState: String, Codable, Equatable, CaseIterable {
    case locallyPersisted
    case relayAccepted
    case peerEndpointStored
    case peerRead
}
