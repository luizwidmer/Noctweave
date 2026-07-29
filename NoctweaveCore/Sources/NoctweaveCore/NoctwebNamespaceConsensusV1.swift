import CryptoKit
import Foundation

public enum NoctwebNamespaceConsensusV1 {
    public static let version = 1
    public static let maximumRecords = 4_096
    public static let maximumSigners = 64
    public static let maximumSnapshotLifetime: TimeInterval = 60 * 60
    public static let snapshotTimeBucket: TimeInterval = 5 * 60
    public static let defaultSnapshotLifetime: TimeInterval = 15 * 60
    public static let digestBytes = 32
    public static let signatureAlgorithm = RelayIdentityV1.signatureAlgorithm
}

public struct NoctwebNamespaceSnapshotRequestV1: Codable, Equatable {
    public let version: Int
    public let federationMode: FederationMode
    public let federationName: String?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case federationMode
        case federationName
    }

    public init(
        federationMode: FederationMode,
        federationName: String?
    ) {
        version = NoctwebNamespaceConsensusV1.version
        self.federationMode = federationMode
        self.federationName = federationName
    }

    public var isStructurallyValid: Bool {
        version == NoctwebNamespaceConsensusV1.version
            && namespaceFederationNameIsCanonical(federationName)
    }

    public init(from decoder: Decoder) throws {
        try namespaceRequireExactFields(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        version = try values.decode(Int.self, forKey: .version)
        federationMode = try values.decode(
            FederationMode.self,
            forKey: .federationMode
        )
        federationName = try values.decodeIfPresent(
            String.self,
            forKey: .federationName
        )
        guard isStructurallyValid else {
            throw namespaceDecodingError(
                decoder,
                "Noctweb namespace snapshot request is invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw namespaceEncodingError(
                encoder,
                "Noctweb namespace snapshot request is invalid"
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(federationMode, forKey: .federationMode)
        try values.encode(federationName, forKey: .federationName)
    }
}

public struct NoctwebNamespaceClaimRequestV1: Codable, Equatable {
    public let identity: SignedRelayIdentityClaimV1

    public init(identity: SignedRelayIdentityClaimV1) {
        self.identity = identity
    }
}

public struct NoctwebNamespaceRotationRequestV1: Codable, Equatable {
    public let rotation: RelayIdentityRotationV1
    public let newIdentity: SignedRelayIdentityClaimV1

    public init(
        rotation: RelayIdentityRotationV1,
        newIdentity: SignedRelayIdentityClaimV1
    ) {
        self.rotation = rotation
        self.newIdentity = newIdentity
    }
}

public enum NoctwebNamespaceRecordStatusV1: String, Codable, Equatable {
    case active
    case tombstoned
}

public enum NoctwebNamespaceLedgerErrorV1: Error, Equatable {
    case invalidClaim
    case suffixAlreadyOwned
    case suffixTombstoned
    case staleSequence
    case ownershipMismatch
    case invalidRotation
    case invalidRelease
}

/// Consensus ownership is durable independently from relay health. An expired
/// identity claim removes routable endpoints, but never frees the suffix.
public struct NoctwebNamespaceRecordV1: Codable, Equatable {
    public let suffix: NoctwebRelaySuffixV1
    public let ownerRelayID: RelayIdentityIDV1
    public let ownerSigningPublicKey: Data
    public let ownershipSequence: Int
    public let status: NoctwebNamespaceRecordStatusV1
    public let assignedAt: Date
    public let updatedAt: Date
    public let activeIdentityClaim: SignedRelayIdentityClaimV1?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case suffix
        case ownerRelayID
        case ownerSigningPublicKey
        case ownershipSequence
        case status
        case assignedAt
        case updatedAt
        case activeIdentityClaim
    }

    public init(
        suffix: NoctwebRelaySuffixV1,
        ownerRelayID: RelayIdentityIDV1,
        ownerSigningPublicKey: Data,
        ownershipSequence: Int,
        status: NoctwebNamespaceRecordStatusV1,
        assignedAt: Date,
        updatedAt: Date,
        activeIdentityClaim: SignedRelayIdentityClaimV1?
    ) {
        self.suffix = suffix
        self.ownerRelayID = ownerRelayID
        self.ownerSigningPublicKey = ownerSigningPublicKey
        self.ownershipSequence = ownershipSequence
        self.status = status
        self.assignedAt = namespaceCanonicalDate(assignedAt)
        self.updatedAt = namespaceCanonicalDate(updatedAt)
        self.activeIdentityClaim = activeIdentityClaim
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard suffix.isStructurallyValid,
                  ownerRelayID == RelayIdentityIDV1.derived(from: ownerSigningPublicKey),
                  try SigningKeyPair.isValidPublicKeyThrowing(ownerSigningPublicKey),
                  (0...RelayIdentityV1.maximumSequence).contains(ownershipSequence),
                  namespaceIsCanonicalDate(assignedAt),
                  namespaceIsCanonicalDate(updatedAt),
                  updatedAt >= assignedAt else {
                return false
            }
            switch status {
            case .active:
                if let activeIdentityClaim {
                    guard try activeIdentityClaim.verifyThrowing(),
                          activeIdentityClaim.claim.relayID == ownerRelayID,
                          activeIdentityClaim.claim.signingPublicKey == ownerSigningPublicKey,
                          activeIdentityClaim.claim.noctwebSuffix == suffix,
                          activeIdentityClaim.claim.sequence >= ownershipSequence else {
                        return false
                    }
                }
            case .tombstoned:
                guard activeIdentityClaim == nil else {
                    return false
                }
            }
            return true
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    public init(from decoder: Decoder) throws {
        try namespaceRequireExactFields(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            suffix: try values.decode(NoctwebRelaySuffixV1.self, forKey: .suffix),
            ownerRelayID: try values.decode(RelayIdentityIDV1.self, forKey: .ownerRelayID),
            ownerSigningPublicKey: try values.decode(Data.self, forKey: .ownerSigningPublicKey),
            ownershipSequence: try values.decode(Int.self, forKey: .ownershipSequence),
            status: try values.decode(NoctwebNamespaceRecordStatusV1.self, forKey: .status),
            assignedAt: try values.decode(Date.self, forKey: .assignedAt),
            updatedAt: try values.decode(Date.self, forKey: .updatedAt),
            activeIdentityClaim: try values.decodeIfPresent(
                SignedRelayIdentityClaimV1.self,
                forKey: .activeIdentityClaim
            )
        )
        guard try isStructurallyValidThrowing else {
            throw namespaceDecodingError(decoder, "Noctweb namespace record is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw namespaceEncodingError(encoder, "Noctweb namespace record is invalid")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(suffix, forKey: .suffix)
        try values.encode(ownerRelayID, forKey: .ownerRelayID)
        try values.encode(ownerSigningPublicKey, forKey: .ownerSigningPublicKey)
        try values.encode(ownershipSequence, forKey: .ownershipSequence)
        try values.encode(status, forKey: .status)
        try values.encode(assignedAt, forKey: .assignedAt)
        try values.encode(updatedAt, forKey: .updatedAt)
        try values.encode(activeIdentityClaim, forKey: .activeIdentityClaim)
    }
}

public struct NoctwebNamespaceReleaseV1: Codable, Equatable {
    public let version: Int
    public let suffix: NoctwebRelaySuffixV1
    public let ownerRelayID: RelayIdentityIDV1
    public let sequence: Int
    public let issuedAt: Date
    public let signatureAlgorithm: String
    public let signature: Data

    private struct Unsigned: Codable {
        let version: Int
        let suffix: NoctwebRelaySuffixV1
        let ownerRelayID: RelayIdentityIDV1
        let sequence: Int
        let issuedAt: Date
        let signatureAlgorithm: String
    }

    public static func signed(
        suffix: NoctwebRelaySuffixV1,
        owner: RelayIdentityKeyMaterialV1,
        sequence: Int,
        issuedAt: Date = Date()
    ) throws -> NoctwebNamespaceReleaseV1 {
        let canonicalIssuedAt = namespaceCanonicalDate(issuedAt)
        let unsigned = Unsigned(
            version: NoctwebNamespaceConsensusV1.version,
            suffix: suffix,
            ownerRelayID: owner.relayID,
            sequence: sequence,
            issuedAt: canonicalIssuedAt,
            signatureAlgorithm: NoctwebNamespaceConsensusV1.signatureAlgorithm
        )
        return NoctwebNamespaceReleaseV1(
            version: unsigned.version,
            suffix: suffix,
            ownerRelayID: owner.relayID,
            sequence: sequence,
            issuedAt: canonicalIssuedAt,
            signatureAlgorithm: unsigned.signatureAlgorithm,
            signature: try owner.signingKeyPair.sign(try Self.transcript(unsigned))
        )
    }

    public func verifyThrowing(ownerSigningPublicKey: Data) throws -> Bool {
        guard version == NoctwebNamespaceConsensusV1.version,
              suffix.isStructurallyValid,
              ownerRelayID == RelayIdentityIDV1.derived(from: ownerSigningPublicKey),
              (1...RelayIdentityV1.maximumSequence).contains(sequence),
              namespaceIsCanonicalDate(issuedAt),
              signatureAlgorithm == NoctwebNamespaceConsensusV1.signatureAlgorithm else {
            return false
        }
        return try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: Self.transcript(Unsigned(
                version: version,
                suffix: suffix,
                ownerRelayID: ownerRelayID,
                sequence: sequence,
                issuedAt: issuedAt,
                signatureAlgorithm: signatureAlgorithm
            )),
            publicKeyData: ownerSigningPublicKey
        )
    }

    private static func transcript(_ unsigned: Unsigned) throws -> Data {
        var transcript = Data("Noctweave/NoctwebNamespaceRelease/v1\u{0}".utf8)
        transcript.append(try NoctweaveCanonicalJSON.encode(unsigned))
        return transcript
    }
}

public struct NoctwebNamespaceLedgerV1: Equatable {
    private var recordsBySuffix: [NoctwebRelaySuffixV1: NoctwebNamespaceRecordV1]

    public init() {
        recordsBySuffix = [:]
    }

    public init(records: [NoctwebNamespaceRecordV1]) throws {
        guard records.count <= NoctwebNamespaceConsensusV1.maximumRecords,
              Set(records.map(\.suffix)).count == records.count,
              try records.allSatisfy({ try $0.isStructurallyValidThrowing }) else {
            throw NoctwebNamespaceLedgerErrorV1.invalidClaim
        }
        recordsBySuffix = Dictionary(uniqueKeysWithValues: records.map { ($0.suffix, $0) })
    }

    public mutating func claim(
        _ identity: SignedRelayIdentityClaimV1,
        now: Date = Date()
    ) throws {
        guard try identity.verifyThrowing(at: now),
              let suffix = identity.claim.noctwebSuffix else {
            throw NoctwebNamespaceLedgerErrorV1.invalidClaim
        }
        if let existing = recordsBySuffix[suffix] {
            guard existing.status != .tombstoned else {
                throw NoctwebNamespaceLedgerErrorV1.suffixTombstoned
            }
            guard existing.ownerRelayID == identity.claim.relayID,
                  existing.ownerSigningPublicKey == identity.claim.signingPublicKey else {
                throw NoctwebNamespaceLedgerErrorV1.suffixAlreadyOwned
            }
            if existing.activeIdentityClaim == identity {
                return
            }
            guard identity.claim.sequence > existing.ownershipSequence else {
                throw NoctwebNamespaceLedgerErrorV1.staleSequence
            }
            recordsBySuffix[suffix] = NoctwebNamespaceRecordV1(
                suffix: suffix,
                ownerRelayID: existing.ownerRelayID,
                ownerSigningPublicKey: existing.ownerSigningPublicKey,
                ownershipSequence: identity.claim.sequence,
                status: .active,
                assignedAt: existing.assignedAt,
                updatedAt: identity.claim.issuedAt,
                activeIdentityClaim: identity
            )
            return
        }
        guard recordsBySuffix.count < NoctwebNamespaceConsensusV1.maximumRecords else {
            throw NoctwebNamespaceLedgerErrorV1.invalidClaim
        }
        recordsBySuffix[suffix] = NoctwebNamespaceRecordV1(
            suffix: suffix,
            ownerRelayID: identity.claim.relayID,
            ownerSigningPublicKey: identity.claim.signingPublicKey,
            ownershipSequence: identity.claim.sequence,
            status: .active,
            assignedAt: identity.claim.issuedAt,
            updatedAt: identity.claim.issuedAt,
            activeIdentityClaim: identity
        )
    }

    public mutating func rotate(
        _ rotation: RelayIdentityRotationV1,
        to newIdentity: SignedRelayIdentityClaimV1,
        now: Date = Date()
    ) throws {
        guard try rotation.verifyThrowing(),
              try newIdentity.verifyThrowing(at: now),
              let suffix = newIdentity.claim.noctwebSuffix,
              let existing = recordsBySuffix[suffix],
              existing.status == .active else {
            throw NoctwebNamespaceLedgerErrorV1.invalidRotation
        }
        guard existing.ownerRelayID == rotation.oldRelayID,
              existing.ownerSigningPublicKey == rotation.oldSigningPublicKey,
              newIdentity.claim.relayID == rotation.newRelayID,
              newIdentity.claim.signingPublicKey == rotation.newSigningPublicKey else {
            throw NoctwebNamespaceLedgerErrorV1.ownershipMismatch
        }
        guard rotation.sequence > existing.ownershipSequence,
              newIdentity.claim.sequence >= rotation.sequence else {
            throw NoctwebNamespaceLedgerErrorV1.staleSequence
        }
        recordsBySuffix[suffix] = NoctwebNamespaceRecordV1(
            suffix: suffix,
            ownerRelayID: rotation.newRelayID,
            ownerSigningPublicKey: rotation.newSigningPublicKey,
            ownershipSequence: rotation.sequence,
            status: .active,
            assignedAt: existing.assignedAt,
            updatedAt: rotation.issuedAt,
            activeIdentityClaim: newIdentity
        )
    }

    public mutating func release(
        _ release: NoctwebNamespaceReleaseV1,
        now: Date = Date()
    ) throws {
        guard let existing = recordsBySuffix[release.suffix],
              existing.status == .active,
              existing.ownerRelayID == release.ownerRelayID else {
            throw NoctwebNamespaceLedgerErrorV1.ownershipMismatch
        }
        guard release.sequence > existing.ownershipSequence else {
            throw NoctwebNamespaceLedgerErrorV1.staleSequence
        }
        guard try release.verifyThrowing(
            ownerSigningPublicKey: existing.ownerSigningPublicKey
        ) else {
            throw NoctwebNamespaceLedgerErrorV1.invalidRelease
        }
        recordsBySuffix[release.suffix] = NoctwebNamespaceRecordV1(
            suffix: existing.suffix,
            ownerRelayID: existing.ownerRelayID,
            ownerSigningPublicKey: existing.ownerSigningPublicKey,
            ownershipSequence: release.sequence,
            status: .tombstoned,
            assignedAt: existing.assignedAt,
            updatedAt: release.issuedAt,
            activeIdentityClaim: nil
        )
    }

    public func record(for suffix: NoctwebRelaySuffixV1) -> NoctwebNamespaceRecordV1? {
        recordsBySuffix[suffix]
    }

    public var records: [NoctwebNamespaceRecordV1] {
        recordsBySuffix.values.sorted { $0.suffix < $1.suffix }
    }

    public func snapshotRecords(at now: Date = Date()) -> [NoctwebNamespaceRecordV1] {
        recordsBySuffix.values.map { record in
            guard record.status == .active,
                  let claim = record.activeIdentityClaim,
                  (try? claim.verifyThrowing(
                      at: now,
                      maximumClockSkew: 0
                  )) != true else {
                return record
            }
            return NoctwebNamespaceRecordV1(
                suffix: record.suffix,
                ownerRelayID: record.ownerRelayID,
                ownerSigningPublicKey: record.ownerSigningPublicKey,
                ownershipSequence: record.ownershipSequence,
                status: record.status,
                assignedAt: record.assignedAt,
                updatedAt: record.updatedAt,
                activeIdentityClaim: nil
            )
        }.sorted { $0.suffix < $1.suffix }
    }

    /// Produces a deterministic payload for all relays that currently hold the
    /// same ownership ledger. Five-minute issuance buckets let independent
    /// members sign byte-identical snapshots without a leader becoming the
    /// namespace authority.
    public func snapshotPayload(
        federation: FederationDescriptor,
        at now: Date = Date()
    ) throws -> NoctwebNamespaceSnapshotPayloadV1 {
        let bucket = NoctwebNamespaceConsensusV1.snapshotTimeBucket
        let issuedAt = Date(
            timeIntervalSince1970:
                floor(now.timeIntervalSince1970 / bucket) * bucket
        )
        let records = snapshotRecords(at: now)
        let epoch = max(
            1,
            records.map(\.ownershipSequence).max() ?? 1
        )
        return try NoctwebNamespaceSnapshotPayloadV1(
            federationMode: federation.mode,
            federationName: federation.name,
            epoch: epoch,
            previousSnapshotDigest: nil,
            records: records,
            issuedAt: issuedAt,
            lifetime:
                NoctwebNamespaceConsensusV1.defaultSnapshotLifetime
        )
    }
}

public struct NoctwebNamespaceSnapshotPayloadV1: Codable, Equatable {
    public let version: Int
    public let federationMode: FederationMode
    public let federationName: String?
    public let epoch: Int
    public let previousSnapshotDigest: Data?
    public let records: [NoctwebNamespaceRecordV1]
    public let recordsDigest: Data
    public let issuedAt: Date
    public let validUntil: Date

    public init(
        federationMode: FederationMode,
        federationName: String?,
        epoch: Int,
        previousSnapshotDigest: Data?,
        records: [NoctwebNamespaceRecordV1],
        issuedAt: Date = Date(),
        lifetime: TimeInterval = 15 * 60
    ) throws {
        let canonicalRecords = records.sorted { $0.suffix < $1.suffix }
        let canonicalIssuedAt = namespaceCanonicalDate(issuedAt)
        guard lifetime.isFinite,
              lifetime > 0,
              lifetime <= NoctwebNamespaceConsensusV1.maximumSnapshotLifetime else {
            throw NoctwebNamespaceLedgerErrorV1.invalidClaim
        }
        version = NoctwebNamespaceConsensusV1.version
        self.federationMode = federationMode
        self.federationName = federationName
        self.epoch = epoch
        self.previousSnapshotDigest = previousSnapshotDigest
        self.records = canonicalRecords
        recordsDigest = Data(
            SHA256.hash(data: try NoctweaveCanonicalJSON.encode(canonicalRecords))
        )
        self.issuedAt = canonicalIssuedAt
        validUntil = namespaceCanonicalDate(
            canonicalIssuedAt.addingTimeInterval(lifetime)
        )
        guard try isStructurallyValidThrowing else {
            throw NoctwebNamespaceLedgerErrorV1.invalidClaim
        }
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard version == NoctwebNamespaceConsensusV1.version,
                  namespaceFederationNameIsCanonical(federationName),
                  (1...RelayIdentityV1.maximumSequence).contains(epoch),
                  previousSnapshotDigest?.count == NoctwebNamespaceConsensusV1.digestBytes
                    || previousSnapshotDigest == nil,
                  records.count <= NoctwebNamespaceConsensusV1.maximumRecords,
                  records == records.sorted(by: { $0.suffix < $1.suffix }),
                  Set(records.map(\.suffix)).count == records.count,
                  try records.allSatisfy({ try $0.isStructurallyValidThrowing }),
                  recordsDigest.count == NoctwebNamespaceConsensusV1.digestBytes,
                  recordsDigest == Data(
                      SHA256.hash(data: try NoctweaveCanonicalJSON.encode(records))
                  ),
                  namespaceIsCanonicalDate(issuedAt),
                  namespaceIsCanonicalDate(validUntil),
                  validUntil > issuedAt,
                  validUntil.timeIntervalSince(issuedAt)
                    <= NoctwebNamespaceConsensusV1.maximumSnapshotLifetime else {
                return false
            }
            return true
        }
    }

    public func transcript() throws -> Data {
        guard try isStructurallyValidThrowing else {
            throw CryptoError.invalidPayload
        }
        var transcript = Data("Noctweave/NoctwebNamespaceSnapshot/v1\u{0}".utf8)
        transcript.append(try NoctweaveCanonicalJSON.encode(self))
        return transcript
    }

    public func digest() throws -> Data {
        Data(SHA256.hash(data: try transcript()))
    }
}

public struct NoctwebNamespaceSnapshotSignatureV1: Codable, Equatable {
    public let signerRelayID: RelayIdentityIDV1
    public let signerPublicKey: Data
    public let signatureAlgorithm: String
    public let signature: Data

    public static func signed(
        payload: NoctwebNamespaceSnapshotPayloadV1,
        by signer: RelayIdentityKeyMaterialV1
    ) throws -> NoctwebNamespaceSnapshotSignatureV1 {
        NoctwebNamespaceSnapshotSignatureV1(
            signerRelayID: signer.relayID,
            signerPublicKey: signer.signingPublicKey,
            signatureAlgorithm: NoctwebNamespaceConsensusV1.signatureAlgorithm,
            signature: try signer.signingKeyPair.sign(payload.transcript())
        )
    }

    public func verifyThrowing(
        payload: NoctwebNamespaceSnapshotPayloadV1
    ) throws -> Bool {
        guard signerRelayID == RelayIdentityIDV1.derived(from: signerPublicKey),
              signatureAlgorithm == NoctwebNamespaceConsensusV1.signatureAlgorithm else {
            return false
        }
        return try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: payload.transcript(),
            publicKeyData: signerPublicKey
        )
    }
}

public struct NoctwebNamespaceConsensusSignerV1: Codable, Equatable {
    public let relayID: RelayIdentityIDV1
    public let signingPublicKey: Data

    public init(relayID: RelayIdentityIDV1, signingPublicKey: Data) {
        self.relayID = relayID
        self.signingPublicKey = signingPublicKey
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard relayID == RelayIdentityIDV1.derived(from: signingPublicKey) else {
                return false
            }
            return try SigningKeyPair.isValidPublicKeyThrowing(signingPublicKey)
        }
    }
}

public struct NoctwebNamespaceConsensusPolicyV1: Codable, Equatable {
    public let federationMode: FederationMode
    public let federationName: String?
    public let signers: [NoctwebNamespaceConsensusSignerV1]
    public let threshold: Int

    public init(
        federationMode: FederationMode,
        federationName: String?,
        signers: [NoctwebNamespaceConsensusSignerV1],
        threshold: Int
    ) {
        self.federationMode = federationMode
        self.federationName = federationName
        self.signers = signers.sorted { $0.relayID < $1.relayID }
        self.threshold = threshold
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard !signers.isEmpty,
                  signers.count <= NoctwebNamespaceConsensusV1.maximumSigners,
                  signers == signers.sorted(by: { $0.relayID < $1.relayID }),
                  Set(signers.map(\.relayID)).count == signers.count,
                  (1...signers.count).contains(threshold),
                  namespaceFederationNameIsCanonical(federationName) else {
                return false
            }
            return try signers.allSatisfy { try $0.isStructurallyValidThrowing }
        }
    }
}

public struct NoctwebNamespaceSnapshotV1: Codable, Equatable {
    public let payload: NoctwebNamespaceSnapshotPayloadV1
    public let signatures: [NoctwebNamespaceSnapshotSignatureV1]

    public init(
        payload: NoctwebNamespaceSnapshotPayloadV1,
        signatures: [NoctwebNamespaceSnapshotSignatureV1]
    ) {
        self.payload = payload
        self.signatures = signatures.sorted { $0.signerRelayID < $1.signerRelayID }
    }

    public static func signed(
        payload: NoctwebNamespaceSnapshotPayloadV1,
        by signers: [RelayIdentityKeyMaterialV1]
    ) throws -> NoctwebNamespaceSnapshotV1 {
        try NoctwebNamespaceSnapshotV1(
            payload: payload,
            signatures: signers.map {
                try NoctwebNamespaceSnapshotSignatureV1.signed(
                    payload: payload,
                    by: $0
                )
            }
        )
    }

    public func verifyThrowing(
        policy: NoctwebNamespaceConsensusPolicyV1,
        at now: Date = Date()
    ) throws -> Bool {
        guard try payload.isStructurallyValidThrowing,
              try policy.isStructurallyValidThrowing,
              payload.federationMode == policy.federationMode,
              payload.federationName == policy.federationName,
              payload.issuedAt <= now.addingTimeInterval(RelayIdentityV1.maximumClockSkew),
              payload.validUntil >= now.addingTimeInterval(-RelayIdentityV1.maximumClockSkew),
              signatures.count <= NoctwebNamespaceConsensusV1.maximumSigners,
              signatures == signatures.sorted(by: { $0.signerRelayID < $1.signerRelayID }),
              Set(signatures.map(\.signerRelayID)).count == signatures.count else {
            return false
        }
        let trusted = Dictionary(
            uniqueKeysWithValues: policy.signers.map { ($0.relayID, $0.signingPublicKey) }
        )
        var accepted = 0
        for signature in signatures {
            guard let trustedKey = trusted[signature.signerRelayID],
                  trustedKey == signature.signerPublicKey,
                  try signature.verifyThrowing(payload: payload) else {
                continue
            }
            accepted += 1
        }
        return accepted >= policy.threshold
    }

    public func record(
        for suffix: NoctwebRelaySuffixV1,
        policy: NoctwebNamespaceConsensusPolicyV1,
        at now: Date = Date()
    ) throws -> NoctwebNamespaceRecordV1? {
        guard try verifyThrowing(policy: policy, at: now) else {
            return nil
        }
        return payload.records.first { $0.suffix == suffix }
    }
}

public enum NoctwebNamespaceSnapshotCollectorV1 {
    /// Combines signatures only when every accepted relay signed the exact
    /// same canonical payload. A conflicting view never contributes toward
    /// quorum and no endpoint supplied by an untrusted signer is accepted.
    public static func verifiedSnapshot(
        from candidates: [NoctwebNamespaceSnapshotV1],
        policy: NoctwebNamespaceConsensusPolicyV1,
        at now: Date = Date()
    ) throws -> NoctwebNamespaceSnapshotV1? {
        guard try policy.isStructurallyValidThrowing,
              candidates.count <= NoctwebNamespaceConsensusV1.maximumSigners
        else {
            return nil
        }

        var groups: [Data: (
            payload: NoctwebNamespaceSnapshotPayloadV1,
            signatures: [RelayIdentityIDV1:
                NoctwebNamespaceSnapshotSignatureV1]
        )] = [:]
        for candidate in candidates {
            guard try candidate.payload.isStructurallyValidThrowing,
                  candidate.payload.federationMode == policy.federationMode,
                  candidate.payload.federationName == policy.federationName,
                  candidate.payload.issuedAt
                    <= now.addingTimeInterval(
                        RelayIdentityV1.maximumClockSkew
                    ),
                  candidate.payload.validUntil
                    >= now.addingTimeInterval(
                        -RelayIdentityV1.maximumClockSkew
                    )
            else {
                continue
            }
            let digest = try candidate.payload.digest()
            var group = groups[digest] ?? (
                payload: candidate.payload,
                signatures: [:]
            )
            guard group.payload == candidate.payload else {
                continue
            }
            for signature in candidate.signatures {
                group.signatures[signature.signerRelayID] = signature
            }
            groups[digest] = group
        }

        let ordered = groups.values.sorted { lhs, rhs in
            if lhs.payload.epoch != rhs.payload.epoch {
                return lhs.payload.epoch > rhs.payload.epoch
            }
            return lhs.payload.recordsDigest.lexicographicallyPrecedes(
                rhs.payload.recordsDigest
            )
        }
        for group in ordered {
            let snapshot = NoctwebNamespaceSnapshotV1(
                payload: group.payload,
                signatures: Array(group.signatures.values)
            )
            if try snapshot.verifyThrowing(policy: policy, at: now) {
                return snapshot
            }
        }
        return nil
    }
}

private func namespaceCanonicalDate(_ value: Date) -> Date {
    Date(timeIntervalSince1970: floor(value.timeIntervalSince1970))
}

private func namespaceIsCanonicalDate(_ value: Date) -> Bool {
    let seconds = value.timeIntervalSince1970
    return seconds.isFinite
        && seconds >= 0
        && seconds <= 4_102_444_800
        && floor(seconds) == seconds
}

private func namespaceFederationNameIsCanonical(_ value: String?) -> Bool {
    guard let value else {
        return true
    }
    let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
    return !normalized.isEmpty
        && normalized == value
        && value.utf8.count <= 1_024
        && !value.unicodeScalars.contains {
            CharacterSet.controlCharacters.contains($0)
        }
}

private func namespaceRequireExactFields<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ keyType: Key.Type
) throws where Key.AllCases: Collection, Key.AllCases.Element == Key {
    let expected = Set(Key.allCases.map(\.stringValue))
    let values = try decoder.container(keyedBy: NamespaceDynamicCodingKey.self)
    guard Set(values.allKeys.map(\.stringValue)) == expected else {
        throw namespaceDecodingError(
            decoder,
            "Noctweb namespace fields must match the current protocol exactly"
        )
    }
}

private struct NamespaceDynamicCodingKey: CodingKey {
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

private func namespaceDecodingError(
    _ decoder: Decoder,
    _ message: String
) -> DecodingError {
    DecodingError.dataCorrupted(
        .init(codingPath: decoder.codingPath, debugDescription: message)
    )
}

private func namespaceEncodingError(
    _ encoder: Encoder,
    _ message: String
) -> EncodingError {
    EncodingError.invalidValue(
        message,
        .init(codingPath: encoder.codingPath, debugDescription: message)
    )
}
