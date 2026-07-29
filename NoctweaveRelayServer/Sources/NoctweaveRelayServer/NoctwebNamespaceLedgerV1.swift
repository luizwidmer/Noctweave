import Crypto
import Foundation

enum NoctwebNamespaceConsensusV1 {
    static let version = 1
    static let maximumRecords = 4_096
    static let maximumSigners = 64
    static let maximumSnapshotLifetime: TimeInterval = 60 * 60
    static let snapshotTimeBucket: TimeInterval = 5 * 60
    static let defaultSnapshotLifetime: TimeInterval = 15 * 60
    static let digestBytes = 32
    static let signatureAlgorithm = RelayIdentityV1.signatureAlgorithm
}

struct NoctwebNamespaceSnapshotRequestV1: Codable, Equatable {
    let version: Int
    let federationMode: FederationMode
    let federationName: String?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case federationMode
        case federationName
    }

    init(federationMode: FederationMode, federationName: String?) {
        version = NoctwebNamespaceConsensusV1.version
        self.federationMode = federationMode
        self.federationName = federationName
    }

    var isStructurallyValid: Bool {
        version == NoctwebNamespaceConsensusV1.version
            && namespaceFederationNameIsCanonical(federationName)
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(
            decoder,
            CodingKeys.self,
            context: "Noctweb namespace snapshot request"
        )
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
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: values,
                debugDescription:
                    "Noctweb namespace snapshot request is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(
                self,
                encoder,
                context: "Noctweb namespace snapshot request"
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(federationMode, forKey: .federationMode)
        try values.encode(federationName, forKey: .federationName)
    }
}

struct NoctwebNamespaceClaimRequestV1: Codable, Equatable {
    let identity: SignedRelayIdentityClaimV1
}

struct NoctwebNamespaceRotationRequestV1: Codable, Equatable {
    let rotation: RelayIdentityRotationV1
    let newIdentity: SignedRelayIdentityClaimV1
}

enum NoctwebNamespaceRecordStatusV1: String, Codable, Equatable {
    case active
    case tombstoned
}

enum NoctwebNamespaceLedgerErrorV1: Error, Equatable {
    case invalidClaim
    case suffixAlreadyOwned
    case suffixTombstoned
    case staleSequence
    case ownershipMismatch
    case invalidRotation
    case invalidRelease
}

/// Ownership outlives endpoint health. An expired identity claim removes live
/// routing data, but does not free the suffix for another relay.
struct NoctwebNamespaceRecordV1: Codable, Equatable {
    let suffix: NoctwebRelaySuffixV1
    let ownerRelayID: RelayIdentityIDV1
    let ownerSigningPublicKey: Data
    let ownershipSequence: Int
    let status: NoctwebNamespaceRecordStatusV1
    let assignedAt: Date
    let updatedAt: Date
    let activeIdentityClaim: SignedRelayIdentityClaimV1?

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

    init(
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

    var isStructurallyValidThrowing: Bool {
        get throws {
            guard suffix.isStructurallyValid,
                  ownerSigningPublicKey.count
                    == OQSSignatureVerifier.mlDSA65PublicKeyBytes,
                  ownerRelayID == RelayIdentityIDV1.derived(
                      from: ownerSigningPublicKey
                  ),
                  (0...RelayIdentityV1.maximumSequence).contains(
                      ownershipSequence
                  ),
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
                          activeIdentityClaim.claim.signingPublicKey
                            == ownerSigningPublicKey,
                          activeIdentityClaim.claim.noctwebSuffix == suffix,
                          activeIdentityClaim.claim.sequence
                            >= ownershipSequence else {
                        return false
                    }
                }
            case .tombstoned:
                guard activeIdentityClaim == nil else { return false }
            }
            return true
        }
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(
            decoder,
            CodingKeys.self,
            context: "Noctweb namespace record"
        )
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
            throw DecodingError.dataCorruptedError(
                forKey: .suffix,
                in: values,
                debugDescription: "Noctweb namespace record is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw invalidModelEncoding(
                self,
                encoder,
                context: "Noctweb namespace record"
            )
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

struct NoctwebNamespaceReleaseV1: Codable, Equatable {
    let version: Int
    let suffix: NoctwebRelaySuffixV1
    let ownerRelayID: RelayIdentityIDV1
    let sequence: Int
    let issuedAt: Date
    let signatureAlgorithm: String
    let signature: Data

    private struct Unsigned: Codable {
        let version: Int
        let suffix: NoctwebRelaySuffixV1
        let ownerRelayID: RelayIdentityIDV1
        let sequence: Int
        let issuedAt: Date
        let signatureAlgorithm: String
    }

    static func signed(
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
            signature: try OQSSignatureVerifier.shared.signThrowing(
                data: try Self.transcript(unsigned),
                privateKey: owner.signingPrivateKey,
                publicKey: owner.signingPublicKey
            )
        )
    }

    func verifyThrowing(ownerSigningPublicKey: Data) throws -> Bool {
        guard version == NoctwebNamespaceConsensusV1.version,
              suffix.isStructurallyValid,
              ownerRelayID == RelayIdentityIDV1.derived(
                  from: ownerSigningPublicKey
              ),
              (1...RelayIdentityV1.maximumSequence).contains(sequence),
              namespaceIsCanonicalDate(issuedAt),
              signatureAlgorithm
                == NoctwebNamespaceConsensusV1.signatureAlgorithm else {
            return false
        }
        return try OQSSignatureVerifier.shared.verifyThrowing(
            signature: signature,
            data: Self.transcript(Unsigned(
                version: version,
                suffix: suffix,
                ownerRelayID: ownerRelayID,
                sequence: sequence,
                issuedAt: issuedAt,
                signatureAlgorithm: signatureAlgorithm
            )),
            publicKey: ownerSigningPublicKey
        )
    }

    private static func transcript(_ unsigned: Unsigned) throws -> Data {
        var transcript = Data(
            "Noctweave/NoctwebNamespaceRelease/v1\u{0}".utf8
        )
        transcript.append(try RelayCanonicalJSON.encode(unsigned))
        return transcript
    }
}

struct NoctwebNamespaceLedgerV1: Codable, Equatable {
    private var recordsBySuffix:
        [NoctwebRelaySuffixV1: NoctwebNamespaceRecordV1]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case records
    }

    init() {
        recordsBySuffix = [:]
    }

    init(records: [NoctwebNamespaceRecordV1]) throws {
        guard records.count <= NoctwebNamespaceConsensusV1.maximumRecords,
              Set(records.map(\.suffix)).count == records.count,
              try records.allSatisfy({
                  try $0.isStructurallyValidThrowing
              }) else {
            throw NoctwebNamespaceLedgerErrorV1.invalidClaim
        }
        recordsBySuffix = Dictionary(
            uniqueKeysWithValues: records.map { ($0.suffix, $0) }
        )
    }

    mutating func claim(
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
                  existing.ownerSigningPublicKey
                    == identity.claim.signingPublicKey else {
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
        guard recordsBySuffix.count
                < NoctwebNamespaceConsensusV1.maximumRecords else {
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

    mutating func rotate(
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
              existing.ownerSigningPublicKey
                == rotation.oldSigningPublicKey,
              newIdentity.claim.relayID == rotation.newRelayID,
              newIdentity.claim.signingPublicKey
                == rotation.newSigningPublicKey else {
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

    mutating func release(
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

    func record(
        for suffix: NoctwebRelaySuffixV1
    ) -> NoctwebNamespaceRecordV1? {
        recordsBySuffix[suffix]
    }

    var records: [NoctwebNamespaceRecordV1] {
        recordsBySuffix.values.sorted { $0.suffix < $1.suffix }
    }

    func snapshotRecords(
        at now: Date = Date()
    ) -> [NoctwebNamespaceRecordV1] {
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

    func snapshotPayload(
        federation: FederationDescriptor,
        at now: Date = Date()
    ) throws -> NoctwebNamespaceSnapshotPayloadV1 {
        let bucket = NoctwebNamespaceConsensusV1.snapshotTimeBucket
        let issuedAt = Date(
            timeIntervalSince1970:
                floor(now.timeIntervalSince1970 / bucket) * bucket
        )
        let records = snapshotRecords(at: now)
        return try NoctwebNamespaceSnapshotPayloadV1(
            federationMode: federation.mode,
            federationName: federation.name,
            epoch: max(
                1,
                records.map(\.ownershipSequence).max() ?? 1
            ),
            previousSnapshotDigest: nil,
            records: records,
            issuedAt: issuedAt,
            lifetime:
                NoctwebNamespaceConsensusV1.defaultSnapshotLifetime
        )
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(
            decoder,
            CodingKeys.self,
            context: "Noctweb namespace ledger"
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let records = try values.decode(
            [NoctwebNamespaceRecordV1].self,
            forKey: .records
        )
        try self.init(records: records)
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(snapshotRecords(), forKey: .records)
    }
}

struct NoctwebNamespaceSnapshotPayloadV1: Codable, Equatable {
    let version: Int
    let federationMode: FederationMode
    let federationName: String?
    let epoch: Int
    let previousSnapshotDigest: Data?
    let records: [NoctwebNamespaceRecordV1]
    let recordsDigest: Data
    let issuedAt: Date
    let validUntil: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case federationMode
        case federationName
        case epoch
        case previousSnapshotDigest
        case records
        case recordsDigest
        case issuedAt
        case validUntil
    }

    init(
        federationMode: FederationMode,
        federationName: String?,
        epoch: Int,
        previousSnapshotDigest: Data?,
        records: [NoctwebNamespaceRecordV1],
        issuedAt: Date = Date(),
        lifetime: TimeInterval =
            NoctwebNamespaceConsensusV1.defaultSnapshotLifetime
    ) throws {
        let canonicalRecords = records.sorted { $0.suffix < $1.suffix }
        let canonicalIssuedAt = namespaceCanonicalDate(issuedAt)
        version = NoctwebNamespaceConsensusV1.version
        self.federationMode = federationMode
        self.federationName = federationName
        self.epoch = epoch
        self.previousSnapshotDigest = previousSnapshotDigest
        self.records = canonicalRecords
        recordsDigest = Data(
            SHA256.hash(
                data: try RelayCanonicalJSON.encode(canonicalRecords)
            )
        )
        self.issuedAt = canonicalIssuedAt
        validUntil = namespaceCanonicalDate(
            canonicalIssuedAt.addingTimeInterval(lifetime)
        )
        guard try isStructurallyValidThrowing else {
            throw NoctwebNamespaceLedgerErrorV1.invalidClaim
        }
    }

    var isStructurallyValidThrowing: Bool {
        get throws {
            guard version == NoctwebNamespaceConsensusV1.version,
                  namespaceFederationNameIsCanonical(federationName),
                  (1...RelayIdentityV1.maximumSequence).contains(epoch),
                  previousSnapshotDigest == nil
                    || previousSnapshotDigest?.count
                        == NoctwebNamespaceConsensusV1.digestBytes,
                  records.count
                    <= NoctwebNamespaceConsensusV1.maximumRecords,
                  records
                    == records.sorted(by: { $0.suffix < $1.suffix }),
                  Set(records.map(\.suffix)).count == records.count,
                  recordsDigest.count
                    == NoctwebNamespaceConsensusV1.digestBytes,
                  namespaceIsCanonicalDate(issuedAt),
                  namespaceIsCanonicalDate(validUntil),
                  validUntil > issuedAt,
                  validUntil.timeIntervalSince(issuedAt)
                    <= NoctwebNamespaceConsensusV1
                        .maximumSnapshotLifetime else {
                return false
            }
            guard try records.allSatisfy({
                try $0.isStructurallyValidThrowing
            }) else {
                return false
            }
            return recordsDigest == Data(
                SHA256.hash(
                    data: try RelayCanonicalJSON.encode(records)
                )
            )
        }
    }

    func transcript() throws -> Data {
        guard try isStructurallyValidThrowing else {
            throw NoctwebNamespaceLedgerErrorV1.invalidClaim
        }
        var transcript = Data(
            "Noctweave/NoctwebNamespaceSnapshot/v1\u{0}".utf8
        )
        transcript.append(try RelayCanonicalJSON.encode(self))
        return transcript
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(
            decoder,
            CodingKeys.self,
            context: "Noctweb namespace snapshot payload"
        )
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
        epoch = try values.decode(Int.self, forKey: .epoch)
        previousSnapshotDigest = try values.decodeIfPresent(
            Data.self,
            forKey: .previousSnapshotDigest
        )
        records = try values.decode(
            [NoctwebNamespaceRecordV1].self,
            forKey: .records
        )
        recordsDigest = try values.decode(
            Data.self,
            forKey: .recordsDigest
        )
        issuedAt = try values.decode(Date.self, forKey: .issuedAt)
        validUntil = try values.decode(Date.self, forKey: .validUntil)
        guard try isStructurallyValidThrowing else {
            throw DecodingError.dataCorruptedError(
                forKey: .records,
                in: values,
                debugDescription:
                    "Noctweb namespace snapshot payload is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw invalidModelEncoding(
                self,
                encoder,
                context: "Noctweb namespace snapshot payload"
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(federationMode, forKey: .federationMode)
        try values.encode(federationName, forKey: .federationName)
        try values.encode(epoch, forKey: .epoch)
        try values.encode(
            previousSnapshotDigest,
            forKey: .previousSnapshotDigest
        )
        try values.encode(records, forKey: .records)
        try values.encode(recordsDigest, forKey: .recordsDigest)
        try values.encode(issuedAt, forKey: .issuedAt)
        try values.encode(validUntil, forKey: .validUntil)
    }
}

struct NoctwebNamespaceSnapshotSignatureV1: Codable, Equatable {
    let signerRelayID: RelayIdentityIDV1
    let signerPublicKey: Data
    let signatureAlgorithm: String
    let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case signerRelayID
        case signerPublicKey
        case signatureAlgorithm
        case signature
    }

    static func signed(
        payload: NoctwebNamespaceSnapshotPayloadV1,
        by signer: RelayIdentityKeyMaterialV1
    ) throws -> NoctwebNamespaceSnapshotSignatureV1 {
        NoctwebNamespaceSnapshotSignatureV1(
            signerRelayID: signer.relayID,
            signerPublicKey: signer.signingPublicKey,
            signatureAlgorithm:
                NoctwebNamespaceConsensusV1.signatureAlgorithm,
            signature: try OQSSignatureVerifier.shared.signThrowing(
                data: payload.transcript(),
                privateKey: signer.signingPrivateKey,
                publicKey: signer.signingPublicKey
            )
        )
    }

    func verifyThrowing(
        payload: NoctwebNamespaceSnapshotPayloadV1
    ) throws -> Bool {
        guard signerRelayID == RelayIdentityIDV1.derived(
            from: signerPublicKey
        ), signatureAlgorithm
            == NoctwebNamespaceConsensusV1.signatureAlgorithm else {
            return false
        }
        return try OQSSignatureVerifier.shared.verifyThrowing(
            signature: signature,
            data: payload.transcript(),
            publicKey: signerPublicKey
        )
    }
}

struct NoctwebNamespaceSnapshotV1: Codable, Equatable {
    let payload: NoctwebNamespaceSnapshotPayloadV1
    let signatures: [NoctwebNamespaceSnapshotSignatureV1]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case payload
        case signatures
    }

    init(
        payload: NoctwebNamespaceSnapshotPayloadV1,
        signatures: [NoctwebNamespaceSnapshotSignatureV1]
    ) {
        self.payload = payload
        self.signatures = signatures.sorted {
            $0.signerRelayID < $1.signerRelayID
        }
    }

    static func signed(
        payload: NoctwebNamespaceSnapshotPayloadV1,
        by signer: RelayIdentityKeyMaterialV1
    ) throws -> NoctwebNamespaceSnapshotV1 {
        try NoctwebNamespaceSnapshotV1(
            payload: payload,
            signatures: [
                NoctwebNamespaceSnapshotSignatureV1.signed(
                    payload: payload,
                    by: signer
                )
            ]
        )
    }

    var isStructurallyValidThrowing: Bool {
        get throws {
            try payload.isStructurallyValidThrowing
                && !signatures.isEmpty
                && signatures.count
                    <= NoctwebNamespaceConsensusV1.maximumSigners
                && signatures == signatures.sorted(by: {
                    $0.signerRelayID < $1.signerRelayID
                })
                && Set(signatures.map(\.signerRelayID)).count
                    == signatures.count
                && signatures.allSatisfy {
                    try $0.verifyThrowing(payload: payload)
                }
        }
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(
            decoder,
            CodingKeys.self,
            context: "Noctweb namespace snapshot"
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            payload: try values.decode(
                NoctwebNamespaceSnapshotPayloadV1.self,
                forKey: .payload
            ),
            signatures: try values.decode(
                [NoctwebNamespaceSnapshotSignatureV1].self,
                forKey: .signatures
            )
        )
        guard try isStructurallyValidThrowing else {
            throw DecodingError.dataCorruptedError(
                forKey: .signatures,
                in: values,
                debugDescription: "Noctweb namespace snapshot is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw invalidModelEncoding(
                self,
                encoder,
                context: "Noctweb namespace snapshot"
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(payload, forKey: .payload)
        try values.encode(signatures, forKey: .signatures)
    }
}

private func namespaceCanonicalDate(_ value: Date) -> Date {
    Date(timeIntervalSince1970: floor(value.timeIntervalSince1970))
}

private func namespaceFederationNameIsCanonical(
    _ value: String?
) -> Bool {
    guard let value else { return true }
    let normalized = value.trimmingCharacters(
        in: .whitespacesAndNewlines
    )
    return !normalized.isEmpty
        && normalized == value
        && value.utf8.count <= 1_024
        && !value.unicodeScalars.contains {
            CharacterSet.controlCharacters.contains($0)
        }
}

private func namespaceIsCanonicalDate(_ value: Date) -> Bool {
    let seconds = value.timeIntervalSince1970
    return seconds.isFinite
        && seconds >= 0
        && seconds <= 4_102_444_800
        && floor(seconds) == seconds
}
