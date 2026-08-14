import CryptoKit
import Foundation

public enum NoctwebDataV1 {
    public static let module = "nw.noctweb-data"
    public static let version = 1
    public static let publisherSignatureAlgorithm = "Ed25519"
    public static let accountSignatureAlgorithm = "ML-DSA-65"
    public static let maximumCollections = 32
    public static let maximumCollectionNameBytes = 48
    public static let maximumRecordIDBytes = 96
    public static let maximumRecordBytes = 64 * 1_024
    public static let maximumRecordsPerDatabase = 10_000
    public static let maximumAccountsPerDatabase = 1_024
    public static let maximumDatabases = 256
    public static let maximumDatabasesPerPublisher = 8
    public static let maximumRecordsPerOwner = 256
    public static let maximumBytesPerOwner = 2 * 1_024 * 1_024
    public static let maximumMutationReplayEntries = 1_024
    public static let maximumMutationReplayBytes = 8 * 1_024 * 1_024
    public static let mutationReplayLifetimeSeconds = 5 * 60 + 31
    public static let authorizationLifetimeSeconds = 2 * 60
    public static let maximumAuthorizationLifetimeSeconds = 5 * 60
    public static let authorizationClockSkewSeconds = 30
    // Eight worst-case encrypted records, including Base64 and ML-DSA
    // provenance, remain below the default 1 MB Swift relay response budget.
    public static let maximumPage = 8
    public static let maximumDatabaseBytes = 64 * 1_024 * 1_024
    public static let maximumTotalDataBytes = 512 * 1_024 * 1_024
    public static let idempotencyKeyBytes = 32
    public static let nonceBytes = 32
    public static let publisherPublicKeyBytes = 32
    public static let publisherSignatureBytes = 64
    public static let accountPublicKeyBytes = 1_952
    public static let accountSignatureBytes = 3_309
    public static let payloadKeyBytes = 32
    public static let payloadKeyIDBytes = 32
    public static let payloadNonceBytes = 12

    public static let capabilityLimits: [String: UInt64] = [
        "maxAccountsPerDatabase": UInt64(maximumAccountsPerDatabase),
        "maxBytesPerOwner": UInt64(maximumBytesPerOwner),
        "maxCollections": UInt64(maximumCollections),
        "maxDatabaseBytes": UInt64(maximumDatabaseBytes),
        "maxDatabases": UInt64(maximumDatabases),
        "maxDatabasesPerPublisher": UInt64(maximumDatabasesPerPublisher),
        "maxIdempotencyBytesPerDatabase": UInt64(maximumMutationReplayBytes),
        "maxIdempotencyEntriesPerDatabase": UInt64(maximumMutationReplayEntries),
        "maxIdempotencyLifetimeSeconds": UInt64(mutationReplayLifetimeSeconds),
        "maxPage": UInt64(maximumPage),
        "maxRecordBytes": UInt64(maximumRecordBytes),
        "maxRecordsPerOwner": UInt64(maximumRecordsPerOwner),
        "maxRecordsPerDatabase": UInt64(maximumRecordsPerDatabase),
        "maxSignedAuthorizationLifetimeSeconds": UInt64(maximumAuthorizationLifetimeSeconds),
        "maxTotalDataBytes": UInt64(maximumTotalDataBytes),
    ]

    public static func advertisedCapabilityLimits(
        databaseCreationEnabled: Bool
    ) -> [String: UInt64] {
        var limits = capabilityLimits
        limits["databaseCreationEnabled"] = databaseCreationEnabled ? 1 : 0
        return limits
    }
}

public enum NoctwebDataReadPolicyV1: String, Codable, Equatable, CaseIterable {
    case publicRead = "public"
    case owner
    case ownerOrPublisher = "owner-or-publisher"
}

public enum NoctwebDataWritePolicyV1: String, Codable, Equatable, CaseIterable {
    case publisher
    case owner
    case ownerOrPublisher = "owner-or-publisher"
}

public enum NoctwebDataActorKindV1: String, Codable, Equatable, CaseIterable {
    case publisher
    case account
}

public struct NoctwebDataOriginV1: Codable, Equatable {
    public let version: Int
    public let relaySuffix: NoctwebRelaySuffixV1
    public let siteLabel: String
    public let publisherID: String
    public let publisherSigningPublicKey: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version, relaySuffix, siteLabel, publisherID, publisherSigningPublicKey
    }

    public init(
        relaySuffix: NoctwebRelaySuffixV1,
        siteLabel: String,
        publisherID: String,
        publisherSigningPublicKey: Data
    ) {
        version = NoctwebDataV1.version
        self.relaySuffix = relaySuffix
        self.siteLabel = siteLabel
        self.publisherID = publisherID
        self.publisherSigningPublicKey = publisherSigningPublicKey
    }

    public var databaseID: String {
        let digest = SHA256.hash(data: NoctwebDataTranscriptV1.origin(self))
        return "nwdb1_" + digest.map { String(format: "%02x", $0) }.joined()
    }

    public var isStructurallyValid: Bool {
        version == NoctwebDataV1.version
            && relaySuffix.isStructurallyValid
            && noctwebDataSiteLabelIsValid(siteLabel)
            && publisherSigningPublicKey.count == NoctwebDataV1.publisherPublicKeyBytes
            && publisherID == noctwebDataPublisherID(for: publisherSigningPublicKey)
    }

    public init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        version = try values.decode(Int.self, forKey: .version)
        relaySuffix = try values.decode(NoctwebRelaySuffixV1.self, forKey: .relaySuffix)
        siteLabel = try values.decode(String.self, forKey: .siteLabel)
        publisherID = try values.decode(String.self, forKey: .publisherID)
        publisherSigningPublicKey = try values.decode(Data.self, forKey: .publisherSigningPublicKey)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb data origin") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(relaySuffix, forKey: .relaySuffix)
        try values.encode(siteLabel, forKey: .siteLabel)
        try values.encode(publisherID, forKey: .publisherID)
        try values.encode(publisherSigningPublicKey, forKey: .publisherSigningPublicKey)
    }
}

public struct NoctwebDataCollectionV1: Codable, Equatable {
    public let name: String
    public let readPolicy: NoctwebDataReadPolicyV1
    public let writePolicy: NoctwebDataWritePolicyV1

    private enum CodingKeys: String, CodingKey, CaseIterable { case name, readPolicy, writePolicy }

    public init(name: String, readPolicy: NoctwebDataReadPolicyV1, writePolicy: NoctwebDataWritePolicyV1) {
        self.name = name
        self.readPolicy = readPolicy
        self.writePolicy = writePolicy
    }

    public var isStructurallyValid: Bool { noctwebDataCollectionNameIsValid(name) }

    public init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        name = try values.decode(String.self, forKey: .name)
        readPolicy = try values.decode(NoctwebDataReadPolicyV1.self, forKey: .readPolicy)
        writePolicy = try values.decode(NoctwebDataWritePolicyV1.self, forKey: .writePolicy)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb data collection") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(name, forKey: .name)
        try values.encode(readPolicy, forKey: .readPolicy)
        try values.encode(writePolicy, forKey: .writePolicy)
    }
}

public struct NoctwebDataAuthorizationV1: Codable, Equatable {
    public let actorKind: NoctwebDataActorKindV1
    public let actorID: String
    public let nonce: Data
    public let expiresAt: Date
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case actorKind, actorID, nonce, expiresAt, signature
    }

    public init(
        actorKind: NoctwebDataActorKindV1,
        actorID: String,
        nonce: Data,
        expiresAt: Date,
        signature: Data
    ) {
        self.actorKind = actorKind
        self.actorID = actorID
        self.nonce = nonce
        self.expiresAt = expiresAt
        self.signature = signature
    }

    public var isStructurallyValid: Bool {
        nonce.count == NoctwebDataV1.nonceBytes
            && noctwebDataActorIDIsValid(actorID, kind: actorKind)
            && noctwebDataDateIsCanonical(expiresAt)
            && signature.count == (actorKind == .publisher
                ? NoctwebDataV1.publisherSignatureBytes
                : NoctwebDataV1.accountSignatureBytes)
    }

    public init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        actorKind = try values.decode(NoctwebDataActorKindV1.self, forKey: .actorKind)
        actorID = try values.decode(String.self, forKey: .actorID)
        nonce = try values.decode(Data.self, forKey: .nonce)
        expiresAt = try values.decode(Date.self, forKey: .expiresAt)
        signature = try values.decode(Data.self, forKey: .signature)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb data authorization") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(actorKind, forKey: .actorKind)
        try values.encode(actorID, forKey: .actorID)
        try values.encode(nonce, forKey: .nonce)
        try values.encode(expiresAt, forKey: .expiresAt)
        try values.encode(signature, forKey: .signature)
    }
}

public struct NoctwebDataDatabaseCreateRequestV1: Codable, Equatable {
    public let databaseID: String
    public let origin: NoctwebDataOriginV1
    public let collections: [NoctwebDataCollectionV1]
    public let idempotencyKey: Data
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case databaseID, origin, collections, idempotencyKey, signature
    }

    public init(
        databaseID: String? = nil,
        origin: NoctwebDataOriginV1,
        collections: [NoctwebDataCollectionV1],
        idempotencyKey: Data,
        signature: Data
    ) {
        self.databaseID = databaseID ?? origin.databaseID
        self.origin = origin
        self.collections = collections.sorted { $0.name < $1.name }
        self.idempotencyKey = idempotencyKey
        self.signature = signature
    }

    public var isStructurallyValid: Bool {
        origin.isStructurallyValid
            && databaseID == origin.databaseID
            && !collections.isEmpty
            && collections.count <= NoctwebDataV1.maximumCollections
            && collections.allSatisfy(\.isStructurallyValid)
            && collections.map(\.name) == collections.map(\.name).sorted()
            && Set(collections.map(\.name)).count == collections.count
            && idempotencyKey.count == NoctwebDataV1.idempotencyKeyBytes
            && signature.count == NoctwebDataV1.publisherSignatureBytes
    }

    public func verifyPublisherSignature() -> Bool {
        guard isStructurallyValid,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: origin.publisherSigningPublicKey) else { return false }
        return key.isValidSignature(signature, for: NoctwebDataTranscriptV1.createDatabase(self))
    }

    public init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        origin = try values.decode(NoctwebDataOriginV1.self, forKey: .origin)
        collections = try values.decode([NoctwebDataCollectionV1].self, forKey: .collections)
        idempotencyKey = try values.decode(Data.self, forKey: .idempotencyKey)
        signature = try values.decode(Data.self, forKey: .signature)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb database creation request") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID)
        try values.encode(origin, forKey: .origin)
        try values.encode(collections, forKey: .collections)
        try values.encode(idempotencyKey, forKey: .idempotencyKey)
        try values.encode(signature, forKey: .signature)
    }
}

public struct NoctwebDataDatabaseReceiptV1: Codable, Equatable {
    public let databaseID: String
    public let created: Bool
    public init(databaseID: String, created: Bool) { self.databaseID = databaseID; self.created = created }
    private enum CodingKeys: String, CodingKey, CaseIterable { case databaseID, created }
    public var isStructurallyValid: Bool { noctwebDataDatabaseIDIsValid(databaseID) }
    public init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        created = try values.decode(Bool.self, forKey: .created)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb database receipt") }
    }
    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID)
        try values.encode(created, forKey: .created)
    }
}

public struct NoctwebDataAccountRegisterRequestV1: Codable, Equatable {
    public let databaseID: String
    public let accountID: String
    public let accountSigningPublicKey: Data
    public let idempotencyKey: Data
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable { case databaseID, accountID, accountSigningPublicKey, idempotencyKey, signature }

    public init(databaseID: String, accountID: String, accountSigningPublicKey: Data, idempotencyKey: Data, signature: Data) {
        self.databaseID = databaseID
        self.accountID = accountID
        self.accountSigningPublicKey = accountSigningPublicKey
        self.idempotencyKey = idempotencyKey
        self.signature = signature
    }

    public static func accountID(databaseID: String, publicKey: Data) -> String {
        let digest = SHA256.hash(data: NoctwebDataTranscriptV1.accountIdentity(databaseID: databaseID, publicKey: publicKey))
        return "nwa1_" + digest.map { String(format: "%02x", $0) }.joined()
    }

    public var isStructurallyValid: Bool {
        noctwebDataDatabaseIDIsValid(databaseID)
            && accountSigningPublicKey.count == NoctwebDataV1.accountPublicKeyBytes
            && accountID == Self.accountID(databaseID: databaseID, publicKey: accountSigningPublicKey)
            && idempotencyKey.count == NoctwebDataV1.idempotencyKeyBytes
            && signature.count == NoctwebDataV1.accountSignatureBytes
    }

    public func verifyAccountSignatureThrowing() throws -> Bool {
        guard isStructurallyValid else { return false }
        return try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: NoctwebDataTranscriptV1.registerAccount(self),
            publicKeyData: accountSigningPublicKey
        )
    }

    public init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        accountID = try values.decode(String.self, forKey: .accountID)
        accountSigningPublicKey = try values.decode(Data.self, forKey: .accountSigningPublicKey)
        idempotencyKey = try values.decode(Data.self, forKey: .idempotencyKey)
        signature = try values.decode(Data.self, forKey: .signature)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb account registration request") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID)
        try values.encode(accountID, forKey: .accountID)
        try values.encode(accountSigningPublicKey, forKey: .accountSigningPublicKey)
        try values.encode(idempotencyKey, forKey: .idempotencyKey)
        try values.encode(signature, forKey: .signature)
    }
}

public struct NoctwebDataAccountReceiptV1: Codable, Equatable {
    public let databaseID: String
    public let accountID: String
    public let created: Bool
    public init(databaseID: String, accountID: String, created: Bool) { self.databaseID = databaseID; self.accountID = accountID; self.created = created }
    private enum CodingKeys: String, CodingKey, CaseIterable { case databaseID, accountID, created }
    public var isStructurallyValid: Bool {
        noctwebDataDatabaseIDIsValid(databaseID) && noctwebDataAccountIDIsValid(accountID)
    }
    public init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        accountID = try values.decode(String.self, forKey: .accountID)
        created = try values.decode(Bool.self, forKey: .created)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb account receipt") }
    }
    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID)
        try values.encode(accountID, forKey: .accountID)
        try values.encode(created, forKey: .created)
    }
}

public struct NoctwebDataRecordPutRequestV1: Codable, Equatable {
    public let databaseID: String
    public let collection: String
    public let recordID: String
    public let ownerAccountID: String?
    public let payload: Data
    public let expectedRevision: UInt64
    public let idempotencyKey: Data
    public let authorization: NoctwebDataAuthorizationV1

    private enum CodingKeys: String, CodingKey, CaseIterable { case databaseID, collection, recordID, ownerAccountID, payload, expectedRevision, idempotencyKey, authorization }

    public init(databaseID: String, collection: String, recordID: String, ownerAccountID: String?, payload: Data, expectedRevision: UInt64, idempotencyKey: Data, authorization: NoctwebDataAuthorizationV1) {
        self.databaseID = databaseID; self.collection = collection; self.recordID = recordID
        self.ownerAccountID = ownerAccountID; self.payload = payload; self.expectedRevision = expectedRevision
        self.idempotencyKey = idempotencyKey; self.authorization = authorization
    }

    public var isStructurallyValid: Bool {
        noctwebDataDatabaseIDIsValid(databaseID) && noctwebDataCollectionNameIsValid(collection)
            && noctwebDataRecordIDIsValid(recordID) && ownerAccountID.map(noctwebDataAccountIDIsValid) != false
            && !payload.isEmpty && payload.count <= NoctwebDataV1.maximumRecordBytes
            && noctwebDataEncryptedPayload(from: payload) != nil
            && expectedRevision < UInt64.max && idempotencyKey.count == NoctwebDataV1.idempotencyKeyBytes
            && authorization.isStructurallyValid
            && (authorization.actorKind != .account
                || ownerAccountID == authorization.actorID)
    }

    public init(from decoder: Decoder) throws {
        try noctwebDataRequireAllowed(
            decoder,
            CodingKeys.self,
            required: ["databaseID", "collection", "recordID", "payload", "expectedRevision", "idempotencyKey", "authorization"]
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        collection = try values.decode(String.self, forKey: .collection)
        recordID = try values.decode(String.self, forKey: .recordID)
        ownerAccountID = try values.decodeIfPresent(String.self, forKey: .ownerAccountID)
        payload = try values.decode(Data.self, forKey: .payload)
        expectedRevision = try values.decode(UInt64.self, forKey: .expectedRevision)
        idempotencyKey = try values.decode(Data.self, forKey: .idempotencyKey)
        authorization = try values.decode(NoctwebDataAuthorizationV1.self, forKey: .authorization)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb record put request") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID)
        try values.encode(collection, forKey: .collection)
        try values.encode(recordID, forKey: .recordID)
        try values.encodeIfPresent(ownerAccountID, forKey: .ownerAccountID)
        try values.encode(payload, forKey: .payload)
        try values.encode(expectedRevision, forKey: .expectedRevision)
        try values.encode(idempotencyKey, forKey: .idempotencyKey)
        try values.encode(authorization, forKey: .authorization)
    }
}

public struct NoctwebDataRecordGetRequestV1: Codable, Equatable {
    public let databaseID: String
    public let collection: String
    public let recordID: String
    public let ownerAccountID: String?
    public let authorization: NoctwebDataAuthorizationV1?
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case databaseID, collection, recordID, ownerAccountID, authorization
    }
    public init(databaseID: String, collection: String, recordID: String, ownerAccountID: String? = nil, authorization: NoctwebDataAuthorizationV1? = nil) { self.databaseID = databaseID; self.collection = collection; self.recordID = recordID; self.ownerAccountID = ownerAccountID; self.authorization = authorization }
    public var isStructurallyValid: Bool {
        noctwebDataDatabaseIDIsValid(databaseID)
            && noctwebDataCollectionNameIsValid(collection)
            && noctwebDataRecordIDIsValid(recordID)
            && ownerAccountID.map(noctwebDataAccountIDIsValid) != false
            && authorization?.isStructurallyValid != false
            && (authorization?.actorKind != .account
                || ownerAccountID == authorization?.actorID)
    }

    public init(from decoder: Decoder) throws {
        try noctwebDataRequireAllowed(
            decoder,
            CodingKeys.self,
            required: ["databaseID", "collection", "recordID"]
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        collection = try values.decode(String.self, forKey: .collection)
        recordID = try values.decode(String.self, forKey: .recordID)
        ownerAccountID = try values.decodeIfPresent(String.self, forKey: .ownerAccountID)
        authorization = try values.decodeIfPresent(NoctwebDataAuthorizationV1.self, forKey: .authorization)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb record get request") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID)
        try values.encode(collection, forKey: .collection)
        try values.encode(recordID, forKey: .recordID)
        try values.encodeIfPresent(ownerAccountID, forKey: .ownerAccountID)
        try values.encodeIfPresent(authorization, forKey: .authorization)
    }
}

public struct NoctwebDataRecordListRequestV1: Codable, Equatable {
    public let databaseID: String
    public let collection: String
    public let afterRecordID: String?
    public let ownerAccountID: String?
    public let limit: Int
    public let authorization: NoctwebDataAuthorizationV1?
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case databaseID, collection, afterRecordID, ownerAccountID, limit, authorization
    }
    public init(databaseID: String, collection: String, afterRecordID: String? = nil, ownerAccountID: String? = nil, limit: Int = NoctwebDataV1.maximumPage, authorization: NoctwebDataAuthorizationV1? = nil) { self.databaseID = databaseID; self.collection = collection; self.afterRecordID = afterRecordID; self.ownerAccountID = ownerAccountID; self.limit = limit; self.authorization = authorization }
    public var isStructurallyValid: Bool {
        noctwebDataDatabaseIDIsValid(databaseID)
            && noctwebDataCollectionNameIsValid(collection)
            && afterRecordID.map(noctwebDataRecordIDIsValid) != false
            && ownerAccountID.map(noctwebDataAccountIDIsValid) != false
            && (1...NoctwebDataV1.maximumPage).contains(limit)
            && authorization?.isStructurallyValid != false
            && (authorization?.actorKind != .account
                || ownerAccountID == authorization?.actorID)
    }

    public init(from decoder: Decoder) throws {
        try noctwebDataRequireAllowed(
            decoder,
            CodingKeys.self,
            required: ["databaseID", "collection", "limit"]
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        collection = try values.decode(String.self, forKey: .collection)
        afterRecordID = try values.decodeIfPresent(String.self, forKey: .afterRecordID)
        ownerAccountID = try values.decodeIfPresent(String.self, forKey: .ownerAccountID)
        limit = try values.decode(Int.self, forKey: .limit)
        authorization = try values.decodeIfPresent(NoctwebDataAuthorizationV1.self, forKey: .authorization)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb record list request") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID)
        try values.encode(collection, forKey: .collection)
        try values.encodeIfPresent(afterRecordID, forKey: .afterRecordID)
        try values.encodeIfPresent(ownerAccountID, forKey: .ownerAccountID)
        try values.encode(limit, forKey: .limit)
        try values.encodeIfPresent(authorization, forKey: .authorization)
    }
}

public struct NoctwebDataRecordDeleteRequestV1: Codable, Equatable {
    public let databaseID: String
    public let collection: String
    public let recordID: String
    public let ownerAccountID: String?
    public let expectedRevision: UInt64
    public let idempotencyKey: Data
    public let authorization: NoctwebDataAuthorizationV1
    private enum CodingKeys: String, CodingKey, CaseIterable { case databaseID, collection, recordID, ownerAccountID, expectedRevision, idempotencyKey, authorization }
    public init(databaseID: String, collection: String, recordID: String, ownerAccountID: String? = nil, expectedRevision: UInt64, idempotencyKey: Data, authorization: NoctwebDataAuthorizationV1) { self.databaseID = databaseID; self.collection = collection; self.recordID = recordID; self.ownerAccountID = ownerAccountID; self.expectedRevision = expectedRevision; self.idempotencyKey = idempotencyKey; self.authorization = authorization }
    public var isStructurallyValid: Bool {
        noctwebDataDatabaseIDIsValid(databaseID)
            && noctwebDataCollectionNameIsValid(collection)
            && noctwebDataRecordIDIsValid(recordID)
            && ownerAccountID.map(noctwebDataAccountIDIsValid) != false
            && expectedRevision > 0
            && idempotencyKey.count == NoctwebDataV1.idempotencyKeyBytes
            && authorization.isStructurallyValid
            && (authorization.actorKind != .account
                || ownerAccountID == authorization.actorID)
    }

    public init(from decoder: Decoder) throws {
        try noctwebDataRequireAllowed(decoder, CodingKeys.self, required: ["databaseID", "collection", "recordID", "expectedRevision", "idempotencyKey", "authorization"])
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        collection = try values.decode(String.self, forKey: .collection)
        recordID = try values.decode(String.self, forKey: .recordID)
        ownerAccountID = try values.decodeIfPresent(String.self, forKey: .ownerAccountID)
        expectedRevision = try values.decode(UInt64.self, forKey: .expectedRevision)
        idempotencyKey = try values.decode(Data.self, forKey: .idempotencyKey)
        authorization = try values.decode(NoctwebDataAuthorizationV1.self, forKey: .authorization)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb record delete request") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID)
        try values.encode(collection, forKey: .collection)
        try values.encode(recordID, forKey: .recordID)
        try values.encodeIfPresent(ownerAccountID, forKey: .ownerAccountID)
        try values.encode(expectedRevision, forKey: .expectedRevision)
        try values.encode(idempotencyKey, forKey: .idempotencyKey)
        try values.encode(authorization, forKey: .authorization)
    }
}

/// Strict envelope carried in every relay-visible record payload. The relay
/// can validate bounds and format but never receives the 256-bit application
/// key needed to authenticate or decrypt the ciphertext.
public struct NoctwebDataEncryptedPayloadV1: Codable, Equatable {
    public let version: Int
    public let algorithm: String
    public let keyID: Data
    public let nonce: Data
    public let ciphertext: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version, algorithm, keyID, nonce, ciphertext
    }

    public init(keyID: Data, nonce: Data, ciphertext: Data) {
        version = NoctwebDataV1.version
        algorithm = "AES-256-GCM"
        self.keyID = keyID
        self.nonce = nonce
        self.ciphertext = ciphertext
    }

    public var isStructurallyValid: Bool {
        version == NoctwebDataV1.version
            && algorithm == "AES-256-GCM"
            && keyID.count == NoctwebDataV1.payloadKeyIDBytes
            && nonce.count == NoctwebDataV1.payloadNonceBytes
            && ciphertext.count > 16
            && ciphertext.count <= NoctwebDataV1.maximumRecordBytes
    }

    public init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        version = try values.decode(Int.self, forKey: .version)
        algorithm = try values.decode(String.self, forKey: .algorithm)
        keyID = try values.decode(Data.self, forKey: .keyID)
        nonce = try values.decode(Data.self, forKey: .nonce)
        ciphertext = try values.decode(Data.self, forKey: .ciphertext)
        guard isStructurallyValid else {
            throw noctwebDataDecodingError(decoder, "Invalid encrypted Noctweb payload")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(algorithm, forKey: .algorithm)
        try values.encode(keyID, forKey: .keyID)
        try values.encode(nonce, forKey: .nonce)
        try values.encode(ciphertext, forKey: .ciphertext)
    }
}

/// Durable author proof retained with the record. It lets clients detect a
/// relay/SQLite operator forging or changing record identifiers, ownership,
/// ciphertext, or revision.
public struct NoctwebDataRecordProvenanceV1: Codable, Equatable {
    public let actorKind: NoctwebDataActorKindV1
    public let actorID: String
    public let actorSigningPublicKey: Data
    public let authorizationNonce: Data
    public let authorizationExpiresAt: Date
    public let idempotencyKey: Data
    public let expectedRevision: UInt64
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case actorKind, actorID, actorSigningPublicKey, authorizationNonce
        case authorizationExpiresAt, idempotencyKey, expectedRevision, signature
    }

    public init(
        actorKind: NoctwebDataActorKindV1,
        actorID: String,
        actorSigningPublicKey: Data,
        authorizationNonce: Data,
        authorizationExpiresAt: Date,
        idempotencyKey: Data,
        expectedRevision: UInt64,
        signature: Data
    ) {
        self.actorKind = actorKind
        self.actorID = actorID
        self.actorSigningPublicKey = actorSigningPublicKey
        self.authorizationNonce = authorizationNonce
        self.authorizationExpiresAt = authorizationExpiresAt
        self.idempotencyKey = idempotencyKey
        self.expectedRevision = expectedRevision
        self.signature = signature
    }

    public var isStructurallyValid: Bool {
        noctwebDataActorIDIsValid(actorID, kind: actorKind)
            && actorSigningPublicKey.count == (actorKind == .publisher
                ? NoctwebDataV1.publisherPublicKeyBytes
                : NoctwebDataV1.accountPublicKeyBytes)
            && authorizationNonce.count == NoctwebDataV1.nonceBytes
            && noctwebDataDateIsCanonical(authorizationExpiresAt)
            && idempotencyKey.count == NoctwebDataV1.idempotencyKeyBytes
            && expectedRevision < UInt64.max
            && signature.count == (actorKind == .publisher
                ? NoctwebDataV1.publisherSignatureBytes
                : NoctwebDataV1.accountSignatureBytes)
    }

    public init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        actorKind = try values.decode(NoctwebDataActorKindV1.self, forKey: .actorKind)
        actorID = try values.decode(String.self, forKey: .actorID)
        actorSigningPublicKey = try values.decode(Data.self, forKey: .actorSigningPublicKey)
        authorizationNonce = try values.decode(Data.self, forKey: .authorizationNonce)
        authorizationExpiresAt = try values.decode(Date.self, forKey: .authorizationExpiresAt)
        idempotencyKey = try values.decode(Data.self, forKey: .idempotencyKey)
        expectedRevision = try values.decode(UInt64.self, forKey: .expectedRevision)
        signature = try values.decode(Data.self, forKey: .signature)
        guard isStructurallyValid else {
            throw noctwebDataDecodingError(decoder, "Invalid Noctweb record provenance")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(actorKind, forKey: .actorKind)
        try values.encode(actorID, forKey: .actorID)
        try values.encode(actorSigningPublicKey, forKey: .actorSigningPublicKey)
        try values.encode(authorizationNonce, forKey: .authorizationNonce)
        try values.encode(authorizationExpiresAt, forKey: .authorizationExpiresAt)
        try values.encode(idempotencyKey, forKey: .idempotencyKey)
        try values.encode(expectedRevision, forKey: .expectedRevision)
        try values.encode(signature, forKey: .signature)
    }
}

public struct NoctwebDataRecordV1: Codable, Equatable {
    public let databaseID: String
    public let collection: String
    public let recordID: String
    public let ownerAccountID: String?
    public let payload: Data
    public let revision: UInt64
    public let createdAt: Date
    public let updatedAt: Date
    public let provenance: NoctwebDataRecordProvenanceV1

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case databaseID, collection, recordID, ownerAccountID, payload
        case revision, createdAt, updatedAt, provenance
    }

    public init(databaseID: String, collection: String, recordID: String, ownerAccountID: String?, payload: Data, revision: UInt64, createdAt: Date, updatedAt: Date, provenance: NoctwebDataRecordProvenanceV1) {
        self.databaseID = databaseID; self.collection = collection; self.recordID = recordID
        self.ownerAccountID = ownerAccountID; self.payload = payload; self.revision = revision
        self.createdAt = createdAt; self.updatedAt = updatedAt; self.provenance = provenance
    }

    public var isStructurallyValid: Bool {
        noctwebDataDatabaseIDIsValid(databaseID) && noctwebDataCollectionNameIsValid(collection)
            && noctwebDataRecordIDIsValid(recordID) && ownerAccountID.map(noctwebDataAccountIDIsValid) != false
            && !payload.isEmpty && payload.count <= NoctwebDataV1.maximumRecordBytes && revision > 0
            && noctwebDataDateIsCanonical(createdAt) && noctwebDataDateIsCanonical(updatedAt) && updatedAt >= createdAt
            && noctwebDataEncryptedPayload(from: payload) != nil
            && provenance.isStructurallyValid
            && provenance.expectedRevision + 1 == revision
            && (provenance.actorKind != .account
                || ownerAccountID == provenance.actorID)
    }

    public init(from decoder: Decoder) throws {
        try noctwebDataRequireAllowed(
            decoder,
            CodingKeys.self,
            required: ["databaseID", "collection", "recordID", "payload", "revision", "createdAt", "updatedAt", "provenance"]
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        collection = try values.decode(String.self, forKey: .collection)
        recordID = try values.decode(String.self, forKey: .recordID)
        ownerAccountID = try values.decodeIfPresent(String.self, forKey: .ownerAccountID)
        payload = try values.decode(Data.self, forKey: .payload)
        revision = try values.decode(UInt64.self, forKey: .revision)
        createdAt = try values.decode(Date.self, forKey: .createdAt)
        updatedAt = try values.decode(Date.self, forKey: .updatedAt)
        provenance = try values.decode(NoctwebDataRecordProvenanceV1.self, forKey: .provenance)
        guard isStructurallyValid else {
            throw noctwebDataDecodingError(decoder, "Invalid Noctweb data record")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID)
        try values.encode(collection, forKey: .collection)
        try values.encode(recordID, forKey: .recordID)
        try values.encodeIfPresent(ownerAccountID, forKey: .ownerAccountID)
        try values.encode(payload, forKey: .payload)
        try values.encode(revision, forKey: .revision)
        try values.encode(createdAt, forKey: .createdAt)
        try values.encode(updatedAt, forKey: .updatedAt)
        try values.encode(provenance, forKey: .provenance)
    }

    public func verifyProvenanceThrowing(origin: NoctwebDataOriginV1) throws -> Bool {
        guard isStructurallyValid, origin.databaseID == databaseID else { return false }
        let authorization = NoctwebDataAuthorizationV1(
            actorKind: provenance.actorKind,
            actorID: provenance.actorID,
            nonce: provenance.authorizationNonce,
            expiresAt: provenance.authorizationExpiresAt,
            signature: provenance.signature
        )
        let request = NoctwebDataRecordPutRequestV1(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: ownerAccountID,
            payload: payload,
            expectedRevision: provenance.expectedRevision,
            idempotencyKey: provenance.idempotencyKey,
            authorization: authorization
        )
        let transcript = NoctwebDataTranscriptV1.putRecord(request)
        switch provenance.actorKind {
        case .publisher:
            guard provenance.actorID == origin.publisherID,
                  provenance.actorSigningPublicKey == origin.publisherSigningPublicKey,
                  let key = try? Curve25519.Signing.PublicKey(
                    rawRepresentation: provenance.actorSigningPublicKey
                  ) else { return false }
            return key.isValidSignature(provenance.signature, for: transcript)
        case .account:
            guard provenance.actorID == NoctwebDataAccountRegisterRequestV1.accountID(
                databaseID: databaseID,
                publicKey: provenance.actorSigningPublicKey
            ) else { return false }
            return try SigningKeyPair.verifyThrowing(
                signature: provenance.signature,
                data: transcript,
                publicKeyData: provenance.actorSigningPublicKey
            )
        }
    }
}

public struct NoctwebDataRecordListV1: Codable, Equatable {
    public let records: [NoctwebDataRecordV1]
    public let nextCursor: String?
    public init(records: [NoctwebDataRecordV1], nextCursor: String?) { self.records = records; self.nextCursor = nextCursor }
    private enum CodingKeys: String, CodingKey, CaseIterable { case records, nextCursor }
    public var isStructurallyValid: Bool {
        records.count <= NoctwebDataV1.maximumPage
            && records.allSatisfy(\.isStructurallyValid)
            && zip(records, records.dropFirst()).allSatisfy {
                $0.0.recordID < $0.1.recordID
            }
            && nextCursor.map(noctwebDataRecordIDIsValid) != false
            && (nextCursor == nil || nextCursor == records.last?.recordID)
    }
    public init(from decoder: Decoder) throws {
        try noctwebDataRequireAllowed(decoder, CodingKeys.self, required: ["records"])
        let values = try decoder.container(keyedBy: CodingKeys.self)
        records = try values.decode([NoctwebDataRecordV1].self, forKey: .records)
        nextCursor = try values.decodeIfPresent(String.self, forKey: .nextCursor)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb record list") }
    }
    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(records, forKey: .records)
        try values.encodeIfPresent(nextCursor, forKey: .nextCursor)
    }
}

public struct NoctwebDataDeleteReceiptV1: Codable, Equatable {
    public let databaseID: String
    public let collection: String
    public let recordID: String
    public let ownerAccountID: String?
    public let deletedRevision: UInt64
    public init(databaseID: String, collection: String, recordID: String, ownerAccountID: String? = nil, deletedRevision: UInt64) { self.databaseID = databaseID; self.collection = collection; self.recordID = recordID; self.ownerAccountID = ownerAccountID; self.deletedRevision = deletedRevision }
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case databaseID, collection, recordID, ownerAccountID, deletedRevision
    }
    public var isStructurallyValid: Bool {
        noctwebDataDatabaseIDIsValid(databaseID)
            && noctwebDataCollectionNameIsValid(collection)
            && noctwebDataRecordIDIsValid(recordID)
            && ownerAccountID.map(noctwebDataAccountIDIsValid) != false
            && deletedRevision > 0
    }
    public init(from decoder: Decoder) throws {
        try noctwebDataRequireAllowed(
            decoder,
            CodingKeys.self,
            required: ["databaseID", "collection", "recordID", "deletedRevision"]
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        collection = try values.decode(String.self, forKey: .collection)
        recordID = try values.decode(String.self, forKey: .recordID)
        ownerAccountID = try values.decodeIfPresent(String.self, forKey: .ownerAccountID)
        deletedRevision = try values.decode(UInt64.self, forKey: .deletedRevision)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb deletion receipt") }
    }
    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID)
        try values.encode(collection, forKey: .collection)
        try values.encode(recordID, forKey: .recordID)
        try values.encodeIfPresent(ownerAccountID, forKey: .ownerAccountID)
        try values.encode(deletedRevision, forKey: .deletedRevision)
    }
}

public enum NoctwebDataTranscriptV1 {
    public static func encryptedPayloadAAD(
        databaseID: String,
        collection: String,
        recordID: String,
        ownerAccountID: String?,
        revision: UInt64,
        keyID: Data
    ) -> Data {
        var data = domain("org.noctweave.noctweb/encrypted-payload/v1")
        append(databaseID, to: &data); append(collection, to: &data)
        append(recordID, to: &data); append(ownerAccountID, to: &data)
        append(revision, to: &data); append(keyID, to: &data)
        return data
    }

    public static func origin(_ origin: NoctwebDataOriginV1) -> Data {
        var data = domain("org.noctweave.noctweb/data-origin/v1")
        append(origin.relaySuffix.rawValue, to: &data); append(origin.siteLabel, to: &data)
        append(origin.publisherID, to: &data); append(origin.publisherSigningPublicKey, to: &data)
        return data
    }

    public static func createDatabase(_ request: NoctwebDataDatabaseCreateRequestV1) -> Data {
        var data = domain("org.noctweave.noctweb/data-create/v1")
        append(request.databaseID, to: &data); append(origin(request.origin), to: &data)
        append(UInt64(request.collections.count), to: &data)
        for item in request.collections { append(item.name, to: &data); append(item.readPolicy.rawValue, to: &data); append(item.writePolicy.rawValue, to: &data) }
        append(request.idempotencyKey, to: &data); return data
    }

    public static func accountIdentity(databaseID: String, publicKey: Data) -> Data {
        var data = domain("org.noctweave.noctweb/account-id/v1")
        append(databaseID, to: &data); append(publicKey, to: &data); return data
    }

    public static func registerAccount(_ request: NoctwebDataAccountRegisterRequestV1) -> Data {
        var data = domain("org.noctweave.noctweb/account-register/v1")
        append(request.databaseID, to: &data); append(request.accountID, to: &data)
        append(request.accountSigningPublicKey, to: &data); append(request.idempotencyKey, to: &data); return data
    }

    public static func putRecord(_ request: NoctwebDataRecordPutRequestV1) -> Data {
        var data = authorizedDomain("org.noctweave.noctweb/data-put/v1", request.authorization)
        append(request.databaseID, to: &data); append(request.collection, to: &data); append(request.recordID, to: &data)
        append(request.ownerAccountID, to: &data); append(request.payload, to: &data)
        append(request.expectedRevision, to: &data); append(request.idempotencyKey, to: &data); return data
    }

    public static func getRecord(_ request: NoctwebDataRecordGetRequestV1) -> Data {
        var data = optionalAuthorizedDomain("org.noctweave.noctweb/data-get/v1", request.authorization)
        append(request.databaseID, to: &data); append(request.collection, to: &data)
        append(request.recordID, to: &data); append(request.ownerAccountID, to: &data); return data
    }

    public static func listRecords(_ request: NoctwebDataRecordListRequestV1) -> Data {
        var data = optionalAuthorizedDomain("org.noctweave.noctweb/data-list/v1", request.authorization)
        append(request.databaseID, to: &data); append(request.collection, to: &data)
        append(request.afterRecordID, to: &data); append(request.ownerAccountID, to: &data)
        append(UInt64(request.limit), to: &data); return data
    }

    public static func deleteRecord(_ request: NoctwebDataRecordDeleteRequestV1) -> Data {
        var data = authorizedDomain("org.noctweave.noctweb/data-delete/v1", request.authorization)
        append(request.databaseID, to: &data); append(request.collection, to: &data); append(request.recordID, to: &data)
        append(request.ownerAccountID, to: &data); append(request.expectedRevision, to: &data)
        append(request.idempotencyKey, to: &data); return data
    }

    private static func authorizedDomain(_ value: String, _ authorization: NoctwebDataAuthorizationV1) -> Data {
        var data = domain(value); append(authorization.actorKind.rawValue, to: &data)
        append(authorization.actorID, to: &data); append(authorization.nonce, to: &data)
        append(authorization.expiresAt, to: &data); return data
    }

    private static func optionalAuthorizedDomain(_ value: String, _ authorization: NoctwebDataAuthorizationV1?) -> Data {
        var data = domain(value); data.append(authorization == nil ? 0 : 1)
        if let authorization {
            append(authorization.actorKind.rawValue, to: &data)
            append(authorization.actorID, to: &data)
            append(authorization.nonce, to: &data)
            append(authorization.expiresAt, to: &data)
        }
        return data
    }

    private static func domain(_ value: String) -> Data { var data = Data(value.utf8); data.append(0); return data }
    private static func append(_ value: String, to data: inout Data) { append(Data(value.utf8), to: &data) }
    private static func append(_ value: String?, to data: inout Data) { data.append(value == nil ? 0 : 1); if let value { append(value, to: &data) } }
    private static func append(_ value: Data, to data: inout Data) { append(UInt64(value.count), to: &data); data.append(value) }
    private static func append(_ value: Date, to data: inout Data) {
        append(UInt64(value.timeIntervalSince1970), to: &data)
    }
    private static func append(_ value: UInt64, to data: inout Data) { var bigEndian = value.bigEndian; Swift.withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) } }
}

public func noctwebDataPublisherID(for publicKey: Data) -> String {
    var data = Data("org.noctweave.noctweb/publisher-id/v1".utf8); data.append(0); data.append(publicKey)
    return "nwpub1_" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

public func noctwebDataEncodeEncryptedPayload(
    _ envelope: NoctwebDataEncryptedPayloadV1
) throws -> Data {
    guard envelope.isStructurallyValid else {
        throw EncodingError.invalidValue(
            envelope,
            .init(codingPath: [], debugDescription: "Invalid encrypted Noctweb payload")
        )
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(envelope)
    guard data.count <= NoctwebDataV1.maximumRecordBytes else {
        throw EncodingError.invalidValue(
            envelope,
            .init(codingPath: [], debugDescription: "Encrypted Noctweb payload is too large")
        )
    }
    return data
}

public func noctwebDataEncryptedPayload(
    from data: Data
) -> NoctwebDataEncryptedPayloadV1? {
    guard !data.isEmpty, data.count <= NoctwebDataV1.maximumRecordBytes else {
        return nil
    }
    guard let envelope = try? JSONDecoder().decode(
        NoctwebDataEncryptedPayloadV1.self,
        from: data
    ), let canonical = try? noctwebDataEncodeEncryptedPayload(envelope),
       canonical == data else {
        return nil
    }
    return envelope
}

private func noctwebDataSiteLabelIsValid(_ value: String) -> Bool {
    value == value.lowercased() && !value.isEmpty && value.utf8.count <= 63 && value.first != "-" && value.last != "-"
        && value.utf8.allSatisfy { (48...57).contains($0) || (97...122).contains($0) || $0 == 45 }
}
private func noctwebDataCollectionNameIsValid(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= NoctwebDataV1.maximumCollectionNameBytes && value.first != "-" && value.last != "-"
        && value.utf8.allSatisfy { (48...57).contains($0) || (97...122).contains($0) || $0 == 45 }
}
private func noctwebDataRecordIDIsValid(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= NoctwebDataV1.maximumRecordIDBytes
        && value.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45, 46, 58, 95].contains($0) }
}
private func noctwebDataDatabaseIDIsValid(_ value: String) -> Bool { noctwebDataDigestIDIsValid(value, prefix: "nwdb1_") }
private func noctwebDataAccountIDIsValid(_ value: String) -> Bool { noctwebDataDigestIDIsValid(value, prefix: "nwa1_") }
private func noctwebDataActorIDIsValid(_ value: String, kind: NoctwebDataActorKindV1) -> Bool { kind == .publisher ? noctwebDataDigestIDIsValid(value, prefix: "nwpub1_") : noctwebDataAccountIDIsValid(value) }
private func noctwebDataDigestIDIsValid(_ value: String, prefix: String) -> Bool { value.hasPrefix(prefix) && value.utf8.count == prefix.utf8.count + 64 && value.dropFirst(prefix.count).utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
private func noctwebDataDateIsCanonical(_ date: Date) -> Bool { let value = date.timeIntervalSince1970; return value.isFinite && value >= 0 && floor(value) == value }

private struct NoctwebDataCodingKey: CodingKey { let stringValue: String; let intValue: Int?; init?(stringValue: String) { self.stringValue = stringValue; intValue = nil }; init?(intValue: Int) { stringValue = String(intValue); self.intValue = intValue } }
private func noctwebDataRequireExact<Key: CodingKey & CaseIterable>(_ decoder: Decoder, _ type: Key.Type) throws where Key.AllCases: Collection {
    let values = try decoder.container(keyedBy: NoctwebDataCodingKey.self)
    let expected = Set(type.allCases.map(\.stringValue)); guard Set(values.allKeys.map(\.stringValue)) == expected else { throw noctwebDataDecodingError(decoder, "Noctweb data fields must match exactly") }
}
private func noctwebDataRequireAllowed<Key: CodingKey & CaseIterable>(_ decoder: Decoder, _ type: Key.Type, required: Set<String>) throws where Key.AllCases: Collection {
    let values = try decoder.container(keyedBy: NoctwebDataCodingKey.self)
    let present = Set(values.allKeys.map(\.stringValue))
    let allowed = Set(type.allCases.map(\.stringValue))
    guard present.isSubset(of: allowed), required.isSubset(of: present) else {
        throw noctwebDataDecodingError(decoder, "Noctweb data fields are missing or unknown")
    }
}
private func noctwebDataDecodingError(_ decoder: Decoder, _ description: String) -> DecodingError { .dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: description)) }
private func noctwebDataEncodingError(_ encoder: Encoder, _ value: Any) -> EncodingError { .invalidValue(value, .init(codingPath: encoder.codingPath, debugDescription: "Invalid Noctweb data value")) }
