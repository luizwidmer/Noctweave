import Crypto
import Foundation

enum NoctwebDataV1 {
    static let module = "nw.noctweb-data"
    static let version = 1
    static let publisherSignatureAlgorithm = "Ed25519"
    static let accountSignatureAlgorithm = "ML-DSA-65"
    static let maximumCollections = 32
    static let maximumCollectionNameBytes = 48
    static let maximumRecordIDBytes = 96
    static let maximumRecordBytes = 64 * 1_024
    static let maximumRecordsPerDatabase = 10_000
    static let maximumAccountsPerDatabase = 1_024
    static let maximumDatabases = 256
    static let maximumDatabasesPerPublisher = 8
    static let maximumRecordsPerOwner = 256
    static let maximumBytesPerOwner = 2 * 1_024 * 1_024
    static let maximumMutationReplayEntries = 1_024
    static let maximumMutationReplayBytes = 8 * 1_024 * 1_024
    static let mutationReplayLifetimeSeconds = 5 * 60 + 31
    static let authorizationLifetimeSeconds = 2 * 60
    static let maximumAuthorizationLifetimeSeconds = 5 * 60
    static let authorizationClockSkewSeconds = 30
    // Mirrors Core's default-client-safe encoded response ceiling.
    static let maximumPage = 8
    static let maximumDatabaseBytes = 64 * 1_024 * 1_024
    static let maximumTotalDataBytes = 512 * 1_024 * 1_024
    static let idempotencyKeyBytes = 32
    static let nonceBytes = 32
    static let publisherPublicKeyBytes = 32
    static let publisherSignatureBytes = 64
    static let accountPublicKeyBytes = 1_952
    static let accountSignatureBytes = 3_309
    static let payloadKeyBytes = 32
    static let payloadKeyIDBytes = 32
    static let payloadNonceBytes = 12

    static let capabilityLimits: [String: UInt64] = [
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

    static func advertisedCapabilityLimits(databaseCreationEnabled: Bool) -> [String: UInt64] {
        var limits = capabilityLimits
        limits["databaseCreationEnabled"] = databaseCreationEnabled ? 1 : 0
        return limits
    }
}

enum NoctwebDataReadPolicyV1: String, Codable, Equatable, CaseIterable {
    case publicRead = "public"
    case owner
    case ownerOrPublisher = "owner-or-publisher"
}

enum NoctwebDataWritePolicyV1: String, Codable, Equatable, CaseIterable {
    case publisher
    case owner
    case ownerOrPublisher = "owner-or-publisher"
}

enum NoctwebDataActorKindV1: String, Codable, Equatable, CaseIterable {
    case publisher
    case account
}

struct NoctwebDataOriginV1: Codable, Equatable {
    let version: Int
    let relaySuffix: NoctwebRelaySuffixV1
    let siteLabel: String
    let publisherID: String
    let publisherSigningPublicKey: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version, relaySuffix, siteLabel, publisherID, publisherSigningPublicKey
    }

    init(
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

    var databaseID: String {
        let digest = SHA256.hash(data: NoctwebDataTranscriptV1.origin(self))
        return "nwdb1_" + digest.map { String(format: "%02x", $0) }.joined()
    }

    var isStructurallyValid: Bool {
        version == NoctwebDataV1.version
            && relaySuffix.isStructurallyValid
            && noctwebDataSiteLabelIsValid(siteLabel)
            && publisherSigningPublicKey.count == NoctwebDataV1.publisherPublicKeyBytes
            && publisherID == noctwebDataPublisherID(for: publisherSigningPublicKey)
    }

    init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        version = try values.decode(Int.self, forKey: .version)
        relaySuffix = try values.decode(NoctwebRelaySuffixV1.self, forKey: .relaySuffix)
        siteLabel = try values.decode(String.self, forKey: .siteLabel)
        publisherID = try values.decode(String.self, forKey: .publisherID)
        publisherSigningPublicKey = try values.decode(Data.self, forKey: .publisherSigningPublicKey)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb data origin") }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(relaySuffix, forKey: .relaySuffix)
        try values.encode(siteLabel, forKey: .siteLabel)
        try values.encode(publisherID, forKey: .publisherID)
        try values.encode(publisherSigningPublicKey, forKey: .publisherSigningPublicKey)
    }
}

struct NoctwebDataCollectionV1: Codable, Equatable {
    let name: String
    let readPolicy: NoctwebDataReadPolicyV1
    let writePolicy: NoctwebDataWritePolicyV1

    private enum CodingKeys: String, CodingKey, CaseIterable { case name, readPolicy, writePolicy }

    init(name: String, readPolicy: NoctwebDataReadPolicyV1, writePolicy: NoctwebDataWritePolicyV1) {
        self.name = name
        self.readPolicy = readPolicy
        self.writePolicy = writePolicy
    }

    var isStructurallyValid: Bool { noctwebDataCollectionNameIsValid(name) }

    init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        name = try values.decode(String.self, forKey: .name)
        readPolicy = try values.decode(NoctwebDataReadPolicyV1.self, forKey: .readPolicy)
        writePolicy = try values.decode(NoctwebDataWritePolicyV1.self, forKey: .writePolicy)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb data collection") }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(name, forKey: .name)
        try values.encode(readPolicy, forKey: .readPolicy)
        try values.encode(writePolicy, forKey: .writePolicy)
    }
}

struct NoctwebDataAuthorizationV1: Codable, Equatable {
    let actorKind: NoctwebDataActorKindV1
    let actorID: String
    let nonce: Data
    let expiresAt: Date
    let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case actorKind, actorID, nonce, expiresAt, signature
    }

    init(actorKind: NoctwebDataActorKindV1, actorID: String, nonce: Data, expiresAt: Date, signature: Data) {
        self.actorKind = actorKind
        self.actorID = actorID
        self.nonce = nonce
        self.expiresAt = expiresAt
        self.signature = signature
    }

    var isStructurallyValid: Bool {
        nonce.count == NoctwebDataV1.nonceBytes
            && noctwebDataActorIDIsValid(actorID, kind: actorKind)
            && noctwebDataDateIsCanonical(expiresAt)
            && signature.count == (actorKind == .publisher
                ? NoctwebDataV1.publisherSignatureBytes
                : NoctwebDataV1.accountSignatureBytes)
    }

    init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        actorKind = try values.decode(NoctwebDataActorKindV1.self, forKey: .actorKind)
        actorID = try values.decode(String.self, forKey: .actorID)
        nonce = try values.decode(Data.self, forKey: .nonce)
        expiresAt = try values.decode(Date.self, forKey: .expiresAt)
        signature = try values.decode(Data.self, forKey: .signature)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb data authorization") }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(actorKind, forKey: .actorKind)
        try values.encode(actorID, forKey: .actorID)
        try values.encode(nonce, forKey: .nonce)
        try values.encode(expiresAt, forKey: .expiresAt)
        try values.encode(signature, forKey: .signature)
    }
}

struct NoctwebDataDatabaseCreateRequestV1: Codable, Equatable {
    let databaseID: String
    let origin: NoctwebDataOriginV1
    let collections: [NoctwebDataCollectionV1]
    let idempotencyKey: Data
    let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case databaseID, origin, collections, idempotencyKey, signature
    }

    init(databaseID: String? = nil, origin: NoctwebDataOriginV1, collections: [NoctwebDataCollectionV1], idempotencyKey: Data, signature: Data) {
        self.databaseID = databaseID ?? origin.databaseID
        self.origin = origin
        self.collections = collections.sorted { $0.name < $1.name }
        self.idempotencyKey = idempotencyKey
        self.signature = signature
    }

    var isStructurallyValid: Bool {
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

    func verifyPublisherSignature() -> Bool {
        guard isStructurallyValid,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: origin.publisherSigningPublicKey) else { return false }
        return key.isValidSignature(signature, for: NoctwebDataTranscriptV1.createDatabase(self))
    }

    init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        origin = try values.decode(NoctwebDataOriginV1.self, forKey: .origin)
        collections = try values.decode([NoctwebDataCollectionV1].self, forKey: .collections)
        idempotencyKey = try values.decode(Data.self, forKey: .idempotencyKey)
        signature = try values.decode(Data.self, forKey: .signature)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb database creation request") }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID)
        try values.encode(origin, forKey: .origin)
        try values.encode(collections, forKey: .collections)
        try values.encode(idempotencyKey, forKey: .idempotencyKey)
        try values.encode(signature, forKey: .signature)
    }
}

struct NoctwebDataDatabaseReceiptV1: Codable, Equatable {
    let databaseID: String
    let created: Bool
    init(databaseID: String, created: Bool) { self.databaseID = databaseID; self.created = created }
    private enum CodingKeys: String, CodingKey, CaseIterable { case databaseID, created }
    var isStructurallyValid: Bool { noctwebDataDatabaseIDIsValid(databaseID) }
    init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        created = try values.decode(Bool.self, forKey: .created)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb database receipt") }
    }
    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID); try values.encode(created, forKey: .created)
    }
}

struct NoctwebDataAccountRegisterRequestV1: Codable, Equatable {
    let databaseID: String
    let accountID: String
    let accountSigningPublicKey: Data
    let idempotencyKey: Data
    let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable { case databaseID, accountID, accountSigningPublicKey, idempotencyKey, signature }

    init(databaseID: String, accountID: String, accountSigningPublicKey: Data, idempotencyKey: Data, signature: Data) {
        self.databaseID = databaseID
        self.accountID = accountID
        self.accountSigningPublicKey = accountSigningPublicKey
        self.idempotencyKey = idempotencyKey
        self.signature = signature
    }

    static func accountID(databaseID: String, publicKey: Data) -> String {
        let digest = SHA256.hash(data: NoctwebDataTranscriptV1.accountIdentity(databaseID: databaseID, publicKey: publicKey))
        return "nwa1_" + digest.map { String(format: "%02x", $0) }.joined()
    }

    var isStructurallyValid: Bool {
        noctwebDataDatabaseIDIsValid(databaseID)
            && accountSigningPublicKey.count == NoctwebDataV1.accountPublicKeyBytes
            && accountID == Self.accountID(databaseID: databaseID, publicKey: accountSigningPublicKey)
            && idempotencyKey.count == NoctwebDataV1.idempotencyKeyBytes
            && signature.count == NoctwebDataV1.accountSignatureBytes
    }

    func verifyAccountSignatureThrowing() throws -> Bool {
        guard isStructurallyValid else { return false }
        return try OQSSignatureVerifier.shared.verifyThrowing(
            signature: signature,
            data: NoctwebDataTranscriptV1.registerAccount(self),
            publicKey: accountSigningPublicKey
        )
    }

    init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        accountID = try values.decode(String.self, forKey: .accountID)
        accountSigningPublicKey = try values.decode(Data.self, forKey: .accountSigningPublicKey)
        idempotencyKey = try values.decode(Data.self, forKey: .idempotencyKey)
        signature = try values.decode(Data.self, forKey: .signature)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb account registration request") }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID)
        try values.encode(accountID, forKey: .accountID)
        try values.encode(accountSigningPublicKey, forKey: .accountSigningPublicKey)
        try values.encode(idempotencyKey, forKey: .idempotencyKey)
        try values.encode(signature, forKey: .signature)
    }
}

struct NoctwebDataAccountReceiptV1: Codable, Equatable {
    let databaseID: String
    let accountID: String
    let created: Bool
    init(databaseID: String, accountID: String, created: Bool) { self.databaseID = databaseID; self.accountID = accountID; self.created = created }
    private enum CodingKeys: String, CodingKey, CaseIterable { case databaseID, accountID, created }
    var isStructurallyValid: Bool { noctwebDataDatabaseIDIsValid(databaseID) && noctwebDataAccountIDIsValid(accountID) }
    init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        accountID = try values.decode(String.self, forKey: .accountID)
        created = try values.decode(Bool.self, forKey: .created)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb account receipt") }
    }
    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID); try values.encode(accountID, forKey: .accountID); try values.encode(created, forKey: .created)
    }
}

struct NoctwebDataRecordPutRequestV1: Codable, Equatable {
    let databaseID: String
    let collection: String
    let recordID: String
    let ownerAccountID: String?
    let payload: Data
    let expectedRevision: UInt64
    let idempotencyKey: Data
    let authorization: NoctwebDataAuthorizationV1

    private enum CodingKeys: String, CodingKey, CaseIterable { case databaseID, collection, recordID, ownerAccountID, payload, expectedRevision, idempotencyKey, authorization }

    init(databaseID: String, collection: String, recordID: String, ownerAccountID: String?, payload: Data, expectedRevision: UInt64, idempotencyKey: Data, authorization: NoctwebDataAuthorizationV1) {
        self.databaseID = databaseID; self.collection = collection; self.recordID = recordID
        self.ownerAccountID = ownerAccountID; self.payload = payload; self.expectedRevision = expectedRevision
        self.idempotencyKey = idempotencyKey; self.authorization = authorization
    }

    var isStructurallyValid: Bool {
        noctwebDataDatabaseIDIsValid(databaseID) && noctwebDataCollectionNameIsValid(collection)
            && noctwebDataRecordIDIsValid(recordID) && ownerAccountID.map(noctwebDataAccountIDIsValid) != false
            && !payload.isEmpty && payload.count <= NoctwebDataV1.maximumRecordBytes
            && noctwebDataEncryptedPayload(from: payload) != nil
            && expectedRevision < UInt64.max && idempotencyKey.count == NoctwebDataV1.idempotencyKeyBytes
            && authorization.isStructurallyValid
            && (authorization.actorKind != .account || ownerAccountID == authorization.actorID)
    }

    init(from decoder: Decoder) throws {
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

    func encode(to encoder: Encoder) throws {
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

struct NoctwebDataRecordGetRequestV1: Codable, Equatable {
    let databaseID: String
    let collection: String
    let recordID: String
    let ownerAccountID: String?
    let authorization: NoctwebDataAuthorizationV1?
    private enum CodingKeys: String, CodingKey, CaseIterable { case databaseID, collection, recordID, ownerAccountID, authorization }
    init(databaseID: String, collection: String, recordID: String, ownerAccountID: String? = nil, authorization: NoctwebDataAuthorizationV1? = nil) { self.databaseID = databaseID; self.collection = collection; self.recordID = recordID; self.ownerAccountID = ownerAccountID; self.authorization = authorization }
    var isStructurallyValid: Bool {
        noctwebDataDatabaseIDIsValid(databaseID)
            && noctwebDataCollectionNameIsValid(collection)
            && noctwebDataRecordIDIsValid(recordID)
            && ownerAccountID.map(noctwebDataAccountIDIsValid) != false
            && authorization?.isStructurallyValid != false
            && (authorization?.actorKind != .account || ownerAccountID == authorization?.actorID)
    }

    init(from decoder: Decoder) throws {
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

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID)
        try values.encode(collection, forKey: .collection)
        try values.encode(recordID, forKey: .recordID)
        try values.encodeIfPresent(ownerAccountID, forKey: .ownerAccountID)
        try values.encodeIfPresent(authorization, forKey: .authorization)
    }
}

struct NoctwebDataRecordListRequestV1: Codable, Equatable {
    let databaseID: String
    let collection: String
    let afterRecordID: String?
    let ownerAccountID: String?
    let limit: Int
    let authorization: NoctwebDataAuthorizationV1?
    private enum CodingKeys: String, CodingKey, CaseIterable { case databaseID, collection, afterRecordID, ownerAccountID, limit, authorization }
    init(databaseID: String, collection: String, afterRecordID: String? = nil, ownerAccountID: String? = nil, limit: Int = NoctwebDataV1.maximumPage, authorization: NoctwebDataAuthorizationV1? = nil) { self.databaseID = databaseID; self.collection = collection; self.afterRecordID = afterRecordID; self.ownerAccountID = ownerAccountID; self.limit = limit; self.authorization = authorization }
    var isStructurallyValid: Bool {
        noctwebDataDatabaseIDIsValid(databaseID)
            && noctwebDataCollectionNameIsValid(collection)
            && afterRecordID.map(noctwebDataRecordIDIsValid) != false
            && ownerAccountID.map(noctwebDataAccountIDIsValid) != false
            && (1...NoctwebDataV1.maximumPage).contains(limit)
            && authorization?.isStructurallyValid != false
            && (authorization?.actorKind != .account || ownerAccountID == authorization?.actorID)
    }

    init(from decoder: Decoder) throws {
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

    func encode(to encoder: Encoder) throws {
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

struct NoctwebDataRecordDeleteRequestV1: Codable, Equatable {
    let databaseID: String
    let collection: String
    let recordID: String
    let ownerAccountID: String?
    let expectedRevision: UInt64
    let idempotencyKey: Data
    let authorization: NoctwebDataAuthorizationV1
    private enum CodingKeys: String, CodingKey, CaseIterable { case databaseID, collection, recordID, ownerAccountID, expectedRevision, idempotencyKey, authorization }
    init(databaseID: String, collection: String, recordID: String, ownerAccountID: String? = nil, expectedRevision: UInt64, idempotencyKey: Data, authorization: NoctwebDataAuthorizationV1) { self.databaseID = databaseID; self.collection = collection; self.recordID = recordID; self.ownerAccountID = ownerAccountID; self.expectedRevision = expectedRevision; self.idempotencyKey = idempotencyKey; self.authorization = authorization }
    var isStructurallyValid: Bool {
        noctwebDataDatabaseIDIsValid(databaseID)
            && noctwebDataCollectionNameIsValid(collection)
            && noctwebDataRecordIDIsValid(recordID)
            && ownerAccountID.map(noctwebDataAccountIDIsValid) != false
            && expectedRevision > 0
            && idempotencyKey.count == NoctwebDataV1.idempotencyKeyBytes
            && authorization.isStructurallyValid
            && (authorization.actorKind != .account || ownerAccountID == authorization.actorID)
    }

    init(from decoder: Decoder) throws {
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

    func encode(to encoder: Encoder) throws {
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

struct NoctwebDataEncryptedPayloadV1: Codable, Equatable {
    let version: Int
    let algorithm: String
    let keyID: Data
    let nonce: Data
    let ciphertext: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version, algorithm, keyID, nonce, ciphertext
    }

    init(keyID: Data, nonce: Data, ciphertext: Data) {
        version = NoctwebDataV1.version
        algorithm = "AES-256-GCM"
        self.keyID = keyID
        self.nonce = nonce
        self.ciphertext = ciphertext
    }

    var isStructurallyValid: Bool {
        version == NoctwebDataV1.version
            && algorithm == "AES-256-GCM"
            && keyID.count == NoctwebDataV1.payloadKeyIDBytes
            && nonce.count == NoctwebDataV1.payloadNonceBytes
            && ciphertext.count > 16
            && ciphertext.count <= NoctwebDataV1.maximumRecordBytes
    }

    init(from decoder: Decoder) throws {
        try noctwebDataRequireExact(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        version = try values.decode(Int.self, forKey: .version)
        algorithm = try values.decode(String.self, forKey: .algorithm)
        keyID = try values.decode(Data.self, forKey: .keyID)
        nonce = try values.decode(Data.self, forKey: .nonce)
        ciphertext = try values.decode(Data.self, forKey: .ciphertext)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid encrypted Noctweb payload") }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(algorithm, forKey: .algorithm)
        try values.encode(keyID, forKey: .keyID)
        try values.encode(nonce, forKey: .nonce)
        try values.encode(ciphertext, forKey: .ciphertext)
    }
}

struct NoctwebDataRecordProvenanceV1: Codable, Equatable {
    let actorKind: NoctwebDataActorKindV1
    let actorID: String
    let actorSigningPublicKey: Data
    let authorizationNonce: Data
    let authorizationExpiresAt: Date
    let idempotencyKey: Data
    let expectedRevision: UInt64
    let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case actorKind, actorID, actorSigningPublicKey, authorizationNonce
        case authorizationExpiresAt, idempotencyKey, expectedRevision, signature
    }

    init(actorKind: NoctwebDataActorKindV1, actorID: String, actorSigningPublicKey: Data, authorizationNonce: Data, authorizationExpiresAt: Date, idempotencyKey: Data, expectedRevision: UInt64, signature: Data) {
        self.actorKind = actorKind; self.actorID = actorID
        self.actorSigningPublicKey = actorSigningPublicKey
        self.authorizationNonce = authorizationNonce
        self.authorizationExpiresAt = authorizationExpiresAt
        self.idempotencyKey = idempotencyKey; self.expectedRevision = expectedRevision
        self.signature = signature
    }

    var isStructurallyValid: Bool {
        noctwebDataActorIDIsValid(actorID, kind: actorKind)
            && actorSigningPublicKey.count == (actorKind == .publisher ? NoctwebDataV1.publisherPublicKeyBytes : NoctwebDataV1.accountPublicKeyBytes)
            && authorizationNonce.count == NoctwebDataV1.nonceBytes
            && noctwebDataDateIsCanonical(authorizationExpiresAt)
            && idempotencyKey.count == NoctwebDataV1.idempotencyKeyBytes
            && expectedRevision < UInt64.max
            && signature.count == (actorKind == .publisher ? NoctwebDataV1.publisherSignatureBytes : NoctwebDataV1.accountSignatureBytes)
    }

    init(from decoder: Decoder) throws {
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
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb record provenance") }
    }

    func encode(to encoder: Encoder) throws {
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

struct NoctwebDataRecordV1: Codable, Equatable {
    let databaseID: String
    let collection: String
    let recordID: String
    let ownerAccountID: String?
    let payload: Data
    let revision: UInt64
    let createdAt: Date
    let updatedAt: Date
    let provenance: NoctwebDataRecordProvenanceV1

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case databaseID, collection, recordID, ownerAccountID, payload
        case revision, createdAt, updatedAt, provenance
    }

    init(databaseID: String, collection: String, recordID: String, ownerAccountID: String?, payload: Data, revision: UInt64, createdAt: Date, updatedAt: Date, provenance: NoctwebDataRecordProvenanceV1) {
        self.databaseID = databaseID; self.collection = collection; self.recordID = recordID
        self.ownerAccountID = ownerAccountID; self.payload = payload; self.revision = revision
        self.createdAt = createdAt; self.updatedAt = updatedAt; self.provenance = provenance
    }

    var isStructurallyValid: Bool {
        noctwebDataDatabaseIDIsValid(databaseID) && noctwebDataCollectionNameIsValid(collection)
            && noctwebDataRecordIDIsValid(recordID) && ownerAccountID.map(noctwebDataAccountIDIsValid) != false
            && !payload.isEmpty && payload.count <= NoctwebDataV1.maximumRecordBytes && revision > 0
            && noctwebDataDateIsCanonical(createdAt) && noctwebDataDateIsCanonical(updatedAt) && updatedAt >= createdAt
            && noctwebDataEncryptedPayload(from: payload) != nil
            && provenance.isStructurallyValid
            && provenance.expectedRevision + 1 == revision
            && (provenance.actorKind != .account || ownerAccountID == provenance.actorID)
    }

    init(from decoder: Decoder) throws {
        try noctwebDataRequireAllowed(decoder, CodingKeys.self, required: ["databaseID", "collection", "recordID", "payload", "revision", "createdAt", "updatedAt", "provenance"])
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
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb data record") }
    }

    func encode(to encoder: Encoder) throws {
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
}

struct NoctwebDataRecordListV1: Codable, Equatable {
    let records: [NoctwebDataRecordV1]
    let nextCursor: String?
    init(records: [NoctwebDataRecordV1], nextCursor: String?) { self.records = records; self.nextCursor = nextCursor }
    private enum CodingKeys: String, CodingKey, CaseIterable { case records, nextCursor }
    var isStructurallyValid: Bool {
        records.count <= NoctwebDataV1.maximumPage
            && records.allSatisfy(\.isStructurallyValid)
            && zip(records, records.dropFirst()).allSatisfy { $0.0.recordID < $0.1.recordID }
            && nextCursor.map(noctwebDataRecordIDIsValid) != false
            && (nextCursor == nil || nextCursor == records.last?.recordID)
    }
    init(from decoder: Decoder) throws {
        try noctwebDataRequireAllowed(decoder, CodingKeys.self, required: ["records"])
        let values = try decoder.container(keyedBy: CodingKeys.self)
        records = try values.decode([NoctwebDataRecordV1].self, forKey: .records)
        nextCursor = try values.decodeIfPresent(String.self, forKey: .nextCursor)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb record list") }
    }
    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(records, forKey: .records); try values.encodeIfPresent(nextCursor, forKey: .nextCursor)
    }
}

struct NoctwebDataDeleteReceiptV1: Codable, Equatable {
    let databaseID: String
    let collection: String
    let recordID: String
    let ownerAccountID: String?
    let deletedRevision: UInt64
    init(databaseID: String, collection: String, recordID: String, ownerAccountID: String? = nil, deletedRevision: UInt64) { self.databaseID = databaseID; self.collection = collection; self.recordID = recordID; self.ownerAccountID = ownerAccountID; self.deletedRevision = deletedRevision }
    private enum CodingKeys: String, CodingKey, CaseIterable { case databaseID, collection, recordID, ownerAccountID, deletedRevision }
    var isStructurallyValid: Bool { noctwebDataDatabaseIDIsValid(databaseID) && noctwebDataCollectionNameIsValid(collection) && noctwebDataRecordIDIsValid(recordID) && ownerAccountID.map(noctwebDataAccountIDIsValid) != false && deletedRevision > 0 }
    init(from decoder: Decoder) throws {
        try noctwebDataRequireAllowed(decoder, CodingKeys.self, required: ["databaseID", "collection", "recordID", "deletedRevision"])
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseID = try values.decode(String.self, forKey: .databaseID)
        collection = try values.decode(String.self, forKey: .collection)
        recordID = try values.decode(String.self, forKey: .recordID)
        ownerAccountID = try values.decodeIfPresent(String.self, forKey: .ownerAccountID)
        deletedRevision = try values.decode(UInt64.self, forKey: .deletedRevision)
        guard isStructurallyValid else { throw noctwebDataDecodingError(decoder, "Invalid Noctweb deletion receipt") }
    }
    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw noctwebDataEncodingError(encoder, self) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(databaseID, forKey: .databaseID); try values.encode(collection, forKey: .collection)
        try values.encode(recordID, forKey: .recordID); try values.encodeIfPresent(ownerAccountID, forKey: .ownerAccountID)
        try values.encode(deletedRevision, forKey: .deletedRevision)
    }
}

enum NoctwebDataTranscriptV1 {
    static func encryptedPayloadAAD(databaseID: String, collection: String, recordID: String, ownerAccountID: String?, revision: UInt64, keyID: Data) -> Data {
        var data = domain("org.noctweave.noctweb/encrypted-payload/v1")
        append(databaseID, to: &data); append(collection, to: &data)
        append(recordID, to: &data); append(ownerAccountID, to: &data)
        append(revision, to: &data); append(keyID, to: &data); return data
    }

    static func origin(_ origin: NoctwebDataOriginV1) -> Data {
        var data = domain("org.noctweave.noctweb/data-origin/v1")
        append(origin.relaySuffix.rawValue, to: &data); append(origin.siteLabel, to: &data)
        append(origin.publisherID, to: &data); append(origin.publisherSigningPublicKey, to: &data)
        return data
    }

    static func createDatabase(_ request: NoctwebDataDatabaseCreateRequestV1) -> Data {
        var data = domain("org.noctweave.noctweb/data-create/v1")
        append(request.databaseID, to: &data); append(origin(request.origin), to: &data); append(UInt64(request.collections.count), to: &data)
        for item in request.collections { append(item.name, to: &data); append(item.readPolicy.rawValue, to: &data); append(item.writePolicy.rawValue, to: &data) }
        append(request.idempotencyKey, to: &data); return data
    }

    static func accountIdentity(databaseID: String, publicKey: Data) -> Data {
        var data = domain("org.noctweave.noctweb/account-id/v1")
        append(databaseID, to: &data); append(publicKey, to: &data); return data
    }

    static func registerAccount(_ request: NoctwebDataAccountRegisterRequestV1) -> Data {
        var data = domain("org.noctweave.noctweb/account-register/v1")
        append(request.databaseID, to: &data); append(request.accountID, to: &data)
        append(request.accountSigningPublicKey, to: &data); append(request.idempotencyKey, to: &data); return data
    }

    static func putRecord(_ request: NoctwebDataRecordPutRequestV1) -> Data {
        var data = authorizedDomain("org.noctweave.noctweb/data-put/v1", request.authorization)
        append(request.databaseID, to: &data); append(request.collection, to: &data); append(request.recordID, to: &data)
        append(request.ownerAccountID, to: &data); append(request.payload, to: &data)
        append(request.expectedRevision, to: &data); append(request.idempotencyKey, to: &data); return data
    }

    static func getRecord(_ request: NoctwebDataRecordGetRequestV1) -> Data {
        var data = optionalAuthorizedDomain("org.noctweave.noctweb/data-get/v1", request.authorization)
        append(request.databaseID, to: &data); append(request.collection, to: &data); append(request.recordID, to: &data); append(request.ownerAccountID, to: &data); return data
    }

    static func listRecords(_ request: NoctwebDataRecordListRequestV1) -> Data {
        var data = optionalAuthorizedDomain("org.noctweave.noctweb/data-list/v1", request.authorization)
        append(request.databaseID, to: &data); append(request.collection, to: &data); append(request.afterRecordID, to: &data); append(request.ownerAccountID, to: &data)
        append(UInt64(request.limit), to: &data); return data
    }

    static func deleteRecord(_ request: NoctwebDataRecordDeleteRequestV1) -> Data {
        var data = authorizedDomain("org.noctweave.noctweb/data-delete/v1", request.authorization)
        append(request.databaseID, to: &data); append(request.collection, to: &data); append(request.recordID, to: &data)
        append(request.ownerAccountID, to: &data); append(request.expectedRevision, to: &data); append(request.idempotencyKey, to: &data); return data
    }

    private static func authorizedDomain(_ value: String, _ authorization: NoctwebDataAuthorizationV1) -> Data {
        var data = domain(value); append(authorization.actorKind.rawValue, to: &data)
        append(authorization.actorID, to: &data); append(authorization.nonce, to: &data); append(authorization.expiresAt, to: &data); return data
    }

    private static func optionalAuthorizedDomain(_ value: String, _ authorization: NoctwebDataAuthorizationV1?) -> Data {
        var data = domain(value); data.append(authorization == nil ? 0 : 1)
        if let authorization { append(authorization.actorKind.rawValue, to: &data); append(authorization.actorID, to: &data); append(authorization.nonce, to: &data); append(authorization.expiresAt, to: &data) }
        return data
    }

    private static func domain(_ value: String) -> Data { var data = Data(value.utf8); data.append(0); return data }
    private static func append(_ value: String, to data: inout Data) { append(Data(value.utf8), to: &data) }
    private static func append(_ value: String?, to data: inout Data) { data.append(value == nil ? 0 : 1); if let value { append(value, to: &data) } }
    private static func append(_ value: Data, to data: inout Data) { append(UInt64(value.count), to: &data); data.append(value) }
    private static func append(_ value: Date, to data: inout Data) { append(UInt64(value.timeIntervalSince1970), to: &data) }
    private static func append(_ value: UInt64, to data: inout Data) { var bigEndian = value.bigEndian; Swift.withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) } }
}

func noctwebDataPublisherID(for publicKey: Data) -> String {
    var data = Data("org.noctweave.noctweb/publisher-id/v1".utf8); data.append(0); data.append(publicKey)
    return "nwpub1_" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

func noctwebDataEncryptedPayload(from data: Data) -> NoctwebDataEncryptedPayloadV1? {
    guard !data.isEmpty, data.count <= NoctwebDataV1.maximumRecordBytes else { return nil }
    guard let envelope = try? JSONDecoder().decode(
        NoctwebDataEncryptedPayloadV1.self,
        from: data
    ) else { return nil }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    guard let canonical = try? encoder.encode(envelope), canonical == data else {
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
