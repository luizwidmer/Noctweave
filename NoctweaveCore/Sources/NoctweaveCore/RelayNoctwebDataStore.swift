import CryptoKit
import Foundation
import SQLite3

public enum RelayNoctwebDataStoreError: Error, Equatable {
    case invalidRequest
    case databaseUnavailable
    case collectionUnavailable
    case accountUnavailable
    case authenticationRequired
    case unauthorized
    case conflict
    case capacityExceeded
    case corruptPersistence
}

public final class RelayNoctwebDataStore: @unchecked Sendable {
    private struct MutationReplay: Codable, Equatable {
        enum Kind: String, Codable { case put, delete }
        let kind: Kind
        let fingerprint: Data
        let record: NoctwebDataRecordV1?
        let deleteReceipt: NoctwebDataDeleteReceiptV1?

        var isStructurallyValid: Bool {
            fingerprint.count == 32
                && ((kind == .put && record?.isStructurallyValid == true && deleteReceipt == nil)
                    || (kind == .delete && record == nil && deleteReceipt != nil))
        }
    }

    private struct DatabaseState: Codable {
        let origin: NoctwebDataOriginV1
        let collections: [String: NoctwebDataCollectionV1]
        var accounts: [String: Data]
        var records: [String: NoctwebDataRecordV1]
        var mutationReplays: [String: MutationReplay]

        var isStructurallyValid: Bool {
            origin.isStructurallyValid
                && !collections.isEmpty
                && collections.count <= NoctwebDataV1.maximumCollections
                && collections.allSatisfy { $0.key == $0.value.name && $0.value.isStructurallyValid }
                && accounts.count <= NoctwebDataV1.maximumAccountsPerDatabase
                && accounts.allSatisfy {
                    $0.value.count == NoctwebDataV1.accountPublicKeyBytes
                        && $0.key == NoctwebDataAccountRegisterRequestV1.accountID(
                            databaseID: origin.databaseID,
                            publicKey: $0.value
                        )
                }
                && records.count <= NoctwebDataV1.maximumRecordsPerDatabase
                && records.allSatisfy { $0.key == Self.recordKey($0.value.collection, $0.value.recordID) && $0.value.databaseID == origin.databaseID && $0.value.isStructurallyValid }
                && records.values.reduce(0, { $0 + $1.payload.count }) <= NoctwebDataV1.maximumDatabaseBytes
                && mutationReplays.count <= RelayNoctwebDataStore.maximumMutationReplays
                && mutationReplays.values.allSatisfy(\.isStructurallyValid)
        }

        static func recordKey(_ collection: String, _ recordID: String) -> String { collection + "\u{0}" + recordID }
    }

    private struct Snapshot: Codable {
        static let version = 1
        let version: Int
        var databases: [String: DatabaseState]
    }

    private static let maximumDatabases = 256
    private static let maximumMutationReplays = 50_000
    private static let maximumSnapshotBytes = 128 * 1_024 * 1_024
    private static let tableName = "noctweb_data_service_v1"
    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    private let queue = DispatchQueue(label: "noctweave.noctweb.data-store")
    private let fileURL: URL?
    private var databases: [String: DatabaseState] = [:]

    public init(fileURL: URL? = nil) { self.fileURL = fileURL }

    public func load() throws {
        try queue.sync {
            guard let fileURL else { return }
            var database: OpaquePointer?
            try openDatabase(at: fileURL, into: &database)
            defer { sqlite3_close(database) }
            guard let database else { throw RelayNoctwebDataStoreError.corruptPersistence }
            try ensureTable(in: database)
            let sql = "SELECT snapshot FROM \(Self.tableName) WHERE singleton = 1;"
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK,
                  let statement else { throw RelayNoctwebDataStoreError.corruptPersistence }
            defer { sqlite3_finalize(statement) }
            switch sqlite3_step(statement) {
            case SQLITE_DONE:
                return
            case SQLITE_ROW:
                break
            default:
                throw RelayNoctwebDataStoreError.corruptPersistence
            }
            let count = Int(sqlite3_column_bytes(statement, 0))
            guard count > 0,
                  count <= Self.maximumSnapshotBytes,
                  let bytes = sqlite3_column_blob(statement, 0) else {
                throw RelayNoctwebDataStoreError.corruptPersistence
            }
            let data = Data(bytes: bytes, count: count)
            let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
            let snapshot = try decoder.decode(Snapshot.self, from: data)
            guard snapshot.version == Snapshot.version,
                  snapshot.databases.count <= Self.maximumDatabases,
                  snapshot.databases.allSatisfy({ $0.key == $0.value.origin.databaseID && $0.value.isStructurallyValid }) else {
                throw RelayNoctwebDataStoreError.corruptPersistence
            }
            databases = snapshot.databases
        }
    }

    public func createDatabase(_ request: NoctwebDataDatabaseCreateRequestV1) throws -> NoctwebDataDatabaseReceiptV1 {
        try queue.sync {
            guard request.isStructurallyValid, request.verifyPublisherSignature() else { throw RelayNoctwebDataStoreError.authenticationRequired }
            let databaseID = request.origin.databaseID
            if let existing = databases[databaseID] {
                guard existing.origin == request.origin,
                      Array(existing.collections.values).sorted(by: { $0.name < $1.name }) == request.collections else { throw RelayNoctwebDataStoreError.conflict }
                return NoctwebDataDatabaseReceiptV1(databaseID: databaseID, created: false)
            }
            guard databases.count < Self.maximumDatabases else { throw RelayNoctwebDataStoreError.capacityExceeded }
            let previous = databases
            databases[databaseID] = DatabaseState(
                origin: request.origin,
                collections: Dictionary(uniqueKeysWithValues: request.collections.map { ($0.name, $0) }),
                accounts: [:], records: [:], mutationReplays: [:]
            )
            do { try saveLocked() } catch { databases = previous; throw error }
            return NoctwebDataDatabaseReceiptV1(databaseID: databaseID, created: true)
        }
    }

    public func registerAccount(_ request: NoctwebDataAccountRegisterRequestV1) throws -> NoctwebDataAccountReceiptV1 {
        try queue.sync {
            guard request.isStructurallyValid else { throw RelayNoctwebDataStoreError.invalidRequest }
            guard var database = databases[request.databaseID] else { throw RelayNoctwebDataStoreError.databaseUnavailable }
            guard try request.verifyAccountSignatureThrowing() else { throw RelayNoctwebDataStoreError.authenticationRequired }
            if let existing = database.accounts[request.accountID] {
                guard existing == request.accountSigningPublicKey else { throw RelayNoctwebDataStoreError.conflict }
                return NoctwebDataAccountReceiptV1(databaseID: request.databaseID, accountID: request.accountID, created: false)
            }
            guard database.accounts.count < NoctwebDataV1.maximumAccountsPerDatabase else { throw RelayNoctwebDataStoreError.capacityExceeded }
            database.accounts[request.accountID] = request.accountSigningPublicKey
            let previous = databases[request.databaseID]
            databases[request.databaseID] = database
            do { try saveLocked() } catch { databases[request.databaseID] = previous; throw error }
            return NoctwebDataAccountReceiptV1(databaseID: request.databaseID, accountID: request.accountID, created: true)
        }
    }

    public func putRecord(_ request: NoctwebDataRecordPutRequestV1, now: Date = Date()) throws -> NoctwebDataRecordV1 {
        try queue.sync {
            guard request.isStructurallyValid else { throw RelayNoctwebDataStoreError.invalidRequest }
            guard var database = databases[request.databaseID] else { throw RelayNoctwebDataStoreError.databaseUnavailable }
            guard let policy = database.collections[request.collection] else { throw RelayNoctwebDataStoreError.collectionUnavailable }
            let replayKey = hex(request.idempotencyKey)
            let fingerprint = mutationFingerprint(NoctwebDataTranscriptV1.putRecord(request), request.authorization.signature)
            if let replay = database.mutationReplays[replayKey] {
                guard replay.kind == .put, replay.fingerprint == fingerprint, let record = replay.record else { throw RelayNoctwebDataStoreError.conflict }
                return record
            }
            try verify(request.authorization, transcript: NoctwebDataTranscriptV1.putRecord(request), in: database)
            let key = DatabaseState.recordKey(request.collection, request.recordID)
            let existing = database.records[key]
            guard (existing == nil && request.expectedRevision == 0)
                    || existing?.revision == request.expectedRevision else { throw RelayNoctwebDataStoreError.conflict }
            try authorizeWrite(policy.writePolicy, authorization: request.authorization, requestedOwner: request.ownerAccountID, existingOwner: existing?.ownerAccountID, database: database)
            if existing == nil {
                guard database.records.count < NoctwebDataV1.maximumRecordsPerDatabase else { throw RelayNoctwebDataStoreError.capacityExceeded }
            }
            let currentBytes = database.records.values.reduce(0) { $0 + $1.payload.count }
            let replacedBytes = existing?.payload.count ?? 0
            guard currentBytes - replacedBytes + request.payload.count <= NoctwebDataV1.maximumDatabaseBytes else { throw RelayNoctwebDataStoreError.capacityExceeded }
            guard database.mutationReplays.count < Self.maximumMutationReplays else { throw RelayNoctwebDataStoreError.capacityExceeded }
            let timestamp = canonicalDate(now)
            let record = NoctwebDataRecordV1(
                databaseID: request.databaseID, collection: request.collection, recordID: request.recordID,
                ownerAccountID: request.ownerAccountID, payload: request.payload,
                revision: (existing?.revision ?? 0) + 1, createdAt: existing?.createdAt ?? timestamp, updatedAt: timestamp
            )
            guard record.isStructurallyValid else { throw RelayNoctwebDataStoreError.invalidRequest }
            database.records[key] = record
            database.mutationReplays[replayKey] = MutationReplay(kind: .put, fingerprint: fingerprint, record: record, deleteReceipt: nil)
            let previous = databases[request.databaseID]; databases[request.databaseID] = database
            do { try saveLocked() } catch { databases[request.databaseID] = previous; throw error }
            return record
        }
    }

    public func getRecord(_ request: NoctwebDataRecordGetRequestV1) throws -> NoctwebDataRecordV1 {
        try queue.sync {
            guard request.isStructurallyValid else { throw RelayNoctwebDataStoreError.invalidRequest }
            guard let database = databases[request.databaseID] else { throw RelayNoctwebDataStoreError.databaseUnavailable }
            guard let policy = database.collections[request.collection] else { throw RelayNoctwebDataStoreError.collectionUnavailable }
            guard let record = database.records[DatabaseState.recordKey(request.collection, request.recordID)] else { throw RelayNoctwebDataStoreError.databaseUnavailable }
            if let authorization = request.authorization { try verify(authorization, transcript: NoctwebDataTranscriptV1.getRecord(request), in: database) }
            try authorizeRead(policy.readPolicy, authorization: request.authorization, owner: record.ownerAccountID, database: database)
            return record
        }
    }

    public func listRecords(_ request: NoctwebDataRecordListRequestV1) throws -> NoctwebDataRecordListV1 {
        try queue.sync {
            guard request.isStructurallyValid else { throw RelayNoctwebDataStoreError.invalidRequest }
            guard let database = databases[request.databaseID] else { throw RelayNoctwebDataStoreError.databaseUnavailable }
            guard let policy = database.collections[request.collection] else { throw RelayNoctwebDataStoreError.collectionUnavailable }
            if let authorization = request.authorization { try verify(authorization, transcript: NoctwebDataTranscriptV1.listRecords(request), in: database) }
            let candidates = database.records.values
                .filter { $0.collection == request.collection && (request.afterRecordID == nil || $0.recordID > request.afterRecordID!) }
                .sorted { $0.recordID < $1.recordID }
                .filter { (try? authorizeRead(policy.readPolicy, authorization: request.authorization, owner: $0.ownerAccountID, database: database)) != nil }
            let selected = Array(candidates.prefix(request.limit))
            let next = candidates.count > selected.count ? selected.last?.recordID : nil
            return NoctwebDataRecordListV1(records: selected, nextCursor: next)
        }
    }

    public func deleteRecord(_ request: NoctwebDataRecordDeleteRequestV1) throws -> NoctwebDataDeleteReceiptV1 {
        try queue.sync {
            guard request.isStructurallyValid else { throw RelayNoctwebDataStoreError.invalidRequest }
            guard var database = databases[request.databaseID] else { throw RelayNoctwebDataStoreError.databaseUnavailable }
            guard let policy = database.collections[request.collection] else { throw RelayNoctwebDataStoreError.collectionUnavailable }
            let replayKey = hex(request.idempotencyKey)
            let fingerprint = mutationFingerprint(NoctwebDataTranscriptV1.deleteRecord(request), request.authorization.signature)
            if let replay = database.mutationReplays[replayKey] {
                guard replay.kind == .delete, replay.fingerprint == fingerprint, let receipt = replay.deleteReceipt else { throw RelayNoctwebDataStoreError.conflict }
                return receipt
            }
            try verify(request.authorization, transcript: NoctwebDataTranscriptV1.deleteRecord(request), in: database)
            let key = DatabaseState.recordKey(request.collection, request.recordID)
            guard let record = database.records[key], record.revision == request.expectedRevision else { throw RelayNoctwebDataStoreError.conflict }
            try authorizeWrite(policy.writePolicy, authorization: request.authorization, requestedOwner: record.ownerAccountID, existingOwner: record.ownerAccountID, database: database)
            guard database.mutationReplays.count < Self.maximumMutationReplays else { throw RelayNoctwebDataStoreError.capacityExceeded }
            let receipt = NoctwebDataDeleteReceiptV1(databaseID: request.databaseID, collection: request.collection, recordID: request.recordID, deletedRevision: record.revision)
            database.records.removeValue(forKey: key)
            database.mutationReplays[replayKey] = MutationReplay(kind: .delete, fingerprint: fingerprint, record: nil, deleteReceipt: receipt)
            let previous = databases[request.databaseID]; databases[request.databaseID] = database
            do { try saveLocked() } catch { databases[request.databaseID] = previous; throw error }
            return receipt
        }
    }

    private func verify(_ authorization: NoctwebDataAuthorizationV1, transcript: Data, in database: DatabaseState) throws {
        switch authorization.actorKind {
        case .publisher:
            guard authorization.actorID == database.origin.publisherID,
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: database.origin.publisherSigningPublicKey),
                  key.isValidSignature(authorization.signature, for: transcript) else { throw RelayNoctwebDataStoreError.authenticationRequired }
        case .account:
            guard let key = database.accounts[authorization.actorID] else { throw RelayNoctwebDataStoreError.accountUnavailable }
            guard try SigningKeyPair.verifyThrowing(signature: authorization.signature, data: transcript, publicKeyData: key) else { throw RelayNoctwebDataStoreError.authenticationRequired }
        }
    }

    private func authorizeRead(_ policy: NoctwebDataReadPolicyV1, authorization: NoctwebDataAuthorizationV1?, owner: String?, database: DatabaseState) throws {
        switch policy {
        case .publicRead: return
        case .owner:
            guard authorization?.actorKind == .account, authorization?.actorID == owner else { throw RelayNoctwebDataStoreError.unauthorized }
        case .ownerOrPublisher:
            guard authorization?.actorKind == .publisher && authorization?.actorID == database.origin.publisherID
                    || authorization?.actorKind == .account && authorization?.actorID == owner else { throw RelayNoctwebDataStoreError.unauthorized }
        }
    }

    private func authorizeWrite(_ policy: NoctwebDataWritePolicyV1, authorization: NoctwebDataAuthorizationV1, requestedOwner: String?, existingOwner: String?, database: DatabaseState) throws {
        if existingOwner != nil && requestedOwner != existingOwner { throw RelayNoctwebDataStoreError.conflict }
        if let requestedOwner, database.accounts[requestedOwner] == nil { throw RelayNoctwebDataStoreError.accountUnavailable }
        switch policy {
        case .publisher:
            guard authorization.actorKind == .publisher, authorization.actorID == database.origin.publisherID else { throw RelayNoctwebDataStoreError.unauthorized }
        case .owner:
            guard authorization.actorKind == .account, authorization.actorID == requestedOwner else { throw RelayNoctwebDataStoreError.unauthorized }
        case .ownerOrPublisher:
            guard authorization.actorKind == .publisher && authorization.actorID == database.origin.publisherID
                    || authorization.actorKind == .account && authorization.actorID == requestedOwner else { throw RelayNoctwebDataStoreError.unauthorized }
        }
    }

    private func saveLocked() throws {
        guard let fileURL else { return }
        let snapshot = Snapshot(version: Snapshot.version, databases: databases)
        guard snapshot.databases.allSatisfy({ $0.value.isStructurallyValid }) else { throw RelayNoctwebDataStoreError.corruptPersistence }
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(snapshot)
        guard data.count <= Self.maximumSnapshotBytes else { throw RelayNoctwebDataStoreError.capacityExceeded }
        var database: OpaquePointer?
        try openDatabase(at: fileURL, into: &database)
        defer { sqlite3_close(database) }
        guard let database else { throw RelayNoctwebDataStoreError.corruptPersistence }
        try ensureTable(in: database)
        let sql = """
        INSERT INTO \(Self.tableName) (singleton, snapshot)
        VALUES (1, ?)
        ON CONFLICT(singleton) DO UPDATE SET snapshot = excluded.snapshot;
        """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK,
              let statement else { throw RelayNoctwebDataStoreError.corruptPersistence }
        defer { sqlite3_finalize(statement) }
        let bindResult = data.withUnsafeBytes { bytes in
            sqlite3_bind_blob(
                statement,
                1,
                bytes.baseAddress,
                Int32(data.count),
                Self.transient
            )
        }
        guard bindResult == SQLITE_OK,
              sqlite3_step(statement) == SQLITE_DONE else {
            throw RelayNoctwebDataStoreError.corruptPersistence
        }
    }

    private func openDatabase(
        at url: URL,
        into database: inout OpaquePointer?
    ) throws {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let flags = SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(url.path, &database, flags, nil) == SQLITE_OK,
              database != nil else {
            if let opened = database { sqlite3_close(opened) }
            database = nil
            throw RelayNoctwebDataStoreError.corruptPersistence
        }
        sqlite3_busy_timeout(database, 5_000)
    }

    private func ensureTable(in database: OpaquePointer) throws {
        let sql = """
        CREATE TABLE IF NOT EXISTS \(Self.tableName) (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            snapshot BLOB NOT NULL
        );
        """
        guard sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else {
            throw RelayNoctwebDataStoreError.corruptPersistence
        }
    }

    private func canonicalDate(_ value: Date) -> Date { Date(timeIntervalSince1970: floor(value.timeIntervalSince1970)) }
    private func mutationFingerprint(_ transcript: Data, _ signature: Data) -> Data { var data = transcript; data.append(signature); return Data(SHA256.hash(data: data)) }
    private func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
}
