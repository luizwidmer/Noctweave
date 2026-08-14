import Crypto
import Foundation
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite
#endif

enum RelayNoctwebDataStoreError: Error, Equatable {
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

private func noctwebDataReplayDateIsCanonical(_ value: Date) -> Bool {
    let seconds = value.timeIntervalSince1970
    return seconds.isFinite && seconds >= 0 && floor(seconds) == seconds
}

final class RelayNoctwebDataStore: @unchecked Sendable {
    private struct MutationReplay: Codable, Equatable {
        enum Kind: String, Codable { case put, delete }
        let kind: Kind
        let fingerprint: Data
        let record: NoctwebDataRecordV1?
        let deleteReceipt: NoctwebDataDeleteReceiptV1?
        let createdAt: Date

        var isStructurallyValid: Bool {
            fingerprint.count == 32
                && noctwebDataReplayDateIsCanonical(createdAt)
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
                && records.allSatisfy { $0.key == Self.recordKey($0.value.collection, $0.value.ownerAccountID, $0.value.recordID) && $0.value.databaseID == origin.databaseID && $0.value.isStructurallyValid }
                && records.values.reduce(0, {
                    $0 + RelayNoctwebDataStore.recordStorageBytes($1)
                }) <= NoctwebDataV1.maximumDatabaseBytes
                && mutationReplays.count <= NoctwebDataV1.maximumMutationReplayEntries
                && RelayNoctwebDataStore.replayBytes(mutationReplays) <= NoctwebDataV1.maximumMutationReplayBytes
                && mutationReplays.values.allSatisfy(\.isStructurallyValid)
        }

        static func recordKey(_ collection: String, _ owner: String?, _ recordID: String) -> String { collection + "\u{0}" + (owner ?? "") + "\u{0}" + recordID }
    }

    // The raw quota includes record/provenance bytes. JSON/Base64 persistence
    // needs bounded headroom for encoding plus replay and account registries.
    private static let maximumPersistedDatabaseBytes = 128 * 1_024 * 1_024
    private static let tableName = "noctweb_data_databases_v2"
    private static let legacyTableName = "noctweb_data_service_v1"
    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    private let queue = DispatchQueue(label: "noctweave.noctweb.data-store")
    private let fileURL: URL?
    private var databases: [String: DatabaseState] = [:]
    private var encodedBytesByDatabase: [String: Int] = [:]
    private var consumedReadAuthorizations: [String: Date] = [:]

    init(fileURL: URL? = nil) { self.fileURL = fileURL }

    func load() throws {
        try queue.sync {
            guard let fileURL else { return }
            var database: OpaquePointer?
            try openDatabase(at: fileURL, into: &database)
            defer { sqlite3_close(database) }
            guard let database else { throw RelayNoctwebDataStoreError.corruptPersistence }
            guard try !legacySnapshotExists(in: database) else {
                throw RelayNoctwebDataStoreError.corruptPersistence
            }
            try ensureTable(in: database)
            let sql = "SELECT database_id, state FROM \(Self.tableName) ORDER BY database_id ASC;"
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK,
                  let statement else { throw RelayNoctwebDataStoreError.corruptPersistence }
            defer { sqlite3_finalize(statement) }
            var loaded: [String: DatabaseState] = [:]
            var loadedEncodedBytes: [String: Int] = [:]
            var loadedTotalBytes = 0
            let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
            while true {
                let step = sqlite3_step(statement)
                if step == SQLITE_DONE { break }
                guard step == SQLITE_ROW,
                      loaded.count < NoctwebDataV1.maximumDatabases,
                      let rawID = sqlite3_column_text(statement, 0),
                      let databaseID = String(
                        validatingUTF8: UnsafeRawPointer(rawID)
                            .assumingMemoryBound(to: CChar.self)
                      ) else {
                    throw RelayNoctwebDataStoreError.corruptPersistence
                }
                let count = Int(sqlite3_column_bytes(statement, 1))
                guard count > 0,
                      count <= Self.maximumPersistedDatabaseBytes,
                      count <= NoctwebDataV1.maximumTotalDataBytes - loadedTotalBytes,
                      let bytes = sqlite3_column_blob(statement, 1) else {
                    throw RelayNoctwebDataStoreError.corruptPersistence
                }
                loadedTotalBytes += count
                var state = try decoder.decode(DatabaseState.self, from: Data(bytes: bytes, count: count))
                pruneMutationReplays(in: &state, now: canonicalDate(Date()))
                guard databaseID == state.origin.databaseID,
                      Self.mutationReplayBoundsAreValid(state.mutationReplays),
                      state.isStructurallyValid,
                      loaded.updateValue(state, forKey: databaseID) == nil,
                      loadedEncodedBytes.updateValue(count, forKey: databaseID) == nil else {
                    throw RelayNoctwebDataStoreError.corruptPersistence
                }
            }
            databases = loaded
            encodedBytesByDatabase = loadedEncodedBytes
        }
    }

    func createDatabase(_ request: NoctwebDataDatabaseCreateRequestV1) throws -> NoctwebDataDatabaseReceiptV1 {
        try queue.sync {
            guard request.isStructurallyValid, request.verifyPublisherSignature() else { throw RelayNoctwebDataStoreError.authenticationRequired }
            let databaseID = request.origin.databaseID
            if let existing = databases[databaseID] {
                guard existing.origin == request.origin,
                      Array(existing.collections.values).sorted(by: { $0.name < $1.name }) == request.collections else { throw RelayNoctwebDataStoreError.conflict }
                return NoctwebDataDatabaseReceiptV1(databaseID: databaseID, created: false)
            }
            guard databases.count < NoctwebDataV1.maximumDatabases else { throw RelayNoctwebDataStoreError.capacityExceeded }
            let publisherDatabaseCount = databases.values.reduce(into: 0) { count, database in
                if database.origin.publisherID == request.origin.publisherID { count += 1 }
            }
            guard publisherDatabaseCount < NoctwebDataV1.maximumDatabasesPerPublisher else { throw RelayNoctwebDataStoreError.capacityExceeded }
            let previous = databases
            databases[databaseID] = DatabaseState(
                origin: request.origin,
                collections: Dictionary(uniqueKeysWithValues: request.collections.map { ($0.name, $0) }),
                accounts: [:], records: [:], mutationReplays: [:]
            )
            do { try saveDatabaseLocked(databaseID) } catch { databases = previous; throw error }
            return NoctwebDataDatabaseReceiptV1(databaseID: databaseID, created: true)
        }
    }

    func registerAccount(_ request: NoctwebDataAccountRegisterRequestV1) throws -> NoctwebDataAccountReceiptV1 {
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
            do { try saveDatabaseLocked(request.databaseID) } catch { databases[request.databaseID] = previous; throw error }
            return NoctwebDataAccountReceiptV1(databaseID: request.databaseID, accountID: request.accountID, created: true)
        }
    }

    func putRecord(_ request: NoctwebDataRecordPutRequestV1, now: Date = Date()) throws -> NoctwebDataRecordV1 {
        try queue.sync {
            guard request.isStructurallyValid else { throw RelayNoctwebDataStoreError.invalidRequest }
            guard var database = databases[request.databaseID] else { throw RelayNoctwebDataStoreError.databaseUnavailable }
            guard let policy = database.collections[request.collection] else { throw RelayNoctwebDataStoreError.collectionUnavailable }
            let timestamp = canonicalDate(now)
            pruneMutationReplays(in: &database, now: timestamp)
            let replayKey = hex(request.idempotencyKey)
            let fingerprint = mutationFingerprint(NoctwebDataTranscriptV1.putRecord(request), request.authorization.signature)
            try verify(request.authorization, transcript: NoctwebDataTranscriptV1.putRecord(request), in: database, now: timestamp)
            if let replay = database.mutationReplays[replayKey] {
                guard replay.kind == .put, replay.fingerprint == fingerprint, let record = replay.record else { throw RelayNoctwebDataStoreError.conflict }
                return record
            }
            let key = DatabaseState.recordKey(request.collection, request.ownerAccountID, request.recordID)
            let existing = database.records[key]
            guard (existing == nil && request.expectedRevision == 0)
                    || existing?.revision == request.expectedRevision else { throw RelayNoctwebDataStoreError.conflict }
            guard policy.readPolicy != .owner
                    || request.ownerAccountID != nil else {
                throw RelayNoctwebDataStoreError.unauthorized
            }
            try authorizeWrite(policy.writePolicy, authorization: request.authorization, requestedOwner: request.ownerAccountID, existingOwner: existing?.ownerAccountID, database: database)
            if existing == nil {
                guard database.records.count < NoctwebDataV1.maximumRecordsPerDatabase else { throw RelayNoctwebDataStoreError.capacityExceeded }
            }
            let actorSigningPublicKey = try signingPublicKey(for: request.authorization, in: database)
            let provenance = NoctwebDataRecordProvenanceV1(
                actorKind: request.authorization.actorKind,
                actorID: request.authorization.actorID,
                actorSigningPublicKey: actorSigningPublicKey,
                authorizationNonce: request.authorization.nonce,
                authorizationExpiresAt: request.authorization.expiresAt,
                idempotencyKey: request.idempotencyKey,
                expectedRevision: request.expectedRevision,
                signature: request.authorization.signature
            )
            let record = NoctwebDataRecordV1(
                databaseID: request.databaseID, collection: request.collection, recordID: request.recordID,
                ownerAccountID: request.ownerAccountID, payload: request.payload,
                revision: (existing?.revision ?? 0) + 1, createdAt: existing?.createdAt ?? timestamp, updatedAt: timestamp,
                provenance: provenance
            )
            guard record.isStructurallyValid else { throw RelayNoctwebDataStoreError.invalidRequest }
            let currentBytes = database.records.values.reduce(0) {
                $0 + Self.recordStorageBytes($1)
            }
            let replacedBytes = existing.map(Self.recordStorageBytes) ?? 0
            let recordBytes = Self.recordStorageBytes(record)
            guard currentBytes - replacedBytes + recordBytes
                    <= NoctwebDataV1.maximumDatabaseBytes else {
                throw RelayNoctwebDataStoreError.capacityExceeded
            }
            if let owner = request.ownerAccountID {
                let ownerRecords = database.records.values.filter {
                    $0.ownerAccountID == owner
                }
                let ownerBytes = ownerRecords.reduce(0) {
                    $0 + Self.recordStorageBytes($1)
                }
                guard ownerRecords.count - (existing == nil ? 0 : 1) + 1
                        <= NoctwebDataV1.maximumRecordsPerOwner,
                      ownerBytes - replacedBytes + recordBytes
                        <= NoctwebDataV1.maximumBytesPerOwner else {
                    throw RelayNoctwebDataStoreError.capacityExceeded
                }
            }
            database.records[key] = record
            database.mutationReplays[replayKey] = MutationReplay(kind: .put, fingerprint: fingerprint, record: record, deleteReceipt: nil, createdAt: timestamp)
            guard Self.mutationReplayBoundsAreValid(database.mutationReplays) else {
                throw RelayNoctwebDataStoreError.capacityExceeded
            }
            let previous = databases[request.databaseID]; databases[request.databaseID] = database
            do { try saveDatabaseLocked(request.databaseID) } catch { databases[request.databaseID] = previous; throw error }
            return record
        }
    }

    func getRecord(_ request: NoctwebDataRecordGetRequestV1, now: Date = Date()) throws -> NoctwebDataRecordV1 {
        try queue.sync {
            guard request.isStructurallyValid else { throw RelayNoctwebDataStoreError.invalidRequest }
            guard let database = databases[request.databaseID] else { throw RelayNoctwebDataStoreError.databaseUnavailable }
            guard let policy = database.collections[request.collection] else { throw RelayNoctwebDataStoreError.collectionUnavailable }
            let timestamp = canonicalDate(now)
            if let authorization = request.authorization {
                try verify(authorization, transcript: NoctwebDataTranscriptV1.getRecord(request), in: database, now: timestamp)
                try consumeReadAuthorization(authorization, databaseID: request.databaseID, now: timestamp)
            }
            let owner = try resolvedReadOwner(policy.readPolicy, requestedOwner: request.ownerAccountID, authorization: request.authorization, database: database)
            guard let record = database.records[DatabaseState.recordKey(request.collection, owner, request.recordID)] else { throw RelayNoctwebDataStoreError.databaseUnavailable }
            try authorizeRead(policy.readPolicy, authorization: request.authorization, owner: record.ownerAccountID, database: database)
            return record
        }
    }

    func listRecords(_ request: NoctwebDataRecordListRequestV1, now: Date = Date()) throws -> NoctwebDataRecordListV1 {
        try queue.sync {
            guard request.isStructurallyValid else { throw RelayNoctwebDataStoreError.invalidRequest }
            guard let database = databases[request.databaseID] else { throw RelayNoctwebDataStoreError.databaseUnavailable }
            guard let policy = database.collections[request.collection] else { throw RelayNoctwebDataStoreError.collectionUnavailable }
            let timestamp = canonicalDate(now)
            if let authorization = request.authorization {
                try verify(authorization, transcript: NoctwebDataTranscriptV1.listRecords(request), in: database, now: timestamp)
                try consumeReadAuthorization(authorization, databaseID: request.databaseID, now: timestamp)
            }
            let owner = try resolvedReadOwner(policy.readPolicy, requestedOwner: request.ownerAccountID, authorization: request.authorization, database: database)
            let candidates = database.records.values
                .filter { $0.collection == request.collection && $0.ownerAccountID == owner && (request.afterRecordID == nil || $0.recordID > request.afterRecordID!) }
                .sorted { $0.recordID < $1.recordID }
                .filter { (try? authorizeRead(policy.readPolicy, authorization: request.authorization, owner: $0.ownerAccountID, database: database)) != nil }
            let selected = Array(candidates.prefix(request.limit))
            let next = candidates.count > selected.count ? selected.last?.recordID : nil
            return NoctwebDataRecordListV1(records: selected, nextCursor: next)
        }
    }

    func deleteRecord(_ request: NoctwebDataRecordDeleteRequestV1, now: Date = Date()) throws -> NoctwebDataDeleteReceiptV1 {
        try queue.sync {
            guard request.isStructurallyValid else { throw RelayNoctwebDataStoreError.invalidRequest }
            guard var database = databases[request.databaseID] else { throw RelayNoctwebDataStoreError.databaseUnavailable }
            guard let policy = database.collections[request.collection] else { throw RelayNoctwebDataStoreError.collectionUnavailable }
            let timestamp = canonicalDate(now)
            pruneMutationReplays(in: &database, now: timestamp)
            let replayKey = hex(request.idempotencyKey)
            let fingerprint = mutationFingerprint(NoctwebDataTranscriptV1.deleteRecord(request), request.authorization.signature)
            try verify(request.authorization, transcript: NoctwebDataTranscriptV1.deleteRecord(request), in: database, now: timestamp)
            if let replay = database.mutationReplays[replayKey] {
                guard replay.kind == .delete, replay.fingerprint == fingerprint, let receipt = replay.deleteReceipt else { throw RelayNoctwebDataStoreError.conflict }
                return receipt
            }
            let owner = try resolvedWriteOwner(policy.writePolicy, requestedOwner: request.ownerAccountID, authorization: request.authorization, database: database)
            let key = DatabaseState.recordKey(request.collection, owner, request.recordID)
            guard let record = database.records[key], record.revision == request.expectedRevision else { throw RelayNoctwebDataStoreError.conflict }
            try authorizeWrite(policy.writePolicy, authorization: request.authorization, requestedOwner: record.ownerAccountID, existingOwner: record.ownerAccountID, database: database)
            let receipt = NoctwebDataDeleteReceiptV1(
                databaseID: request.databaseID,
                collection: request.collection,
                recordID: request.recordID,
                ownerAccountID: record.ownerAccountID,
                deletedRevision: record.revision
            )
            database.records.removeValue(forKey: key)
            database.mutationReplays[replayKey] = MutationReplay(kind: .delete, fingerprint: fingerprint, record: nil, deleteReceipt: receipt, createdAt: timestamp)
            guard Self.mutationReplayBoundsAreValid(database.mutationReplays) else {
                throw RelayNoctwebDataStoreError.capacityExceeded
            }
            let previous = databases[request.databaseID]; databases[request.databaseID] = database
            do { try saveDatabaseLocked(request.databaseID) } catch { databases[request.databaseID] = previous; throw error }
            return receipt
        }
    }

    private func verify(_ authorization: NoctwebDataAuthorizationV1, transcript: Data, in database: DatabaseState, now: Date) throws {
        let earliestAccepted = now.addingTimeInterval(-TimeInterval(NoctwebDataV1.authorizationClockSkewSeconds))
        let latestAccepted = now.addingTimeInterval(TimeInterval(NoctwebDataV1.maximumAuthorizationLifetimeSeconds))
        guard authorization.expiresAt >= earliestAccepted,
              authorization.expiresAt <= latestAccepted else { throw RelayNoctwebDataStoreError.authenticationRequired }
        switch authorization.actorKind {
        case .publisher:
            guard authorization.actorID == database.origin.publisherID,
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: database.origin.publisherSigningPublicKey),
                  key.isValidSignature(authorization.signature, for: transcript) else { throw RelayNoctwebDataStoreError.authenticationRequired }
        case .account:
            guard let key = database.accounts[authorization.actorID] else { throw RelayNoctwebDataStoreError.accountUnavailable }
            guard try OQSSignatureVerifier.shared.verifyThrowing(signature: authorization.signature, data: transcript, publicKey: key) else { throw RelayNoctwebDataStoreError.authenticationRequired }
        }
    }

    private func signingPublicKey(for authorization: NoctwebDataAuthorizationV1, in database: DatabaseState) throws -> Data {
        switch authorization.actorKind {
        case .publisher:
            guard authorization.actorID == database.origin.publisherID else { throw RelayNoctwebDataStoreError.authenticationRequired }
            return database.origin.publisherSigningPublicKey
        case .account:
            guard let key = database.accounts[authorization.actorID] else { throw RelayNoctwebDataStoreError.accountUnavailable }
            return key
        }
    }

    private func consumeReadAuthorization(_ authorization: NoctwebDataAuthorizationV1, databaseID: String, now: Date) throws {
        consumedReadAuthorizations = consumedReadAuthorizations.filter { $0.value >= now }
        let scope = databaseID + "\u{0}" + authorization.actorID + "\u{0}"
        let key = scope + hex(authorization.nonce)
        guard consumedReadAuthorizations[key] == nil else { throw RelayNoctwebDataStoreError.authenticationRequired }
        guard consumedReadAuthorizations.count < 65_536,
              consumedReadAuthorizations.keys.lazy.filter({ $0.hasPrefix(scope) })
                .prefix(513).count < 512 else {
            throw RelayNoctwebDataStoreError.capacityExceeded
        }
        consumedReadAuthorizations[key] = authorization.expiresAt.addingTimeInterval(
            TimeInterval(NoctwebDataV1.authorizationClockSkewSeconds)
        )
    }

    private func resolvedReadOwner(_ policy: NoctwebDataReadPolicyV1, requestedOwner: String?, authorization: NoctwebDataAuthorizationV1?, database: DatabaseState) throws -> String? {
        switch policy {
        case .publicRead:
            return requestedOwner
        case .owner:
            guard authorization?.actorKind == .account,
                  requestedOwner == nil || requestedOwner == authorization?.actorID else { throw RelayNoctwebDataStoreError.unauthorized }
            return authorization?.actorID
        case .ownerOrPublisher:
            if authorization?.actorKind == .account {
                guard requestedOwner == nil || requestedOwner == authorization?.actorID else { throw RelayNoctwebDataStoreError.unauthorized }
                return authorization?.actorID
            }
            guard authorization?.actorKind == .publisher,
                  authorization?.actorID == database.origin.publisherID else {
                throw RelayNoctwebDataStoreError.unauthorized
            }
            return requestedOwner
        }
    }

    private func resolvedWriteOwner(_ policy: NoctwebDataWritePolicyV1, requestedOwner: String?, authorization: NoctwebDataAuthorizationV1, database: DatabaseState) throws -> String? {
        switch policy {
        case .publisher:
            guard authorization.actorKind == .publisher,
                  authorization.actorID == database.origin.publisherID else { throw RelayNoctwebDataStoreError.unauthorized }
            return requestedOwner
        case .owner:
            guard authorization.actorKind == .account,
                  requestedOwner == nil || requestedOwner == authorization.actorID else { throw RelayNoctwebDataStoreError.unauthorized }
            return authorization.actorID
        case .ownerOrPublisher:
            if authorization.actorKind == .account {
                guard requestedOwner == nil || requestedOwner == authorization.actorID else { throw RelayNoctwebDataStoreError.unauthorized }
                return authorization.actorID
            }
            guard authorization.actorID == database.origin.publisherID else { throw RelayNoctwebDataStoreError.unauthorized }
            return requestedOwner
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

    private func pruneMutationReplays(in database: inout DatabaseState, now: Date) {
        let cutoff = now.addingTimeInterval(-TimeInterval(NoctwebDataV1.mutationReplayLifetimeSeconds))
        database.mutationReplays = database.mutationReplays.filter { $0.value.createdAt >= cutoff }
    }

    private static func mutationReplayBoundsAreValid(
        _ replays: [String: MutationReplay]
    ) -> Bool {
        replays.count <= NoctwebDataV1.maximumMutationReplayEntries
            && replayBytes(replays) <= NoctwebDataV1.maximumMutationReplayBytes
    }

    private static func replayBytes(_ replays: [String: MutationReplay]) -> Int {
        replays.reduce(0) { total, entry in
            total + entry.key.utf8.count + 128
                + (entry.value.record.map(recordStorageBytes(_:)) ?? 0)
                + (entry.value.deleteReceipt.map(deleteReceiptStorageBytes(_:)) ?? 0)
        }
    }

    private static func deleteReceiptStorageBytes(
        _ receipt: NoctwebDataDeleteReceiptV1
    ) -> Int {
        receipt.databaseID.utf8.count
            + receipt.collection.utf8.count
            + receipt.recordID.utf8.count
            + (receipt.ownerAccountID?.utf8.count ?? 0)
            + 64
    }

    private static func recordStorageBytes(_ record: NoctwebDataRecordV1) -> Int {
        record.databaseID.utf8.count
            + record.collection.utf8.count
            + record.recordID.utf8.count
            + (record.ownerAccountID?.utf8.count ?? 0)
            + record.payload.count
            + record.provenance.actorID.utf8.count
            + record.provenance.actorSigningPublicKey.count
            + record.provenance.authorizationNonce.count
            + record.provenance.idempotencyKey.count
            + record.provenance.signature.count
            + 256
    }

    private func saveDatabaseLocked(_ databaseID: String) throws {
        guard let state = databases[databaseID], state.isStructurallyValid else { throw RelayNoctwebDataStoreError.corruptPersistence }
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(state)
        guard data.count <= Self.maximumPersistedDatabaseBytes else { throw RelayNoctwebDataStoreError.capacityExceeded }
        let replacedBytes = encodedBytesByDatabase[databaseID] ?? 0
        let otherBytes = encodedBytesByDatabase.values.reduce(0, +) - replacedBytes
        guard data.count <= NoctwebDataV1.maximumTotalDataBytes - otherBytes else {
            throw RelayNoctwebDataStoreError.capacityExceeded
        }
        guard let fileURL else {
            encodedBytesByDatabase[databaseID] = data.count
            return
        }
        var database: OpaquePointer?
        try openDatabase(at: fileURL, into: &database)
        defer { sqlite3_close(database) }
        guard let database else { throw RelayNoctwebDataStoreError.corruptPersistence }
        guard try !legacySnapshotExists(in: database) else {
            throw RelayNoctwebDataStoreError.corruptPersistence
        }
        try ensureTable(in: database)
        let sql = """
        INSERT INTO \(Self.tableName) (database_id, state)
        VALUES (?, ?)
        ON CONFLICT(database_id) DO UPDATE SET state = excluded.state;
        """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK,
              let statement else { throw RelayNoctwebDataStoreError.corruptPersistence }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_bind_text(statement, 1, databaseID, -1, Self.transient) == SQLITE_OK else { throw RelayNoctwebDataStoreError.corruptPersistence }
        let bindResult = data.withUnsafeBytes { bytes in
            sqlite3_bind_blob(
                statement,
                2,
                bytes.baseAddress,
                Int32(data.count),
                Self.transient
            )
        }
        guard bindResult == SQLITE_OK,
              sqlite3_step(statement) == SQLITE_DONE else {
            throw RelayNoctwebDataStoreError.corruptPersistence
        }
        encodedBytesByDatabase[databaseID] = data.count
    }

    private func openDatabase(
        at url: URL,
        into database: inout OpaquePointer?
    ) throws {
        let flags = SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE
            | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW
        do {
            try RelayServerSecureFileIO.withPreparedPrivateSQLiteFile(at: url) { path in
                guard sqlite3_open_v2(path, &database, flags, nil) == SQLITE_OK,
                      database != nil else {
                    throw RelayNoctwebDataStoreError.corruptPersistence
                }
            }
        } catch {
            if let opened = database { sqlite3_close(opened) }
            database = nil
            throw RelayNoctwebDataStoreError.corruptPersistence
        }
        sqlite3_busy_timeout(database, 5_000)
    }

    private func ensureTable(in database: OpaquePointer) throws {
        let sql = """
        CREATE TABLE IF NOT EXISTS \(Self.tableName) (
            database_id TEXT PRIMARY KEY NOT NULL,
            state BLOB NOT NULL
        );
        """
        guard sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else {
            throw RelayNoctwebDataStoreError.corruptPersistence
        }
    }

    /// A v1 snapshot contains relay-visible plaintext and no retained author
    /// proof. The relay has no application encryption keys, so it cannot safely
    /// migrate that state into the hardened format. Fail closed when data is
    /// present rather than silently dropping or re-serving it.
    private func legacySnapshotExists(in database: OpaquePointer) throws -> Bool {
        let tableSQL = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1;"
        var tableStatement: OpaquePointer?
        guard sqlite3_prepare_v2(database, tableSQL, -1, &tableStatement, nil) == SQLITE_OK,
              let tableStatement else {
            throw RelayNoctwebDataStoreError.corruptPersistence
        }
        defer { sqlite3_finalize(tableStatement) }
        guard sqlite3_bind_text(tableStatement, 1, Self.legacyTableName, -1, Self.transient) == SQLITE_OK else {
            throw RelayNoctwebDataStoreError.corruptPersistence
        }
        let tableStep = sqlite3_step(tableStatement)
        if tableStep == SQLITE_DONE { return false }
        guard tableStep == SQLITE_ROW else { throw RelayNoctwebDataStoreError.corruptPersistence }

        let snapshotSQL = "SELECT 1 FROM \(Self.legacyTableName) WHERE singleton = 1 AND length(snapshot) > 0 LIMIT 1;"
        var snapshotStatement: OpaquePointer?
        guard sqlite3_prepare_v2(database, snapshotSQL, -1, &snapshotStatement, nil) == SQLITE_OK,
              let snapshotStatement else {
            throw RelayNoctwebDataStoreError.corruptPersistence
        }
        defer { sqlite3_finalize(snapshotStatement) }
        let snapshotStep = sqlite3_step(snapshotStatement)
        if snapshotStep == SQLITE_ROW { return true }
        guard snapshotStep == SQLITE_DONE else { throw RelayNoctwebDataStoreError.corruptPersistence }
        return false
    }

    private func canonicalDate(_ value: Date) -> Date { Date(timeIntervalSince1970: floor(value.timeIntervalSince1970)) }
    private func mutationFingerprint(_ transcript: Data, _ signature: Data) -> Data { var data = transcript; data.append(signature); return Data(SHA256.hash(data: data)) }
    private func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
}
