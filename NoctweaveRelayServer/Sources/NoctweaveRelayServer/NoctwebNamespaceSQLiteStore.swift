import Foundation
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite
#endif

private enum NoctwebNamespaceSQLiteError: Error {
    case unavailable
    case corrupt
}

/// A separate table keeps namespace ownership upgrades independent from the
/// message-store snapshot schema. Ownership writes are conservative: a claim
/// is durable before a transient federation-directory record is accepted.
enum NoctwebNamespaceSQLiteStore {
    private static let tableName = "noctweb_namespace_ownership_v1"
    private static let transient = unsafeBitCast(
        -1,
        to: sqlite3_destructor_type.self
    )

    static func load(at url: URL) throws -> NoctwebNamespaceLedgerV1 {
        var database: OpaquePointer?
        try open(at: url, database: &database)
        defer { sqlite3_close(database) }
        guard let database else { throw NoctwebNamespaceSQLiteError.unavailable }
        try ensureTable(in: database)

        let sql = "SELECT ledger FROM \(tableName) WHERE singleton = 1;"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            database,
            sql,
            -1,
            &statement,
            nil
        ) == SQLITE_OK, let statement else {
            throw NoctwebNamespaceSQLiteError.unavailable
        }
        defer { sqlite3_finalize(statement) }
        switch sqlite3_step(statement) {
        case SQLITE_DONE:
            let empty = NoctwebNamespaceLedgerV1()
            try save(empty, in: database)
            return empty
        case SQLITE_ROW:
            let count = Int(sqlite3_column_bytes(statement, 0))
            guard count > 0,
                  count <= 16 * 1_024 * 1_024,
                  let bytes = sqlite3_column_blob(statement, 0) else {
                throw NoctwebNamespaceSQLiteError.corrupt
            }
            do {
                return try RelayCodec.decoder().decode(
                    NoctwebNamespaceLedgerV1.self,
                    from: Data(bytes: bytes, count: count)
                )
            } catch {
                throw NoctwebNamespaceSQLiteError.corrupt
            }
        default:
            throw NoctwebNamespaceSQLiteError.unavailable
        }
    }

    static func save(
        _ ledger: NoctwebNamespaceLedgerV1,
        at url: URL
    ) throws {
        var database: OpaquePointer?
        try open(at: url, database: &database)
        defer { sqlite3_close(database) }
        guard let database else { throw NoctwebNamespaceSQLiteError.unavailable }
        try ensureTable(in: database)
        try save(ledger, in: database)
    }

    private static func save(
        _ ledger: NoctwebNamespaceLedgerV1,
        in database: OpaquePointer
    ) throws {
        let encoded = try RelayCodec.encoder(sortedKeys: true).encode(ledger)
        guard encoded.count <= 16 * 1_024 * 1_024 else {
            throw NoctwebNamespaceSQLiteError.corrupt
        }
        let sql = """
        INSERT INTO \(tableName) (singleton, ledger)
        VALUES (1, ?)
        ON CONFLICT(singleton) DO UPDATE SET ledger = excluded.ledger;
        """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            database,
            sql,
            -1,
            &statement,
            nil
        ) == SQLITE_OK, let statement else {
            throw NoctwebNamespaceSQLiteError.unavailable
        }
        defer { sqlite3_finalize(statement) }
        let bound = encoded.withUnsafeBytes { bytes in
            sqlite3_bind_blob(
                statement,
                1,
                bytes.baseAddress,
                Int32(encoded.count),
                transient
            )
        }
        guard bound == SQLITE_OK,
              sqlite3_step(statement) == SQLITE_DONE else {
            throw NoctwebNamespaceSQLiteError.unavailable
        }
    }

    private static func open(
        at url: URL,
        database: inout OpaquePointer?
    ) throws {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let flags = SQLITE_OPEN_CREATE
            | SQLITE_OPEN_READWRITE
            | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(url.path, &database, flags, nil) == SQLITE_OK,
              let database else {
            if let opened = database {
                sqlite3_close(opened)
                self.clear(&database)
            }
            throw NoctwebNamespaceSQLiteError.unavailable
        }
        sqlite3_busy_timeout(database, 5_000)
    }

    private static func clear(_ database: inout OpaquePointer?) {
        database = nil
    }

    private static func ensureTable(in database: OpaquePointer) throws {
        let sql = """
        CREATE TABLE IF NOT EXISTS \(tableName) (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            ledger BLOB NOT NULL
        );
        """
        guard sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else {
            throw NoctwebNamespaceSQLiteError.unavailable
        }
    }
}
