import Foundation
import XCTest
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite
#endif
@testable import NoctweaveRelayServer

final class RelayStoreCurrentTests: XCTestCase {
    private static let sqliteTransient = unsafeBitCast(
        -1,
        to: sqlite3_destructor_type.self
    )

    func testCurrentStatePersistsAttachmentsFederationAndPinsInOneSchema() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("relay.sqlite")
        let attachmentID = UUID()
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0x11, count: 12),
            ciphertext: Data(repeating: 0x22, count: 512),
            tag: Data(repeating: 0x33, count: 16)
        )
        let endpoint = RelayEndpoint(
            host: "relay.example.org",
            port: 443,
            useTLS: true,
            transport: .http
        )
        let pinnedKey = Data(repeating: 0x44, count: 32)

        let writer = RelayStore(fileURL: url, temporalBucketSeconds: 0)
        _ = try writer.storeAttachment(
            attachmentId: attachmentID,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: 300
        )
        _ = try writer.registerFederationNode(
            FederationNodeRegistrationRequest(
                endpoint: endpoint,
                relayInfo: RelayConfiguration(
                    federation: FederationDescriptor(mode: .open)
                ).makeInfo(),
                ttlSeconds: 300
            )
        )
        try writer.pinCoordinatorPublicKey(pinnedKey, for: endpoint)

        let reader = RelayStore(fileURL: url, temporalBucketSeconds: 0)
        try reader.load()
        XCTAssertEqual(
            try reader.fetchAttachment(attachmentId: attachmentID, chunkIndex: 0)?.payload,
            payload
        )
        XCTAssertEqual(reader.listFederationNodes(nil).map(\.endpoint), [endpoint])
        XCTAssertEqual(reader.pinnedCoordinatorPublicKey(for: endpoint), pinnedKey)
        XCTAssertEqual(try tableNames(in: url), ["relay_runtime_state_v1"])
    }

    func testPersistenceFailureRestoresLastDurableAttachmentState() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("relay.sqlite")
        let store = RelayStore(fileURL: url, temporalBucketSeconds: 0)
        let attachmentID = UUID()
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0xA1, count: 12),
            ciphertext: Data(repeating: 0xA2, count: 512),
            tag: Data(repeating: 0xA3, count: 16)
        )

        store.failNextPersistenceForTesting()
        XCTAssertThrowsError(try store.storeAttachment(
            attachmentId: attachmentID,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: 300
        ))
        XCTAssertNil(try store.fetchAttachment(attachmentId: attachmentID, chunkIndex: 0))

        _ = try store.storeAttachment(
            attachmentId: attachmentID,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: 300
        )
        let reader = RelayStore(fileURL: url, temporalBucketSeconds: 0)
        try reader.load()
        XCTAssertEqual(
            try reader.fetchAttachment(attachmentId: attachmentID, chunkIndex: 0)?.payload,
            payload
        )
    }

    func testExistingForeignDatabaseIsRejectedWithoutImportFallback() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("relay.sqlite")
        var database: OpaquePointer?
        XCTAssertEqual(sqlite3_open(url.path, &database), SQLITE_OK)
        XCTAssertEqual(
            sqlite3_exec(database, "CREATE TABLE foreign_state (value BLOB);", nil, nil, nil),
            SQLITE_OK
        )
        XCTAssertEqual(sqlite3_close(database), SQLITE_OK)

        let store = RelayStore(fileURL: url)
        XCTAssertThrowsError(try store.load())
    }

    func testPersistedSnapshotGraphRejectsUnknownAndMissingFields() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("relay.sqlite")
        try writeRichSnapshot(to: url)
        let original = try readSnapshotData(from: url)
        let root = try snapshotObject(original)
        XCTAssertEqual(
            Set(root.keys),
            [
                "version",
                "rendezvousRoutesV2",
                "opaqueRouteRuntimeV2",
                "attachments",
                "federationNodes",
                "coordinatorPinnedPublicKeys"
            ]
        )

        try assertSnapshotRejectsMutation(original: original, at: url) {
            $0["legacy"] = true
        }
        try assertSnapshotRejectsMutation(original: original, at: url) {
            $0.removeValue(forKey: "attachments")
        }
        try assertSnapshotRejectsMutation(original: original, at: url) { snapshot in
            var routes = try XCTUnwrap(snapshot["rendezvousRoutesV2"] as? [String: Any])
            let key = try XCTUnwrap(routes.keys.first)
            var route = try XCTUnwrap(routes[key] as? [String: Any])
            route["legacy"] = true
            routes[key] = route
            snapshot["rendezvousRoutesV2"] = routes
        }
        try assertSnapshotRejectsMutation(original: original, at: url) { snapshot in
            var routes = try XCTUnwrap(snapshot["rendezvousRoutesV2"] as? [String: Any])
            let routeKey = try XCTUnwrap(routes.keys.first)
            var route = try XCTUnwrap(routes[routeKey] as? [String: Any])
            var lanes = try XCTUnwrap(route["lanes"] as? [String: Any])
            let laneKey = try XCTUnwrap(lanes.keys.first)
            var lane = try XCTUnwrap(lanes[laneKey] as? [String: Any])
            lane["legacy"] = true
            lanes[laneKey] = lane
            route["lanes"] = lanes
            routes[routeKey] = route
            snapshot["rendezvousRoutesV2"] = routes
        }
        try assertSnapshotRejectsMutation(original: original, at: url) { snapshot in
            var routes = try XCTUnwrap(snapshot["rendezvousRoutesV2"] as? [String: Any])
            let routeKey = try XCTUnwrap(routes.keys.first)
            var route = try XCTUnwrap(routes[routeKey] as? [String: Any])
            var lanes = try XCTUnwrap(route["lanes"] as? [String: Any])
            let laneKey = try XCTUnwrap(lanes.first(where: {
                (($0.value as? [String: Any])?["frames"] as? [Any])?.isEmpty == false
            })?.key)
            var lane = try XCTUnwrap(lanes[laneKey] as? [String: Any])
            var frames = try XCTUnwrap(lane["frames"] as? [[String: Any]])
            frames[0]["legacy"] = true
            lane["frames"] = frames
            lanes[laneKey] = lane
            route["lanes"] = lanes
            routes[routeKey] = route
            snapshot["rendezvousRoutesV2"] = routes
        }
        try assertSnapshotRejectsMutation(original: original, at: url) { snapshot in
            var attachments = try XCTUnwrap(snapshot["attachments"] as? [String: Any])
            let key = try XCTUnwrap(attachments.keys.first)
            var records = try XCTUnwrap(attachments[key] as? [[String: Any]])
            records[0]["legacy"] = true
            attachments[key] = records
            snapshot["attachments"] = attachments
        }
        try assertSnapshotRejectsMutation(original: original, at: url) { snapshot in
            var nodes = try XCTUnwrap(snapshot["federationNodes"] as? [String: Any])
            let key = try XCTUnwrap(nodes.keys.first)
            var node = try XCTUnwrap(nodes[key] as? [String: Any])
            node["legacy"] = true
            nodes[key] = node
            snapshot["federationNodes"] = nodes
        }
    }

    private func writeRichSnapshot(to url: URL) throws {
        let store = RelayStore(fileURL: url, temporalBucketSeconds: 0)
        let now = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
        let route = RendezvousRelayRouteCapabilityV2(
            rawValue: Data(repeating: 0x11, count: 32)
        )
        let lanes = [
            RendezvousRelayLaneRegistrationV2(
                laneId: RendezvousRelayLaneIDV2(rawValue: Data(repeating: 0x21, count: 32)),
                publishCapability: RendezvousRelayPublishCapabilityV2(
                    rawValue: Data(repeating: 0x22, count: 32)
                ),
                readCapability: RendezvousRelayReadCapabilityV2(
                    rawValue: Data(repeating: 0x23, count: 32)
                ),
                deleteCapability: RendezvousRelayDeleteCapabilityV2(
                    rawValue: Data(repeating: 0x24, count: 32)
                )
            ),
            RendezvousRelayLaneRegistrationV2(
                laneId: RendezvousRelayLaneIDV2(rawValue: Data(repeating: 0x31, count: 32)),
                publishCapability: RendezvousRelayPublishCapabilityV2(
                    rawValue: Data(repeating: 0x32, count: 32)
                ),
                readCapability: RendezvousRelayReadCapabilityV2(
                    rawValue: Data(repeating: 0x33, count: 32)
                ),
                deleteCapability: RendezvousRelayDeleteCapabilityV2(
                    rawValue: Data(repeating: 0x34, count: 32)
                )
            )
        ]
        try store.registerRendezvousTransportV2(
            RegisterRendezvousTransportV2Request(
                routeCapability: route,
                expiresAt: now.addingTimeInterval(300),
                lanes: lanes
            ),
            now: now
        )
        _ = try store.appendRendezvousTransportV2(
            AppendRendezvousTransportV2Request(
                routeCapability: route,
                laneId: lanes[0].laneId,
                publishCapability: lanes[0].publishCapability,
                frame: RendezvousRelayCiphertextFrameV2(
                    frameId: RendezvousRelayFrameIDV2(
                        rawValue: Data(repeating: 0x41, count: 16)
                    ),
                    sequence: 1,
                    ciphertext: Data(repeating: 0x42, count: 4_096)
                )
            ),
            now: now
        )
        _ = try store.storeAttachment(
            attachmentId: UUID(),
            chunkIndex: 0,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x51, count: 12),
                ciphertext: Data(repeating: 0x52, count: 512),
                tag: Data(repeating: 0x53, count: 16)
            ),
            ttlSeconds: 300
        )
        _ = try store.registerFederationNode(
            FederationNodeRegistrationRequest(
                endpoint: RelayEndpoint(
                    host: "relay.example.org",
                    port: 443,
                    useTLS: true,
                    transport: .http
                ),
                relayInfo: RelayConfiguration(
                    federation: FederationDescriptor(mode: .open)
                ).makeInfo(),
                ttlSeconds: 300
            )
        )
    }

    private func assertSnapshotRejectsMutation(
        original: Data,
        at url: URL,
        mutate: (inout [String: Any]) throws -> Void,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        var snapshot = try snapshotObject(original)
        try mutate(&snapshot)
        let mutated = try JSONSerialization.data(
            withJSONObject: snapshot,
            options: [.sortedKeys]
        )
        try writeSnapshotData(mutated, to: url)
        XCTAssertThrowsError(
            try RelayStore(fileURL: url).load(),
            file: file,
            line: line
        )
        try writeSnapshotData(original, to: url)
    }

    private func snapshotObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func readSnapshotData(from url: URL) throws -> Data {
        var database: OpaquePointer?
        guard sqlite3_open_v2(url.path, &database, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
              let database else {
            throw NSError(domain: "RelayStoreCurrentTests", code: 3)
        }
        defer { sqlite3_close(database) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            database,
            "SELECT snapshot FROM relay_runtime_state_v1 WHERE singleton = 1;",
            -1,
            &statement,
            nil
        ) == SQLITE_OK,
              let statement else {
            throw NSError(domain: "RelayStoreCurrentTests", code: 4)
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW,
              let bytes = sqlite3_column_blob(statement, 0) else {
            throw NSError(domain: "RelayStoreCurrentTests", code: 5)
        }
        return Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
    }

    private func writeSnapshotData(_ data: Data, to url: URL) throws {
        var database: OpaquePointer?
        guard sqlite3_open_v2(url.path, &database, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK,
              let database else {
            throw NSError(domain: "RelayStoreCurrentTests", code: 6)
        }
        defer { sqlite3_close(database) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            database,
            "UPDATE relay_runtime_state_v1 SET snapshot = ? WHERE singleton = 1;",
            -1,
            &statement,
            nil
        ) == SQLITE_OK,
              let statement else {
            throw NSError(domain: "RelayStoreCurrentTests", code: 7)
        }
        defer { sqlite3_finalize(statement) }
        let bindResult = data.withUnsafeBytes { bytes in
            sqlite3_bind_blob(
                statement,
                1,
                bytes.baseAddress,
                Int32(data.count),
                Self.sqliteTransient
            )
        }
        guard bindResult == SQLITE_OK, sqlite3_step(statement) == SQLITE_DONE else {
            throw NSError(domain: "RelayStoreCurrentTests", code: 8)
        }
    }

    private func tableNames(in url: URL) throws -> [String] {
        var database: OpaquePointer?
        guard sqlite3_open_v2(url.path, &database, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
              let database else {
            throw NSError(domain: "RelayStoreCurrentTests", code: 1)
        }
        defer { sqlite3_close(database) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            database,
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name;",
            -1,
            &statement,
            nil
        ) == SQLITE_OK,
              let statement else {
            throw NSError(domain: "RelayStoreCurrentTests", code: 2)
        }
        defer { sqlite3_finalize(statement) }
        var names: [String] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            names.append(String(cString: sqlite3_column_text(statement, 0)))
        }
        return names
    }
}
