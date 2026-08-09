import XCTest
@testable import NoctweaveCore

final class RealtimeRelayV1Tests: XCTestCase {
    private func capability() -> Data { OpaqueCapabilityV1.generate() }

    func testRealtimeRouteIsImmediateAndCapabilityScoped() throws {
        var runtime = RealtimeRelayRuntimeV1()
        let route = capability()
        let append = capability()
        let read = capability()
        let now = Date(timeIntervalSince1970: 10_000)
        _ = try runtime.createRoute(
            RealtimeRouteCreateRequestV1(
                routeCapability: route,
                appendCapability: append,
                readCapability: read,
                expiresAt: now.addingTimeInterval(3_600)
            ),
            now: now
        )
        let recordID = UUID()
        _ = try runtime.appendRoute(
            RealtimeRouteAppendRequestV1(
                routeCapability: route,
                appendCapability: append,
                recordID: recordID,
                payload: Data("opaque-now".utf8)
            ),
            now: now
        )
        let subscription = try runtime.subscribe(
            RealtimeRouteSubscribeRequestV1(routeCapability: route, readCapability: read),
            now: now
        )
        let storedSubscriptions = try XCTUnwrap(runtime.state.routes.values.first?.subscriptions)
        XCTAssertEqual(storedSubscriptions.count, 1)
        XCTAssertNil(storedSubscriptions[subscription.subscriptionCapability.base64EncodedString()])
        let batch = try runtime.syncRoute(
            RealtimeRouteSyncRequestV1(
                routeCapability: route,
                subscriptionCapability: subscription.subscriptionCapability,
                maxRecords: 16
            ),
            now: now
        )
        XCTAssertEqual(batch.records.map { $0.recordID }, [recordID])
        XCTAssertThrowsError(
            try runtime.appendRoute(
                RealtimeRouteAppendRequestV1(
                    routeCapability: route,
                    appendCapability: capability(),
                    recordID: UUID(),
                    payload: Data("wrong-authority".utf8)
                ),
                now: now
            )
        ) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .unauthorized) }
    }

    func testSharedLogPersistsOpaqueCursorHistory() async throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-realtime-\(UUID().uuidString).db")
        defer { try? FileManager.default.removeItem(at: url) }
        let log = capability()
        let append = capability()
        let read = capability()
        let store = RelayStore(storeURL: url)
        try await store.loadFromDisk()
        _ = try await store.createSharedLogV1(
            SharedLogCreateRequestV1(
                logCapability: log,
                appendCapability: append,
                readCapability: read,
                retentionSeconds: 3_600,
                maxRecords: 16
            )
        )
        let recordID = UUID()
        _ = try await store.appendSharedLogV1(
            SharedLogAppendRequestV1(
                logCapability: log,
                appendCapability: append,
                recordID: recordID,
                payload: Data("durable-opaque".utf8)
            )
        )
        let restarted = RelayStore(storeURL: url)
        try await restarted.loadFromDisk()
        let batch = try await restarted.syncSharedLogV1(
            SharedLogSyncRequestV1(logCapability: log, readCapability: read, maxRecords: 16)
        )
        XCTAssertEqual(batch.records.map { $0.recordID }, [recordID])
        XCTAssertEqual(batch.records.first?.payload, Data("durable-opaque".utf8))
    }

    func testPresenceLeaseIsEphemeralAndScopeCapabilityBound() throws {
        var runtime = RealtimeRelayRuntimeV1()
        let scope = Data("call-scope".utf8)
        let scopeCapability = capability()
        let leaseCapability = capability()
        let leaseID = Data(repeating: 7, count: 16)
        _ = try runtime.acquirePresence(
            PresenceLeaseAcquireRequestV1(
                scope: scope,
                scopeCapability: scopeCapability,
                leaseID: leaseID,
                leaseCapability: leaseCapability,
                payload: Data("opaque-presence".utf8),
                ttlSeconds: 30
            )
        )
        XCTAssertEqual(
            try runtime.listPresence(PresenceLeaseListRequestV1(scope: scope, scopeCapability: scopeCapability)).count,
            1
        )
        XCTAssertEqual(
            try runtime.listPresence(PresenceLeaseListRequestV1(scope: scope, scopeCapability: capability())).count,
            0
        )
        runtime.prune(now: Date().addingTimeInterval(121))
        XCTAssertTrue(try runtime.listPresence(PresenceLeaseListRequestV1(scope: scope, scopeCapability: scopeCapability)).isEmpty)
    }

    func testMediaBlobRequiresCapabilityAndExpiresByPolicy() throws {
        var runtime = RealtimeRelayRuntimeV1()
        let blobID = UUID()
        let blobCapability = capability()
        let now = Date(timeIntervalSince1970: 20_000)
        _ = try runtime.createMediaBlob(
            MediaBlobCreateRequestV1(blobID: blobID, blobCapability: blobCapability, chunkCount: 1, ttlSeconds: 600),
            now: now
        )
        let chunk = try runtime.uploadMediaBlob(
            MediaBlobUploadRequestV1(
                blobID: blobID,
                blobCapability: blobCapability,
                chunkIndex: 0,
                payload: Data("encrypted-media".utf8),
                idempotencyKey: Data(repeating: 9, count: 32)
            ),
            now: now
        )
        XCTAssertEqual(chunk.payload, Data("encrypted-media".utf8))
        XCTAssertThrowsError(
            try runtime.fetchMediaBlob(
                MediaBlobFetchRequestV1(blobID: blobID, blobCapability: capability(), chunkIndex: 0),
                now: now
            )
        ) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .unavailable) }
        XCTAssertThrowsError(
            try runtime.fetchMediaBlob(
                MediaBlobFetchRequestV1(blobID: blobID, blobCapability: blobCapability, chunkIndex: 0),
                now: now.addingTimeInterval(601)
            )
        ) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .unavailable) }
    }

    func testRealtimeRequestRoundTripsThroughCanonicalRelayEnvelope() throws {
        let request = RelayRequest.createRealtimeRouteV1(
            RealtimeRouteCreateRequestV1(
                routeCapability: capability(),
                appendCapability: capability(),
                readCapability: capability(),
                expiresAt: Date(timeIntervalSince1970: 30_000)
            )
        )
        let encoded = try NoctweaveCoder.encode(request, sortedKeys: true)
        let decoded = try NoctweaveCoder.decode(RelayRequest.self, from: encoded)
        XCTAssertEqual(decoded, request)
        XCTAssertTrue(encoded.contains(Data("nw.realtime-route".utf8)))
        XCTAssertTrue(encoded.contains(Data("request".utf8)))
    }

    func testDisabledRealtimeRoutePolicyRejectsRuntimeRequests() async throws {
        let configuration = RelayConfiguration(realtimeRoutesEnabled: false)
        let server = RelayServer(
            store: RelayStore(),
            configuration: configuration
        )
        let port = UInt16.random(in: 50_100...51_000)
        let started = expectation(description: "policy relay started")
        server.onEvent = { event in
            if case .started = event { started.fulfill() }
        }
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2)

        let response = try await RelayClient(
            endpoint: RelayEndpoint(host: "127.0.0.1", port: port)
        ).send(.createRealtimeRouteV1(
            RealtimeRouteCreateRequestV1(
                routeCapability: capability(),
                appendCapability: capability(),
                readCapability: capability(),
                expiresAt: Date(
                    timeIntervalSince1970: floor(Date().timeIntervalSince1970)
                ).addingTimeInterval(3_600)
            )
        ))

        XCTAssertEqual(response.status, .error)
        XCTAssertEqual(
            response.error?.message,
            "Realtime routes are disabled or require a standard relay and confidential transport."
        )
    }
}
