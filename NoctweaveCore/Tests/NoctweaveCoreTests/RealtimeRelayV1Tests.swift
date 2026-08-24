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

    func testCursorsRejectOverflowAndFuturePositions() throws {
        var runtime = RealtimeRelayRuntimeV1()
        let route = capability()
        let append = capability()
        let read = capability()
        let now = Date(timeIntervalSince1970: 25_000)
        _ = try runtime.createRoute(
            RealtimeRouteCreateRequestV1(
                routeCapability: route,
                appendCapability: append,
                readCapability: read,
                expiresAt: now.addingTimeInterval(3_600)
            ),
            now: now
        )
        let subscription = try runtime.subscribe(
            RealtimeRouteSubscribeRequestV1(routeCapability: route, readCapability: read),
            now: now
        )
        XCTAssertThrowsError(try runtime.syncRoute(
            RealtimeRouteSyncRequestV1(
                routeCapability: route,
                subscriptionCapability: subscription.subscriptionCapability,
                afterSequence: .max,
                maxRecords: 1
            ),
            now: now
        )) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .invalidCursor) }

        let log = capability()
        _ = try runtime.createSharedLog(
            SharedLogCreateRequestV1(
                logCapability: log,
                appendCapability: append,
                readCapability: read,
                retentionSeconds: 3_600,
                maxRecords: 8
            ),
            now: now
        )
        XCTAssertThrowsError(try runtime.syncSharedLog(
            SharedLogSyncRequestV1(
                logCapability: log,
                readCapability: read,
                afterSequence: .max,
                maxRecords: 1
            ),
            now: now
        )) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .invalidCursor) }

        XCTAssertTrue(OpaqueRelaySyncBatchV1(
            records: [],
            nextSequence: .max,
            highWatermark: .max,
            retentionFloor: .max,
            hasMore: false
        ).isStructurallyValid)
    }

    func testResourceCreationRetriesRequireExactPolicy() throws {
        var runtime = RealtimeRelayRuntimeV1()
        let now = Date(timeIntervalSince1970: 26_000)
        let log = capability()
        let append = capability()
        let read = capability()
        let createLog = SharedLogCreateRequestV1(
            logCapability: log,
            appendCapability: append,
            readCapability: read,
            retentionSeconds: 3_600,
            maxRecords: 8
        )
        _ = try runtime.createSharedLog(createLog, now: now)
        XCTAssertThrowsError(try runtime.createSharedLog(
            SharedLogCreateRequestV1(
                logCapability: log,
                appendCapability: append,
                readCapability: read,
                retentionSeconds: 7_200,
                maxRecords: 8
            ),
            now: now
        )) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .conflict) }

        let blobID = UUID()
        let blobCapability = capability()
        let createBlob = MediaBlobCreateRequestV1(
            blobID: blobID,
            blobCapability: blobCapability,
            chunkCount: 2,
            ttlSeconds: 600
        )
        let first = try runtime.createMediaBlob(createBlob, now: now)
        XCTAssertEqual(
            try runtime.createMediaBlob(createBlob, now: now.addingTimeInterval(30)).expiresAt,
            first.expiresAt
        )
        XCTAssertThrowsError(try runtime.createMediaBlob(
            MediaBlobCreateRequestV1(
                blobID: blobID,
                blobCapability: blobCapability,
                chunkCount: 2,
                ttlSeconds: 601
            ),
            now: now
        )) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .conflict) }
    }

    func testMediaUploadIdempotencyBindsKeyAndChunkCoordinate() throws {
        var runtime = RealtimeRelayRuntimeV1()
        let now = Date(timeIntervalSince1970: 27_000)
        let blobID = UUID()
        let blobCapability = capability()
        _ = try runtime.createMediaBlob(
            MediaBlobCreateRequestV1(
                blobID: blobID,
                blobCapability: blobCapability,
                chunkCount: 2,
                ttlSeconds: 600
            ),
            now: now
        )
        let payload = Data("encrypted-chunk".utf8)
        let key = Data(repeating: 1, count: 32)
        let first = MediaBlobUploadRequestV1(
            blobID: blobID,
            blobCapability: blobCapability,
            chunkIndex: 0,
            payload: payload,
            idempotencyKey: key
        )
        _ = try runtime.uploadMediaBlob(first, now: now)
        XCTAssertEqual(try runtime.uploadMediaBlob(first, now: now).payload, payload)
        XCTAssertThrowsError(try runtime.uploadMediaBlob(
            MediaBlobUploadRequestV1(
                blobID: blobID,
                blobCapability: blobCapability,
                chunkIndex: 1,
                payload: payload,
                idempotencyKey: key
            ),
            now: now
        )) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .conflict) }
        XCTAssertThrowsError(try runtime.uploadMediaBlob(
            MediaBlobUploadRequestV1(
                blobID: blobID,
                blobCapability: blobCapability,
                chunkIndex: 0,
                payload: payload,
                idempotencyKey: Data(repeating: 2, count: 32)
            ),
            now: now
        )) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .conflict) }
        XCTAssertThrowsError(try runtime.fetchMediaBlob(
            MediaBlobFetchRequestV1(
                blobID: blobID,
                blobCapability: blobCapability,
                chunkIndex: 1
            ),
            now: now
        )) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .unavailable) }
    }

    func testRealtimeSubscriptionsAreBoundedPerRoute() throws {
        var runtime = RealtimeRelayRuntimeV1()
        let route = capability()
        let append = capability()
        let read = capability()
        let now = Date(timeIntervalSince1970: 28_000)
        _ = try runtime.createRoute(
            RealtimeRouteCreateRequestV1(
                routeCapability: route,
                appendCapability: append,
                readCapability: read,
                expiresAt: now.addingTimeInterval(3_600)
            ),
            now: now
        )
        for _ in 0..<RealtimeRelayLimitsV1.maximumRealtimeSubscriptionsPerRoute {
            _ = try runtime.subscribe(
                RealtimeRouteSubscribeRequestV1(routeCapability: route, readCapability: read),
                now: now
            )
        }
        XCTAssertThrowsError(try runtime.subscribe(
            RealtimeRouteSubscribeRequestV1(routeCapability: route, readCapability: read),
            now: now
        )) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .capacity) }
    }

    func testDurableRealtimeStateRejectsCorruptionAndReadsLegacyMediaTTL() throws {
        var runtime = RealtimeRelayRuntimeV1()
        let now = Date(timeIntervalSince1970: 28_500)
        _ = try runtime.createRoute(
            RealtimeRouteCreateRequestV1(
                routeCapability: capability(),
                appendCapability: capability(),
                readCapability: capability(),
                expiresAt: now.addingTimeInterval(3_600)
            ),
            now: now
        )
        _ = try runtime.createMediaBlob(
            MediaBlobCreateRequestV1(
                blobID: UUID(),
                blobCapability: capability(),
                chunkCount: 1,
                ttlSeconds: 600
            ),
            now: now
        )
        let encoded = try NoctweaveCoder.encode(runtime.state, sortedKeys: true)
        XCTAssertEqual(
            try NoctweaveCoder.decode(RealtimeRelayRuntimeStateV1.self, from: encoded),
            runtime.state
        )

        var corrupt = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        var routes = try XCTUnwrap(corrupt["routes"] as? [String: Any])
        let routeKey = try XCTUnwrap(routes.keys.first)
        var route = try XCTUnwrap(routes[routeKey] as? [String: Any])
        route["nextSequence"] = 0
        routes[routeKey] = route
        corrupt["routes"] = routes
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            RealtimeRelayRuntimeStateV1.self,
            from: JSONSerialization.data(withJSONObject: corrupt)
        ))

        var legacy = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        var blobs = try XCTUnwrap(legacy["mediaBlobs"] as? [String: Any])
        let blobKey = try XCTUnwrap(blobs.keys.first)
        var blob = try XCTUnwrap(blobs[blobKey] as? [String: Any])
        blob.removeValue(forKey: "ttlSeconds")
        blobs[blobKey] = blob
        legacy["mediaBlobs"] = blobs
        let decodedLegacy = try NoctweaveCoder.decode(
            RealtimeRelayRuntimeStateV1.self,
            from: JSONSerialization.data(withJSONObject: legacy)
        )
        XCTAssertNil(decodedLegacy.mediaBlobs.values.first?.ttlSeconds)
    }

    func testExpiredSharedLogRecordIsNotReturnedAsAnIdempotentRetry() throws {
        var runtime = RealtimeRelayRuntimeV1()
        let now = Date(timeIntervalSince1970: 29_000)
        let log = capability()
        let append = capability()
        let read = capability()
        _ = try runtime.createSharedLog(
            SharedLogCreateRequestV1(
                logCapability: log,
                appendCapability: append,
                readCapability: read,
                retentionSeconds: 60,
                maxRecords: 8
            ),
            now: now
        )
        let request = SharedLogAppendRequestV1(
            logCapability: log,
            appendCapability: append,
            recordID: UUID(),
            payload: Data("opaque".utf8)
        )
        XCTAssertEqual(try runtime.appendSharedLog(request, now: now).sequence, 1)
        XCTAssertEqual(
            try runtime.appendSharedLog(request, now: now.addingTimeInterval(61)).sequence,
            2
        )
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

    func testRealtimeWireRejectsUnknownNestedFields() throws {
        let request = RelayRequest.syncRealtimeRouteV1(
            RealtimeRouteSyncRequestV1(
                routeCapability: capability(),
                subscriptionCapability: capability(),
                afterSequence: 0,
                maxRecords: 16
            )
        )
        let encoded = try NoctweaveCoder.encode(request, sortedKeys: true)
        var envelope = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        var body = try XCTUnwrap(envelope["body"] as? [String: Any])
        var nested = try XCTUnwrap(body["request"] as? [String: Any])
        nested["unexpected"] = true
        body["request"] = nested
        envelope["body"] = body
        let tampered = try JSONSerialization.data(withJSONObject: envelope)
        XCTAssertThrowsError(try NoctweaveCoder.decode(RelayRequest.self, from: tampered))

        let lease = PresenceLeaseV1(
            leaseID: Data(repeating: 1, count: 16),
            payload: Data("opaque".utf8),
            expiresAt: Date(timeIntervalSince1970: 30_000)
        )
        var leaseObject = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: NoctweaveCoder.encode(lease, sortedKeys: true)
            ) as? [String: Any]
        )
        leaseObject["unexpected"] = true
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            PresenceLeaseV1.self,
            from: JSONSerialization.data(withJSONObject: leaseObject)
        ))

        let excessiveTimestamp = PresenceLeaseV1(
            leaseID: Data(repeating: 1, count: 16),
            payload: Data("opaque".utf8),
            expiresAt: Date(timeIntervalSince1970: 9_007_199_254_740_992)
        )
        XCTAssertFalse(excessiveTimestamp.isStructurallyValid)
        XCTAssertThrowsError(try NoctweaveCoder.encode(excessiveTimestamp))
    }

    func testSyncBatchRejectsSequenceGaps() {
        let batch = OpaqueRelaySyncBatchV1(
            records: [
                .init(sequence: 1, recordID: UUID(), payload: Data("one".utf8)),
                .init(sequence: 3, recordID: UUID(), payload: Data("three".utf8)),
            ],
            nextSequence: 3,
            highWatermark: 3,
            retentionFloor: 1,
            hasMore: false
        )
        XCTAssertFalse(batch.isStructurallyValid)

        XCTAssertFalse(OpaqueRelaySyncBatchV1(
            records: [],
            nextSequence: 2,
            highWatermark: 8,
            retentionFloor: 5,
            hasMore: true
        ).isStructurallyValid)
        XCTAssertFalse(OpaqueRelaySyncBatchV1(
            records: [
                .init(sequence: 4, recordID: UUID(), payload: Data("stale".utf8)),
            ],
            nextSequence: 4,
            highWatermark: 8,
            retentionFloor: 5,
            hasMore: true
        ).isStructurallyValid)
    }

    func testSequenceExhaustionReturnsCapacityInsteadOfOverflowing() throws {
        var runtime = RealtimeRelayRuntimeV1()
        let routeCapability = capability()
        let appendCapability = capability()
        let readCapability = capability()
        let now = Date(timeIntervalSince1970: 40_000)
        _ = try runtime.createRoute(.init(
            routeCapability: routeCapability,
            appendCapability: appendCapability,
            readCapability: readCapability,
            expiresAt: now.addingTimeInterval(3_600)
        ), now: now)
        let routeKey = try XCTUnwrap(runtime.state.routes.keys.first)
        let route = try XCTUnwrap(runtime.state.routes[routeKey])
        runtime.state.routes[routeKey] = .init(
            appendDigest: route.appendDigest,
            readDigest: route.readDigest,
            expiresAt: route.expiresAt,
            nextSequence: .max,
            retentionFloor: .max,
            records: [],
            subscriptions: route.subscriptions
        )
        XCTAssertThrowsError(try runtime.appendRoute(.init(
            routeCapability: routeCapability,
            appendCapability: appendCapability,
            recordID: UUID(),
            payload: Data("ciphertext".utf8)
        ), now: now)) {
            XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .capacity)
        }
    }

    func testCollaborationResponsesAreBoundToTheSubmittedOperation() {
        let route = Data(repeating: 1, count: 32)
        let append = Data(repeating: 2, count: 32)
        let read = Data(repeating: 3, count: 32)
        let expiry = Date(timeIntervalSince1970: 30_000)
        let createRequest = RelayRequest.createRealtimeRouteV1(.init(
            routeCapability: route,
            appendCapability: append,
            readCapability: read,
            expiresAt: expiry
        ))
        let substitutedCreate = RelayResponse.success(
            .realtimeRouteCreated(.init(
                routeCapability: Data(repeating: 4, count: 32),
                appendCapability: append,
                readCapability: read,
                expiresAt: expiry
            )),
            respondingTo: createRequest
        )
        XCTAssertFalse(substitutedCreate.isSemanticallyBound(to: createRequest))

        let syncRequest = RelayRequest.syncRealtimeRouteV1(.init(
            routeCapability: route,
            subscriptionCapability: Data(repeating: 5, count: 32),
            afterSequence: 4,
            maxRecords: 2
        ))
        let skippedCursor = RelayResponse.success(
            .realtimeRouteSync(.init(
                records: [.init(sequence: 6, recordID: UUID(), payload: Data("six".utf8))],
                nextSequence: 6,
                highWatermark: 6,
                retentionFloor: 1,
                hasMore: false
            )),
            respondingTo: syncRequest
        )
        XCTAssertFalse(skippedCursor.isSemanticallyBound(to: syncRequest))

        let leaseID = Data(repeating: 6, count: 16)
        let presenceRequest = RelayRequest.acquirePresenceV1(.init(
            scope: Data("scope".utf8),
            scopeCapability: Data(repeating: 7, count: 32),
            leaseID: leaseID,
            leaseCapability: Data(repeating: 8, count: 32),
            payload: Data("expected".utf8),
            ttlSeconds: 30
        ))
        let substitutedLease = RelayResponse.success(
            .presenceLease(.init(
                leaseID: leaseID,
                payload: Data("substituted".utf8),
                expiresAt: expiry
            )),
            respondingTo: presenceRequest
        )
        XCTAssertFalse(substitutedLease.isSemanticallyBound(to: presenceRequest))

        let blobID = UUID()
        let uploadRequest = RelayRequest.uploadMediaBlobV1(.init(
            blobID: blobID,
            blobCapability: Data(repeating: 9, count: 32),
            chunkIndex: 1,
            payload: Data("ciphertext".utf8),
            idempotencyKey: Data(repeating: 10, count: 32)
        ))
        let substitutedChunk = RelayResponse.success(
            .mediaBlobChunk(.init(
                blobID: blobID,
                chunkIndex: 0,
                payload: Data("ciphertext".utf8)
            )),
            respondingTo: uploadRequest
        )
        XCTAssertFalse(substitutedChunk.isSemanticallyBound(to: uploadRequest))
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
