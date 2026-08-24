import XCTest
@testable import NoctweaveRelayServer

final class RealtimeRelayV1Tests: XCTestCase {
    private func capability() -> Data { OpaqueCapabilityV1.generate() }

    func testRealtimeSubscriptionCapabilityIsHashedAtRest() throws {
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
        let subscription = try runtime.subscribe(
            RealtimeRouteSubscribeRequestV1(
                routeCapability: route,
                readCapability: read,
                afterSequence: 0
            ),
            now: now
        )

        let storedSubscriptions = try XCTUnwrap(runtime.state.routes.values.first?.subscriptions)
        XCTAssertEqual(storedSubscriptions.count, 1)
        XCTAssertNil(storedSubscriptions[subscription.subscriptionCapability.base64EncodedString()])
        XCTAssertNoThrow(try runtime.syncRoute(
            RealtimeRouteSyncRequestV1(
                routeCapability: route,
                subscriptionCapability: subscription.subscriptionCapability,
                afterSequence: 0,
                maxRecords: 1
            ),
            now: now
        ))
    }

    func testLinuxWireRoundTripMatchesCoreModuleAndNestedRequestShape() throws {
        let request = RelayRequest.createRealtimeRouteV1(
            RealtimeRouteCreateRequestV1(
                routeCapability: capability(),
                appendCapability: capability(),
                readCapability: capability(),
                expiresAt: Date(timeIntervalSince1970: 40_000)
            )
        )
        let data = try RelayCodec.encoder(sortedKeys: true).encode(request)
        let decoded = try RelayCodec.decoder().decode(RelayRequest.self, from: data)
        XCTAssertEqual(decoded, request)
        XCTAssertTrue(data.contains(Data("nw.realtime-route".utf8)))
        XCTAssertTrue(data.contains(Data("request".utf8)))
    }

    func testLinuxWireRejectsUnknownNestedFields() throws {
        let request = RelayRequest.syncRealtimeRouteV1(
            RealtimeRouteSyncRequestV1(
                routeCapability: capability(),
                subscriptionCapability: capability(),
                afterSequence: 0,
                maxRecords: 16
            )
        )
        let encoded = try RelayCodec.encoder(sortedKeys: true).encode(request)
        var envelope = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        var body = try XCTUnwrap(envelope["body"] as? [String: Any])
        var nested = try XCTUnwrap(body["request"] as? [String: Any])
        nested["unexpected"] = true
        body["request"] = nested
        envelope["body"] = body
        let tampered = try JSONSerialization.data(withJSONObject: envelope)
        XCTAssertThrowsError(try RelayCodec.decoder().decode(RelayRequest.self, from: tampered))

        let lease = PresenceLeaseV1(
            leaseID: Data(repeating: 1, count: 16),
            payload: Data("opaque".utf8),
            expiresAt: Date(timeIntervalSince1970: 30_000)
        )
        var leaseObject = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: RelayCodec.encoder(sortedKeys: true).encode(lease)
            ) as? [String: Any]
        )
        leaseObject["unexpected"] = true
        XCTAssertThrowsError(try RelayCodec.decoder().decode(
            PresenceLeaseV1.self,
            from: JSONSerialization.data(withJSONObject: leaseObject)
        ))

        let excessiveTimestamp = PresenceLeaseV1(
            leaseID: Data(repeating: 1, count: 16),
            payload: Data("opaque".utf8),
            expiresAt: Date(timeIntervalSince1970: 9_007_199_254_740_992)
        )
        XCTAssertFalse(excessiveTimestamp.isStructurallyValid)
        XCTAssertThrowsError(try RelayCodec.encoder().encode(excessiveTimestamp))
    }

    func testSharedLogAndMediaAreOpaqueAndDurableInStoreSurface() throws {
        let store = RelayStore(fileURL: nil)
        let log = capability()
        let append = capability()
        let read = capability()
        _ = try store.createSharedLogV1(
            SharedLogCreateRequestV1(
                logCapability: log,
                appendCapability: append,
                readCapability: read,
                retentionSeconds: 3_600,
                maxRecords: 8
            )
        )
        let recordID = UUID()
        _ = try store.appendSharedLogV1(
            SharedLogAppendRequestV1(
                logCapability: log,
                appendCapability: append,
                recordID: recordID,
                payload: Data("opaque-linux-history".utf8)
            )
        )
        let batch = try store.syncSharedLogV1(
            SharedLogSyncRequestV1(logCapability: log, readCapability: read, afterSequence: 0, maxRecords: 8)
        )
        XCTAssertEqual(batch.records.map { $0.recordID }, [recordID])

        let blobID = UUID()
        let blobCapability = capability()
        _ = try store.createMediaBlobV1(
            MediaBlobCreateRequestV1(blobID: blobID, blobCapability: blobCapability, chunkCount: 1, ttlSeconds: 600)
        )
        _ = try store.uploadMediaBlobV1(
            MediaBlobUploadRequestV1(
                blobID: blobID,
                blobCapability: blobCapability,
                chunkIndex: 0,
                payload: Data("encrypted-channel-media".utf8),
                idempotencyKey: Data(repeating: 4, count: 32)
            )
        )
        XCTAssertEqual(
            try store.fetchMediaBlobV1(MediaBlobFetchRequestV1(blobID: blobID, blobCapability: blobCapability, chunkIndex: 0)).payload,
            Data("encrypted-channel-media".utf8)
        )
    }

    func testPresenceRejectsWrongScopeCapabilityAndIsNotAStoreHistoryModule() throws {
        let store = RelayStore(fileURL: nil)
        let scope = Data("voice-call".utf8)
        let scopeCapability = capability()
        let leaseCapability = capability()
        let request = PresenceLeaseAcquireRequestV1(
            scope: scope,
            scopeCapability: scopeCapability,
            leaseID: Data(repeating: 8, count: 16),
            leaseCapability: leaseCapability,
            payload: Data("opaque-presence".utf8),
            ttlSeconds: 30
        )
        _ = try store.acquirePresenceV1(request)
        XCTAssertEqual(try store.listPresenceV1(PresenceLeaseListRequestV1(scope: scope, scopeCapability: scopeCapability)).count, 1)
        XCTAssertEqual(try store.listPresenceV1(PresenceLeaseListRequestV1(scope: scope, scopeCapability: capability())).count, 0)
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
            RealtimeRouteSubscribeRequestV1(
                routeCapability: route,
                readCapability: read,
                afterSequence: 0
            ),
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
        let create = MediaBlobCreateRequestV1(
            blobID: blobID,
            blobCapability: blobCapability,
            chunkCount: 2,
            ttlSeconds: 600
        )
        let first = try runtime.createMediaBlob(create, now: now)
        XCTAssertEqual(
            try runtime.createMediaBlob(create, now: now.addingTimeInterval(30)).expiresAt,
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
                RealtimeRouteSubscribeRequestV1(
                    routeCapability: route,
                    readCapability: read,
                    afterSequence: 0
                ),
                now: now
            )
        }
        XCTAssertThrowsError(try runtime.subscribe(
            RealtimeRouteSubscribeRequestV1(
                routeCapability: route,
                readCapability: read,
                afterSequence: 0
            ),
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
        let encoded = try RelayCodec.encoder(sortedKeys: true).encode(runtime.state)
        XCTAssertEqual(
            try RelayCodec.decoder().decode(RealtimeRelayRuntimeStateV1.self, from: encoded),
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
        XCTAssertThrowsError(try RelayCodec.decoder().decode(
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
        let decodedLegacy = try RelayCodec.decoder().decode(
            RealtimeRelayRuntimeStateV1.self,
            from: JSONSerialization.data(withJSONObject: legacy)
        )
        XCTAssertNil(decodedLegacy.mediaBlobs.values.first?.ttlSeconds)
    }

    func testStandardCapabilitiesAdvertiseOnlyImplementedCollaborationModules() throws {
        let info = RelayConfiguration().makeInfo()
        let manifest = try XCTUnwrap(info.protocolCapabilities)
        for module in ["nw.realtime-route", "nw.shared-log", "nw.ephemeral-presence", "nw.media-blobs"] {
            XCTAssertTrue(manifest.supports(module: module, version: 1), module)
        }
        let passthrough = RelayCapabilityManifestV2.advertised(
            relayKind: .passthrough,
            attachmentsEnabled: true,
            hiddenRetrievalEnabled: false,
            onionEnabled: false,
            mixnetEnabled: false
        )
        XCTAssertFalse(passthrough.supports(module: "nw.realtime-route", version: 1))
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

    func testEachRealtimeCapabilityCanBeDisabledIndependently() throws {
        let manifest = try XCTUnwrap(
            RelayConfiguration(
                realtimeRoutesEnabled: false,
                sharedLogsEnabled: false,
                ephemeralPresenceEnabled: false,
                mediaBlobsEnabled: false
            ).makeInfo().protocolCapabilities
        )
        for module in ["nw.realtime-route", "nw.shared-log", "nw.ephemeral-presence", "nw.media-blobs"] {
            XCTAssertFalse(manifest.supports(module: module, version: 1), module)
        }
        XCTAssertTrue(manifest.supports(module: "nw.opaque-route", version: 2))
    }
}
