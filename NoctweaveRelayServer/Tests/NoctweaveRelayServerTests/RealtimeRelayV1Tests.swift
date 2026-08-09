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
