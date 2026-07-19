import Foundation
import XCTest
@preconcurrency import NIOCore
@preconcurrency import NIOFoundationCompat
@preconcurrency import NIOPosix
@testable import NoctweaveRelayServer

final class RendezvousRelayTransportTests: XCTestCase {
    func testHandlerIsDefaultOffAndAllowsExplicitLoopbackDevelopment() throws {
        let now = canonical(Date().timeIntervalSince1970)
        let fixture = makeFixture(now: now)
        let disabled = try RendezvousRelayTCPHarness(enabled: false)
        defer { try? disabled.shutdown() }
        let disabledResponse = try disabled.send(.registerRendezvousTransportV2(fixture.registration))
        XCTAssertEqual(disabledResponse.status, .error)
        XCTAssertEqual(disabledResponse.error?.message, "Rendezvous transport is disabled")

        let enabled = try RendezvousRelayTCPHarness(enabled: true)
        defer { try? enabled.shutdown() }
        let registrationResponse = try enabled.send(.registerRendezvousTransportV2(fixture.registration))
        guard case .empty? = registrationResponse.successBody else {
            return XCTFail("Expected rendezvous registration success")
        }
        let first = frame(marker: 0x11, sequence: 1)
        let appendResponse = try enabled.send(
                .appendRendezvousTransportV2(
                    AppendRendezvousTransportV2Request(
                        routeCapability: fixture.route,
                        laneId: fixture.lanes[0].laneId,
                        publishCapability: fixture.lanes[0].publishCapability,
                        frame: first
                    )
                )
            )
        guard case .empty? = appendResponse.successBody else {
            return XCTFail("Expected rendezvous append success")
        }
        let synced = try enabled.send(
            .syncRendezvousTransportV2(
                SyncRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    laneId: fixture.lanes[0].laneId,
                    readCapability: fixture.lanes[0].readCapability
                )
            )
        )
        guard case .rendezvousSync(let batch)? = synced.successBody else {
            return XCTFail("Expected rendezvous sync response")
        }
        XCTAssertEqual(batch.frames, [first])
    }

    func testWireShapeBoundsAndCapabilityAdvertisementMirrorCore() throws {
        let now = canonical(2_000_000_000)
        let fixture = makeFixture(now: now)
        let encoded = try RelayCodec.encoder().encode(fixture.registration)
        let json = try XCTUnwrap(String(data: encoded, encoding: .utf8)?.lowercased())
        for forbidden in ["purpose", "generation", "identity", "endpoint", "provider", "contact"] {
            XCTAssertFalse(json.contains(forbidden), "relay registration leaked \(forbidden)")
        }
        XCTAssertFalse(RelayConfiguration().isRendezvousTransportEnabled)
        XCTAssertFalse(
            try XCTUnwrap(RelayConfiguration().makeInfo().protocolCapabilities)
                .supports(module: "nw.rendezvous-transport", version: 2)
        )
        XCTAssertTrue(
            try XCTUnwrap(
                RelayConfiguration(rendezvousTransportEnabled: true)
                    .makeInfo()
                    .protocolCapabilities
            ).supports(module: "nw.rendezvous-transport", version: 2)
        )
        XCTAssertFalse(
            RegisterRendezvousTransportV2Request(
                routeCapability: fixture.route,
                expiresAt: now.addingTimeInterval(601),
                lanes: fixture.lanes
            ).isStructurallyValid(at: now)
        )
        XCTAssertFalse(
            RendezvousRelayCiphertextFrameV2(
                frameId: frameID(),
                sequence: 1,
                ciphertext: Data(repeating: 0x20, count: 8_192)
            ).isStructurallyValid
        )

        XCTAssertFalse(ServerConfig.parse(arguments: [], environment: [:]).rendezvousTransportEnabled)
        XCTAssertTrue(
            ServerConfig.parse(
                arguments: [],
                environment: ["NOCTWEAVE_RENDEZVOUS_TRANSPORT": "true"]
            ).rendezvousTransportEnabled
        )
        XCTAssertTrue(
            ServerConfig.parse(
                arguments: ["--rendezvous-transport", "true"],
                environment: [:]
            ).rendezvousTransportEnabled
        )
    }

    func testAuthoritySeparationSequenceAndExactIdempotenceMirrorCore() throws {
        let now = canonical(2_000_000_000)
        let fixture = makeFixture(now: now)
        let store = RelayStore(fileURL: nil, temporalBucketSeconds: 0)
        try store.registerRendezvousTransportV2(fixture.registration, now: now)
        let first = frame(marker: 0x31, sequence: 1)
        let append = AppendRendezvousTransportV2Request(
            routeCapability: fixture.route,
            laneId: fixture.lanes[0].laneId,
            publishCapability: fixture.lanes[0].publishCapability,
            frame: first
        )
        XCTAssertEqual(try store.appendRendezvousTransportV2(append, now: now), 1)
        XCTAssertEqual(try store.appendRendezvousTransportV2(append, now: now), 1)
        let batch = try store.syncRendezvousTransportV2(
            SyncRendezvousTransportV2Request(
                routeCapability: fixture.route,
                laneId: fixture.lanes[0].laneId,
                readCapability: fixture.lanes[0].readCapability
            ),
            now: now
        )
        XCTAssertEqual(batch.frames, [first])
        XCTAssertEqual(batch.highWatermark, 1)

        XCTAssertThrowsError(
            try store.syncRendezvousTransportV2(
                SyncRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    laneId: fixture.lanes[0].laneId,
                    readCapability: fixture.lanes[1].readCapability
                ),
                now: now
            )
        ) { XCTAssertEqual($0 as? RelayStoreError, .rendezvousRouteUnavailable) }
        XCTAssertThrowsError(
            try store.appendRendezvousTransportV2(
                AppendRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    laneId: fixture.lanes[0].laneId,
                    publishCapability: fixture.lanes[0].publishCapability,
                    frame: self.frame(marker: 0x32, sequence: 3)
                ),
                now: now
            )
        ) { XCTAssertEqual($0 as? RelayStoreError, .rendezvousSequenceGap) }
        XCTAssertThrowsError(
            try store.appendRendezvousTransportV2(
                AppendRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    laneId: fixture.lanes[0].laneId,
                    publishCapability: fixture.lanes[0].publishCapability,
                    frame: RendezvousRelayCiphertextFrameV2(
                        frameId: first.frameId,
                        sequence: 1,
                        ciphertext: Data(repeating: 0x33, count: 4_096)
                    )
                ),
                now: now
            )
        ) { XCTAssertEqual($0 as? RelayStoreError, .rendezvousFrameConflict) }
    }

    func testReplayDeletionExpiryAndTombstonesSurviveRestart() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-rendezvous-linux-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("relay.sqlite")
        let now = canonical(2_000_000_000)
        let fixture = makeFixture(now: now, lifetime: 20)
        let first = frame(marker: 0x41, sequence: 1)
        let append = AppendRendezvousTransportV2Request(
            routeCapability: fixture.route,
            laneId: fixture.lanes[1].laneId,
            publishCapability: fixture.lanes[1].publishCapability,
            frame: first
        )
        let store = RelayStore(fileURL: storeURL, temporalBucketSeconds: 0)
        try store.registerRendezvousTransportV2(fixture.registration, now: now)
        _ = try store.appendRendezvousTransportV2(append, now: now)
        try store.deleteRendezvousTransportV2(
            DeleteRendezvousTransportV2Request(
                routeCapability: fixture.route,
                laneId: fixture.lanes[0].laneId,
                deleteCapability: fixture.lanes[0].deleteCapability
            ),
            now: now
        )

        let sqlite = try Data(contentsOf: storeURL)
        let rawBearers = [fixture.route.rawValue] + fixture.lanes.flatMap {
            [
                $0.publishCapability.rawValue,
                $0.readCapability.rawValue,
                $0.deleteCapability.rawValue
            ]
        }
        for bearer in rawBearers {
            XCTAssertNil(sqlite.range(of: bearer), "raw rendezvous bearer was persisted")
        }

        let reloaded = RelayStore(fileURL: storeURL, temporalBucketSeconds: 0)
        try reloaded.load()
        try reloaded.registerRendezvousTransportV2(fixture.registration, now: now)
        XCTAssertThrowsError(
            try reloaded.registerRendezvousTransportV2(
                RegisterRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    expiresAt: fixture.registration.expiresAt.addingTimeInterval(1),
                    lanes: fixture.lanes
                ),
                now: now
            )
        ) { XCTAssertEqual($0 as? RelayStoreError, .rendezvousRegistrationConflict) }
        XCTAssertEqual(try reloaded.appendRendezvousTransportV2(append, now: now), 1)
        XCTAssertThrowsError(
            try reloaded.syncRendezvousTransportV2(
                SyncRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    laneId: fixture.lanes[0].laneId,
                    readCapability: fixture.lanes[0].readCapability
                ),
                now: now
            )
        ) { XCTAssertEqual($0 as? RelayStoreError, .rendezvousRouteUnavailable) }

        // Expiration turns the active route into a permanent tombstone.
        XCTAssertThrowsError(
            try reloaded.syncRendezvousTransportV2(
                SyncRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    laneId: fixture.lanes[1].laneId,
                    readCapability: fixture.lanes[1].readCapability
                ),
                now: now.addingTimeInterval(20)
            )
        ) { XCTAssertEqual($0 as? RelayStoreError, .rendezvousRouteUnavailable) }

        let tombstoneReload = RelayStore(fileURL: storeURL, temporalBucketSeconds: 0)
        try tombstoneReload.load()
        XCTAssertThrowsError(
            try tombstoneReload.registerRendezvousTransportV2(
                RegisterRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    expiresAt: now.addingTimeInterval(300),
                    lanes: fixture.lanes
                ),
                now: now.addingTimeInterval(30)
            )
        ) { XCTAssertEqual($0 as? RelayStoreError, .rendezvousRouteUnavailable) }
    }

    func testEveryRendezvousWireObjectRejectsUnknownFields() throws {
        let now = canonical(2_000_000_000)
        let fixture = makeFixture(now: now)
        let sampleFrame = frame(marker: 0x51, sequence: 1)
        let append = AppendRendezvousTransportV2Request(
            routeCapability: fixture.route,
            laneId: fixture.lanes[0].laneId,
            publishCapability: fixture.lanes[0].publishCapability,
            frame: sampleFrame
        )
        let sync = SyncRendezvousTransportV2Request(
            routeCapability: fixture.route,
            laneId: fixture.lanes[0].laneId,
            readCapability: fixture.lanes[0].readCapability
        )
        let delete = DeleteRendezvousTransportV2Request(
            routeCapability: fixture.route,
            laneId: fixture.lanes[0].laneId,
            deleteCapability: fixture.lanes[0].deleteCapability
        )
        let batch = RendezvousRelaySyncBatchV2(
            frames: [sampleFrame],
            highWatermark: 1,
            nextSequence: 1,
            hasMore: false
        )

        try assertRejectsUnknownField(fixture.route)
        try assertRejectsUnknownField(fixture.lanes[0].publishCapability)
        try assertRejectsUnknownField(fixture.lanes[0].readCapability)
        try assertRejectsUnknownField(fixture.lanes[0].deleteCapability)
        try assertRejectsUnknownField(fixture.lanes[0].laneId)
        try assertRejectsUnknownField(sampleFrame.frameId)
        try assertRejectsUnknownField(fixture.lanes[0])
        try assertRejectsUnknownField(fixture.registration)
        try assertRejectsUnknownField(sampleFrame)
        try assertRejectsUnknownField(append)
        try assertRejectsUnknownField(sync)
        try assertRejectsUnknownField(delete)
        try assertRejectsUnknownField(batch)

        var registrationObject = try jsonObject(fixture.registration)
        var lanes = try XCTUnwrap(registrationObject["lanes"] as? [[String: Any]])
        var lane = lanes[0]
        var readCapability = try XCTUnwrap(lane["readCapability"] as? [String: Any])
        readCapability["identity"] = "must-not-be-accepted"
        lane["readCapability"] = readCapability
        lanes[0] = lane
        registrationObject["lanes"] = lanes
        XCTAssertThrowsError(
            try decode(RegisterRendezvousTransportV2Request.self, from: registrationObject)
        )

        var appendObject = try jsonObject(append)
        var nestedFrame = try XCTUnwrap(appendObject["frame"] as? [String: Any])
        nestedFrame["provider"] = "must-not-be-accepted"
        appendObject["frame"] = nestedFrame
        XCTAssertThrowsError(
            try decode(AppendRendezvousTransportV2Request.self, from: appendObject)
        )
    }

    func testRendezvousWireRequiresEveryFieldIncludingExplicitNullMaxCount() throws {
        let now = canonical(2_000_000_000)
        let fixture = makeFixture(now: now)
        let sync = SyncRendezvousTransportV2Request(
            routeCapability: fixture.route,
            laneId: fixture.lanes[0].laneId,
            readCapability: fixture.lanes[0].readCapability,
            maxCount: nil
        )
        var syncObject = try jsonObject(sync)
        XCTAssertTrue(syncObject.keys.contains("maxCount"))
        XCTAssertTrue(syncObject["maxCount"] is NSNull)
        syncObject.removeValue(forKey: "maxCount")
        XCTAssertThrowsError(try decode(SyncRendezvousTransportV2Request.self, from: syncObject))

        var capabilityObject = try jsonObject(fixture.route)
        capabilityObject.removeValue(forKey: "rawValue")
        XCTAssertThrowsError(try decode(RendezvousRelayRouteCapabilityV2.self, from: capabilityObject))

        var laneObject = try jsonObject(fixture.lanes[0])
        laneObject.removeValue(forKey: "deleteCapability")
        XCTAssertThrowsError(try decode(RendezvousRelayLaneRegistrationV2.self, from: laneObject))

        var registrationObject = try jsonObject(fixture.registration)
        registrationObject.removeValue(forKey: "version")
        XCTAssertThrowsError(
            try decode(RegisterRendezvousTransportV2Request.self, from: registrationObject)
        )

        let sampleFrame = frame(marker: 0x52, sequence: 1)
        var batchObject = try jsonObject(
            RendezvousRelaySyncBatchV2(
                frames: [sampleFrame],
                highWatermark: 1,
                nextSequence: 1,
                hasMore: false
            )
        )
        batchObject.removeValue(forKey: "hasMore")
        XCTAssertThrowsError(try decode(RendezvousRelaySyncBatchV2.self, from: batchObject))
    }

    func testRendezvousWireRejectsInvalidValuesOnDecodeAndEncode() throws {
        let now = canonical(2_000_000_000)
        let fixture = makeFixture(now: now)

        XCTAssertThrowsError(
            try RelayCodec.encoder().encode(
                RendezvousRelayRouteCapabilityV2(rawValue: Data(repeating: 0, count: 32))
            )
        )
        XCTAssertThrowsError(
            try RelayCodec.encoder().encode(
                RendezvousRelayPublishCapabilityV2(rawValue: Data(repeating: 1, count: 31))
            )
        )
        XCTAssertThrowsError(
            try RelayCodec.encoder().encode(
                RendezvousRelayReadCapabilityV2(rawValue: Data())
            )
        )
        XCTAssertThrowsError(
            try RelayCodec.encoder().encode(
                RendezvousRelayDeleteCapabilityV2(rawValue: Data(repeating: 2, count: 33))
            )
        )
        XCTAssertThrowsError(
            try RelayCodec.encoder().encode(
                RendezvousRelayLaneIDV2(rawValue: Data(repeating: 0, count: 32))
            )
        )
        XCTAssertThrowsError(
            try RelayCodec.encoder().encode(
                RendezvousRelayFrameIDV2(rawValue: Data(repeating: 3, count: 15))
            )
        )
        try assertRejectsInvalidOpaqueValue(
            fixture.route,
            invalidValue: Data(repeating: 0, count: 32)
        )
        try assertRejectsInvalidOpaqueValue(
            fixture.lanes[0].publishCapability,
            invalidValue: Data(repeating: 1, count: 31)
        )
        try assertRejectsInvalidOpaqueValue(
            fixture.lanes[0].readCapability,
            invalidValue: Data()
        )
        try assertRejectsInvalidOpaqueValue(
            fixture.lanes[0].deleteCapability,
            invalidValue: Data(repeating: 2, count: 33)
        )
        try assertRejectsInvalidOpaqueValue(
            fixture.lanes[0].laneId,
            invalidValue: Data(repeating: 0, count: 32)
        )
        try assertRejectsInvalidOpaqueValue(
            frameID(),
            invalidValue: Data(repeating: 3, count: 15)
        )

        var registrationObject = try jsonObject(fixture.registration)
        registrationObject["version"] = 3
        XCTAssertThrowsError(
            try decode(RegisterRendezvousTransportV2Request.self, from: registrationObject)
        )
        XCTAssertThrowsError(
            try RelayCodec.encoder().encode(
                RegisterRendezvousTransportV2Request(
                    version: 3,
                    routeCapability: fixture.route,
                    expiresAt: fixture.registration.expiresAt,
                    lanes: fixture.lanes
                )
            )
        )

        let sampleFrame = frame(marker: 0x53, sequence: 1)
        var frameObject = try jsonObject(sampleFrame)
        frameObject["sequence"] = 0
        XCTAssertThrowsError(try decode(RendezvousRelayCiphertextFrameV2.self, from: frameObject))
        XCTAssertThrowsError(
            try RelayCodec.encoder().encode(
                RendezvousRelayCiphertextFrameV2(
                    frameId: sampleFrame.frameId,
                    sequence: 0,
                    ciphertext: sampleFrame.ciphertext
                )
            )
        )

        let sync = SyncRendezvousTransportV2Request(
            routeCapability: fixture.route,
            laneId: fixture.lanes[0].laneId,
            readCapability: fixture.lanes[0].readCapability,
            maxCount: 1
        )
        var syncObject = try jsonObject(sync)
        syncObject["maxCount"] = 0
        XCTAssertThrowsError(try decode(SyncRendezvousTransportV2Request.self, from: syncObject))
        XCTAssertThrowsError(
            try RelayCodec.encoder().encode(
                SyncRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    laneId: fixture.lanes[0].laneId,
                    readCapability: fixture.lanes[0].readCapability,
                    maxCount: 0
                )
            )
        )

        let batch = RendezvousRelaySyncBatchV2(
            frames: [sampleFrame],
            highWatermark: 1,
            nextSequence: 1,
            hasMore: false
        )
        var batchObject = try jsonObject(batch)
        batchObject["hasMore"] = true
        XCTAssertThrowsError(try decode(RendezvousRelaySyncBatchV2.self, from: batchObject))
        XCTAssertThrowsError(
            try RelayCodec.encoder().encode(
                RendezvousRelaySyncBatchV2(
                    frames: [sampleFrame],
                    highWatermark: 1,
                    nextSequence: 1,
                    hasMore: true
                )
            )
        )
    }

    private func canonical(_ seconds: TimeInterval) -> Date {
        Date(timeIntervalSince1970: floor(seconds))
    }

    private func randomData(count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) })
    }

    private func makeFixture(
        now: Date,
        lifetime: TimeInterval = 300
    ) -> (
        route: RendezvousRelayRouteCapabilityV2,
        lanes: [RendezvousRelayLaneRegistrationV2],
        registration: RegisterRendezvousTransportV2Request
    ) {
        let route = RendezvousRelayRouteCapabilityV2(rawValue: randomData(count: 32))
        let lanes = (0..<2).map { _ in
            RendezvousRelayLaneRegistrationV2(
                laneId: RendezvousRelayLaneIDV2(rawValue: randomData(count: 32)),
                publishCapability: RendezvousRelayPublishCapabilityV2(rawValue: randomData(count: 32)),
                readCapability: RendezvousRelayReadCapabilityV2(rawValue: randomData(count: 32)),
                deleteCapability: RendezvousRelayDeleteCapabilityV2(rawValue: randomData(count: 32))
            )
        }
        return (
            route,
            lanes,
            RegisterRendezvousTransportV2Request(
                routeCapability: route,
                expiresAt: now.addingTimeInterval(lifetime),
                lanes: lanes
            )
        )
    }

    private func frameID() -> RendezvousRelayFrameIDV2 {
        RendezvousRelayFrameIDV2(rawValue: randomData(count: 16))
    }

    private func frame(marker: UInt8, sequence: UInt64) -> RendezvousRelayCiphertextFrameV2 {
        RendezvousRelayCiphertextFrameV2(
            frameId: frameID(),
            sequence: sequence,
            ciphertext: Data(repeating: marker, count: 4_096)
        )
    }

    private func jsonObject<T: Encodable>(_ value: T) throws -> [String: Any] {
        let data = try RelayCodec.encoder().encode(value)
        return try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
    }

    private func decode<T: Decodable>(
        _ type: T.Type,
        from object: [String: Any]
    ) throws -> T {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        return try RelayCodec.decoder().decode(type, from: data)
    }

    private func assertRejectsUnknownField<T: Codable>(
        _ value: T,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        var object = try jsonObject(value)
        object["unexpected"] = true
        XCTAssertThrowsError(
            try decode(T.self, from: object),
            file: file,
            line: line
        )
    }

    private func assertRejectsInvalidOpaqueValue<T: Codable>(
        _ value: T,
        invalidValue: Data,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        var object = try jsonObject(value)
        object["rawValue"] = invalidValue.base64EncodedString()
        XCTAssertThrowsError(
            try decode(T.self, from: object),
            file: file,
            line: line
        )
    }
}

private final class RendezvousRelayTCPHarness {
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let host = "127.0.0.1"
    private let port: Int

    init(enabled: Bool) throws {
        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let store = RelayStore(fileURL: nil, temporalBucketSeconds: 0)
        let configuration = RelayConfiguration(
            tlsEnabled: false,
            rendezvousTransportEnabled: enabled
        )
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 16)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(LineFrameHandler(maxLength: 512 * 1_024)).flatMap {
                    channel.pipeline.addHandler(
                        RelayHandler(
                            store: store,
                            maxMessageBytes: 512 * 1_024,
                            maxLineBytes: 640 * 1_024,
                            localEndpoint: RelayEndpoint(host: "127.0.0.1", port: 0),
                            relayConfiguration: configuration,
                            forwardingRequestTimeoutSeconds: 2
                        )
                    )
                }
            }
            .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
        do {
            channel = try bootstrap.bind(host: host, port: 0).wait()
        } catch {
            try? group.syncShutdownGracefully()
            throw error
        }
        guard let boundPort = channel.localAddress?.port else {
            try? channel.close().wait()
            try? group.syncShutdownGracefully()
            throw NSError(domain: "RendezvousRelayTCPHarness", code: 1)
        }
        port = boundPort
    }

    func shutdown() throws {
        try? channel.close().wait()
        try group.syncShutdownGracefully()
    }

    func send(_ request: RelayRequest) throws -> RelayResponse {
        let promise = group.next().makePromise(of: RelayResponse.self)
        let requestData = try RelayCodec.encoder().encode(request)
        let bootstrap = ClientBootstrap(group: group).channelInitializer { channel in
            channel.pipeline.addHandler(LineFrameHandler(maxLength: 640 * 1_024)).flatMap {
                channel.pipeline.addHandler(
                    RendezvousRelayResponseHandler(
                        requestData: requestData,
                        promise: promise
                    )
                )
            }
        }
        let client = try bootstrap.connect(host: host, port: port).wait()
        let response = try promise.futureResult.wait()
        try? client.close().wait()
        return response
    }
}

private final class RendezvousRelayResponseHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let requestData: Data
    private let promise: EventLoopPromise<RelayResponse>
    private var resolved = false

    init(requestData: Data, promise: EventLoopPromise<RelayResponse>) {
        self.requestData = requestData
        self.promise = promise
    }

    func channelActive(context: ChannelHandlerContext) {
        var buffer = context.channel.allocator.buffer(capacity: requestData.count + 1)
        LineEncoder.wrap(requestData, into: &buffer)
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !resolved else { return }
        var buffer = unwrapInboundIn(data)
        guard let bytes = buffer.readData(length: buffer.readableBytes) else {
            fail(NSError(domain: "RendezvousRelayResponseHandler", code: 2), context: context)
            return
        }
        do {
            resolved = true
            promise.succeed(try RelayCodec.decodeWire(RelayResponse.self, from: bytes))
            context.close(promise: nil)
        } catch {
            fail(error, context: context)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        fail(error, context: context)
    }

    private func fail(_ error: Error, context: ChannelHandlerContext) {
        guard !resolved else { return }
        resolved = true
        promise.fail(error)
        context.close(promise: nil)
    }
}
