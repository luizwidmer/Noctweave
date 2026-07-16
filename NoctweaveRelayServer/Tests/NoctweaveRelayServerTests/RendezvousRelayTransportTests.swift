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
        XCTAssertEqual(
            try disabled.send(.registerRendezvousTransportV2(fixture.registration)).error,
            "Rendezvous transport is disabled"
        )

        let enabled = try RendezvousRelayTCPHarness(enabled: true)
        defer { try? enabled.shutdown() }
        XCTAssertEqual(
            try enabled.send(.registerRendezvousTransportV2(fixture.registration)).type,
            .ok
        )
        let first = frame(marker: 0x11, sequence: 1)
        XCTAssertEqual(
            try enabled.send(
                .appendRendezvousTransportV2(
                    AppendRendezvousTransportV2Request(
                        routeCapability: fixture.route,
                        laneId: fixture.lanes[0].laneId,
                        publishCapability: fixture.lanes[0].publishCapability,
                        frame: first
                    )
                )
            ).type,
            .ok
        )
        let synced = try enabled.send(
            .syncRendezvousTransportV2(
                SyncRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    laneId: fixture.lanes[0].laneId,
                    readCapability: fixture.lanes[0].readCapability
                )
            )
        )
        XCTAssertEqual(synced.rendezvousSyncV2?.frames, [first])
    }

    func testWireShapeBoundsAndCapabilityAdvertisementMirrorCore() throws {
        let now = canonical(2_000_000_000)
        let fixture = makeFixture(now: now)
        let encoded = try RelayCodec.encoder().encode(fixture.registration)
        let json = try XCTUnwrap(String(data: encoded, encoding: .utf8)?.lowercased())
        for forbidden in ["purpose", "generation", "identity", "endpoint", "inbox", "provider", "contact"] {
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
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
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
        let store = RelayStore(fileURL: storeURL, maxInboxMessages: nil, temporalBucketSeconds: 0)
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

        let reloaded = RelayStore(fileURL: storeURL, maxInboxMessages: nil, temporalBucketSeconds: 0)
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

        let tombstoneReload = RelayStore(fileURL: storeURL, maxInboxMessages: nil, temporalBucketSeconds: 0)
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
}

private final class RendezvousRelayTCPHarness {
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let host = "127.0.0.1"
    private let port: Int

    init(enabled: Bool) throws {
        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let configuration = RelayConfiguration(
            tlsEnabled: false,
            compatibilityProfiles: [],
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
            promise.succeed(try RelayCodec.decoder().decode(RelayResponse.self, from: bytes))
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
