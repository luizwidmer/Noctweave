import Foundation
import XCTest
@preconcurrency import NIOCore
@preconcurrency import NIOFoundationCompat
@preconcurrency import NIOPosix
@testable import NoctweaveRelayServer

final class OpaqueRouteRelayIntegrationTests: XCTestCase {
    func testStableOpaqueRuntimeIsTheOnlyDirectDeliveryWireSurface() throws {
        let harness = try OpaqueRouteRelayTCPHarness(enabled: true)
        defer { try? harness.shutdown() }
        let now = Date()
        let response = try harness.send(
            .createOpaqueRouteV2(try OpaqueRouteIntegrationFixture().create(at: now))
        )
        guard case .opaqueRoute? = response.successBody else {
            return XCTFail("Expected opaque route create response")
        }

        XCTAssertThrowsError(
            try harness.sendRaw(Data(#"{"type":"notAProtocolOperation"}"#.utf8))
        )
    }

    func testRuntimeCanBeExplicitlyDisabledByStableOperatorSetting() throws {
        let harness = try OpaqueRouteRelayTCPHarness(enabled: false)
        defer { try? harness.shutdown() }
        let response = try harness.send(
            .createOpaqueRouteV2(try OpaqueRouteIntegrationFixture().create(at: Date()))
        )
        XCTAssertEqual(response.status, .error)
        XCTAssertEqual(response.error?.message, "Opaque route runtime is disabled")
    }
}

private struct OpaqueRouteIntegrationFixture {
    private let routeID = OpaqueReceiveRouteIDV2(rawValue: Data(repeating: 0x51, count: 32))
    private let send = RouteSendCapabilityV2(rawValue: Data(repeating: 0x61, count: 32))
    private let read = RouteReadCredentialV2(rawValue: Data(repeating: 0x62, count: 32))
    private let renew = RouteRenewCapabilityV2(rawValue: Data(repeating: 0x63, count: 32))
    private let teardown = RouteTeardownCapabilityV2(rawValue: Data(repeating: 0x64, count: 32))

    func create(at date: Date) throws -> OpaqueRouteCreateSubmissionV2 {
        let lease = OpaqueRouteLeaseV2(
            issuedAt: date,
            expiresAt: date.addingTimeInterval(3_600),
            policy: OpaqueRoutePolicyV2(
                paddingBucket: .bytes4096,
                retentionBucket: .oneHour,
                quotaBucket: .packets64
            )
        )
        let placeholder = OpaqueRouteAuthorizationProofV2(
            authority: .renew,
            nonce: OpaqueRouteProofNonceV2(rawValue: Data(repeating: 0x71, count: 32)),
            operationDigest: Data(repeating: 0, count: 32),
            authorizedAt: date,
            mac: Data(repeating: 0, count: 32)
        )
        let provisional = OpaqueRouteCreateRequestV2(
            version: 2,
            routeID: routeID,
            sendCapabilityDigest: opaqueRouteCredentialDigest(.send, send.rawValue),
            readCredentialDigest: opaqueRouteCredentialDigest(.read, read.rawValue),
            renewCapabilityDigest: opaqueRouteCredentialDigest(.renew, renew.rawValue),
            teardownCapabilityDigest: opaqueRouteCredentialDigest(.teardown, teardown.rawValue),
            lease: lease,
            idempotencyKey: OpaqueRouteIdempotencyKeyV2(
                rawValue: Data(repeating: 0x72, count: 32)
            ),
            authorization: placeholder
        )
        guard let transitionDigest = provisional.transitionDigest else {
            throw NSError(domain: "OpaqueRouteIntegrationFixture", code: 1)
        }
        let request = OpaqueRouteCreateRequestV2(
            version: provisional.version,
            routeID: provisional.routeID,
            sendCapabilityDigest: provisional.sendCapabilityDigest,
            readCredentialDigest: provisional.readCredentialDigest,
            renewCapabilityDigest: provisional.renewCapabilityDigest,
            teardownCapabilityDigest: provisional.teardownCapabilityDigest,
            lease: provisional.lease,
            idempotencyKey: provisional.idempotencyKey,
            authorization: try OpaqueRouteAuthorizationProofV2.make(
                authority: .renew,
                routeID: routeID,
                operationDigest: transitionDigest,
                authorizedAt: date,
                nonce: placeholder.nonce,
                secret: renew.rawValue
            )
        )
        return OpaqueRouteCreateSubmissionV2(request: request, renewCapability: renew)
    }
}

private final class OpaqueRouteRelayTCPHarness {
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let host = "127.0.0.1"
    private let port: Int

    init(enabled: Bool) throws {
        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let configuration = RelayConfiguration(
            tlsEnabled: false,
            opaqueRouteRuntimeEnabled: enabled
        )
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 16)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(LineFrameHandler(maxLength: 640 * 1_024)).flatMap {
                    channel.pipeline.addHandler(
                        RelayHandler(
                            store: RelayStore(fileURL: nil, temporalBucketSeconds: 0),
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
            throw NSError(domain: "OpaqueRouteRelayTCPHarness", code: 1)
        }
        port = boundPort
    }

    func shutdown() throws {
        try? channel.close().wait()
        try group.syncShutdownGracefully()
    }

    func send(_ request: RelayRequest) throws -> RelayResponse {
        let response = try sendRaw(RelayCodec.encoder().encode(request))
        guard response.isResponse(to: request) else {
            throw NSError(domain: "OpaqueRouteRelayTCPHarness", code: 2)
        }
        return response
    }

    func sendRaw(_ requestData: Data) throws -> RelayResponse {
        let promise = group.next().makePromise(of: RelayResponse.self)
        let bootstrap = ClientBootstrap(group: group).channelInitializer { channel in
            channel.pipeline.addHandler(LineFrameHandler(maxLength: 640 * 1_024)).flatMap {
                channel.pipeline.addHandler(
                    OpaqueRouteRelayResponseHandler(requestData: requestData, promise: promise)
                )
            }
        }
        let client = try bootstrap.connect(host: host, port: port).wait()
        let response = try promise.futureResult.wait()
        try? client.close().wait()
        return response
    }
}

private final class OpaqueRouteRelayResponseHandler: ChannelInboundHandler {
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
        var buffer = unwrapInboundIn(data)
        guard let responseData = buffer.readData(length: buffer.readableBytes) else {
            fail(ChannelError.inputClosed)
            return
        }
        do {
            succeed(try RelayCodec.decoder().decode(RelayResponse.self, from: responseData))
        } catch {
            fail(error)
        }
        context.close(promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        fail(error)
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        fail(ChannelError.inputClosed)
    }

    private func succeed(_ response: RelayResponse) {
        guard !resolved else { return }
        resolved = true
        promise.succeed(response)
    }

    private func fail(_ error: Error) {
        guard !resolved else { return }
        resolved = true
        promise.fail(error)
    }
}
