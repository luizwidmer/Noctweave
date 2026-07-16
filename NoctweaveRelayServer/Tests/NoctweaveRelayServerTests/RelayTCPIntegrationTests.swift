import Foundation
import XCTest
import Crypto
@preconcurrency import NIOCore
@preconcurrency import NIOHTTP1
@preconcurrency import NIOPosix
@preconcurrency import NIOFoundationCompat
@testable import NoctweaveRelayServer

final class RelayTCPIntegrationTests: XCTestCase {
    func testPublicRelayEndpointPolicyRejectsIPv6TransitionPrivateTargets() {
        let endpoints = [
            RelayEndpoint(host: "64:ff9b::7f00:1", port: 443, useTLS: true),
            RelayEndpoint(host: "64:ff9b::0a00:1", port: 443, useTLS: true),
            RelayEndpoint(host: "2002:0a00:0001::1", port: 443, useTLS: true),
            RelayEndpoint(host: "2001:0000:4136:e378:8000:63bf:3fff:fdd2", port: 443, useTLS: true),
            RelayEndpoint(host: "::7f00:1", port: 443, useTLS: true),
            RelayEndpoint(host: "100::1", port: 443, useTLS: true),
            RelayEndpoint(host: "fec0::1", port: 443, useTLS: true),
            RelayEndpoint(host: "3fff::1", port: 443, useTLS: true)
        ]

        for endpoint in endpoints {
            XCTAssertFalse(
                PublicRelayEndpointPolicy.permits(endpoint),
                "Expected public endpoint policy to reject \(endpoint.host)"
            )
        }
    }

    func testHealthRoundTripOverTCP() throws {
        let harness = try RelayTCPHarness()
        defer { try? harness.shutdown() }

        let response = try harness.send(.health())
        XCTAssertEqual(response.type, .ok)
    }

    func testHTTPBridgeResponsesIncludeSecurityHeaders() {
        var headers = HTTPHeaders()
        HTTPRelaySecurityHeaders.apply(to: &headers)

        XCTAssertEqual(headers.first(name: "Cache-Control"), "no-store")
        XCTAssertEqual(headers.first(name: "Pragma"), "no-cache")
        XCTAssertEqual(headers.first(name: "X-Content-Type-Options"), "nosniff")
        XCTAssertEqual(headers.first(name: "X-Frame-Options"), "DENY")
        XCTAssertEqual(headers.first(name: "Referrer-Policy"), "no-referrer")
        XCTAssertEqual(headers.first(name: "Cross-Origin-Resource-Policy"), "same-origin")
        XCTAssertEqual(headers.first(name: "Content-Security-Policy"), "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        XCTAssertEqual(headers.first(name: "Permissions-Policy"), "camera=(), microphone=(), geolocation=(), interest-cohort=()")
    }

    func testHTTPBridgeUsesForwardedAddressOnlyFromLoopbackProxy() throws {
        var headers = HTTPHeaders()
        headers.add(name: "X-Forwarded-For", value: "198.51.100.22, 127.0.0.1")

        let loopback = try SocketAddress(ipAddress: "127.0.0.1", port: 443)
        XCTAssertEqual(relayHTTPSourceKey(address: loopback, headers: headers), "198.51.100.22")

        let remote = try SocketAddress(ipAddress: "203.0.113.9", port: 443)
        XCTAssertEqual(relayHTTPSourceKey(address: remote, headers: headers), "203.0.113.9")
    }

    func testDeliverThenFetchRoundTripOverTCP() throws {
        let harness = try RelayTCPHarness()
        defer { try? harness.shutdown() }

        let inbox = InboxAddress.generate()
        let envelope = makeEnvelope()
        try harness.registerInboxDirect(inboxId: inbox, accessPublicKey: Data([0x31]))

        let deliverResponse = try harness.send(
            .deliver(
                DeliverRequest(
                    inboxId: inbox,
                    routingToken: inbox,
                    envelope: envelope,
                    destinationRelay: nil
                )
            )
        )
        XCTAssertEqual(deliverResponse.type, .delivered)
        XCTAssertEqual(deliverResponse.delivered?.storedCount, 1)

        let fetchResponse = try harness.send(.fetch(FetchRequest(inboxId: inbox, routingToken: inbox, maxCount: 10)))
        XCTAssertEqual(fetchResponse.type, .messages)
        XCTAssertEqual(fetchResponse.messages?.count, 1)
        XCTAssertEqual(fetchResponse.messages?.first?.id, envelope.id)
    }

    func testUnregisteredDirectDestinationIsRejectedWithoutMailboxAllocationOverTCP() throws {
        let harness = try RelayTCPHarness()
        defer { try? harness.shutdown() }

        let inbox = InboxAddress.generate()
        let envelope = makeEnvelope()
        let request = RelayRequest.deliver(
            DeliverRequest(
                inboxId: inbox,
                routingToken: inbox,
                envelope: envelope,
                destinationRelay: nil
            )
        )

        let rejected = try harness.send(request)
        XCTAssertEqual(rejected.type, .error)
        XCTAssertEqual(rejected.error, "Destination inbox is not registered")
        let beforeRegistration = try harness.send(
            .fetch(FetchRequest(inboxId: inbox, routingToken: inbox, maxCount: 10))
        )
        XCTAssertEqual(beforeRegistration.messages?.count, 0)

        try harness.registerInboxDirect(inboxId: inbox, accessPublicKey: Data([0x35]))
        let accepted = try harness.send(request)
        XCTAssertEqual(accepted.type, .delivered)
        XCTAssertEqual(accepted.delivered?.storedCount, 1)
    }

    func testLongPollFetchReturnsMessageDeliveredDuringWaitOverTCP() throws {
        let harness = try RelayTCPHarness(
            wakeSupport: DecentralizedWakeSupport(
                mode: .longPoll,
                minPollIntervalSeconds: 5,
                maxPollIntervalSeconds: 5,
                jitterPermille: 0,
                longPollTimeoutSeconds: 5
            )
        )
        defer { try? harness.shutdown() }

        let inbox = InboxAddress.generate()
        let envelope = makeEnvelope()
        try harness.registerInboxDirect(inboxId: inbox, accessPublicKey: Data([0x32]))
        let expectation = expectation(description: "long-poll fetch returned delivered message")
        var fetchResponse: RelayResponse?
        var fetchError: Error?

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                fetchResponse = try harness.send(
                    .fetch(
                        FetchRequest(
                            inboxId: inbox,
                            routingToken: inbox,
                            maxCount: 10,
                            longPollTimeoutSeconds: 5
                        )
                    )
                )
            } catch {
                fetchError = error
            }
            expectation.fulfill()
        }

        Thread.sleep(forTimeInterval: 0.25)
        let deliverResponse = try harness.send(
            .deliver(
                DeliverRequest(
                    inboxId: inbox,
                    routingToken: inbox,
                    envelope: envelope,
                    destinationRelay: nil
                )
            )
        )
        XCTAssertEqual(deliverResponse.type, .delivered)

        wait(for: [expectation], timeout: 7.0)
        XCTAssertNil(fetchError)
        XCTAssertEqual(fetchResponse?.type, .messages)
        XCTAssertEqual(fetchResponse?.messages?.map(\.id), [envelope.id])
    }

    func testPasswordProtectedRelayRejectsUnauthorizedRequestsOverTCP() throws {
        let harness = try RelayTCPHarness(accessPassword: "secret-pass")
        defer { try? harness.shutdown() }
        let inbox = InboxAddress.generate()
        try harness.registerInboxDirect(inboxId: inbox, accessPublicKey: Data([0x33]))
        let request = RelayRequest.deliver(
            DeliverRequest(
                inboxId: inbox,
                routingToken: inbox,
                envelope: makeEnvelope(),
                destinationRelay: nil
            )
        )

        let unauthorized = try harness.send(request)
        XCTAssertEqual(unauthorized.type, .error)
        XCTAssertEqual(unauthorized.error, "Unauthorized: relay password is required.")

        let authorized = try harness.send(request.withAuthToken("secret-pass"))
        XCTAssertEqual(authorized.type, .delivered)
    }

    func testInboxFetchRequiresRegistrationAndProof() throws {
        let harness = try RelayTCPHarness(requireInboxAccessControl: true)
        defer { try? harness.shutdown() }
        let inbox = InboxAddress.generate()

        let response = try harness.send(
            .fetch(FetchRequest(inboxId: inbox, routingToken: inbox, maxCount: 10))
        )

        XCTAssertEqual(response.type, .error)
        XCTAssertEqual(response.error, "Inbox is not registered")
    }

    func testCoordinatorRegistrationTokenIsEnforcedOverTCP() throws {
        let federation = FederationDescriptor(mode: .curated, name: "mesh-token")
        let token = "relay-mesh-token"
        let harness = try RelayTCPHarness(
            kind: .coordinator,
            federation: federation,
            coordinatorRegistrationToken: token
        )
        let registrant = try RelayTCPHarness(
            kind: .standard,
            federation: federation
        )
        defer { try? harness.shutdown() }
        defer { try? registrant.shutdown() }

        let request = RelayRequest.registerFederationNode(
            FederationNodeRegistrationRequest(
                endpoint: registrant.endpoint,
                relayInfo: RelayConfiguration(
                    kind: .standard,
                    federation: federation,
                    relayName: "Relay Token"
                ).makeInfo(),
                ttlSeconds: 120
            )
        )

        let unauthorized = try harness.send(request)
        XCTAssertEqual(unauthorized.type, .error)
        XCTAssertEqual(unauthorized.error, "Unauthorized: coordinator registration token is required.")

        let authorized = try harness.send(request.withAuthToken(token))
        XCTAssertEqual(authorized.type, .federationNodes)
        XCTAssertEqual(authorized.federationNodes?.count, 1)
    }

    func testCuratedCoordinatorFailsClosedWithoutRegistrationToken() throws {
        let federation = FederationDescriptor(mode: .curated, name: "mesh-token-required")
        let harness = try RelayTCPHarness(kind: .coordinator, federation: federation)
        defer { try? harness.shutdown() }

        let request = RelayRequest.registerFederationNode(
            FederationNodeRegistrationRequest(
                endpoint: RelayEndpoint(host: "127.0.0.1", port: 39999),
                relayInfo: RelayConfiguration(kind: .standard, federation: federation).makeInfo(),
                ttlSeconds: 120
            )
        )
        let response = try harness.send(request)

        XCTAssertEqual(response.type, .error)
        XCTAssertEqual(
            response.error,
            "Coordinator configuration error: curated registration requires a token."
        )
    }

    func testForwardingDoesNotReuseInboundClientAuthToken() throws {
        let federation = FederationDescriptor(mode: .open, name: "mesh-auth-isolation")
        let source = try RelayTCPHarness(
            kind: .bridge,
            federation: federation,
            accessPassword: "client-token"
        )
        let destination = try RelayTCPHarness(
            kind: .standard,
            federation: federation,
            accessPassword: "client-token"
        )
        defer {
            try? source.shutdown()
            try? destination.shutdown()
        }

        let inbox = InboxAddress.generate()
        let deliver = RelayRequest.deliver(
            DeliverRequest(
                inboxId: inbox,
                routingToken: inbox,
                envelope: makeEnvelope(),
                destinationRelay: destination.endpoint
            )
        ).withAuthToken("client-token")

        let response = try source.send(deliver)
        XCTAssertEqual(response.type, .error)
        XCTAssertTrue((response.error ?? "").localizedCaseInsensitiveContains("unauthorized"))

        let fetch = try destination.send(
            RelayRequest.fetch(FetchRequest(inboxId: inbox, routingToken: inbox, maxCount: 10))
                .withAuthToken("client-token")
        )
        XCTAssertEqual(fetch.type, .messages)
        XCTAssertEqual(fetch.messages?.count ?? 0, 0)
    }

    func testForwardingUsesDedicatedInterRelayTokenWhenConfigured() throws {
        let federation = FederationDescriptor(mode: .open, name: "mesh-auth-forward")
        let source = try RelayTCPHarness(
            kind: .bridge,
            federation: federation,
            accessPassword: "client-token",
            federationForwardingAuthToken: "relay-token"
        )
        let destination = try RelayTCPHarness(
            kind: .standard,
            federation: federation,
            accessPassword: "relay-token"
        )
        defer {
            try? source.shutdown()
            try? destination.shutdown()
        }

        let inbox = InboxAddress.generate()
        let envelope = makeEnvelope()
        try destination.registerInboxDirect(inboxId: inbox, accessPublicKey: Data([0x34]))
        let deliver = RelayRequest.deliver(
            DeliverRequest(
                inboxId: inbox,
                routingToken: inbox,
                envelope: envelope,
                destinationRelay: destination.endpoint
            )
        ).withAuthToken("client-token")

        let response = try source.send(deliver)
        XCTAssertEqual(response.type, .delivered)
        XCTAssertEqual(response.delivered?.storedCount, 1)

        let fetch = try destination.send(
            RelayRequest.fetch(FetchRequest(inboxId: inbox, routingToken: inbox, maxCount: 10))
                .withAuthToken("relay-token")
        )
        XCTAssertEqual(fetch.type, .messages)
        XCTAssertEqual(fetch.messages?.count, 1)
        XCTAssertEqual(fetch.messages?.first?.id, envelope.id)
    }

    func testForwardedDeliveryIsAdmittedOnlyByFinalRelayRegistration() throws {
        let federation = FederationDescriptor(mode: .open, name: "mesh-final-admission")
        let source = try RelayTCPHarness(kind: .bridge, federation: federation)
        let destination = try RelayTCPHarness(kind: .standard, federation: federation)
        defer {
            try? source.shutdown()
            try? destination.shutdown()
        }

        let inbox = InboxAddress.generate()
        let envelope = makeEnvelope()
        let request = RelayRequest.deliver(
            DeliverRequest(
                inboxId: inbox,
                routingToken: inbox,
                envelope: envelope,
                destinationRelay: destination.endpoint
            )
        )

        let rejected = try source.send(request)
        XCTAssertEqual(rejected.type, .error)
        XCTAssertEqual(rejected.error, "Destination inbox is not registered")

        try destination.registerInboxDirect(inboxId: inbox, accessPublicKey: Data([0x36]))
        let accepted = try source.send(request)
        XCTAssertEqual(accepted.type, .delivered)
        XCTAssertEqual(accepted.delivered?.storedCount, 1)
    }

    func testForwardingTimesOutWhenDestinationStalls() throws {
        let stalledDestination = try SilentRelayDestinationHarness()
        defer { try? stalledDestination.shutdown() }

        let source = try RelayTCPHarness(
            kind: .bridge,
            federation: FederationDescriptor(mode: .open, name: "mesh-timeout"),
            forwardingRequestTimeoutSeconds: 1
        )
        defer { try? source.shutdown() }

        let inbox = InboxAddress.generate()
        let response = try source.send(
            .deliver(
                DeliverRequest(
                    inboxId: inbox,
                    routingToken: inbox,
                    envelope: makeEnvelope(),
                    destinationRelay: stalledDestination.endpoint
                )
            )
        )
        XCTAssertEqual(response.type, .error)
        XCTAssertEqual(response.error, "Forwarding failed")
    }

    private func makeEnvelope() -> Envelope {
        Envelope(
            conversationId: "tcp-integration-conversation",
            sessionId: UUID().uuidString,
            senderFingerprint: Data(repeating: 0x44, count: 32).base64EncodedString(),
            sentAt: Date(),
            messageCounter: 1,
            kemCiphertext: nil,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0xA5, count: 12),
                ciphertext: Data(repeating: 0x10, count: 512),
                tag: Data(repeating: 0xB6, count: 16)
            ),
            signature: Data(
                repeating: 0xCC,
                count: OQSSignatureVerifier.mlDSA65SignatureBytes
            )
        )
    }

}

final class RelayTCPHarness {
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let store: RelayStore
    private let host: String
    private let port: Int
    private let maxLineBytes: Int?
    var endpoint: RelayEndpoint {
        RelayEndpoint(host: host, port: UInt16(port))
    }

    init(
        kind: RelayKind = .standard,
        federation: FederationDescriptor = FederationDescriptor(mode: .solo),
        accessPassword: String? = nil,
        coordinatorRegistrationToken: String? = nil,
        federationForwardingAuthToken: String? = nil,
        forwardingRequestTimeoutSeconds: Int = 8,
        maxLineBytes: Int? = 64 * 1024,
        requireInboxAccessControl: Bool = false,
        wakeSupport: DecentralizedWakeSupport? = nil,
        storeFileURL: URL? = nil,
        experimentalRouteCapabilitiesEnabled: Bool = false
    ) throws {
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.host = "127.0.0.1"
        self.maxLineBytes = maxLineBytes

        let store = RelayStore(
            fileURL: storeFileURL,
            maxInboxMessages: nil,
            temporalBucketSeconds: 300
        )
        self.store = store
        let config = RelayConfiguration(
            kind: kind,
            federation: federation,
            tlsEnabled: false,
            temporalBucketSeconds: 300,
            wakeSupport: wakeSupport,
            relayName: "Integration Relay",
            operatorNote: nil,
            softwareVersion: "test",
            groupCreationMode: .allowed,
            accessPassword: accessPassword,
            coordinatorRegistrationToken: coordinatorRegistrationToken,
            federationForwardingAuthToken: federationForwardingAuthToken,
            allowPrivateFederationEndpoints: true,
            requireInboxAccessControl: requireInboxAccessControl,
            experimentalRouteCapabilitiesEnabled: experimentalRouteCapabilitiesEnabled
        )

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 64)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(LineFrameHandler(maxLength: maxLineBytes)).flatMap {
                    channel.pipeline.addHandler(
                        RelayHandler(
                            store: store,
                            maxMessageBytes: 512 * 1024,
                            maxLineBytes: maxLineBytes,
                            localEndpoint: RelayEndpoint(host: "127.0.0.1", port: 0),
                            relayConfiguration: config,
                            forwardingRequestTimeoutSeconds: forwardingRequestTimeoutSeconds
                        )
                    )
                }
            }
            .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)

        do {
            self.channel = try bootstrap.bind(host: host, port: 0).wait()
        } catch {
            try? group.syncShutdownGracefully()
            throw error
        }
        guard let localPort = channel.localAddress?.port else {
            try? channel.close().wait()
            try? group.syncShutdownGracefully()
            throw NSError(domain: "RelayTCPHarness", code: 1, userInfo: [NSLocalizedDescriptionKey: "Missing bound port"])
        }
        self.port = localPort
    }

    func shutdown() throws {
        try? channel.close().wait()
        try group.syncShutdownGracefully()
    }

    func registerInboxDirect(inboxId: String, accessPublicKey: Data) throws {
        try store.registerInbox(inboxId: inboxId, accessPublicKey: accessPublicKey)
    }

    func failNextPersistenceForTesting() {
        store.failNextPersistenceForTesting()
    }

    func send(_ request: RelayRequest) throws -> RelayResponse {
        let promise = group.next().makePromise(of: RelayResponse.self)
        let data = try RelayCodec.encoder().encode(request)
        let completion = TCPResponseCompletion()

        let bootstrap = ClientBootstrap(group: group).channelInitializer { channel in
            channel.pipeline.addHandler(LineFrameHandler(maxLength: self.maxLineBytes)).flatMap {
                channel.pipeline.addHandler(
                    TCPResponseHandler(
                        requestData: data,
                        promise: promise,
                        completion: completion
                    )
                )
            }
        }

        let clientChannel = try bootstrap.connect(host: host, port: port).wait()
        let result = try promise.futureResult.wait()
        try? clientChannel.close().wait()
        return result
    }
}

private final class SilentRelayDestinationHarness {
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let host: String
    private let port: Int

    var endpoint: RelayEndpoint {
        RelayEndpoint(host: host, port: UInt16(port))
    }

    init() throws {
        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        host = "127.0.0.1"
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 16)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(SilentInboundHandler())
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
            throw NSError(
                domain: "SilentRelayDestinationHarness",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Missing bound port"]
            )
        }
        port = boundPort
    }

    func shutdown() throws {
        try? channel.close().wait()
        try group.syncShutdownGracefully()
    }
}

private final class SilentInboundHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {}
}

private final class TCPResponseHandler: ChannelDuplexHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let requestData: Data
    private let promise: EventLoopPromise<RelayResponse>
    private let completion: TCPResponseCompletion

    init(requestData: Data, promise: EventLoopPromise<RelayResponse>, completion: TCPResponseCompletion) {
        self.requestData = requestData
        self.promise = promise
        self.completion = completion
    }

    func channelActive(context: ChannelHandlerContext) {
        var buffer = context.channel.allocator.buffer(capacity: requestData.count + 1)
        LineEncoder.wrap(requestData, into: &buffer)
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        guard let payload = buffer.readData(length: buffer.readableBytes) else {
            completion.resolve(promise, .failure(ChannelError.inputClosed))
            context.close(promise: nil)
            return
        }
        do {
            let response = try RelayCodec.decoder().decode(RelayResponse.self, from: payload)
            completion.resolve(promise, .success(response))
        } catch {
            completion.resolve(promise, .failure(error))
        }
        context.close(promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        completion.resolve(promise, .failure(error))
        context.close(promise: nil)
    }
}

private final class TCPResponseCompletion {
    private let lock = NSLock()
    private var completed = false

    func resolve(_ promise: EventLoopPromise<RelayResponse>, _ result: Result<RelayResponse, Error>) {
        lock.lock()
        defer { lock.unlock() }
        guard !completed else { return }
        completed = true
        switch result {
        case .success(let response):
            promise.succeed(response)
        case .failure(let error):
            promise.fail(error)
        }
    }
}
