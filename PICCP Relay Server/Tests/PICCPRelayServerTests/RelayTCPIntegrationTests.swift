import Foundation
import XCTest
import Crypto
@preconcurrency import NIOCore
import NIOPosix
import NIOFoundationCompat
@testable import PICCPRelayServer

final class RelayTCPIntegrationTests: XCTestCase {
    func testPublicRelayEndpointPolicyRejectsIPv6TransitionPrivateTargets() {
        let endpoints = [
            RelayEndpoint(host: "64:ff9b::7f00:1", port: 443, useTLS: true),
            RelayEndpoint(host: "64:ff9b::0a00:1", port: 443, useTLS: true),
            RelayEndpoint(host: "2002:0a00:0001::1", port: 443, useTLS: true),
            RelayEndpoint(host: "2001:0000:4136:e378:8000:63bf:3fff:fdd2", port: 443, useTLS: true)
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

    func testDeliverThenFetchRoundTripOverTCP() throws {
        let harness = try RelayTCPHarness()
        defer { try? harness.shutdown() }

        let inbox = InboxAddress.generate()
        let envelope = makeEnvelope()

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

    func testPasswordProtectedRelayRejectsUnauthorizedRequestsOverTCP() throws {
        let harness = try RelayTCPHarness(accessPassword: "secret-pass")
        defer { try? harness.shutdown() }
        let inbox = InboxAddress.generate()
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

    func testUnsignedContactAnnouncementIsRejected() throws {
        let harness = try RelayTCPHarness()
        defer { try? harness.shutdown() }
        let signingKey = Data("invalid-signing-key".utf8)
        let offer = ContactOffer(
            version: 2,
            displayName: "Mallory",
            inboxId: InboxAddress.generate(),
            relay: harness.endpoint,
            signingPublicKey: signingKey,
            agreementPublicKey: Data([0x01]),
            inboxAccessPublicKey: nil,
            fingerprint: Data(SHA256.hash(data: signingKey)).base64EncodedString(),
            signature: Data()
        )

        let response = try harness.send(.announce(AnnounceRequest(offer: offer, ttlSeconds: 300)))
        XCTAssertEqual(response.type, .error)
        XCTAssertEqual(response.error, "Invalid contact offer.")
    }

    func testInboxRegistrationWithoutIdentityBindingIsRejected() throws {
        let harness = try RelayTCPHarness()
        defer { try? harness.shutdown() }
        let accessPublicKey = Data(repeating: 0x01, count: 32)
        let request = RegisterInboxRequest(
            inboxId: InboxAddress.derived(from: accessPublicKey),
            accessPublicKey: accessPublicKey
        )

        let response = try harness.send(.registerInbox(request))
        XCTAssertEqual(response.type, .error)
        XCTAssertEqual(response.error, "Inbox registration is not bound to a valid identity offer")
    }

    func testPrekeyUploadWithoutIdentityProofIsRejected() throws {
        let harness = try RelayTCPHarness()
        defer { try? harness.shutdown() }
        let fingerprint = "prekey-owner"
        let bundle = PrekeyBundle(
            identityFingerprint: fingerprint,
            signedPrekey: SignedPrekey(
                id: UUID(),
                publicKey: Data([0x01]),
                issuedAt: Date(),
                signature: Data([0x02])
            ),
            oneTimePrekeys: []
        )

        let response = try harness.send(
            .uploadPrekeys(
                UploadPrekeyBundleRequest(
                    fingerprint: fingerprint,
                    bundle: bundle
                )
            )
        )
        XCTAssertEqual(response.type, .error)
        XCTAssertEqual(response.error, "Missing actor proof.")
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

    func testPairRequestFetchRequiresIdentityProof() throws {
        let harness = try RelayTCPHarness()
        defer { try? harness.shutdown() }
        let signingKey = Data("synthetic-recipient-key".utf8)
        let fingerprint = Data(SHA256.hash(data: signingKey)).base64EncodedString()

        let response = try harness.send(
            .fetchPairRequests(
                FetchPairRequestsRequest(
                    fingerprint: fingerprint,
                    maxCount: 10
                )
            )
        )

        XCTAssertEqual(response.type, .error)
        XCTAssertEqual(response.error, "Missing actor proof.")
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

    func testGroupActorProofRejectedWhenVerificationUnavailable() throws {
        let harness = try RelayTCPHarness()
        defer { try? harness.shutdown() }

        let response = try harness.send(makeCreateGroupRelayRequest())
        XCTAssertEqual(response.type, .error)
        if OQSSignatureVerifier.shared.isAvailable {
            XCTAssertEqual(response.error, "Invalid actor proof signature.")
        } else {
            XCTAssertEqual(response.error, "Actor proof signature verification is unavailable on this relay build.")
        }
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
        XCTAssertTrue((response.error ?? "").localizedCaseInsensitiveContains("timed out"))
    }

    private func makeEnvelope() -> Envelope {
        Envelope(
            conversationId: "tcp-integration-conversation",
            sessionId: UUID().uuidString,
            senderFingerprint: "sender-fingerprint",
            sentAt: Date(),
            messageCounter: 1,
            kemCiphertext: Data([0x01, 0x02, 0x03]),
            payload: EncryptedPayload(
                nonce: Data(repeating: 0xA5, count: 12),
                ciphertext: Data([0x10, 0x11, 0x12]),
                tag: Data(repeating: 0xB6, count: 16)
            ),
            signature: Data([0xCC, 0xDD, 0xEE])
        )
    }

    private func makeCreateGroupRelayRequest() -> RelayRequest {
        let signingKey = Data("synthetic-group-signing-key".utf8)
        let fingerprint = Data(SHA256.hash(data: signingKey)).base64EncodedString()
        let proof = RelayActorProof(
            fingerprint: fingerprint,
            publicSigningKey: signingKey,
            signedAt: Date(),
            nonce: UUID(),
            signature: Data([0x01, 0x02, 0x03])
        )
        let creatorProfile = RelayGroupMemberProfile(
            fingerprint: fingerprint,
            displayName: "Creator",
            inboxId: nil,
            relay: nil,
            signingPublicKey: signingKey,
            agreementPublicKey: nil
        )
        let request = CreateGroupRequest(
            title: "Ops",
            creatorFingerprint: fingerprint,
            memberFingerprints: ["member-b"],
            creatorProfile: creatorProfile,
            memberProfiles: nil,
            creatorProof: proof
        )
        return .createGroup(request)
    }
}

private final class RelayTCPHarness {
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
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
        requireInboxAccessControl: Bool = false
    ) throws {
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.host = "127.0.0.1"
        self.maxLineBytes = maxLineBytes

        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 300)
        let config = RelayConfiguration(
            kind: kind,
            federation: federation,
            tlsEnabled: false,
            temporalBucketSeconds: 300,
            relayName: "Integration Relay",
            operatorNote: nil,
            softwareVersion: "test",
            groupCreationMode: .allowed,
            accessPassword: accessPassword,
            coordinatorRegistrationToken: coordinatorRegistrationToken,
            federationForwardingAuthToken: federationForwardingAuthToken,
            allowPrivateFederationEndpoints: true,
            requireInboxAccessControl: requireInboxAccessControl
        )

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 64)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(ByteToMessageHandler(LineDecoder(maxLength: maxLineBytes))).flatMap {
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

    func send(_ request: RelayRequest) throws -> RelayResponse {
        let promise = group.next().makePromise(of: RelayResponse.self)
        let data = try RelayCodec.encoder().encode(request)
        let completion = TCPResponseCompletion()

        let bootstrap = ClientBootstrap(group: group).channelInitializer { channel in
            channel.pipeline.addHandler(ByteToMessageHandler(LineDecoder(maxLength: self.maxLineBytes))).flatMap {
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
