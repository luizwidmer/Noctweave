import Foundation
@preconcurrency import NIOCore
import NIOPosix
@preconcurrency import NIOHTTP1
@preconcurrency import NIOWebSocket
@preconcurrency import NIOFoundationCompat
@preconcurrency import NIOConcurrencyHelpers

private let defaultRelayRequestLimit = 512 * 1024
private let absoluteRelayRequestLimit = 8 * 1024 * 1024

private func boundedRelayRequestLimit(_ configured: Int?) -> Int {
    min(max(1_024, configured ?? defaultRelayRequestLimit), absoluteRelayRequestLimit)
}

func makeHTTPRelayBridgeBootstrap(
    group: EventLoopGroup,
    forwarder: LocalRelayForwarder,
    store: RelayStore,
    maxMessageBytes: Int?
) -> ServerBootstrap {
    ServerBootstrap(group: group)
        .serverChannelOption(ChannelOptions.backlog, value: 256)
        .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
        .childChannelInitializer { channel in
            let upgrader = NIOWebSocketServerUpgrader(
                shouldUpgrade: { channel, head in
                    guard head.method == .GET else {
                        return channel.eventLoop.makeFailedFuture(NIOWebSocketUpgradeError.invalidUpgradeHeader)
                    }
                    let path = head.uri.split(separator: "?", maxSplits: 1).first.map(String.init) ?? head.uri
                    guard path == "/relay" else {
                        return channel.eventLoop.makeFailedFuture(NIOWebSocketUpgradeError.invalidUpgradeHeader)
                    }
                    return channel.eventLoop.makeSucceededFuture([:])
                },
                upgradePipelineHandler: { channel, head in
                    channel.pipeline.addHandler(
                        WebSocketRelayHandler(
                            forwarder: forwarder,
                            store: store,
                            sourceKey: relayHTTPSourceKey(address: channel.remoteAddress, headers: head.headers),
                            maxMessageBytes: maxMessageBytes
                        )
                    )
                }
            )

            let httpHandler = HTTPRelayHandler(
                forwarder: forwarder,
                store: store,
                maxMessageBytes: maxMessageBytes
            )
            let upgradeConfig = NIOHTTPServerUpgradeConfiguration(
                upgraders: [upgrader],
                completionHandler: { context in
                    context.pipeline.removeHandler(httpHandler, promise: nil)
                }
            )
            return channel.pipeline.configureHTTPServerPipeline(withServerUpgrade: upgradeConfig).flatMap {
                channel.pipeline.addHandler(httpHandler)
            }
        }
        .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
        .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 16)
        .childChannelOption(ChannelOptions.recvAllocator, value: AdaptiveRecvByteBufferAllocator())
}

final class LocalRelayForwarder {
    private let relayHost: String
    private let relayPort: Int
    private let maxLineBytes: Int?
    private let requestTimeoutSeconds: Int

    init(relayHost: String, relayPort: Int, maxLineBytes: Int?, requestTimeoutSeconds: Int) {
        self.relayHost = relayHost
        self.relayPort = relayPort
        self.maxLineBytes = maxLineBytes
        self.requestTimeoutSeconds = max(1, requestTimeoutSeconds)
    }

    func forward(_ payload: Data, on eventLoop: EventLoop) -> EventLoopFuture<Data> {
        let promise = eventLoop.makePromise(of: Data.self)
        let completion = ForwardDataCompletion()
        let timeoutTask = eventLoop.scheduleTask(in: .seconds(Int64(requestTimeoutSeconds))) {
            completion.resolve(promise, .failure(RelayBridgeTimeoutError()))
        }
        promise.futureResult.whenComplete { _ in
            timeoutTask.cancel()
        }

        let bootstrap = ClientBootstrap(group: eventLoop)
            .connectTimeout(.seconds(Int64(requestTimeoutSeconds)))
            .channelInitializer { channel in
                channel.pipeline.addHandler(LineFrameHandler(maxLength: self.maxLineBytes)).flatMap {
                    channel.pipeline.addHandler(
                        RelayBridgeForwardingHandler(
                            requestData: payload,
                            promise: promise,
                            completion: completion
                        )
                    )
                }
            }
        bootstrap.connect(host: relayHost, port: relayPort).whenComplete { result in
            switch result {
            case .success(let channel):
                promise.futureResult.whenComplete { _ in
                    channel.close(promise: nil)
                }
            case .failure(let error):
                completion.resolve(promise, .failure(error))
            }
        }
        return promise.futureResult
    }
}

private struct RelayBridgeTimeoutError: LocalizedError {
    var errorDescription: String? { "Relay bridge request timed out." }
}

private final class HTTPRelayHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let forwarder: LocalRelayForwarder
    private let store: RelayStore
    private let maxMessageBytes: Int
    private var requestHead: HTTPRequestHead?
    private var requestBody = ByteBuffer()
    private var isRejected = false

    init(forwarder: LocalRelayForwarder, store: RelayStore, maxMessageBytes: Int?) {
        self.forwarder = forwarder
        self.store = store
        self.maxMessageBytes = boundedRelayRequestLimit(maxMessageBytes)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            requestHead = head
            requestBody.clear()
            isRejected = false
            let declaredLengths = head.headers["Content-Length"]
            if declaredLengths.count > 1 || declaredLengths.contains(where: { value in
                guard let parsed = Int(value), parsed >= 0 else { return true }
                return parsed > maxMessageBytes
            }) {
                isRejected = true
                sendHTTPResponse(
                    status: declaredLengths.count > 1 ? .badRequest : .payloadTooLarge,
                    body: Data(#"{"type":"error","error":"Invalid or oversized payload"}"#.utf8),
                    context: context
                )
            }
        case .body(var body):
            guard !isRejected else { return }
            requestBody.writeBuffer(&body)
            if requestBody.readableBytes > maxMessageBytes {
                isRejected = true
                sendHTTPResponse(
                    status: .payloadTooLarge,
                    body: Data(#"{"type":"error","error":"Payload too large"}"#.utf8),
                    context: context
                )
            }
        case .end:
            guard !isRejected else { return }
            guard let head = requestHead else {
                sendHTTPResponse(status: .badRequest, body: Data(), context: context)
                return
            }
            handleRequest(head: head, context: context)
        }
    }

    private func handleRequest(head: HTTPRequestHead, context: ChannelHandlerContext) {
        let sourceKey = relayHTTPSourceKey(address: context.channel.remoteAddress, headers: head.headers)
        guard store.allowRelayRequest(sourceKey: sourceKey) else {
            sendHTTPResponse(
                status: .tooManyRequests,
                body: Data(#"{"type":"error","error":"Rate limit exceeded"}"#.utf8),
                context: context
            )
            return
        }
        let path = head.uri.split(separator: "?", maxSplits: 1).first.map(String.init) ?? head.uri
        if head.method == .GET, path == "/health" {
            sendHTTPResponse(status: .ok, body: Data(#"{"status":"ok"}"#.utf8), context: context)
            return
        }
        guard head.method == .POST, path == "/relay" else {
            sendHTTPResponse(status: .notFound, body: Data(#"{"error":"Not found"}"#.utf8), context: context)
            return
        }

        let payload = requestBody.readData(length: requestBody.readableBytes) ?? Data()
        let responseContext = NIOContextBox(context)
        forwarder.forward(payload, on: context.eventLoop).whenComplete { result in
            switch result {
            case .success(let responseData):
                self.sendHTTPResponse(status: .ok, body: responseData, context: responseContext.context)
            case .failure:
                let body = Data(#"{"type":"error","error":"Bridge forward failed"}"#.utf8)
                self.sendHTTPResponse(status: .badGateway, body: body, context: responseContext.context)
                print("[relay] http bridge forward failure")
            }
        }
    }

    private func sendHTTPResponse(status: HTTPResponseStatus, body: Data, context: ChannelHandlerContext) {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: "application/json")
        headers.add(name: "Content-Length", value: "\(body.count)")
        headers.add(name: "Connection", value: "close")
        HTTPRelaySecurityHeaders.apply(to: &headers)
        let responseHead = HTTPResponseHead(version: .http1_1, status: status, headers: headers)
        context.write(wrapOutboundOut(.head(responseHead)), promise: nil)
        var buffer = context.channel.allocator.buffer(capacity: body.count)
        buffer.writeBytes(body)
        context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        let responseContext = NIOContextBox(context)
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
            responseContext.context.close(promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

enum HTTPRelaySecurityHeaders {
    static let fields: [(name: String, value: String)] = [
        ("Cache-Control", "no-store"),
        ("Pragma", "no-cache"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
        ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
    ]

    static func apply(to headers: inout HTTPHeaders) {
        for field in fields {
            headers.replaceOrAdd(name: field.name, value: field.value)
        }
    }
}

private final class WebSocketRelayHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = WebSocketFrame
    typealias OutboundOut = WebSocketFrame

    private let forwarder: LocalRelayForwarder
    private let store: RelayStore
    private let sourceKey: String
    private let maxMessageBytes: Int
    private var isForwarding = false

    init(forwarder: LocalRelayForwarder, store: RelayStore, sourceKey: String, maxMessageBytes: Int?) {
        self.forwarder = forwarder
        self.store = store
        self.sourceKey = sourceKey
        self.maxMessageBytes = boundedRelayRequestLimit(maxMessageBytes)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let frame = unwrapInboundIn(data)
        switch frame.opcode {
        case .connectionClose:
            context.close(promise: nil)
        case .ping:
            let pongData = frame.unmaskedData
            let pong = WebSocketFrame(fin: true, opcode: .pong, data: pongData)
            context.writeAndFlush(wrapOutboundOut(pong), promise: nil)
        case .text, .binary:
            guard store.allowRelayRequest(sourceKey: sourceKey) else {
                send(
                    frameType: .text,
                    payload: Data(#"{"type":"error","error":"Rate limit exceeded"}"#.utf8),
                    context: context
                )
                return
            }
            guard frame.fin else {
                context.close(promise: nil)
                return
            }
            guard !isForwarding else {
                send(
                    frameType: .text,
                    payload: Data(#"{"type":"error","error":"Request already in progress"}"#.utf8),
                    context: context
                )
                return
            }
            var payloadBuffer = frame.unmaskedData
            guard let payload = payloadBuffer.readData(length: payloadBuffer.readableBytes) else {
                context.close(promise: nil)
                return
            }
            if payload.count > maxMessageBytes {
                send(frameType: .text, payload: Data(#"{"type":"error","error":"Payload too large"}"#.utf8), context: context)
                return
            }
            isForwarding = true
            let responseContext = NIOContextBox(context)
            forwarder.forward(payload, on: context.eventLoop).whenComplete { result in
                self.isForwarding = false
                switch result {
                case .success(let responseData):
                    self.send(frameType: frame.opcode, payload: responseData, context: responseContext.context)
                case .failure:
                    let response = Data(#"{"type":"error","error":"Bridge forward failed"}"#.utf8)
                    self.send(frameType: .text, payload: response, context: responseContext.context)
                    print("[relay] websocket bridge forward failure")
                }
            }
        default:
            break
        }
    }

    private func send(frameType: WebSocketOpcode, payload: Data, context: ChannelHandlerContext) {
        switch frameType {
        case .text:
            if let text = String(data: payload, encoding: .utf8) {
                var textBuffer = context.channel.allocator.buffer(capacity: text.utf8.count)
                textBuffer.writeString(text)
                let frame = WebSocketFrame(fin: true, opcode: .text, data: textBuffer)
                context.writeAndFlush(wrapOutboundOut(frame), promise: nil)
                return
            }
            fallthrough
        default:
            var binaryBuffer = context.channel.allocator.buffer(capacity: payload.count)
            binaryBuffer.writeBytes(payload)
            let frame = WebSocketFrame(fin: true, opcode: .binary, data: binaryBuffer)
            context.writeAndFlush(wrapOutboundOut(frame), promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

func relayHTTPSourceKey(address: SocketAddress?, headers: HTTPHeaders) -> String {
    let direct = address?.ipAddress?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
    if isLoopbackRelaySource(direct) {
        if let connectingIP = normalizedForwardedAddress(headers.first(name: "CF-Connecting-IP")) {
            return connectingIP
        }
        if let forwarded = headers.first(name: "X-Forwarded-For")?.split(separator: ",").first,
           let forwardedIP = normalizedForwardedAddress(String(forwarded)) {
            return forwardedIP
        }
    }
    if !direct.isEmpty {
        return direct
    }
    let fallback = address?.description.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
    return fallback.isEmpty ? "unknown" : fallback
}

private func normalizedForwardedAddress(_ value: String?) -> String? {
    guard let value else { return nil }
    let candidate = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    guard !candidate.isEmpty,
          candidate.count <= 64,
          !candidate.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) }),
          (try? SocketAddress(ipAddress: candidate, port: 0)) != nil else {
        return nil
    }
    return candidate
}

private func isLoopbackRelaySource(_ source: String) -> Bool {
    source == "127.0.0.1" || source == "::1" || source == "0:0:0:0:0:0:0:1"
}

private final class RelayBridgeForwardingHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let requestData: Data
    private let promise: EventLoopPromise<Data>
    private let completion: ForwardDataCompletion

    init(requestData: Data, promise: EventLoopPromise<Data>, completion: ForwardDataCompletion) {
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
        completion.resolve(promise, .success(payload))
        context.close(promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        completion.resolve(promise, .failure(error))
        context.close(promise: nil)
    }
}

private final class ForwardDataCompletion: @unchecked Sendable {
    private let lock = NIOLock()
    private var completed = false

    func resolve(_ promise: EventLoopPromise<Data>, _ result: Result<Data, Error>) {
        lock.lock()
        defer { lock.unlock() }
        guard !completed else { return }
        completed = true
        switch result {
        case .success(let value):
            promise.succeed(value)
        case .failure(let error):
            promise.fail(error)
        }
    }
}
