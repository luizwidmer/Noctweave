import Foundation
@preconcurrency import NIOCore
import NIOPosix
import NIOHTTP1
import NIOWebSocket
import NIOFoundationCompat
import NIOConcurrencyHelpers

func makeHTTPRelayBridgeBootstrap(
    group: EventLoopGroup,
    forwarder: LocalRelayForwarder,
    maxMessageBytes: Int?
) -> ServerBootstrap {
    ServerBootstrap(group: group)
        .serverChannelOption(ChannelOptions.backlog, value: 256)
        .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
        .childChannelInitializer { channel in
            let webSocketHandler = WebSocketRelayHandler(forwarder: forwarder, maxMessageBytes: maxMessageBytes)
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
                upgradePipelineHandler: { channel, _ in
                    channel.pipeline.addHandler(webSocketHandler)
                }
            )

            let httpHandler = HTTPRelayHandler(forwarder: forwarder, maxMessageBytes: maxMessageBytes)
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
                channel.pipeline.addHandler(ByteToMessageHandler(LineDecoder(maxLength: self.maxLineBytes))).flatMap {
                    channel.pipeline.addHandler(
                        RelayBridgeForwardingHandler(
                            requestData: payload,
                            promise: promise,
                            completion: completion
                        )
                    )
                }
            }
        bootstrap.connect(host: relayHost, port: relayPort).whenFailure { error in
            completion.resolve(promise, .failure(error))
        }
        return promise.futureResult
    }
}

private struct RelayBridgeTimeoutError: LocalizedError {
    var errorDescription: String? { "Relay bridge request timed out." }
}

private final class HTTPRelayHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let forwarder: LocalRelayForwarder
    private let maxMessageBytes: Int?
    private var requestHead: HTTPRequestHead?
    private var requestBody = ByteBuffer()
    private var isRejected = false

    init(forwarder: LocalRelayForwarder, maxMessageBytes: Int?) {
        self.forwarder = forwarder
        self.maxMessageBytes = maxMessageBytes
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            requestHead = head
            requestBody.clear()
            isRejected = false
        case .body(var body):
            guard !isRejected else { return }
            requestBody.writeBuffer(&body)
            if let maxMessageBytes, requestBody.readableBytes > maxMessageBytes {
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
        forwarder.forward(payload, on: context.eventLoop).whenComplete { result in
            switch result {
            case .success(let responseData):
                self.sendHTTPResponse(status: .ok, body: responseData, context: context)
            case .failure(let error):
                let body = Data(#"{"type":"error","error":"Bridge forward failed"}"#.utf8)
                self.sendHTTPResponse(status: .badGateway, body: body, context: context)
                print("[relay] http bridge forward failure: \(error.localizedDescription)")
            }
        }
    }

    private func sendHTTPResponse(status: HTTPResponseStatus, body: Data, context: ChannelHandlerContext) {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: "application/json")
        headers.add(name: "Content-Length", value: "\(body.count)")
        headers.add(name: "Connection", value: "close")
        let responseHead = HTTPResponseHead(version: .http1_1, status: status, headers: headers)
        context.write(wrapOutboundOut(.head(responseHead)), promise: nil)
        var buffer = context.channel.allocator.buffer(capacity: body.count)
        buffer.writeBytes(body)
        context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
            context.close(promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

private final class WebSocketRelayHandler: ChannelInboundHandler {
    typealias InboundIn = WebSocketFrame
    typealias OutboundOut = WebSocketFrame

    private let forwarder: LocalRelayForwarder
    private let maxMessageBytes: Int?

    init(forwarder: LocalRelayForwarder, maxMessageBytes: Int?) {
        self.forwarder = forwarder
        self.maxMessageBytes = maxMessageBytes
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
            guard frame.fin else {
                context.close(promise: nil)
                return
            }
            var payloadBuffer = frame.unmaskedData
            guard let payload = payloadBuffer.readData(length: payloadBuffer.readableBytes) else {
                context.close(promise: nil)
                return
            }
            if let maxMessageBytes, payload.count > maxMessageBytes {
                send(frameType: .text, payload: Data(#"{"type":"error","error":"Payload too large"}"#.utf8), context: context)
                return
            }
            forwarder.forward(payload, on: context.eventLoop).whenComplete { result in
                switch result {
                case .success(let responseData):
                    self.send(frameType: frame.opcode, payload: responseData, context: context)
                case .failure(let error):
                    let response = Data(#"{"type":"error","error":"Bridge forward failed"}"#.utf8)
                    self.send(frameType: .text, payload: response, context: context)
                    print("[relay] websocket bridge forward failure: \(error.localizedDescription)")
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
