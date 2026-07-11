import Foundation
@preconcurrency import NIOCore
@preconcurrency import NIOPosix
@preconcurrency import NIOHTTP1
@preconcurrency import NIOFoundationCompat
@preconcurrency import NIOConcurrencyHelpers

struct OperatorServerStatus: Codable, Equatable {
    let softwareVersion: String
    let uptimeSeconds: Int
    let storage: String
    let transport: String
    let persistenceEnabled: Bool
    let restartRequired: Bool
    let bootstrap: [String: String]
}

struct OperatorStateResponse: Codable, Equatable {
    let status: OperatorServerStatus
    let configuration: OperatorEditableConfiguration
}

final class OperatorControlPlane: @unchecked Sendable {
    private let lock = NIOLock()
    private let configurationStore: RelayConfigurationStore
    private let persistence: OperatorConfigurationPersistence
    private let relayStore: RelayStore
    private let startedAt: Date
    private let bootstrap: [String: String]
    private let storageDescription: String
    private let transportDescription: String
    private let activeRestartControlledSignature: String
    private var editableConfiguration: OperatorEditableConfiguration

    init(
        configurationStore: RelayConfigurationStore,
        persistence: OperatorConfigurationPersistence,
        relayStore: RelayStore,
        startedAt: Date,
        bootstrap: [String: String],
        storageDescription: String,
        transportDescription: String,
        editableConfiguration: OperatorEditableConfiguration? = nil
    ) {
        self.configurationStore = configurationStore
        self.persistence = persistence
        self.relayStore = relayStore
        self.startedAt = startedAt
        self.bootstrap = bootstrap
        self.storageDescription = storageDescription
        self.transportDescription = transportDescription
        let editable = editableConfiguration ?? OperatorEditableConfiguration(configuration: configurationStore.snapshot())
        self.editableConfiguration = editable
        activeRestartControlledSignature = editable.restartControlledSignature
    }

    func state(now: Date = Date()) -> OperatorStateResponse {
        lock.withLock { makeState(now: now) }
    }

    private func makeState(now: Date) -> OperatorStateResponse {
        return OperatorStateResponse(
            status: OperatorServerStatus(
                softwareVersion: ServerConfig.advertisedSoftwareVersion,
                uptimeSeconds: max(0, Int(now.timeIntervalSince(startedAt))),
                storage: storageDescription,
                transport: transportDescription,
                persistenceEnabled: persistence.isAvailable,
                restartRequired: editableConfiguration.restartControlledSignature != activeRestartControlledSignature,
                bootstrap: bootstrap
            ),
            configuration: editableConfiguration
        )
    }

    func update(_ editable: OperatorEditableConfiguration) throws -> OperatorStateResponse {
        try lock.withLock {
            let updated = try editable.validatedConfiguration(from: configurationStore.snapshot())
            if persistence.isAvailable {
                try persistence.save(editable)
            }
            relayStore.updateTemporalBuckets(
                primarySeconds: updated.temporalBucketSeconds,
                scheduleSeconds: updated.temporalBucketScheduleSeconds
            )
            configurationStore.replace(with: updated)
            editableConfiguration = editable
            return makeState(now: Date())
        }
    }
}

func makeOperatorHTTPBootstrap(
    group: EventLoopGroup,
    controlPlane: OperatorControlPlane,
    authenticationToken: String
) -> ServerBootstrap {
    let authenticator = OperatorTokenAuthenticator(expectedToken: authenticationToken)
    return ServerBootstrap(group: group)
        .serverChannelOption(ChannelOptions.backlog, value: 64)
        .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
        .childChannelInitializer { channel in
            channel.pipeline.configureHTTPServerPipeline().flatMap {
                channel.pipeline.addHandler(
                    OperatorHTTPHandler(controlPlane: controlPlane, authenticator: authenticator)
                )
            }
        }
        .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
        .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 8)
        .childChannelOption(ChannelOptions.recvAllocator, value: AdaptiveRecvByteBufferAllocator())
}

final class OperatorTokenAuthenticator: @unchecked Sendable {
    private let expectedBytes: [UInt8]
    private let lock = NIOLock()
    private var failuresBySource: [String: [Date]] = [:]
    private let maximumSources = 2_048
    private let maximumFailuresPerMinute = 12

    init(expectedToken: String) {
        expectedBytes = Array(expectedToken.utf8)
    }

    func authenticate(headers: HTTPHeaders, source: String, now: Date = Date()) -> Bool {
        guard allowAttempt(source: source, now: now) else { return false }
        let values = headers["Authorization"]
        guard values.count == 1,
              values[0].hasPrefix("Bearer ") else {
            recordFailure(source: source, now: now)
            return false
        }
        let supplied = Array(values[0].dropFirst("Bearer ".count).utf8)
        guard constantTimeEqual(supplied, expectedBytes) else {
            recordFailure(source: source, now: now)
            return false
        }
        clearFailures(source: source)
        return true
    }

    private func allowAttempt(source: String, now: Date) -> Bool {
        lock.withLock {
            let cutoff = now.addingTimeInterval(-60)
            let recent = (failuresBySource[source] ?? []).filter { $0 >= cutoff }
            failuresBySource[source] = recent
            return recent.count < maximumFailuresPerMinute
        }
    }

    private func recordFailure(source: String, now: Date) {
        lock.withLock {
            if failuresBySource[source] == nil, failuresBySource.count >= maximumSources {
                failuresBySource.removeValue(forKey: failuresBySource.keys.sorted().first ?? "")
            }
            failuresBySource[source, default: []].append(now)
        }
    }

    private func clearFailures(source: String) {
        lock.withLock { _ = failuresBySource.removeValue(forKey: source) }
    }

    private func constantTimeEqual(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        var difference = UInt64(lhs.count ^ rhs.count)
        let count = max(lhs.count, rhs.count)
        for index in 0..<count {
            let left = index < lhs.count ? lhs[index] : 0
            let right = index < rhs.count ? rhs[index] : 0
            difference |= UInt64(left ^ right)
        }
        return difference == 0
    }
}

private final class OperatorHTTPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private static let maximumBodyBytes = 128 * 1_024
    private let controlPlane: OperatorControlPlane
    private let authenticator: OperatorTokenAuthenticator
    private var requestHead: HTTPRequestHead?
    private var requestBody = ByteBuffer()
    private var rejected = false

    init(controlPlane: OperatorControlPlane, authenticator: OperatorTokenAuthenticator) {
        self.controlPlane = controlPlane
        self.authenticator = authenticator
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            requestHead = head
            requestBody.clear()
            rejected = false
            let lengths = head.headers["Content-Length"]
            if lengths.count > 1 || lengths.contains(where: { Int($0).map { $0 > Self.maximumBodyBytes } ?? true }) {
                rejected = true
                respondJSON(status: .payloadTooLarge, object: ["error": "Request body is too large."], context: context)
            }
        case .body(var body):
            guard !rejected else { return }
            requestBody.writeBuffer(&body)
            if requestBody.readableBytes > Self.maximumBodyBytes {
                rejected = true
                respondJSON(status: .payloadTooLarge, object: ["error": "Request body is too large."], context: context)
            }
        case .end:
            guard !rejected, let head = requestHead else { return }
            route(head: head, context: context)
        }
    }

    private func route(head: HTTPRequestHead, context: ChannelHandlerContext) {
        let path = head.uri.split(separator: "?", maxSplits: 1).first.map(String.init) ?? head.uri
        if head.method == .GET, path == "/" {
            respond(status: .temporaryRedirect, contentType: "text/plain; charset=utf-8", body: Data(), extraHeaders: [("Location", "/admin/")], context: context)
            return
        }
        if head.method == .GET, path == "/admin/" {
            respond(status: .ok, contentType: "text/html; charset=utf-8", body: Data(OperatorWebUI.html.utf8), context: context)
            return
        }
        if head.method == .GET, path == "/admin/assets/app.css" {
            respond(status: .ok, contentType: "text/css; charset=utf-8", body: Data(OperatorWebUI.css.utf8), context: context)
            return
        }
        if head.method == .GET, path == "/admin/assets/app.js" {
            respond(status: .ok, contentType: "text/javascript; charset=utf-8", body: Data(OperatorWebUI.javascript.utf8), context: context)
            return
        }

        guard path.hasPrefix("/admin/api/") else {
            respondJSON(status: .notFound, object: ["error": "Not found."], context: context)
            return
        }
        let source = relayHTTPSourceKey(address: context.channel.remoteAddress, headers: head.headers)
        guard authenticator.authenticate(headers: head.headers, source: source) else {
            respond(
                status: .unauthorized,
                contentType: "application/json; charset=utf-8",
                body: encodedJSON(["error": "Authentication failed."]),
                extraHeaders: [("WWW-Authenticate", "Bearer")],
                context: context
            )
            return
        }
        if head.method == .GET, path == "/admin/api/state" {
            respondEncodable(status: .ok, value: controlPlane.state(), context: context)
            return
        }
        if head.method == .PUT, path == "/admin/api/config" {
            do {
                let data = requestBody.readData(length: requestBody.readableBytes) ?? Data()
                let editable = try operatorJSONDecoder().decode(OperatorEditableConfiguration.self, from: data)
                let state = try controlPlane.update(editable)
                respondEncodable(status: .ok, value: state, context: context)
            } catch {
                respondJSON(
                    status: .badRequest,
                    object: ["error": (error as? LocalizedError)?.errorDescription ?? "Invalid configuration."],
                    context: context
                )
            }
            return
        }
        respondJSON(status: .notFound, object: ["error": "Not found."], context: context)
    }

    private func respondEncodable<T: Encodable>(
        status: HTTPResponseStatus,
        value: T,
        context: ChannelHandlerContext
    ) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(value) else {
            respondJSON(status: .internalServerError, object: ["error": "Encoding failed."], context: context)
            return
        }
        respond(status: status, contentType: "application/json; charset=utf-8", body: data, context: context)
    }

    private func respondJSON(status: HTTPResponseStatus, object: [String: String], context: ChannelHandlerContext) {
        respond(status: status, contentType: "application/json; charset=utf-8", body: encodedJSON(object), context: context)
    }

    private func encodedJSON(_ object: [String: String]) -> Data {
        (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data(#"{"error":"Encoding failed."}"#.utf8)
    }

    private func respond(
        status: HTTPResponseStatus,
        contentType: String,
        body: Data,
        extraHeaders: [(String, String)] = [],
        context: ChannelHandlerContext
    ) {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: contentType)
        headers.add(name: "Content-Length", value: "\(body.count)")
        headers.add(name: "Connection", value: "close")
        for (name, value) in extraHeaders { headers.add(name: name, value: value) }
        OperatorHTTPSecurityHeaders.apply(to: &headers)
        context.write(wrapOutboundOut(.head(HTTPResponseHead(version: .http1_1, status: status, headers: headers))), promise: nil)
        var buffer = context.channel.allocator.buffer(capacity: body.count)
        buffer.writeBytes(body)
        context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        let contextBox = NIOContextBox(context)
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
            contextBox.context.close(promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

enum OperatorHTTPSecurityHeaders {
    static func apply(to headers: inout HTTPHeaders) {
        headers.replaceOrAdd(name: "Cache-Control", value: "no-store")
        headers.replaceOrAdd(name: "Pragma", value: "no-cache")
        headers.replaceOrAdd(name: "X-Content-Type-Options", value: "nosniff")
        headers.replaceOrAdd(name: "X-Frame-Options", value: "DENY")
        headers.replaceOrAdd(name: "Referrer-Policy", value: "no-referrer")
        headers.replaceOrAdd(name: "Cross-Origin-Resource-Policy", value: "same-origin")
        headers.replaceOrAdd(
            name: "Content-Security-Policy",
            value: "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        headers.replaceOrAdd(name: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()")
    }
}
