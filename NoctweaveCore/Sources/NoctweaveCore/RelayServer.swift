import Foundation
import Network

public final class RelayServer {
    public enum Event {
        case started(port: UInt16)
        case stopped
        case error(String)
    }

    public var onEvent: ((Event) -> Void)?

    private let store: RelayStore
    private let opaqueRouteStore: OpaqueRouteRelayStoreV2
    private var listener: NWListener?
    private var localEndpoint: RelayEndpoint?
    private var coordinatorHeartbeatTask: Task<Void, Never>?
    private let coordinatorHeartbeatTaskLock = NSLock()
    private let coordinatorDirectorySigningPrivateKey: Data?
    private let coordinatorDirectoryPublicKey: Data?
    private let coordinatorDirectoryCacheLock = NSLock()
    private var coordinatorDirectoryCache: [FederationNodeRecord] = []
    private let requestRateLimiter = RelayRequestRateLimiter()
    private let configurationLock = NSLock()
    private var relayConfiguration: RelayConfiguration
    public var configuration: RelayConfiguration {
        get {
            configurationLock.lock()
            defer { configurationLock.unlock() }
            return relayConfiguration
        }
        set {
            configurationLock.lock()
            relayConfiguration = newValue
            configurationLock.unlock()
        }
    }
    private let listenerQueue = DispatchQueue(label: "NoctweaveCore.RelayServer")

    public init(
        store: RelayStore,
        opaqueRouteStore: OpaqueRouteRelayStoreV2 = OpaqueRouteRelayStoreV2(),
        configuration: RelayConfiguration = RelayConfiguration()
    ) {
        self.store = store
        self.opaqueRouteStore = opaqueRouteStore
        self.relayConfiguration = configuration
        if configuration.kind == .coordinator {
            let keyData = FederationDirectorySignature.privateKeyData(
                from: configuration.coordinatorDirectorySigningPrivateKey
            )
            self.coordinatorDirectorySigningPrivateKey = keyData
            self.coordinatorDirectoryPublicKey = FederationDirectorySignature.publicKeyData(from: keyData)
        } else {
            self.coordinatorDirectorySigningPrivateKey = nil
            self.coordinatorDirectoryPublicKey = nil
        }
    }

    public func start(port: UInt16) throws {
        try start(host: "0.0.0.0", port: port)
    }

    public func start(host: String, port: UInt16) throws {
        guard listener == nil else {
            return
        }
        let configuration = configuration
        localEndpoint = RelayEndpoint(
            host: host,
            port: port,
            useTLS: configuration.tlsEnabled,
            transport: configuration.transport
        )
        let parameters = try RelayNetworkTransport.listenerParameters(configuration: configuration)
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
            throw RelayNetworkError.connectionFailed
        }
        let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        let listener: NWListener
        if !trimmedHost.isEmpty, trimmedHost != "0.0.0.0" {
            let endpointHost = NWEndpoint.Host(trimmedHost)
            parameters.requiredLocalEndpoint = .hostPort(host: endpointHost, port: endpointPort)
            listener = try NWListener(using: parameters)
        } else {
            listener = try NWListener(using: parameters, on: endpointPort)
        }
        self.listener = listener
        listener.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                // Port zero asks Network.framework for an available local port.
                // Report the actual bound port so callers can establish a
                // race-free ephemeral listener without probing a random port
                // before startup.
                let boundPort = self?.listener?.port?.rawValue ?? port
                self?.localEndpoint?.port = boundPort
                self?.onEvent?(.started(port: boundPort))
            case .failed:
                self?.onEvent?(.error("Listener failed"))
            default:
                break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            switch self.configuration.transport {
            case .tcp:
                self.handleTCP(connection: connection)
            case .http, .websocket:
                self.handleHTTP(connection: connection)
            }
        }
        listener.start(queue: listenerQueue)
        startCoordinatorHeartbeatLoopIfNeeded()
    }

    public func stop() {
        coordinatorHeartbeatTaskLock.lock()
        coordinatorHeartbeatTask?.cancel()
        coordinatorHeartbeatTask = nil
        coordinatorHeartbeatTaskLock.unlock()
        listener?.cancel()
        listener = nil
        onEvent?(.stopped)
    }

    public func updateFederationAllowList(_ allowList: [RelayEndpoint]) {
        mutateConfiguration { configuration in
            configuration.federationAllowList = allowList
        }
    }

    public func updateFederationRuntimeSettings(from updated: RelayConfiguration) {
        let isOpenFederation = updated.federation.mode == .open
        mutateConfiguration { configuration in
            configuration.federation = updated.federation
            configuration.federationAllowList = updated.federationAllowList
            configuration.federationCoordinatorEndpoints = updated.federationCoordinatorEndpoints
            configuration.coordinatorRegistrationToken = updated.coordinatorRegistrationToken
            configuration.coordinatorHeartbeatSeconds = updated.coordinatorHeartbeatSeconds
            configuration.coordinatorDirectoryMaxStalenessSeconds = updated.coordinatorDirectoryMaxStalenessSeconds
            configuration.relayPeerExchangeLimit = isOpenFederation ? updated.relayPeerExchangeLimit : 0
            configuration.openFederationDHTEnabled = isOpenFederation ? updated.openFederationDHTEnabled : false
            configuration.openFederationDHTMaxRecords = updated.openFederationDHTMaxRecords
            configuration.openFederationDHTMaxRecordsPerHost = updated.openFederationDHTMaxRecordsPerHost
            configuration.openFederationDHTMaxQueryRecords = updated.openFederationDHTMaxQueryRecords
            configuration.curatedStrictPolicyEnabled = updated.curatedStrictPolicyEnabled
            configuration.curatedCoordinatorQuorum = updated.curatedCoordinatorQuorum
            configuration.curatedRequireSignedDirectory = updated.curatedRequireSignedDirectory
            configuration.allowPrivateFederationEndpoints = updated.allowPrivateFederationEndpoints
            configuration.advertisedEndpoint = updated.advertisedEndpoint
        }
        startCoordinatorHeartbeatLoopIfNeeded()
    }

    private func mutateConfiguration(_ body: (inout RelayConfiguration) -> Void) {
        configurationLock.lock()
        body(&relayConfiguration)
        configurationLock.unlock()
    }

    private func handleTCP(connection: NWConnection) {
        Task {
            do {
                try await connection.awaitReady()
                let line = try await connection.receiveLine(maxLength: RelayClient.maxResponseBytes)
                let request = try NoctweaveCoder.decode(RelayRequest.self, from: line)
                let response = try await handle(
                    request: request,
                    sourceKey: endpointSourceKey(connection.endpoint)
                )
                let responseData = try NoctweaveCoder.encode(response)
                try await connection.sendLine(responseData)
                connection.cancel()
            } catch {
                onEvent?(.error("Connection error"))
                connection.cancel()
            }
        }
    }

    private func handleHTTP(connection: NWConnection) {
        Task {
            do {
                try await connection.awaitReady()
                let request = try await receiveHTTPMessage(from: connection)
                let responseData = try await processHTTPRequest(
                    request,
                    sourceKey: endpointSourceKey(connection.endpoint)
                )
                try await sendRaw(responseData, on: connection)
            } catch {
                onEvent?(.error("HTTP connection error"))
                let errorResponse = httpResponse(
                    statusCode: 400,
                    reasonPhrase: "Bad Request",
                    body: Data("bad request\n".utf8),
                    contentType: "text/plain; charset=utf-8"
                )
                try? await sendRaw(errorResponse, on: connection)
            }
            connection.cancel()
        }
    }

    private struct HTTPMessage {
        let method: String
        let path: String
        let body: Data
    }

    private func receiveHTTPMessage(from connection: NWConnection) async throws -> HTTPMessage {
        let maxHeaderBytes = 64 * 1024
        let maxBodyBytes = RelayClient.maxResponseBytes
        var buffer = Data()
        var headerEndIndex: Int?
        var contentLength = 0
        var method = ""
        var path = ""
        let separator = Data("\r\n\r\n".utf8)

        while true {
            if let headerEndIndex, buffer.count >= headerEndIndex + contentLength {
                break
            }
            if buffer.count > (maxHeaderBytes + maxBodyBytes) {
                throw RelayNetworkError.responseTooLarge
            }
            let chunk = try await receiveChunk(from: connection)
            buffer.append(chunk)
            if headerEndIndex == nil, let range = buffer.range(of: separator) {
                let headerData = buffer[..<range.lowerBound]
                guard headerData.count <= maxHeaderBytes else {
                    throw RelayNetworkError.responseTooLarge
                }
                guard let headerString = String(data: headerData, encoding: .utf8) else {
                    throw RelayNetworkError.invalidResponse
                }
                let lines = headerString.components(separatedBy: "\r\n")
                guard let requestLine = lines.first, !requestLine.isEmpty else {
                    throw RelayNetworkError.invalidResponse
                }
                let requestParts = requestLine.split(separator: " ", omittingEmptySubsequences: true)
                guard requestParts.count == 3,
                      requestParts[2] == "HTTP/1.1" || requestParts[2] == "HTTP/1.0" else {
                    throw RelayNetworkError.invalidResponse
                }
                method = String(requestParts[0]).uppercased()
                path = String(requestParts[1])
                guard path.hasPrefix("/"),
                      !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                    throw RelayNetworkError.invalidResponse
                }
                if let queryStart = path.firstIndex(of: "?") {
                    path = String(path[..<queryStart])
                }
                var headers: [String: String] = [:]
                for line in lines.dropFirst() where !line.isEmpty {
                    guard !line.hasPrefix(" "), !line.hasPrefix("\t"),
                          let separator = line.firstIndex(of: ":") else {
                        throw RelayNetworkError.invalidResponse
                    }
                    let key = line[..<separator].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !key.isEmpty, headers[key] == nil else {
                        throw RelayNetworkError.invalidResponse
                    }
                    headers[key] = value
                }
                if headers["transfer-encoding"] != nil {
                    throw RelayNetworkError.invalidResponse
                }
                let lengthHeader = headers["content-length"] ?? "0"
                guard let parsedLength = Int(lengthHeader), parsedLength >= 0 else {
                    throw RelayNetworkError.invalidResponse
                }
                guard parsedLength <= maxBodyBytes else {
                    throw RelayNetworkError.responseTooLarge
                }
                contentLength = parsedLength
                headerEndIndex = range.upperBound
            }
        }

        guard let headerEndIndex else {
            throw RelayNetworkError.invalidResponse
        }
        let bodyStart = headerEndIndex
        let bodyEnd = headerEndIndex + contentLength
        guard bodyEnd <= buffer.count else {
            throw RelayNetworkError.invalidResponse
        }
        let body = Data(buffer[bodyStart..<bodyEnd])
        return HTTPMessage(method: method, path: path, body: body)
    }

    private func processHTTPRequest(_ message: HTTPMessage, sourceKey: String?) async throws -> Data {
        switch (message.method, message.path) {
        case ("POST", "/relay"):
            guard !message.body.isEmpty else {
                return httpResponse(
                    statusCode: 400,
                    reasonPhrase: "Bad Request",
                    body: Data("missing request body\n".utf8),
                    contentType: "text/plain; charset=utf-8"
                )
            }
            let request: RelayRequest
            do {
                request = try NoctweaveCoder.decode(RelayRequest.self, from: message.body)
            } catch {
                return httpResponse(
                    statusCode: 400,
                    reasonPhrase: "Bad Request",
                    body: Data("invalid relay request\n".utf8),
                    contentType: "text/plain; charset=utf-8"
                )
            }
            do {
                let response = try await handle(request: request, sourceKey: sourceKey)
                let body = try NoctweaveCoder.encode(response)
                return httpResponse(statusCode: 200, reasonPhrase: "OK", body: body)
            } catch {
                let body = try NoctweaveCoder.encode(RelayResponse.error(
                    "Relay processing failed",
                    code: .internalFailure,
                    retryable: true,
                    respondingTo: request
                ))
                return httpResponse(statusCode: 200, reasonPhrase: "OK", body: body)
            }
        case ("GET", "/relay"):
            return httpResponse(
                statusCode: 405,
                reasonPhrase: "Method Not Allowed",
                body: Data("method not allowed\n".utf8),
                contentType: "text/plain; charset=utf-8"
            )
        default:
            return httpResponse(
                statusCode: 404,
                reasonPhrase: "Not Found",
                body: Data("not found\n".utf8),
                contentType: "text/plain; charset=utf-8"
            )
        }
    }

    private func httpResponse(
        statusCode: Int,
        reasonPhrase: String,
        body: Data,
        contentType: String = "application/json"
    ) -> Data {
        var response = Data()
        var headerLines = [
            "HTTP/1.1 \(statusCode) \(reasonPhrase)",
            "Content-Type: \(contentType)",
            "Content-Length: \(body.count)",
            "Connection: close"
        ]
        RelayHTTPSecurityHeaders.append(to: &headerLines)
        let header = headerLines.joined(separator: "\r\n") + "\r\n\r\n"
        response.append(Data(header.utf8))
        response.append(body)
        return response
    }

    private func sendRaw(_ data: Data, on connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    private func receiveChunk(from connection: NWConnection) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                if isComplete && (data == nil || data?.isEmpty == true) {
                    continuation.resume(throwing: RelayNetworkError.invalidResponse)
                    return
                }
                continuation.resume(returning: data ?? Data())
            }
        }
    }

    private func handle(request: RelayRequest, sourceKey: String? = nil) async throws -> RelayResponse {
        if let sourceKey,
           await !requestRateLimiter.allow(sourceKey: sourceKey) {
            return .error(
                "Rate limit exceeded",
                code: .rateLimited,
                retryable: true,
                respondingTo: request
            )
        }
        if requiresAuthentication(for: request.binding),
           let authFailure = validateAuthentication(token: request.authToken) {
            return .error(
                authFailure,
                code: .authenticationRequired,
                respondingTo: request
            )
        }
        if configuration.kind == .coordinator,
           !isCoordinatorDirectoryRequest(request.binding) {
            return .error(
                "Coordinator relays are directory-only and do not carry user traffic.",
                code: .unavailable,
                respondingTo: request
            )
        }
        switch request.body {
        case .createOpaqueRoute(let payload):
            guard payload.isStructurallyValid else {
                return .error("Invalid opaque route create request", respondingTo: request)
            }
            do {
                return .success(.opaqueRoute(try await opaqueRouteStore.create(
                    payload.request,
                    presentedCapability: payload.renewCapability,
                    confidentialTransport: hasConfidentialRouteTransport(sourceKey),
                    receivedAt: Date()
                )), respondingTo: request)
            } catch {
                return opaqueRouteErrorResponse(error, respondingTo: request)
            }
        case .renewOpaqueRoute(let payload):
            guard payload.isStructurallyValid else {
                return .error("Invalid opaque route renewal request", respondingTo: request)
            }
            do {
                return .success(.opaqueRoute(try await opaqueRouteStore.renew(
                    payload.request,
                    presentedCapability: payload.renewCapability,
                    confidentialTransport: hasConfidentialRouteTransport(sourceKey),
                    receivedAt: Date()
                )), respondingTo: request)
            } catch {
                return opaqueRouteErrorResponse(error, respondingTo: request)
            }
        case .teardownOpaqueRoute(let payload):
            guard payload.isStructurallyValid else {
                return .error("Invalid opaque route teardown request", respondingTo: request)
            }
            do {
                return .success(.opaqueRoute(try await opaqueRouteStore.teardown(
                    payload.request,
                    presentedCapability: payload.teardownCapability,
                    confidentialTransport: hasConfidentialRouteTransport(sourceKey),
                    receivedAt: Date()
                )), respondingTo: request)
            } catch {
                return opaqueRouteErrorResponse(error, respondingTo: request)
            }
        case .appendOpaqueRoute(let payload):
            guard payload.isStructurallyValid else {
                return .error("Invalid opaque route append request", respondingTo: request)
            }
            do {
                return .success(.opaqueRouteAppend(try await opaqueRouteStore.append(
                    payload.packet,
                    presentedCapability: payload.sendCapability,
                    confidentialTransport: hasConfidentialRouteTransport(sourceKey),
                    receivedAt: Date()
                )), respondingTo: request)
            } catch {
                return opaqueRouteErrorResponse(error, respondingTo: request)
            }
        case .syncOpaqueRoute(let payload):
            guard payload.isStructurallyValid else {
                return .error("Invalid opaque route sync request", respondingTo: request)
            }
            do {
                return .success(.opaqueRouteSync(try await opaqueRouteStore.sync(
                    payload.request,
                    presentedCredential: payload.readCredential,
                    confidentialTransport: hasConfidentialRouteTransport(sourceKey),
                    receivedAt: Date()
                )), respondingTo: request)
            } catch {
                return opaqueRouteErrorResponse(error, respondingTo: request)
            }
        case .commitOpaqueRoute(let payload):
            guard payload.isStructurallyValid else {
                return .error("Invalid opaque route commit request", respondingTo: request)
            }
            do {
                return .success(.opaqueRouteCommit(try await opaqueRouteStore.commit(
                    payload.request,
                    presentedCredential: payload.readCredential,
                    confidentialTransport: hasConfidentialRouteTransport(sourceKey),
                    receivedAt: Date()
                )), respondingTo: request)
            } catch {
                return opaqueRouteErrorResponse(error, respondingTo: request)
            }
        case .registerRendezvous(let registration):
            guard configuration.isRendezvousTransportEnabled else {
                return .error("Rendezvous transport is disabled", code: .unavailable, respondingTo: request)
            }
            guard configuration.tlsEnabled || isLiteralLoopbackSource(sourceKey) else {
                return .error("Rendezvous transport requires confidential transport", respondingTo: request)
            }
            guard registration.isStructurallyValid() else {
                return .error("Invalid rendezvous transport request", respondingTo: request)
            }
            do {
                try await store.registerRendezvousTransportV2(registration)
                return .success(.empty, respondingTo: request)
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error, respondingTo: request)
            } catch {
                return .error("Relay storage is unavailable", code: .unavailable, retryable: true, respondingTo: request)
            }
        case .appendRendezvous(let append):
            guard configuration.isRendezvousTransportEnabled else {
                return .error("Rendezvous transport is disabled", code: .unavailable, respondingTo: request)
            }
            guard configuration.tlsEnabled || isLiteralLoopbackSource(sourceKey) else {
                return .error("Rendezvous transport requires confidential transport", respondingTo: request)
            }
            guard append.isStructurallyValid else {
                return .error("Invalid rendezvous transport request", respondingTo: request)
            }
            do {
                _ = try await store.appendRendezvousTransportV2(append)
                return .success(.empty, respondingTo: request)
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error, respondingTo: request)
            } catch {
                return .error("Relay storage is unavailable", code: .unavailable, retryable: true, respondingTo: request)
            }
        case .syncRendezvous(let sync):
            guard configuration.isRendezvousTransportEnabled else {
                return .error("Rendezvous transport is disabled", code: .unavailable, respondingTo: request)
            }
            guard configuration.tlsEnabled || isLiteralLoopbackSource(sourceKey) else {
                return .error("Rendezvous transport requires confidential transport", respondingTo: request)
            }
            guard sync.isStructurallyValid else {
                return .error("Invalid rendezvous transport request", respondingTo: request)
            }
            do {
                return .success(.rendezvousSync(try await store.syncRendezvousTransportV2(sync)), respondingTo: request)
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error, respondingTo: request)
            } catch {
                return .error("Relay storage is unavailable", code: .unavailable, retryable: true, respondingTo: request)
            }
        case .deleteRendezvous(let deletion):
            guard configuration.isRendezvousTransportEnabled else {
                return .error("Rendezvous transport is disabled", code: .unavailable, respondingTo: request)
            }
            guard configuration.tlsEnabled || isLiteralLoopbackSource(sourceKey) else {
                return .error("Rendezvous transport requires confidential transport", respondingTo: request)
            }
            guard deletion.isStructurallyValid else {
                return .error("Invalid rendezvous transport request", respondingTo: request)
            }
            do {
                try await store.deleteRendezvousTransportV2(deletion)
                return .success(.empty, respondingTo: request)
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error, respondingTo: request)
            } catch {
                return .error("Relay storage is unavailable", code: .unavailable, retryable: true, respondingTo: request)
            }
        case .empty:
            switch request.method {
            case .health:
                return .success(.empty, respondingTo: request)
            case .info:
                var info = configuration.makeInfo()
                if configuration.kind == .coordinator {
                    info.coordinatorReportedRelayCount = await store.listFederationNodes(
                        ListFederationNodesRequest(
                            mode: configuration.federation.mode,
                            federationName: configuration.federation.name,
                            onlyHealthy: true,
                            maxStalenessSeconds: configuration.coordinatorDirectoryMaxStalenessSeconds
                        )
                    ).count
                    info.federationDirectoryPublicKey = coordinatorDirectoryPublicKey
                } else {
                    let hints = knownOpenFederationPeers()
                    info.knownOpenPeers = hints.isEmpty ? nil : hints
                }
                return .success(.relayInfo(info), respondingTo: request)
            default:
                return .error("Invalid empty relay request", respondingTo: request)
            }
        case .uploadAttachment(let upload):
            guard configuration.attachmentsEnabled != false else {
                return .error("Attachments are disabled on this relay", code: .unavailable, respondingTo: request)
            }
            let boundedTTL = boundedAttachmentTTL(requested: upload.ttlSeconds)
            do {
                let chunk = try await store.storeAttachment(
                    attachmentId: upload.attachmentId,
                    chunkIndex: upload.chunkIndex,
                    payload: upload.payload,
                    ttlSeconds: boundedTTL
                )
                return .success(.attachment(chunk), respondingTo: request)
            } catch RelayStoreError.invalidChunkIndex {
                return .error("Invalid chunk index", respondingTo: request)
            } catch RelayStoreError.invalidAttachmentPayload {
                return .error("Invalid attachment payload", respondingTo: request)
            } catch {
                return .error("Attachment store error", code: .unavailable, retryable: true, respondingTo: request)
            }
        case .fetchAttachment(let fetch):
            guard configuration.attachmentsEnabled != false else {
                return .error("Attachments are disabled on this relay", code: .unavailable, respondingTo: request)
            }
            do {
                if let chunk = try await store.fetchAttachment(
                    attachmentId: fetch.attachmentId,
                    chunkIndex: fetch.chunkIndex
                ) {
                    return .success(.attachment(chunk), respondingTo: request)
                }
                return .error("Attachment not found", code: .notFound, respondingTo: request)
            } catch RelayStoreError.invalidChunkIndex {
                return .error("Invalid chunk index", respondingTo: request)
            } catch {
                return .error("Attachment store error", code: .unavailable, retryable: true, respondingTo: request)
            }
        case .registerFederationNode(let registration):
            guard configuration.kind == .coordinator else {
                return .error("This relay is not a coordinator node.", code: .unavailable, respondingTo: request)
            }
            if let authFailure = validateCoordinatorRegistrationAuthentication(token: request.authToken) {
                return .error(authFailure, code: .authenticationRequired, respondingTo: request)
            }
            let federationSource = normalizedFederationSourceKey(sourceKey)
            let allowed = await store.allowFederationRegistration(
                sourceKey: federationSource,
                endpoint: registration.endpoint
            )
            guard allowed else {
                return .error("Coordinator registration throttled. Retry later.", code: .rateLimited, retryable: true, respondingTo: request)
            }
            if let reachabilityFailure = try await validateFederationRegistrationReachability(registration) {
                return .error(reachabilityFailure, code: .invalidRequest, respondingTo: request)
            }
            do {
                let node = try await store.registerFederationNode(registration)
                return .success(.federationNodes(FederationNodesResponseBody(nodes: [node])), respondingTo: request)
            } catch {
                return .error("Coordinator registration failed", code: .unavailable, retryable: true, respondingTo: request)
            }
        case .listFederationNodes(let listRequest):
            if configuration.kind == .coordinator {
                let federationSource = normalizedFederationSourceKey(sourceKey)
                let allowed = await store.allowFederationDirectoryList(sourceKey: federationSource)
                guard allowed else {
                    return .error("Coordinator directory listing throttled. Retry later.", code: .rateLimited, retryable: true, respondingTo: request)
                }
                let nodes = await store.listFederationNodes(listRequest)
                let snapshot = makeCoordinatorDirectorySnapshot(nodes: nodes, request: listRequest)
                if listRequest.requireSignedSnapshot == true, snapshot == nil {
                    return .error("Coordinator snapshot signing is not available.", code: .unavailable, respondingTo: request)
                }
                return .success(.federationNodes(FederationNodesResponseBody(nodes: nodes, snapshot: snapshot)), respondingTo: request)
            }
            let remoteNodes = try await fetchCoordinatorNodeDirectory(request: listRequest)
            return .success(.federationNodes(FederationNodesResponseBody(nodes: remoteNodes)), respondingTo: request)
        case .publishDHTRecord(let publish):
            guard let dhtConfiguration = openFederationDHTConfiguration() else {
                return .error("Open-federation DHT is available only on DHT-enabled open non-coordinator relays.", code: .unavailable, respondingTo: request)
            }
            let expectedNamespace = OpenFederationDHTRecord.namespace(federationName: dhtConfiguration.federationName)
            guard publish.namespace == expectedNamespace else {
                return .error("Open-federation DHT namespace mismatch.", respondingTo: request)
            }
            let result = await store.ingestOpenFederationDHTRecords(
                [publish.record],
                configuration: dhtConfiguration
            )
            guard !result.accepted.isEmpty else {
                let reason = result.rejected.first.map { "\($0.reason)" } ?? "record rejected"
                return .error("Open-federation DHT record rejected: \(reason)", respondingTo: request)
            }
            return .success(.empty, respondingTo: request)
        case .listDHTRecords(let list):
            guard let dhtConfiguration = openFederationDHTConfiguration() else {
                return .error("Open-federation DHT is available only on DHT-enabled open non-coordinator relays.", code: .unavailable, respondingTo: request)
            }
            let expectedNamespace = OpenFederationDHTRecord.namespace(federationName: dhtConfiguration.federationName)
            guard list.namespace == expectedNamespace else {
                return .error("Open-federation DHT namespace mismatch.", respondingTo: request)
            }
            let records = await store.listOpenFederationDHTRecords(
                configuration: dhtConfiguration,
                limit: list.limit
            )
            return .success(.dhtRecords(records), respondingTo: request)
        }
    }

    private func hasConfidentialRouteTransport(_ sourceKey: String?) -> Bool {
        configuration.tlsEnabled || isLiteralLoopbackSource(sourceKey)
    }

    private func opaqueRouteErrorResponse(
        _ error: Error,
        respondingTo request: RelayRequest
    ) -> RelayResponse {
        if let error = error as? OpaqueRouteRelayStoreV2Error {
            switch error {
            case .routeNotFound:
                return .error("Opaque route is unavailable", code: .notFound, respondingTo: request)
            case .invalidRequest:
                return .error("Invalid opaque route request", respondingTo: request)
            case .invalidCursor:
                return .error("Invalid opaque route cursor", respondingTo: request)
            case .cursorExpired:
                return .error("Opaque route cursor expired", code: .conflict, respondingTo: request)
            case .cursorAheadOfRoute:
                return .error("Opaque route cursor is ahead of the route", code: .conflict, respondingTo: request)
            case .packetIdentifierConflict:
                return .error("Opaque route packet identifier conflict", code: .conflict, respondingTo: request)
            case .requestIdentifierConflict:
                return .error("Opaque route request identifier conflict", code: .conflict, respondingTo: request)
            case .routeQuotaExceeded:
                return .error("Opaque route quota reached", code: .capacity, respondingTo: request)
            case .routeCapacityExceeded:
                return .error("Opaque route capacity reached", code: .capacity, respondingTo: request)
            case .packetIdentifierLedgerExhausted:
                return .error("Opaque route packet ledger exhausted", code: .capacity, respondingTo: request)
            case .requestReceiptLedgerExhausted:
                return .error("Opaque route request ledger exhausted", code: .capacity, respondingTo: request)
            case .sequenceExhausted:
                return .error("Opaque route sequence exhausted", code: .capacity, respondingTo: request)
            }
        }
        if let error = error as? OpaqueRouteV2Error {
            switch error {
            case .confidentialTransportRequired:
                return .error("Opaque routes require confidential transport", respondingTo: request)
            case .invalidAuthorization, .authorizationExpired, .authorizationReplay:
                return .error("Opaque route authorization failed", code: .authenticationRequired, respondingTo: request)
            case .routeExpired, .routeTornDown:
                return .error("Opaque route is unavailable", code: .notFound, respondingTo: request)
            case .routeAlreadyExists, .idempotencyConflict:
                return .error("Opaque route idempotency conflict", code: .conflict, respondingTo: request)
            case .staleTransition, .transitionOutOfOrder, .transitionFork:
                return .error("Opaque route transition rejected", code: .conflict, respondingTo: request)
            case .renewalSequenceExhausted:
                return .error("Opaque route renewal sequence exhausted", code: .capacity, respondingTo: request)
            case .authorizationLedgerExhausted:
                return .error("Opaque route authorization ledger exhausted", code: .capacity, respondingTo: request)
            case .invalidRouteIdentifier, .invalidCredential, .invalidIdempotencyKey,
                 .invalidPolicy, .invalidLease, .invalidRequest, .routeMismatch:
                return .error("Invalid opaque route request", respondingTo: request)
            }
        }
        return .error("Opaque route storage is unavailable", code: .unavailable, retryable: true, respondingTo: request)
    }

    private func relayStoreErrorResponse(
        _ error: RelayStoreError,
        respondingTo request: RelayRequest
    ) -> RelayResponse {
        switch error {
        case .invalidRendezvousRoute:
            return .error("Invalid rendezvous transport request", respondingTo: request)
        case .rendezvousRouteUnavailable:
            return .error("Rendezvous route is unavailable", code: .notFound, respondingTo: request)
        case .rendezvousRegistrationConflict:
            return .error("Rendezvous route registration conflicts with stored state", code: .conflict, respondingTo: request)
        case .rendezvousCapacityReached:
            return .error("Rendezvous transport capacity reached", code: .capacity, respondingTo: request)
        case .rendezvousFrameConflict:
            return .error("Rendezvous frame conflicts with stored state", code: .conflict, respondingTo: request)
        case .rendezvousSequenceGap:
            return .error("Rendezvous lane sequence is not contiguous", code: .conflict, respondingTo: request)
        case .rendezvousQuotaReached:
            return .error("Rendezvous lane quota reached", code: .capacity, respondingTo: request)
        case .relayCapacityExceeded:
            return .error("Relay storage capacity reached", code: .capacity, respondingTo: request)
        case .invalidChunkIndex:
            return .error("Invalid chunk index", respondingTo: request)
        case .invalidAttachmentPayload:
            return .error("Invalid attachment payload", respondingTo: request)
        }
    }

    private func requiresAuthentication(for binding: RelayOperationBinding) -> Bool {
        binding.module != .core
            && !(binding.module == .federation && [.register, .list].contains(binding.method))
    }

    private func isCoordinatorDirectoryRequest(_ binding: RelayOperationBinding) -> Bool {
        binding.module == .core
            || (binding.module == .federation && [.register, .list].contains(binding.method))
    }

    private func validateAuthentication(token: String?) -> String? {
        let expected = configuration.accessPassword?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !expected.isEmpty else {
            return nil
        }
        guard expected.utf8.count <= 4_096,
              let token,
              token.utf8.count <= 4_096 else {
            return "Unauthorized: relay password is required."
        }
        let provided = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard secureCompare(provided, expected) else {
            return "Unauthorized: relay password is required."
        }
        return nil
    }

    private func validateCoordinatorRegistrationAuthentication(token: String?) -> String? {
        let expected = configuration.coordinatorRegistrationToken?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if expected.isEmpty, configuration.federation.mode == .curated {
            return "Coordinator configuration error: curated registration requires a token."
        }
        guard !expected.isEmpty else {
            return nil
        }
        guard expected.utf8.count <= 4_096,
              let token,
              token.utf8.count <= 4_096 else {
            return "Unauthorized: coordinator registration token is required."
        }
        let provided = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard secureCompare(provided, expected) else {
            return "Unauthorized: coordinator registration token is required."
        }
        return nil
    }

    private func normalizedFederationSourceKey(_ value: String?) -> String {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        return trimmed.isEmpty ? "unknown" : trimmed
    }

    private func endpointSourceKey(_ endpoint: NWEndpoint?) -> String? {
        guard let endpoint else { return nil }
        switch endpoint {
        case .hostPort(let host, _):
            return String(describing: host).lowercased()
        case .service(let name, let type, let domain, _):
            return "service:\(name.lowercased()):\(type.lowercased()):\(domain.lowercased())"
        case .unix(let path):
            return "unix:\(path)"
        default:
            return String(describing: endpoint).lowercased()
        }
    }

    private func isLiteralLoopbackSource(_ source: String?) -> Bool {
        source == "127.0.0.1" || source == "::1" || source == "0:0:0:0:0:0:0:1"
    }

    private func validateFederationRegistrationReachability(
        _ registration: FederationNodeRegistrationRequest
    ) async throws -> String? {
        guard registration.relayInfo.federation.mode == configuration.federation.mode else {
            return "Coordinator registration rejected: node federation mode differs from coordinator policy."
        }
        if let coordinatorName = configuration.federation.name?.trimmingCharacters(in: .whitespacesAndNewlines),
           !coordinatorName.isEmpty,
           registration.relayInfo.federation.name != coordinatorName {
            return "Coordinator registration rejected: node federation name differs from coordinator policy."
        }
        if configuration.federation.mode == .open,
           !configuration.allowPrivateFederationEndpoints,
           (!registration.endpoint.useTLS || !PublicRelayEndpointPolicy.permits(registration.endpoint)) {
            return "Coordinator registration rejected: open-federation endpoint must use TLS and be publicly routable."
        }
        guard let info = try await fetchRelayInfo(endpoint: registration.endpoint) else {
            return "Coordinator registration rejected: endpoint is unreachable or did not return relay info."
        }
        guard info.federation.mode == registration.relayInfo.federation.mode else {
            return "Coordinator registration rejected: federation mode mismatch."
        }
        if let expectedName = registration.relayInfo.federation.name?.trimmingCharacters(in: .whitespacesAndNewlines),
           !expectedName.isEmpty,
           info.federation.name != expectedName {
            return "Coordinator registration rejected: federation name mismatch."
        }
        return nil
    }

    private func secureCompare(_ lhs: String, _ rhs: String) -> Bool {
        let lhsBytes = Array(lhs.utf8)
        let rhsBytes = Array(rhs.utf8)
        var difference = lhsBytes.count ^ rhsBytes.count
        for index in 0..<max(lhsBytes.count, rhsBytes.count) {
            let left = index < lhsBytes.count ? lhsBytes[index] : 0
            let right = index < rhsBytes.count ? rhsBytes[index] : 0
            difference |= Int(left ^ right)
        }
        return difference == 0
    }

    private func coordinatorEndpoints() -> [RelayEndpoint] {
        (configuration.federationCoordinatorEndpoints ?? []).filter { endpoint in
            !endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
    }

    private func coordinatorHeartbeatInterval() -> TimeInterval {
        let configured = configuration.coordinatorHeartbeatSeconds ?? 45
        return TimeInterval(max(15, configured))
    }

    private func effectiveAdvertisedEndpoint() -> RelayEndpoint? {
        if let explicit = configuration.advertisedEndpoint {
            return explicit
        }
        guard let local = localEndpoint else {
            return nil
        }
        let host = local.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if host.isEmpty || host == "0.0.0.0" || host == "::" {
            return nil
        }
        return local
    }

    private func startCoordinatorHeartbeatLoopIfNeeded() {
        guard listener != nil else {
            return
        }
        coordinatorHeartbeatTaskLock.lock()
        defer { coordinatorHeartbeatTaskLock.unlock() }
        coordinatorHeartbeatTask?.cancel()
        coordinatorHeartbeatTask = nil
        guard configuration.kind != .coordinator else {
            return
        }
        guard !coordinatorEndpoints().isEmpty else {
            return
        }
        coordinatorHeartbeatTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                do {
                    try await self.sendCoordinatorHeartbeat()
                    if self.configuration.federation.mode == .open {
                        _ = try? await self.fetchCoordinatorNodeDirectory(
                            request: ListFederationNodesRequest(
                                mode: .open,
                                federationName: self.configuration.federation.name,
                                onlyHealthy: true,
                                maxStalenessSeconds: self.configuration.coordinatorDirectoryMaxStalenessSeconds,
                                requireSignedSnapshot: true
                            )
                        )
                    }
                } catch {
                    self.onEvent?(.error("Coordinator heartbeat failed"))
                }
                let waitNanos = UInt64(self.coordinatorHeartbeatInterval() * 1_000_000_000)
                try? await Task.sleep(nanoseconds: waitNanos)
            }
        }
    }

    private func sendCoordinatorHeartbeat() async throws {
        guard let advertisedEndpoint = effectiveAdvertisedEndpoint() else {
            onEvent?(.error("Coordinator heartbeat skipped: advertised endpoint is not configured."))
            return
        }
        let interval = coordinatorHeartbeatInterval()
        let ttl = max(Int(interval * 3), 60)
        var info = configuration.makeInfo(now: Date())
        let hints = knownOpenFederationPeers()
        info.knownOpenPeers = hints.isEmpty ? nil : hints
        let request = RelayRequest.registerFederationNode(
            FederationNodeRegistrationRequest(
                endpoint: advertisedEndpoint,
                relayInfo: info,
                ttlSeconds: ttl
            )
        ).withAuthToken(configuration.coordinatorRegistrationToken)
        for coordinator in coordinatorEndpoints() {
            let client = RelayClient(endpoint: coordinator)
            _ = try await client.send(request)
        }
    }

    private func fetchCoordinatorNodeDirectory(request: ListFederationNodesRequest) async throws -> [FederationNodeRecord] {
        let coordinators = coordinatorEndpoints()
        guard !coordinators.isEmpty else {
            return []
        }
        var merged: [String: FederationNodeRecord] = [:]
        var firstError: Error?
        let maxStaleness = max(30, request.maxStalenessSeconds ?? configuration.coordinatorDirectoryMaxStalenessSeconds ?? 300)
        let effectiveRequest = ListFederationNodesRequest(
            mode: request.mode ?? configuration.federation.mode,
            federationName: request.federationName ?? configuration.federation.name,
            onlyHealthy: request.onlyHealthy ?? true,
            maxStalenessSeconds: maxStaleness,
            requireSignedSnapshot: request.requireSignedSnapshot ?? configuration.curatedRequireSignedDirectory
        )
        for coordinator in coordinators {
            do {
                let nodes = try await fetchValidatedCoordinatorNodes(
                    from: coordinator,
                    request: effectiveRequest
                )
                for node in nodes {
                    let key = endpointKey(node.endpoint)
                    if let existing = merged[key] {
                        if node.lastHeartbeatAt > existing.lastHeartbeatAt {
                            merged[key] = node
                        }
                    } else {
                        merged[key] = node
                    }
                }
            } catch {
                if firstError == nil {
                    firstError = error
                }
            }
        }
        let sorted = merged.values.sorted { lhs, rhs in
            if lhs.lastHeartbeatAt != rhs.lastHeartbeatAt {
                return lhs.lastHeartbeatAt > rhs.lastHeartbeatAt
            }
            return lhs.endpoint.host < rhs.endpoint.host
        }
        if sorted.isEmpty, let firstError {
            throw firstError
        }
        setCoordinatorDirectoryCache(sorted)
        return sorted
    }

    private func fetchValidatedCoordinatorNodes(
        from coordinator: RelayEndpoint,
        request: ListFederationNodesRequest
    ) async throws -> [FederationNodeRecord] {
        let client = RelayClient(endpoint: coordinator)
        let infoResponse = try await client.send(.info())
        guard case .relayInfo(let relayInfo)? = infoResponse.successBody else {
            return []
        }
        let advertisedPublicKey = relayInfo.federationDirectoryPublicKey
        let trustedPublicKey = coordinator.directorySigningPublicKey
        if let trustedPublicKey, let advertisedPublicKey, trustedPublicKey != advertisedPublicKey {
            throw RelayNetworkError.invalidResponse
        }
        let response = try await client.send(.listFederationNodes(request))
        guard case .federationNodes(let directory)? = response.successBody else {
            return []
        }
        if request.requireSignedSnapshot == true, trustedPublicKey == nil {
            throw RelayNetworkError.invalidResponse
        }
        return try validatedCoordinatorNodes(
            directory: directory,
            request: request,
            trustedPublicKey: trustedPublicKey
        )
    }

    private func makeCoordinatorDirectorySnapshot(
        nodes: [FederationNodeRecord],
        request: ListFederationNodesRequest
    ) -> FederationDirectorySnapshot? {
        guard configuration.kind == .coordinator,
              let privateKey = coordinatorDirectorySigningPrivateKey else {
            return nil
        }
        let issuedAt = Date()
        let maxStaleness = max(30, request.maxStalenessSeconds ?? configuration.coordinatorDirectoryMaxStalenessSeconds ?? 300)
        let validFor = max(30, min(maxStaleness, max(Int(coordinatorHeartbeatInterval() * 2), 60)))
        let unsigned = FederationDirectorySnapshot(
            mode: request.mode ?? configuration.federation.mode,
            federationName: request.federationName ?? configuration.federation.name,
            issuedAt: issuedAt,
            validUntil: issuedAt.addingTimeInterval(TimeInterval(validFor)),
            maxStalenessSeconds: maxStaleness,
            nodes: nodes
        )
        return try? FederationDirectorySignature.signedSnapshot(from: unsigned, privateKeyData: privateKey)
    }

    private func validatedCoordinatorNodes(
        directory: FederationNodesResponseBody,
        request: ListFederationNodesRequest,
        trustedPublicKey: Data?
    ) throws -> [FederationNodeRecord] {
        if let snapshot = directory.snapshot {
            if let mode = request.mode, snapshot.mode != mode {
                throw RelayNetworkError.invalidResponse
            }
            if let expectedName = request.federationName?.trimmingCharacters(in: .whitespacesAndNewlines),
               !expectedName.isEmpty,
               snapshot.federationName != expectedName {
                throw RelayNetworkError.invalidResponse
            }
            guard snapshot.validUntil > Date() else {
                throw RelayNetworkError.invalidResponse
            }
            if request.requireSignedSnapshot == true {
                guard let trustedPublicKey,
                      FederationDirectorySignature.verify(snapshot: snapshot, trustedPublicKey: trustedPublicKey) else {
                    throw RelayNetworkError.invalidResponse
                }
            } else if let trustedPublicKey, snapshot.signature != nil {
                guard FederationDirectorySignature.verify(snapshot: snapshot, trustedPublicKey: trustedPublicKey) else {
                    throw RelayNetworkError.invalidResponse
                }
            }
            return applyFreshnessPolicy(nodes: snapshot.nodes, request: request)
        }
        if request.requireSignedSnapshot == true {
            throw RelayNetworkError.invalidResponse
        }
        return applyFreshnessPolicy(nodes: directory.nodes, request: request)
    }

    private func applyFreshnessPolicy(
        nodes: [FederationNodeRecord],
        request: ListFederationNodesRequest
    ) -> [FederationNodeRecord] {
        let now = Date()
        var filtered = nodes
        if request.onlyHealthy == true {
            filtered = filtered.filter { $0.expiresAt > now }
        }
        if let maxStaleness = request.maxStalenessSeconds, maxStaleness > 0 {
            let cutoff = now.addingTimeInterval(-TimeInterval(maxStaleness))
            filtered = filtered.filter { $0.lastHeartbeatAt >= cutoff }
        }
        return filtered
    }

    private func endpointKey(_ endpoint: RelayEndpoint) -> String {
        "\(endpoint.host.lowercased()):\(endpoint.port):\(endpoint.useTLS ? 1 : 0):\(endpoint.transport.rawValue)"
    }

    private func knownOpenFederationPeers() -> [RelayEndpoint] {
        guard configuration.federation.mode == .open,
              configuration.kind != .coordinator else {
            return []
        }
        let limit = max(0, configuration.relayPeerExchangeLimit ?? 12)
        guard limit > 0 else {
            return []
        }
        let selfEndpoint = effectiveAdvertisedEndpoint()
        var seen = Set<String>()
        var peers: [RelayEndpoint] = []
        for node in coordinatorDirectoryCacheSnapshot() {
            guard node.relayInfo.federation.mode == .open,
                  node.relayInfo.kind != .coordinator else {
                continue
            }
            if let selfEndpoint, node.endpoint == selfEndpoint {
                continue
            }
            let key = endpointKey(node.endpoint)
            if seen.contains(key) {
                continue
            }
            seen.insert(key)
            peers.append(node.endpoint)
            if peers.count >= limit {
                break
            }
        }
        return peers
    }

    private func openFederationDHTConfiguration() -> OpenFederationDHTDiscoveryConfiguration? {
        guard configuration.federation.mode == .open,
              configuration.kind != .coordinator,
              configuration.openFederationDHTEnabled else {
            return nil
        }
        return OpenFederationDHTDiscoveryConfiguration(
            isEnabled: true,
            federationName: configuration.federation.name,
            requirePublicEndpoint: !configuration.allowPrivateFederationEndpoints,
            maxRecords: configuration.openFederationDHTMaxRecords,
            maxRecordsPerHost: configuration.openFederationDHTMaxRecordsPerHost,
            maxQueryRecords: configuration.openFederationDHTMaxQueryRecords
        )
    }

    private func boundedAttachmentTTL(requested: Int?) -> Int {
        let defaultTTL = max(60, configuration.attachmentDefaultTTLSeconds)
        let maxTTL = max(defaultTTL, configuration.attachmentMaxTTLSeconds)
        guard let requested else {
            return defaultTTL
        }
        return min(max(60, requested), maxTTL)
    }

    private func isDestinationAllowedByCoordinator(_ destination: RelayEndpoint) async throws -> Bool {
        let coordinators = coordinatorEndpoints()
        guard !coordinators.isEmpty else {
            return false
        }
        let nodes = try await fetchCoordinatorNodeDirectory(
            request: ListFederationNodesRequest(
                mode: configuration.federation.mode,
                federationName: configuration.federation.name,
                onlyHealthy: true,
                maxStalenessSeconds: configuration.coordinatorDirectoryMaxStalenessSeconds,
                requireSignedSnapshot: configuration.curatedRequireSignedDirectory
            )
        )
        return nodes.contains(where: { $0.endpoint == destination })
    }

    private func destinationSeenByCoordinatorCount(
        _ destination: RelayEndpoint,
        request: ListFederationNodesRequest
    ) async throws -> Int {
        let coordinators = coordinatorEndpoints()
        guard !coordinators.isEmpty else {
            return 0
        }
        var count = 0
        var firstError: Error?
        for coordinator in coordinators {
            do {
                let nodes = try await fetchValidatedCoordinatorNodes(from: coordinator, request: request)
                if nodes.contains(where: { $0.endpoint == destination }) {
                    count += 1
                }
            } catch {
                if firstError == nil {
                    firstError = error
                }
            }
        }
        if count == 0, let firstError {
            throw firstError
        }
        return count
    }

    private func fetchRelayInfo(endpoint: RelayEndpoint) async throws -> RelayInfo? {
        let client = RelayClient(endpoint: endpoint)
        let response = try await client.send(.info())
        guard case .relayInfo(let info)? = response.successBody else {
            return nil
        }
        return info
    }

    private func setCoordinatorDirectoryCache(_ nodes: [FederationNodeRecord]) {
        coordinatorDirectoryCacheLock.lock()
        coordinatorDirectoryCache = nodes
        coordinatorDirectoryCacheLock.unlock()
    }

    private func coordinatorDirectoryCacheSnapshot() -> [FederationNodeRecord] {
        coordinatorDirectoryCacheLock.lock()
        defer { coordinatorDirectoryCacheLock.unlock() }
        return coordinatorDirectoryCache
    }
}

enum RelayHTTPSecurityHeaders {
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

    static func append(to lines: inout [String]) {
        for field in fields {
            lines.append("\(field.name): \(field.value)")
        }
    }
}

actor RelayRequestRateLimiter {
    private let maxRequests: Int
    private let windowSeconds: TimeInterval
    private let maxSources: Int
    private var attemptsBySource: [String: [Date]] = [:]

    init(maxRequests: Int = 240, windowSeconds: TimeInterval = 60, maxSources: Int = 10_000) {
        self.maxRequests = max(1, maxRequests)
        self.windowSeconds = max(1, windowSeconds)
        self.maxSources = max(1, maxSources)
    }

    func allow(sourceKey: String, now: Date = Date()) -> Bool {
        let source = normalized(sourceKey)
        let cutoff = now.addingTimeInterval(-windowSeconds)
        attemptsBySource = attemptsBySource.compactMapValues { attempts in
            let filtered = attempts.filter { $0 >= cutoff }
            return filtered.isEmpty ? nil : filtered
        }

        var attempts = attemptsBySource[source, default: []]
        guard attempts.count < maxRequests else {
            attemptsBySource[source] = attempts
            return false
        }
        if attemptsBySource[source] == nil,
           attemptsBySource.count >= maxSources,
           let oldestSource = attemptsBySource.min(by: {
               ($0.value.first ?? now) < ($1.value.first ?? now)
           })?.key {
            attemptsBySource.removeValue(forKey: oldestSource)
        }
        attempts.append(now)
        attemptsBySource[source] = attempts
        return true
    }

    private func normalized(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return trimmed.isEmpty ? "unknown" : trimmed
    }
}
