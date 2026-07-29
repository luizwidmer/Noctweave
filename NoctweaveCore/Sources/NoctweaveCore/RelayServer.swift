import Foundation
import Network

public final class RelayServer {
    public enum Event {
        case started(port: UInt16)
        case stopped
        case error(String)
    }

    public var onEvent: ((Event) -> Void)?
    /// Optional host-owned durability hook. When configured, every successful
    /// opaque-route mutation is acknowledged only after the validated snapshot
    /// has been persisted by the host.
    public var onOpaqueRouteStateSnapshot: (@Sendable (OpaqueRouteRelayStateSnapshotV2) async throws -> Void)?
    /// Optional host-owned persistence hook for the public, signed Noctweb
    /// suffix ledger. The records contain no private key material.
    public var onNoctwebNamespaceStateSnapshot:
        (@Sendable ([NoctwebNamespaceRecordV1]) async -> Void)?

    private let store: RelayStore
    private let opaqueRouteStore: OpaqueRouteRelayStoreV2
    private let noctwebHostStore: RelayNoctwebHostStore?
    private let noctwebNamespaceRuntime =
        NoctwebNamespaceRuntimeV1()
    private var listener: NWListener?
    private var localEndpoint: RelayEndpoint?
    private var coordinatorHeartbeatTask: Task<Void, Never>?
    private let coordinatorHeartbeatTaskLock = NSLock()
    private let coordinatorDirectorySigningPrivateKey: Data?
    private let coordinatorDirectoryPublicKey: Data?
    private let coordinatorDirectoryCacheLock = NSLock()
    private var coordinatorDirectoryCache: [FederationNodeRecord] = []
    private let relayIdentityKeyMaterial: RelayIdentityKeyMaterialV1?
    private let relayIdentitySequenceLock = NSLock()
    private var relayIdentityClaimSequence = 0
    private var cachedRelayIdentity: SignedRelayIdentityClaimV1?
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
        configuration: RelayConfiguration = RelayConfiguration(),
        relayIdentity: RelayIdentityKeyMaterialV1? = nil,
        noctwebHostStore: RelayNoctwebHostStore? = nil
    ) {
        self.store = store
        self.opaqueRouteStore = opaqueRouteStore
        self.noctwebHostStore = noctwebHostStore
        self.relayConfiguration = configuration
        self.relayIdentityKeyMaterial = relayIdentity
            ?? (try? RelayIdentityKeyMaterialV1.generate())
        let coordinatorKeyMaterial: (privateKey: Data, publicKey: Data)?
        if configuration.kind == .coordinator {
            do {
                let keyData = try FederationDirectorySignature.privateKeyDataThrowing(
                    from: configuration.coordinatorDirectorySigningPrivateKey
                )
                coordinatorKeyMaterial = (
                    keyData,
                    try FederationDirectorySignature.publicKeyDataThrowing(from: keyData)
                )
            } catch {
                coordinatorKeyMaterial = nil
            }
        } else {
            coordinatorKeyMaterial = nil
        }
        self.coordinatorDirectorySigningPrivateKey = coordinatorKeyMaterial?.privateKey
        self.coordinatorDirectoryPublicKey = coordinatorKeyMaterial?.publicKey
    }

    public func start(port: UInt16) throws {
        try start(host: "0.0.0.0", port: port)
    }

    /// Captures opaque-route runtime state for the host application's durable
    /// encrypted relay snapshot. Core does not persist this data itself.
    public func opaqueRouteStateSnapshot() async throws -> OpaqueRouteRelayStateSnapshotV2 {
        try await opaqueRouteStore.snapshot()
    }

    /// Restores opaque-route runtime state from an explicit validated snapshot.
    /// The host must load it from its encrypted persistence boundary.
    public func restoreOpaqueRouteState(
        from snapshot: OpaqueRouteRelayStateSnapshotV2
    ) async throws {
        try await opaqueRouteStore.restore(snapshot)
    }

    public func noctwebNamespaceRecords() async
        -> [NoctwebNamespaceRecordV1]
    {
        await noctwebNamespaceRuntime.records()
    }

    public func restoreNoctwebNamespaceRecords(
        _ records: [NoctwebNamespaceRecordV1]
    ) async throws {
        try await noctwebNamespaceRuntime.restore(records)
    }

    public func start(host: String, port: UInt16) throws {
        guard listener == nil else {
            return
        }
        let configuration = configuration
        guard configuration.kind != .passthrough,
              !configuration.isNetHostEnabled
                || noctwebHostStore != nil else {
            // Passthrough requires the Linux forwarding runtime. Hosting
            // requires an explicitly supplied bounded native host store.
            throw RelayNetworkError.connectionFailed
        }
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
                if let self {
                    Task {
                        await self.activateConfiguredNoctwebNamespace()
                    }
                }
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

    private func activateConfiguredNoctwebNamespace() async {
        guard configuration.noctwebRelaySuffix != nil else {
            return
        }
        do {
            let identity = try makeCurrentSignedRelayIdentity()
            guard let suffix = identity.claim.noctwebSuffix else {
                return
            }
            let previous = await noctwebNamespaceRuntime.record(
                for: suffix
            )
            let record = try await noctwebNamespaceRuntime.claim(identity)
            await publishNoctwebNamespaceState()
            if previous != record {
                await propagateNoctwebNamespaceMutation(
                    .claimNoctwebNamespaceV1(
                        NoctwebNamespaceClaimRequestV1(
                            identity: identity
                        )
                    )
                )
            }
        } catch {
            onEvent?(.error(
                "Configured Noctweb namespace could not be activated."
            ))
        }
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
                let request: RelayRequest
                do {
                    request = try NoctweaveCoder.decode(RelayRequest.self, from: line)
                } catch is CryptoError {
                    onEvent?(.error("Relay cryptography unavailable while decoding request"))
                    connection.cancel()
                    return
                } catch {
                    onEvent?(.error("Invalid relay request"))
                    connection.cancel()
                    return
                }
                let response: RelayResponse
                do {
                    response = try await handle(
                        request: request,
                        sourceKey: endpointSourceKey(connection.endpoint)
                    )
                } catch {
                    response = .error(
                        "Relay processing failed",
                        code: .internalFailure,
                        retryable: true,
                        respondingTo: request
                    )
                }
                let responseData = try NoctweaveCoder.encode(response)
                try await connection.sendLine(responseData)
                connection.cancel()
            } catch is CryptoError {
                onEvent?(.error("Relay cryptography unavailable while encoding response"))
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
            } catch is CryptoError {
                onEvent?(.error("Relay cryptography unavailable while processing HTTP request"))
                let errorResponse = httpResponse(
                    statusCode: 503,
                    reasonPhrase: "Service Unavailable",
                    body: Data("relay temporarily unavailable\n".utf8),
                    contentType: "text/plain; charset=utf-8"
                )
                try? await sendRaw(errorResponse, on: connection)
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
            } catch is CryptoError {
                return httpResponse(
                    statusCode: 503,
                    reasonPhrase: "Service Unavailable",
                    body: Data("relay temporarily unavailable\n".utf8),
                    contentType: "text/plain; charset=utf-8"
                )
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
        case .getNoctwebNamespaceSnapshot(let snapshotRequest):
            guard snapshotRequest.isStructurallyValid,
                  snapshotRequest.federationMode
                    == configuration.federation.mode,
                  snapshotRequest.federationName
                    == configuration.federation.name else {
                return .error(
                    "Noctweb namespace snapshot trust domain mismatch.",
                    code: .authenticationRequired,
                    respondingTo: request
                )
            }
            do {
                let snapshot = try await makeNoctwebNamespaceSnapshot(
                    for: snapshotRequest
                )
                return .success(
                    .noctwebNamespaceSnapshot(snapshot),
                    respondingTo: request
                )
            } catch {
                return .error(
                    "Noctweb namespace snapshot is unavailable.",
                    code: .unavailable,
                    retryable: true,
                    respondingTo: request
                )
            }
        case .claimNoctwebNamespace(let claim):
            guard claim.identity.claim.federationMode
                    == configuration.federation.mode,
                  claim.identity.claim.federationName
                    == configuration.federation.name,
                  claim.identity.claim.noctwebSuffix != nil else {
                return .error(
                    "Noctweb namespace claim trust domain mismatch.",
                    code: .authenticationRequired,
                    respondingTo: request
                )
            }
            do {
                let suffix = claim.identity.claim.noctwebSuffix!
                let previous = await noctwebNamespaceRuntime.record(
                    for: suffix
                )
                let record = try await noctwebNamespaceRuntime.claim(
                    claim.identity
                )
                await publishNoctwebNamespaceState()
                if previous != record {
                    await propagateNoctwebNamespaceMutation(request)
                }
                return .success(
                    .noctwebNamespaceRecord(record),
                    respondingTo: request
                )
            } catch {
                return .error(
                    "Noctweb namespace claim is invalid or conflicts with ownership.",
                    code: .conflict,
                    respondingTo: request
                )
            }
        case .rotateNoctwebNamespace(let rotationRequest):
            guard rotationRequest.newIdentity.claim.federationMode
                    == configuration.federation.mode,
                  rotationRequest.newIdentity.claim.federationName
                    == configuration.federation.name,
                  rotationRequest.newIdentity.claim.noctwebSuffix
                    != nil else {
                return .error(
                    "Noctweb namespace rotation trust domain mismatch.",
                    code: .authenticationRequired,
                    respondingTo: request
                )
            }
            do {
                let record = try await noctwebNamespaceRuntime.rotate(
                    rotationRequest.rotation,
                    to: rotationRequest.newIdentity
                )
                await publishNoctwebNamespaceState()
                await propagateNoctwebNamespaceMutation(request)
                return .success(
                    .noctwebNamespaceRecord(record),
                    respondingTo: request
                )
            } catch {
                return .error(
                    "Noctweb namespace rotation proof is invalid.",
                    code: .authenticationRequired,
                    respondingTo: request
                )
            }
        case .releaseNoctwebNamespace(let release):
            do {
                let record = try await noctwebNamespaceRuntime.release(
                    release
                )
                await publishNoctwebNamespaceState()
                await propagateNoctwebNamespaceMutation(request)
                return .success(
                    .noctwebNamespaceRecord(record),
                    respondingTo: request
                )
            } catch {
                return .error(
                    "Noctweb namespace release proof is invalid.",
                    code: .authenticationRequired,
                    respondingTo: request
                )
            }
        case .createOpaqueRoute(let payload):
            guard payload.isStructurallyValid else {
                return .error("Invalid opaque route create request", respondingTo: request)
            }
            do {
                let result = try await opaqueRouteStore.create(
                    payload.request,
                    presentedCapability: payload.renewCapability,
                    confidentialTransport: hasConfidentialRouteTransport(sourceKey),
                    receivedAt: Date()
                )
                return try await durableOpaqueRouteResponse(.opaqueRoute(result), respondingTo: request)
            } catch {
                return opaqueRouteErrorResponse(error, respondingTo: request)
            }
        case .renewOpaqueRoute(let payload):
            guard payload.isStructurallyValid else {
                return .error("Invalid opaque route renewal request", respondingTo: request)
            }
            do {
                let result = try await opaqueRouteStore.renew(
                    payload.request,
                    presentedCapability: payload.renewCapability,
                    confidentialTransport: hasConfidentialRouteTransport(sourceKey),
                    receivedAt: Date()
                )
                return try await durableOpaqueRouteResponse(.opaqueRoute(result), respondingTo: request)
            } catch {
                return opaqueRouteErrorResponse(error, respondingTo: request)
            }
        case .teardownOpaqueRoute(let payload):
            guard payload.isStructurallyValid else {
                return .error("Invalid opaque route teardown request", respondingTo: request)
            }
            do {
                let result = try await opaqueRouteStore.teardown(
                    payload.request,
                    presentedCapability: payload.teardownCapability,
                    confidentialTransport: hasConfidentialRouteTransport(sourceKey),
                    receivedAt: Date()
                )
                return try await durableOpaqueRouteResponse(.opaqueRoute(result), respondingTo: request)
            } catch {
                return opaqueRouteErrorResponse(error, respondingTo: request)
            }
        case .appendOpaqueRoute(let payload):
            guard payload.isStructurallyValid else {
                return .error("Invalid opaque route append request", respondingTo: request)
            }
            do {
                let result = try await opaqueRouteStore.append(
                    payload.packet,
                    presentedCapability: payload.sendCapability,
                    confidentialTransport: hasConfidentialRouteTransport(sourceKey),
                    receivedAt: Date()
                )
                return try await durableOpaqueRouteResponse(.opaqueRouteAppend(result), respondingTo: request)
            } catch {
                return opaqueRouteErrorResponse(error, respondingTo: request)
            }
        case .forwardOpaqueRoute(let payload):
            guard configuration.kind == .standard,
                  configuration.federation.mode != .solo else {
                return .error(
                    "Federation forwarding is unavailable on this relay.",
                    code: .unavailable,
                    respondingTo: request
                )
            }
            guard hasConfidentialRouteTransport(sourceKey) else {
                return .error(
                    "Federation forwarding requires confidential client transport.",
                    respondingTo: request
                )
            }
            guard payload.isStructurallyValid else {
                return .error("Invalid federation forwarding request.", respondingTo: request)
            }
            do {
                _ = try await authenticatedFederationPeer(
                    destination: payload.destination,
                    expectedRelayID: payload.destinationRelayID
                )
                let sourceIdentity = try makeCurrentSignedRelayIdentity()
                let delivery = try FederatedOpaqueRouteDeliveryV1.signed(
                    sourceIdentity: sourceIdentity,
                    sourceKey: requiredRelayIdentityKeyMaterial(),
                    destinationRelayID: payload.destinationRelayID,
                    append: payload.append
                )
                let destinationResponse = try await RelayClient(
                    endpoint: payload.destination
                ).send(.deliverOpaqueRouteV1(delivery))
                if case .opaqueRouteAppend(let receipt)? = destinationResponse.successBody {
                    return .success(.opaqueRouteAppend(receipt), respondingTo: request)
                }
                return forwardedRelayErrorResponse(
                    destinationResponse,
                    respondingTo: request
                )
            } catch {
                return .error(
                    "Authenticated federation delivery failed.",
                    code: .unavailable,
                    retryable: true,
                    respondingTo: request
                )
            }
        case .deliverOpaqueRoute(let delivery):
            guard configuration.kind == .standard,
                  configuration.federation.mode != .solo else {
                return .error(
                    "Federation delivery is unavailable on this relay.",
                    code: .unavailable,
                    respondingTo: request
                )
            }
            do {
                let localRelayID = try requiredRelayIdentityKeyMaterial().relayID
                guard try delivery.verifyThrowing(
                    expectedDestinationRelayID: localRelayID,
                    federation: configuration.federation
                ),
                try await isAuthenticatedFederationMember(
                    delivery.sourceIdentity
                ) else {
                    return .error(
                        "Federation delivery identity or membership is invalid.",
                        code: .authenticationRequired,
                        respondingTo: request
                    )
                }
                let result = try await opaqueRouteStore.append(
                    delivery.append.packet,
                    presentedCapability: delivery.append.sendCapability,
                    confidentialTransport: true,
                    receivedAt: Date()
                )
                return try await durableOpaqueRouteResponse(
                    .opaqueRouteAppend(result),
                    respondingTo: request
                )
            } catch {
                return opaqueRouteErrorResponse(error, respondingTo: request)
            }
        case .syncOpaqueRoute(let payload):
            guard payload.isStructurallyValid else {
                return .error("Invalid opaque route sync request", respondingTo: request)
            }
            do {
                let result = try await opaqueRouteStore.sync(
                    payload.request,
                    presentedCredential: payload.readCredential,
                    confidentialTransport: hasConfidentialRouteTransport(sourceKey),
                    receivedAt: Date()
                )
                return try await durableOpaqueRouteResponse(.opaqueRouteSync(result), respondingTo: request)
            } catch {
                return opaqueRouteErrorResponse(error, respondingTo: request)
            }
        case .commitOpaqueRoute(let payload):
            guard payload.isStructurallyValid else {
                return .error("Invalid opaque route commit request", respondingTo: request)
            }
            do {
                let result = try await opaqueRouteStore.commit(
                    payload.request,
                    presentedCredential: payload.readCredential,
                    confidentialTransport: hasConfidentialRouteTransport(sourceKey),
                    receivedAt: Date()
                )
                return try await durableOpaqueRouteResponse(.opaqueRouteCommit(result), respondingTo: request)
            } catch {
                return opaqueRouteErrorResponse(error, respondingTo: request)
            }
        case .registerRendezvous(let registration):
            guard configuration.isRendezvousTransportEnabled else {
                return .error("Rendezvous transport is disabled", code: .unavailable, respondingTo: request)
            }
            guard hasConfidentialRouteTransport(sourceKey) else {
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
            guard hasConfidentialRouteTransport(sourceKey) else {
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
            guard hasConfidentialRouteTransport(sourceKey) else {
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
            guard hasConfidentialRouteTransport(sourceKey) else {
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
                if relayIdentityKeyMaterial != nil {
                    let endpoints = advertisedIdentityEndpoints(configuration: configuration)
                    guard !endpoints.isEmpty else {
                        return .error(
                            "Relay identity requires an advertised endpoint.",
                            code: .unavailable,
                            respondingTo: request
                        )
                    }
                    do {
                        info = try makeCurrentSignedRelayInfo(
                            base: info,
                            at: info.advertisedAt
                        )
                    } catch {
                        return .error(
                            "Relay identity signing is unavailable.",
                            code: .unavailable,
                            retryable: true,
                            respondingTo: request
                        )
                    }
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
                    ttlSeconds: upload.ttlSeconds,
                    idempotencyKey: upload.idempotencyKey,
                    effectiveTTLSeconds: boundedTTL
                )
                return .success(.attachment(chunk), respondingTo: request)
            } catch RelayStoreError.invalidChunkIndex {
                return .error("Invalid chunk index", respondingTo: request)
            } catch RelayStoreError.invalidAttachmentPayload {
                return .error("Invalid attachment payload", respondingTo: request)
            } catch RelayStoreError.invalidAttachmentIdempotency {
                return .error("Invalid attachment idempotency key", respondingTo: request)
            } catch RelayStoreError.attachmentConflict {
                return .error(
                    "Attachment coordinate conflicts with stored state",
                    code: .conflict,
                    respondingTo: request
                )
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
            guard configuration.federation.mode != .manual else {
                return .error(
                    "Manual federation does not accept relay registration; configure peers explicitly.",
                    code: .invalidRequest,
                    respondingTo: request
                )
            }
            guard configuration.kind == .coordinator else {
                return .error("This relay is not a coordinator node.", code: .unavailable, respondingTo: request)
            }
            if let authFailure = validateCoordinatorRegistrationAuthentication(token: request.authToken) {
                return .error(authFailure, code: .authenticationRequired, respondingTo: request)
            }
            if let identityFailure = validateFederationRegistrationIdentity(
                registration
            ) {
                return .error(
                    identityFailure,
                    code: .invalidRequest,
                    respondingTo: request
                )
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
                let snapshot: FederationDirectorySnapshot?
                do {
                    snapshot = try makeCoordinatorDirectorySnapshot(
                        nodes: nodes,
                        request: listRequest
                    )
                } catch {
                    return .error(
                        "Coordinator snapshot signing is temporarily unavailable.",
                        code: .internalFailure,
                        retryable: true,
                        respondingTo: request
                    )
                }
                if listRequest.requireSignedSnapshot == true, snapshot == nil {
                    return .error(
                        "Coordinator snapshot signing is not available.",
                        code: .unavailable,
                        retryable: true,
                        respondingTo: request
                    )
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
            let result = try await store.ingestOpenFederationDHTRecords(
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
        case .getFederatedNetHostObject(let read):
            guard configuration.kind == .standard,
                  configuration.federation.mode != .solo,
                  read.isStructurallyValid else {
                return .error(
                    "Federated Noctweb retrieval is unavailable.",
                    code: .unavailable,
                    respondingTo: request
                )
            }
            do {
                let destinationInfo = try await authenticatedFederationPeer(
                    destination: read.destination,
                    expectedRelayID: read.destinationRelayID,
                    requiredModule: "nw.net-host",
                    allowedKinds: [.standard, .host]
                )
                let destinationResponse = try await RelayClient(
                    endpoint: read.destination
                ).send(.getNetHostObject(read.request))
                guard case .netHostObject(
                    let object
                )? = destinationResponse.successBody,
                let destinationIdentity =
                    destinationInfo.relayIdentity else {
                    return forwardedRelayErrorResponse(
                        destinationResponse,
                        respondingTo: request
                    )
                }
                let federated = FederatedNetHostObjectResponseV1(
                    destinationIdentity: destinationIdentity,
                    object: object
                )
                guard try federated.verifyThrowing(
                    expectedRelayID: read.destinationRelayID
                ) else {
                    return .error(
                        "Federated Noctweb object failed relay identity verification.",
                        code: .authenticationRequired,
                        respondingTo: request
                    )
                }
                return .success(
                    .federatedNetHostObject(federated),
                    respondingTo: request
                )
            } catch {
                return .error(
                    "Federated Noctweb destination is unavailable.",
                    code: .unavailable,
                    retryable: true,
                    respondingTo: request
                )
            }
        case .resolveFederatedNetHostName(let read):
            guard configuration.kind == .standard,
                  configuration.federation.mode != .solo,
                  read.isStructurallyValid else {
                return .error(
                    "Federated Noctweb name resolution is unavailable.",
                    code: .unavailable,
                    respondingTo: request
                )
            }
            do {
                let destinationInfo = try await authenticatedFederationPeer(
                    destination: read.destination,
                    expectedRelayID: read.destinationRelayID,
                    requiredModule: "nw.net-host",
                    allowedKinds: [.standard, .host]
                )
                let destinationResponse = try await RelayClient(
                    endpoint: read.destination
                ).send(.resolveNetHostName(read.request))
                guard case .netHostNameResolution(
                    let resolution
                )? = destinationResponse.successBody,
                let destinationIdentity =
                    destinationInfo.relayIdentity else {
                    return forwardedRelayErrorResponse(
                        destinationResponse,
                        respondingTo: request
                    )
                }
                let federated = FederatedNetHostNameResponseV1(
                    destinationIdentity: destinationIdentity,
                    resolution: resolution
                )
                guard try federated.verifyThrowing(
                    expectedRelayID: read.destinationRelayID
                ) else {
                    return .error(
                        "Federated Noctweb name failed relay identity verification.",
                        code: .authenticationRequired,
                        respondingTo: request
                    )
                }
                return .success(
                    .federatedNetHostNameResolution(federated),
                    respondingTo: request
                )
            } catch {
                return .error(
                    "Federated Noctweb destination is unavailable.",
                    code: .unavailable,
                    retryable: true,
                    respondingTo: request
                )
            }
        case .netPassthrough:
            return .error(
                "Noctweave Net passthrough requires NoctweaveRelayServer.",
                code: .unavailable,
                respondingTo: request
            )
        case .putNetHostObject(let put):
            guard configuration.isNetHostEnabled,
                  let noctwebHostStore else {
                return .error(
                    "This relay does not provide Noctweave Net hosting.",
                    code: .unavailable,
                    respondingTo: request
                )
            }
            guard hasConfidentialRouteTransport(sourceKey) else {
                return .error(
                    "Noctweave Net hosting writes require confidential transport.",
                    respondingTo: request
                )
            }
            do {
                return .success(
                    .netHostReceipt(try noctwebHostStore.put(put)),
                    respondingTo: request
                )
            } catch RelayNoctwebHostStoreError.conflict {
                return .error(
                    "Host object conflicts with stored state.",
                    code: .conflict,
                    respondingTo: request
                )
            } catch RelayNoctwebHostStoreError.capacityExceeded {
                return .error(
                    "Host object capacity reached.",
                    code: .capacity,
                    respondingTo: request
                )
            } catch {
                return .error(
                    "Host object could not be stored.",
                    code: .internalFailure,
                    retryable: true,
                    respondingTo: request
                )
            }
        case .bindNetHostName(let binding):
            guard configuration.isNetHostEnabled,
                  let noctwebHostStore,
                  let configuredSuffix =
                    configuration.noctwebRelaySuffix,
                  binding.relaySuffix == configuredSuffix else {
                return .error(
                    "This relay does not own the requested Noctweb suffix.",
                    code: .unavailable,
                    respondingTo: request
                )
            }
            guard hasConfidentialRouteTransport(sourceKey) else {
                return .error(
                    "Noctweave Net name writes require confidential transport.",
                    respondingTo: request
                )
            }
            do {
                let now = Date()
                let stored = try noctwebHostStore.bindName(
                    binding,
                    now: now
                )
                let resolution =
                    try NoctweaveNetHostNameResolutionV1.signed(
                        binding: stored,
                        updatedAt: now,
                        signer:
                            requiredRelayIdentityKeyMaterial(),
                        at: now
                    )
                return .success(
                    .netHostNameResolution(resolution),
                    respondingTo: request
                )
            } catch RelayNoctwebHostStoreError.conflict {
                return .error(
                    "Noctweb name conflicts with publisher continuity.",
                    code: .conflict,
                    respondingTo: request
                )
            } catch RelayNoctwebHostStoreError.objectUnavailable {
                return .error(
                    "The named host object is not available.",
                    code: .notFound,
                    respondingTo: request
                )
            } catch {
                return .error(
                    "Noctweb name could not be stored.",
                    code: .internalFailure,
                    retryable: true,
                    respondingTo: request
                )
            }
        case .getNetHostObject(let get):
            guard configuration.isNetHostEnabled,
                  let noctwebHostStore else {
                return .error(
                    "This relay does not provide Noctweave Net hosting.",
                    code: .unavailable,
                    respondingTo: request
                )
            }
            do {
                guard let object = try noctwebHostStore.fetch(get) else {
                    return .error(
                        "Host object not found.",
                        code: .notFound,
                        respondingTo: request
                    )
                }
                return .success(
                    .netHostObject(object),
                    respondingTo: request
                )
            } catch {
                return .error(
                    "Host object could not be read.",
                    code: .internalFailure,
                    retryable: true,
                    respondingTo: request
                )
            }
        case .resolveNetHostName(let name):
            guard configuration.isNetHostEnabled,
                  let noctwebHostStore,
                  let configuredSuffix =
                    configuration.noctwebRelaySuffix,
                  name.relaySuffix == configuredSuffix else {
                return .error(
                    "This relay does not own the requested Noctweb suffix.",
                    code: .notFound,
                    respondingTo: request
                )
            }
            do {
                let now = Date()
                guard let binding =
                    try noctwebHostStore.resolveName(
                        name,
                        now: now
                    ) else {
                    return .error(
                        "Noctweb name not found.",
                        code: .notFound,
                        respondingTo: request
                    )
                }
                let resolution =
                    try NoctweaveNetHostNameResolutionV1.signed(
                        binding: binding,
                        updatedAt: now,
                        signer:
                            requiredRelayIdentityKeyMaterial(),
                        at: now
                    )
                return .success(
                    .netHostNameResolution(resolution),
                    respondingTo: request
                )
            } catch {
                return .error(
                    "Noctweb name could not be resolved.",
                    code: .internalFailure,
                    retryable: true,
                    respondingTo: request
                )
            }
        case .hasNetHostObject(let has):
            guard configuration.isNetHostEnabled,
                  let noctwebHostStore else {
                return .error(
                    "This relay does not provide Noctweave Net hosting.",
                    code: .unavailable,
                    respondingTo: request
                )
            }
            do {
                return .success(
                    .netHostPresence(
                        try noctwebHostStore.presence(has)
                    ),
                    respondingTo: request
                )
            } catch {
                return .error(
                    "Host object presence could not be read.",
                    code: .internalFailure,
                    retryable: true,
                    respondingTo: request
                )
            }
        case .releaseNetHostObject(let release):
            guard configuration.isNetHostEnabled,
                  let noctwebHostStore else {
                return .error(
                    "This relay does not provide Noctweave Net hosting.",
                    code: .unavailable,
                    respondingTo: request
                )
            }
            guard hasConfidentialRouteTransport(sourceKey) else {
                return .error(
                    "Noctweave Net hosting releases require confidential transport.",
                    respondingTo: request
                )
            }
            do {
                return .success(
                    .netHostRelease(
                        try noctwebHostStore.release(release)
                    ),
                    respondingTo: request
                )
            } catch RelayNoctwebHostStoreError
                .unauthorizedRelease {
                return .error(
                    "Host release capability rejected.",
                    code: .authenticationRequired,
                    respondingTo: request
                )
            } catch {
                return .error(
                    "Host object could not be released.",
                    code: .internalFailure,
                    retryable: true,
                    respondingTo: request
                )
            }
        }
    }

    private func hasConfidentialRouteTransport(_ sourceKey: String?) -> Bool {
        configuration.effectiveTransportConfidentiality(
            isLiteralLoopbackSource: isLiteralLoopbackSource(sourceKey)
        ).permitsCapabilityTransport
    }

    private func requiredRelayIdentityKeyMaterial() throws -> RelayIdentityKeyMaterialV1 {
        guard let relayIdentityKeyMaterial else {
            throw RelayNetworkError.invalidResponse
        }
        return relayIdentityKeyMaterial
    }

    private func makeCurrentSignedRelayIdentity(
        at date: Date = Date()
    ) throws -> SignedRelayIdentityClaimV1 {
        let configuration = configuration
        let endpoints = advertisedIdentityEndpoints(configuration: configuration)
        guard !endpoints.isEmpty,
              let capabilities = configuration.makeInfo(now: date).protocolCapabilities else {
            throw RelayNetworkError.invalidResponse
        }
        let keyMaterial = try requiredRelayIdentityKeyMaterial()
        let capabilityDigest = try RelayIdentityClaimV1.capabilityDigest(
            for: capabilities
        )
        relayIdentitySequenceLock.lock()
        defer { relayIdentitySequenceLock.unlock() }
        if let cachedRelayIdentity,
           cachedRelayIdentity.claim.expiresAt
            > date.addingTimeInterval(
                RelayIdentityV1.maximumClockSkew
            ),
           cachedRelayIdentity.claim.relayKind == configuration.kind,
           cachedRelayIdentity.claim.federationMode
            == configuration.federation.mode,
           cachedRelayIdentity.claim.federationName
            == configuration.federation.name,
           cachedRelayIdentity.claim.noctwebSuffix
            == configuration.noctwebRelaySuffix,
           cachedRelayIdentity.claim.hostSigningPublicKey
            == noctwebHostStore?.signingPublicKey,
           cachedRelayIdentity.claim.capabilityDigest == capabilityDigest,
           cachedRelayIdentity.claim.advertisedEndpoints
            .map(endpointKey)
            .sorted()
            == endpoints.map(endpointKey).sorted() {
            return cachedRelayIdentity
        }
        let wallClock = max(0, Int(floor(date.timeIntervalSince1970)))
        relayIdentityClaimSequence = max(
            wallClock,
            min(
                relayIdentityClaimSequence + 1,
                RelayIdentityV1.maximumSequence
            )
        )
        let identity = try keyMaterial.makeSignedClaim(
            sequence: relayIdentityClaimSequence,
            relayKind: configuration.kind,
            federation: configuration.federation,
            advertisedEndpoints: endpoints,
            noctwebSuffix: configuration.noctwebRelaySuffix,
            hostSigningPublicKey:
                noctwebHostStore?.signingPublicKey,
            capabilities: capabilities,
            issuedAt: date
        )
        cachedRelayIdentity = identity
        return identity
    }

    private func makeCurrentSignedRelayInfo(
        base: RelayInfo? = nil,
        at date: Date = Date()
    ) throws -> RelayInfo {
        let configuration = configuration
        let identity = try makeCurrentSignedRelayIdentity(at: date)
        return try (base ?? configuration.makeInfo(now: date)).authenticated(
            by: requiredRelayIdentityKeyMaterial(),
            sequence: identity.claim.sequence,
            advertisedEndpoints: advertisedIdentityEndpoints(
                configuration: configuration
            ),
            noctwebSuffix: configuration.noctwebRelaySuffix,
            hostSigningPublicKey:
                noctwebHostStore?.signingPublicKey,
            precomputedIdentity: identity
        )
    }

    private func makeNoctwebNamespaceSnapshot(
        for request: NoctwebNamespaceSnapshotRequestV1,
        at now: Date = Date()
    ) async throws -> NoctwebNamespaceSnapshotV1 {
        let configuration = configuration
        guard request.federationMode == configuration.federation.mode,
              request.federationName == configuration.federation.name else {
            throw RelayNetworkError.invalidResponse
        }

        var identities: [SignedRelayIdentityClaimV1] = [
            try makeCurrentSignedRelayIdentity(at: now)
        ]
        let directoryRequest = ListFederationNodesRequest(
            mode: configuration.federation.mode,
            federationName: configuration.federation.name,
            onlyHealthy: true,
            maxStalenessSeconds:
                configuration.coordinatorDirectoryMaxStalenessSeconds,
            requireSignedSnapshot:
                configuration.federation.mode == .manual
                    ? false
                    : configuration.curatedRequireSignedDirectory
        )
        let records: [FederationNodeRecord]
        if configuration.kind == .coordinator {
            records = await store.listFederationNodes(directoryRequest)
        } else if configuration.federation.mode == .solo {
            records = []
        } else {
            records = (try? await fetchCoordinatorNodeDirectory(
                request: directoryRequest
            )) ?? []
        }
        identities.append(contentsOf: records.compactMap {
            $0.relayInfo.relayIdentity
        })

        if configuration.federation.mode == .manual {
            for endpoint in configuration.federationAllowList {
                if let advertised = configuration.advertisedEndpoint,
                   endpointKey(endpoint) == endpointKey(advertised) {
                    continue
                }
                guard let info = try? await fetchRelayInfo(endpoint: endpoint),
                      info.federation == configuration.federation,
                      let identity = info.relayIdentity else {
                    continue
                }
                identities.append(identity)
            }
        }

        var latestByRelayID:
            [RelayIdentityIDV1: SignedRelayIdentityClaimV1] = [:]
        for identity in identities {
            guard identity.claim.federationMode
                    == configuration.federation.mode,
                  identity.claim.federationName
                    == configuration.federation.name,
                  identity.claim.noctwebSuffix != nil,
                  try identity.verifyThrowing(at: now) else {
                continue
            }
            let relayID = identity.claim.relayID
            if let existing = latestByRelayID[relayID],
               existing.claim.sequence >= identity.claim.sequence {
                continue
            }
            latestByRelayID[relayID] = identity
        }

        for identity in latestByRelayID.values.sorted(by: {
            if $0.claim.sequence != $1.claim.sequence {
                return $0.claim.sequence < $1.claim.sequence
            }
            return $0.claim.relayID < $1.claim.relayID
        }) {
            _ = try await noctwebNamespaceRuntime.claim(
                identity,
                now: now
            )
        }
        await publishNoctwebNamespaceState()
        let ledger = try NoctwebNamespaceLedgerV1(
            records: await noctwebNamespaceRuntime.records()
        )
        let payload = try ledger.snapshotPayload(
            federation: configuration.federation,
            at: now
        )
        return try .signed(
            payload: payload,
            by: [requiredRelayIdentityKeyMaterial()]
        )
    }

    private func publishNoctwebNamespaceState() async {
        guard let onNoctwebNamespaceStateSnapshot else {
            return
        }
        await onNoctwebNamespaceStateSnapshot(
            await noctwebNamespaceRuntime.records()
        )
    }

    private func authenticatedFederationPeer(
        destination: RelayEndpoint,
        expectedRelayID: RelayIdentityIDV1,
        requiredModule: String = "nw.federation-forward",
        allowedKinds: Set<RelayKind> = [.standard]
    ) async throws -> RelayInfo {
        guard permitsFederationTransport(destination) else {
            throw RelayNetworkError.invalidResponse
        }
        let membership = try await federationMembershipRecord(
            destination: destination
        )
        guard let liveInfo = try await fetchRelayInfo(endpoint: destination),
              try isValidFederationPeerInfo(
                  liveInfo,
                  endpoint: destination,
                  expectedRelayID: expectedRelayID,
                  requiredModule: requiredModule,
                  allowedKinds: allowedKinds
              ) else {
            throw RelayNetworkError.invalidResponse
        }
        if let membership {
            guard let membershipIdentity = membership.relayInfo.relayIdentity,
                  try membershipIdentity.verifyThrowing(at: Date()),
                  membershipIdentity.claim.relayID == expectedRelayID,
                  membershipIdentity.claim.signingPublicKey
                    == liveInfo.relayIdentity?.claim.signingPublicKey else {
                throw RelayNetworkError.invalidResponse
            }
        }
        return liveInfo
    }

    private func federationMembershipRecord(
        destination: RelayEndpoint
    ) async throws -> FederationNodeRecord? {
        let configuration = configuration
        guard configuration.federation.mode != .solo else {
            throw RelayNetworkError.invalidResponse
        }
        if configuration.federation.mode == .manual {
            guard configuration.federationAllowList.contains(where: {
                endpointKey($0) == endpointKey(destination)
            }) else {
                throw RelayNetworkError.invalidResponse
            }
            return nil
        }
        let records = try await fetchCoordinatorNodeDirectory(
            request: ListFederationNodesRequest(
                mode: configuration.federation.mode,
                federationName: configuration.federation.name,
                onlyHealthy: true,
                maxStalenessSeconds: configuration.coordinatorDirectoryMaxStalenessSeconds,
                requireSignedSnapshot: true
            )
        )
        guard let record = records.first(where: {
            endpointKey($0.endpoint) == endpointKey(destination)
        }) else {
            throw RelayNetworkError.invalidResponse
        }
        return record
    }

    private func isAuthenticatedFederationMember(
        _ identity: SignedRelayIdentityClaimV1
    ) async throws -> Bool {
        let configuration = configuration
        guard try identity.verifyThrowing(at: Date()),
              identity.claim.relayKind == .standard,
              identity.claim.federationMode == configuration.federation.mode,
              identity.claim.federationName == configuration.federation.name else {
            return false
        }
        if configuration.federation.mode == .manual {
            return identity.claim.advertisedEndpoints.contains { advertised in
                configuration.federationAllowList.contains {
                    endpointKey($0) == endpointKey(advertised)
                }
            }
        }
        let records = try await fetchCoordinatorNodeDirectory(
            request: ListFederationNodesRequest(
                mode: configuration.federation.mode,
                federationName: configuration.federation.name,
                onlyHealthy: true,
                maxStalenessSeconds: configuration.coordinatorDirectoryMaxStalenessSeconds,
                requireSignedSnapshot: true
            )
        )
        return records.contains { record in
            guard let listedIdentity = record.relayInfo.relayIdentity else {
                return false
            }
            return listedIdentity.claim.relayID == identity.claim.relayID
                && listedIdentity.claim.signingPublicKey
                    == identity.claim.signingPublicKey
                && identity.claim.advertisedEndpoints.contains {
                    endpointKey($0) == endpointKey(record.endpoint)
                }
        }
    }

    private func isValidFederationPeerInfo(
        _ info: RelayInfo,
        endpoint: RelayEndpoint,
        expectedRelayID: RelayIdentityIDV1,
        requiredModule: String,
        allowedKinds: Set<RelayKind>
    ) throws -> Bool {
        let configuration = configuration
        guard allowedKinds.contains(info.kind),
              info.federation.mode == configuration.federation.mode,
              info.federation.name == configuration.federation.name,
              info.protocolCapabilities?.supports(
                  module: requiredModule,
                  version: 1
              ) == true,
              let identity = info.relayIdentity,
              try identity.verifyThrowing(at: Date()),
              identity.claim.relayID == expectedRelayID,
              identity.claim.advertisedEndpoints.contains(where: {
                  endpointKey($0) == endpointKey(endpoint)
              }) else {
            return false
        }
        return true
    }

    private func permitsFederationTransport(_ endpoint: RelayEndpoint) -> Bool {
        if endpoint.useTLS {
            return true
        }
        let host = endpoint.host
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        return host == "127.0.0.1"
            || host == "::1"
            || host == "localhost"
    }

    private func forwardedRelayErrorResponse(
        _ response: RelayResponse,
        respondingTo request: RelayRequest
    ) -> RelayResponse {
        guard let error = response.error else {
            return .error(
                "Federation peer returned an invalid response.",
                code: .unavailable,
                retryable: true,
                respondingTo: request
            )
        }
        return .error(
            error.message,
            code: error.code,
            retryable: error.retryable,
            respondingTo: request
        )
    }

    private func advertisedIdentityEndpoints(
        configuration: RelayConfiguration
    ) -> [RelayEndpoint] {
        if let advertisedEndpoint = configuration.advertisedEndpoint {
            return [advertisedEndpoint]
        }
        guard var endpoint = localEndpoint else {
            return []
        }
        let host = endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines)
        if host == "0.0.0.0" || host == "::" {
            endpoint.host = "127.0.0.1"
        }
        return [endpoint]
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
            case .invalidSnapshot:
                return .error("Invalid opaque route state snapshot", respondingTo: request)
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

    private func durableOpaqueRouteResponse(
        _ body: RelaySuccessBody,
        respondingTo request: RelayRequest
    ) async throws -> RelayResponse {
        if let onOpaqueRouteStateSnapshot {
            try await onOpaqueRouteStateSnapshot(try await opaqueRouteStore.snapshot())
        }
        return .success(body, respondingTo: request)
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
        case .invalidAttachmentIdempotency:
            return .error("Invalid attachment idempotency key", respondingTo: request)
        case .attachmentConflict:
            return .error(
                "Attachment coordinate conflicts with stored state",
                code: .conflict,
                respondingTo: request
            )
        }
    }

    private func requiresAuthentication(for binding: RelayOperationBinding) -> Bool {
        if binding.module == .core
            || (binding.module == .federation
                && [
                    .register,
                    .list,
                    .namespace,
                    .claim,
                    .rotate,
                    .release
                ].contains(binding.method)) {
            return false
        }
        // Relay-to-relay delivery is authenticated by a short-lived signed
        // source claim plus federation membership, not by a shared operator
        // password. Client-originated `.forward` remains password protected.
        if binding.module == .federationForward,
           binding.method == .deliver {
            return false
        }
        return true
    }

    private func isCoordinatorDirectoryRequest(_ binding: RelayOperationBinding) -> Bool {
        binding.module == .core
            || (binding.module == .federation
                && [
                    .register,
                    .list,
                    .namespace,
                    .claim,
                    .rotate,
                    .release
                ].contains(binding.method))
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
        if configuration.federation.mode == .manual {
            return "Manual federation does not accept relay registration; configure peers explicitly."
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
        guard let registrationIdentity = registration.relayInfo.relayIdentity else {
            return "Coordinator registration rejected: relay identity is missing."
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
        guard let liveIdentity = info.relayIdentity,
              try liveIdentity.verifyThrowing(at: info.advertisedAt),
              liveIdentity.claim.relayID == registrationIdentity.claim.relayID,
              liveIdentity.claim.signingPublicKey
                == registrationIdentity.claim.signingPublicKey,
              liveIdentity.claim.advertisedEndpoints.contains(where: {
                  endpointKey($0) == endpointKey(registration.endpoint)
              }) else {
            return "Coordinator registration rejected: live relay identity differs from the submitted identity."
        }
        return nil
    }

    private func validateFederationRegistrationIdentity(
        _ registration: FederationNodeRegistrationRequest
    ) -> String? {
        guard let identity = registration.relayInfo.relayIdentity,
              (try? identity.verifyThrowing(
                  at: registration.relayInfo.advertisedAt
              )) == true,
              identity.claim.advertisedEndpoints.contains(where: {
                  endpointKey($0) == endpointKey(registration.endpoint)
              }) else {
            return "Coordinator registration rejected: relay identity is missing, invalid, or does not bind the advertised endpoint."
        }
        guard identity.claim.noctwebSuffix != nil else {
            return "Coordinator registration rejected: federated relays must advertise an authenticated Noctweb suffix."
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
        let endpoints = configuration.federation.mode == .manual
            ? configuration.federationAllowList
            : configuration.federationCoordinatorEndpoints ?? []
        var seen = Set<String>()
        return endpoints.filter { endpoint in
            !endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && seen.insert(endpointKey(endpoint)).inserted
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
                    let mode = self.configuration.federation.mode
                    if mode == .manual {
                        _ = try await self.fetchCoordinatorNodeDirectory(
                            request: ListFederationNodesRequest(
                                mode: mode,
                                federationName: self.configuration.federation.name,
                                onlyHealthy: true,
                                maxStalenessSeconds: self.configuration.coordinatorDirectoryMaxStalenessSeconds,
                                requireSignedSnapshot: false
                            )
                        )
                    } else {
                        try await self.sendCoordinatorHeartbeat()
                    }
                    if mode == .open {
                        _ = try? await self.fetchCoordinatorNodeDirectory(
                            request: ListFederationNodesRequest(
                                mode: mode,
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
        var info = try makeCurrentSignedRelayInfo(at: Date())
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
        if request.mode == .manual {
            guard relayInfo.kind == .standard,
                  relayInfo.federation.mode == .manual else {
                throw RelayNetworkError.invalidResponse
            }
            if let expectedName = request.federationName?
                .trimmingCharacters(in: .whitespacesAndNewlines),
               !expectedName.isEmpty,
               relayInfo.federation.name != expectedName {
                throw RelayNetworkError.invalidResponse
            }
            let now = Date()
            let lifetime = min(
                900,
                max(
                    60,
                    request.maxStalenessSeconds
                        ?? configuration.coordinatorDirectoryMaxStalenessSeconds
                        ?? 300
                )
            )
            return [
                FederationNodeRecord(
                    endpoint: coordinator,
                    relayInfo: relayInfo,
                    lastHeartbeatAt: now,
                    expiresAt: now.addingTimeInterval(TimeInterval(lifetime))
                )
            ]
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
    ) throws -> FederationDirectorySnapshot? {
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
        return try FederationDirectorySignature.signedSnapshot(
            from: unsigned,
            privateKeyData: privateKey
        )
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
                      try FederationDirectorySignature.verifyThrowing(
                          snapshot: snapshot,
                          trustedPublicKey: trustedPublicKey
                      ) else {
                    throw RelayNetworkError.invalidResponse
                }
            } else if let trustedPublicKey, snapshot.signature != nil {
                guard try FederationDirectorySignature.verifyThrowing(
                    snapshot: snapshot,
                    trustedPublicKey: trustedPublicKey
                ) else {
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

    private func propagateNoctwebNamespaceMutation(
        _ request: RelayRequest
    ) async {
        guard configuration.federation.mode != .solo else {
            return
        }
        var candidates = configuration.federationAllowList
        candidates.append(
            contentsOf: configuration.federationCoordinatorEndpoints ?? []
        )
        candidates.append(contentsOf: knownOpenFederationPeers())
        candidates.append(
            contentsOf: coordinatorDirectoryCacheSnapshot().map(\.endpoint)
        )

        let localKey = effectiveAdvertisedEndpoint().map(endpointKey)
        var seen = Set<String>()
        let endpoints = candidates.filter { endpoint in
            guard permitsFederationTransport(endpoint) else {
                return false
            }
            let key = endpointKey(endpoint)
            return key != localKey && seen.insert(key).inserted
        }
        .prefix(64)

        guard !endpoints.isEmpty else {
            return
        }
        let policy =
            (try? RelayClientPolicy(timeout: 3))
                ?? RelayClientPolicy.default
        await withTaskGroup(of: Void.self) { group in
            for endpoint in endpoints {
                group.addTask {
                    _ = try? await RelayClient(
                        endpoint: endpoint,
                        policy: policy
                    ).send(request)
                }
            }
        }
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

private actor NoctwebNamespaceRuntimeV1 {
    private var ledger: NoctwebNamespaceLedgerV1

    init() {
        ledger = NoctwebNamespaceLedgerV1()
    }

    func claim(
        _ identity: SignedRelayIdentityClaimV1,
        now: Date = Date()
    ) throws -> NoctwebNamespaceRecordV1 {
        try ledger.claim(identity, now: now)
        guard let suffix = identity.claim.noctwebSuffix,
              let record = ledger.record(for: suffix) else {
            throw NoctwebNamespaceLedgerErrorV1.invalidClaim
        }
        return record
    }

    func rotate(
        _ rotation: RelayIdentityRotationV1,
        to newIdentity: SignedRelayIdentityClaimV1,
        now: Date = Date()
    ) throws -> NoctwebNamespaceRecordV1 {
        try ledger.rotate(rotation, to: newIdentity, now: now)
        guard let suffix = newIdentity.claim.noctwebSuffix,
              let record = ledger.record(for: suffix) else {
            throw NoctwebNamespaceLedgerErrorV1.invalidRotation
        }
        return record
    }

    func release(
        _ release: NoctwebNamespaceReleaseV1,
        now: Date = Date()
    ) throws -> NoctwebNamespaceRecordV1 {
        try ledger.release(release, now: now)
        guard let record = ledger.record(for: release.suffix) else {
            throw NoctwebNamespaceLedgerErrorV1.invalidRelease
        }
        return record
    }

    func records() -> [NoctwebNamespaceRecordV1] {
        ledger.records
    }

    func record(
        for suffix: NoctwebRelaySuffixV1
    ) -> NoctwebNamespaceRecordV1? {
        ledger.record(for: suffix)
    }

    func restore(_ records: [NoctwebNamespaceRecordV1]) throws {
        ledger = try NoctwebNamespaceLedgerV1(records: records)
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
