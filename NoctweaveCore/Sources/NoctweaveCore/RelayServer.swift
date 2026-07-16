import Foundation
import Network

public final class RelayServer {
    public enum Event {
        case started(port: UInt16)
        case stopped
        case delivered(inboxId: String, storedCount: Int)
        case fetched(inboxId: String, count: Int)
        case error(String)
    }

    public var onEvent: ((Event) -> Void)?

    private let store: RelayStore
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

    public init(store: RelayStore, configuration: RelayConfiguration = RelayConfiguration()) {
        self.store = store
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
            configuration.federationForwardingAuthToken = updated.federationForwardingAuthToken
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
        case ("GET", "/health"):
            return httpResponse(
                statusCode: 200,
                reasonPhrase: "OK",
                body: Data("ok\n".utf8),
                contentType: "text/plain; charset=utf-8"
            )
        case ("GET", "/info"):
            let response = try await handle(request: .info())
            let body = try NoctweaveCoder.encode(response)
            return httpResponse(statusCode: 200, reasonPhrase: "OK", body: body)
        case ("POST", "/relay"):
            guard !message.body.isEmpty else {
                let body = try NoctweaveCoder.encode(RelayResponse.error("Missing relay request body"))
                return httpResponse(statusCode: 400, reasonPhrase: "Bad Request", body: body)
            }
            let request: RelayRequest
            do {
                request = try NoctweaveCoder.decode(RelayRequest.self, from: message.body)
            } catch {
                let body = try NoctweaveCoder.encode(RelayResponse.error("Invalid relay JSON request"))
                return httpResponse(statusCode: 400, reasonPhrase: "Bad Request", body: body)
            }
            do {
                let response = try await handle(request: request, sourceKey: sourceKey)
                let body = try NoctweaveCoder.encode(response)
                return httpResponse(statusCode: 200, reasonPhrase: "OK", body: body)
            } catch {
                let body = try NoctweaveCoder.encode(RelayResponse.error("Relay processing failed"))
                return httpResponse(statusCode: 200, reasonPhrase: "OK", body: body)
            }
        case ("GET", "/relay"):
            let body = try NoctweaveCoder.encode(RelayResponse.error("Use POST /relay"))
            return httpResponse(statusCode: 405, reasonPhrase: "Method Not Allowed", body: body)
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
            return .error("Rate limit exceeded")
        }
        if requiresAuthentication(for: request.type),
           let authFailure = validateAuthentication(token: request.authToken) {
            return authFailure
        }
        if configuration.kind == .coordinator,
           !isCoordinatorDirectoryRequestType(request.type) {
            return .error("Coordinator relays are directory-only and do not carry user traffic.")
        }
        if request.type.requiresLegacyFingerprintCompatibility,
           !configuration.legacyFingerprintCompatibilityEnabled {
            return .error(
                "Deprecated compatibility profile \(RelayCompatibilityProfile.legacyFingerprint) is disabled"
            )
        }
        switch request.type {
        case .deliver:
            guard let deliver = request.deliver else {
                return .error("Missing deliver payload")
            }
            let capability = deliver.inboxCapability
            if let capability {
                guard configuration.opaqueRouteCapabilitiesEnabled else {
                    return .error("Experimental opaque route capabilities are disabled")
                }
                guard capability.isStructurallyValid,
                      deliver.inboxId == nil,
                      deliver.routingToken == nil else {
                    return .error("Invalid inbox route capability")
                }
            } else {
                guard let legacyRoutingToken = deliver.routingToken ?? deliver.inboxId,
                      InboxAddress.isValid(legacyRoutingToken) else {
                    return .error("Invalid routing token")
                }
            }
            if let destination = deliver.destinationRelay,
               destination != localEndpoint {
                do {
                    if let response = try await federationGate(forwardingTo: destination) {
                        return response
                    }
                    let forward: DeliverRequest
                    if let capability {
                        // Federation preserves only the opaque bearer value;
                        // the forwarding relay never learns the destination
                        // inbox or any endpoint/relationship identifier.
                        forward = DeliverRequest(
                            inboxCapability: capability,
                            envelope: deliver.envelope
                        )
                    } else {
                        guard let legacyInboxId = deliver.inboxId else {
                            return .error("Invalid routing token")
                        }
                        forward = DeliverRequest(
                            inboxId: legacyInboxId,
                            routingToken: deliver.routingToken,
                            envelope: deliver.envelope
                        )
                    }
                    let client = RelayClient(endpoint: destination, authToken: configuration.federationForwardingAuthToken)
                    return try await client.send(.deliver(forward))
                } catch {
                    return .error("Forwarding failed")
                }
            }
            let routingToken: String
            if let capability {
                guard let resolved = await store.resolveInboxRouteCapability(capability) else {
                    return .error("Inbox route capability is unavailable")
                }
                routingToken = resolved
            } else if let legacyRoutingToken = deliver.routingToken ?? deliver.inboxId {
                routingToken = legacyRoutingToken
            } else {
                return .error("Invalid routing token")
            }
            do {
                let count = try await store.deliver(deliver.envelope, to: routingToken)
                onEvent?(.delivered(inboxId: routingToken, storedCount: count))
                return .delivered(count: count)
            } catch RelayStoreError.inboxFull {
                return .error("Inbox full")
            } catch RelayStoreError.destinationInboxNotRegistered {
                return .error("Destination inbox is not registered")
            } catch RelayStoreError.inboxRetired {
                return .error("Destination inbox is retired")
            } catch RelayStoreError.relayCapacityExceeded {
                return .error("Relay storage capacity reached")
            } catch RelayStoreError.invalidEnvelopePayload {
                return .error("Invalid envelope payload")
            }
        case .registerInbox:
            guard let registration = request.registerInbox else {
                return .error("Missing inbox registration payload")
            }
            guard InboxAddress.isValid(registration.inboxId),
                  !registration.accessPublicKey.isEmpty,
                  InboxAddress.isBound(registration.inboxId, to: registration.accessPublicKey) else {
                return .error("Invalid inbox registration")
            }
            switch registration.registrationVersion {
            case RegisterInboxRequest.privacyMinimizedVersion:
                guard registration.contactOffer == nil else {
                    return .error("Privacy-minimized inbox registration must not include a contact offer")
                }
            case nil:
                guard let offer = registration.contactOffer,
                      (try? offer.verified()) != nil,
                      offer.inboxId == registration.inboxId,
                      offer.inboxAccessPublicKey == registration.accessPublicKey else {
                    return .error("Inbox registration is not bound to a valid identity offer")
                }
            default:
                return .error("Unsupported inbox registration version")
            }
            let accessFingerprint = CryptoBox.fingerprint(for: registration.accessPublicKey)
            if let proofFailure = await validateActorProof(
                registration.accessProof,
                expectedFingerprint: accessFingerprint,
                expectedSigningKey: registration.accessPublicKey,
                signableDataBuilder: { proof in try registration.signableData(for: proof) }
            ) {
                return proofFailure
            }
            do {
                let receipt = try await store.registerInbox(
                    inboxId: registration.inboxId,
                    accessPublicKey: registration.accessPublicKey
                )
                return .ok(
                    inboxRegistration: configuration.opaqueRouteCapabilitiesEnabled
                        ? receipt
                        : nil
                )
            } catch RelayStoreError.inboxAlreadyRegistered {
                return .error("Inbox is already registered to another access key")
            } catch RelayStoreError.inboxRetired {
                return .error("Inbox is retired")
            } catch RelayStoreError.relayCapacityExceeded {
                return .error("Relay storage capacity reached")
            } catch {
                return .error("Invalid inbox registration")
            }
        case .retireInbox:
            guard let retirement = request.retireInbox,
                  InboxAddress.isValid(retirement.inboxId),
                  let requestDigest = try? retirement.requestDigest() else {
                return .error("Invalid inbox retirement request")
            }
            if await store.isInboxRetired(inboxId: retirement.inboxId) {
                guard await store.isMatchingInboxRetirement(
                    inboxId: retirement.inboxId,
                    requestDigest: requestDigest
                ) else {
                    return .error("Inbox retirement request does not match tombstone")
                }
                return .ok()
            }
            let accessPublicKey = await store.inboxAccessPublicKey(for: retirement.inboxId)
            guard let proofSigningKey = retirement.accessProof?.publicSigningKey else {
                return .error("Missing inbox retirement proof.")
            }
            if let proofFailure = validateInboxRetirementProof(
                retirement.accessProof,
                inboxId: retirement.inboxId,
                expectedSigningKey: accessPublicKey ?? proofSigningKey,
                signableDataBuilder: { proof in try retirement.signableData(for: proof) }
            ) {
                return proofFailure
            }
            do {
                // Persist the non-resurrection marker even when this relay has
                // no live registration. That makes a pre-signed burn request
                // safe after partial state loss and prevents later reuse.
                try await store.retireInbox(
                    inboxId: retirement.inboxId,
                    requestDigest: requestDigest
                )
                return .ok()
            } catch RelayStoreError.invalidInboxRetirement {
                return .error("Inbox retirement request does not match tombstone")
            } catch RelayStoreError.relayCapacityExceeded {
                return .error("Relay lifetime inbox capacity reached")
            } catch {
                return .error("Relay storage is unavailable")
            }
        case .createInboxRouteCapability:
            guard configuration.opaqueRouteCapabilitiesEnabled else {
                return .error("Experimental opaque route capabilities are disabled")
            }
            guard let mutation = request.createInboxRouteCapability,
                  InboxAddress.isValid(mutation.inboxId),
                  mutation.capability.isStructurallyValid,
                  mutation.relayScope.isValidRouteMutationScope,
                  mutation.mutationSequence > 0,
                  mutation.mutationSequence <= CreateInboxRouteCapabilityRequest.maximumMutationSequence else {
                return .error("Invalid inbox route capability request")
            }
            guard let accessPublicKey = await store.inboxAccessPublicKey(for: mutation.inboxId) else {
                return .error("Inbox is not registered")
            }
            guard let mutationDigest = try? mutation.mutationDigest() else {
                return .error("Invalid inbox route capability request")
            }
            let isCurrentReplay = await store.isCurrentInboxRouteCapabilityMutation(
                inboxId: mutation.inboxId,
                relayScope: mutation.relayScope,
                mutationSequence: mutation.mutationSequence,
                mutationDigest: mutationDigest
            )
            let accessFingerprint = CryptoBox.fingerprint(for: accessPublicKey)
            if let proofFailure = validateActorProofCryptographically(
                mutation.authorityProof,
                expectedFingerprint: accessFingerprint,
                expectedSigningKey: accessPublicKey,
                enforceFreshness: !isCurrentReplay,
                signableDataBuilder: { proof in try mutation.signableData(for: proof) }
            ) {
                return proofFailure
            }
            do {
                _ = try await store.applyInboxRouteCapabilityMutation(
                    operation: .create,
                    inboxId: mutation.inboxId,
                    capability: mutation.capability,
                    relayScope: mutation.relayScope,
                    mutationSequence: mutation.mutationSequence,
                    mutationDigest: mutationDigest
                )
                return .ok()
            } catch RelayStoreError.inboxRouteCapabilityRevoked {
                return .error("Inbox route capability is revoked")
            } catch RelayStoreError.inboxRouteCapabilityLimitReached {
                return .error("Inbox route capability limit reached")
            } catch RelayStoreError.relayCapacityExceeded {
                return .error("Relay route capability capacity reached")
            } catch RelayStoreError.inboxRetired {
                return .error("Inbox is retired")
            } catch RelayStoreError.invalidInboxRouteCapabilityMutation {
                return .error("Inbox route capability relay scope mismatch")
            } catch RelayStoreError.inboxRouteCapabilityMutationConflict {
                return .error("Inbox route capability mutation sequence conflict")
            } catch RelayStoreError.inboxRouteCapabilityMutationOutOfOrder {
                return .error("Inbox route capability mutation is out of order")
            } catch RelayStoreError.destinationInboxNotRegistered {
                return .error("Inbox is not registered")
            } catch {
                return .error("Relay storage is unavailable")
            }
        case .revokeInboxRouteCapability:
            guard configuration.opaqueRouteCapabilitiesEnabled else {
                return .error("Experimental opaque route capabilities are disabled")
            }
            guard let mutation = request.revokeInboxRouteCapability,
                  InboxAddress.isValid(mutation.inboxId),
                  mutation.capability.isStructurallyValid,
                  mutation.relayScope.isValidRouteMutationScope,
                  mutation.mutationSequence > 0,
                  mutation.mutationSequence <= CreateInboxRouteCapabilityRequest.maximumMutationSequence else {
                return .error("Invalid inbox route capability request")
            }
            guard let accessPublicKey = await store.inboxAccessPublicKey(for: mutation.inboxId) else {
                return .error("Inbox is not registered")
            }
            guard let mutationDigest = try? mutation.mutationDigest() else {
                return .error("Invalid inbox route capability request")
            }
            let isCurrentReplay = await store.isCurrentInboxRouteCapabilityMutation(
                inboxId: mutation.inboxId,
                relayScope: mutation.relayScope,
                mutationSequence: mutation.mutationSequence,
                mutationDigest: mutationDigest
            )
            let accessFingerprint = CryptoBox.fingerprint(for: accessPublicKey)
            if let proofFailure = validateActorProofCryptographically(
                mutation.authorityProof,
                expectedFingerprint: accessFingerprint,
                expectedSigningKey: accessPublicKey,
                enforceFreshness: !isCurrentReplay,
                signableDataBuilder: { proof in try mutation.signableData(for: proof) }
            ) {
                return proofFailure
            }
            do {
                _ = try await store.applyInboxRouteCapabilityMutation(
                    operation: .revoke,
                    inboxId: mutation.inboxId,
                    capability: mutation.capability,
                    relayScope: mutation.relayScope,
                    mutationSequence: mutation.mutationSequence,
                    mutationDigest: mutationDigest
                )
                return .ok()
            } catch RelayStoreError.relayCapacityExceeded {
                return .error("Relay route capability capacity reached")
            } catch RelayStoreError.inboxRetired {
                return .error("Inbox is retired")
            } catch RelayStoreError.invalidInboxRouteCapabilityMutation {
                return .error("Inbox route capability relay scope mismatch")
            } catch RelayStoreError.inboxRouteCapabilityMutationConflict {
                return .error("Inbox route capability mutation sequence conflict")
            } catch RelayStoreError.inboxRouteCapabilityMutationOutOfOrder {
                return .error("Inbox route capability mutation is out of order")
            } catch RelayStoreError.destinationInboxNotRegistered {
                return .error("Inbox is not registered")
            } catch {
                return .error("Relay storage is unavailable")
            }
        case .registerRendezvousTransportV2:
            guard configuration.isRendezvousTransportEnabled else {
                return .error("Rendezvous transport is disabled")
            }
            guard configuration.tlsEnabled || isLiteralLoopbackSource(sourceKey) else {
                return .error("Rendezvous transport requires confidential transport")
            }
            guard let registration = request.registerRendezvousTransportV2,
                  registration.isStructurallyValid() else {
                return .error("Invalid rendezvous transport request")
            }
            do {
                try await store.registerRendezvousTransportV2(registration)
                return .ok()
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error)
            } catch {
                return .error("Relay storage is unavailable")
            }
        case .appendRendezvousTransportV2:
            guard configuration.isRendezvousTransportEnabled else {
                return .error("Rendezvous transport is disabled")
            }
            guard configuration.tlsEnabled || isLiteralLoopbackSource(sourceKey) else {
                return .error("Rendezvous transport requires confidential transport")
            }
            guard let append = request.appendRendezvousTransportV2,
                  append.isStructurallyValid else {
                return .error("Invalid rendezvous transport request")
            }
            do {
                _ = try await store.appendRendezvousTransportV2(append)
                return .ok()
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error)
            } catch {
                return .error("Relay storage is unavailable")
            }
        case .syncRendezvousTransportV2:
            guard configuration.isRendezvousTransportEnabled else {
                return .error("Rendezvous transport is disabled")
            }
            guard configuration.tlsEnabled || isLiteralLoopbackSource(sourceKey) else {
                return .error("Rendezvous transport requires confidential transport")
            }
            guard let sync = request.syncRendezvousTransportV2,
                  sync.isStructurallyValid else {
                return .error("Invalid rendezvous transport request")
            }
            do {
                return .rendezvousSyncV2(try await store.syncRendezvousTransportV2(sync))
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error)
            } catch {
                return .error("Relay storage is unavailable")
            }
        case .deleteRendezvousTransportV2:
            guard configuration.isRendezvousTransportEnabled else {
                return .error("Rendezvous transport is disabled")
            }
            guard configuration.tlsEnabled || isLiteralLoopbackSource(sourceKey) else {
                return .error("Rendezvous transport requires confidential transport")
            }
            guard let deletion = request.deleteRendezvousTransportV2,
                  deletion.isStructurallyValid else {
                return .error("Invalid rendezvous transport request")
            }
            do {
                try await store.deleteRendezvousTransportV2(deletion)
                return .ok()
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error)
            } catch {
                return .error("Relay storage is unavailable")
            }
        case .fetch:
            guard let fetch = request.fetch else {
                return .error("Missing fetch payload")
            }
            let routingToken = fetch.routingToken ?? fetch.inboxId
            guard InboxAddress.isValid(routingToken) else {
                return .error("Invalid routing token")
            }
            guard let accessPublicKey = await store.inboxAccessPublicKey(for: routingToken) else {
                return .error("Inbox is not registered")
            }
            guard !(await store.hasMailboxConsumerBindings(inboxId: routingToken)) else {
                return .error("Legacy mailbox fetch is disabled for endpoint-managed inboxes")
            }
            let accessFingerprint = CryptoBox.fingerprint(for: accessPublicKey)
            if let proofFailure = await validateActorProof(
                fetch.accessProof,
                expectedFingerprint: accessFingerprint,
                expectedSigningKey: accessPublicKey,
                signableDataBuilder: { proof in try fetch.signableData(for: proof) }
            ) {
                return proofFailure
            }
            let messages = try await fetchWithOptionalLongPoll(fetch, routingToken: routingToken)
            onEvent?(.fetched(inboxId: routingToken, count: messages.count))
            return .messages(messages)
        case .acknowledgeMessages:
            guard let acknowledgement = request.acknowledgeMessages else {
                return .error("Missing acknowledgement payload")
            }
            guard InboxAddress.isValid(acknowledgement.inboxId),
                  !acknowledgement.messageIds.isEmpty,
                  acknowledgement.messageIds.count <= 1_000 else {
                return .error("Invalid acknowledgement")
            }
            guard let accessPublicKey = await store.inboxAccessPublicKey(for: acknowledgement.inboxId) else {
                return .error("Inbox is not registered")
            }
            guard !(await store.hasMailboxConsumerBindings(inboxId: acknowledgement.inboxId)) else {
                return .error("Legacy mailbox acknowledgement is disabled for endpoint-managed inboxes")
            }
            let accessFingerprint = CryptoBox.fingerprint(for: accessPublicKey)
            if let proofFailure = await validateActorProof(
                acknowledgement.accessProof,
                expectedFingerprint: accessFingerprint,
                expectedSigningKey: accessPublicKey,
                signableDataBuilder: { proof in try acknowledgement.signableData(for: proof) }
            ) {
                return proofFailure
            }
            _ = try await store.acknowledge(
                inboxId: acknowledgement.inboxId,
                messageIds: acknowledgement.messageIds
            )
            return .ok()
        case .registerMailboxConsumer:
            guard let registration = request.registerMailboxConsumer,
                  InboxAddress.isValid(registration.inboxId),
                  registration.consumerId.isStructurallyValid,
                  registration.sponsorConsumerId?.isStructurallyValid ?? true,
                  SigningKeyPair.isValidPublicKey(registration.consumerSigningPublicKey) else {
                return .error("Invalid mailbox consumer registration")
            }
            guard !(await store.isInboxRetired(inboxId: registration.inboxId)) else {
                return .error("Inbox is retired")
            }
            guard let accessPublicKey = await store.inboxAccessPublicKey(for: registration.inboxId) else {
                return .error("Invalid mailbox consumer registration")
            }
            let accessFingerprint = CryptoBox.fingerprint(for: accessPublicKey)
            if let proofFailure = await validateActorProof(
                registration.authorityProof,
                expectedFingerprint: accessFingerprint,
                expectedSigningKey: accessPublicKey,
                signableDataBuilder: { proof in try registration.authoritySignableData(for: proof) }
            ) {
                return proofFailure
            }
            let consumerFingerprint = CryptoBox.fingerprint(for: registration.consumerSigningPublicKey)
            if let proofFailure = await validateActorProof(
                registration.consumerProof,
                expectedFingerprint: consumerFingerprint,
                expectedSigningKey: registration.consumerSigningPublicKey,
                signableDataBuilder: { proof in try registration.consumerSignableData(for: proof) }
            ) {
                return proofFailure
            }
            let existingConsumer = await store.mailboxConsumer(
                inboxId: registration.inboxId,
                consumerId: registration.consumerId
            )
            let activeBoundConsumers = await store.mailboxConsumers(inboxId: registration.inboxId)
                .filter {
                    $0.state == .active
                        && $0.consumerSigningPublicKey.map(SigningKeyPair.isValidPublicKey) == true
                }
            let isManaged = await store.hasMailboxConsumerBindings(inboxId: registration.inboxId)
            let requiresSponsor: Bool
            if let existingConsumer {
                requiresSponsor = existingConsumer.state == .active
                    && existingConsumer.consumerSigningPublicKey == nil
                    && !activeBoundConsumers.isEmpty
            } else {
                guard !isManaged || !activeBoundConsumers.isEmpty else {
                    return mailboxSyncErrorResponse(MailboxSyncError.freshInboxRequired)
                }
                requiresSponsor = isManaged
            }
            if requiresSponsor {
                guard let sponsorConsumerId = registration.sponsorConsumerId,
                      sponsorConsumerId != registration.consumerId,
                      let sponsorSigningPublicKey = await store.activeMailboxConsumerSigningPublicKey(
                        inboxId: registration.inboxId,
                        consumerId: sponsorConsumerId
                      ) else {
                    return mailboxSyncErrorResponse(MailboxSyncError.consumerSponsorRequired)
                }
                let sponsorFingerprint = CryptoBox.fingerprint(for: sponsorSigningPublicKey)
                if let proofFailure = await validateActorProof(
                    registration.sponsorProof,
                    expectedFingerprint: sponsorFingerprint,
                    expectedSigningKey: sponsorSigningPublicKey,
                    signableDataBuilder: { proof in try registration.sponsorSignableData(for: proof) }
                ) {
                    return proofFailure
                }
            }
            do {
                return .mailboxConsumer(
                    try await store.registerMailboxConsumer(
                        inboxId: registration.inboxId,
                        consumerId: registration.consumerId,
                        consumerSigningPublicKey: registration.consumerSigningPublicKey,
                        sponsorConsumerId: registration.sponsorConsumerId,
                        startingSequence: registration.startingSequence
                    )
                )
            } catch {
                return mailboxSyncErrorResponse(error)
            }
        case .syncMailbox:
            guard let sync = request.syncMailbox,
                  InboxAddress.isValid(sync.inboxId),
                  sync.consumerId.isStructurallyValid,
                  sync.cursor?.isStructurallyValid ?? true,
                  (sync.maxCount ?? 100) > 0,
                  (sync.maxCount ?? 100) <= 256,
                  let consumerSigningPublicKey = await store.mailboxConsumerSigningPublicKey(
                    inboxId: sync.inboxId,
                    consumerId: sync.consumerId
                  ) else {
                return .error("Invalid mailbox sync request")
            }
            let consumerFingerprint = CryptoBox.fingerprint(for: consumerSigningPublicKey)
            if let proofFailure = await validateActorProof(
                sync.consumerProof,
                expectedFingerprint: consumerFingerprint,
                expectedSigningKey: consumerSigningPublicKey,
                signableDataBuilder: { proof in try sync.signableData(for: proof) }
            ) {
                return proofFailure
            }
            do {
                return .mailboxSync(try await syncMailboxWithOptionalLongPoll(sync))
            } catch {
                return mailboxSyncErrorResponse(error)
            }
        case .commitMailboxCursor:
            guard let commit = request.commitMailboxCursor,
                  InboxAddress.isValid(commit.inboxId),
                  commit.consumerId.isStructurallyValid,
                  commit.cursor.isStructurallyValid,
                  let consumerSigningPublicKey = await store.mailboxConsumerSigningPublicKey(
                    inboxId: commit.inboxId,
                    consumerId: commit.consumerId
                  ) else {
                return .error("Invalid mailbox cursor commit")
            }
            let consumerFingerprint = CryptoBox.fingerprint(for: consumerSigningPublicKey)
            if let proofFailure = await validateActorProof(
                commit.consumerProof,
                expectedFingerprint: consumerFingerprint,
                expectedSigningKey: consumerSigningPublicKey,
                signableDataBuilder: { proof in try commit.signableData(for: proof) }
            ) {
                return proofFailure
            }
            do {
                return .mailboxConsumer(
                    try await store.commitMailboxCursor(
                        inboxId: commit.inboxId,
                        consumerId: commit.consumerId,
                        cursor: commit.cursor,
                        sequence: commit.sequence
                    )
                )
            } catch {
                return mailboxSyncErrorResponse(error)
            }
        case .revokeMailboxConsumer:
            guard let revocation = request.revokeMailboxConsumer,
                  InboxAddress.isValid(revocation.inboxId),
                  revocation.consumerId.isStructurallyValid,
                  let accessPublicKey = await store.inboxAccessPublicKey(for: revocation.inboxId) else {
                return .error("Invalid mailbox consumer revocation")
            }
            let accessFingerprint = CryptoBox.fingerprint(for: accessPublicKey)
            if let proofFailure = await validateActorProof(
                revocation.authorityProof,
                expectedFingerprint: accessFingerprint,
                expectedSigningKey: accessPublicKey,
                signableDataBuilder: { proof in try revocation.signableData(for: proof) }
            ) {
                return proofFailure
            }
            do {
                return .mailboxConsumer(
                    try await store.revokeMailboxConsumer(
                        inboxId: revocation.inboxId,
                        consumerId: revocation.consumerId
                    )
                )
            } catch {
                return mailboxSyncErrorResponse(error)
            }
        case .deliverGroupMessage:
            guard let deliver = request.deliverGroupMessage else {
                return .error("Missing group message delivery payload")
            }
            guard InboxAddress.isValid(deliver.groupInboxId),
                  deliver.envelope.groupId == deliver.groupId else {
                return .error("Invalid group message delivery")
            }
            if let destination = deliver.destinationRelay,
               destination != localEndpoint {
                do {
                    if let response = try await federationGate(forwardingTo: destination) {
                        return response
                    }
                    let forward = DeliverGroupMessageRequest(
                        groupId: deliver.groupId,
                        groupInboxId: deliver.groupInboxId,
                        envelope: deliver.envelope
                    )
                    let client = RelayClient(endpoint: destination, authToken: configuration.federationForwardingAuthToken)
                    return try await client.send(.deliverGroupMessage(forward))
                } catch {
                    return .error("Forwarding failed")
                }
            }
            guard let group = await store.fetchGroup(groupId: deliver.groupId),
                  group.inboxId == deliver.groupInboxId else {
                return .error("Destination group inbox is not registered")
            }
            guard group.mlsEpochState.protocolVersion == MLSGroupEpochState.currentProtocolVersion,
                  group.mlsEpochState.cipherSuite == MLSGroupEpochState.currentCipherSuite,
                  deliver.envelope.protocolVersion == group.mlsEpochState.protocolVersion,
                  deliver.envelope.cipherSuite == group.mlsEpochState.cipherSuite,
                  deliver.envelope.epoch == group.mlsEpochState.epoch,
                  deliver.envelope.transcriptHash == group.mlsEpochState.confirmedTranscriptHash else {
                return .error("Group message does not match the current authenticated epoch")
            }
            guard let senderKey = registeredSigningKey(
                for: deliver.envelope.senderFingerprint,
                in: group
            ),
                  deliver.envelope.verifySignature(publicSigningKey: senderKey) else {
                return .error("Invalid group message signature")
            }
            do {
                let recipientFingerprints = group.members
                    .map(\.fingerprint)
                    .filter { $0 != deliver.envelope.senderFingerprint }
                let count = try await store.deliverGroupEnvelope(
                    carrierEnvelope(for: deliver.envelope),
                    to: deliver.groupInboxId,
                    recipientFingerprints: recipientFingerprints
                )
                onEvent?(.delivered(inboxId: deliver.groupInboxId, storedCount: count))
                return .delivered(count: count)
            } catch RelayStoreError.inboxFull {
                return .error("Inbox full")
            } catch RelayStoreError.destinationInboxNotRegistered {
                return .error("Destination group inbox is not registered")
            } catch RelayStoreError.inboxRetired {
                return .error("Destination group inbox is retired")
            } catch RelayStoreError.relayCapacityExceeded {
                return .error("Relay storage capacity reached")
            } catch RelayStoreError.invalidEnvelopePayload {
                return .error("Invalid envelope payload")
            }
        case .fetchGroupMessages:
            guard let fetch = request.fetchGroupMessages else {
                return .error("Missing group message fetch payload")
            }
            guard InboxAddress.isValid(fetch.groupInboxId) else {
                return .error("Invalid group inbox")
            }
            guard let group = await store.fetchGroup(groupId: fetch.groupId),
                  group.inboxId == fetch.groupInboxId else {
                return .error("Group not found")
            }
            guard let signingKey = registeredSigningKey(for: fetch.actorFingerprint, in: group) else {
                return .error("Actor is not a group member")
            }
            if let proofFailure = await validateActorProof(
                fetch.actorProof,
                expectedFingerprint: fetch.actorFingerprint,
                expectedSigningKey: signingKey,
                signableDataBuilder: { proof in try fetch.signableData(for: proof) }
            ) {
                return proofFailure
            }
            let messages = try await fetchGroupMessagesWithOptionalLongPoll(fetch)
            onEvent?(.fetched(inboxId: fetch.groupInboxId, count: messages.count))
            return .groupMessages(messages)
        case .acknowledgeGroupMessages:
            guard let acknowledgement = request.acknowledgeGroupMessages else {
                return .error("Missing group acknowledgement payload")
            }
            guard InboxAddress.isValid(acknowledgement.groupInboxId),
                  !acknowledgement.messageIds.isEmpty,
                  acknowledgement.messageIds.count <= 1_000 else {
                return .error("Invalid group acknowledgement")
            }
            guard let group = await store.fetchGroup(groupId: acknowledgement.groupId),
                  group.inboxId == acknowledgement.groupInboxId else {
                return .error("Group not found")
            }
            guard let signingKey = registeredSigningKey(for: acknowledgement.actorFingerprint, in: group) else {
                return .error("Actor is not a group member")
            }
            if let proofFailure = await validateActorProof(
                acknowledgement.actorProof,
                expectedFingerprint: acknowledgement.actorFingerprint,
                expectedSigningKey: signingKey,
                signableDataBuilder: { proof in try acknowledgement.signableData(for: proof) }
            ) {
                return proofFailure
            }
            _ = try await store.acknowledgeGroupEnvelopes(
                inboxId: acknowledgement.groupInboxId,
                messageIds: acknowledgement.messageIds,
                recipientFingerprint: acknowledgement.actorFingerprint
            )
            return .ok()
        case .health:
            return .ok()
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
            return .info(info)
        case .announce:
            guard let announce = request.announce else {
                return .error("Missing announce payload")
            }
            do {
                _ = try announce.offer.verified()
            } catch {
                return .error("Invalid contact offer.")
            }
            let announcement = await store.announce(announce.offer, ttlSeconds: announce.ttlSeconds)
            return .announcements([announcement])
        case .listAnnouncements:
            guard let list = request.listAnnouncements else {
                return .error("Missing list payload")
            }
            let announcements = await store.listAnnouncements(limit: list.limit)
            return .announcements(announcements)
        case .sendPairRequest:
            guard let pair = request.sendPairRequest else {
                return .error("Missing pair request payload")
            }
            guard isValidIdentityFingerprint(pair.targetFingerprint) else {
                return .error("Invalid target fingerprint.")
            }
            do {
                _ = try pair.offer.verified()
            } catch {
                return .error("Invalid contact offer.")
            }
            if let proofFailure = await validateActorProof(
                pair.actorProof,
                expectedFingerprint: pair.offer.fingerprint,
                expectedSigningKey: pair.offer.signingPublicKey,
                signableDataBuilder: { proof in try pair.signableData(for: proof) }
            ) {
                return proofFailure
            }
            _ = await store.sendPairRequest(targetFingerprint: pair.targetFingerprint, offer: pair.offer)
            return .ok()
        case .fetchPairRequests:
            guard let fetch = request.fetchPairRequests else {
                return .error("Missing fetch pair payload")
            }
            let fingerprint = fetch.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard isValidIdentityFingerprint(fingerprint) else {
                return .error("Invalid fingerprint.")
            }
            if let proofFailure = await validateActorProof(
                fetch.actorProof,
                expectedFingerprint: fingerprint,
                expectedSigningKey: nil,
                signableDataBuilder: { proof in try fetch.signableData(for: proof) }
            ) {
                return proofFailure
            }
            let requests = await store.fetchPairRequests(targetFingerprint: fetch.fingerprint, maxCount: fetch.maxCount)
            return .pairRequests(requests)
        case .uploadAttachment:
            guard configuration.attachmentsEnabled != false else {
                return .error("Attachments are disabled on this relay")
            }
            guard let upload = request.uploadAttachment else {
                return .error("Missing upload attachment payload")
            }
            let boundedTTL = boundedAttachmentTTL(requested: upload.ttlSeconds)
            do {
                let chunk = try await store.storeAttachment(
                    attachmentId: upload.attachmentId,
                    chunkIndex: upload.chunkIndex,
                    payload: upload.payload,
                    ttlSeconds: boundedTTL
                )
                return .attachment(chunk)
            } catch RelayStoreError.invalidChunkIndex {
                return .error("Invalid chunk index")
            } catch RelayStoreError.invalidAttachmentPayload {
                return .error("Invalid attachment payload")
            } catch {
                return .error("Attachment store error")
            }
        case .fetchAttachment:
            guard configuration.attachmentsEnabled != false else {
                return .error("Attachments are disabled on this relay")
            }
            guard let fetch = request.fetchAttachment else {
                return .error("Missing fetch attachment payload")
            }
            do {
                if let chunk = try await store.fetchAttachment(
                    attachmentId: fetch.attachmentId,
                    chunkIndex: fetch.chunkIndex
                ) {
                    return .attachment(chunk)
                }
                return .error("Attachment not found")
            } catch RelayStoreError.invalidChunkIndex {
                return .error("Invalid chunk index")
            } catch {
                return .error("Attachment store error")
            }
        case .uploadPrekeys:
            guard let upload = request.uploadPrekeys else {
                return .error("Missing prekey bundle payload")
            }
            let fingerprint = upload.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard fingerprint == upload.bundle.identityFingerprint else {
                return .error("Prekey bundle fingerprint mismatch.")
            }
            if let proofFailure = await validateActorProof(
                upload.actorProof,
                expectedFingerprint: fingerprint,
                expectedSigningKey: nil,
                signableDataBuilder: { proof in try upload.signableData(for: proof) }
            ) {
                return proofFailure
            }
            guard let publicSigningKey = upload.actorProof?.publicSigningKey,
                  upload.bundle.isStructurallyValid(),
                  upload.bundle.signedPrekey.verify(using: publicSigningKey),
                  upload.bundle.oneTimePrekeys.allSatisfy({ $0.verify(using: publicSigningKey) }) else {
                return .error("Invalid authenticated prekey bundle.")
            }
            do {
                try await store.uploadPrekeyBundle(
                    fingerprint: fingerprint,
                    bundle: upload.bundle,
                    ttlSeconds: upload.ttlSeconds
                )
                return .ok()
            } catch RelayStoreError.invalidPrekeyBundle {
                return .error("Invalid prekey bundle.")
            }
        case .fetchPrekeyBundle:
            guard let fetch = request.fetchPrekeyBundle else {
                return .error("Missing fetch prekey payload")
            }
            let bundle = try await store.fetchPrekeyBundle(fingerprint: fetch.fingerprint)
            return .prekeyBundle(bundle)
        case .createGroup:
            guard let create = request.createGroup else {
                return .error("Missing create group payload")
            }
            guard configuration.groupCreationMode != .disabled else {
                return .error("Group creation is disabled on this relay.")
            }
            let creatorFingerprint = create.creatorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !creatorFingerprint.isEmpty else {
                return .error("Invalid fingerprint")
            }
            guard let creatorProfile = create.creatorProfile,
                  let creatorSigningKey = creatorProfile.signingPublicKey,
                  !creatorSigningKey.isEmpty else {
                return .error("Creator profile must include a signing key.")
            }
            guard creatorProfile.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines) == creatorFingerprint else {
                return .error("Creator profile fingerprint mismatch.")
            }
            if let proofFailure = await validateActorProof(
                create.creatorProof,
                expectedFingerprint: creatorFingerprint,
                expectedSigningKey: creatorSigningKey,
                signableDataBuilder: { proof in try create.signableData(for: proof) }
            ) {
                return proofFailure
            }
            do {
                let group = try await store.createGroup(
                    groupId: create.groupId,
                    title: create.title,
                    creatorFingerprint: create.creatorFingerprint,
                    memberFingerprints: create.memberFingerprints,
                    creatorProfile: create.creatorProfile,
                    memberProfiles: create.memberProfiles,
                    invitedFingerprints: create.invitedFingerprints,
                    initialRatchetSecretDistribution: create.initialRatchetSecretDistribution
                )
                return .group(group)
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error)
            } catch {
                return .error("Group creation failed")
            }
        case .getGroup:
            guard let get = request.getGroup else {
                return .error("Missing get group payload")
            }
            guard let group = await store.fetchGroup(groupId: get.groupId) else {
                return .group(nil)
            }
            let memberFingerprint = get.memberFingerprint?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !memberFingerprint.isEmpty else {
                return .error("Group membership is required")
            }
            let memberKey = registeredSigningKey(for: memberFingerprint, in: group)
            let isInvited = await store.hasGroupInvitation(
                groupId: get.groupId,
                invitedFingerprint: memberFingerprint
            )
            guard memberKey != nil || isInvited else {
                return .error("Group membership is required")
            }
            if let proofFailure = await validateActorProof(
                get.memberProof,
                expectedFingerprint: memberFingerprint,
                expectedSigningKey: memberKey,
                signableDataBuilder: { proof in try get.signableData(for: proof) }
            ) {
                return proofFailure
            }
            return .group(group)
        case .listGroups:
            guard let list = request.listGroups else {
                return .error("Missing list groups payload")
            }
            let memberFingerprint = list.memberFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !memberFingerprint.isEmpty else {
                return .error("Invalid fingerprint")
            }
            if let proofFailure = await validateActorProof(
                list.memberProof,
                expectedFingerprint: memberFingerprint,
                expectedSigningKey: nil,
                signableDataBuilder: { proof in try list.signableData(for: proof) }
            ) {
                return proofFailure
            }
            let groups = await store.listGroups(memberFingerprint: list.memberFingerprint, limit: list.limit)
            return .groups(groups)
        case .listGroupInvitations:
            guard let list = request.listGroupInvitations else {
                return .error("Missing list invitations payload")
            }
            let invitedFingerprint = list.invitedFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !invitedFingerprint.isEmpty else {
                return .error("Invalid fingerprint")
            }
            if let proofFailure = await validateActorProof(
                list.invitedProof,
                expectedFingerprint: invitedFingerprint,
                expectedSigningKey: nil,
                signableDataBuilder: { proof in try list.signableData(for: proof) }
            ) {
                return proofFailure
            }
            let invitations = await store.listGroupInvitations(list)
            return .groupInvitations(invitations)
        case .inviteGroupMembers:
            guard let invite = request.inviteGroupMembers else {
                return .error("Missing invite group members payload")
            }
            guard let group = await store.fetchGroup(groupId: invite.groupId) else {
                return relayStoreErrorResponse(.groupNotFound)
            }
            let actorFingerprint = invite.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard actorFingerprint == group.createdByFingerprint else {
                return relayStoreErrorResponse(.unauthorizedGroupMutation)
            }
            guard let actorSigningKey = registeredSigningKey(
                for: actorFingerprint,
                in: group
            ) else {
                return .error("Group creator signing key is missing. Re-pair and re-join the group.")
            }
            if let proofFailure = await validateActorProof(
                invite.actorProof,
                expectedFingerprint: actorFingerprint,
                expectedSigningKey: actorSigningKey,
                signableDataBuilder: { proof in try invite.signableData(for: proof) }
            ) {
                return proofFailure
            }
            do {
                let group = try await store.inviteGroupMembers(invite)
                return .group(group)
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error)
            } catch {
                return .error("Group invitation failed")
            }
        case .updateGroup:
            guard let update = request.updateGroup else {
                return .error("Missing update group payload")
            }
            guard let group = await store.fetchGroup(groupId: update.groupId) else {
                return relayStoreErrorResponse(.groupNotFound)
            }
            let actorFingerprint = update.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !actorFingerprint.isEmpty else {
                return .error("Invalid fingerprint")
            }
            guard let actorSigningKey = registeredSigningKey(
                for: actorFingerprint,
                in: group
            ) else {
                return .error("Group member signing key is missing. Re-pair and re-join the group.")
            }
            guard let groupCommit = update.groupCommit else {
                return .error("Missing signed group commit")
            }
            if let proofFailure = await validateActorProof(
                groupCommit.actorProof,
                expectedFingerprint: actorFingerprint,
                expectedSigningKey: actorSigningKey,
                signableDataBuilder: { proof in try groupCommit.signableData(for: proof) }
            ) {
                return proofFailure
            }
            do {
                let group = try await store.updateGroup(update)
                return .group(group)
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error)
            } catch {
                return .error("Group update failed")
            }
        case .deleteGroup:
            guard let delete = request.deleteGroup else {
                return .error("Missing delete group payload")
            }
            guard let group = await store.fetchGroup(groupId: delete.groupId) else {
                return relayStoreErrorResponse(.groupNotFound)
            }
            let actorFingerprint = delete.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !actorFingerprint.isEmpty else {
                return .error("Invalid fingerprint")
            }
            guard let actorSigningKey = registeredSigningKey(
                for: actorFingerprint,
                in: group
            ) else {
                return .error("Group member signing key is missing. Re-pair and re-join the group.")
            }
            if let proofFailure = await validateActorProof(
                delete.actorProof,
                expectedFingerprint: actorFingerprint,
                expectedSigningKey: actorSigningKey,
                signableDataBuilder: { proof in try delete.signableData(for: proof) }
            ) {
                return proofFailure
            }
            do {
                try await store.deleteGroup(delete)
                return .ok()
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error)
            } catch {
                return .error("Delete group failed")
            }
        case .requestGroupJoin:
            guard let join = request.requestGroupJoin else {
                return .error("Missing request join payload")
            }
            let requesterFingerprint = join.requesterProfile.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !requesterFingerprint.isEmpty else {
                return .error("Invalid fingerprint")
            }
            guard let requesterSigningKey = join.requesterProfile.signingPublicKey,
                  !requesterSigningKey.isEmpty else {
                return .error("Requester profile must include a signing key.")
            }
            if let proofFailure = await validateActorProof(
                join.requesterProof,
                expectedFingerprint: requesterFingerprint,
                expectedSigningKey: requesterSigningKey,
                signableDataBuilder: { proof in try join.signableData(for: proof) }
            ) {
                return proofFailure
            }
            if let groupCommit = join.groupCommit {
                if let proofFailure = await validateActorProof(
                    groupCommit.actorProof,
                    expectedFingerprint: requesterFingerprint,
                    expectedSigningKey: requesterSigningKey,
                    signableDataBuilder: { proof in try groupCommit.signableData(for: proof) }
                ) {
                    return proofFailure
                }
            }
            do {
                if join.invitedFingerprint?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false,
                   join.groupCommit != nil {
                    let group = try await store.acceptGroupInvitation(join)
                    return .group(group)
                }
                let created = try await store.requestGroupJoin(join)
                return .groupJoinRequests([created])
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error)
            } catch {
                return .error("Group join request failed")
            }
        case .listGroupJoinRequests:
            guard let list = request.listGroupJoinRequests else {
                return .error("Missing list join payload")
            }
            guard let group = await store.fetchGroup(groupId: list.groupId) else {
                return relayStoreErrorResponse(.groupNotFound)
            }
            let actorFingerprint = list.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !actorFingerprint.isEmpty else {
                return .error("Invalid fingerprint")
            }
            guard let actorSigningKey = registeredSigningKey(
                for: actorFingerprint,
                in: group
            ) else {
                return .error("Group member signing key is missing. Re-pair and re-join the group.")
            }
            if let proofFailure = await validateActorProof(
                list.actorProof,
                expectedFingerprint: actorFingerprint,
                expectedSigningKey: actorSigningKey,
                signableDataBuilder: { proof in try list.signableData(for: proof) }
            ) {
                return proofFailure
            }
            do {
                let requests = try await store.listGroupJoinRequests(list)
                return .groupJoinRequests(requests)
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error)
            } catch {
                return .error("List join requests failed")
            }
        case .approveGroupJoin:
            guard let approve = request.approveGroupJoin else {
                return .error("Missing approve join payload")
            }
            guard let group = await store.fetchGroup(groupId: approve.groupId) else {
                return relayStoreErrorResponse(.groupNotFound)
            }
            let actorFingerprint = approve.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !actorFingerprint.isEmpty else {
                return .error("Invalid fingerprint")
            }
            guard let actorSigningKey = registeredSigningKey(
                for: actorFingerprint,
                in: group
            ) else {
                return .error("Group member signing key is missing. Re-pair and re-join the group.")
            }
            if let proofFailure = await validateActorProof(
                approve.actorProof,
                expectedFingerprint: actorFingerprint,
                expectedSigningKey: actorSigningKey,
                signableDataBuilder: { proof in try approve.signableData(for: proof) }
            ) {
                return proofFailure
            }
            if let proofFailure = await validateActorProof(
                approve.groupCommit.actorProof,
                expectedFingerprint: actorFingerprint,
                expectedSigningKey: actorSigningKey,
                signableDataBuilder: { proof in try approve.groupCommit.signableData(for: proof) }
            ) {
                return proofFailure
            }
            do {
                let group = try await store.approveGroupJoin(approve)
                return .group(group)
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error)
            } catch {
                return .error("Approve join failed")
            }
        case .rejectGroupJoin:
            guard let reject = request.rejectGroupJoin else {
                return .error("Missing reject join payload")
            }
            guard let group = await store.fetchGroup(groupId: reject.groupId) else {
                return relayStoreErrorResponse(.groupNotFound)
            }
            let actorFingerprint = reject.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !actorFingerprint.isEmpty else {
                return .error("Invalid fingerprint")
            }
            guard let actorSigningKey = registeredSigningKey(
                for: actorFingerprint,
                in: group
            ) else {
                return .error("Group member signing key is missing. Re-pair and re-join the group.")
            }
            if let proofFailure = await validateActorProof(
                reject.actorProof,
                expectedFingerprint: actorFingerprint,
                expectedSigningKey: actorSigningKey,
                signableDataBuilder: { proof in try reject.signableData(for: proof) }
            ) {
                return proofFailure
            }
            do {
                try await store.rejectGroupJoin(reject)
                return .ok()
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error)
            } catch {
                return .error("Reject join failed")
            }
        case .registerFederationNode:
            guard configuration.kind == .coordinator else {
                return .error("This relay is not a coordinator node.")
            }
            if let authFailure = validateCoordinatorRegistrationAuthentication(token: request.authToken) {
                return authFailure
            }
            guard let registration = request.registerFederationNode else {
                return .error("Missing federation registration payload")
            }
            let federationSource = normalizedFederationSourceKey(sourceKey)
            let allowed = await store.allowFederationRegistration(
                sourceKey: federationSource,
                endpoint: registration.endpoint
            )
            guard allowed else {
                return .error("Coordinator registration throttled. Retry later.")
            }
            if let reachabilityFailure = try await validateFederationRegistrationReachability(registration) {
                return reachabilityFailure
            }
            do {
                let node = try await store.registerFederationNode(registration)
                return .federationNodes([node])
            } catch {
                return .error("Coordinator registration failed")
            }
        case .listFederationNodes:
            let listRequest = request.listFederationNodes ?? ListFederationNodesRequest()
            if configuration.kind == .coordinator {
                let federationSource = normalizedFederationSourceKey(sourceKey)
                let allowed = await store.allowFederationDirectoryList(sourceKey: federationSource)
                guard allowed else {
                    return .error("Coordinator directory listing throttled. Retry later.")
                }
                let nodes = await store.listFederationNodes(listRequest)
                let snapshot = makeCoordinatorDirectorySnapshot(nodes: nodes, request: listRequest)
                if listRequest.requireSignedSnapshot == true, snapshot == nil {
                    return .error("Coordinator snapshot signing is not available.")
                }
                return .federationNodes(nodes, snapshot: snapshot)
            }
            let remoteNodes = try await fetchCoordinatorNodeDirectory(request: listRequest)
            return .federationNodes(remoteNodes)
        case .publishOpenFederationDHTRecord:
            guard let dhtConfiguration = openFederationDHTConfiguration() else {
                return .error("Open-federation DHT is available only on DHT-enabled open non-coordinator relays.")
            }
            guard let publish = request.publishOpenFederationDHTRecord else {
                return .error("Missing open-federation DHT record payload")
            }
            let expectedNamespace = OpenFederationDHTRecord.namespace(federationName: dhtConfiguration.federationName)
            guard publish.namespace == expectedNamespace else {
                return .error("Open-federation DHT namespace mismatch.")
            }
            let result = await store.ingestOpenFederationDHTRecords(
                [publish.record],
                configuration: dhtConfiguration
            )
            guard !result.accepted.isEmpty else {
                let reason = result.rejected.first.map { "\($0.reason)" } ?? "record rejected"
                return .error("Open-federation DHT record rejected: \(reason)")
            }
            return .ok()
        case .listOpenFederationDHTRecords:
            guard let dhtConfiguration = openFederationDHTConfiguration() else {
                return .error("Open-federation DHT is available only on DHT-enabled open non-coordinator relays.")
            }
            guard let list = request.listOpenFederationDHTRecords else {
                return .error("Missing open-federation DHT list payload")
            }
            let expectedNamespace = OpenFederationDHTRecord.namespace(federationName: dhtConfiguration.federationName)
            guard list.namespace == expectedNamespace else {
                return .error("Open-federation DHT namespace mismatch.")
            }
            let records = await store.listOpenFederationDHTRecords(
                configuration: dhtConfiguration,
                limit: list.limit
            )
            return .openFederationDHTRecords(records)
        }
    }

    private func relayStoreErrorResponse(_ error: RelayStoreError) -> RelayResponse {
        switch error {
        case .inboxFull:
            return .error("Inbox full")
        case .invalidInboxRegistration:
            return .error("Invalid inbox registration")
        case .invalidInboxRetirement:
            return .error("Invalid inbox retirement")
        case .inboxAlreadyRegistered:
            return .error("Inbox is already registered")
        case .inboxRetired:
            return .error("Inbox is retired")
        case .invalidInboxRouteCapability, .inboxRouteCapabilityRevoked:
            return .error("Inbox route capability is unavailable")
        case .inboxRouteCapabilityLimitReached:
            return .error("Inbox route capability limit reached")
        case .invalidInboxRouteCapabilityMutation:
            return .error("Invalid inbox route capability mutation")
        case .inboxRouteCapabilityMutationConflict:
            return .error("Inbox route capability mutation conflict")
        case .inboxRouteCapabilityMutationOutOfOrder:
            return .error("Inbox route capability mutation out of order")
        case .invalidRendezvousRoute:
            return .error("Invalid rendezvous transport request")
        case .rendezvousRouteUnavailable:
            return .error("Rendezvous route is unavailable")
        case .rendezvousRegistrationConflict:
            return .error("Rendezvous route registration conflicts with stored state")
        case .rendezvousCapacityReached:
            return .error("Rendezvous transport capacity reached")
        case .rendezvousFrameConflict:
            return .error("Rendezvous frame conflicts with stored state")
        case .rendezvousSequenceGap:
            return .error("Rendezvous lane sequence is not contiguous")
        case .rendezvousQuotaReached:
            return .error("Rendezvous lane quota reached")
        case .destinationInboxNotRegistered:
            return .error("Destination inbox is not registered")
        case .relayCapacityExceeded:
            return .error("Relay storage capacity reached")
        case .invalidEnvelopePayload:
            return .error("Invalid envelope payload")
        case .invalidChunkIndex:
            return .error("Invalid chunk index")
        case .invalidAttachmentPayload:
            return .error("Invalid attachment payload")
        case .invalidPrekeyBundle:
            return .error("Invalid prekey bundle")
        case .groupCapacityExceeded:
            return .error("Group capacity reached")
        case .invalidGroupTitle:
            return .error("Invalid group title")
        case .invalidFingerprint:
            return .error("Invalid fingerprint")
        case .invalidGroupCommit:
            return .error("Invalid group commit")
        case .notEnoughGroupMembers:
            return .error("A group requires at least 2 members")
        case .groupNotFound:
            return .error("Group not found")
        case .unauthorizedGroupMutation:
            return .error("Unauthorized group update")
        case .groupJoinRequestNotFound:
            return .error("Group join request not found")
        case .alreadyGroupMember:
            return .error("Requester is already a group member")
        }
    }

    private func mailboxSyncErrorResponse(_ error: Error) -> RelayResponse {
        switch error {
        case MailboxSyncError.invalidConsumer:
            return .error("Invalid mailbox consumer")
        case MailboxSyncError.consumerNotFound:
            return .error("Mailbox consumer not found")
        case MailboxSyncError.consumerRevoked:
            return .error("Mailbox consumer revoked")
        case MailboxSyncError.consumerCredentialMissing:
            return .error("Mailbox consumer credential is not bound")
        case MailboxSyncError.consumerSigningKeyMismatch:
            return .error("Mailbox consumer signing key mismatch")
        case MailboxSyncError.consumerSponsorRequired:
            return .error("Active mailbox consumer sponsorship is required")
        case MailboxSyncError.invalidConsumerSponsor:
            return .error("Invalid mailbox consumer sponsor")
        case MailboxSyncError.freshInboxRequired:
            return .error("The old inbox has no active route credential; create a fresh identity generation and inbox")
        case MailboxSyncError.invalidCursor:
            return .error("Invalid mailbox cursor")
        case MailboxSyncError.cursorExpired:
            return .error("Mailbox cursor expired; encrypted history recovery is required")
        case MailboxSyncError.cursorRollback:
            return .error("Mailbox cursor rollback rejected")
        case MailboxSyncError.sequenceOverflow:
            return .error("Mailbox sequence exhausted")
        default:
            return .error("Mailbox synchronization failed")
        }
    }

    private func registeredSigningKey(
        for actorFingerprint: String,
        in group: RelayGroupDescriptor
    ) -> Data? {
        guard let key = group.members.first(where: { member in
            member.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines) == actorFingerprint
        })?.signingPublicKey,
            !key.isEmpty else {
            return nil
        }
        return key
    }

    private func validateActorProof(
        _ proof: RelayActorProof?,
        expectedFingerprint: String,
        expectedSigningKey: Data?,
        signableDataBuilder: (RelayActorProof) throws -> Data
    ) async -> RelayResponse? {
        if let failure = validateActorProofCryptographically(
            proof,
            expectedFingerprint: expectedFingerprint,
            expectedSigningKey: expectedSigningKey,
            signableDataBuilder: signableDataBuilder
        ) {
            return failure
        }
        guard let proof else {
            return .error("Missing actor proof.")
        }
        let nonceAccepted = await store.consumeActorProofNonce(
            fingerprint: proof.fingerprint,
            nonce: proof.nonce,
            now: Date(),
            maxAgeSeconds: RelayActorProof.maximumAgeSeconds
        )
        guard nonceAccepted else {
            return .error("Actor proof replay detected.")
        }
        return nil
    }

    private func validateActorProofCryptographically(
        _ proof: RelayActorProof?,
        expectedFingerprint: String,
        expectedSigningKey: Data?,
        enforceFreshness: Bool = true,
        signableDataBuilder: (RelayActorProof) throws -> Data
    ) -> RelayResponse? {
        guard let proof else {
            return .error("Missing actor proof.")
        }
        guard proof.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines) == expectedFingerprint else {
            return .error("Actor proof fingerprint mismatch.")
        }
        guard proof.isConsistentFingerprint() else {
            return .error("Actor proof key does not match fingerprint.")
        }
        if let expectedSigningKey, proof.publicSigningKey != expectedSigningKey {
            return .error("Actor proof signing key mismatch.")
        }
        guard !enforceFreshness
                || abs(proof.signedAt.timeIntervalSinceNow) <= RelayActorProof.maximumAgeSeconds else {
            return .error("Actor proof expired.")
        }
        let signableData: Data
        do {
            signableData = try signableDataBuilder(proof)
        } catch {
            return .error("Invalid actor proof payload.")
        }
        guard proof.verify(signableData: signableData) else {
            return .error("Invalid actor proof signature.")
        }
        return nil
    }

    /// Retirement proofs are intentionally non-expiring and do not consume the
    /// general actor-proof replay cache. The operation is monotonic and bound to
    /// one inbox access key; its durable request digest is the replay boundary.
    /// This lets a client journal the exact request, delete the old private key,
    /// and retry after arbitrary offline time or a relay persistence failure.
    private func validateInboxRetirementProof(
        _ proof: RelayActorProof?,
        inboxId: String,
        expectedSigningKey: Data,
        signableDataBuilder: (RelayActorProof) throws -> Data
    ) -> RelayResponse? {
        guard let proof else {
            return .error("Missing inbox retirement proof.")
        }
        guard InboxAddress.isBound(inboxId, to: proof.publicSigningKey),
              proof.publicSigningKey == expectedSigningKey else {
            return .error("Inbox retirement proof signing key mismatch.")
        }
        guard proof.isConsistentFingerprint() else {
            return .error("Inbox retirement proof key does not match fingerprint.")
        }
        let signableData: Data
        do {
            signableData = try signableDataBuilder(proof)
        } catch {
            return .error("Invalid inbox retirement proof payload.")
        }
        guard proof.verify(signableData: signableData) else {
            return .error("Invalid inbox retirement proof signature.")
        }
        return nil
    }

    private func fetchWithOptionalLongPoll(_ fetch: FetchRequest, routingToken: String) async throws -> [Envelope] {
        var messages = try await store.fetch(inboxId: routingToken, maxCount: fetch.maxCount)
        guard messages.isEmpty,
              let timeout = boundedLongPollTimeoutSeconds(for: fetch) else {
            return messages
        }

        let deadline = Date().addingTimeInterval(TimeInterval(timeout))
        while Date() < deadline {
            let remaining = max(0, deadline.timeIntervalSinceNow)
            let sleepSeconds = min(0.25, remaining)
            if sleepSeconds > 0 {
                try? await Task.sleep(nanoseconds: UInt64(sleepSeconds * 1_000_000_000))
            }
            messages = try await store.fetch(inboxId: routingToken, maxCount: fetch.maxCount)
            if !messages.isEmpty {
                return messages
            }
        }
        return messages
    }

    private func syncMailboxWithOptionalLongPoll(_ request: SyncMailboxRequest) async throws -> MailboxSyncBatch {
        var batch = try await store.syncMailbox(
            inboxId: request.inboxId,
            consumerId: request.consumerId,
            cursor: request.cursor,
            maxCount: request.maxCount
        )
        guard batch.events.isEmpty,
              let timeout = boundedLongPollTimeoutSeconds(requested: request.longPollTimeoutSeconds) else {
            return batch
        }
        let deadline = Date().addingTimeInterval(TimeInterval(timeout))
        while Date() < deadline {
            let remaining = max(0, deadline.timeIntervalSinceNow)
            let sleepSeconds = min(0.25, remaining)
            if sleepSeconds > 0 {
                try? await Task.sleep(nanoseconds: UInt64(sleepSeconds * 1_000_000_000))
            }
            batch = try await store.syncMailbox(
                inboxId: request.inboxId,
                consumerId: request.consumerId,
                cursor: request.cursor,
                maxCount: request.maxCount
            )
            if !batch.events.isEmpty {
                return batch
            }
        }
        return batch
    }

    private func fetchGroupMessagesWithOptionalLongPoll(_ fetch: FetchGroupMessagesRequest) async throws -> [GroupRatchetEnvelope] {
        var messages = try await store.fetchGroupEnvelopes(
            inboxId: fetch.groupInboxId,
            recipientFingerprint: fetch.actorFingerprint,
            maxCount: fetch.maxCount
        )
            .compactMap(groupRatchetEnvelope)
        guard messages.isEmpty,
              let timeout = boundedLongPollTimeoutSeconds(
                requested: fetch.longPollTimeoutSeconds
              ) else {
            return messages
        }

        let deadline = Date().addingTimeInterval(TimeInterval(timeout))
        while Date() < deadline {
            let remaining = max(0, deadline.timeIntervalSinceNow)
            let sleepSeconds = min(0.25, remaining)
            if sleepSeconds > 0 {
                try? await Task.sleep(nanoseconds: UInt64(sleepSeconds * 1_000_000_000))
            }
            messages = try await store.fetchGroupEnvelopes(
                inboxId: fetch.groupInboxId,
                recipientFingerprint: fetch.actorFingerprint,
                maxCount: fetch.maxCount
            )
                .compactMap(groupRatchetEnvelope)
            if !messages.isEmpty {
                return messages
            }
        }
        return messages
    }

    private func boundedLongPollTimeoutSeconds(for fetch: FetchRequest) -> Int? {
        boundedLongPollTimeoutSeconds(requested: fetch.longPollTimeoutSeconds)
    }

    private func boundedLongPollTimeoutSeconds(requested: Int?) -> Int? {
        guard let requested,
              requested > 0,
              configuration.wakeSupport?.mode == .longPoll else {
            return nil
        }
        let advertised = configuration.wakeSupport?.longPollTimeoutSeconds
            ?? configuration.wakeSupport?.minPollIntervalSeconds
            ?? 0
        guard advertised > 0 else {
            return nil
        }
        return min(max(1, requested), advertised)
    }

    private func carrierEnvelope(for envelope: GroupRatchetEnvelope) -> Envelope {
        Envelope(
            id: envelope.id,
            conversationId: "group:\(envelope.groupId.uuidString)",
            sessionId: nil,
            senderFingerprint: envelope.senderFingerprint,
            sentAt: envelope.sentAt,
            messageCounter: envelope.messageCounter,
            kemCiphertext: nil,
            prekey: nil,
            rootRatchet: nil,
            authenticatedContext: .group(
                protocolVersion: envelope.protocolVersion,
                cipherSuite: envelope.cipherSuite,
                groupId: envelope.groupId,
                epoch: envelope.epoch,
                senderFingerprint: envelope.senderFingerprint,
                transcriptHash: envelope.transcriptHash
            ),
            payload: envelope.payload,
            signature: envelope.signature
        )
    }

    private func groupRatchetEnvelope(from carrier: Envelope) -> GroupRatchetEnvelope? {
        guard let context = carrier.authenticatedContext?.group else {
            return nil
        }
        return GroupRatchetEnvelope(
            id: carrier.id,
            protocolVersion: context.protocolVersion,
            cipherSuite: context.cipherSuite,
            groupId: context.groupId,
            epoch: context.epoch,
            transcriptHash: context.transcriptHash,
            senderFingerprint: carrier.senderFingerprint,
            sentAt: carrier.sentAt,
            messageCounter: carrier.messageCounter,
            payload: carrier.payload,
            signature: carrier.signature
        )
    }

    private func requiresAuthentication(for type: RelayRequestType) -> Bool {
        switch type {
        case .health, .info, .registerFederationNode, .listFederationNodes:
            return false
        default:
            return true
        }
    }

    private func isCoordinatorDirectoryRequestType(_ type: RelayRequestType) -> Bool {
        switch type {
        case .health, .info, .registerFederationNode, .listFederationNodes:
            return true
        default:
            return false
        }
    }

    private func validateAuthentication(token: String?) -> RelayResponse? {
        let expected = configuration.accessPassword?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !expected.isEmpty else {
            return nil
        }
        guard expected.utf8.count <= 4_096,
              let token,
              token.utf8.count <= 4_096 else {
            return .error("Unauthorized: relay password is required.")
        }
        let provided = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard secureCompare(provided, expected) else {
            return .error("Unauthorized: relay password is required.")
        }
        return nil
    }

    private func validateCoordinatorRegistrationAuthentication(token: String?) -> RelayResponse? {
        let expected = configuration.coordinatorRegistrationToken?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if expected.isEmpty, configuration.federation.mode == .curated {
            return .error("Coordinator configuration error: curated registration requires a token.")
        }
        guard !expected.isEmpty else {
            return nil
        }
        guard expected.utf8.count <= 4_096,
              let token,
              token.utf8.count <= 4_096 else {
            return .error("Unauthorized: coordinator registration token is required.")
        }
        let provided = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard secureCompare(provided, expected) else {
            return .error("Unauthorized: coordinator registration token is required.")
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
    ) async throws -> RelayResponse? {
        guard registration.relayInfo.federation.mode == configuration.federation.mode else {
            return .error("Coordinator registration rejected: node federation mode differs from coordinator policy.")
        }
        if let coordinatorName = configuration.federation.name?.trimmingCharacters(in: .whitespacesAndNewlines),
           !coordinatorName.isEmpty,
           registration.relayInfo.federation.name != coordinatorName {
            return .error("Coordinator registration rejected: node federation name differs from coordinator policy.")
        }
        if configuration.federation.mode == .open,
           !configuration.allowPrivateFederationEndpoints,
           (!registration.endpoint.useTLS || !PublicRelayEndpointPolicy.permits(registration.endpoint)) {
            return .error("Coordinator registration rejected: open-federation endpoint must use TLS and be publicly routable.")
        }
        guard let info = try await fetchRelayInfo(endpoint: registration.endpoint) else {
            return .error("Coordinator registration rejected: endpoint is unreachable or did not return relay info.")
        }
        guard info.federation.mode == registration.relayInfo.federation.mode else {
            return .error("Coordinator registration rejected: federation mode mismatch.")
        }
        if let expectedName = registration.relayInfo.federation.name?.trimmingCharacters(in: .whitespacesAndNewlines),
           !expectedName.isEmpty,
           info.federation.name != expectedName {
            return .error("Coordinator registration rejected: federation name mismatch.")
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

    private func isValidIdentityFingerprint(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed == value
            && trimmed.count <= 64
            && Data(base64Encoded: trimmed)?.count == 32
    }

    private func federationGate(forwardingTo destination: RelayEndpoint) async throws -> RelayResponse? {
        switch configuration.federation.mode {
        case .solo:
            return .error("Relay is not configured for federation forwarding.")
        case .manual:
            guard configuration.federationAllowList.contains(destination) else {
                return .error("Manual federation: destination relay is not in the node list.")
            }
            guard let info = try await fetchRelayInfo(endpoint: destination) else {
                return .error("Federation check failed: destination relay did not report its configuration.")
            }
            guard info.federation.mode == .manual else {
                return .error("Federation mismatch: destination relay is not manual.")
            }
            guard info.kind == .standard else {
                return .error("Manual federation requires destination relay kind standard.")
            }
            if let name = configuration.federation.name,
               !name.isEmpty,
               info.federation.name != name {
                return .error("Federation mismatch: destination relay name differs.")
            }
            return nil
        case .open:
            if !configuration.federationAllowList.isEmpty {
                return .error("Open federation cannot use an allow list.")
            }
            guard configuration.allowPrivateFederationEndpoints
                    || (destination.useTLS && PublicRelayEndpointPolicy.permits(destination)) else {
                return .error("Open federation destination must use TLS and be publicly routable.")
            }
            guard let info = try await fetchRelayInfo(endpoint: destination) else {
                return .error("Federation check failed: destination relay did not report its configuration.")
            }
            guard info.federation.mode == .open else {
                return .error("Federation mismatch: destination relay is not open.")
            }
            if let name = configuration.federation.name,
               !name.isEmpty,
               info.federation.name != name {
                return .error("Federation mismatch: destination relay name differs.")
            }
            return nil
        case .curated:
            let isInStaticAllowList = configuration.federationAllowList.contains(destination)
            if configuration.curatedStrictPolicyEnabled {
                guard !configuration.federationAllowList.isEmpty else {
                    return .error("Curated strict policy requires a non-empty allow list.")
                }
                guard isInStaticAllowList else {
                    return .error("Curated strict policy: destination relay is not in the allow list.")
                }
                guard !coordinatorEndpoints().isEmpty else {
                    return .error("Curated strict policy requires coordinator endpoints.")
                }
                let quorum = max(1, configuration.curatedCoordinatorQuorum)
                let seenBy = try await destinationSeenByCoordinatorCount(
                    destination,
                    request: ListFederationNodesRequest(
                        mode: .curated,
                        federationName: configuration.federation.name,
                        onlyHealthy: true,
                        maxStalenessSeconds: configuration.coordinatorDirectoryMaxStalenessSeconds,
                        requireSignedSnapshot: configuration.curatedRequireSignedDirectory
                    )
                )
                guard seenBy >= quorum else {
                    return .error("Curated strict policy: destination relay quorum not met (\(seenBy)/\(quorum)).")
                }
            } else {
                let isAllowedByCoordinator = try await isDestinationAllowedByCoordinator(destination)
                guard isInStaticAllowList || isAllowedByCoordinator else {
                    return .error("Destination relay is not in the federation allow list.")
                }
            }
            guard let info = try await fetchRelayInfo(endpoint: destination) else {
                return .error("Federation check failed: destination relay did not report its configuration.")
            }
            guard info.federation.mode == .curated else {
                return .error("Federation mismatch: destination relay is not curated.")
            }
            if let name = configuration.federation.name,
               !name.isEmpty,
               info.federation.name != name {
                return .error("Federation mismatch: destination relay name differs.")
            }
            return nil
        }
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
        guard infoResponse.type == .info else {
            return []
        }
        let advertisedPublicKey = infoResponse.relayInfo?.federationDirectoryPublicKey
        let trustedPublicKey = coordinator.directorySigningPublicKey
        if let trustedPublicKey, let advertisedPublicKey, trustedPublicKey != advertisedPublicKey {
            throw RelayNetworkError.invalidResponse
        }
        let response = try await client.send(.listFederationNodes(request))
        guard response.type == .federationNodes else {
            return []
        }
        if request.requireSignedSnapshot == true, trustedPublicKey == nil {
            throw RelayNetworkError.invalidResponse
        }
        return try validatedCoordinatorNodes(
            response: response,
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
        response: RelayResponse,
        request: ListFederationNodesRequest,
        trustedPublicKey: Data?
    ) throws -> [FederationNodeRecord] {
        if let snapshot = response.federationSnapshot {
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
        return applyFreshnessPolicy(nodes: response.federationNodes ?? [], request: request)
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
        guard response.type == .info else {
            return nil
        }
        return response.relayInfo
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
