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
    private let coordinatorDirectorySigningPrivateKey: Data?
    private let coordinatorDirectoryPublicKey: Data?
    private var coordinatorDirectoryCache: [FederationNodeRecord] = []
    public var configuration: RelayConfiguration
    private let listenerQueue = DispatchQueue(label: "PICCPCore.RelayServer")

    public init(store: RelayStore, configuration: RelayConfiguration = RelayConfiguration()) {
        self.store = store
        self.configuration = configuration
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
                self?.onEvent?(.started(port: port))
            case .failed(let error):
                self?.onEvent?(.error("Listener failed: \(error.localizedDescription)"))
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
        coordinatorHeartbeatTask?.cancel()
        coordinatorHeartbeatTask = nil
        listener?.cancel()
        listener = nil
        onEvent?(.stopped)
    }

    private func handleTCP(connection: NWConnection) {
        Task {
            do {
                try await connection.awaitReady()
                let line = try await connection.receiveLine(maxLength: RelayClient.maxResponseBytes)
                let request = try PICCPCoder.decode(RelayRequest.self, from: line)
                let response = try await handle(
                    request: request,
                    sourceKey: endpointSourceKey(connection.endpoint)
                )
                let responseData = try PICCPCoder.encode(response)
                try await connection.sendLine(responseData)
                connection.cancel()
            } catch {
                onEvent?(.error("Connection error: \(error.localizedDescription)"))
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
                onEvent?(.error("HTTP connection error: \(error.localizedDescription)"))
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
                let requestParts = requestLine.split(separator: " ")
                guard requestParts.count >= 2 else {
                    throw RelayNetworkError.invalidResponse
                }
                method = String(requestParts[0]).uppercased()
                path = String(requestParts[1])
                if let queryStart = path.firstIndex(of: "?") {
                    path = String(path[..<queryStart])
                }
                var headers: [String: String] = [:]
                for line in lines.dropFirst() where !line.isEmpty {
                    guard let separator = line.firstIndex(of: ":") else { continue }
                    let key = line[..<separator].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespacesAndNewlines)
                    headers[key] = value
                }
                if let transferEncoding = headers["transfer-encoding"]?.lowercased(),
                   transferEncoding.contains("chunked") {
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
            let body = try PICCPCoder.encode(response)
            return httpResponse(statusCode: 200, reasonPhrase: "OK", body: body)
        case ("POST", "/relay"):
            guard !message.body.isEmpty else {
                let body = try PICCPCoder.encode(RelayResponse.error("Missing relay request body"))
                return httpResponse(statusCode: 400, reasonPhrase: "Bad Request", body: body)
            }
            let request: RelayRequest
            do {
                request = try PICCPCoder.decode(RelayRequest.self, from: message.body)
            } catch {
                let body = try PICCPCoder.encode(RelayResponse.error("Invalid relay JSON request"))
                return httpResponse(statusCode: 400, reasonPhrase: "Bad Request", body: body)
            }
            do {
                let response = try await handle(request: request, sourceKey: sourceKey)
                let body = try PICCPCoder.encode(response)
                return httpResponse(statusCode: 200, reasonPhrase: "OK", body: body)
            } catch {
                let body = try PICCPCoder.encode(RelayResponse.error("Relay processing failed: \(error.localizedDescription)"))
                return httpResponse(statusCode: 200, reasonPhrase: "OK", body: body)
            }
        case ("GET", "/relay"):
            let body = try PICCPCoder.encode(RelayResponse.error("Use POST /relay"))
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
        let header = [
            "HTTP/1.1 \(statusCode) \(reasonPhrase)",
            "Content-Type: \(contentType)",
            "Content-Length: \(body.count)",
            "Connection: close"
        ].joined(separator: "\r\n") + "\r\n\r\n"
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
        if requiresAuthentication(for: request.type),
           let authFailure = validateAuthentication(token: request.authToken) {
            return authFailure
        }
        if configuration.kind == .coordinator,
           !isCoordinatorDirectoryRequestType(request.type) {
            return .error("Coordinator relays are directory-only and do not carry user traffic.")
        }
        switch request.type {
        case .deliver:
            guard let deliver = request.deliver else {
                return .error("Missing deliver payload")
            }
            let routingToken = deliver.routingToken ?? deliver.inboxId
            guard InboxAddress.isValid(routingToken) else {
                return .error("Invalid routing token")
            }
            if let destination = deliver.destinationRelay,
               destination != localEndpoint {
                if let response = try await federationGate(forwardingTo: destination) {
                    return response
                }
                let forward = DeliverRequest(
                    inboxId: deliver.inboxId,
                    routingToken: routingToken,
                    envelope: deliver.envelope
                )
                let client = RelayClient(endpoint: destination, authToken: configuration.federationForwardingAuthToken)
                return try await client.send(.deliver(forward))
            }
            do {
                let count = try await store.deliver(deliver.envelope, to: routingToken)
                onEvent?(.delivered(inboxId: routingToken, storedCount: count))
                return .delivered(count: count)
            } catch RelayStoreError.inboxFull {
                return .error("Inbox full")
            } catch RelayStoreError.relayCapacityExceeded {
                return .error("Relay storage capacity reached")
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
            guard let offer = registration.contactOffer,
                  (try? offer.verified()) != nil,
                  offer.inboxId == registration.inboxId,
                  offer.inboxAccessPublicKey == registration.accessPublicKey else {
                return .error("Inbox registration is not bound to a valid identity offer")
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
                try await store.registerInbox(
                    inboxId: registration.inboxId,
                    accessPublicKey: registration.accessPublicKey
                )
                return .ok()
            } catch RelayStoreError.inboxAlreadyRegistered {
                return .error("Inbox is already registered to another access key")
            } catch RelayStoreError.relayCapacityExceeded {
                return .error("Relay storage capacity reached")
            } catch {
                return .error("Invalid inbox registration")
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
            let ttl = announce.ttlSeconds.map(String.init) ?? "default"
            print("[relay] announce ttl=\(ttl)")
            let announcement = await store.announce(announce.offer, ttlSeconds: announce.ttlSeconds)
            return .announcements([announcement])
        case .listAnnouncements:
            guard let list = request.listAnnouncements else {
                return .error("Missing list payload")
            }
            let limit = list.limit.map(String.init) ?? "all"
            print("[relay] list announcements limit=\(limit)")
            let announcements = await store.listAnnouncements(limit: list.limit)
            return .announcements(announcements)
        case .sendPairRequest:
            guard let pair = request.sendPairRequest else {
                return .error("Missing pair request payload")
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
            print("[relay] pair request received")
            _ = await store.sendPairRequest(targetFingerprint: pair.targetFingerprint, offer: pair.offer)
            return .ok()
        case .fetchPairRequests:
            guard let fetch = request.fetchPairRequests else {
                return .error("Missing fetch pair payload")
            }
            let fingerprint = fetch.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            if let proofFailure = await validateActorProof(
                fetch.actorProof,
                expectedFingerprint: fingerprint,
                expectedSigningKey: nil,
                signableDataBuilder: { proof in try fetch.signableData(for: proof) }
            ) {
                return proofFailure
            }
            let max = fetch.maxCount.map(String.init) ?? "all"
            print("[relay] fetch pair requests max=\(max)")
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
                return .error("Attachment store error: \(error.localizedDescription)")
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
                return .error("Attachment store error: \(error.localizedDescription)")
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
                    initialRatchetSecretDistribution: create.initialRatchetSecretDistribution
                )
                return .group(group)
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error)
            } catch {
                return .error("Group creation failed: \(error.localizedDescription)")
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
            guard !memberFingerprint.isEmpty,
                  let memberKey = registeredSigningKey(for: memberFingerprint, in: group) else {
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
                return .error("Group update failed: \(error.localizedDescription)")
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
                return .error("Delete group failed: \(error.localizedDescription)")
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
            do {
                let created = try await store.requestGroupJoin(join)
                return .groupJoinRequests([created])
            } catch let error as RelayStoreError {
                return relayStoreErrorResponse(error)
            } catch {
                return .error("Group join request failed: \(error.localizedDescription)")
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
                return .error("List join requests failed: \(error.localizedDescription)")
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
                return .error("Approve join failed: \(error.localizedDescription)")
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
                return .error("Reject join failed: \(error.localizedDescription)")
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
                return .error("Coordinator registration failed: \(error.localizedDescription)")
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
        }
    }

    private func relayStoreErrorResponse(_ error: RelayStoreError) -> RelayResponse {
        switch error {
        case .inboxFull:
            return .error("Inbox full")
        case .invalidInboxRegistration:
            return .error("Invalid inbox registration")
        case .inboxAlreadyRegistered:
            return .error("Inbox is already registered")
        case .relayCapacityExceeded:
            return .error("Relay storage capacity reached")
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
        let maxAgeSeconds: TimeInterval = 300
        guard abs(proof.signedAt.timeIntervalSinceNow) <= maxAgeSeconds else {
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
        let nonceAccepted = await store.consumeActorProofNonce(
            fingerprint: proof.fingerprint,
            nonce: proof.nonce,
            now: Date(),
            maxAgeSeconds: maxAgeSeconds
        )
        guard nonceAccepted else {
            return .error("Actor proof replay detected.")
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

    private func boundedLongPollTimeoutSeconds(for fetch: FetchRequest) -> Int? {
        guard let requested = fetch.longPollTimeoutSeconds,
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
        let provided = token?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard secureCompare(provided, expected) else {
            return .error("Unauthorized: relay password is required.")
        }
        return nil
    }

    private func validateCoordinatorRegistrationAuthentication(token: String?) -> RelayResponse? {
        let expected = configuration.coordinatorRegistrationToken?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !expected.isEmpty else {
            return nil
        }
        let provided = token?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
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
        return String(describing: endpoint)
    }

    private func validateFederationRegistrationReachability(
        _ registration: FederationNodeRegistrationRequest
    ) async throws -> RelayResponse? {
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
        let lhsData = Data(lhs.utf8)
        let rhsData = Data(rhs.utf8)
        guard lhsData.count == rhsData.count else {
            return false
        }
        var difference: UInt8 = 0
        for index in lhsData.indices {
            difference |= lhsData[index] ^ rhsData[index]
        }
        return difference == 0
    }

    private func federationGate(forwardingTo destination: RelayEndpoint) async throws -> RelayResponse? {
        switch configuration.federation.mode {
        case .solo:
            return .error("Relay is not configured for federation forwarding.")
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
                    self.onEvent?(.error("Coordinator heartbeat failed: \(error.localizedDescription)"))
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
        coordinatorDirectoryCache = sorted
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
        for node in coordinatorDirectoryCache {
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
}
