import Foundation
@preconcurrency import NIOCore
@preconcurrency import NIOFoundationCompat
@preconcurrency import NIOPosix
@preconcurrency import NIOConcurrencyHelpers
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

private enum FederationDirectoryValidationError: Error {
    case invalidSnapshot
}

private enum RelayForwardHTTPError: Error {
    case invalidURL
    case badStatus(Int)
    case invalidResponseBinding
}

private enum RelayForwardTransportError: Error {
    case rawTLSUnavailable
}

private struct RelayForwardTimeoutError: LocalizedError {
    var errorDescription: String? { "Relay forwarding request timed out." }
}

final class RelayHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let store: RelayStore
    private let maxMessageBytes: Int
    private let maxLineBytes: Int
    private let localEndpoint: RelayEndpoint?
    private let relayConfiguration: RelayConfiguration
    private let forwardingRequestTimeoutSeconds: Int
    private let coordinatorDirectorySigningPrivateKey: Data?
    private let coordinatorDirectoryPublicKey: Data?
    private let coordinatorHeartbeatLock = NIOLock()
    private var lastCoordinatorHeartbeatAt: Date?

    init(
        store: RelayStore,
        maxMessageBytes: Int?,
        maxLineBytes: Int?,
        localEndpoint: RelayEndpoint?,
        relayConfiguration: RelayConfiguration,
        forwardingRequestTimeoutSeconds: Int
    ) {
        self.store = store
        self.maxMessageBytes = min(max(1_024, maxMessageBytes ?? (512 * 1024)), 8 * 1024 * 1024)
        self.maxLineBytes = min(
            max(maxLineBytes ?? (640 * 1024), self.maxMessageBytes + (128 * 1024)),
            10 * 1024 * 1024
        )
        self.localEndpoint = localEndpoint
        self.relayConfiguration = relayConfiguration
        self.forwardingRequestTimeoutSeconds = max(1, forwardingRequestTimeoutSeconds)
        if relayConfiguration.kind == .coordinator {
            let keyData = FederationDirectorySignature.privateKeyData(
                from: relayConfiguration.coordinatorDirectorySigningPrivateKey
            )
            self.coordinatorDirectorySigningPrivateKey = keyData
            self.coordinatorDirectoryPublicKey = FederationDirectorySignature.publicKeyData(from: keyData)
        } else {
            self.coordinatorDirectorySigningPrivateKey = nil
            self.coordinatorDirectoryPublicKey = nil
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        guard let payload = buffer.readData(length: buffer.readableBytes) else {
            context.close(promise: nil)
            return
        }
        if payload.count > maxMessageBytes {
            context.close(promise: nil)
            return
        }
        do {
            let request = try RelayCodec.decoder().decode(RelayRequest.self, from: payload)
            let responseContext = NIOContextBox(context)
            handle(request, context: context).whenComplete { result in
                switch result {
                case .success(let response):
                    self.respond(response, context: responseContext.context)
                case .failure:
                    self.respond(
                        .error(
                            "Handler error",
                            code: .internalFailure,
                            retryable: true,
                            respondingTo: request
                        ),
                        context: responseContext.context
                    )
                }
            }
        } catch {
            context.close(promise: nil)
        }
    }

    private func handle(_ request: RelayRequest, context: ChannelHandlerContext) -> EventLoopFuture<RelayResponse> {
        scheduleCoordinatorHeartbeatIfNeeded(on: context.eventLoop)
        func success(_ body: RelaySuccessBody) -> EventLoopFuture<RelayResponse> {
            context.eventLoop.makeSucceededFuture(.success(body, respondingTo: request))
        }
        func failure(
            _ message: String,
            code: RelayErrorCode = .invalidRequest,
            retryable: Bool = false
        ) -> EventLoopFuture<RelayResponse> {
            context.eventLoop.makeSucceededFuture(
                .error(message, code: code, retryable: retryable, respondingTo: request)
            )
        }
        let requestSourceKey = sourceKey(for: context.channel.remoteAddress)
        if !isLoopbackRequestSource(requestSourceKey) {
            guard store.allowRelayRequest(sourceKey: requestSourceKey) else {
                return failure("Rate limit exceeded", code: .rateLimited, retryable: true)
            }
        }
        if requiresAuthentication(for: request.binding),
           let authFailure = validateAuthentication(token: request.authToken) {
            return failure(authFailure, code: .authenticationRequired)
        }
        if relayConfiguration.kind == .coordinator,
           !isCoordinatorDirectoryRequest(request.binding) {
            return failure("Coordinator relays are directory-only and do not carry user traffic.", code: .unavailable)
        }
        switch request.body {
        case .createOpaqueRoute(let submission):
            guard relayConfiguration.isOpaqueRouteRuntimeEnabled else {
                return failure("Opaque route runtime is disabled", code: .unavailable)
            }
            let confidentialTransport = relayConfiguration.tlsEnabled == true
                || isLoopbackRequestSource(requestSourceKey)
            guard confidentialTransport else {
                return failure("Opaque route runtime requires confidential transport")
            }
            guard submission.isStructurallyValid else {
                return failure("Invalid opaque route request")
            }
            do {
                return success(.opaqueRoute(try store.createOpaqueRouteV2(
                    submission,
                    confidentialTransport: confidentialTransport
                )))
            } catch {
                return context.eventLoop.makeSucceededFuture(opaqueRouteErrorResponse(error, respondingTo: request))
            }
        case .renewOpaqueRoute(let submission):
            guard relayConfiguration.isOpaqueRouteRuntimeEnabled else {
                return failure("Opaque route runtime is disabled", code: .unavailable)
            }
            let confidentialTransport = relayConfiguration.tlsEnabled == true
                || isLoopbackRequestSource(requestSourceKey)
            guard confidentialTransport else {
                return failure("Opaque route runtime requires confidential transport")
            }
            guard submission.isStructurallyValid else {
                return failure("Invalid opaque route request")
            }
            do {
                return success(.opaqueRoute(try store.renewOpaqueRouteV2(
                    submission,
                    confidentialTransport: confidentialTransport
                )))
            } catch {
                return context.eventLoop.makeSucceededFuture(opaqueRouteErrorResponse(error, respondingTo: request))
            }
        case .teardownOpaqueRoute(let submission):
            guard relayConfiguration.isOpaqueRouteRuntimeEnabled else {
                return failure("Opaque route runtime is disabled", code: .unavailable)
            }
            let confidentialTransport = relayConfiguration.tlsEnabled == true
                || isLoopbackRequestSource(requestSourceKey)
            guard confidentialTransport else {
                return failure("Opaque route runtime requires confidential transport")
            }
            guard submission.isStructurallyValid else {
                return failure("Invalid opaque route request")
            }
            do {
                return success(.opaqueRoute(try store.teardownOpaqueRouteV2(
                    submission,
                    confidentialTransport: confidentialTransport
                )))
            } catch {
                return context.eventLoop.makeSucceededFuture(opaqueRouteErrorResponse(error, respondingTo: request))
            }
        case .appendOpaqueRoute(let submission):
            guard relayConfiguration.isOpaqueRouteRuntimeEnabled else {
                return failure("Opaque route runtime is disabled", code: .unavailable)
            }
            let confidentialTransport = relayConfiguration.tlsEnabled == true
                || isLoopbackRequestSource(requestSourceKey)
            guard confidentialTransport else {
                return failure("Opaque route runtime requires confidential transport")
            }
            guard submission.isStructurallyValid else {
                return failure("Invalid opaque route request")
            }
            do {
                return success(.opaqueRouteAppend(try store.appendOpaqueRouteV2(
                    submission,
                    confidentialTransport: confidentialTransport
                )))
            } catch {
                return context.eventLoop.makeSucceededFuture(opaqueRouteErrorResponse(error, respondingTo: request))
            }
        case .syncOpaqueRoute(let submission):
            guard relayConfiguration.isOpaqueRouteRuntimeEnabled else {
                return failure("Opaque route runtime is disabled", code: .unavailable)
            }
            let confidentialTransport = relayConfiguration.tlsEnabled == true
                || isLoopbackRequestSource(requestSourceKey)
            guard confidentialTransport else {
                return failure("Opaque route runtime requires confidential transport")
            }
            guard submission.isStructurallyValid else {
                return failure("Invalid opaque route request")
            }
            do {
                return success(.opaqueRouteSync(try store.syncOpaqueRouteV2(
                    submission,
                    confidentialTransport: confidentialTransport
                )))
            } catch {
                return context.eventLoop.makeSucceededFuture(opaqueRouteErrorResponse(error, respondingTo: request))
            }
        case .commitOpaqueRoute(let submission):
            guard relayConfiguration.isOpaqueRouteRuntimeEnabled else {
                return failure("Opaque route runtime is disabled", code: .unavailable)
            }
            let confidentialTransport = relayConfiguration.tlsEnabled == true
                || isLoopbackRequestSource(requestSourceKey)
            guard confidentialTransport else {
                return failure("Opaque route runtime requires confidential transport")
            }
            guard submission.isStructurallyValid else {
                return failure("Invalid opaque route request")
            }
            do {
                return success(.opaqueRouteCommit(try store.commitOpaqueRouteV2(
                    submission,
                    confidentialTransport: confidentialTransport
                )))
            } catch {
                return context.eventLoop.makeSucceededFuture(opaqueRouteErrorResponse(error, respondingTo: request))
            }
        case .registerRendezvous(let registration):
            guard relayConfiguration.isRendezvousTransportEnabled else {
                return failure("Rendezvous transport is disabled", code: .unavailable)
            }
            guard relayConfiguration.tlsEnabled == true
                    || isLoopbackRequestSource(requestSourceKey) else {
                return failure("Rendezvous transport requires confidential transport")
            }
            guard registration.isStructurallyValid() else {
                return failure("Invalid rendezvous transport request")
            }
            do {
                try store.registerRendezvousTransportV2(registration)
                return success(.empty)
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error, respondingTo: request))
            }
        case .appendRendezvous(let append):
            guard relayConfiguration.isRendezvousTransportEnabled else {
                return failure("Rendezvous transport is disabled", code: .unavailable)
            }
            guard relayConfiguration.tlsEnabled == true
                    || isLoopbackRequestSource(requestSourceKey) else {
                return failure("Rendezvous transport requires confidential transport")
            }
            guard append.isStructurallyValid else {
                return failure("Invalid rendezvous transport request")
            }
            do {
                _ = try store.appendRendezvousTransportV2(append)
                return success(.empty)
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error, respondingTo: request))
            }
        case .syncRendezvous(let sync):
            guard relayConfiguration.isRendezvousTransportEnabled else {
                return failure("Rendezvous transport is disabled", code: .unavailable)
            }
            guard relayConfiguration.tlsEnabled == true
                    || isLoopbackRequestSource(requestSourceKey) else {
                return failure("Rendezvous transport requires confidential transport")
            }
            guard sync.isStructurallyValid else {
                return failure("Invalid rendezvous transport request")
            }
            do {
                return success(.rendezvousSync(try store.syncRendezvousTransportV2(sync)))
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error, respondingTo: request))
            }
        case .deleteRendezvous(let deletion):
            guard relayConfiguration.isRendezvousTransportEnabled else {
                return failure("Rendezvous transport is disabled", code: .unavailable)
            }
            guard relayConfiguration.tlsEnabled == true
                    || isLoopbackRequestSource(requestSourceKey) else {
                return failure("Rendezvous transport requires confidential transport")
            }
            guard deletion.isStructurallyValid else {
                return failure("Invalid rendezvous transport request")
            }
            do {
                try store.deleteRendezvousTransportV2(deletion)
                return success(.empty)
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error, respondingTo: request))
            }
        case .empty:
            if request.method == .health {
                return success(.empty)
            }
            guard request.method == .info else {
                return failure("Invalid empty relay request")
            }
            var info = relayConfiguration.makeInfo(now: Date())
            if relayConfiguration.kind == .coordinator {
                info = RelayInfo(
                    kind: info.kind,
                    federation: info.federation,
                    tlsEnabled: info.tlsEnabled,
                    transport: info.transport,
                    temporalBucketSeconds: info.temporalBucketSeconds,
                    temporalBucketScheduleSeconds: info.temporalBucketScheduleSeconds,
                    attachmentDefaultTTLSeconds: info.attachmentDefaultTTLSeconds,
                    attachmentMaxTTLSeconds: info.attachmentMaxTTLSeconds,
                    attachmentsEnabled: info.attachmentsEnabled,
                    attachmentStorageBackend: info.attachmentStorageBackend,
                    hiddenRetrieval: info.hiddenRetrieval,
                    onionTransport: info.onionTransport,
                    mixnetTransport: info.mixnetTransport,
                    relayName: info.relayName,
                    operatorNote: info.operatorNote,
                    softwareVersion: info.softwareVersion,
                    protocolCapabilities: info.protocolCapabilities,
                    requiresPassword: info.requiresPassword,
                    federationCoordinatorEndpoints: info.federationCoordinatorEndpoints,
                    coordinatorReportedRelayCount: store.listFederationNodes(
                        ListFederationNodesRequest(
                            mode: relayConfiguration.federation.mode,
                            federationName: relayConfiguration.federation.name,
                            onlyHealthy: true,
                            maxStalenessSeconds: relayConfiguration.coordinatorDirectoryMaxStalenessSeconds
                        )
                    ).count,
                    federationDirectoryPublicKey: coordinatorDirectoryPublicKey,
                    advertisedAt: info.advertisedAt
                )
            } else {
                let hints = knownOpenFederationPeers()
                if !hints.isEmpty {
                    info = RelayInfo(
                        kind: info.kind,
                        federation: info.federation,
                        tlsEnabled: info.tlsEnabled,
                        transport: info.transport,
                        temporalBucketSeconds: info.temporalBucketSeconds,
                        temporalBucketScheduleSeconds: info.temporalBucketScheduleSeconds,
                        attachmentDefaultTTLSeconds: info.attachmentDefaultTTLSeconds,
                        attachmentMaxTTLSeconds: info.attachmentMaxTTLSeconds,
                        attachmentsEnabled: info.attachmentsEnabled,
                        attachmentStorageBackend: info.attachmentStorageBackend,
                        hiddenRetrieval: info.hiddenRetrieval,
                        onionTransport: info.onionTransport,
                        mixnetTransport: info.mixnetTransport,
                        relayName: info.relayName,
                        operatorNote: info.operatorNote,
                        softwareVersion: info.softwareVersion,
                        protocolCapabilities: info.protocolCapabilities,
                        requiresPassword: info.requiresPassword,
                        federationCoordinatorEndpoints: info.federationCoordinatorEndpoints,
                        coordinatorReportedRelayCount: info.coordinatorReportedRelayCount,
                        curatedStrictPolicyEnabled: info.curatedStrictPolicyEnabled,
                        curatedCoordinatorQuorum: info.curatedCoordinatorQuorum,
                        curatedRequireSignedDirectory: info.curatedRequireSignedDirectory,
                        federationDirectoryPublicKey: info.federationDirectoryPublicKey,
                        knownOpenPeers: hints,
                        openFederationDiscovery: info.openFederationDiscovery,
                        advertisedAt: info.advertisedAt
                    )
                }
            }
            return success(.relayInfo(info))
        case .uploadAttachment(let upload):
            guard relayConfiguration.attachmentsEnabled != false else {
                return failure("Attachments are disabled on this relay", code: .unavailable)
            }
            let boundedTTL = boundedAttachmentTTL(requested: upload.ttlSeconds)
            do {
                let chunk = try store.storeAttachment(
                    attachmentId: upload.attachmentId,
                    chunkIndex: upload.chunkIndex,
                    payload: upload.payload,
                    ttlSeconds: boundedTTL
                )
                return success(.attachment(chunk))
            } catch RelayStoreError.invalidChunkIndex {
                return failure("Invalid chunk index")
            } catch RelayStoreError.invalidAttachmentPayload {
                return failure("Invalid attachment payload")
            } catch RelayStoreError.attachmentBlobUnavailable {
                return failure("Attachment blob backend unavailable", code: .unavailable, retryable: true)
            } catch {
                return failure("Attachment store error", code: .unavailable, retryable: true)
            }
        case .fetchAttachment(let fetch):
            guard relayConfiguration.attachmentsEnabled != false else {
                return failure("Attachments are disabled on this relay", code: .unavailable)
            }
            do {
                if let chunk = try store.fetchAttachment(
                    attachmentId: fetch.attachmentId,
                    chunkIndex: fetch.chunkIndex
                ) {
                    return success(.attachment(chunk))
                }
                return failure("Attachment not found", code: .notFound)
            } catch RelayStoreError.invalidChunkIndex {
                return failure("Invalid chunk index")
            } catch RelayStoreError.attachmentBlobUnavailable {
                return failure("Attachment blob backend unavailable", code: .unavailable, retryable: true)
            } catch {
                return failure("Attachment store error", code: .unavailable, retryable: true)
            }
        case .registerFederationNode(let registration):
            guard relayConfiguration.kind == .coordinator else {
                return failure("This relay is not a coordinator node.", code: .unavailable)
            }
            if let authFailure = validateCoordinatorRegistrationAuthentication(token: request.authToken) {
                return failure(authFailure, code: .authenticationRequired)
            }
            let sourceKey = sourceKey(for: context.channel.remoteAddress)
            let allowed = store.allowFederationRegistration(sourceKey: sourceKey, endpoint: registration.endpoint)
            guard allowed else {
                return failure("Coordinator registration throttled. Retry later.", code: .rateLimited, retryable: true)
            }
            let eventLoop = context.eventLoop
            return validateFederationRegistrationReachability(registration, on: eventLoop).flatMap { failure in
                if let failure {
                    return eventLoop.makeSucceededFuture(
                        .error(failure, respondingTo: request)
                    )
                }
                do {
                    let node = try self.store.registerFederationNode(registration)
                    return eventLoop.makeSucceededFuture(
                        .success(.federationNodes(.init(nodes: [node])), respondingTo: request)
                    )
                } catch {
                    return eventLoop.makeSucceededFuture(
                        .error("Coordinator registration failed", code: .unavailable, retryable: true, respondingTo: request)
                    )
                }
            }
        case .listFederationNodes(let listRequest):
            if relayConfiguration.kind == .coordinator {
                let sourceKey = sourceKey(for: context.channel.remoteAddress)
                let allowed = store.allowFederationDirectoryList(sourceKey: sourceKey)
                guard allowed else {
                    return failure("Coordinator directory listing throttled. Retry later.", code: .rateLimited, retryable: true)
                }
                let nodes = store.listFederationNodes(listRequest)
                let snapshot = makeCoordinatorDirectorySnapshot(nodes: nodes, request: listRequest)
                if listRequest.requireSignedSnapshot == true, snapshot == nil {
                    return failure("Coordinator snapshot signing is not available.", code: .unavailable)
                }
                return success(.federationNodes(.init(nodes: nodes, snapshot: snapshot)))
            }
            return fetchCoordinatorNodeDirectory(request: listRequest, on: context.eventLoop)
                .map { .success(.federationNodes(.init(nodes: $0)), respondingTo: request) }
        case .publishDHTRecord(let publish):
            guard let dhtConfiguration = openFederationDHTConfiguration() else {
                return failure("Open-federation DHT is available only on open non-coordinator relays.", code: .unavailable)
            }
            let expectedNamespace = OpenFederationDHTRecord.namespace(federationName: dhtConfiguration.federationName)
            guard publish.namespace == expectedNamespace else {
                return failure("Open-federation DHT namespace mismatch.")
            }
            let result = store.ingestOpenFederationDHTRecords(
                [publish.record],
                configuration: dhtConfiguration
            )
            guard !result.accepted.isEmpty else {
                let reason = result.rejected.first.map { "\($0.reason)" } ?? "record rejected"
                return failure("Open-federation DHT record rejected: \(reason)")
            }
            return success(.empty)
        case .listDHTRecords(let list):
            guard let dhtConfiguration = openFederationDHTConfiguration() else {
                return failure("Open-federation DHT is available only on open non-coordinator relays.", code: .unavailable)
            }
            let expectedNamespace = OpenFederationDHTRecord.namespace(federationName: dhtConfiguration.federationName)
            guard list.namespace == expectedNamespace else {
                return failure("Open-federation DHT namespace mismatch.")
            }
            let records = store.listOpenFederationDHTRecords(
                configuration: dhtConfiguration,
                limit: list.limit
            )
            return success(.dhtRecords(records))
        }
    }

    private func relayStoreErrorResponse(_ error: Error, respondingTo request: RelayRequest) -> RelayResponse {
        switch error {
        case RelayStoreError.relayCapacityExceeded:
            return .error("Relay storage capacity reached", code: .capacity, respondingTo: request)
        case RelayStoreError.invalidRendezvousRoute:
            return .error("Invalid rendezvous transport request", respondingTo: request)
        case RelayStoreError.rendezvousRouteUnavailable:
            return .error("Rendezvous route is unavailable", code: .notFound, respondingTo: request)
        case RelayStoreError.rendezvousRegistrationConflict:
            return .error("Rendezvous route registration conflicts with stored state", code: .conflict, respondingTo: request)
        case RelayStoreError.rendezvousCapacityReached:
            return .error("Rendezvous transport capacity reached", code: .capacity, respondingTo: request)
        case RelayStoreError.rendezvousFrameConflict:
            return .error("Rendezvous frame conflicts with stored state", code: .conflict, respondingTo: request)
        case RelayStoreError.rendezvousSequenceGap:
            return .error("Rendezvous lane sequence is not contiguous", code: .conflict, respondingTo: request)
        case RelayStoreError.rendezvousQuotaReached:
            return .error("Rendezvous lane quota reached", code: .capacity, respondingTo: request)
        case RelayStoreError.invalidChunkIndex:
            return .error("Invalid chunk index", respondingTo: request)
        case RelayStoreError.invalidAttachmentPayload:
            return .error("Invalid attachment payload", respondingTo: request)
        case RelayStoreError.attachmentBlobUnavailable:
            return .error("Attachment blob backend unavailable", code: .unavailable, retryable: true, respondingTo: request)
        default:
            return .error("Store error", code: .internalFailure, retryable: true, respondingTo: request)
        }
    }

    private func opaqueRouteErrorResponse(_ error: Error, respondingTo request: RelayRequest) -> RelayResponse {
        switch error {
        case OpaqueRouteRelayStoreV2Error.routeNotFound:
            return .error("Opaque route not found", code: .notFound, respondingTo: request)
        case OpaqueRouteRelayStoreV2Error.invalidCursor:
            return .error("Invalid opaque route cursor", respondingTo: request)
        case OpaqueRouteRelayStoreV2Error.cursorExpired:
            return .error("Opaque route cursor expired", code: .conflict, respondingTo: request)
        case OpaqueRouteRelayStoreV2Error.cursorAheadOfRoute:
            return .error("Opaque route cursor is ahead of the route", code: .conflict, respondingTo: request)
        case OpaqueRouteRelayStoreV2Error.packetIdentifierConflict:
            return .error("Opaque route packet identifier conflict", code: .conflict, respondingTo: request)
        case OpaqueRouteRelayStoreV2Error.requestIdentifierConflict:
            return .error("Opaque route request identifier conflict", code: .conflict, respondingTo: request)
        case OpaqueRouteRelayStoreV2Error.routeQuotaExceeded:
            return .error("Opaque route quota exceeded", code: .capacity, respondingTo: request)
        case OpaqueRouteRelayStoreV2Error.packetIdentifierLedgerExhausted,
             OpaqueRouteRelayStoreV2Error.requestReceiptLedgerExhausted,
             OpaqueRouteRelayStoreV2Error.sequenceExhausted,
             OpaqueRouteRelayStoreV2Error.routeCapacityExceeded:
            return .error("Opaque route capacity reached", code: .capacity, respondingTo: request)
        case OpaqueRouteV2Error.confidentialTransportRequired:
            return .error("Opaque route runtime requires confidential transport", respondingTo: request)
        case OpaqueRouteV2Error.invalidAuthorization,
             OpaqueRouteV2Error.authorizationExpired,
             OpaqueRouteV2Error.authorizationReplay:
            return .error("Opaque route authorization rejected", code: .authenticationRequired, respondingTo: request)
        case OpaqueRouteV2Error.routeExpired:
            return .error("Opaque route expired", code: .notFound, respondingTo: request)
        case OpaqueRouteV2Error.routeTornDown:
            return .error("Opaque route is torn down", code: .notFound, respondingTo: request)
        case OpaqueRouteV2Error.idempotencyConflict,
             OpaqueRouteV2Error.routeAlreadyExists,
             OpaqueRouteV2Error.transitionFork:
            return .error("Opaque route state conflict", code: .conflict, respondingTo: request)
        case OpaqueRouteV2Error.staleTransition,
             OpaqueRouteV2Error.transitionOutOfOrder:
            return .error("Opaque route transition order rejected", code: .conflict, respondingTo: request)
        default:
            return .error("Invalid opaque route request", respondingTo: request)
        }
    }

    private func respond(_ response: RelayResponse, context: ChannelHandlerContext) {
        do {
            let data = try RelayCodec.encoder().encode(response)
            var buffer = context.channel.allocator.buffer(capacity: data.count + 1)
            LineEncoder.wrap(data, into: &buffer)
            context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
        } catch {
            context.close(promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }

    private func fetchRelayInfo(from endpoint: RelayEndpoint, on eventLoop: EventLoop) -> EventLoopFuture<RelayInfo?> {
        sendRequest(.info(), to: endpoint, on: eventLoop).map { response in
            guard case .relayInfo(let info)? = response.successBody else {
                return nil
            }
            return info
        }
    }

    private func openFederationDHTConfiguration() -> OpenFederationDHTDiscoveryConfiguration? {
        guard relayConfiguration.federation.mode == .open,
              relayConfiguration.kind != .coordinator,
              relayConfiguration.openFederationDHTEnabled else {
            return nil
        }
        return OpenFederationDHTDiscoveryConfiguration(
            isEnabled: true,
            federationName: relayConfiguration.federation.name,
            requirePublicEndpoint: !relayConfiguration.allowPrivateFederationEndpoints,
            maxRecords: relayConfiguration.openFederationDHTMaxRecords,
            maxRecordsPerHost: relayConfiguration.openFederationDHTMaxRecordsPerHost,
            maxQueryRecords: relayConfiguration.openFederationDHTMaxQueryRecords
        )
    }

    private func validateFederationRegistrationReachability(
        _ registration: FederationNodeRegistrationRequest,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<String?> {
        guard registration.relayInfo.federation.mode == relayConfiguration.federation.mode else {
            return eventLoop.makeSucceededFuture(
                "Coordinator registration rejected: node federation mode differs from coordinator policy."
            )
        }
        if let coordinatorName = relayConfiguration.federation.name?.trimmingCharacters(in: .whitespacesAndNewlines),
           !coordinatorName.isEmpty,
           registration.relayInfo.federation.name != coordinatorName {
            return eventLoop.makeSucceededFuture(
                "Coordinator registration rejected: node federation name differs from coordinator policy."
            )
        }
        if relayConfiguration.federation.mode == .open,
           !relayConfiguration.allowPrivateFederationEndpoints,
           (!registration.endpoint.useTLS || !PublicRelayEndpointPolicy.permits(registration.endpoint)) {
            return eventLoop.makeSucceededFuture(
                "Coordinator registration rejected: open-federation endpoint must use TLS and be publicly routable."
            )
        }
        return fetchRelayInfo(from: registration.endpoint, on: eventLoop).map { info -> String? in
            guard let info else {
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
        }.flatMapError { _ in
            eventLoop.makeSucceededFuture(
                String?.some("Coordinator registration rejected: endpoint reachability check failed.")
            )
        }
    }

    private func coordinatorEndpoints() -> [RelayEndpoint] {
        (relayConfiguration.federationCoordinatorEndpoints ?? []).filter { endpoint in
            !endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
    }

    private func coordinatorHeartbeatInterval() -> TimeInterval {
        let configured = relayConfiguration.coordinatorHeartbeatSeconds ?? 45
        return TimeInterval(max(15, configured))
    }

    private func effectiveAdvertisedEndpoint() -> RelayEndpoint? {
        if let explicit = relayConfiguration.advertisedEndpoint {
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

    private func scheduleCoordinatorHeartbeatIfNeeded(on eventLoop: EventLoop) {
        guard relayConfiguration.kind != .coordinator else { return }
        let coordinators = coordinatorEndpoints()
        guard !coordinators.isEmpty else { return }
        let now = Date()
        let shouldSend = coordinatorHeartbeatLock.withLock { () -> Bool in
            if let last = lastCoordinatorHeartbeatAt,
               now.timeIntervalSince(last) < coordinatorHeartbeatInterval() {
                return false
            }
            lastCoordinatorHeartbeatAt = now
            return true
        }
        guard shouldSend else { return }
        performCoordinatorHeartbeat(on: eventLoop).whenFailure { _ in
            print("[relay] coordinator heartbeat failed")
        }
    }

    private func performCoordinatorHeartbeat(on eventLoop: EventLoop) -> EventLoopFuture<Void> {
        guard let advertisedEndpoint = effectiveAdvertisedEndpoint() else {
            return eventLoop.makeSucceededFuture(())
        }
        let coordinators = coordinatorEndpoints()
        guard !coordinators.isEmpty else {
            return eventLoop.makeSucceededFuture(())
        }
        let interval = coordinatorHeartbeatInterval()
        let ttl = max(Int(interval * 3), 60)
        let info = relayConfiguration.makeInfo(now: Date())
        let request = RelayRequest.registerFederationNode(
            FederationNodeRegistrationRequest(
                endpoint: advertisedEndpoint,
                relayInfo: info,
                ttlSeconds: ttl
            )
        ).withAuthToken(relayConfiguration.coordinatorRegistrationToken)
        let futures = coordinators.map { coordinator in
            sendRequest(request, to: coordinator, on: eventLoop).map { _ in () }
        }
        return EventLoopFuture.andAllSucceed(futures, on: eventLoop)
    }

    private func fetchCoordinatorNodeDirectory(
        request: ListFederationNodesRequest,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<[FederationNodeRecord]> {
        let coordinators = coordinatorEndpoints()
        guard !coordinators.isEmpty else {
            return eventLoop.makeSucceededFuture([])
        }
        let maxStaleness = max(30, request.maxStalenessSeconds ?? relayConfiguration.coordinatorDirectoryMaxStalenessSeconds ?? 300)
        let effectiveRequest = ListFederationNodesRequest(
            mode: request.mode ?? relayConfiguration.federation.mode,
            federationName: request.federationName ?? relayConfiguration.federation.name,
            onlyHealthy: request.onlyHealthy ?? true,
            maxStalenessSeconds: maxStaleness,
            requireSignedSnapshot: request.requireSignedSnapshot ?? relayConfiguration.curatedRequireSignedDirectory
        )
        let futures: [EventLoopFuture<[FederationNodeRecord]>] = coordinators.map { coordinator in
            fetchValidatedCoordinatorNodes(from: coordinator, request: effectiveRequest, on: eventLoop)
            .flatMapError { _ in
                eventLoop.makeSucceededFuture([])
            }
        }
        return EventLoopFuture.whenAllSucceed(futures, on: eventLoop).map { all in
            var merged: [String: FederationNodeRecord] = [:]
            for nodes in all {
                for node in nodes {
                    let key = "\(node.endpoint.host.lowercased()):\(node.endpoint.port):\(node.endpoint.useTLS ? 1 : 0):\(node.endpoint.transport.rawValue)"
                    if let existing = merged[key] {
                        if node.lastHeartbeatAt > existing.lastHeartbeatAt {
                            merged[key] = node
                        }
                    } else {
                        merged[key] = node
                    }
                }
            }
            let sorted = merged.values.sorted { lhs, rhs in
                if lhs.lastHeartbeatAt != rhs.lastHeartbeatAt {
                    return lhs.lastHeartbeatAt > rhs.lastHeartbeatAt
                }
                return lhs.endpoint.host < rhs.endpoint.host
            }
            self.store.setCoordinatorDirectoryCache(sorted)
            return sorted
        }
    }

    private func fetchValidatedCoordinatorNodes(
        from coordinator: RelayEndpoint,
        request: ListFederationNodesRequest,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<[FederationNodeRecord]> {
        sendRequest(.info(), to: coordinator, on: eventLoop).flatMap { infoResponse -> EventLoopFuture<[FederationNodeRecord]> in
            guard case .relayInfo(let relayInfo)? = infoResponse.successBody else {
                return eventLoop.makeSucceededFuture([])
            }
            let advertisedPublicKey = relayInfo.federationDirectoryPublicKey
            let pinnedPublicKey = self.store.pinnedCoordinatorPublicKey(for: coordinator)
            if let advertisedPublicKey {
                if let pinnedPublicKey, pinnedPublicKey != advertisedPublicKey {
                    return eventLoop.makeFailedFuture(FederationDirectoryValidationError.invalidSnapshot)
                }
                if pinnedPublicKey == nil {
                    do {
                        try self.store.pinCoordinatorPublicKey(advertisedPublicKey, for: coordinator)
                    } catch {
                        return eventLoop.makeFailedFuture(error)
                    }
                }
            }
            let trustedPublicKey = pinnedPublicKey ?? advertisedPublicKey
            return self.sendRequest(.listFederationNodes(request), to: coordinator, on: eventLoop).flatMapThrowing { response in
                guard case .federationNodes(let directory)? = response.successBody else {
                    return []
                }
                if request.requireSignedSnapshot == true, trustedPublicKey == nil {
                    throw FederationDirectoryValidationError.invalidSnapshot
                }
                return try self.validatedCoordinatorNodes(
                    directory: directory,
                    request: request,
                    trustedPublicKey: trustedPublicKey
                )
            }
        }
    }

    private func makeCoordinatorDirectorySnapshot(
        nodes: [FederationNodeRecord],
        request: ListFederationNodesRequest
    ) -> FederationDirectorySnapshot? {
        guard relayConfiguration.kind == .coordinator,
              let privateKey = coordinatorDirectorySigningPrivateKey else {
            return nil
        }
        let issuedAt = Date()
        let maxStaleness = max(30, request.maxStalenessSeconds ?? relayConfiguration.coordinatorDirectoryMaxStalenessSeconds ?? 300)
        let validFor = max(30, min(maxStaleness, max(Int(coordinatorHeartbeatInterval() * 2), 60)))
        let unsigned = FederationDirectorySnapshot(
            mode: request.mode ?? relayConfiguration.federation.mode,
            federationName: request.federationName ?? relayConfiguration.federation.name,
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
                throw FederationDirectoryValidationError.invalidSnapshot
            }
            if let expectedName = request.federationName?.trimmingCharacters(in: .whitespacesAndNewlines),
               !expectedName.isEmpty,
               snapshot.federationName != expectedName {
                throw FederationDirectoryValidationError.invalidSnapshot
            }
            guard snapshot.validUntil > Date() else {
                throw FederationDirectoryValidationError.invalidSnapshot
            }
            if request.requireSignedSnapshot == true {
                guard let trustedPublicKey,
                      FederationDirectorySignature.verify(snapshot: snapshot, trustedPublicKey: trustedPublicKey) else {
                    throw FederationDirectoryValidationError.invalidSnapshot
                }
            } else if let trustedPublicKey, snapshot.signature != nil {
                guard FederationDirectorySignature.verify(snapshot: snapshot, trustedPublicKey: trustedPublicKey) else {
                    throw FederationDirectoryValidationError.invalidSnapshot
                }
            }
            return applyFreshnessPolicy(nodes: snapshot.nodes, request: request)
        }
        if request.requireSignedSnapshot == true {
            throw FederationDirectoryValidationError.invalidSnapshot
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

    private func isDestinationAllowedByCoordinator(
        _ destination: RelayEndpoint,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<Bool> {
        fetchCoordinatorNodeDirectory(
            request: ListFederationNodesRequest(
                mode: relayConfiguration.federation.mode,
                federationName: relayConfiguration.federation.name,
                onlyHealthy: true,
                maxStalenessSeconds: relayConfiguration.coordinatorDirectoryMaxStalenessSeconds,
                requireSignedSnapshot: relayConfiguration.curatedRequireSignedDirectory
            ),
            on: eventLoop
        ).map { nodes in
            nodes.contains(where: { $0.endpoint == destination })
        }
    }

    private func destinationSeenByCoordinatorCount(
        _ destination: RelayEndpoint,
        request: ListFederationNodesRequest,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<Int> {
        let coordinators = coordinatorEndpoints()
        guard !coordinators.isEmpty else {
            return eventLoop.makeSucceededFuture(0)
        }
        let futures: [EventLoopFuture<Bool>] = coordinators.map { coordinator in
            fetchValidatedCoordinatorNodes(from: coordinator, request: request, on: eventLoop)
                .map { nodes in
                    nodes.contains(where: { $0.endpoint == destination })
                }
                .flatMapError { _ in
                    eventLoop.makeSucceededFuture(false)
                }
        }
        return EventLoopFuture.whenAllSucceed(futures, on: eventLoop).map { results in
            results.filter { $0 }.count
        }
    }

    private func knownOpenFederationPeers() -> [RelayEndpoint] {
        guard relayConfiguration.federation.mode == .open,
              relayConfiguration.kind != .coordinator else {
            return []
        }
        let limit = max(0, relayConfiguration.relayPeerExchangeLimit ?? 12)
        guard limit > 0 else {
            return []
        }
        let selfEndpoint = effectiveAdvertisedEndpoint()
        var seen = Set<String>()
        var peers: [RelayEndpoint] = []
        for node in store.coordinatorDirectoryCacheSnapshot() {
            guard node.relayInfo.federation.mode == .open,
                  node.relayInfo.kind != .coordinator else {
                continue
            }
            if let selfEndpoint, node.endpoint == selfEndpoint {
                continue
            }
            let key = "\(node.endpoint.host.lowercased()):\(node.endpoint.port):\(node.endpoint.useTLS ? 1 : 0):\(node.endpoint.transport.rawValue)"
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
        let defaultTTL = max(60, relayConfiguration.attachmentDefaultTTLSeconds)
        let maxTTL = max(defaultTTL, relayConfiguration.attachmentMaxTTLSeconds)
        guard let requested else {
            return defaultTTL
        }
        return min(max(60, requested), maxTTL)
    }

    private func sendRequest(
        _ request: RelayRequest,
        to endpoint: RelayEndpoint,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<RelayResponse> {
        switch endpoint.transport {
        case .tcp:
            return sendRequestTCP(request, to: endpoint, on: eventLoop)
        case .http:
            return sendRequestHTTP(request, to: endpoint, on: eventLoop)
        case .websocket:
            return sendRequestHTTP(request, to: endpoint, on: eventLoop)
        }
    }

    private func sendRequestTCP(
        _ request: RelayRequest,
        to endpoint: RelayEndpoint,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<RelayResponse> {
        guard !endpoint.useTLS else {
            return eventLoop.makeFailedFuture(RelayForwardTransportError.rawTLSUnavailable)
        }
        let promise = eventLoop.makePromise(of: RelayResponse.self)
        let completion = ForwardingCompletion()
        let channelCloser = ForwardingChannelCloser()
        let timeoutTask = eventLoop.scheduleTask(in: .seconds(Int64(forwardingRequestTimeoutSeconds))) {
            channelCloser.close()
            completion.resolve(promise, .failure(RelayForwardTimeoutError()))
        }
        promise.futureResult.whenComplete { _ in
            timeoutTask.cancel()
            channelCloser.close()
        }
        do {
            let data = try RelayCodec.encoder().encode(request)
            let bootstrap = ClientBootstrap(group: eventLoop)
                .connectTimeout(.seconds(Int64(forwardingRequestTimeoutSeconds)))
                .channelInitializer { channel in
                    channel.pipeline.addHandler(LineFrameHandler(maxLength: self.maxLineBytes)).flatMap {
                        channel.pipeline.addHandler(ForwardingHandler(
                            requestData: data,
                            expectedRequest: request,
                            promise: promise,
                            completion: completion
                        ))
                    }
                }
            bootstrap.connect(host: endpoint.host, port: Int(endpoint.port)).whenComplete { result in
                switch result {
                case .success(let channel):
                    channelCloser.attach(channel)
                case .failure(let error):
                    completion.resolve(promise, .failure(error))
                }
            }
        } catch {
            completion.resolve(promise, .failure(error))
        }
        return promise.futureResult
    }

    private func sendRequestHTTP(
        _ request: RelayRequest,
        to endpoint: RelayEndpoint,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<RelayResponse> {
        let promise = eventLoop.makePromise(of: RelayResponse.self)
        let completion = ForwardingCompletion()
        let forwardingTask = Task.detached {
            do {
                var components = URLComponents()
                components.scheme = endpoint.useTLS ? "https" : "http"
                components.host = endpoint.host
                components.port = Int(endpoint.port)
                components.path = "/relay"
                guard let url = components.url else {
                    throw RelayForwardHTTPError.invalidURL
                }
                var urlRequest = URLRequest(url: url)
                urlRequest.httpMethod = "POST"
                urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
                urlRequest.httpBody = try RelayCodec.encoder().encode(request)
                urlRequest.timeoutInterval = TimeInterval(self.forwardingRequestTimeoutSeconds)
                urlRequest.cachePolicy = .reloadIgnoringLocalCacheData
                let (data, response) = try await BoundedURLSessionLoader.load(
                    urlRequest,
                    maximumBytes: self.maxMessageBytes
                )
                try Task.checkCancellation()
                guard let status = (response as? HTTPURLResponse)?.statusCode,
                      (200...299).contains(status) else {
                    let status = (response as? HTTPURLResponse)?.statusCode ?? -1
                    throw RelayForwardHTTPError.badStatus(status)
                }
                let decoded = try RelayCodec.decoder().decode(RelayResponse.self, from: data)
                guard decoded.isResponse(to: request) else {
                    throw RelayForwardHTTPError.invalidResponseBinding
                }
                eventLoop.execute { completion.resolve(promise, .success(decoded)) }
            } catch {
                eventLoop.execute { completion.resolve(promise, .failure(error)) }
            }
        }
        let timeoutTask = eventLoop.scheduleTask(in: .seconds(Int64(forwardingRequestTimeoutSeconds))) {
            forwardingTask.cancel()
            completion.resolve(promise, .failure(RelayForwardTimeoutError()))
        }
        promise.futureResult.whenComplete { _ in
            timeoutTask.cancel()
        }
        return promise.futureResult
    }

    private func requiresAuthentication(for binding: RelayOperationBinding) -> Bool {
        binding.module != .core
            && !(binding.module == .federation && [.register, .list].contains(binding.method))
    }

    private func validateAuthentication(token: String?) -> String? {
        let expected = relayConfiguration.accessPassword?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
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
        let expected = relayConfiguration.coordinatorRegistrationToken?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if expected.isEmpty, relayConfiguration.federation.mode == .curated {
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

    private func sourceKey(for address: SocketAddress?) -> String {
        if let ipAddress = address?.ipAddress?.trimmingCharacters(in: .whitespacesAndNewlines),
           !ipAddress.isEmpty {
            return ipAddress.lowercased()
        }
        return normalizedFederationSourceKey(address?.description)
    }

    private func isLoopbackRequestSource(_ source: String) -> Bool {
        source == "127.0.0.1" || source == "::1" || source == "0:0:0:0:0:0:0:1"
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

    private func isCoordinatorDirectoryRequest(_ binding: RelayOperationBinding) -> Bool {
        binding.module == .core
            || (binding.module == .federation && [.register, .list].contains(binding.method))
    }
}

private final class ForwardingHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let requestData: Data
    private let expectedRequest: RelayRequest
    private let promise: EventLoopPromise<RelayResponse>
    private let completion: ForwardingCompletion

    init(
        requestData: Data,
        expectedRequest: RelayRequest,
        promise: EventLoopPromise<RelayResponse>,
        completion: ForwardingCompletion
    ) {
        self.requestData = requestData
        self.expectedRequest = expectedRequest
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
            guard response.isResponse(to: expectedRequest) else {
                throw RelayForwardHTTPError.invalidResponseBinding
            }
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

private final class ForwardingCompletion: @unchecked Sendable {
    private let lock = NIOLock()
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

private final class ForwardingChannelCloser: @unchecked Sendable {
    private let lock = NIOLock()
    private var channel: Channel?
    private var shouldClose = false

    func attach(_ channel: Channel) {
        lock.lock()
        if shouldClose {
            lock.unlock()
            channel.close(promise: nil)
            return
        }
        self.channel = channel
        lock.unlock()
    }

    func close() {
        lock.lock()
        shouldClose = true
        let channel = self.channel
        self.channel = nil
        lock.unlock()
        channel?.close(promise: nil)
    }
}
