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
    case destinationRejected
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
    private let relayIdentityRuntime: RelayIdentityRuntime
    private let forwardingRequestTimeoutSeconds: Int
    private let netHostStore: NoctweaveNetHostStore?
    private let passthroughAllowedEndpoints: [RelayEndpoint]
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
        relayIdentityRuntime: RelayIdentityRuntime,
        forwardingRequestTimeoutSeconds: Int,
        netHostStore: NoctweaveNetHostStore? = nil,
        passthroughAllowedEndpoints: [RelayEndpoint] = []
    ) {
        self.store = store
        self.maxMessageBytes = min(max(1_024, maxMessageBytes ?? (512 * 1024)), 8 * 1024 * 1024)
        self.maxLineBytes = min(
            max(maxLineBytes ?? (640 * 1024), self.maxMessageBytes + (128 * 1024)),
            10 * 1024 * 1024
        )
        self.localEndpoint = localEndpoint
        self.relayConfiguration = relayConfiguration
        self.relayIdentityRuntime = relayIdentityRuntime
        self.forwardingRequestTimeoutSeconds = max(1, forwardingRequestTimeoutSeconds)
        self.netHostStore = netHostStore
        self.passthroughAllowedEndpoints = Array(passthroughAllowedEndpoints.prefix(64))
        let coordinatorKeyMaterial: (privateKey: Data, publicKey: Data)?
        if relayConfiguration.kind == .coordinator {
            do {
                let keyData = try FederationDirectorySignature.privateKeyDataThrowing(
                    from: relayConfiguration.coordinatorDirectorySigningPrivateKey
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
            let request = try RelayCodec.decodeWire(RelayRequest.self, from: payload)
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
        } catch is RetryableRelayLocalError {
            print("[relay] local cryptography unavailable while decoding request")
            context.close(promise: nil)
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
           let authFailure = validateAuthentication(
               token: request.authToken,
               binding: request.binding
           ) {
            return failure(authFailure, code: .authenticationRequired)
        }
        guard roleAllows(request.binding) else {
            return failure(
                "Relay role \(relayConfiguration.kind.rawValue) does not serve this module.",
                code: .unavailable
            )
        }
        if relayConfiguration.kind == .coordinator,
           !isCoordinatorDirectoryRequest(request.binding) {
            return failure("Coordinator relays are directory-only and do not carry user traffic.", code: .unavailable)
        }
        switch request.body {
        case .getNoctwebNamespaceSnapshot(let snapshotRequest):
            guard snapshotRequest.isStructurallyValid,
                  snapshotRequest.federationMode
                    == relayConfiguration.federation.mode,
                  snapshotRequest.federationName
                    == relayConfiguration.federation.name else {
                return failure(
                    "Noctweb namespace snapshot trust domain mismatch.",
                    code: .authenticationRequired
                )
            }
            let eventLoop = context.eventLoop
            let makeSnapshot: ([FederationNodeRecord]) -> RelayResponse = {
                nodes in
                do {
                    let now = Date()
                    let identity = try self.relayIdentityRuntime
                        .signedIdentity(
                            configuration: self.relayConfiguration,
                            advertisedEndpoints:
                                self.advertisedIdentityEndpoints(),
                            hostSigningPublicKey:
                                self.netHostStore?.signingPublicKey,
                            at: now
                        )
                    if identity.claim.noctwebSuffix != nil {
                        try self.store.claimNoctwebNamespace(
                            identity,
                            now: now
                        )
                    }
                    for peerIdentity in nodes.compactMap({
                        $0.relayInfo.relayIdentity
                    }) where peerIdentity.claim.noctwebSuffix != nil {
                        try self.store.claimNoctwebNamespace(
                            peerIdentity,
                            now: now
                        )
                    }
                    let ledger = try NoctwebNamespaceLedgerV1(
                        records: self.store.noctwebNamespaceRecords(
                            at: now
                        )
                    )
                    let payload = try ledger.snapshotPayload(
                        federation: self.relayConfiguration.federation,
                        at: now
                    )
                    let snapshot = try NoctwebNamespaceSnapshotV1.signed(
                        payload: payload,
                        by: self.relayIdentityRuntime.keyMaterial
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
            }
            guard relayConfiguration.kind != .coordinator,
                  relayConfiguration.federation.mode != .solo else {
                return eventLoop.makeSucceededFuture(makeSnapshot([]))
            }
            let directoryRequest = ListFederationNodesRequest(
                mode: relayConfiguration.federation.mode,
                federationName: relayConfiguration.federation.name,
                onlyHealthy: true,
                maxStalenessSeconds:
                    relayConfiguration
                        .coordinatorDirectoryMaxStalenessSeconds,
                requireSignedSnapshot:
                    relayConfiguration.federation.mode == .manual
                        ? false
                        : relayConfiguration.curatedRequireSignedDirectory
            )
            return fetchCoordinatorNodeDirectory(
                request: directoryRequest,
                on: eventLoop
            ).map(makeSnapshot)
        case .claimNoctwebNamespace(let claim):
            guard claim.identity.claim.federationMode
                    == relayConfiguration.federation.mode,
                  claim.identity.claim.federationName
                    == relayConfiguration.federation.name,
                  claim.identity.claim.noctwebSuffix != nil else {
                return failure(
                    "Noctweb namespace claim trust domain mismatch.",
                    code: .authenticationRequired
                )
            }
            do {
                let suffix = claim.identity.claim.noctwebSuffix!
                let previous = store.noctwebNamespaceRecord(
                    for: suffix
                )
                try store.claimNoctwebNamespace(claim.identity)
                guard let record = store.noctwebNamespaceRecord(
                        for: suffix
                      ) else {
                    return failure(
                        "Noctweb namespace claim was not retained.",
                        code: .internalFailure
                    )
                }
                if previous != record {
                    propagateNoctwebNamespaceMutation(
                        request,
                        on: context.eventLoop
                    )
                }
                return success(.noctwebNamespaceRecord(record))
            } catch NoctwebNamespaceLedgerErrorV1.suffixAlreadyOwned {
                return failure(
                    "Noctweb suffix is already owned.",
                    code: .conflict
                )
            } catch NoctwebNamespaceLedgerErrorV1.suffixTombstoned {
                return failure(
                    "Noctweb suffix is permanently tombstoned.",
                    code: .conflict
                )
            } catch {
                return failure(
                    "Noctweb namespace claim is invalid.",
                    code: .invalidRequest
                )
            }
        case .rotateNoctwebNamespace(let rotationRequest):
            guard rotationRequest.newIdentity.claim.federationMode
                    == relayConfiguration.federation.mode,
                  rotationRequest.newIdentity.claim.federationName
                    == relayConfiguration.federation.name,
                  rotationRequest.newIdentity.claim.noctwebSuffix
                    != nil else {
                return failure(
                    "Noctweb namespace rotation trust domain mismatch.",
                    code: .authenticationRequired
                )
            }
            do {
                try store.rotateNoctwebNamespace(
                    rotationRequest.rotation,
                    to: rotationRequest.newIdentity
                )
                guard let suffix =
                    rotationRequest.newIdentity.claim.noctwebSuffix,
                    let record = store.noctwebNamespaceRecord(
                        for: suffix
                    ) else {
                    return failure(
                        "Noctweb namespace rotation was not retained.",
                        code: .internalFailure
                    )
                }
                propagateNoctwebNamespaceMutation(
                    request,
                    on: context.eventLoop
                )
                return success(.noctwebNamespaceRecord(record))
            } catch {
                return failure(
                    "Noctweb namespace rotation proof is invalid.",
                    code: .authenticationRequired
                )
            }
        case .releaseNoctwebNamespace(let release):
            do {
                try store.releaseNoctwebNamespace(release)
                guard let record = store.noctwebNamespaceRecord(
                    for: release.suffix
                ) else {
                    return failure(
                        "Noctweb namespace release was not retained.",
                        code: .internalFailure
                    )
                }
                propagateNoctwebNamespaceMutation(
                    request,
                    on: context.eventLoop
                )
                return success(.noctwebNamespaceRecord(record))
            } catch {
                return failure(
                    "Noctweb namespace release proof is invalid.",
                    code: .authenticationRequired
                )
            }
        case .createOpaqueRoute(let submission):
            guard relayConfiguration.isOpaqueRouteRuntimeEnabled else {
                return failure("Opaque route runtime is disabled", code: .unavailable)
            }
            let confidentialTransport = hasConfidentialTransport(requestSourceKey)
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
            let confidentialTransport = hasConfidentialTransport(requestSourceKey)
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
            let confidentialTransport = hasConfidentialTransport(requestSourceKey)
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
            let confidentialTransport = hasConfidentialTransport(requestSourceKey)
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
        case .forwardOpaqueRoute(let forwarding):
            guard relayConfiguration.kind == .standard,
                  relayConfiguration.federation.mode != .solo else {
                return failure(
                    "Federation forwarding is unavailable on this relay.",
                    code: .unavailable
                )
            }
            guard hasConfidentialTransport(requestSourceKey) else {
                return failure(
                    "Federation forwarding requires confidential client transport."
                )
            }
            guard forwarding.isStructurallyValid else {
                return failure("Invalid federation forwarding request.")
            }
            let eventLoop = context.eventLoop
            return authenticatedFederationPeer(
                destination: forwarding.destination,
                expectedRelayID: forwarding.destinationRelayID,
                requiredModule: "nw.federation-forward",
                allowedKinds: [.standard],
                on: eventLoop
            ).flatMap { _ in
                do {
                    let sourceIdentity = try self.relayIdentityRuntime.signedIdentity(
                        configuration: self.relayConfiguration,
                        advertisedEndpoints: self.advertisedIdentityEndpoints(),
                        hostSigningPublicKey: self.netHostStore?.signingPublicKey
                    )
                    let delivery = try FederatedOpaqueRouteDeliveryV1.signed(
                        sourceIdentity: sourceIdentity,
                        sourceKey: self.relayIdentityRuntime.keyMaterial,
                        destinationRelayID: forwarding.destinationRelayID,
                        append: forwarding.append
                    )
                    return self.sendRequest(
                        .deliverOpaqueRouteV1(delivery),
                        to: forwarding.destination,
                        on: eventLoop
                    ).map { response in
                        if case .opaqueRouteAppend(let receipt)? = response.successBody {
                            return .success(
                                .opaqueRouteAppend(receipt),
                                respondingTo: request
                            )
                        }
                        return self.forwardedRelayErrorResponse(
                            response,
                            respondingTo: request
                        )
                    }
                } catch {
                    return eventLoop.makeFailedFuture(error)
                }
            }.flatMapError { _ in
                failure(
                    "Authenticated federation delivery failed.",
                    code: .unavailable,
                    retryable: true
                )
            }
        case .deliverOpaqueRoute(let delivery):
            guard relayConfiguration.kind == .standard,
                  relayConfiguration.federation.mode != .solo,
                  relayConfiguration.isOpaqueRouteRuntimeEnabled else {
                return failure(
                    "Federation delivery is unavailable on this relay.",
                    code: .unavailable
                )
            }
            do {
                guard try delivery.verifyThrowing(
                    expectedDestinationRelayID: relayIdentityRuntime.relayID,
                    federation: relayConfiguration.federation
                ) else {
                    return failure(
                        "Federation delivery identity is invalid.",
                        code: .authenticationRequired
                    )
                }
            } catch {
                return failure(
                    "Federation delivery identity verification failed.",
                    code: .authenticationRequired
                )
            }
            return isAuthenticatedFederationMember(
                delivery.sourceIdentity,
                requiredModule: "nw.federation-forward",
                allowedKinds: [.standard],
                on: context.eventLoop
            ).map { allowed in
                guard allowed else {
                    return RelayResponse.error(
                        "Federation source is not an authenticated member.",
                        code: .authenticationRequired,
                        respondingTo: request
                    )
                }
                do {
                    return RelayResponse.success(
                        .opaqueRouteAppend(
                            try self.store.appendOpaqueRouteV2(
                                delivery.append,
                                confidentialTransport: true
                            )
                        ),
                        respondingTo: request
                    )
                } catch {
                    return self.opaqueRouteErrorResponse(
                        error,
                        respondingTo: request
                    )
                }
            }.flatMapErrorThrowing { _ in
                RelayResponse.error(
                    "Federation membership verification failed.",
                    code: .unavailable,
                    retryable: true,
                    respondingTo: request
                )
            }
        case .syncOpaqueRoute(let submission):
            guard relayConfiguration.isOpaqueRouteRuntimeEnabled else {
                return failure("Opaque route runtime is disabled", code: .unavailable)
            }
            let confidentialTransport = hasConfidentialTransport(requestSourceKey)
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
            let confidentialTransport = hasConfidentialTransport(requestSourceKey)
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
            guard hasConfidentialTransport(requestSourceKey) else {
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
            guard hasConfidentialTransport(requestSourceKey) else {
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
            guard hasConfidentialTransport(requestSourceKey) else {
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
            guard hasConfidentialTransport(requestSourceKey) else {
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
                    wakeSupport: info.wakeSupport,
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
                        wakeSupport: info.wakeSupport,
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
            do {
                info = try relayIdentityRuntime.authenticatedInfo(
                    info,
                    configuration: relayConfiguration,
                    advertisedEndpoints: advertisedIdentityEndpoints(),
                    hostSigningPublicKey: netHostStore?.signingPublicKey
                )
                return success(.relayInfo(info))
            } catch {
                return failure(
                    "Relay identity signing is unavailable.",
                    code: .unavailable,
                    retryable: true
                )
            }
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
                    ttlSeconds: upload.ttlSeconds,
                    idempotencyKey: upload.idempotencyKey,
                    effectiveTTLSeconds: boundedTTL
                )
                return success(.attachment(chunk))
            } catch RelayStoreError.invalidChunkIndex {
                return failure("Invalid chunk index")
            } catch RelayStoreError.invalidAttachmentPayload {
                return failure("Invalid attachment payload")
            } catch RelayStoreError.invalidAttachmentIdempotency {
                return failure("Invalid attachment idempotency key")
            } catch RelayStoreError.attachmentConflict {
                return failure(
                    "Attachment coordinate conflicts with stored state",
                    code: .conflict
                )
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
            guard relayConfiguration.federation.mode != .manual else {
                return failure(
                    "Manual federation does not accept relay registration; configure peers explicitly.",
                    code: .invalidRequest
                )
            }
            guard relayConfiguration.kind == .coordinator else {
                return failure("This relay is not a coordinator node.", code: .unavailable)
            }
            if let authFailure = validateCoordinatorRegistrationAuthentication(token: request.authToken) {
                return failure(authFailure, code: .authenticationRequired)
            }
            if let identityFailure = validateFederationRegistrationIdentity(
                registration
            ) {
                return failure(identityFailure, code: .invalidRequest)
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
                let snapshot: FederationDirectorySnapshot?
                do {
                    snapshot = try makeCoordinatorDirectorySnapshot(
                        nodes: nodes,
                        request: listRequest
                    )
                } catch {
                    return failure(
                        "Coordinator snapshot signing is temporarily unavailable.",
                        code: .unavailable,
                        retryable: true
                    )
                }
                if listRequest.requireSignedSnapshot == true, snapshot == nil {
                    return failure(
                        "Coordinator snapshot signing is not available.",
                        code: .unavailable,
                        retryable: true
                    )
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
            let result: OpenFederationDHTDiscoveryIngestResult
            do {
                result = try store.ingestOpenFederationDHTRecords(
                    [publish.record],
                    configuration: dhtConfiguration
                )
            } catch is RetryableRelayLocalError {
                return failure(
                    "Relay cryptography is temporarily unavailable.",
                    code: .unavailable,
                    retryable: true
                )
            } catch {
                return failure(
                    "Open-federation DHT processing failed.",
                    code: .internalFailure,
                    retryable: true
                )
            }
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
        case .getFederatedNetHostObject(let read):
            guard relayConfiguration.kind == .standard,
                  relayConfiguration.federation.mode != .solo,
                  read.isStructurallyValid else {
                return failure(
                    "Federated Noctweb retrieval is unavailable.",
                    code: .unavailable
                )
            }
            let eventLoop = context.eventLoop
            return authenticatedFederationPeer(
                destination: read.destination,
                expectedRelayID: read.destinationRelayID,
                requiredModule: "nw.net-host",
                allowedKinds: [.standard, .host],
                on: eventLoop
            ).flatMap { destinationInfo in
                self.sendRequest(
                    .getNetHostObject(read.request),
                    to: read.destination,
                    on: eventLoop
                ).map { response in
                    guard case .netHostObject(let object)? = response.successBody,
                          let destinationIdentity = destinationInfo.relayIdentity else {
                        return self.forwardedRelayErrorResponse(
                            response,
                            respondingTo: request
                        )
                    }
                    let federated = FederatedNetHostObjectResponseV1(
                        destinationIdentity: destinationIdentity,
                        object: object
                    )
                    guard (try? federated.verifyThrowing(
                        expectedRelayID: read.destinationRelayID
                    )) == true else {
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
                }
            }.flatMapError { _ in
                failure(
                    "Federated Noctweb destination is unavailable.",
                    code: .unavailable,
                    retryable: true
                )
            }
        case .resolveFederatedNetHostName(let read):
            guard relayConfiguration.kind == .standard,
                  relayConfiguration.federation.mode != .solo,
                  read.isStructurallyValid else {
                return failure(
                    "Federated Noctweb name resolution is unavailable.",
                    code: .unavailable
                )
            }
            let eventLoop = context.eventLoop
            return authenticatedFederationPeer(
                destination: read.destination,
                expectedRelayID: read.destinationRelayID,
                requiredModule: "nw.net-host",
                allowedKinds: [.standard, .host],
                on: eventLoop
            ).flatMap { destinationInfo in
                self.sendRequest(
                    .resolveNetHostName(read.request),
                    to: read.destination,
                    on: eventLoop
                ).map { response in
                    guard case .netHostNameResolution(
                        let resolution
                    )? = response.successBody,
                    let destinationIdentity =
                        destinationInfo.relayIdentity else {
                        return self.forwardedRelayErrorResponse(
                            response,
                            respondingTo: request
                        )
                    }
                    let federated = FederatedNetHostNameResponseV1(
                        destinationIdentity: destinationIdentity,
                        resolution: resolution
                    )
                    guard (try? federated.verifyThrowing(
                        expectedRelayID: read.destinationRelayID
                    )) == true else {
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
                }
            }.flatMapError { _ in
                failure(
                    "Federated Noctweb destination is unavailable.",
                    code: .unavailable,
                    retryable: true
                )
            }
        case .netPassthrough(let passthrough):
            guard relayConfiguration.kind == .passthrough else {
                return failure("This relay is not a passthrough relay.", code: .unavailable)
            }
            guard hasConfidentialTransport(requestSourceKey) else {
                return failure("Noctweave Net passthrough requires confidential transport.")
            }
            guard passthrough.isStructurallyValid,
                  passthrough.destination.useTLS,
                  passthroughAllowedEndpoints.contains(passthrough.destination),
                  PublicRelayEndpointPolicy.permits(passthrough.destination) else {
                return failure("Passthrough destination is not allowed.")
            }
            return forwardNoctweaveNetPayload(
                passthrough.payload,
                to: passthrough.destination,
                on: context.eventLoop
            ).map {
                .success(
                    .netPassthrough(NoctweaveNetPassthroughResponse(payload: $0)),
                    respondingTo: request
                )
            }.flatMapError { _ in
                failure(
                    "Passthrough destination is unavailable.",
                    code: .unavailable,
                    retryable: true
                )
            }
        case .putNetHostObject(let put):
            guard relayConfiguration.isNetHostEnabled, let netHostStore else {
                return failure("This relay does not provide Noctweave Net hosting.", code: .unavailable)
            }
            guard hasConfidentialTransport(requestSourceKey) else {
                return failure("Noctweave Net hosting writes require confidential transport.")
            }
            do {
                return success(.netHostReceipt(try netHostStore.put(put)))
            } catch NoctweaveNetHostStoreError.conflict {
                return failure("Host object conflicts with stored state.", code: .conflict)
            } catch NoctweaveNetHostStoreError.capacityExceeded {
                return failure("Host object capacity reached.", code: .capacity)
            } catch {
                return failure("Host object could not be stored.", code: .internalFailure, retryable: true)
            }
        case .bindNetHostName(let binding):
            guard relayConfiguration.isNetHostEnabled,
                  let netHostStore,
                  let configuredSuffix =
                    relayConfiguration.noctwebRelaySuffix,
                  binding.relaySuffix == configuredSuffix else {
                return failure(
                    "This relay does not own the requested Noctweb suffix.",
                    code: .unavailable
                )
            }
            guard hasConfidentialTransport(requestSourceKey) else {
                return failure(
                    "Noctweave Net name writes require confidential transport."
                )
            }
            do {
                let now = Date()
                let stored = try netHostStore.bindName(
                    binding,
                    now: now
                )
                let resolution = try NoctweaveNetHostNameResolutionV1.signed(
                    binding: stored,
                    updatedAt: now,
                    signer: relayIdentityRuntime.keyMaterial,
                    at: now
                )
                return success(.netHostNameResolution(resolution))
            } catch NoctweaveNetHostStoreError.conflict {
                return failure(
                    "Noctweb name conflicts with publisher continuity.",
                    code: .conflict
                )
            } catch NoctweaveNetHostStoreError.objectUnavailable {
                return failure(
                    "The named host object is not available.",
                    code: .notFound
                )
            } catch {
                return failure(
                    "Noctweb name could not be stored.",
                    code: .internalFailure,
                    retryable: true
                )
            }
        case .getNetHostObject(let get):
            guard relayConfiguration.isNetHostEnabled, let netHostStore else {
                return failure("This relay does not provide Noctweave Net hosting.", code: .unavailable)
            }
            do {
                guard let object = try netHostStore.fetch(get) else {
                    return failure("Host object not found.", code: .notFound)
                }
                return success(.netHostObject(object))
            } catch {
                return failure("Host object could not be read.", code: .internalFailure, retryable: true)
            }
        case .resolveNetHostName(let name):
            guard relayConfiguration.isNetHostEnabled,
                  let netHostStore,
                  let configuredSuffix =
                    relayConfiguration.noctwebRelaySuffix,
                  name.relaySuffix == configuredSuffix else {
                return failure(
                    "This relay does not own the requested Noctweb suffix.",
                    code: .notFound
                )
            }
            do {
                let now = Date()
                guard let binding = try netHostStore.resolveName(
                    name,
                    now: now
                ) else {
                    return failure(
                        "Noctweb name not found.",
                        code: .notFound
                    )
                }
                let resolution = try NoctweaveNetHostNameResolutionV1.signed(
                    binding: binding,
                    updatedAt: now,
                    signer: relayIdentityRuntime.keyMaterial,
                    at: now
                )
                return success(.netHostNameResolution(resolution))
            } catch {
                return failure(
                    "Noctweb name could not be resolved.",
                    code: .internalFailure,
                    retryable: true
                )
            }
        case .hasNetHostObject(let has):
            guard relayConfiguration.isNetHostEnabled, let netHostStore else {
                return failure("This relay does not provide Noctweave Net hosting.", code: .unavailable)
            }
            do {
                return success(.netHostPresence(try netHostStore.presence(has)))
            } catch {
                return failure("Host object presence could not be read.", code: .internalFailure, retryable: true)
            }
        case .releaseNetHostObject(let release):
            guard relayConfiguration.isNetHostEnabled, let netHostStore else {
                return failure("This relay does not provide Noctweave Net hosting.", code: .unavailable)
            }
            guard hasConfidentialTransport(requestSourceKey) else {
                return failure("Noctweave Net hosting releases require confidential transport.")
            }
            do {
                return success(.netHostRelease(try netHostStore.release(release)))
            } catch NoctweaveNetHostStoreError.unauthorizedRelease {
                return failure(
                    "Host release capability rejected.",
                    code: .authenticationRequired
                )
            } catch {
                return failure("Host object could not be released.", code: .internalFailure, retryable: true)
            }
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
        case RelayStoreError.invalidAttachmentIdempotency:
            return .error("Invalid attachment idempotency key", respondingTo: request)
        case RelayStoreError.attachmentConflict:
            return .error(
                "Attachment coordinate conflicts with stored state",
                code: .conflict,
                respondingTo: request
            )
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
        } catch is RetryableRelayLocalError {
            print("[relay] local cryptography unavailable while encoding response")
            context.close(promise: nil)
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

    private func authenticatedFederationPeer(
        destination: RelayEndpoint,
        expectedRelayID: RelayIdentityIDV1,
        requiredModule: String,
        allowedKinds: Set<RelayKind>,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<RelayInfo> {
        guard permitsFederationTransport(destination) else {
            return eventLoop.makeFailedFuture(
                RelayForwardHTTPError.destinationRejected
            )
        }
        return federationMembershipRecord(
            destination: destination,
            on: eventLoop
        ).flatMap { membership in
            self.fetchRelayInfo(from: destination, on: eventLoop).flatMapThrowing {
                liveInfo in
                guard let liveInfo,
                      try self.isValidFederationPeerInfo(
                          liveInfo,
                          endpoint: destination,
                          expectedRelayID: expectedRelayID,
                          requiredModule: requiredModule,
                          allowedKinds: allowedKinds
                      ) else {
                    throw RelayForwardHTTPError.destinationRejected
                }
                if let membership {
                    guard let listedIdentity = membership.relayInfo.relayIdentity,
                          try listedIdentity.verifyThrowing(at: Date()),
                          listedIdentity.claim.relayID == expectedRelayID,
                          listedIdentity.claim.signingPublicKey
                            == liveInfo.relayIdentity?.claim.signingPublicKey else {
                        throw RelayForwardHTTPError.destinationRejected
                    }
                }
                return liveInfo
            }
        }
    }

    private func federationMembershipRecord(
        destination: RelayEndpoint,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<FederationNodeRecord?> {
        guard relayConfiguration.federation.mode != .solo else {
            return eventLoop.makeFailedFuture(
                RelayForwardHTTPError.destinationRejected
            )
        }
        if relayConfiguration.federation.mode == .manual {
            guard relayConfiguration.federationAllowList.contains(where: {
                federationEndpointKey($0) == federationEndpointKey(destination)
            }) else {
                return eventLoop.makeFailedFuture(
                    RelayForwardHTTPError.destinationRejected
                )
            }
            return eventLoop.makeSucceededFuture(nil)
        }
        return fetchCoordinatorNodeDirectory(
            request: ListFederationNodesRequest(
                mode: relayConfiguration.federation.mode,
                federationName: relayConfiguration.federation.name,
                onlyHealthy: true,
                maxStalenessSeconds: relayConfiguration.coordinatorDirectoryMaxStalenessSeconds,
                requireSignedSnapshot: true
            ),
            on: eventLoop
        ).flatMapThrowing { nodes in
            guard let record = nodes.first(where: {
                self.federationEndpointKey($0.endpoint)
                    == self.federationEndpointKey(destination)
            }) else {
                throw RelayForwardHTTPError.destinationRejected
            }
            return record
        }
    }

    private func isAuthenticatedFederationMember(
        _ identity: SignedRelayIdentityClaimV1,
        requiredModule: String,
        allowedKinds: Set<RelayKind>,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<Bool> {
        do {
            guard try identity.verifyThrowing(at: Date()),
                  allowedKinds.contains(identity.claim.relayKind),
                  identity.claim.federationMode
                    == relayConfiguration.federation.mode,
                  identity.claim.federationName
                    == relayConfiguration.federation.name else {
                return eventLoop.makeSucceededFuture(false)
            }
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
        if relayConfiguration.federation.mode == .manual {
            let allowed = identity.claim.advertisedEndpoints.contains { advertised in
                relayConfiguration.federationAllowList.contains {
                    federationEndpointKey($0) == federationEndpointKey(advertised)
                }
            }
            return eventLoop.makeSucceededFuture(allowed)
        }
        return fetchCoordinatorNodeDirectory(
            request: ListFederationNodesRequest(
                mode: relayConfiguration.federation.mode,
                federationName: relayConfiguration.federation.name,
                onlyHealthy: true,
                maxStalenessSeconds: relayConfiguration.coordinatorDirectoryMaxStalenessSeconds,
                requireSignedSnapshot: true
            ),
            on: eventLoop
        ).map { records in
            records.contains { record in
                guard let listedIdentity = record.relayInfo.relayIdentity,
                      listedIdentity.claim.relayID == identity.claim.relayID,
                      listedIdentity.claim.signingPublicKey
                        == identity.claim.signingPublicKey,
                      record.relayInfo.protocolCapabilities?.supports(
                          module: requiredModule,
                          version: 1
                      ) == true else {
                    return false
                }
                return identity.claim.advertisedEndpoints.contains {
                    self.federationEndpointKey($0)
                        == self.federationEndpointKey(record.endpoint)
                }
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
        guard allowedKinds.contains(info.kind),
              info.federation.mode == relayConfiguration.federation.mode,
              info.federation.name == relayConfiguration.federation.name,
              info.protocolCapabilities?.supports(
                  module: requiredModule,
                  version: 1
              ) == true,
              let identity = info.relayIdentity,
              try identity.verifyThrowing(at: Date()),
              identity.claim.relayID == expectedRelayID,
              identity.claim.advertisedEndpoints.contains(where: {
                  federationEndpointKey($0) == federationEndpointKey(endpoint)
              }) else {
            return false
        }
        return true
    }

    private func permitsFederationTransport(_ endpoint: RelayEndpoint) -> Bool {
        if endpoint.useTLS { return true }
        let host = endpoint.host
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        return host == "127.0.0.1" || host == "::1" || host == "localhost"
    }

    private func advertisedIdentityEndpoints() -> [RelayEndpoint] {
        if let advertised = relayConfiguration.advertisedEndpoint {
            return [advertised]
        }
        guard let localEndpoint else { return [] }
        let normalizedHost: String
        switch localEndpoint.host
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() {
        case "", "0.0.0.0", "::":
            normalizedHost = "127.0.0.1"
        default:
            normalizedHost = localEndpoint.host
        }
        return [
            RelayEndpoint(
                host: normalizedHost,
                port: localEndpoint.port,
                useTLS: localEndpoint.useTLS,
                transport: localEndpoint.transport,
                tlsCertificateFingerprintSHA256:
                    localEndpoint.tlsCertificateFingerprintSHA256,
                directorySigningPublicKey:
                    localEndpoint.directorySigningPublicKey
            )
        ]
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
        if relayConfiguration.federation.mode == .manual {
            return eventLoop.makeSucceededFuture(
                "Manual federation does not accept relay registration; configure peers explicitly."
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
        guard let submittedIdentity = registration.relayInfo.relayIdentity else {
            return eventLoop.makeSucceededFuture(
                "Coordinator registration rejected: relay identity is missing."
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
            guard let liveIdentity = info.relayIdentity,
                  (try? liveIdentity.verifyThrowing(at: info.advertisedAt)) == true,
                  liveIdentity.claim.relayID == submittedIdentity.claim.relayID,
                  liveIdentity.claim.signingPublicKey
                    == submittedIdentity.claim.signingPublicKey,
                  liveIdentity.claim.advertisedEndpoints.contains(where: {
                      self.federationEndpointKey($0)
                        == self.federationEndpointKey(registration.endpoint)
                  }) else {
                return "Coordinator registration rejected: live relay identity differs from the submitted identity."
            }
            return nil
        }.flatMapError { _ in
            eventLoop.makeSucceededFuture(
                String?.some("Coordinator registration rejected: endpoint reachability check failed.")
            )
        }
    }

    private func validateFederationRegistrationIdentity(
        _ registration: FederationNodeRegistrationRequest
    ) -> String? {
        guard let identity = registration.relayInfo.relayIdentity,
              (try? identity.verifyThrowing(
                  at: registration.relayInfo.advertisedAt
              )) == true,
              identity.claim.advertisedEndpoints.contains(where: {
                  federationEndpointKey($0)
                    == federationEndpointKey(registration.endpoint)
              }) else {
            return "Coordinator registration rejected: relay identity is missing, invalid, or does not bind the advertised endpoint."
        }
        guard identity.claim.noctwebSuffix != nil else {
            return "Coordinator registration rejected: federated relays must advertise an authenticated Noctweb suffix."
        }
        return nil
    }

    private func coordinatorEndpoints() -> [RelayEndpoint] {
        let endpoints = relayConfiguration.federation.mode == .manual
            ? relayConfiguration.federationAllowList
            : relayConfiguration.federationCoordinatorEndpoints ?? []
        var seen = Set<String>()
        return endpoints.filter { endpoint in
            !endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && seen.insert(federationEndpointKey(endpoint)).inserted
        }
    }

    private func federationEndpointKey(_ endpoint: RelayEndpoint) -> String {
        "\(endpoint.host.lowercased()):\(endpoint.port):\(endpoint.useTLS ? 1 : 0):\(endpoint.transport.rawValue)"
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
        if relayConfiguration.federation.mode == .manual {
            return fetchCoordinatorNodeDirectory(
                request: ListFederationNodesRequest(
                    mode: .manual,
                    federationName: relayConfiguration.federation.name,
                    onlyHealthy: true,
                    maxStalenessSeconds: relayConfiguration.coordinatorDirectoryMaxStalenessSeconds,
                    requireSignedSnapshot: false
                ),
                on: eventLoop
            ).map { _ in () }
        }
        guard let advertisedEndpoint = effectiveAdvertisedEndpoint() else {
            return eventLoop.makeSucceededFuture(())
        }
        let coordinators = coordinatorEndpoints()
        guard !coordinators.isEmpty else {
            return eventLoop.makeSucceededFuture(())
        }
        let interval = coordinatorHeartbeatInterval()
        let ttl = max(Int(interval * 3), 60)
        let info: RelayInfo
        do {
            info = try relayIdentityRuntime.authenticatedInfo(
                relayConfiguration.makeInfo(now: Date()),
                configuration: relayConfiguration,
                advertisedEndpoints: advertisedIdentityEndpoints(),
                hostSigningPublicKey: netHostStore?.signingPublicKey
            )
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
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
            if request.mode == .manual {
                guard relayInfo.kind == .standard,
                      relayInfo.federation.mode == .manual else {
                    return eventLoop.makeFailedFuture(
                        FederationDirectoryValidationError.invalidSnapshot
                    )
                }
                if let expectedName = request.federationName?
                    .trimmingCharacters(in: .whitespacesAndNewlines),
                   !expectedName.isEmpty,
                   relayInfo.federation.name != expectedName {
                    return eventLoop.makeFailedFuture(
                        FederationDirectoryValidationError.invalidSnapshot
                    )
                }
                let now = Date()
                let lifetime = min(
                    900,
                    max(
                        60,
                        request.maxStalenessSeconds
                            ?? self.relayConfiguration
                                .coordinatorDirectoryMaxStalenessSeconds
                            ?? 300
                    )
                )
                return eventLoop.makeSucceededFuture([
                    FederationNodeRecord(
                        endpoint: coordinator,
                        relayInfo: relayInfo,
                        lastHeartbeatAt: now,
                        expiresAt: now.addingTimeInterval(
                            TimeInterval(lifetime)
                        )
                    )
                ])
            }
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
    ) throws -> FederationDirectorySnapshot? {
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
                      try FederationDirectorySignature.verifyThrowing(
                          snapshot: snapshot,
                          trustedPublicKey: trustedPublicKey
                      ) else {
                    throw FederationDirectoryValidationError.invalidSnapshot
                }
            } else if let trustedPublicKey, snapshot.signature != nil {
                guard try FederationDirectorySignature.verifyThrowing(
                    snapshot: snapshot,
                    trustedPublicKey: trustedPublicKey
                ) else {
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

    private func propagateNoctwebNamespaceMutation(
        _ request: RelayRequest,
        on eventLoop: EventLoop
    ) {
        guard relayConfiguration.federation.mode != .solo else {
            return
        }
        var candidates = relayConfiguration.federationAllowList
        candidates.append(
            contentsOf:
                relayConfiguration.federationCoordinatorEndpoints ?? []
        )
        candidates.append(contentsOf: knownOpenFederationPeers())
        candidates.append(
            contentsOf:
                store.coordinatorDirectoryCacheSnapshot().map(\.endpoint)
        )

        let localKey = effectiveAdvertisedEndpoint().map(
            federationEndpointKey
        )
        var seen = Set<String>()
        let endpoints = Array(candidates.filter { endpoint in
            guard permitsFederationTransport(endpoint) else {
                return false
            }
            let key = federationEndpointKey(endpoint)
            return key != localKey && seen.insert(key).inserted
        }.prefix(64))
        guard !endpoints.isEmpty else {
            return
        }

        let futures = endpoints.map { endpoint in
            sendRequest(request, to: endpoint, on: eventLoop)
                .map { _ in () }
                .flatMapError { _ in
                    eventLoop.makeSucceededFuture(())
                }
        }
        EventLoopFuture.andAllSucceed(
            futures,
            on: eventLoop
        ).whenComplete { _ in }
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
                let decoded = try RelayCodec.decodeWire(RelayResponse.self, from: data)
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

    private func forwardNoctweaveNetPayload(
        _ payload: Data,
        to endpoint: RelayEndpoint,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<Data> {
        let promise = eventLoop.makePromise(of: Data.self)
        let completion = ForwardingCompletion()
        let forwardingTask = Task.detached {
            do {
                guard endpoint.transport == .http,
                      endpoint.useTLS,
                      PublicRelayEndpointPolicy.permits(endpoint) else {
                    throw RelayForwardHTTPError.destinationRejected
                }
                var components = URLComponents()
                components.scheme = "https"
                components.host = endpoint.host
                components.port = Int(endpoint.port)
                components.path = "/relay"
                guard let url = components.url else {
                    throw RelayForwardHTTPError.invalidURL
                }
                var request = URLRequest(url: url)
                request.httpMethod = "POST"
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                request.httpBody = payload
                request.timeoutInterval = TimeInterval(self.forwardingRequestTimeoutSeconds)
                request.cachePolicy = .reloadIgnoringLocalCacheData
                let (data, response) = try await BoundedURLSessionLoader.load(
                    request,
                    maximumBytes: NoctweaveNetLimits.maximumPassthroughPayloadBytes
                )
                try Task.checkCancellation()
                guard let status = (response as? HTTPURLResponse)?.statusCode,
                      (200...299).contains(status),
                      !data.isEmpty else {
                    throw RelayForwardHTTPError.badStatus(
                        (response as? HTTPURLResponse)?.statusCode ?? -1
                    )
                }
                eventLoop.execute {
                    completion.resolve(promise, .success(data))
                }
            } catch {
                eventLoop.execute {
                    completion.resolve(promise, .failure(error))
                }
            }
        }
        let timeoutTask = eventLoop.scheduleTask(
            in: .seconds(Int64(forwardingRequestTimeoutSeconds))
        ) {
            forwardingTask.cancel()
            completion.resolve(promise, .failure(RelayForwardTimeoutError()))
        }
        promise.futureResult.whenComplete { _ in
            timeoutTask.cancel()
        }
        return promise.futureResult
    }

    private func requiresAuthentication(for binding: RelayOperationBinding) -> Bool {
        if binding.module == .netHost,
           [.get, .resolve, .has].contains(binding.method) {
            return false
        }
        if binding.module == .federationForward,
           binding.method == .deliver {
            return false
        }
        return binding.module != .core
            && !(binding.module == .federation
                && [
                    .register,
                    .list,
                    .namespace,
                    .claim,
                    .rotate,
                    .release
                ].contains(binding.method))
    }

    private func roleAllows(_ binding: RelayOperationBinding) -> Bool {
        if binding.module == .core {
            return true
        }
        if binding.module == .netHost {
            return relayConfiguration.isNetHostEnabled && netHostStore != nil
        }
        if binding.module == .federation,
           [.namespace, .claim, .rotate, .release].contains(
                binding.method
           ) {
            return true
        }
        switch relayConfiguration.kind {
        case .standard:
            return binding.module != .netPassthrough
        case .passthrough:
            return binding.module == .netPassthrough
        case .host:
            return false
        case .discovery, .bridge, .privateRelay, .coordinator:
            return binding.module != .netPassthrough
        }
    }

    private func validateAuthentication(
        token: String?,
        binding: RelayOperationBinding
    ) -> String? {
        let configuredPassword = binding.module == .netHost
            && [.put, .bind, .release].contains(binding.method)
            ? relayConfiguration.publisherPassword ?? relayConfiguration.accessPassword
            : relayConfiguration.accessPassword
        let expected = configuredPassword?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
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

    private func hasConfidentialTransport(_ source: String) -> Bool {
        relayConfiguration.effectiveTransportConfidentiality(
            isLiteralLoopbackSource: isLoopbackRequestSource(source)
        ).permitsCapabilityTransport
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
            let response = try RelayCodec.decodeWire(RelayResponse.self, from: payload)
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

    func resolve<Value>(
        _ promise: EventLoopPromise<Value>,
        _ result: Result<Value, Error>
    ) {
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
