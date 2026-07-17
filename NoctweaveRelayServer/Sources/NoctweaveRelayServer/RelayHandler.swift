import Foundation
import Crypto
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
            respond(.error("Invalid payload"), context: context)
            return
        }
        if payload.count > maxMessageBytes {
            respond(.error("Payload too large"), context: context)
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
                    self.respond(.error("Handler error"), context: responseContext.context)
                }
            }
        } catch {
            respond(.error("Decode failed"), context: context)
        }
    }

    private func handle(_ request: RelayRequest, context: ChannelHandlerContext) -> EventLoopFuture<RelayResponse> {
        scheduleCoordinatorHeartbeatIfNeeded(on: context.eventLoop)
        let requestSourceKey = sourceKey(for: context.channel.remoteAddress)
        if !isLoopbackRequestSource(requestSourceKey) {
            guard store.allowRelayRequest(sourceKey: requestSourceKey) else {
                return context.eventLoop.makeSucceededFuture(.error("Rate limit exceeded"))
            }
        }
        if requiresAuthentication(for: request.type),
           let authFailure = validateAuthentication(token: request.authToken) {
            return context.eventLoop.makeSucceededFuture(authFailure)
        }
        if relayConfiguration.kind == .coordinator,
           !isCoordinatorDirectoryRequestType(request.type) {
            return context.eventLoop.makeSucceededFuture(
                .error("Coordinator relays are directory-only and do not carry user traffic.")
            )
        }
        switch request.type {
        case .deliver:
            guard let deliver = request.deliver else {
                return context.eventLoop.makeSucceededFuture(.error("Missing deliver payload"))
            }
            let capability = deliver.inboxCapability
            if let capability {
                guard relayConfiguration.opaqueRouteCapabilitiesEnabled else {
                    return context.eventLoop.makeSucceededFuture(
                        .error("Experimental opaque route capabilities are disabled")
                    )
                }
                guard capability.isStructurallyValid,
                      deliver.inboxId == nil,
                      deliver.routingToken == nil else {
                    return context.eventLoop.makeSucceededFuture(
                        .error("Invalid inbox route capability")
                    )
                }
            } else {
                guard let legacyRoutingToken = deliver.routingToken ?? deliver.inboxId,
                      InboxAddress.isValid(legacyRoutingToken) else {
                    return context.eventLoop.makeSucceededFuture(.error("Invalid routing token"))
                }
            }
            if let destination = deliver.destinationRelay,
               destination != localEndpoint {
                let eventLoop = context.eventLoop
                return federationGate(forwardingTo: destination, on: eventLoop).flatMap { response in
                    if let response {
                        return eventLoop.makeSucceededFuture(response)
                    }
                    let forward: DeliverRequest
                    if let capability {
                        forward = DeliverRequest(
                            inboxCapability: capability,
                            envelope: deliver.envelope,
                            destinationRelay: nil
                        )
                    } else {
                        guard let legacyInboxId = deliver.inboxId else {
                            return eventLoop.makeSucceededFuture(.error("Invalid routing token"))
                        }
                        forward = DeliverRequest(
                            inboxId: legacyInboxId,
                            routingToken: deliver.routingToken,
                            envelope: deliver.envelope,
                            destinationRelay: nil
                        )
                    }
                    return self.forwardDeliver(
                        forward,
                        to: destination,
                        on: eventLoop
                    ).recover { _ in
                        .error("Forwarding failed")
                    }
                }.recover { _ in
                    .error("Forwarding failed")
                }
            }
            let routingToken: String
            if let capability {
                guard let resolved = store.resolveInboxRouteCapability(capability) else {
                    return context.eventLoop.makeSucceededFuture(
                        .error("Inbox route capability is unavailable")
                    )
                }
                routingToken = resolved
            } else if let legacyRoutingToken = deliver.routingToken ?? deliver.inboxId {
                routingToken = legacyRoutingToken
            } else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid routing token"))
            }
            do {
                let count = try store.deliver(deliver.envelope, to: routingToken)
                return context.eventLoop.makeSucceededFuture(.delivered(count: count))
            } catch RelayStoreError.inboxFull {
                return context.eventLoop.makeSucceededFuture(.error("Inbox full"))
            } catch RelayStoreError.destinationInboxNotRegistered {
                return context.eventLoop.makeSucceededFuture(.error("Destination inbox is not registered"))
            } catch RelayStoreError.inboxRetired {
                return context.eventLoop.makeSucceededFuture(.error("Destination inbox is retired"))
            } catch RelayStoreError.relayCapacityExceeded {
                return context.eventLoop.makeSucceededFuture(.error("Relay storage capacity reached"))
            } catch RelayStoreError.invalidEnvelopePayload {
                return context.eventLoop.makeSucceededFuture(.error("Invalid envelope payload"))
            } catch {
                return context.eventLoop.makeSucceededFuture(.error("Store error"))
            }
        case .registerInbox:
            guard let registration = request.registerInbox else {
                return context.eventLoop.makeSucceededFuture(.error("Missing inbox registration payload"))
            }
            guard InboxAddress.isValid(registration.inboxId),
                  !registration.accessPublicKey.isEmpty,
                  InboxAddress.isBound(registration.inboxId, to: registration.accessPublicKey) else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid inbox registration"))
            }
            guard registration.registrationVersion == RegisterInboxRequest.privacyMinimizedVersion else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Unsupported inbox registration version")
                )
            }
            let accessFingerprint = Data(SHA256.hash(data: registration.accessPublicKey)).base64EncodedString()
            if let proofFailure = validateActorProof(
                registration.accessProof,
                expectedFingerprint: accessFingerprint,
                expectedSigningKey: registration.accessPublicKey,
                signableDataBuilder: { proof in try registration.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            do {
                let receipt = try store.registerInbox(
                    inboxId: registration.inboxId,
                    accessPublicKey: registration.accessPublicKey
                )
                return context.eventLoop.makeSucceededFuture(
                    .ok(
                        inboxRegistration: relayConfiguration.opaqueRouteCapabilitiesEnabled
                            ? receipt
                            : nil
                    )
                )
            } catch RelayStoreError.inboxAlreadyRegistered {
                return context.eventLoop.makeSucceededFuture(
                    .error("Inbox is already registered to another access key")
                )
            } catch RelayStoreError.inboxRetired {
                return context.eventLoop.makeSucceededFuture(.error("Inbox is retired"))
            } catch RelayStoreError.relayCapacityExceeded {
                return context.eventLoop.makeSucceededFuture(.error("Relay storage capacity reached"))
            } catch {
                return context.eventLoop.makeSucceededFuture(.error("Invalid inbox registration"))
            }
        case .retireInbox:
            guard let retirement = request.retireInbox,
                  InboxAddress.isValid(retirement.inboxId),
                  let requestDigest = try? retirement.requestDigest() else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Invalid inbox retirement request")
                )
            }
            if store.isInboxRetired(inboxId: retirement.inboxId) {
                guard store.isMatchingInboxRetirement(
                    inboxId: retirement.inboxId,
                    requestDigest: requestDigest
                ) else {
                    return context.eventLoop.makeSucceededFuture(
                        .error("Inbox retirement request does not match tombstone")
                    )
                }
                return context.eventLoop.makeSucceededFuture(.ok())
            }
            let accessPublicKey = store.inboxAccessPublicKey(for: retirement.inboxId)
            guard let proofSigningKey = retirement.accessProof?.publicSigningKey else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Missing inbox retirement proof.")
                )
            }
            if let proofFailure = validateInboxRetirementProof(
                retirement.accessProof,
                inboxId: retirement.inboxId,
                expectedSigningKey: accessPublicKey ?? proofSigningKey,
                signableDataBuilder: { proof in try retirement.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            do {
                // Record non-resurrection even when no live registration is
                // present; the self-bound proof is sufficient authority.
                try store.retireInbox(
                    inboxId: retirement.inboxId,
                    requestDigest: requestDigest
                )
                return context.eventLoop.makeSucceededFuture(.ok())
            } catch RelayStoreError.invalidInboxRetirement {
                return context.eventLoop.makeSucceededFuture(
                    .error("Inbox retirement request does not match tombstone")
                )
            } catch RelayStoreError.relayCapacityExceeded {
                return context.eventLoop.makeSucceededFuture(
                    .error("Relay lifetime inbox capacity reached")
                )
            } catch {
                return context.eventLoop.makeSucceededFuture(
                    .error("Relay storage is unavailable")
                )
            }
        case .createInboxRouteCapability:
            guard relayConfiguration.opaqueRouteCapabilitiesEnabled else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Experimental opaque route capabilities are disabled")
                )
            }
            guard let mutation = request.createInboxRouteCapability,
                  InboxAddress.isValid(mutation.inboxId),
                  mutation.capability.isStructurallyValid,
                  mutation.relayScope.isValidRouteMutationScope,
                  mutation.mutationSequence > 0,
                  mutation.mutationSequence <= CreateInboxRouteCapabilityRequest.maximumMutationSequence else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Invalid inbox route capability request")
                )
            }
            guard let accessPublicKey = store.inboxAccessPublicKey(for: mutation.inboxId) else {
                return context.eventLoop.makeSucceededFuture(.error("Inbox is not registered"))
            }
            guard let mutationDigest = try? mutation.mutationDigest() else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Invalid inbox route capability request")
                )
            }
            let isCurrentReplay = store.isCurrentInboxRouteCapabilityMutation(
                inboxId: mutation.inboxId,
                relayScope: mutation.relayScope,
                mutationSequence: mutation.mutationSequence,
                mutationDigest: mutationDigest
            )
            let accessFingerprint = Data(SHA256.hash(data: accessPublicKey)).base64EncodedString()
            if let proofFailure = validateActorProofCryptographically(
                mutation.authorityProof,
                expectedFingerprint: accessFingerprint,
                expectedSigningKey: accessPublicKey,
                enforceFreshness: !isCurrentReplay,
                signableDataBuilder: { proof in try mutation.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            do {
                _ = try store.applyInboxRouteCapabilityMutation(
                    operation: .create,
                    inboxId: mutation.inboxId,
                    capability: mutation.capability,
                    relayScope: mutation.relayScope,
                    mutationSequence: mutation.mutationSequence,
                    mutationDigest: mutationDigest
                )
                return context.eventLoop.makeSucceededFuture(.ok())
            } catch RelayStoreError.inboxRouteCapabilityRevoked {
                return context.eventLoop.makeSucceededFuture(.error("Inbox route capability is revoked"))
            } catch RelayStoreError.inboxRouteCapabilityLimitReached {
                return context.eventLoop.makeSucceededFuture(.error("Inbox route capability limit reached"))
            } catch RelayStoreError.relayCapacityExceeded {
                return context.eventLoop.makeSucceededFuture(.error("Relay route capability capacity reached"))
            } catch RelayStoreError.inboxRetired {
                return context.eventLoop.makeSucceededFuture(.error("Inbox is retired"))
            } catch RelayStoreError.invalidInboxRouteCapabilityMutation {
                return context.eventLoop.makeSucceededFuture(.error("Inbox route capability relay scope mismatch"))
            } catch RelayStoreError.inboxRouteCapabilityMutationConflict {
                return context.eventLoop.makeSucceededFuture(.error("Inbox route capability mutation sequence conflict"))
            } catch RelayStoreError.inboxRouteCapabilityMutationOutOfOrder {
                return context.eventLoop.makeSucceededFuture(.error("Inbox route capability mutation is out of order"))
            } catch RelayStoreError.destinationInboxNotRegistered {
                return context.eventLoop.makeSucceededFuture(.error("Inbox is not registered"))
            } catch {
                return context.eventLoop.makeSucceededFuture(
                    .error("Relay storage is unavailable")
                )
            }
        case .revokeInboxRouteCapability:
            guard relayConfiguration.opaqueRouteCapabilitiesEnabled else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Experimental opaque route capabilities are disabled")
                )
            }
            guard let mutation = request.revokeInboxRouteCapability,
                  InboxAddress.isValid(mutation.inboxId),
                  mutation.capability.isStructurallyValid,
                  mutation.relayScope.isValidRouteMutationScope,
                  mutation.mutationSequence > 0,
                  mutation.mutationSequence <= CreateInboxRouteCapabilityRequest.maximumMutationSequence else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Invalid inbox route capability request")
                )
            }
            guard let accessPublicKey = store.inboxAccessPublicKey(for: mutation.inboxId) else {
                return context.eventLoop.makeSucceededFuture(.error("Inbox is not registered"))
            }
            guard let mutationDigest = try? mutation.mutationDigest() else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Invalid inbox route capability request")
                )
            }
            let isCurrentReplay = store.isCurrentInboxRouteCapabilityMutation(
                inboxId: mutation.inboxId,
                relayScope: mutation.relayScope,
                mutationSequence: mutation.mutationSequence,
                mutationDigest: mutationDigest
            )
            let accessFingerprint = Data(SHA256.hash(data: accessPublicKey)).base64EncodedString()
            if let proofFailure = validateActorProofCryptographically(
                mutation.authorityProof,
                expectedFingerprint: accessFingerprint,
                expectedSigningKey: accessPublicKey,
                enforceFreshness: !isCurrentReplay,
                signableDataBuilder: { proof in try mutation.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            do {
                _ = try store.applyInboxRouteCapabilityMutation(
                    operation: .revoke,
                    inboxId: mutation.inboxId,
                    capability: mutation.capability,
                    relayScope: mutation.relayScope,
                    mutationSequence: mutation.mutationSequence,
                    mutationDigest: mutationDigest
                )
                return context.eventLoop.makeSucceededFuture(.ok())
            } catch RelayStoreError.relayCapacityExceeded {
                return context.eventLoop.makeSucceededFuture(.error("Relay route capability capacity reached"))
            } catch RelayStoreError.inboxRetired {
                return context.eventLoop.makeSucceededFuture(.error("Inbox is retired"))
            } catch RelayStoreError.invalidInboxRouteCapabilityMutation {
                return context.eventLoop.makeSucceededFuture(.error("Inbox route capability relay scope mismatch"))
            } catch RelayStoreError.inboxRouteCapabilityMutationConflict {
                return context.eventLoop.makeSucceededFuture(.error("Inbox route capability mutation sequence conflict"))
            } catch RelayStoreError.inboxRouteCapabilityMutationOutOfOrder {
                return context.eventLoop.makeSucceededFuture(.error("Inbox route capability mutation is out of order"))
            } catch RelayStoreError.destinationInboxNotRegistered {
                return context.eventLoop.makeSucceededFuture(.error("Inbox is not registered"))
            } catch {
                return context.eventLoop.makeSucceededFuture(
                    .error("Relay storage is unavailable")
                )
            }
        case .createOpaqueRouteV2:
            guard relayConfiguration.opaqueRouteCapabilitiesEnabled else {
                return context.eventLoop.makeSucceededFuture(.error("Opaque route runtime is disabled"))
            }
            let confidentialTransport = relayConfiguration.tlsEnabled == true
                || isLoopbackRequestSource(requestSourceKey)
            guard confidentialTransport else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Opaque route runtime requires confidential transport")
                )
            }
            guard let submission = request.createOpaqueRouteV2,
                  submission.isStructurallyValid else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid opaque route request"))
            }
            do {
                return context.eventLoop.makeSucceededFuture(
                    .opaqueRouteV2(try store.createOpaqueRouteV2(
                        submission,
                        confidentialTransport: confidentialTransport
                    ))
                )
            } catch {
                return context.eventLoop.makeSucceededFuture(opaqueRouteErrorResponse(error))
            }
        case .renewOpaqueRouteV2:
            guard relayConfiguration.opaqueRouteCapabilitiesEnabled else {
                return context.eventLoop.makeSucceededFuture(.error("Opaque route runtime is disabled"))
            }
            let confidentialTransport = relayConfiguration.tlsEnabled == true
                || isLoopbackRequestSource(requestSourceKey)
            guard confidentialTransport else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Opaque route runtime requires confidential transport")
                )
            }
            guard let submission = request.renewOpaqueRouteV2,
                  submission.isStructurallyValid else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid opaque route request"))
            }
            do {
                return context.eventLoop.makeSucceededFuture(
                    .opaqueRouteV2(try store.renewOpaqueRouteV2(
                        submission,
                        confidentialTransport: confidentialTransport
                    ))
                )
            } catch {
                return context.eventLoop.makeSucceededFuture(opaqueRouteErrorResponse(error))
            }
        case .teardownOpaqueRouteV2:
            guard relayConfiguration.opaqueRouteCapabilitiesEnabled else {
                return context.eventLoop.makeSucceededFuture(.error("Opaque route runtime is disabled"))
            }
            let confidentialTransport = relayConfiguration.tlsEnabled == true
                || isLoopbackRequestSource(requestSourceKey)
            guard confidentialTransport else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Opaque route runtime requires confidential transport")
                )
            }
            guard let submission = request.teardownOpaqueRouteV2,
                  submission.isStructurallyValid else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid opaque route request"))
            }
            do {
                return context.eventLoop.makeSucceededFuture(
                    .opaqueRouteV2(try store.teardownOpaqueRouteV2(
                        submission,
                        confidentialTransport: confidentialTransport
                    ))
                )
            } catch {
                return context.eventLoop.makeSucceededFuture(opaqueRouteErrorResponse(error))
            }
        case .appendOpaqueRouteV2:
            guard relayConfiguration.opaqueRouteCapabilitiesEnabled else {
                return context.eventLoop.makeSucceededFuture(.error("Opaque route runtime is disabled"))
            }
            let confidentialTransport = relayConfiguration.tlsEnabled == true
                || isLoopbackRequestSource(requestSourceKey)
            guard confidentialTransport else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Opaque route runtime requires confidential transport")
                )
            }
            guard let submission = request.appendOpaqueRouteV2,
                  submission.isStructurallyValid else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid opaque route request"))
            }
            do {
                return context.eventLoop.makeSucceededFuture(
                    .opaqueRouteAppendV2(try store.appendOpaqueRouteV2(
                        submission,
                        confidentialTransport: confidentialTransport
                    ))
                )
            } catch {
                return context.eventLoop.makeSucceededFuture(opaqueRouteErrorResponse(error))
            }
        case .syncOpaqueRouteV2:
            guard relayConfiguration.opaqueRouteCapabilitiesEnabled else {
                return context.eventLoop.makeSucceededFuture(.error("Opaque route runtime is disabled"))
            }
            let confidentialTransport = relayConfiguration.tlsEnabled == true
                || isLoopbackRequestSource(requestSourceKey)
            guard confidentialTransport else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Opaque route runtime requires confidential transport")
                )
            }
            guard let submission = request.syncOpaqueRouteV2,
                  submission.isStructurallyValid else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid opaque route request"))
            }
            do {
                return context.eventLoop.makeSucceededFuture(
                    .opaqueRouteSyncV2(try store.syncOpaqueRouteV2(
                        submission,
                        confidentialTransport: confidentialTransport
                    ))
                )
            } catch {
                return context.eventLoop.makeSucceededFuture(opaqueRouteErrorResponse(error))
            }
        case .commitOpaqueRouteV2:
            guard relayConfiguration.opaqueRouteCapabilitiesEnabled else {
                return context.eventLoop.makeSucceededFuture(.error("Opaque route runtime is disabled"))
            }
            let confidentialTransport = relayConfiguration.tlsEnabled == true
                || isLoopbackRequestSource(requestSourceKey)
            guard confidentialTransport else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Opaque route runtime requires confidential transport")
                )
            }
            guard let submission = request.commitOpaqueRouteV2,
                  submission.isStructurallyValid else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid opaque route request"))
            }
            do {
                return context.eventLoop.makeSucceededFuture(
                    .opaqueRouteCommitV2(try store.commitOpaqueRouteV2(
                        submission,
                        confidentialTransport: confidentialTransport
                    ))
                )
            } catch {
                return context.eventLoop.makeSucceededFuture(opaqueRouteErrorResponse(error))
            }
        case .registerRendezvousTransportV2:
            guard relayConfiguration.isRendezvousTransportEnabled else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Rendezvous transport is disabled")
                )
            }
            guard relayConfiguration.tlsEnabled == true
                    || isLoopbackRequestSource(requestSourceKey) else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Rendezvous transport requires confidential transport")
                )
            }
            guard let registration = request.registerRendezvousTransportV2,
                  registration.isStructurallyValid() else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Invalid rendezvous transport request")
                )
            }
            do {
                try store.registerRendezvousTransportV2(registration)
                return context.eventLoop.makeSucceededFuture(.ok())
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error))
            }
        case .appendRendezvousTransportV2:
            guard relayConfiguration.isRendezvousTransportEnabled else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Rendezvous transport is disabled")
                )
            }
            guard relayConfiguration.tlsEnabled == true
                    || isLoopbackRequestSource(requestSourceKey) else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Rendezvous transport requires confidential transport")
                )
            }
            guard let append = request.appendRendezvousTransportV2,
                  append.isStructurallyValid else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Invalid rendezvous transport request")
                )
            }
            do {
                _ = try store.appendRendezvousTransportV2(append)
                return context.eventLoop.makeSucceededFuture(.ok())
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error))
            }
        case .syncRendezvousTransportV2:
            guard relayConfiguration.isRendezvousTransportEnabled else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Rendezvous transport is disabled")
                )
            }
            guard relayConfiguration.tlsEnabled == true
                    || isLoopbackRequestSource(requestSourceKey) else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Rendezvous transport requires confidential transport")
                )
            }
            guard let sync = request.syncRendezvousTransportV2,
                  sync.isStructurallyValid else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Invalid rendezvous transport request")
                )
            }
            do {
                return context.eventLoop.makeSucceededFuture(
                    .rendezvousSyncV2(try store.syncRendezvousTransportV2(sync))
                )
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error))
            }
        case .deleteRendezvousTransportV2:
            guard relayConfiguration.isRendezvousTransportEnabled else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Rendezvous transport is disabled")
                )
            }
            guard relayConfiguration.tlsEnabled == true
                    || isLoopbackRequestSource(requestSourceKey) else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Rendezvous transport requires confidential transport")
                )
            }
            guard let deletion = request.deleteRendezvousTransportV2,
                  deletion.isStructurallyValid else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Invalid rendezvous transport request")
                )
            }
            do {
                try store.deleteRendezvousTransportV2(deletion)
                return context.eventLoop.makeSucceededFuture(.ok())
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error))
            }
        case .fetch:
            guard let fetch = request.fetch else {
                return context.eventLoop.makeSucceededFuture(.error("Missing fetch payload"))
            }
            let routingToken = fetch.routingToken ?? fetch.inboxId
            guard InboxAddress.isValid(routingToken) else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid routing token"))
            }
            guard !store.hasMailboxConsumerBindings(inboxId: routingToken) else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Legacy mailbox fetch is disabled for endpoint-managed inboxes")
                )
            }
            if relayConfiguration.requireInboxAccessControl != false {
                guard let accessPublicKey = store.inboxAccessPublicKey(for: routingToken) else {
                    return context.eventLoop.makeSucceededFuture(.error("Inbox is not registered"))
                }
                let accessFingerprint = Data(SHA256.hash(data: accessPublicKey)).base64EncodedString()
                if let proofFailure = validateActorProof(
                    fetch.accessProof,
                    expectedFingerprint: accessFingerprint,
                    expectedSigningKey: accessPublicKey,
                    signableDataBuilder: { proof in try fetch.signableData(for: proof) }
                ) {
                    return context.eventLoop.makeSucceededFuture(proofFailure)
                }
            }
            return fetchWithOptionalLongPoll(fetch, routingToken: routingToken, on: context.eventLoop)
                .map { RelayResponse.messages($0) }
        case .registerMailboxConsumer:
            guard let registration = request.registerMailboxConsumer,
                  InboxAddress.isValid(registration.inboxId),
                  registration.consumerId.isStructurallyValid,
                  registration.sponsorConsumerId?.isStructurallyValid ?? true,
                  registration.consumerSigningPublicKey.count
                    == OQSSignatureVerifier.mlDSA65PublicKeyBytes else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Invalid mailbox consumer registration")
                )
            }
            guard !store.isInboxRetired(inboxId: registration.inboxId) else {
                return context.eventLoop.makeSucceededFuture(.error("Inbox is retired"))
            }
            guard let accessPublicKey = store.inboxAccessPublicKey(for: registration.inboxId) else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Invalid mailbox consumer registration")
                )
            }
            let accessFingerprint = Data(SHA256.hash(data: accessPublicKey)).base64EncodedString()
            if let proofFailure = validateActorProof(
                registration.authorityProof,
                expectedFingerprint: accessFingerprint,
                expectedSigningKey: accessPublicKey,
                signableDataBuilder: { proof in try registration.authoritySignableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            let consumerFingerprint = Data(
                SHA256.hash(data: registration.consumerSigningPublicKey)
            ).base64EncodedString()
            if let proofFailure = validateActorProof(
                registration.consumerProof,
                expectedFingerprint: consumerFingerprint,
                expectedSigningKey: registration.consumerSigningPublicKey,
                signableDataBuilder: { proof in try registration.consumerSignableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            let existingConsumer = store.mailboxConsumer(
                inboxId: registration.inboxId,
                consumerId: registration.consumerId
            )
            let activeBoundConsumers = store.mailboxConsumers(inboxId: registration.inboxId)
                .filter {
                    $0.state == .active
                        && $0.consumerSigningPublicKey.count
                            == OQSSignatureVerifier.mlDSA65PublicKeyBytes
                }
            let isManaged = store.hasMailboxConsumerBindings(inboxId: registration.inboxId)
            let requiresSponsor = existingConsumer == nil && isManaged
            if existingConsumer == nil {
                guard !isManaged || !activeBoundConsumers.isEmpty else {
                    return context.eventLoop.makeSucceededFuture(
                        mailboxSyncErrorResponse(MailboxSyncError.freshInboxRequired)
                    )
                }
            }
            if requiresSponsor {
                guard let sponsorConsumerId = registration.sponsorConsumerId,
                      sponsorConsumerId != registration.consumerId,
                      let sponsorSigningPublicKey = store.activeMailboxConsumerSigningPublicKey(
                        inboxId: registration.inboxId,
                        consumerId: sponsorConsumerId
                      ) else {
                    return context.eventLoop.makeSucceededFuture(
                        mailboxSyncErrorResponse(MailboxSyncError.consumerSponsorRequired)
                    )
                }
                let sponsorFingerprint = Data(
                    SHA256.hash(data: sponsorSigningPublicKey)
                ).base64EncodedString()
                if let proofFailure = validateActorProof(
                    registration.sponsorProof,
                    expectedFingerprint: sponsorFingerprint,
                    expectedSigningKey: sponsorSigningPublicKey,
                    signableDataBuilder: { proof in try registration.sponsorSignableData(for: proof) }
                ) {
                    return context.eventLoop.makeSucceededFuture(proofFailure)
                }
            }
            do {
                return context.eventLoop.makeSucceededFuture(
                    .mailboxConsumer(
                        try store.registerMailboxConsumer(
                            inboxId: registration.inboxId,
                            consumerId: registration.consumerId,
                            consumerSigningPublicKey: registration.consumerSigningPublicKey,
                            sponsorConsumerId: registration.sponsorConsumerId,
                            startingSequence: registration.startingSequence
                        )
                    )
                )
            } catch {
                return context.eventLoop.makeSucceededFuture(mailboxSyncErrorResponse(error))
            }
        case .syncMailbox:
            guard let sync = request.syncMailbox,
                  InboxAddress.isValid(sync.inboxId),
                  sync.consumerId.isStructurallyValid,
                  sync.cursor?.isStructurallyValid ?? true,
                  (sync.maxCount ?? 100) > 0,
                  (sync.maxCount ?? 100) <= 256,
                  let consumerSigningPublicKey = store.mailboxConsumerSigningPublicKey(
                    inboxId: sync.inboxId,
                    consumerId: sync.consumerId
                  ) else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid mailbox sync request"))
            }
            let consumerFingerprint = Data(
                SHA256.hash(data: consumerSigningPublicKey)
            ).base64EncodedString()
            if let proofFailure = validateActorProof(
                sync.consumerProof,
                expectedFingerprint: consumerFingerprint,
                expectedSigningKey: consumerSigningPublicKey,
                signableDataBuilder: { proof in try sync.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            return syncMailboxWithOptionalLongPoll(sync, on: context.eventLoop)
                .map { RelayResponse.mailboxSync($0) }
                .recover { self.mailboxSyncErrorResponse($0) }
        case .commitMailboxCursor:
            guard let commit = request.commitMailboxCursor,
                  InboxAddress.isValid(commit.inboxId),
                  commit.consumerId.isStructurallyValid,
                  commit.cursor.isStructurallyValid,
                  let consumerSigningPublicKey = store.mailboxConsumerSigningPublicKey(
                    inboxId: commit.inboxId,
                    consumerId: commit.consumerId
                  ) else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid mailbox cursor commit"))
            }
            let consumerFingerprint = Data(
                SHA256.hash(data: consumerSigningPublicKey)
            ).base64EncodedString()
            if let proofFailure = validateActorProof(
                commit.consumerProof,
                expectedFingerprint: consumerFingerprint,
                expectedSigningKey: consumerSigningPublicKey,
                signableDataBuilder: { proof in try commit.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            do {
                return context.eventLoop.makeSucceededFuture(
                    .mailboxConsumer(
                        try store.commitMailboxCursor(
                            inboxId: commit.inboxId,
                            consumerId: commit.consumerId,
                            cursor: commit.cursor,
                            sequence: commit.sequence
                        )
                    )
                )
            } catch {
                return context.eventLoop.makeSucceededFuture(mailboxSyncErrorResponse(error))
            }
        case .revokeMailboxConsumer:
            guard let revocation = request.revokeMailboxConsumer,
                  InboxAddress.isValid(revocation.inboxId),
                  revocation.consumerId.isStructurallyValid,
                  let accessPublicKey = store.inboxAccessPublicKey(for: revocation.inboxId) else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Invalid mailbox consumer revocation")
                )
            }
            let accessFingerprint = Data(SHA256.hash(data: accessPublicKey)).base64EncodedString()
            if let proofFailure = validateActorProof(
                revocation.authorityProof,
                expectedFingerprint: accessFingerprint,
                expectedSigningKey: accessPublicKey,
                signableDataBuilder: { proof in try revocation.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            do {
                return context.eventLoop.makeSucceededFuture(
                    .mailboxConsumer(
                        try store.revokeMailboxConsumer(
                            inboxId: revocation.inboxId,
                            consumerId: revocation.consumerId
                        )
                    )
                )
            } catch {
                return context.eventLoop.makeSucceededFuture(mailboxSyncErrorResponse(error))
            }
        case .health:
            return context.eventLoop.makeSucceededFuture(.ok())
        case .info:
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
                    wakeSupport: info.wakeSupport,
                    relayName: info.relayName,
                    operatorNote: info.operatorNote,
                    softwareVersion: info.softwareVersion,
                    groupCreationMode: info.groupCreationMode,
                    groupSecurityModel: info.groupSecurityModel,
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
                        groupCreationMode: info.groupCreationMode,
                        groupSecurityModel: info.groupSecurityModel,
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
            return context.eventLoop.makeSucceededFuture(.info(info))
        case .uploadAttachment:
            guard relayConfiguration.attachmentsEnabled != false else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Attachments are disabled on this relay")
                )
            }
            guard let upload = request.uploadAttachment else {
                return context.eventLoop.makeSucceededFuture(.error("Missing upload attachment payload"))
            }
            let boundedTTL = boundedAttachmentTTL(requested: upload.ttlSeconds)
            do {
                let chunk = try store.storeAttachment(
                    attachmentId: upload.attachmentId,
                    chunkIndex: upload.chunkIndex,
                    payload: upload.payload,
                    ttlSeconds: boundedTTL
                )
                return context.eventLoop.makeSucceededFuture(.attachment(chunk))
            } catch RelayStoreError.invalidChunkIndex {
                return context.eventLoop.makeSucceededFuture(.error("Invalid chunk index"))
            } catch RelayStoreError.invalidAttachmentPayload {
                return context.eventLoop.makeSucceededFuture(.error("Invalid attachment payload"))
            } catch RelayStoreError.attachmentBlobUnavailable {
                return context.eventLoop.makeSucceededFuture(.error("Attachment blob backend unavailable"))
            } catch {
                return context.eventLoop.makeSucceededFuture(.error("Attachment store error"))
            }
        case .fetchAttachment:
            guard relayConfiguration.attachmentsEnabled != false else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Attachments are disabled on this relay")
                )
            }
            guard let fetch = request.fetchAttachment else {
                return context.eventLoop.makeSucceededFuture(.error("Missing fetch attachment payload"))
            }
            do {
                if let chunk = try store.fetchAttachment(
                    attachmentId: fetch.attachmentId,
                    chunkIndex: fetch.chunkIndex
                ) {
                    return context.eventLoop.makeSucceededFuture(.attachment(chunk))
                }
                return context.eventLoop.makeSucceededFuture(.error("Attachment not found"))
            } catch RelayStoreError.invalidChunkIndex {
                return context.eventLoop.makeSucceededFuture(.error("Invalid chunk index"))
            } catch RelayStoreError.attachmentBlobUnavailable {
                return context.eventLoop.makeSucceededFuture(.error("Attachment blob backend unavailable"))
            } catch {
                return context.eventLoop.makeSucceededFuture(.error("Attachment store error"))
            }
        case .registerFederationNode:
            guard relayConfiguration.kind == .coordinator else {
                return context.eventLoop.makeSucceededFuture(.error("This relay is not a coordinator node."))
            }
            if let authFailure = validateCoordinatorRegistrationAuthentication(token: request.authToken) {
                return context.eventLoop.makeSucceededFuture(authFailure)
            }
            guard let registration = request.registerFederationNode else {
                return context.eventLoop.makeSucceededFuture(.error("Missing federation registration payload"))
            }
            let sourceKey = sourceKey(for: context.channel.remoteAddress)
            let allowed = store.allowFederationRegistration(sourceKey: sourceKey, endpoint: registration.endpoint)
            guard allowed else {
                return context.eventLoop.makeSucceededFuture(.error("Coordinator registration throttled. Retry later."))
            }
            let eventLoop = context.eventLoop
            return validateFederationRegistrationReachability(registration, on: eventLoop).flatMap { failure in
                if let failure {
                    return eventLoop.makeSucceededFuture(failure)
                }
                do {
                    let node = try self.store.registerFederationNode(registration)
                    return eventLoop.makeSucceededFuture(.federationNodes([node]))
                } catch {
                    return eventLoop.makeSucceededFuture(.error("Coordinator registration failed"))
                }
            }
        case .listFederationNodes:
            let listRequest = request.listFederationNodes ?? ListFederationNodesRequest()
            if relayConfiguration.kind == .coordinator {
                let sourceKey = sourceKey(for: context.channel.remoteAddress)
                let allowed = store.allowFederationDirectoryList(sourceKey: sourceKey)
                guard allowed else {
                    return context.eventLoop.makeSucceededFuture(.error("Coordinator directory listing throttled. Retry later."))
                }
                let nodes = store.listFederationNodes(listRequest)
                let snapshot = makeCoordinatorDirectorySnapshot(nodes: nodes, request: listRequest)
                if listRequest.requireSignedSnapshot == true, snapshot == nil {
                    return context.eventLoop.makeSucceededFuture(.error("Coordinator snapshot signing is not available."))
                }
                return context.eventLoop.makeSucceededFuture(.federationNodes(nodes, snapshot: snapshot))
            }
            return fetchCoordinatorNodeDirectory(request: listRequest, on: context.eventLoop)
                .map { .federationNodes($0) }
        case .publishOpenFederationDHTRecord:
            guard let dhtConfiguration = openFederationDHTConfiguration() else {
                return context.eventLoop.makeSucceededFuture(.error("Open-federation DHT is available only on open non-coordinator relays."))
            }
            guard let publish = request.publishOpenFederationDHTRecord else {
                return context.eventLoop.makeSucceededFuture(.error("Missing open-federation DHT record payload"))
            }
            let expectedNamespace = OpenFederationDHTRecord.namespace(federationName: dhtConfiguration.federationName)
            guard publish.namespace == expectedNamespace else {
                return context.eventLoop.makeSucceededFuture(.error("Open-federation DHT namespace mismatch."))
            }
            let result = store.ingestOpenFederationDHTRecords(
                [publish.record],
                configuration: dhtConfiguration
            )
            guard !result.accepted.isEmpty else {
                let reason = result.rejected.first.map { "\($0.reason)" } ?? "record rejected"
                return context.eventLoop.makeSucceededFuture(.error("Open-federation DHT record rejected: \(reason)"))
            }
            return context.eventLoop.makeSucceededFuture(.ok())
        case .listOpenFederationDHTRecords:
            guard let dhtConfiguration = openFederationDHTConfiguration() else {
                return context.eventLoop.makeSucceededFuture(.error("Open-federation DHT is available only on open non-coordinator relays."))
            }
            guard let list = request.listOpenFederationDHTRecords else {
                return context.eventLoop.makeSucceededFuture(.error("Missing open-federation DHT list payload"))
            }
            let expectedNamespace = OpenFederationDHTRecord.namespace(federationName: dhtConfiguration.federationName)
            guard list.namespace == expectedNamespace else {
                return context.eventLoop.makeSucceededFuture(.error("Open-federation DHT namespace mismatch."))
            }
            let records = store.listOpenFederationDHTRecords(
                configuration: dhtConfiguration,
                limit: list.limit
            )
            return context.eventLoop.makeSucceededFuture(.openFederationDHTRecords(records))
        }
    }

    private func relayStoreErrorResponse(_ error: Error) -> RelayResponse {
        switch error {
        case RelayStoreError.inboxFull:
            return .error("Inbox full")
        case RelayStoreError.relayCapacityExceeded:
            return .error("Relay storage capacity reached")
        case RelayStoreError.destinationInboxNotRegistered:
            return .error("Destination inbox is not registered")
        case RelayStoreError.inboxRetired:
            return .error("Inbox is retired")
        case RelayStoreError.invalidRendezvousRoute:
            return .error("Invalid rendezvous transport request")
        case RelayStoreError.rendezvousRouteUnavailable:
            return .error("Rendezvous route is unavailable")
        case RelayStoreError.rendezvousRegistrationConflict:
            return .error("Rendezvous route registration conflicts with stored state")
        case RelayStoreError.rendezvousCapacityReached:
            return .error("Rendezvous transport capacity reached")
        case RelayStoreError.rendezvousFrameConflict:
            return .error("Rendezvous frame conflicts with stored state")
        case RelayStoreError.rendezvousSequenceGap:
            return .error("Rendezvous lane sequence is not contiguous")
        case RelayStoreError.rendezvousQuotaReached:
            return .error("Rendezvous lane quota reached")
        case RelayStoreError.invalidInboxRetirement:
            return .error("Invalid inbox retirement")
        case RelayStoreError.invalidEnvelopePayload:
            return .error("Invalid envelope payload")
        case RelayStoreError.invalidChunkIndex:
            return .error("Invalid chunk index")
        case RelayStoreError.invalidAttachmentPayload:
            return .error("Invalid attachment payload")
        case RelayStoreError.attachmentBlobUnavailable:
            return .error("Attachment blob backend unavailable")
        default:
            return .error("Store error")
        }
    }

    private func opaqueRouteErrorResponse(_ error: Error) -> RelayResponse {
        switch error {
        case OpaqueRouteRelayStoreV2Error.routeNotFound:
            return .error("Opaque route not found")
        case OpaqueRouteRelayStoreV2Error.invalidCursor:
            return .error("Invalid opaque route cursor")
        case OpaqueRouteRelayStoreV2Error.cursorExpired:
            return .error("Opaque route cursor expired")
        case OpaqueRouteRelayStoreV2Error.cursorAheadOfRoute:
            return .error("Opaque route cursor is ahead of the route")
        case OpaqueRouteRelayStoreV2Error.packetIdentifierConflict:
            return .error("Opaque route packet identifier conflict")
        case OpaqueRouteRelayStoreV2Error.requestIdentifierConflict:
            return .error("Opaque route request identifier conflict")
        case OpaqueRouteRelayStoreV2Error.routeQuotaExceeded:
            return .error("Opaque route quota exceeded")
        case OpaqueRouteRelayStoreV2Error.packetIdentifierLedgerExhausted,
             OpaqueRouteRelayStoreV2Error.requestReceiptLedgerExhausted,
             OpaqueRouteRelayStoreV2Error.sequenceExhausted,
             OpaqueRouteRelayStoreV2Error.routeCapacityExceeded:
            return .error("Opaque route capacity reached")
        case OpaqueRouteV2Error.confidentialTransportRequired:
            return .error("Opaque route runtime requires confidential transport")
        case OpaqueRouteV2Error.invalidAuthorization,
             OpaqueRouteV2Error.authorizationExpired,
             OpaqueRouteV2Error.authorizationReplay:
            return .error("Opaque route authorization rejected")
        case OpaqueRouteV2Error.routeExpired:
            return .error("Opaque route expired")
        case OpaqueRouteV2Error.routeTornDown:
            return .error("Opaque route is torn down")
        case OpaqueRouteV2Error.idempotencyConflict,
             OpaqueRouteV2Error.routeAlreadyExists,
             OpaqueRouteV2Error.transitionFork:
            return .error("Opaque route state conflict")
        case OpaqueRouteV2Error.staleTransition,
             OpaqueRouteV2Error.transitionOutOfOrder:
            return .error("Opaque route transition order rejected")
        default:
            return .error("Invalid opaque route request")
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

    private func forwardDeliver(
        _ deliver: DeliverRequest,
        to endpoint: RelayEndpoint,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<RelayResponse> {
        sendRequest(
            .deliver(deliver).withAuthToken(relayConfiguration.federationForwardingAuthToken),
            to: endpoint,
            on: eventLoop
        )
    }

    private func federationGate(forwardingTo destination: RelayEndpoint, on eventLoop: EventLoop) -> EventLoopFuture<RelayResponse?> {
        switch relayConfiguration.federation.mode {
        case .solo:
            return eventLoop.makeSucceededFuture(.error("Relay is not configured for federation forwarding."))
        case .manual:
            guard relayConfiguration.federationAllowList.contains(destination) else {
                return eventLoop.makeSucceededFuture(.error("Manual federation: destination relay is not in the node list."))
            }
            return fetchRelayInfo(from: destination, on: eventLoop).map { info in
                guard let info else {
                    return .error("Federation check failed: destination relay did not report its configuration.")
                }
                guard info.federation.mode == .manual else {
                    return .error("Federation mismatch: destination relay is not manual.")
                }
                guard info.kind == .standard else {
                    return .error("Manual federation requires destination relay kind standard.")
                }
                if let name = self.relayConfiguration.federation.name,
                   !name.isEmpty,
                   info.federation.name != name {
                    return .error("Federation mismatch: destination relay name differs.")
                }
                return nil
            }
        case .open:
            if !relayConfiguration.federationAllowList.isEmpty {
                return eventLoop.makeSucceededFuture(.error("Open federation cannot use an allow list."))
            }
            guard relayConfiguration.allowPrivateFederationEndpoints
                    || (destination.useTLS && PublicRelayEndpointPolicy.permits(destination)) else {
                return eventLoop.makeSucceededFuture(
                    .error("Open federation destination must use TLS and be publicly routable.")
                )
            }
            return fetchRelayInfo(from: destination, on: eventLoop).map { info in
                guard let info else {
                    return .error("Federation check failed: destination relay did not report its configuration.")
                }
                guard info.federation.mode == .open else {
                    return .error("Federation mismatch: destination relay is not open.")
                }
                if let name = self.relayConfiguration.federation.name,
                   !name.isEmpty,
                   info.federation.name != name {
                    return .error("Federation mismatch: destination relay name differs.")
                }
                return nil
            }
        case .curated:
            let isInStaticAllowList = relayConfiguration.federationAllowList.contains(destination)
            if relayConfiguration.curatedStrictPolicyEnabled {
                guard !relayConfiguration.federationAllowList.isEmpty else {
                    return eventLoop.makeSucceededFuture(.error("Curated strict policy requires a non-empty allow list."))
                }
                guard isInStaticAllowList else {
                    return eventLoop.makeSucceededFuture(.error("Curated strict policy: destination relay is not in the allow list."))
                }
                guard !coordinatorEndpoints().isEmpty else {
                    return eventLoop.makeSucceededFuture(.error("Curated strict policy requires coordinator endpoints."))
                }
                let quorum = max(1, relayConfiguration.curatedCoordinatorQuorum)
                let request = ListFederationNodesRequest(
                    mode: .curated,
                    federationName: relayConfiguration.federation.name,
                    onlyHealthy: true,
                    maxStalenessSeconds: relayConfiguration.coordinatorDirectoryMaxStalenessSeconds,
                    requireSignedSnapshot: relayConfiguration.curatedRequireSignedDirectory
                )
                return destinationSeenByCoordinatorCount(destination, request: request, on: eventLoop).flatMap { seenBy in
                    guard seenBy >= quorum else {
                        return eventLoop.makeSucceededFuture(
                            .error("Curated strict policy: destination relay quorum not met (\(seenBy)/\(quorum)).")
                        )
                    }
                    return self.fetchRelayInfo(from: destination, on: eventLoop).map { info in
                        guard let info else {
                            return .error("Federation check failed: destination relay did not report its configuration.")
                        }
                        guard info.federation.mode == .curated else {
                            return .error("Federation mismatch: destination relay is not curated.")
                        }
                        if let name = self.relayConfiguration.federation.name,
                           !name.isEmpty,
                           info.federation.name != name {
                            return .error("Federation mismatch: destination relay name differs.")
                        }
                        return nil
                    }
                }
            }
            return isDestinationAllowedByCoordinator(destination, on: eventLoop).flatMap { allowed in
                guard isInStaticAllowList || allowed else {
                    return eventLoop.makeSucceededFuture(.error("Destination relay is not in the federation allow list."))
                }
                return self.fetchRelayInfo(from: destination, on: eventLoop).map { info in
                    guard let info else {
                        return .error("Federation check failed: destination relay did not report its configuration.")
                    }
                    guard info.federation.mode == .curated else {
                        return .error("Federation mismatch: destination relay is not curated.")
                    }
                    if let name = self.relayConfiguration.federation.name,
                       !name.isEmpty,
                       info.federation.name != name {
                        return .error("Federation mismatch: destination relay name differs.")
                    }
                    return nil
                }
            }
        }
    }

    private func fetchRelayInfo(from endpoint: RelayEndpoint, on eventLoop: EventLoop) -> EventLoopFuture<RelayInfo?> {
        sendRequest(.info(), to: endpoint, on: eventLoop).map { response in
            guard response.type == .info else {
                return nil
            }
            return response.relayInfo
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
    ) -> EventLoopFuture<RelayResponse?> {
        guard registration.relayInfo.federation.mode == relayConfiguration.federation.mode else {
            return eventLoop.makeSucceededFuture(
                .error("Coordinator registration rejected: node federation mode differs from coordinator policy.")
            )
        }
        if let coordinatorName = relayConfiguration.federation.name?.trimmingCharacters(in: .whitespacesAndNewlines),
           !coordinatorName.isEmpty,
           registration.relayInfo.federation.name != coordinatorName {
            return eventLoop.makeSucceededFuture(
                .error("Coordinator registration rejected: node federation name differs from coordinator policy.")
            )
        }
        if relayConfiguration.federation.mode == .open,
           !relayConfiguration.allowPrivateFederationEndpoints,
           (!registration.endpoint.useTLS || !PublicRelayEndpointPolicy.permits(registration.endpoint)) {
            return eventLoop.makeSucceededFuture(
                .error("Coordinator registration rejected: open-federation endpoint must use TLS and be publicly routable.")
            )
        }
        return fetchRelayInfo(from: registration.endpoint, on: eventLoop).map { info -> RelayResponse? in
            guard let info else {
                return RelayResponse.error("Coordinator registration rejected: endpoint is unreachable or did not return relay info.")
            }
            guard info.federation.mode == registration.relayInfo.federation.mode else {
                return RelayResponse.error("Coordinator registration rejected: federation mode mismatch.")
            }
            if let expectedName = registration.relayInfo.federation.name?.trimmingCharacters(in: .whitespacesAndNewlines),
               !expectedName.isEmpty,
               info.federation.name != expectedName {
                return RelayResponse.error("Coordinator registration rejected: federation name mismatch.")
            }
            return nil
        }.flatMapError { _ in
            eventLoop.makeSucceededFuture(
                RelayResponse?.some(.error("Coordinator registration rejected: endpoint reachability check failed."))
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
            guard infoResponse.type == .info else {
                return eventLoop.makeSucceededFuture([])
            }
            let advertisedPublicKey = infoResponse.relayInfo?.federationDirectoryPublicKey
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
                guard response.type == .federationNodes else {
                    return []
                }
                if request.requireSignedSnapshot == true, trustedPublicKey == nil {
                    throw FederationDirectoryValidationError.invalidSnapshot
                }
                return try self.validatedCoordinatorNodes(
                    response: response,
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
        response: RelayResponse,
        request: ListFederationNodesRequest,
        trustedPublicKey: Data?
    ) throws -> [FederationNodeRecord] {
        if let snapshot = response.federationSnapshot {
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
                        channel.pipeline.addHandler(ForwardingHandler(requestData: data, promise: promise, completion: completion))
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

    private func validateActorProof(
        _ proof: RelayActorProof?,
        expectedFingerprint: String,
        expectedSigningKey: Data?,
        signableDataBuilder: (RelayActorProof) throws -> Data
    ) -> RelayResponse? {
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
        let consumed: Bool
        do {
            consumed = try store.consumeActorProofNonce(
                fingerprint: proof.fingerprint,
                nonce: proof.nonce,
                now: Date(),
                maxAgeSeconds: RelayActorProof.maximumAgeSeconds
            )
        } catch {
            return .error("Relay storage is unavailable.")
        }
        guard consumed else {
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
        guard !proof.signature.isEmpty else {
            return .error("Actor proof signature is missing.")
        }
        let signableData: Data
        do {
            signableData = try signableDataBuilder(proof)
        } catch {
            return .error("Invalid actor proof payload.")
        }
        if OQSSignatureVerifier.shared.isAvailable {
            guard proof.verify(signableData: signableData) else {
                return .error("Invalid actor proof signature.")
            }
        } else {
            return .error("Actor proof signature verification is unavailable on this relay build.")
        }
        return nil
    }

    /// Retirement is monotonic and irreversible, so the durable request digest
    /// and inbox-key binding are its replay boundary. This proof intentionally
    /// has no freshness window and consumes no actor-proof nonce: a client may
    /// journal it, delete the old private key, and retry after any offline or
    /// relay-persistence failure.
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
        guard !proof.signature.isEmpty else {
            return .error("Inbox retirement proof signature is missing.")
        }
        let signableData: Data
        do {
            signableData = try signableDataBuilder(proof)
        } catch {
            return .error("Invalid inbox retirement proof payload.")
        }
        guard OQSSignatureVerifier.shared.isAvailable else {
            return .error("Actor proof signature verification is unavailable on this relay build.")
        }
        guard proof.verify(signableData: signableData) else {
            return .error("Invalid inbox retirement proof signature.")
        }
        return nil
    }

    private func fetchWithOptionalLongPoll(
        _ fetch: FetchRequest,
        routingToken: String,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<[Envelope]> {
        let messages = store.fetch(inboxId: routingToken, maxCount: fetch.maxCount)
        guard messages.isEmpty,
              let timeout = boundedLongPollTimeoutSeconds(for: fetch) else {
            return eventLoop.makeSucceededFuture(messages)
        }
        let deadline = Date().addingTimeInterval(TimeInterval(timeout))
        return fetchWithLongPollRetry(
            fetch,
            routingToken: routingToken,
            deadline: deadline,
            on: eventLoop
        )
    }

    private func fetchWithLongPollRetry(
        _ fetch: FetchRequest,
        routingToken: String,
        deadline: Date,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<[Envelope]> {
        let remaining = deadline.timeIntervalSinceNow
        guard remaining > 0 else {
            return eventLoop.makeSucceededFuture(
                store.fetch(inboxId: routingToken, maxCount: fetch.maxCount)
            )
        }
        let delayMilliseconds = Int64(max(1, min(250, remaining * 1_000)))
        return eventLoop.scheduleTask(in: .milliseconds(delayMilliseconds)) {
            let messages = self.store.fetch(inboxId: routingToken, maxCount: fetch.maxCount)
            if !messages.isEmpty || Date() >= deadline {
                return eventLoop.makeSucceededFuture(messages)
            }
            return self.fetchWithLongPollRetry(
                fetch,
                routingToken: routingToken,
                deadline: deadline,
                on: eventLoop
            )
        }.futureResult.flatMap { $0 }
    }

    private func syncMailboxWithOptionalLongPoll(
        _ request: SyncMailboxRequest,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<MailboxSyncBatch> {
        let batch: MailboxSyncBatch
        do {
            batch = try store.syncMailbox(
                inboxId: request.inboxId,
                consumerId: request.consumerId,
                cursor: request.cursor,
                maxCount: request.maxCount
            )
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
        guard batch.events.isEmpty,
              let timeout = boundedLongPollTimeoutSeconds(requested: request.longPollTimeoutSeconds) else {
            return eventLoop.makeSucceededFuture(batch)
        }
        return syncMailboxWithLongPollRetry(
            request,
            deadline: Date().addingTimeInterval(TimeInterval(timeout)),
            on: eventLoop
        )
    }

    private func syncMailboxWithLongPollRetry(
        _ request: SyncMailboxRequest,
        deadline: Date,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<MailboxSyncBatch> {
        let remaining = deadline.timeIntervalSinceNow
        guard remaining > 0 else {
            do {
                return eventLoop.makeSucceededFuture(
                    try store.syncMailbox(
                        inboxId: request.inboxId,
                        consumerId: request.consumerId,
                        cursor: request.cursor,
                        maxCount: request.maxCount
                    )
                )
            } catch {
                return eventLoop.makeFailedFuture(error)
            }
        }
        let delayMilliseconds = Int64(max(1, min(250, remaining * 1_000)))
        return eventLoop.scheduleTask(in: .milliseconds(delayMilliseconds)) {
            do {
                let batch = try self.store.syncMailbox(
                    inboxId: request.inboxId,
                    consumerId: request.consumerId,
                    cursor: request.cursor,
                    maxCount: request.maxCount
                )
                if !batch.events.isEmpty || Date() >= deadline {
                    return eventLoop.makeSucceededFuture(batch)
                }
                return self.syncMailboxWithLongPollRetry(
                    request,
                    deadline: deadline,
                    on: eventLoop
                )
            } catch {
                return eventLoop.makeFailedFuture(error)
            }
        }.futureResult.flatMap { $0 }
    }

    private func boundedLongPollTimeoutSeconds(for fetch: FetchRequest) -> Int? {
        boundedLongPollTimeoutSeconds(requested: fetch.longPollTimeoutSeconds)
    }

    private func boundedLongPollTimeoutSeconds(requested: Int?) -> Int? {
        guard let requested,
              requested > 0,
              relayConfiguration.wakeSupport?.mode == .longPoll else {
            return nil
        }
        let advertised = relayConfiguration.wakeSupport?.longPollTimeoutSeconds
            ?? relayConfiguration.wakeSupport?.minPollIntervalSeconds
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

    private func validateAuthentication(token: String?) -> RelayResponse? {
        let expected = relayConfiguration.accessPassword?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
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
        let expected = relayConfiguration.coordinatorRegistrationToken?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if expected.isEmpty, relayConfiguration.federation.mode == .curated {
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

    private func isCoordinatorDirectoryRequestType(_ type: RelayRequestType) -> Bool {
        switch type {
        case .health, .info, .registerFederationNode, .listFederationNodes:
            return true
        default:
            return false
        }
    }
}

private struct SignedPrekeyVerificationPayload: Codable {
    let id: UUID
    let publicKey: Data
    let issuedAt: Date
}

private struct OneTimePrekeyVerificationPayload: Codable {
    let id: UUID
    let publicKey: Data
}

private final class ForwardingHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let requestData: Data
    private let promise: EventLoopPromise<RelayResponse>
    private let completion: ForwardingCompletion

    init(requestData: Data, promise: EventLoopPromise<RelayResponse>, completion: ForwardingCompletion) {
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
