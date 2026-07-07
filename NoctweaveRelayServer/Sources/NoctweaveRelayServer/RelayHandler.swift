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

private struct RelayForwardTimeoutError: LocalizedError {
    var errorDescription: String? { "Relay forwarding request timed out." }
}

final class RelayHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let store: RelayStore
    private let maxMessageBytes: Int?
    private let maxLineBytes: Int?
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
        self.maxMessageBytes = maxMessageBytes
        self.maxLineBytes = maxLineBytes
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
        if let maxMessageBytes, payload.count > maxMessageBytes {
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
        let requestSourceKey = normalizedFederationSourceKey(context.channel.remoteAddress?.description)
        guard store.allowRelayRequest(sourceKey: requestSourceKey) else {
            return context.eventLoop.makeSucceededFuture(.error("Rate limit exceeded"))
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
            let routingToken = deliver.routingToken ?? deliver.inboxId
            guard InboxAddress.isValid(routingToken) else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid routing token"))
            }
            if let destination = deliver.destinationRelay,
               destination != localEndpoint {
                let eventLoop = context.eventLoop
                return federationGate(forwardingTo: destination, on: eventLoop).flatMap { response in
                    if let response {
                        return eventLoop.makeSucceededFuture(response)
                    }
                    let forward = DeliverRequest(
                        inboxId: deliver.inboxId,
                        routingToken: routingToken,
                        envelope: deliver.envelope,
                        destinationRelay: nil
                    )
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
            do {
                let count = try store.deliver(deliver.envelope, to: routingToken)
                return context.eventLoop.makeSucceededFuture(.delivered(count: count))
            } catch RelayStoreError.inboxFull {
                return context.eventLoop.makeSucceededFuture(.error("Inbox full"))
            } catch RelayStoreError.relayCapacityExceeded {
                return context.eventLoop.makeSucceededFuture(.error("Relay storage capacity reached"))
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
            guard let offer = registration.contactOffer,
                  offer.verifySignature(),
                  offer.inboxId == registration.inboxId,
                  offer.inboxAccessPublicKey == registration.accessPublicKey else {
                return context.eventLoop.makeSucceededFuture(
                    .error("Inbox registration is not bound to a valid identity offer")
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
                try store.registerInbox(
                    inboxId: registration.inboxId,
                    accessPublicKey: registration.accessPublicKey
                )
                return context.eventLoop.makeSucceededFuture(.ok())
            } catch RelayStoreError.inboxAlreadyRegistered {
                return context.eventLoop.makeSucceededFuture(
                    .error("Inbox is already registered to another access key")
                )
            } catch RelayStoreError.relayCapacityExceeded {
                return context.eventLoop.makeSucceededFuture(.error("Relay storage capacity reached"))
            } catch {
                return context.eventLoop.makeSucceededFuture(.error("Invalid inbox registration"))
            }
        case .fetch:
            guard let fetch = request.fetch else {
                return context.eventLoop.makeSucceededFuture(.error("Missing fetch payload"))
            }
            let routingToken = fetch.routingToken ?? fetch.inboxId
            guard InboxAddress.isValid(routingToken) else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid routing token"))
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
        case .acknowledgeMessages:
            guard let acknowledgement = request.acknowledgeMessages else {
                return context.eventLoop.makeSucceededFuture(.error("Missing acknowledgement payload"))
            }
            guard InboxAddress.isValid(acknowledgement.inboxId),
                  !acknowledgement.messageIds.isEmpty,
                  acknowledgement.messageIds.count <= 1_000 else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid acknowledgement"))
            }
            guard let accessPublicKey = store.inboxAccessPublicKey(for: acknowledgement.inboxId) else {
                return context.eventLoop.makeSucceededFuture(.error("Inbox is not registered"))
            }
            let accessFingerprint = Data(SHA256.hash(data: accessPublicKey)).base64EncodedString()
            if let proofFailure = validateActorProof(
                acknowledgement.accessProof,
                expectedFingerprint: accessFingerprint,
                expectedSigningKey: accessPublicKey,
                signableDataBuilder: { proof in try acknowledgement.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            _ = store.acknowledge(
                inboxId: acknowledgement.inboxId,
                messageIds: acknowledgement.messageIds
            )
            return context.eventLoop.makeSucceededFuture(.ok())
        case .deliverGroupMessage:
            guard let deliver = request.deliverGroupMessage else {
                return context.eventLoop.makeSucceededFuture(.error("Missing group message delivery payload"))
            }
            guard InboxAddress.isValid(deliver.groupInboxId),
                  deliver.envelope.groupId == deliver.groupId else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid group message delivery"))
            }
            if let destination = deliver.destinationRelay,
               destination != localEndpoint {
                let eventLoop = context.eventLoop
                return federationGate(forwardingTo: destination, on: eventLoop).flatMap { response in
                    if let response {
                        return eventLoop.makeSucceededFuture(response)
                    }
                    let forward = DeliverGroupMessageRequest(
                        groupId: deliver.groupId,
                        groupInboxId: deliver.groupInboxId,
                        envelope: deliver.envelope,
                        destinationRelay: nil
                    )
                    return self.forwardGroupDeliver(
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
            guard let group = store.fetchGroup(groupId: deliver.groupId),
                  group.inboxId == deliver.groupInboxId else {
                return context.eventLoop.makeSucceededFuture(.error("Group not found"))
            }
            guard let senderKey = registeredSigningKey(
                for: deliver.envelope.senderFingerprint,
                in: group
            ),
                  deliver.envelope.verifySignature(publicSigningKey: senderKey) else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid group message signature"))
            }
            do {
                let recipientFingerprints = group.members
                    .map(\.fingerprint)
                    .filter { $0 != deliver.envelope.senderFingerprint }
                let count = try store.deliverGroupEnvelope(
                    carrierEnvelope(for: deliver.envelope),
                    to: deliver.groupInboxId,
                    recipientFingerprints: recipientFingerprints
                )
                return context.eventLoop.makeSucceededFuture(.delivered(count: count))
            } catch RelayStoreError.inboxFull {
                return context.eventLoop.makeSucceededFuture(.error("Inbox full"))
            } catch RelayStoreError.relayCapacityExceeded {
                return context.eventLoop.makeSucceededFuture(.error("Relay storage capacity reached"))
            } catch {
                return context.eventLoop.makeSucceededFuture(.error("Store error"))
            }
        case .fetchGroupMessages:
            guard let fetch = request.fetchGroupMessages else {
                return context.eventLoop.makeSucceededFuture(.error("Missing group message fetch payload"))
            }
            guard InboxAddress.isValid(fetch.groupInboxId) else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid group inbox"))
            }
            guard let group = store.fetchGroup(groupId: fetch.groupId),
                  group.inboxId == fetch.groupInboxId else {
                return context.eventLoop.makeSucceededFuture(.error("Group not found"))
            }
            guard let signingKey = registeredSigningKey(for: fetch.actorFingerprint, in: group) else {
                return context.eventLoop.makeSucceededFuture(.error("Actor is not a group member"))
            }
            if let proofFailure = validateActorProof(
                fetch.actorProof,
                expectedFingerprint: fetch.actorFingerprint,
                expectedSigningKey: signingKey,
                signableDataBuilder: { proof in try fetch.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            return fetchGroupMessagesWithOptionalLongPoll(fetch, on: context.eventLoop)
                .map { RelayResponse.groupMessages($0) }
        case .acknowledgeGroupMessages:
            guard let acknowledgement = request.acknowledgeGroupMessages else {
                return context.eventLoop.makeSucceededFuture(.error("Missing group acknowledgement payload"))
            }
            guard InboxAddress.isValid(acknowledgement.groupInboxId),
                  !acknowledgement.messageIds.isEmpty,
                  acknowledgement.messageIds.count <= 1_000 else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid group acknowledgement"))
            }
            guard let group = store.fetchGroup(groupId: acknowledgement.groupId),
                  group.inboxId == acknowledgement.groupInboxId else {
                return context.eventLoop.makeSucceededFuture(.error("Group not found"))
            }
            guard let signingKey = registeredSigningKey(for: acknowledgement.actorFingerprint, in: group) else {
                return context.eventLoop.makeSucceededFuture(.error("Actor is not a group member"))
            }
            if let proofFailure = validateActorProof(
                acknowledgement.actorProof,
                expectedFingerprint: acknowledgement.actorFingerprint,
                expectedSigningKey: signingKey,
                signableDataBuilder: { proof in try acknowledgement.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            _ = store.acknowledgeGroupEnvelopes(
                inboxId: acknowledgement.groupInboxId,
                messageIds: acknowledgement.messageIds,
                recipientFingerprint: acknowledgement.actorFingerprint
            )
            return context.eventLoop.makeSucceededFuture(.ok())
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
        case .announce:
            guard let announce = request.announce else {
                return context.eventLoop.makeSucceededFuture(.error("Missing announce payload"))
            }
            guard OQSSignatureVerifier.shared.isAvailable,
                  announce.offer.verifySignature() else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid contact offer."))
            }
            let announcement = store.announce(announce.offer, ttlSeconds: announce.ttlSeconds)
            return context.eventLoop.makeSucceededFuture(.announcements([announcement]))
        case .listAnnouncements:
            guard let list = request.listAnnouncements else {
                return context.eventLoop.makeSucceededFuture(.error("Missing list payload"))
            }
            let announcements = store.listAnnouncements(limit: list.limit)
            return context.eventLoop.makeSucceededFuture(.announcements(announcements))
        case .sendPairRequest:
            guard let request = request.sendPairRequest else {
                return context.eventLoop.makeSucceededFuture(.error("Missing pair request payload"))
            }
            guard OQSSignatureVerifier.shared.isAvailable,
                  request.offer.verifySignature() else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid contact offer."))
            }
            if let proofFailure = validateActorProof(
                request.actorProof,
                expectedFingerprint: request.offer.fingerprint,
                expectedSigningKey: request.offer.signingPublicKey,
                signableDataBuilder: { proof in try request.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            _ = store.sendPairRequest(targetFingerprint: request.targetFingerprint, offer: request.offer)
            return context.eventLoop.makeSucceededFuture(.ok())
        case .fetchPairRequests:
            guard let fetch = request.fetchPairRequests else {
                return context.eventLoop.makeSucceededFuture(.error("Missing fetch pair payload"))
            }
            let expectedFingerprint = fetch.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            if let proofFailure = validateActorProof(
                fetch.actorProof,
                expectedFingerprint: expectedFingerprint,
                expectedSigningKey: nil,
                signableDataBuilder: { proof in try fetch.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            let requests = store.fetchPairRequests(targetFingerprint: fetch.fingerprint, maxCount: fetch.maxCount)
            return context.eventLoop.makeSucceededFuture(.pairRequests(requests))
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
        case .uploadPrekeys:
            guard let upload = request.uploadPrekeys else {
                return context.eventLoop.makeSucceededFuture(.error("Missing prekey bundle payload"))
            }
            let fingerprint = upload.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard fingerprint == upload.bundle.identityFingerprint else {
                return context.eventLoop.makeSucceededFuture(.error("Prekey bundle fingerprint mismatch."))
            }
            if let proofFailure = validateActorProof(
                upload.actorProof,
                expectedFingerprint: fingerprint,
                expectedSigningKey: nil,
                signableDataBuilder: { proof in try upload.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            guard let publicSigningKey = upload.actorProof?.publicSigningKey,
                  verifySignedPrekey(upload.bundle.signedPrekey, using: publicSigningKey),
                  upload.bundle.oneTimePrekeys.allSatisfy({
                      verifyOneTimePrekey($0, using: publicSigningKey)
                  }) else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid authenticated prekey bundle."))
            }
            do {
                try store.uploadPrekeyBundle(
                    fingerprint: fingerprint,
                    bundle: upload.bundle,
                    ttlSeconds: upload.ttlSeconds
                )
                return context.eventLoop.makeSucceededFuture(.ok())
            } catch RelayStoreError.invalidPrekeyBundle {
                return context.eventLoop.makeSucceededFuture(.error("Invalid prekey bundle."))
            } catch {
                return context.eventLoop.makeSucceededFuture(.error("Prekey store error"))
            }
        case .fetchPrekeyBundle:
            guard let fetch = request.fetchPrekeyBundle else {
                return context.eventLoop.makeSucceededFuture(.error("Missing fetch prekey payload"))
            }
            do {
                let bundle = try store.fetchPrekeyBundle(fingerprint: fetch.fingerprint)
                return context.eventLoop.makeSucceededFuture(.prekeyBundle(bundle))
            } catch {
                return context.eventLoop.makeSucceededFuture(.error("Prekey fetch error"))
            }
        case .createGroup:
            guard let create = request.createGroup else {
                return context.eventLoop.makeSucceededFuture(.error("Missing create group payload"))
            }
            guard relayConfiguration.groupCreationMode != .disabled else {
                return context.eventLoop.makeSucceededFuture(.error("Group creation is disabled on this relay."))
            }
            let creatorFingerprint = create.creatorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !creatorFingerprint.isEmpty else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid fingerprint"))
            }
            guard let creatorProfile = create.creatorProfile,
                  let creatorSigningKey = creatorProfile.signingPublicKey,
                  !creatorSigningKey.isEmpty else {
                return context.eventLoop.makeSucceededFuture(.error("Creator profile must include a signing key."))
            }
            guard creatorProfile.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines) == creatorFingerprint else {
                return context.eventLoop.makeSucceededFuture(.error("Creator profile fingerprint mismatch."))
            }
            if let proofFailure = validateActorProof(
                create.creatorProof,
                expectedFingerprint: creatorFingerprint,
                expectedSigningKey: creatorSigningKey,
                signableDataBuilder: { proof in try create.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            do {
                let group = try store.createGroup(
                    groupId: create.groupId,
                    title: create.title,
                    creatorFingerprint: create.creatorFingerprint,
                    memberFingerprints: create.memberFingerprints,
                    creatorProfile: create.creatorProfile,
                    memberProfiles: create.memberProfiles,
                    initialRatchetSecretDistribution: create.initialRatchetSecretDistribution
                )
                return context.eventLoop.makeSucceededFuture(.group(group))
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error))
            }
        case .getGroup:
            guard let get = request.getGroup else {
                return context.eventLoop.makeSucceededFuture(.error("Missing get group payload"))
            }
            guard let group = store.fetchGroup(groupId: get.groupId) else {
                return context.eventLoop.makeSucceededFuture(.group(nil))
            }
            let memberFingerprint = get.memberFingerprint?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !memberFingerprint.isEmpty,
                  let memberKey = registeredSigningKey(for: memberFingerprint, in: group) else {
                return context.eventLoop.makeSucceededFuture(.error("Group membership is required"))
            }
            if let proofFailure = validateActorProof(
                get.memberProof,
                expectedFingerprint: memberFingerprint,
                expectedSigningKey: memberKey,
                signableDataBuilder: { proof in try get.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            return context.eventLoop.makeSucceededFuture(.group(group))
        case .listGroups:
            guard let list = request.listGroups else {
                return context.eventLoop.makeSucceededFuture(.error("Missing list groups payload"))
            }
            let memberFingerprint = list.memberFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !memberFingerprint.isEmpty else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid fingerprint"))
            }
            if let proofFailure = validateActorProof(
                list.memberProof,
                expectedFingerprint: memberFingerprint,
                expectedSigningKey: nil,
                signableDataBuilder: { proof in try list.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            let groups = store.listGroups(memberFingerprint: list.memberFingerprint, limit: list.limit)
            return context.eventLoop.makeSucceededFuture(.groups(groups))
        case .updateGroup:
            guard let update = request.updateGroup else {
                return context.eventLoop.makeSucceededFuture(.error("Missing update group payload"))
            }
            guard let group = store.fetchGroup(groupId: update.groupId) else {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(RelayStoreError.groupNotFound))
            }
            let actorFingerprint = update.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !actorFingerprint.isEmpty else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid fingerprint"))
            }
            guard let actorSigningKey = registeredSigningKey(for: actorFingerprint, in: group) else {
                return context.eventLoop.makeSucceededFuture(.error("Group member signing key is missing. Re-pair and re-join the group."))
            }
            guard let groupCommit = update.groupCommit else {
                return context.eventLoop.makeSucceededFuture(.error("Missing signed group commit"))
            }
            if let proofFailure = validateActorProof(
                groupCommit.actorProof,
                expectedFingerprint: actorFingerprint,
                expectedSigningKey: actorSigningKey,
                signableDataBuilder: { proof in try groupCommit.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            do {
                let group = try store.updateGroup(update)
                return context.eventLoop.makeSucceededFuture(.group(group))
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error))
            }
        case .deleteGroup:
            guard let delete = request.deleteGroup else {
                return context.eventLoop.makeSucceededFuture(.error("Missing delete group payload"))
            }
            guard let group = store.fetchGroup(groupId: delete.groupId) else {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(RelayStoreError.groupNotFound))
            }
            let actorFingerprint = delete.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !actorFingerprint.isEmpty else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid fingerprint"))
            }
            guard let actorSigningKey = registeredSigningKey(for: actorFingerprint, in: group) else {
                return context.eventLoop.makeSucceededFuture(.error("Group member signing key is missing. Re-pair and re-join the group."))
            }
            if let proofFailure = validateActorProof(
                delete.actorProof,
                expectedFingerprint: actorFingerprint,
                expectedSigningKey: actorSigningKey,
                signableDataBuilder: { proof in try delete.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            do {
                try store.deleteGroup(delete)
                return context.eventLoop.makeSucceededFuture(.ok())
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error))
            }
        case .requestGroupJoin:
            guard let join = request.requestGroupJoin else {
                return context.eventLoop.makeSucceededFuture(.error("Missing request join payload"))
            }
            let requesterFingerprint = join.requesterProfile.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !requesterFingerprint.isEmpty else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid fingerprint"))
            }
            guard let requesterSigningKey = join.requesterProfile.signingPublicKey,
                  !requesterSigningKey.isEmpty else {
                return context.eventLoop.makeSucceededFuture(.error("Requester profile must include a signing key."))
            }
            if let proofFailure = validateActorProof(
                join.requesterProof,
                expectedFingerprint: requesterFingerprint,
                expectedSigningKey: requesterSigningKey,
                signableDataBuilder: { proof in try join.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            do {
                let created = try store.requestGroupJoin(join)
                return context.eventLoop.makeSucceededFuture(.groupJoinRequests([created]))
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error))
            }
        case .listGroupJoinRequests:
            guard let list = request.listGroupJoinRequests else {
                return context.eventLoop.makeSucceededFuture(.error("Missing list join payload"))
            }
            guard let group = store.fetchGroup(groupId: list.groupId) else {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(RelayStoreError.groupNotFound))
            }
            let actorFingerprint = list.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !actorFingerprint.isEmpty else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid fingerprint"))
            }
            guard let actorSigningKey = registeredSigningKey(for: actorFingerprint, in: group) else {
                return context.eventLoop.makeSucceededFuture(.error("Group member signing key is missing. Re-pair and re-join the group."))
            }
            if let proofFailure = validateActorProof(
                list.actorProof,
                expectedFingerprint: actorFingerprint,
                expectedSigningKey: actorSigningKey,
                signableDataBuilder: { proof in try list.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            do {
                let pending = try store.listGroupJoinRequests(list)
                return context.eventLoop.makeSucceededFuture(.groupJoinRequests(pending))
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error))
            }
        case .approveGroupJoin:
            guard let approve = request.approveGroupJoin else {
                return context.eventLoop.makeSucceededFuture(.error("Missing approve join payload"))
            }
            guard let group = store.fetchGroup(groupId: approve.groupId) else {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(RelayStoreError.groupNotFound))
            }
            let actorFingerprint = approve.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !actorFingerprint.isEmpty else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid fingerprint"))
            }
            guard let actorSigningKey = registeredSigningKey(for: actorFingerprint, in: group) else {
                return context.eventLoop.makeSucceededFuture(.error("Group member signing key is missing. Re-pair and re-join the group."))
            }
            if let proofFailure = validateActorProof(
                approve.actorProof,
                expectedFingerprint: actorFingerprint,
                expectedSigningKey: actorSigningKey,
                signableDataBuilder: { proof in try approve.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            if let proofFailure = validateActorProof(
                approve.groupCommit.actorProof,
                expectedFingerprint: actorFingerprint,
                expectedSigningKey: actorSigningKey,
                signableDataBuilder: { proof in try approve.groupCommit.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            do {
                let group = try store.approveGroupJoin(approve)
                return context.eventLoop.makeSucceededFuture(.group(group))
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error))
            }
        case .rejectGroupJoin:
            guard let reject = request.rejectGroupJoin else {
                return context.eventLoop.makeSucceededFuture(.error("Missing reject join payload"))
            }
            guard let group = store.fetchGroup(groupId: reject.groupId) else {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(RelayStoreError.groupNotFound))
            }
            let actorFingerprint = reject.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !actorFingerprint.isEmpty else {
                return context.eventLoop.makeSucceededFuture(.error("Invalid fingerprint"))
            }
            guard let actorSigningKey = registeredSigningKey(for: actorFingerprint, in: group) else {
                return context.eventLoop.makeSucceededFuture(.error("Group member signing key is missing. Re-pair and re-join the group."))
            }
            if let proofFailure = validateActorProof(
                reject.actorProof,
                expectedFingerprint: actorFingerprint,
                expectedSigningKey: actorSigningKey,
                signableDataBuilder: { proof in try reject.signableData(for: proof) }
            ) {
                return context.eventLoop.makeSucceededFuture(proofFailure)
            }
            do {
                try store.rejectGroupJoin(reject)
                return context.eventLoop.makeSucceededFuture(.ok())
            } catch {
                return context.eventLoop.makeSucceededFuture(relayStoreErrorResponse(error))
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
            let sourceKey = normalizedFederationSourceKey(context.channel.remoteAddress?.description)
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
                let sourceKey = normalizedFederationSourceKey(context.channel.remoteAddress?.description)
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
        case RelayStoreError.invalidEnvelopePayload:
            return .error("Invalid envelope payload")
        case RelayStoreError.invalidChunkIndex:
            return .error("Invalid chunk index")
        case RelayStoreError.invalidAttachmentPayload:
            return .error("Invalid attachment payload")
        case RelayStoreError.attachmentBlobUnavailable:
            return .error("Attachment blob backend unavailable")
        case RelayStoreError.invalidPrekeyBundle:
            return .error("Invalid prekey bundle")
        case RelayStoreError.groupCapacityExceeded:
            return .error("Group capacity reached")
        case RelayStoreError.invalidGroupTitle:
            return .error("Invalid group title")
        case RelayStoreError.invalidFingerprint:
            return .error("Invalid fingerprint")
        case RelayStoreError.invalidGroupCommit:
            return .error("Invalid group commit")
        case RelayStoreError.notEnoughGroupMembers:
            return .error("A group requires at least 2 members")
        case RelayStoreError.groupNotFound:
            return .error("Group not found")
        case RelayStoreError.unauthorizedGroupMutation:
            return .error("Unauthorized group update")
        case RelayStoreError.groupJoinRequestNotFound:
            return .error("Group join request not found")
        case RelayStoreError.alreadyGroupMember:
            return .error("Requester is already a group member")
        default:
            return .error("Store error")
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

    private func forwardGroupDeliver(
        _ deliver: DeliverGroupMessageRequest,
        to endpoint: RelayEndpoint,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<RelayResponse> {
        sendRequest(
            .deliverGroupMessage(deliver).withAuthToken(relayConfiguration.federationForwardingAuthToken),
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
                    self.store.pinCoordinatorPublicKey(advertisedPublicKey, for: coordinator)
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
            return sendRequestHTTP(request, to: endpoint, on: eventLoop).flatMapError { _ in
                self.sendRequestTCP(request, to: endpoint, on: eventLoop)
            }
        case .websocket:
            return sendRequestHTTP(request, to: endpoint, on: eventLoop).flatMapError { _ in
                self.sendRequestTCP(request, to: endpoint, on: eventLoop)
            }
        }
    }

    private func sendRequestTCP(
        _ request: RelayRequest,
        to endpoint: RelayEndpoint,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<RelayResponse> {
        let promise = eventLoop.makePromise(of: RelayResponse.self)
        let completion = ForwardingCompletion()
        let timeoutTask = eventLoop.scheduleTask(in: .seconds(Int64(forwardingRequestTimeoutSeconds))) {
            completion.resolve(promise, .failure(RelayForwardTimeoutError()))
        }
        promise.futureResult.whenComplete { _ in
            timeoutTask.cancel()
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
            bootstrap.connect(host: endpoint.host, port: Int(endpoint.port)).whenFailure { error in
                completion.resolve(promise, .failure(error))
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
        let timeoutTask = eventLoop.scheduleTask(in: .seconds(Int64(forwardingRequestTimeoutSeconds))) {
            completion.resolve(promise, .failure(RelayForwardTimeoutError()))
        }
        promise.futureResult.whenComplete { _ in
            timeoutTask.cancel()
        }
        Task.detached {
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
                let session = URLSession(configuration: .ephemeral)
                defer { session.invalidateAndCancel() }
                let (data, response) = try await session.data(for: urlRequest)
                guard self.maxMessageBytes.map({ data.count <= $0 }) ?? true else {
                    throw RelayForwardHTTPError.badStatus(413)
                }
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
        return promise.futureResult
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
        let maxAgeSeconds: TimeInterval = 300
        guard abs(proof.signedAt.timeIntervalSinceNow) <= maxAgeSeconds else {
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
        guard store.consumeActorProofNonce(
            fingerprint: proof.fingerprint,
            nonce: proof.nonce,
            now: Date(),
            maxAgeSeconds: maxAgeSeconds
        ) else {
            return .error("Actor proof replay detected.")
        }
        return nil
    }

    private func verifySignedPrekey(_ prekey: SignedPrekey, using publicSigningKey: Data) -> Bool {
        guard OQSSignatureVerifier.shared.isAvailable,
              let signableData = try? RelayCodec.encoder(sortedKeys: true).encode(
                SignedPrekeyVerificationPayload(
                    id: prekey.id,
                    publicKey: prekey.publicKey,
                    issuedAt: prekey.issuedAt
                )
              ) else {
            return false
        }
        return OQSSignatureVerifier.shared.verify(
            signature: prekey.signature,
            data: signableData,
            publicKey: publicSigningKey
        )
    }

    private func verifyOneTimePrekey(_ prekey: OneTimePrekey, using publicSigningKey: Data) -> Bool {
        guard OQSSignatureVerifier.shared.isAvailable,
              let signableData = try? RelayCodec.encoder(sortedKeys: true).encode(
                OneTimePrekeyVerificationPayload(
                    id: prekey.id,
                    publicKey: prekey.publicKey
                )
              ) else {
            return false
        }
        return OQSSignatureVerifier.shared.verify(
            signature: prekey.signature,
            data: signableData,
            publicKey: publicSigningKey
        )
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

    private func boundedLongPollTimeoutSeconds(for fetch: FetchRequest) -> Int? {
        boundedLongPollTimeoutSeconds(requested: fetch.longPollTimeoutSeconds)
    }

    private func fetchGroupMessagesWithOptionalLongPoll(
        _ fetch: FetchGroupMessagesRequest,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<[GroupRatchetEnvelope]> {
        let messages = store.fetchGroupEnvelopes(
            inboxId: fetch.groupInboxId,
            recipientFingerprint: fetch.actorFingerprint,
            maxCount: fetch.maxCount
        )
            .compactMap { groupRatchetEnvelope(from: $0, groupId: fetch.groupId) }
        guard messages.isEmpty,
              let timeout = boundedLongPollTimeoutSeconds(requested: fetch.longPollTimeoutSeconds) else {
            return eventLoop.makeSucceededFuture(messages)
        }
        let deadline = Date().addingTimeInterval(TimeInterval(timeout))
        return fetchGroupMessagesWithLongPollRetry(fetch, deadline: deadline, on: eventLoop)
    }

    private func fetchGroupMessagesWithLongPollRetry(
        _ fetch: FetchGroupMessagesRequest,
        deadline: Date,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<[GroupRatchetEnvelope]> {
        let remaining = deadline.timeIntervalSinceNow
        guard remaining > 0 else {
            return eventLoop.makeSucceededFuture(
                store.fetchGroupEnvelopes(
                    inboxId: fetch.groupInboxId,
                    recipientFingerprint: fetch.actorFingerprint,
                    maxCount: fetch.maxCount
                )
                    .compactMap { groupRatchetEnvelope(from: $0, groupId: fetch.groupId) }
            )
        }
        let delayMilliseconds = Int64(max(1, min(250, remaining * 1_000)))
        return eventLoop.scheduleTask(in: .milliseconds(delayMilliseconds)) {
            let messages = self.store.fetchGroupEnvelopes(
                inboxId: fetch.groupInboxId,
                recipientFingerprint: fetch.actorFingerprint,
                maxCount: fetch.maxCount
            )
                .compactMap { self.groupRatchetEnvelope(from: $0, groupId: fetch.groupId) }
            if !messages.isEmpty || Date() >= deadline {
                return eventLoop.makeSucceededFuture(messages)
            }
            return self.fetchGroupMessagesWithLongPollRetry(fetch, deadline: deadline, on: eventLoop)
        }.futureResult.flatMap { $0 }
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

    private func carrierEnvelope(for envelope: GroupRatchetEnvelope) -> Envelope {
        Envelope(
            id: envelope.id,
            conversationId: "group:\(envelope.groupId.uuidString)",
            sessionId: String(envelope.epoch),
            senderFingerprint: envelope.senderFingerprint,
            sentAt: envelope.sentAt,
            messageCounter: envelope.messageCounter,
            kemCiphertext: envelope.transcriptHash,
            payload: envelope.payload,
            signature: envelope.signature
        )
    }

    private func groupRatchetEnvelope(from carrier: Envelope, groupId: UUID) -> GroupRatchetEnvelope? {
        guard carrier.conversationId == "group:\(groupId.uuidString)",
              let epochText = carrier.sessionId,
              let epoch = UInt64(epochText),
              let transcriptHash = carrier.kemCiphertext else {
            return nil
        }
        return GroupRatchetEnvelope(
            id: carrier.id,
            groupId: groupId,
            epoch: epoch,
            transcriptHash: transcriptHash,
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

    private func validateAuthentication(token: String?) -> RelayResponse? {
        let expected = relayConfiguration.accessPassword?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
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
        let expected = relayConfiguration.coordinatorRegistrationToken?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
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
