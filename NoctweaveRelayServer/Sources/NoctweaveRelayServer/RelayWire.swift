import Foundation

enum RelayModuleID: String, Codable, CaseIterable {
    case core = "nw.core"
    case opaqueRoute = "nw.opaque-route"
    case rendezvousTransport = "nw.rendezvous-transport"
    case blobs = "nw.blobs"
    case federation = "nw.federation"
    case federationForward = "nw.federation-forward"
    case openDiscovery = "nw.open-discovery"
    case netPassthrough = "nw.net-passthrough"
    case netHost = "nw.net-host"
    case noctwebData = "nw.noctweb-data"
    case realtimeRoute = "nw.realtime-route"
    case sharedLog = "nw.shared-log"
    case ephemeralPresence = "nw.ephemeral-presence"
    case mediaBlobs = "nw.media-blobs"
    case iceService = "nw.ice-service"

    var currentVersion: Int {
        switch self {
        case .core, .opaqueRoute, .rendezvousTransport: return 2
        case .blobs, .federation, .federationForward, .openDiscovery,
             .netPassthrough, .netHost, .noctwebData, .realtimeRoute, .sharedLog,
             .ephemeralPresence, .mediaBlobs, .iceService: return 1
        }
    }
}

enum RelayMethodID: String, Codable, CaseIterable {
    case health
    case info
    case create
    case renew
    case teardown
    case append
    case sync
    case commit
    case register
    case delete
    case upload
    case fetch
    case list
    case namespace
    case claim
    case rotate
    case publishDHT = "publish-dht"
    case listDHT = "list-dht"
    case forward
    case deliver
    case put
    case bind
    case get
    case resolve
    case has
    case release
    case subscribe
    case unsubscribe
    case acquire
    case renewLease = "renew-lease"
}

struct RelayOperationBinding: Codable, Equatable, Hashable {
    let module: RelayModuleID
    let version: Int
    let method: RelayMethodID

    var isCurrent: Bool {
        version == module.currentVersion && Self.allowedMethods[module]?.contains(method) == true
    }

    private static let allowedMethods: [RelayModuleID: Set<RelayMethodID>] = [
        .core: [.health, .info],
        .opaqueRoute: [.create, .renew, .teardown, .append, .sync, .commit],
        .rendezvousTransport: [.register, .append, .sync, .delete],
        .blobs: [.upload, .fetch],
        .federation: [
            .register,
            .list,
            .namespace,
            .claim,
            .rotate,
            .release
        ],
        .federationForward: [.forward, .deliver, .get, .resolve],
        .openDiscovery: [.publishDHT, .listDHT],
        .netPassthrough: [.forward],
        .netHost: [.put, .bind, .get, .resolve, .has, .release],
        .noctwebData: [.create, .register, .put, .get, .list, .delete],
        .realtimeRoute: [.create, .append, .subscribe, .sync, .unsubscribe],
        .sharedLog: [.create, .append, .sync],
        .ephemeralPresence: [.acquire, .renewLease, .release, .list],
        .mediaBlobs: [.create, .upload, .fetch, .release],
        .iceService: [.acquire]
    ]
}

enum RelayRequestBody: Equatable {
    case empty
    case createOpaqueRoute(OpaqueRouteCreateSubmissionV2)
    case renewOpaqueRoute(OpaqueRouteRenewSubmissionV2)
    case teardownOpaqueRoute(OpaqueRouteTeardownSubmissionV2)
    case appendOpaqueRoute(OpaqueRouteAppendSubmissionV2)
    case syncOpaqueRoute(OpaqueRouteSyncSubmissionV2)
    case commitOpaqueRoute(OpaqueRouteCommitSubmissionV2)
    case registerRendezvous(RegisterRendezvousTransportV2Request)
    case appendRendezvous(AppendRendezvousTransportV2Request)
    case syncRendezvous(SyncRendezvousTransportV2Request)
    case deleteRendezvous(DeleteRendezvousTransportV2Request)
    case uploadAttachment(UploadAttachmentRequest)
    case fetchAttachment(FetchAttachmentRequest)
    case registerFederationNode(FederationNodeRegistrationRequest)
    case listFederationNodes(ListFederationNodesRequest)
    case getNoctwebNamespaceSnapshot(NoctwebNamespaceSnapshotRequestV1)
    case claimNoctwebNamespace(NoctwebNamespaceClaimRequestV1)
    case rotateNoctwebNamespace(NoctwebNamespaceRotationRequestV1)
    case releaseNoctwebNamespace(NoctwebNamespaceReleaseV1)
    case forwardOpaqueRoute(FederatedOpaqueRouteForwardRequestV1)
    case deliverOpaqueRoute(FederatedOpaqueRouteDeliveryV1)
    case getFederatedNetHostObject(FederatedNetHostReadRequestV1)
    case resolveFederatedNetHostName(
        FederatedNetHostNameReadRequestV1
    )
    case publishDHTRecord(PublishOpenFederationDHTRecordRequest)
    case listDHTRecords(ListOpenFederationDHTRecordsRequest)
    case netPassthrough(NoctweaveNetPassthroughRequest)
    case putNetHostObject(NoctweaveNetHostPutRequest)
    case bindNetHostName(NoctweaveNetHostNameBindingRequestV1)
    case getNetHostObject(NoctweaveNetHostObjectRequest)
    case resolveNetHostName(NoctweaveNetHostNameRequestV1)
    case hasNetHostObject(NoctweaveNetHostObjectRequest)
    case releaseNetHostObject(NoctweaveNetHostReleaseRequest)
    case createNoctwebDatabase(NoctwebDataDatabaseCreateRequestV1)
    case registerNoctwebAccount(NoctwebDataAccountRegisterRequestV1)
    case putNoctwebRecord(NoctwebDataRecordPutRequestV1)
    case getNoctwebRecord(NoctwebDataRecordGetRequestV1)
    case listNoctwebRecords(NoctwebDataRecordListRequestV1)
    case deleteNoctwebRecord(NoctwebDataRecordDeleteRequestV1)
    case createRealtimeRoute(RealtimeRouteCreateRequestV1)
    case appendRealtimeRoute(RealtimeRouteAppendRequestV1)
    case subscribeRealtimeRoute(RealtimeRouteSubscribeRequestV1)
    case syncRealtimeRoute(RealtimeRouteSyncRequestV1)
    case unsubscribeRealtimeRoute(RealtimeRouteUnsubscribeRequestV1)
    case createSharedLog(SharedLogCreateRequestV1)
    case appendSharedLog(SharedLogAppendRequestV1)
    case syncSharedLog(SharedLogSyncRequestV1)
    case acquirePresence(PresenceLeaseAcquireRequestV1)
    case renewPresence(PresenceLeaseRenewRequestV1)
    case releasePresence(PresenceLeaseReleaseRequestV1)
    case listPresence(PresenceLeaseListRequestV1)
    case createMediaBlob(MediaBlobCreateRequestV1)
    case uploadMediaBlob(MediaBlobUploadRequestV1)
    case fetchMediaBlob(MediaBlobFetchRequestV1)
    case releaseMediaBlob(MediaBlobReleaseRequestV1)
    case acquireICECredentials(RelayICECredentialRequestV1)

    var binding: RelayOperationBinding {
        switch self {
        case .empty: preconditionFailure("An empty relay body requires an explicit core operation")
        case .createOpaqueRoute: return .init(module: .opaqueRoute, version: 2, method: .create)
        case .renewOpaqueRoute: return .init(module: .opaqueRoute, version: 2, method: .renew)
        case .teardownOpaqueRoute: return .init(module: .opaqueRoute, version: 2, method: .teardown)
        case .appendOpaqueRoute: return .init(module: .opaqueRoute, version: 2, method: .append)
        case .syncOpaqueRoute: return .init(module: .opaqueRoute, version: 2, method: .sync)
        case .commitOpaqueRoute: return .init(module: .opaqueRoute, version: 2, method: .commit)
        case .registerRendezvous: return .init(module: .rendezvousTransport, version: 2, method: .register)
        case .appendRendezvous: return .init(module: .rendezvousTransport, version: 2, method: .append)
        case .syncRendezvous: return .init(module: .rendezvousTransport, version: 2, method: .sync)
        case .deleteRendezvous: return .init(module: .rendezvousTransport, version: 2, method: .delete)
        case .uploadAttachment: return .init(module: .blobs, version: 1, method: .upload)
        case .fetchAttachment: return .init(module: .blobs, version: 1, method: .fetch)
        case .registerFederationNode: return .init(module: .federation, version: 1, method: .register)
        case .listFederationNodes: return .init(module: .federation, version: 1, method: .list)
        case .getNoctwebNamespaceSnapshot:
            return .init(module: .federation, version: 1, method: .namespace)
        case .claimNoctwebNamespace:
            return .init(module: .federation, version: 1, method: .claim)
        case .rotateNoctwebNamespace:
            return .init(module: .federation, version: 1, method: .rotate)
        case .releaseNoctwebNamespace:
            return .init(module: .federation, version: 1, method: .release)
        case .forwardOpaqueRoute: return .init(module: .federationForward, version: 1, method: .forward)
        case .deliverOpaqueRoute: return .init(module: .federationForward, version: 1, method: .deliver)
        case .getFederatedNetHostObject: return .init(module: .federationForward, version: 1, method: .get)
        case .resolveFederatedNetHostName:
            return .init(
                module: .federationForward,
                version: 1,
                method: .resolve
            )
        case .publishDHTRecord: return .init(module: .openDiscovery, version: 1, method: .publishDHT)
        case .listDHTRecords: return .init(module: .openDiscovery, version: 1, method: .listDHT)
        case .netPassthrough: return .init(module: .netPassthrough, version: 1, method: .forward)
        case .putNetHostObject: return .init(module: .netHost, version: 1, method: .put)
        case .bindNetHostName:
            return .init(module: .netHost, version: 1, method: .bind)
        case .getNetHostObject: return .init(module: .netHost, version: 1, method: .get)
        case .resolveNetHostName:
            return .init(module: .netHost, version: 1, method: .resolve)
        case .hasNetHostObject: return .init(module: .netHost, version: 1, method: .has)
        case .releaseNetHostObject: return .init(module: .netHost, version: 1, method: .release)
        case .createNoctwebDatabase: return .init(module: .noctwebData, version: 1, method: .create)
        case .registerNoctwebAccount: return .init(module: .noctwebData, version: 1, method: .register)
        case .putNoctwebRecord: return .init(module: .noctwebData, version: 1, method: .put)
        case .getNoctwebRecord: return .init(module: .noctwebData, version: 1, method: .get)
        case .listNoctwebRecords: return .init(module: .noctwebData, version: 1, method: .list)
        case .deleteNoctwebRecord: return .init(module: .noctwebData, version: 1, method: .delete)
        case .createRealtimeRoute: return .init(module: .realtimeRoute, version: 1, method: .create)
        case .appendRealtimeRoute: return .init(module: .realtimeRoute, version: 1, method: .append)
        case .subscribeRealtimeRoute: return .init(module: .realtimeRoute, version: 1, method: .subscribe)
        case .syncRealtimeRoute: return .init(module: .realtimeRoute, version: 1, method: .sync)
        case .unsubscribeRealtimeRoute: return .init(module: .realtimeRoute, version: 1, method: .unsubscribe)
        case .createSharedLog: return .init(module: .sharedLog, version: 1, method: .create)
        case .appendSharedLog: return .init(module: .sharedLog, version: 1, method: .append)
        case .syncSharedLog: return .init(module: .sharedLog, version: 1, method: .sync)
        case .acquirePresence: return .init(module: .ephemeralPresence, version: 1, method: .acquire)
        case .renewPresence: return .init(module: .ephemeralPresence, version: 1, method: .renewLease)
        case .releasePresence: return .init(module: .ephemeralPresence, version: 1, method: .release)
        case .listPresence: return .init(module: .ephemeralPresence, version: 1, method: .list)
        case .createMediaBlob: return .init(module: .mediaBlobs, version: 1, method: .create)
        case .uploadMediaBlob: return .init(module: .mediaBlobs, version: 1, method: .upload)
        case .fetchMediaBlob: return .init(module: .mediaBlobs, version: 1, method: .fetch)
        case .releaseMediaBlob: return .init(module: .mediaBlobs, version: 1, method: .release)
        case .acquireICECredentials: return .init(module: .iceService, version: 1, method: .acquire)
        }
    }

    static func decode(for binding: RelayOperationBinding, from decoder: Decoder) throws -> RelayRequestBody {
        switch (binding.module, binding.method) {
        case (.core, .health), (.core, .info):
            try relayRequireExactObject(decoder, keys: [])
            return .empty
        case (.opaqueRoute, .create):
            return .createOpaqueRoute(try relayDecodeExact(OpaqueRouteCreateSubmissionV2.self, from: decoder, keys: ["request", "renewCapability"]))
        case (.opaqueRoute, .renew):
            return .renewOpaqueRoute(try relayDecodeExact(OpaqueRouteRenewSubmissionV2.self, from: decoder, keys: ["request", "renewCapability"]))
        case (.opaqueRoute, .teardown):
            return .teardownOpaqueRoute(try relayDecodeExact(OpaqueRouteTeardownSubmissionV2.self, from: decoder, keys: ["request", "teardownCapability"]))
        case (.opaqueRoute, .append):
            return .appendOpaqueRoute(try relayDecodeExact(OpaqueRouteAppendSubmissionV2.self, from: decoder, keys: ["packet", "sendCapability"]))
        case (.opaqueRoute, .sync):
            return .syncOpaqueRoute(try relayDecodeExact(OpaqueRouteSyncSubmissionV2.self, from: decoder, keys: ["request", "readCredential"]))
        case (.opaqueRoute, .commit):
            return .commitOpaqueRoute(try relayDecodeExact(OpaqueRouteCommitSubmissionV2.self, from: decoder, keys: ["request", "readCredential"]))
        case (.rendezvousTransport, .register):
            return .registerRendezvous(try relayDecodeExact(RegisterRendezvousTransportV2Request.self, from: decoder, keys: ["version", "routeCapability", "expiresAt", "lanes"]))
        case (.rendezvousTransport, .append):
            return .appendRendezvous(try relayDecodeExact(AppendRendezvousTransportV2Request.self, from: decoder, keys: ["routeCapability", "laneId", "publishCapability", "frame"]))
        case (.rendezvousTransport, .sync):
            return .syncRendezvous(try relayDecodeExact(SyncRendezvousTransportV2Request.self, from: decoder, keys: ["routeCapability", "laneId", "readCapability", "afterSequence", "maxCount"]))
        case (.rendezvousTransport, .delete):
            return .deleteRendezvous(try relayDecodeExact(DeleteRendezvousTransportV2Request.self, from: decoder, keys: ["routeCapability", "laneId", "deleteCapability"]))
        case (.blobs, .upload):
            return .uploadAttachment(try relayDecodeExact(UploadAttachmentRequest.self, from: decoder, keys: ["attachmentId", "chunkIndex", "payload", "ttlSeconds", "idempotencyKey"]))
        case (.blobs, .fetch):
            return .fetchAttachment(try relayDecodeExact(FetchAttachmentRequest.self, from: decoder, keys: ["attachmentId", "chunkIndex"]))
        case (.federation, .register):
            return .registerFederationNode(try relayDecodeExact(FederationNodeRegistrationRequest.self, from: decoder, keys: ["endpoint", "relayInfo", "ttlSeconds"]))
        case (.federation, .list):
            return .listFederationNodes(try relayDecodeExact(ListFederationNodesRequest.self, from: decoder, keys: ["mode", "federationName", "onlyHealthy", "maxStalenessSeconds", "requireSignedSnapshot"]))
        case (.federation, .namespace):
            return .getNoctwebNamespaceSnapshot(try relayDecodeExact(
                NoctwebNamespaceSnapshotRequestV1.self,
                from: decoder,
                keys: ["version", "federationMode", "federationName"]
            ))
        case (.federation, .claim):
            return .claimNoctwebNamespace(try relayDecodeExact(
                NoctwebNamespaceClaimRequestV1.self,
                from: decoder,
                keys: ["identity"]
            ))
        case (.federation, .rotate):
            return .rotateNoctwebNamespace(try relayDecodeExact(
                NoctwebNamespaceRotationRequestV1.self,
                from: decoder,
                keys: ["rotation", "newIdentity"]
            ))
        case (.federation, .release):
            return .releaseNoctwebNamespace(try relayDecodeExact(
                NoctwebNamespaceReleaseV1.self,
                from: decoder,
                keys: [
                    "version",
                    "suffix",
                    "ownerRelayID",
                    "sequence",
                    "issuedAt",
                    "signatureAlgorithm",
                    "signature"
                ]
            ))
        case (.federationForward, .forward):
            return .forwardOpaqueRoute(try relayDecodeExact(
                FederatedOpaqueRouteForwardRequestV1.self,
                from: decoder,
                keys: ["destinationRelayID", "destination", "append"]
            ))
        case (.federationForward, .deliver):
            return .deliverOpaqueRoute(try relayDecodeExact(
                FederatedOpaqueRouteDeliveryV1.self,
                from: decoder,
                keys: [
                    "version",
                    "deliveryID",
                    "sourceIdentity",
                    "destinationRelayID",
                    "append",
                    "issuedAt",
                    "expiresAt",
                    "signatureAlgorithm",
                    "signature"
                ]
            ))
        case (.federationForward, .get):
            return .getFederatedNetHostObject(try relayDecodeExact(
                FederatedNetHostReadRequestV1.self,
                from: decoder,
                keys: ["destinationRelayID", "destination", "request"]
            ))
        case (.federationForward, .resolve):
            return .resolveFederatedNetHostName(try relayDecodeExact(
                FederatedNetHostNameReadRequestV1.self,
                from: decoder,
                keys: ["destinationRelayID", "destination", "request"]
            ))
        case (.openDiscovery, .publishDHT):
            return .publishDHTRecord(try relayDecodeExact(PublishOpenFederationDHTRecordRequest.self, from: decoder, keys: ["namespace", "record"]))
        case (.openDiscovery, .listDHT):
            return .listDHTRecords(try relayDecodeExact(ListOpenFederationDHTRecordsRequest.self, from: decoder, keys: ["namespace", "limit"]))
        case (.netPassthrough, .forward):
            return .netPassthrough(try relayDecodeExact(
                NoctweaveNetPassthroughRequest.self,
                from: decoder,
                keys: ["destination", "payload"]
            ))
        case (.netHost, .put):
            return .putNetHostObject(try relayDecodeExact(
                NoctweaveNetHostPutRequest.self,
                from: decoder,
                keys: ["objectID", "payload", "ttlSeconds", "releaseCapabilityDigest", "idempotencyKey"]
            ))
        case (.netHost, .bind):
            return .bindNetHostName(try relayDecodeExact(
                NoctweaveNetHostNameBindingRequestV1.self,
                from: decoder,
                keys: [
                    "version",
                    "relaySuffix",
                    "siteLabel",
                    "objectID",
                    "publisherID",
                    "headID",
                    "revision",
                    "previousObjectID",
                    "idempotencyKey"
                ]
            ))
        case (.netHost, .get):
            return .getNetHostObject(try relayDecodeExact(
                NoctweaveNetHostObjectRequest.self,
                from: decoder,
                keys: ["objectID"]
            ))
        case (.netHost, .resolve):
            return .resolveNetHostName(try relayDecodeExact(
                NoctweaveNetHostNameRequestV1.self,
                from: decoder,
                keys: ["version", "relaySuffix", "siteLabel"]
            ))
        case (.netHost, .has):
            return .hasNetHostObject(try relayDecodeExact(
                NoctweaveNetHostObjectRequest.self,
                from: decoder,
                keys: ["objectID"]
            ))
        case (.netHost, .release):
            return .releaseNetHostObject(try relayDecodeExact(
                NoctweaveNetHostReleaseRequest.self,
                from: decoder,
                keys: ["objectID", "releaseCapability"]
            ))
        case (.noctwebData, .create):
            return .createNoctwebDatabase(try relayDecodeSingle(NoctwebDataDatabaseCreateRequestV1.self, from: decoder, key: "request"))
        case (.noctwebData, .register):
            return .registerNoctwebAccount(try relayDecodeSingle(NoctwebDataAccountRegisterRequestV1.self, from: decoder, key: "request"))
        case (.noctwebData, .put):
            return .putNoctwebRecord(try relayDecodeSingle(NoctwebDataRecordPutRequestV1.self, from: decoder, key: "request"))
        case (.noctwebData, .get):
            return .getNoctwebRecord(try relayDecodeSingle(NoctwebDataRecordGetRequestV1.self, from: decoder, key: "request"))
        case (.noctwebData, .list):
            return .listNoctwebRecords(try relayDecodeSingle(NoctwebDataRecordListRequestV1.self, from: decoder, key: "request"))
        case (.noctwebData, .delete):
            return .deleteNoctwebRecord(try relayDecodeSingle(NoctwebDataRecordDeleteRequestV1.self, from: decoder, key: "request"))
        case (.realtimeRoute, .create):
            return .createRealtimeRoute(try relayDecodeSingle(RealtimeRouteCreateRequestV1.self, from: decoder, key: "request"))
        case (.realtimeRoute, .append):
            return .appendRealtimeRoute(try relayDecodeSingle(RealtimeRouteAppendRequestV1.self, from: decoder, key: "request"))
        case (.realtimeRoute, .subscribe):
            return .subscribeRealtimeRoute(try relayDecodeSingle(RealtimeRouteSubscribeRequestV1.self, from: decoder, key: "request"))
        case (.realtimeRoute, .sync):
            return .syncRealtimeRoute(try relayDecodeSingle(RealtimeRouteSyncRequestV1.self, from: decoder, key: "request"))
        case (.realtimeRoute, .unsubscribe):
            return .unsubscribeRealtimeRoute(try relayDecodeSingle(RealtimeRouteUnsubscribeRequestV1.self, from: decoder, key: "request"))
        case (.sharedLog, .create):
            return .createSharedLog(try relayDecodeSingle(SharedLogCreateRequestV1.self, from: decoder, key: "request"))
        case (.sharedLog, .append):
            return .appendSharedLog(try relayDecodeSingle(SharedLogAppendRequestV1.self, from: decoder, key: "request"))
        case (.sharedLog, .sync):
            return .syncSharedLog(try relayDecodeSingle(SharedLogSyncRequestV1.self, from: decoder, key: "request"))
        case (.ephemeralPresence, .acquire):
            return .acquirePresence(try relayDecodeSingle(PresenceLeaseAcquireRequestV1.self, from: decoder, key: "request"))
        case (.ephemeralPresence, .renewLease):
            return .renewPresence(try relayDecodeSingle(PresenceLeaseRenewRequestV1.self, from: decoder, key: "request"))
        case (.ephemeralPresence, .release):
            return .releasePresence(try relayDecodeSingle(PresenceLeaseReleaseRequestV1.self, from: decoder, key: "request"))
        case (.ephemeralPresence, .list):
            return .listPresence(try relayDecodeSingle(PresenceLeaseListRequestV1.self, from: decoder, key: "request"))
        case (.mediaBlobs, .create):
            return .createMediaBlob(try relayDecodeSingle(MediaBlobCreateRequestV1.self, from: decoder, key: "request"))
        case (.mediaBlobs, .upload):
            return .uploadMediaBlob(try relayDecodeSingle(MediaBlobUploadRequestV1.self, from: decoder, key: "request"))
        case (.mediaBlobs, .fetch):
            return .fetchMediaBlob(try relayDecodeSingle(MediaBlobFetchRequestV1.self, from: decoder, key: "request"))
        case (.mediaBlobs, .release):
            return .releaseMediaBlob(try relayDecodeSingle(MediaBlobReleaseRequestV1.self, from: decoder, key: "request"))
        case (.iceService, .acquire):
            return .acquireICECredentials(try relayDecodeSingle(RelayICECredentialRequestV1.self, from: decoder, key: "request"))
        default:
            throw relayWireError(decoder, "Relay binding does not identify a current request body")
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RelayWireCodingKey.self)
        switch self {
        case .empty:
            break
        case .createOpaqueRoute(let value):
            try container.encode(value.request, forKey: relayWireKey("request"))
            try container.encode(value.renewCapability, forKey: relayWireKey("renewCapability"))
        case .renewOpaqueRoute(let value):
            try container.encode(value.request, forKey: relayWireKey("request"))
            try container.encode(value.renewCapability, forKey: relayWireKey("renewCapability"))
        case .teardownOpaqueRoute(let value):
            try container.encode(value.request, forKey: relayWireKey("request"))
            try container.encode(value.teardownCapability, forKey: relayWireKey("teardownCapability"))
        case .appendOpaqueRoute(let value):
            try container.encode(value.packet, forKey: relayWireKey("packet"))
            try container.encode(value.sendCapability, forKey: relayWireKey("sendCapability"))
        case .syncOpaqueRoute(let value):
            try container.encode(value.request, forKey: relayWireKey("request"))
            try container.encode(value.readCredential, forKey: relayWireKey("readCredential"))
        case .commitOpaqueRoute(let value):
            try container.encode(value.request, forKey: relayWireKey("request"))
            try container.encode(value.readCredential, forKey: relayWireKey("readCredential"))
        case .registerRendezvous(let value):
            try container.encode(value.version, forKey: relayWireKey("version"))
            try container.encode(value.routeCapability, forKey: relayWireKey("routeCapability"))
            try container.encode(value.expiresAt, forKey: relayWireKey("expiresAt"))
            try container.encode(value.lanes, forKey: relayWireKey("lanes"))
        case .appendRendezvous(let value):
            try container.encode(value.routeCapability, forKey: relayWireKey("routeCapability"))
            try container.encode(value.laneId, forKey: relayWireKey("laneId"))
            try container.encode(value.publishCapability, forKey: relayWireKey("publishCapability"))
            try container.encode(value.frame, forKey: relayWireKey("frame"))
        case .syncRendezvous(let value):
            try container.encode(value.routeCapability, forKey: relayWireKey("routeCapability"))
            try container.encode(value.laneId, forKey: relayWireKey("laneId"))
            try container.encode(value.readCapability, forKey: relayWireKey("readCapability"))
            try container.encode(value.afterSequence, forKey: relayWireKey("afterSequence"))
            try relayEncodeOptional(value.maxCount, key: "maxCount", into: &container)
        case .deleteRendezvous(let value):
            try container.encode(value.routeCapability, forKey: relayWireKey("routeCapability"))
            try container.encode(value.laneId, forKey: relayWireKey("laneId"))
            try container.encode(value.deleteCapability, forKey: relayWireKey("deleteCapability"))
        case .uploadAttachment(let value):
            try container.encode(value.attachmentId, forKey: relayWireKey("attachmentId"))
            try container.encode(value.chunkIndex, forKey: relayWireKey("chunkIndex"))
            try container.encode(value.payload, forKey: relayWireKey("payload"))
            try relayEncodeOptional(value.ttlSeconds, key: "ttlSeconds", into: &container)
            try container.encode(value.idempotencyKey, forKey: relayWireKey("idempotencyKey"))
        case .fetchAttachment(let value):
            try container.encode(value.attachmentId, forKey: relayWireKey("attachmentId"))
            try container.encode(value.chunkIndex, forKey: relayWireKey("chunkIndex"))
        case .registerFederationNode(let value):
            try container.encode(value.endpoint, forKey: relayWireKey("endpoint"))
            try container.encode(value.relayInfo, forKey: relayWireKey("relayInfo"))
            try relayEncodeOptional(value.ttlSeconds, key: "ttlSeconds", into: &container)
        case .listFederationNodes(let value):
            try relayEncodeOptional(value.mode, key: "mode", into: &container)
            try relayEncodeOptional(value.federationName, key: "federationName", into: &container)
            try relayEncodeOptional(value.onlyHealthy, key: "onlyHealthy", into: &container)
            try relayEncodeOptional(value.maxStalenessSeconds, key: "maxStalenessSeconds", into: &container)
            try relayEncodeOptional(value.requireSignedSnapshot, key: "requireSignedSnapshot", into: &container)
        case .getNoctwebNamespaceSnapshot(let value):
            try container.encode(value.version, forKey: relayWireKey("version"))
            try container.encode(
                value.federationMode,
                forKey: relayWireKey("federationMode")
            )
            try relayEncodeOptional(
                value.federationName,
                key: "federationName",
                into: &container
            )
        case .claimNoctwebNamespace(let value):
            try container.encode(
                value.identity,
                forKey: relayWireKey("identity")
            )
        case .rotateNoctwebNamespace(let value):
            try container.encode(
                value.rotation,
                forKey: relayWireKey("rotation")
            )
            try container.encode(
                value.newIdentity,
                forKey: relayWireKey("newIdentity")
            )
        case .releaseNoctwebNamespace(let value):
            try container.encode(value.version, forKey: relayWireKey("version"))
            try container.encode(value.suffix, forKey: relayWireKey("suffix"))
            try container.encode(
                value.ownerRelayID,
                forKey: relayWireKey("ownerRelayID")
            )
            try container.encode(value.sequence, forKey: relayWireKey("sequence"))
            try container.encode(value.issuedAt, forKey: relayWireKey("issuedAt"))
            try container.encode(
                value.signatureAlgorithm,
                forKey: relayWireKey("signatureAlgorithm")
            )
            try container.encode(value.signature, forKey: relayWireKey("signature"))
        case .forwardOpaqueRoute(let value):
            try container.encode(value.destinationRelayID, forKey: relayWireKey("destinationRelayID"))
            try container.encode(value.destination, forKey: relayWireKey("destination"))
            try container.encode(value.append, forKey: relayWireKey("append"))
        case .deliverOpaqueRoute(let value):
            try container.encode(value.version, forKey: relayWireKey("version"))
            try container.encode(value.deliveryID, forKey: relayWireKey("deliveryID"))
            try container.encode(value.sourceIdentity, forKey: relayWireKey("sourceIdentity"))
            try container.encode(value.destinationRelayID, forKey: relayWireKey("destinationRelayID"))
            try container.encode(value.append, forKey: relayWireKey("append"))
            try container.encode(value.issuedAt, forKey: relayWireKey("issuedAt"))
            try container.encode(value.expiresAt, forKey: relayWireKey("expiresAt"))
            try container.encode(value.signatureAlgorithm, forKey: relayWireKey("signatureAlgorithm"))
            try container.encode(value.signature, forKey: relayWireKey("signature"))
        case .getFederatedNetHostObject(let value):
            try container.encode(value.destinationRelayID, forKey: relayWireKey("destinationRelayID"))
            try container.encode(value.destination, forKey: relayWireKey("destination"))
            try container.encode(value.request, forKey: relayWireKey("request"))
        case .resolveFederatedNetHostName(let value):
            try container.encode(
                value.destinationRelayID,
                forKey: relayWireKey("destinationRelayID")
            )
            try container.encode(
                value.destination,
                forKey: relayWireKey("destination")
            )
            try container.encode(
                value.request,
                forKey: relayWireKey("request")
            )
        case .publishDHTRecord(let value):
            try container.encode(value.namespace, forKey: relayWireKey("namespace"))
            try container.encode(value.record, forKey: relayWireKey("record"))
        case .listDHTRecords(let value):
            try container.encode(value.namespace, forKey: relayWireKey("namespace"))
            try relayEncodeOptional(value.limit, key: "limit", into: &container)
        case .netPassthrough(let value):
            try container.encode(value.destination, forKey: relayWireKey("destination"))
            try container.encode(value.payload, forKey: relayWireKey("payload"))
        case .putNetHostObject(let value):
            try container.encode(value.objectID, forKey: relayWireKey("objectID"))
            try container.encode(value.payload, forKey: relayWireKey("payload"))
            try relayEncodeOptional(value.ttlSeconds, key: "ttlSeconds", into: &container)
            try container.encode(value.releaseCapabilityDigest, forKey: relayWireKey("releaseCapabilityDigest"))
            try container.encode(value.idempotencyKey, forKey: relayWireKey("idempotencyKey"))
        case .bindNetHostName(let value):
            try container.encode(value.version, forKey: relayWireKey("version"))
            try container.encode(
                value.relaySuffix,
                forKey: relayWireKey("relaySuffix")
            )
            try container.encode(
                value.siteLabel,
                forKey: relayWireKey("siteLabel")
            )
            try container.encode(value.objectID, forKey: relayWireKey("objectID"))
            try container.encode(
                value.publisherID,
                forKey: relayWireKey("publisherID")
            )
            try relayEncodeOptional(value.headID, key: "headID", into: &container)
            try container.encode(value.revision, forKey: relayWireKey("revision"))
            try relayEncodeOptional(
                value.previousObjectID,
                key: "previousObjectID",
                into: &container
            )
            try container.encode(
                value.idempotencyKey,
                forKey: relayWireKey("idempotencyKey")
            )
        case .getNetHostObject(let value), .hasNetHostObject(let value):
            try container.encode(value.objectID, forKey: relayWireKey("objectID"))
        case .resolveNetHostName(let value):
            try container.encode(value.version, forKey: relayWireKey("version"))
            try container.encode(
                value.relaySuffix,
                forKey: relayWireKey("relaySuffix")
            )
            try container.encode(
                value.siteLabel,
                forKey: relayWireKey("siteLabel")
            )
        case .releaseNetHostObject(let value):
            try container.encode(value.objectID, forKey: relayWireKey("objectID"))
            try container.encode(value.releaseCapability, forKey: relayWireKey("releaseCapability"))
        case .createNoctwebDatabase(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .registerNoctwebAccount(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .putNoctwebRecord(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .getNoctwebRecord(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .listNoctwebRecords(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .deleteNoctwebRecord(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .createRealtimeRoute(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .appendRealtimeRoute(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .subscribeRealtimeRoute(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .syncRealtimeRoute(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .unsubscribeRealtimeRoute(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .createSharedLog(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .appendSharedLog(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .syncSharedLog(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .acquirePresence(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .renewPresence(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .releasePresence(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .listPresence(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .createMediaBlob(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .uploadMediaBlob(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .fetchMediaBlob(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .releaseMediaBlob(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        case .acquireICECredentials(let value):
            try container.encode(value, forKey: relayWireKey("request"))
        }
    }
}

struct RelayRequest: Codable, Equatable {
    let requestID: UUID
    let module: RelayModuleID
    let version: Int
    let method: RelayMethodID
    let body: RelayRequestBody
    let authToken: String?

    var binding: RelayOperationBinding { .init(module: module, version: version, method: method) }

    private init(requestID: UUID = UUID(), binding: RelayOperationBinding, body: RelayRequestBody, authToken: String? = nil) {
        self.requestID = requestID
        module = binding.module
        version = binding.version
        method = binding.method
        self.body = body
        self.authToken = authToken
    }

    static func health(requestID: UUID = UUID()) -> RelayRequest {
        .init(requestID: requestID, binding: .init(module: .core, version: 2, method: .health), body: .empty)
    }

    static func info(requestID: UUID = UUID()) -> RelayRequest {
        .init(requestID: requestID, binding: .init(module: .core, version: 2, method: .info), body: .empty)
    }

    static func createOpaqueRouteV2(_ value: OpaqueRouteCreateSubmissionV2) -> RelayRequest { make(.createOpaqueRoute(value)) }
    static func renewOpaqueRouteV2(_ value: OpaqueRouteRenewSubmissionV2) -> RelayRequest { make(.renewOpaqueRoute(value)) }
    static func teardownOpaqueRouteV2(_ value: OpaqueRouteTeardownSubmissionV2) -> RelayRequest { make(.teardownOpaqueRoute(value)) }
    static func appendOpaqueRouteV2(_ value: OpaqueRouteAppendSubmissionV2) -> RelayRequest { make(.appendOpaqueRoute(value)) }
    static func syncOpaqueRouteV2(_ value: OpaqueRouteSyncSubmissionV2) -> RelayRequest { make(.syncOpaqueRoute(value)) }
    static func commitOpaqueRouteV2(_ value: OpaqueRouteCommitSubmissionV2) -> RelayRequest { make(.commitOpaqueRoute(value)) }
    static func registerRendezvousTransportV2(_ value: RegisterRendezvousTransportV2Request) -> RelayRequest { make(.registerRendezvous(value)) }
    static func appendRendezvousTransportV2(_ value: AppendRendezvousTransportV2Request) -> RelayRequest { make(.appendRendezvous(value)) }
    static func syncRendezvousTransportV2(_ value: SyncRendezvousTransportV2Request) -> RelayRequest { make(.syncRendezvous(value)) }
    static func deleteRendezvousTransportV2(_ value: DeleteRendezvousTransportV2Request) -> RelayRequest { make(.deleteRendezvous(value)) }
    static func uploadAttachment(_ value: UploadAttachmentRequest) -> RelayRequest { make(.uploadAttachment(value)) }
    static func fetchAttachment(_ value: FetchAttachmentRequest) -> RelayRequest { make(.fetchAttachment(value)) }
    static func registerFederationNode(_ value: FederationNodeRegistrationRequest) -> RelayRequest { make(.registerFederationNode(value)) }
    static func listFederationNodes(_ value: ListFederationNodesRequest) -> RelayRequest { make(.listFederationNodes(value)) }
    static func getNoctwebNamespaceSnapshotV1(
        _ value: NoctwebNamespaceSnapshotRequestV1
    ) -> RelayRequest {
        make(.getNoctwebNamespaceSnapshot(value))
    }
    static func claimNoctwebNamespaceV1(
        _ value: NoctwebNamespaceClaimRequestV1
    ) -> RelayRequest {
        make(.claimNoctwebNamespace(value))
    }
    static func rotateNoctwebNamespaceV1(
        _ value: NoctwebNamespaceRotationRequestV1
    ) -> RelayRequest {
        make(.rotateNoctwebNamespace(value))
    }
    static func releaseNoctwebNamespaceV1(
        _ value: NoctwebNamespaceReleaseV1
    ) -> RelayRequest {
        make(.releaseNoctwebNamespace(value))
    }
    static func forwardOpaqueRouteV1(_ value: FederatedOpaqueRouteForwardRequestV1) -> RelayRequest { make(.forwardOpaqueRoute(value)) }
    static func deliverOpaqueRouteV1(_ value: FederatedOpaqueRouteDeliveryV1) -> RelayRequest { make(.deliverOpaqueRoute(value)) }
    static func getFederatedNetHostObjectV1(_ value: FederatedNetHostReadRequestV1) -> RelayRequest { make(.getFederatedNetHostObject(value)) }
    static func resolveFederatedNetHostNameV1(
        _ value: FederatedNetHostNameReadRequestV1
    ) -> RelayRequest {
        make(.resolveFederatedNetHostName(value))
    }
    static func publishOpenFederationDHTRecord(_ value: PublishOpenFederationDHTRecordRequest) -> RelayRequest { make(.publishDHTRecord(value)) }
    static func listOpenFederationDHTRecords(_ value: ListOpenFederationDHTRecordsRequest) -> RelayRequest { make(.listDHTRecords(value)) }
    static func netPassthrough(_ value: NoctweaveNetPassthroughRequest) -> RelayRequest { make(.netPassthrough(value)) }
    static func putNetHostObject(_ value: NoctweaveNetHostPutRequest) -> RelayRequest { make(.putNetHostObject(value)) }
    static func bindNetHostName(
        _ value: NoctweaveNetHostNameBindingRequestV1,
        authToken: String? = nil
    ) -> RelayRequest {
        make(.bindNetHostName(value)).withAuthToken(authToken)
    }
    static func getNetHostObject(_ value: NoctweaveNetHostObjectRequest) -> RelayRequest { make(.getNetHostObject(value)) }
    static func resolveNetHostName(
        _ value: NoctweaveNetHostNameRequestV1
    ) -> RelayRequest {
        make(.resolveNetHostName(value))
    }
    static func hasNetHostObject(_ value: NoctweaveNetHostObjectRequest) -> RelayRequest { make(.hasNetHostObject(value)) }
    static func releaseNetHostObject(_ value: NoctweaveNetHostReleaseRequest) -> RelayRequest { make(.releaseNetHostObject(value)) }
    static func createNoctwebDatabaseV1(_ value: NoctwebDataDatabaseCreateRequestV1) -> RelayRequest { make(.createNoctwebDatabase(value)) }
    static func registerNoctwebAccountV1(_ value: NoctwebDataAccountRegisterRequestV1) -> RelayRequest { make(.registerNoctwebAccount(value)) }
    static func putNoctwebRecordV1(_ value: NoctwebDataRecordPutRequestV1) -> RelayRequest { make(.putNoctwebRecord(value)) }
    static func getNoctwebRecordV1(_ value: NoctwebDataRecordGetRequestV1) -> RelayRequest { make(.getNoctwebRecord(value)) }
    static func listNoctwebRecordsV1(_ value: NoctwebDataRecordListRequestV1) -> RelayRequest { make(.listNoctwebRecords(value)) }
    static func deleteNoctwebRecordV1(_ value: NoctwebDataRecordDeleteRequestV1) -> RelayRequest { make(.deleteNoctwebRecord(value)) }
    static func createRealtimeRouteV1(_ value: RealtimeRouteCreateRequestV1) -> RelayRequest { make(.createRealtimeRoute(value)) }
    static func appendRealtimeRouteV1(_ value: RealtimeRouteAppendRequestV1) -> RelayRequest { make(.appendRealtimeRoute(value)) }
    static func subscribeRealtimeRouteV1(_ value: RealtimeRouteSubscribeRequestV1) -> RelayRequest { make(.subscribeRealtimeRoute(value)) }
    static func syncRealtimeRouteV1(_ value: RealtimeRouteSyncRequestV1) -> RelayRequest { make(.syncRealtimeRoute(value)) }
    static func unsubscribeRealtimeRouteV1(_ value: RealtimeRouteUnsubscribeRequestV1) -> RelayRequest { make(.unsubscribeRealtimeRoute(value)) }
    static func createSharedLogV1(_ value: SharedLogCreateRequestV1) -> RelayRequest { make(.createSharedLog(value)) }
    static func appendSharedLogV1(_ value: SharedLogAppendRequestV1) -> RelayRequest { make(.appendSharedLog(value)) }
    static func syncSharedLogV1(_ value: SharedLogSyncRequestV1) -> RelayRequest { make(.syncSharedLog(value)) }
    static func acquirePresenceV1(_ value: PresenceLeaseAcquireRequestV1) -> RelayRequest { make(.acquirePresence(value)) }
    static func renewPresenceV1(_ value: PresenceLeaseRenewRequestV1) -> RelayRequest { make(.renewPresence(value)) }
    static func releasePresenceV1(_ value: PresenceLeaseReleaseRequestV1) -> RelayRequest { make(.releasePresence(value)) }
    static func listPresenceV1(_ value: PresenceLeaseListRequestV1) -> RelayRequest { make(.listPresence(value)) }
    static func createMediaBlobV1(_ value: MediaBlobCreateRequestV1) -> RelayRequest { make(.createMediaBlob(value)) }
    static func uploadMediaBlobV1(_ value: MediaBlobUploadRequestV1) -> RelayRequest { make(.uploadMediaBlob(value)) }
    static func fetchMediaBlobV1(_ value: MediaBlobFetchRequestV1) -> RelayRequest { make(.fetchMediaBlob(value)) }
    static func releaseMediaBlobV1(_ value: MediaBlobReleaseRequestV1) -> RelayRequest { make(.releaseMediaBlob(value)) }
    static func acquireICECredentialsV1(_ value: RelayICECredentialRequestV1) -> RelayRequest { make(.acquireICECredentials(value)) }

    private static func make(_ body: RelayRequestBody) -> RelayRequest {
        .init(binding: body.binding, body: body)
    }

    func withAuthToken(_ token: String?) -> RelayRequest {
        .init(requestID: requestID, binding: binding, body: body, authToken: token)
    }

    init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: ["requestID", "module", "version", "method", "body", "authToken"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        requestID = try container.decode(UUID.self, forKey: .requestID)
        module = try container.decode(RelayModuleID.self, forKey: .module)
        version = try container.decode(Int.self, forKey: .version)
        method = try container.decode(RelayMethodID.self, forKey: .method)
        authToken = try container.decodeIfPresent(String.self, forKey: .authToken)
        let binding = RelayOperationBinding(module: module, version: version, method: method)
        guard binding.isCurrent else { throw relayWireError(decoder, "Unsupported relay binding") }
        body = try RelayRequestBody.decode(for: binding, from: container.superDecoder(forKey: .body))
        if case .empty = body {
            guard module == .core else { throw relayWireError(decoder, "Empty body is valid only for nw.core") }
        } else if body.binding != binding {
            throw relayWireError(decoder, "Relay body does not match its binding")
        }
        guard authToken.map({ !$0.isEmpty && $0.utf8.count <= 4_096 }) ?? true else {
            throw relayWireError(decoder, "Relay auth token is invalid")
        }
    }

    func encode(to encoder: Encoder) throws {
        guard binding.isCurrent else { throw relayWireError(encoder, "Cannot encode unsupported relay binding") }
        guard authToken.map({ !$0.isEmpty && $0.utf8.count <= 4_096 }) ?? true else {
            throw relayWireError(encoder, "Relay auth token is invalid")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(requestID, forKey: .requestID)
        try container.encode(module, forKey: .module)
        try container.encode(version, forKey: .version)
        try container.encode(method, forKey: .method)
        try body.encode(to: container.superEncoder(forKey: .body))
        if let authToken { try container.encode(authToken, forKey: .authToken) }
        else { try container.encodeNil(forKey: .authToken) }
    }

    private enum CodingKeys: String, CodingKey {
        case requestID, module, version, method, body, authToken
    }
}

enum RelayResponseStatus: String, Codable { case success, error }

enum RelayErrorCode: String, Codable, CaseIterable {
    case authenticationRequired = "authentication-required"
    case rateLimited = "rate-limited"
    case invalidRequest = "invalid-request"
    case unavailable
    case notFound = "not-found"
    case conflict
    case capacity
    case internalFailure = "internal-failure"
}

struct RelayErrorBody: Codable, Equatable {
    static let maximumMessageBytes = 512
    let code: RelayErrorCode
    let message: String
    let retryable: Bool

    init(code: RelayErrorCode, message: String, retryable: Bool = false) {
        self.code = code
        self.message = relayBoundedErrorMessage(message)
        self.retryable = retryable
    }

    init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: ["code", "message", "retryable"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        code = try container.decode(RelayErrorCode.self, forKey: .code)
        message = try container.decode(String.self, forKey: .message)
        retryable = try container.decode(Bool.self, forKey: .retryable)
        guard !message.isEmpty, message.utf8.count <= Self.maximumMessageBytes else {
            throw relayWireError(decoder, "Relay error message is outside bounds")
        }
    }

    private enum CodingKeys: String, CodingKey { case code, message, retryable }
}

struct FederationNodesResponseBody: Equatable {
    let nodes: [FederationNodeRecord]
    let snapshot: FederationDirectorySnapshot?

    init(nodes: [FederationNodeRecord], snapshot: FederationDirectorySnapshot? = nil) {
        self.nodes = nodes
        self.snapshot = snapshot
    }

    var isStructurallyValid: Bool {
        guard nodes.count <= 10_000,
              nodes.allSatisfy(\.isStructurallyValid),
              Set(nodes.map { relayWireEndpointKey($0.endpoint) }).count == nodes.count else {
            return false
        }
        return snapshot.map { $0.isStructurallyValid && $0.nodes == nodes } ?? true
    }
}

enum RelaySuccessBody: Equatable {
    case empty
    case relayInfo(RelayInfo)
    case opaqueRoute(OpaqueReceiveRouteV2)
    case opaqueRouteAppend(OpaqueRouteAppendReceiptV2)
    case opaqueRouteSync(OpaqueRouteSyncResponseV2)
    case opaqueRouteCommit(OpaqueRouteCommitResponseV2)
    case rendezvousSync(RendezvousRelaySyncBatchV2)
    case realtimeRouteCreated(RealtimeRouteCreatedV1)
    case realtimeRouteAppend(RealtimeRouteAppendReceiptV1)
    case realtimeRouteSubscription(RealtimeRouteSubscriptionV1)
    case realtimeRouteSync(OpaqueRelaySyncBatchV1)
    case sharedLogCreated(SharedLogCreatedV1)
    case sharedLogAppend(SharedLogAppendReceiptV1)
    case sharedLogSync(OpaqueRelaySyncBatchV1)
    case presenceLease(PresenceLeaseV1)
    case presenceLeases([PresenceLeaseV1])
    case mediaBlobCreated(MediaBlobCreatedV1)
    case mediaBlobChunk(MediaBlobChunkV1)
    case iceCredentials(RelayICECredentialsV1)
    case attachment(AttachmentChunk)
    case federationNodes(FederationNodesResponseBody)
    case noctwebNamespaceSnapshot(NoctwebNamespaceSnapshotV1)
    case noctwebNamespaceRecord(NoctwebNamespaceRecordV1)
    case dhtRecords([OpenFederationDHTRecord])
    case netPassthrough(NoctweaveNetPassthroughResponse)
    case netHostReceipt(NoctweaveNetHostingReceipt)
    case netHostObject(NoctweaveNetHostFetchResponse)
    case federatedNetHostObject(FederatedNetHostObjectResponseV1)
    case netHostNameResolution(NoctweaveNetHostNameResolutionV1)
    case federatedNetHostNameResolution(FederatedNetHostNameResponseV1)
    case netHostPresence(NoctweaveNetHostPresence)
    case netHostRelease(NoctweaveNetHostReleaseReceipt)
    case noctwebDatabase(NoctwebDataDatabaseReceiptV1)
    case noctwebAccount(NoctwebDataAccountReceiptV1)
    case noctwebRecord(NoctwebDataRecordV1)
    case noctwebRecords(NoctwebDataRecordListV1)
    case noctwebDelete(NoctwebDataDeleteReceiptV1)

    func supports(_ binding: RelayOperationBinding) -> Bool {
        switch self {
        case .empty:
            return binding == .init(module: .core, version: 2, method: .health)
                || binding == .init(module: .rendezvousTransport, version: 2, method: .register)
                || binding == .init(module: .rendezvousTransport, version: 2, method: .append)
                || binding == .init(module: .rendezvousTransport, version: 2, method: .delete)
                || binding == .init(module: .openDiscovery, version: 1, method: .publishDHT)
                || binding == .init(module: .realtimeRoute, version: 1, method: .unsubscribe)
                || binding == .init(module: .ephemeralPresence, version: 1, method: .release)
                || binding == .init(module: .mediaBlobs, version: 1, method: .release)
        case .relayInfo: return binding == .init(module: .core, version: 2, method: .info)
        case .opaqueRoute: return binding.module == .opaqueRoute && binding.version == 2 && [.create, .renew, .teardown].contains(binding.method)
        case .opaqueRouteAppend:
            return binding == .init(module: .opaqueRoute, version: 2, method: .append)
                || binding == .init(module: .federationForward, version: 1, method: .forward)
                || binding == .init(module: .federationForward, version: 1, method: .deliver)
        case .opaqueRouteSync: return binding == .init(module: .opaqueRoute, version: 2, method: .sync)
        case .opaqueRouteCommit: return binding == .init(module: .opaqueRoute, version: 2, method: .commit)
        case .rendezvousSync: return binding == .init(module: .rendezvousTransport, version: 2, method: .sync)
        case .realtimeRouteCreated: return binding == .init(module: .realtimeRoute, version: 1, method: .create)
        case .realtimeRouteAppend: return binding == .init(module: .realtimeRoute, version: 1, method: .append)
        case .realtimeRouteSubscription: return binding == .init(module: .realtimeRoute, version: 1, method: .subscribe)
        case .realtimeRouteSync: return binding == .init(module: .realtimeRoute, version: 1, method: .sync)
        case .sharedLogCreated: return binding == .init(module: .sharedLog, version: 1, method: .create)
        case .sharedLogAppend: return binding == .init(module: .sharedLog, version: 1, method: .append)
        case .sharedLogSync: return binding == .init(module: .sharedLog, version: 1, method: .sync)
        case .presenceLease: return binding == .init(module: .ephemeralPresence, version: 1, method: .acquire) || binding == .init(module: .ephemeralPresence, version: 1, method: .renewLease)
        case .presenceLeases: return binding == .init(module: .ephemeralPresence, version: 1, method: .list)
        case .mediaBlobCreated: return binding == .init(module: .mediaBlobs, version: 1, method: .create)
        case .mediaBlobChunk: return binding == .init(module: .mediaBlobs, version: 1, method: .upload) || binding == .init(module: .mediaBlobs, version: 1, method: .fetch)
        case .iceCredentials: return binding == .init(module: .iceService, version: 1, method: .acquire)
        case .attachment: return binding.module == .blobs && binding.version == 1 && [.upload, .fetch].contains(binding.method)
        case .federationNodes: return binding.module == .federation && binding.version == 1 && [.register, .list].contains(binding.method)
        case .noctwebNamespaceSnapshot:
            return binding == .init(
                module: .federation,
                version: 1,
                method: .namespace
            )
        case .noctwebNamespaceRecord:
            return binding.module == .federation
                && binding.version == 1
                && [.claim, .rotate, .release].contains(
                    binding.method
                )
        case .dhtRecords: return binding == .init(module: .openDiscovery, version: 1, method: .listDHT)
        case .netPassthrough: return binding == .init(module: .netPassthrough, version: 1, method: .forward)
        case .netHostReceipt: return binding == .init(module: .netHost, version: 1, method: .put)
        case .netHostObject: return binding == .init(module: .netHost, version: 1, method: .get)
        case .federatedNetHostObject:
            return binding == .init(module: .federationForward, version: 1, method: .get)
        case .netHostNameResolution:
            return binding == .init(
                module: .netHost,
                version: 1,
                method: .bind
            ) || binding == .init(
                module: .netHost,
                version: 1,
                method: .resolve
            )
        case .federatedNetHostNameResolution:
            return binding == .init(
                module: .federationForward,
                version: 1,
                method: .resolve
            )
        case .netHostPresence: return binding == .init(module: .netHost, version: 1, method: .has)
        case .netHostRelease: return binding == .init(module: .netHost, version: 1, method: .release)
        case .noctwebDatabase: return binding == .init(module: .noctwebData, version: 1, method: .create)
        case .noctwebAccount: return binding == .init(module: .noctwebData, version: 1, method: .register)
        case .noctwebRecord: return binding.module == .noctwebData && binding.version == 1 && [.put, .get].contains(binding.method)
        case .noctwebRecords: return binding == .init(module: .noctwebData, version: 1, method: .list)
        case .noctwebDelete: return binding == .init(module: .noctwebData, version: 1, method: .delete)
        }
    }

    static func decode(for binding: RelayOperationBinding, from decoder: Decoder) throws -> RelaySuccessBody {
        switch (binding.module, binding.method) {
        case (.core, .health), (.rendezvousTransport, .register), (.rendezvousTransport, .append), (.rendezvousTransport, .delete), (.openDiscovery, .publishDHT), (.realtimeRoute, .unsubscribe), (.ephemeralPresence, .release), (.mediaBlobs, .release):
            try relayRequireExactObject(decoder, keys: [])
            return .empty
        case (.core, .info):
            return .relayInfo(try relayDecodeSingle(RelayInfo.self, from: decoder, key: "relayInfo"))
        case (.opaqueRoute, .create), (.opaqueRoute, .renew), (.opaqueRoute, .teardown):
            return .opaqueRoute(try relayDecodeSingle(OpaqueReceiveRouteV2.self, from: decoder, key: "route"))
        case (.opaqueRoute, .append),
             (.federationForward, .forward),
             (.federationForward, .deliver):
            return .opaqueRouteAppend(try relayDecodeSingle(OpaqueRouteAppendReceiptV2.self, from: decoder, key: "receipt"))
        case (.opaqueRoute, .sync):
            return .opaqueRouteSync(try relayDecodeSingle(OpaqueRouteSyncResponseV2.self, from: decoder, key: "batch"))
        case (.opaqueRoute, .commit):
            return .opaqueRouteCommit(try relayDecodeSingle(OpaqueRouteCommitResponseV2.self, from: decoder, key: "commit"))
        case (.rendezvousTransport, .sync):
            return .rendezvousSync(try relayDecodeSingle(RendezvousRelaySyncBatchV2.self, from: decoder, key: "batch"))
        case (.realtimeRoute, .create):
            return .realtimeRouteCreated(try relayDecodeSingle(RealtimeRouteCreatedV1.self, from: decoder, key: "route"))
        case (.realtimeRoute, .append):
            return .realtimeRouteAppend(try relayDecodeSingle(RealtimeRouteAppendReceiptV1.self, from: decoder, key: "receipt"))
        case (.realtimeRoute, .subscribe):
            return .realtimeRouteSubscription(try relayDecodeSingle(RealtimeRouteSubscriptionV1.self, from: decoder, key: "subscription"))
        case (.realtimeRoute, .sync):
            return .realtimeRouteSync(try relayDecodeSingle(OpaqueRelaySyncBatchV1.self, from: decoder, key: "batch"))
        case (.sharedLog, .create):
            return .sharedLogCreated(try relayDecodeSingle(SharedLogCreatedV1.self, from: decoder, key: "log"))
        case (.sharedLog, .append):
            return .sharedLogAppend(try relayDecodeSingle(SharedLogAppendReceiptV1.self, from: decoder, key: "receipt"))
        case (.sharedLog, .sync):
            return .sharedLogSync(try relayDecodeSingle(OpaqueRelaySyncBatchV1.self, from: decoder, key: "batch"))
        case (.ephemeralPresence, .acquire), (.ephemeralPresence, .renewLease):
            return .presenceLease(try relayDecodeSingle(PresenceLeaseV1.self, from: decoder, key: "lease"))
        case (.ephemeralPresence, .list):
            return .presenceLeases(try relayDecodeSingle([PresenceLeaseV1].self, from: decoder, key: "leases"))
        case (.mediaBlobs, .create):
            return .mediaBlobCreated(try relayDecodeSingle(MediaBlobCreatedV1.self, from: decoder, key: "blob"))
        case (.mediaBlobs, .upload), (.mediaBlobs, .fetch):
            return .mediaBlobChunk(try relayDecodeSingle(MediaBlobChunkV1.self, from: decoder, key: "chunk"))
        case (.iceService, .acquire):
            return .iceCredentials(try relayDecodeSingle(RelayICECredentialsV1.self, from: decoder, key: "credentials"))
        case (.blobs, .upload), (.blobs, .fetch):
            return .attachment(try relayDecodeSingle(AttachmentChunk.self, from: decoder, key: "chunk"))
        case (.federation, .register), (.federation, .list):
            try relayRequireExactObject(decoder, keys: ["nodes", "snapshot"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            let value = FederationNodesResponseBody(
                nodes: try container.decode([FederationNodeRecord].self, forKey: relayWireKey("nodes")),
                snapshot: try container.decodeIfPresent(FederationDirectorySnapshot.self, forKey: relayWireKey("snapshot"))
            )
            guard value.isStructurallyValid else {
                throw relayWireError(decoder, "Federation nodes response is invalid")
            }
            return .federationNodes(value)
        case (.federation, .namespace):
            return .noctwebNamespaceSnapshot(try relayDecodeSingle(
                NoctwebNamespaceSnapshotV1.self,
                from: decoder,
                key: "namespaceSnapshot"
            ))
        case (.federation, .claim),
             (.federation, .rotate),
             (.federation, .release):
            return .noctwebNamespaceRecord(try relayDecodeSingle(
                NoctwebNamespaceRecordV1.self,
                from: decoder,
                key: "namespaceRecord"
            ))
        case (.openDiscovery, .listDHT):
            return .dhtRecords(try relayDecodeSingle([OpenFederationDHTRecord].self, from: decoder, key: "records"))
        case (.netPassthrough, .forward):
            return .netPassthrough(try relayDecodeSingle(
                NoctweaveNetPassthroughResponse.self,
                from: decoder,
                key: "passthrough"
            ))
        case (.netHost, .put):
            return .netHostReceipt(try relayDecodeSingle(
                NoctweaveNetHostingReceipt.self,
                from: decoder,
                key: "receipt"
            ))
        case (.netHost, .get):
            return .netHostObject(try relayDecodeSingle(
                NoctweaveNetHostFetchResponse.self,
                from: decoder,
                key: "object"
            ))
        case (.federationForward, .get):
            return .federatedNetHostObject(try relayDecodeSingle(
                FederatedNetHostObjectResponseV1.self,
                from: decoder,
                key: "federatedObject"
            ))
        case (.netHost, .bind), (.netHost, .resolve):
            return .netHostNameResolution(try relayDecodeSingle(
                NoctweaveNetHostNameResolutionV1.self,
                from: decoder,
                key: "nameResolution"
            ))
        case (.federationForward, .resolve):
            return .federatedNetHostNameResolution(
                try relayDecodeSingle(
                    FederatedNetHostNameResponseV1.self,
                    from: decoder,
                    key: "federatedNameResolution"
                )
            )
        case (.netHost, .has):
            return .netHostPresence(try relayDecodeSingle(
                NoctweaveNetHostPresence.self,
                from: decoder,
                key: "presence"
            ))
        case (.netHost, .release):
            return .netHostRelease(try relayDecodeSingle(
                NoctweaveNetHostReleaseReceipt.self,
                from: decoder,
                key: "release"
            ))
        case (.noctwebData, .create):
            return .noctwebDatabase(try relayDecodeSingle(NoctwebDataDatabaseReceiptV1.self, from: decoder, key: "database"))
        case (.noctwebData, .register):
            return .noctwebAccount(try relayDecodeSingle(NoctwebDataAccountReceiptV1.self, from: decoder, key: "account"))
        case (.noctwebData, .put), (.noctwebData, .get):
            return .noctwebRecord(try relayDecodeSingle(NoctwebDataRecordV1.self, from: decoder, key: "record"))
        case (.noctwebData, .list):
            return .noctwebRecords(try relayDecodeSingle(NoctwebDataRecordListV1.self, from: decoder, key: "records"))
        case (.noctwebData, .delete):
            return .noctwebDelete(try relayDecodeSingle(NoctwebDataDeleteReceiptV1.self, from: decoder, key: "deletion"))
        default:
            throw relayWireError(decoder, "Relay operation has no success body")
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RelayWireCodingKey.self)
        switch self {
        case .empty: break
        case .relayInfo(let value): try container.encode(value, forKey: relayWireKey("relayInfo"))
        case .opaqueRoute(let value): try container.encode(value, forKey: relayWireKey("route"))
        case .opaqueRouteAppend(let value): try container.encode(value, forKey: relayWireKey("receipt"))
        case .opaqueRouteSync(let value): try container.encode(value, forKey: relayWireKey("batch"))
        case .opaqueRouteCommit(let value): try container.encode(value, forKey: relayWireKey("commit"))
        case .rendezvousSync(let value): try container.encode(value, forKey: relayWireKey("batch"))
        case .realtimeRouteCreated(let value): try container.encode(value, forKey: relayWireKey("route"))
        case .realtimeRouteAppend(let value): try container.encode(value, forKey: relayWireKey("receipt"))
        case .realtimeRouteSubscription(let value): try container.encode(value, forKey: relayWireKey("subscription"))
        case .realtimeRouteSync(let value), .sharedLogSync(let value): try container.encode(value, forKey: relayWireKey("batch"))
        case .sharedLogCreated(let value): try container.encode(value, forKey: relayWireKey("log"))
        case .sharedLogAppend(let value): try container.encode(value, forKey: relayWireKey("receipt"))
        case .presenceLease(let value): try container.encode(value, forKey: relayWireKey("lease"))
        case .presenceLeases(let value): try container.encode(value, forKey: relayWireKey("leases"))
        case .mediaBlobCreated(let value): try container.encode(value, forKey: relayWireKey("blob"))
        case .mediaBlobChunk(let value): try container.encode(value, forKey: relayWireKey("chunk"))
        case .iceCredentials(let value): try container.encode(value, forKey: relayWireKey("credentials"))
        case .attachment(let value): try container.encode(value, forKey: relayWireKey("chunk"))
        case .federationNodes(let value):
            guard value.isStructurallyValid else {
                throw relayWireError(encoder, "Federation nodes response is invalid")
            }
            try container.encode(value.nodes, forKey: relayWireKey("nodes"))
            try relayEncodeOptional(value.snapshot, key: "snapshot", into: &container)
        case .noctwebNamespaceSnapshot(let value):
            try container.encode(
                value,
                forKey: relayWireKey("namespaceSnapshot")
            )
        case .noctwebNamespaceRecord(let value):
            try container.encode(
                value,
                forKey: relayWireKey("namespaceRecord")
            )
        case .dhtRecords(let value): try container.encode(value, forKey: relayWireKey("records"))
        case .netPassthrough(let value): try container.encode(value, forKey: relayWireKey("passthrough"))
        case .netHostReceipt(let value): try container.encode(value, forKey: relayWireKey("receipt"))
        case .netHostObject(let value): try container.encode(value, forKey: relayWireKey("object"))
        case .federatedNetHostObject(let value):
            try container.encode(value, forKey: relayWireKey("federatedObject"))
        case .netHostNameResolution(let value):
            try container.encode(
                value,
                forKey: relayWireKey("nameResolution")
            )
        case .federatedNetHostNameResolution(let value):
            try container.encode(
                value,
                forKey: relayWireKey("federatedNameResolution")
            )
        case .netHostPresence(let value): try container.encode(value, forKey: relayWireKey("presence"))
        case .netHostRelease(let value): try container.encode(value, forKey: relayWireKey("release"))
        case .noctwebDatabase(let value): try container.encode(value, forKey: relayWireKey("database"))
        case .noctwebAccount(let value): try container.encode(value, forKey: relayWireKey("account"))
        case .noctwebRecord(let value): try container.encode(value, forKey: relayWireKey("record"))
        case .noctwebRecords(let value): try container.encode(value, forKey: relayWireKey("records"))
        case .noctwebDelete(let value): try container.encode(value, forKey: relayWireKey("deletion"))
        }
    }
}

struct RelayResponse: Codable, Equatable {
    let requestID: UUID
    let module: RelayModuleID
    let version: Int
    let method: RelayMethodID
    let status: RelayResponseStatus
    let successBody: RelaySuccessBody?
    let error: RelayErrorBody?

    var binding: RelayOperationBinding { .init(module: module, version: version, method: method) }

    private init(request: RelayRequest, status: RelayResponseStatus, successBody: RelaySuccessBody?, error: RelayErrorBody?) {
        requestID = request.requestID
        module = request.module
        version = request.version
        method = request.method
        self.status = status
        self.successBody = successBody
        self.error = error
    }

    static func success(_ body: RelaySuccessBody, respondingTo request: RelayRequest) -> RelayResponse {
        precondition(body.supports(request.binding), "Success body does not match request binding")
        return .init(request: request, status: .success, successBody: body, error: nil)
    }

    static func error(_ message: String, code: RelayErrorCode = .invalidRequest, retryable: Bool = false, respondingTo request: RelayRequest) -> RelayResponse {
        .init(request: request, status: .error, successBody: nil, error: .init(code: code, message: message, retryable: retryable))
    }

    func isResponse(to request: RelayRequest) -> Bool { requestID == request.requestID && binding == request.binding }

    init(from decoder: Decoder) throws {
        try relayRequireExactObject(decoder, keys: ["requestID", "module", "version", "method", "status", "body", "error"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        requestID = try container.decode(UUID.self, forKey: .requestID)
        module = try container.decode(RelayModuleID.self, forKey: .module)
        version = try container.decode(Int.self, forKey: .version)
        method = try container.decode(RelayMethodID.self, forKey: .method)
        status = try container.decode(RelayResponseStatus.self, forKey: .status)
        let binding = RelayOperationBinding(module: module, version: version, method: method)
        guard binding.isCurrent else { throw relayWireError(decoder, "Unsupported response binding") }
        switch status {
        case .success:
            guard try container.decodeNil(forKey: .error) else { throw relayWireError(decoder, "Success response error must be null") }
            successBody = try RelaySuccessBody.decode(for: binding, from: container.superDecoder(forKey: .body))
            error = nil
        case .error:
            guard try container.decodeNil(forKey: .body) else { throw relayWireError(decoder, "Error response body must be null") }
            successBody = nil
            error = try container.decode(RelayErrorBody.self, forKey: .error)
        }
    }

    func encode(to encoder: Encoder) throws {
        guard binding.isCurrent else { throw relayWireError(encoder, "Cannot encode unsupported response binding") }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(requestID, forKey: .requestID)
        try container.encode(module, forKey: .module)
        try container.encode(version, forKey: .version)
        try container.encode(method, forKey: .method)
        try container.encode(status, forKey: .status)
        switch status {
        case .success:
            guard let successBody, error == nil, successBody.supports(binding) else { throw relayWireError(encoder, "Invalid success response state") }
            try successBody.encode(to: container.superEncoder(forKey: .body))
            try container.encodeNil(forKey: .error)
        case .error:
            guard successBody == nil, let error else { throw relayWireError(encoder, "Invalid error response state") }
            try container.encodeNil(forKey: .body)
            try container.encode(error, forKey: .error)
        }
    }

    private enum CodingKeys: String, CodingKey { case requestID, module, version, method, status, body, error }
}

private struct RelayWireCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?
    init?(stringValue: String) { self.stringValue = stringValue; intValue = nil }
    init?(intValue: Int) { stringValue = String(intValue); self.intValue = intValue }
}

private func relayWireKey(_ value: String) -> RelayWireCodingKey { RelayWireCodingKey(stringValue: value)! }

private func relayRequireExactObject(_ decoder: Decoder, keys: Set<String>) throws {
    let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == keys else {
        throw relayWireError(decoder, "Relay object fields do not match the current protocol exactly")
    }
}

private func relayDecodeExact<T: Decodable>(_ type: T.Type, from decoder: Decoder, keys: Set<String>) throws -> T {
    try relayRequireExactObject(decoder, keys: keys)
    return try T(from: decoder)
}

private func relayDecodeSingle<T: Decodable>(_ type: T.Type, from decoder: Decoder, key: String) throws -> T {
    try relayRequireExactObject(decoder, keys: [key])
    let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
    return try container.decode(T.self, forKey: relayWireKey(key))
}

private func relayWireEndpointKey(_ endpoint: RelayEndpoint) -> String {
    [
        endpoint.host.lowercased(),
        String(endpoint.port),
        endpoint.useTLS ? "1" : "0",
        endpoint.transport.rawValue
    ].joined(separator: "\u{0}")
}

private func relayEncodeOptional<T: Encodable>(_ value: T?, key: String, into container: inout KeyedEncodingContainer<RelayWireCodingKey>) throws {
    if let value { try container.encode(value, forKey: relayWireKey(key)) }
    else { try container.encodeNil(forKey: relayWireKey(key)) }
}

private func relayBoundedErrorMessage(_ message: String) -> String {
    let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty, trimmed.utf8.count <= RelayErrorBody.maximumMessageBytes else { return "Relay request failed" }
    return trimmed
}

private func relayWireError(_ decoder: Decoder, _ description: String) -> DecodingError {
    .dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: description))
}

private func relayWireError(_ encoder: Encoder, _ description: String) -> EncodingError {
    .invalidValue(description, .init(codingPath: encoder.codingPath, debugDescription: description))
}

extension RelayCodec {
    /// Decodes relay wire JSON only after validating the raw object structure.
    ///
    /// Foundation's `JSONDecoder` collapses duplicate object members before a
    /// `Decodable` implementation can inspect them. Protocol inputs must use
    /// this entry point so an attacker cannot smuggle conflicting values under
    /// repeated or escape-equivalent member names.
    static func decodeWire<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try preflightJSON(data)
        return try decoder().decode(type, from: data)
    }

    static func preflightJSON(_ data: Data) throws {
        var validator = RelayRawJSONValidator(data: data)
        try validator.validate()
    }
}

private struct RelayRawJSONValidator {
    private static let maximumNestingDepth = 128

    private let bytes: [UInt8]
    private var index: Int

    init(data: Data) {
        bytes = Array(data)
        index = 0
    }

    mutating func validate() throws {
        guard String(bytes: bytes, encoding: .utf8) != nil else {
            throw error("Relay JSON is not valid UTF-8")
        }
        skipWhitespace()
        try parseValue(containerDepth: 0)
        skipWhitespace()
        guard index == bytes.count else {
            throw error("Relay JSON contains trailing data")
        }
    }

    private mutating func parseValue(containerDepth: Int) throws {
        guard index < bytes.count else { throw error("Relay JSON ended before a value") }
        switch bytes[index] {
        case 0x7B: // {
            try enterContainer(from: containerDepth)
            try parseObject(depth: containerDepth + 1)
        case 0x5B: // [
            try enterContainer(from: containerDepth)
            try parseArray(depth: containerDepth + 1)
        case 0x22: // "
            _ = try consumeString()
        case 0x74: // true
            try consumeLiteral([0x74, 0x72, 0x75, 0x65])
        case 0x66: // false
            try consumeLiteral([0x66, 0x61, 0x6C, 0x73, 0x65])
        case 0x6E: // null
            try consumeLiteral([0x6E, 0x75, 0x6C, 0x6C])
        case 0x2D, 0x30...0x39: // - or digit
            try consumeNumber()
        default:
            throw error("Relay JSON contains an invalid value")
        }
    }

    private mutating func enterContainer(from depth: Int) throws {
        guard depth < Self.maximumNestingDepth else {
            throw error("Relay JSON exceeds the maximum nesting depth")
        }
    }

    private mutating func parseObject(depth: Int) throws {
        index += 1
        skipWhitespace()
        if consume(0x7D) { return }

        var memberNames = Set<String>()
        while true {
            guard index < bytes.count, bytes[index] == 0x22 else {
                throw error("Relay JSON object member name is invalid")
            }
            let nameRange = try consumeString()
            let nameData = Data(bytes[nameRange])
            guard let name = try? JSONSerialization.jsonObject(
                with: nameData,
                options: [.fragmentsAllowed]
            ) as? String else {
                throw error("Relay JSON object member name is invalid")
            }
            guard memberNames.insert(name).inserted else {
                throw error("Relay JSON contains a duplicate object member")
            }

            skipWhitespace()
            guard consume(0x3A) else { throw error("Relay JSON object is missing a colon") }
            skipWhitespace()
            try parseValue(containerDepth: depth)
            skipWhitespace()
            if consume(0x7D) { return }
            guard consume(0x2C) else { throw error("Relay JSON object is missing a comma") }
            skipWhitespace()
        }
    }

    private mutating func parseArray(depth: Int) throws {
        index += 1
        skipWhitespace()
        if consume(0x5D) { return }

        while true {
            try parseValue(containerDepth: depth)
            skipWhitespace()
            if consume(0x5D) { return }
            guard consume(0x2C) else { throw error("Relay JSON array is missing a comma") }
            skipWhitespace()
        }
    }

    private mutating func consumeString() throws -> Range<Int> {
        let start = index
        index += 1
        while index < bytes.count {
            let byte = bytes[index]
            switch byte {
            case 0x22:
                index += 1
                return start..<index
            case 0x5C:
                index += 1
                guard index < bytes.count else { throw error("Relay JSON string escape is incomplete") }
                switch bytes[index] {
                case 0x22, 0x2F, 0x5C, 0x62, 0x66, 0x6E, 0x72, 0x74:
                    index += 1
                case 0x75:
                    guard let first = hexCodeUnit(startingAt: index + 1) else {
                        throw error("Relay JSON Unicode escape is incomplete or invalid")
                    }
                    if (0xD800...0xDBFF).contains(first) {
                        guard index + 10 < bytes.count,
                              bytes[index + 5] == 0x5C,
                              bytes[index + 6] == 0x75,
                              let second = hexCodeUnit(startingAt: index + 7),
                              (0xDC00...0xDFFF).contains(second) else {
                            throw error("Relay JSON Unicode surrogate is unpaired")
                        }
                        index += 11
                    } else {
                        guard !(0xDC00...0xDFFF).contains(first) else {
                            throw error("Relay JSON Unicode surrogate is unpaired")
                        }
                        index += 5
                    }
                default:
                    throw error("Relay JSON string escape is invalid")
                }
            case 0x00...0x1F:
                throw error("Relay JSON string contains a control byte")
            default:
                index += 1
            }
        }
        throw error("Relay JSON string is unterminated")
    }

    private mutating func consumeLiteral(_ literal: [UInt8]) throws {
        guard index + literal.count <= bytes.count,
              Array(bytes[index..<(index + literal.count)]) == literal else {
            throw error("Relay JSON literal is invalid")
        }
        index += literal.count
    }

    private mutating func consumeNumber() throws {
        let start = index
        if consume(0x2D), index == bytes.count {
            throw error("Relay JSON number is incomplete")
        }

        if consume(0x30) {
            if index < bytes.count, Self.isDigit(bytes[index]) {
                throw error("Relay JSON number has a leading zero")
            }
        } else {
            guard index < bytes.count, (0x31...0x39).contains(bytes[index]) else {
                throw error("Relay JSON number is invalid")
            }
            index += 1
            while index < bytes.count, Self.isDigit(bytes[index]) { index += 1 }
        }

        if consume(0x2E) {
            guard index < bytes.count, Self.isDigit(bytes[index]) else {
                throw error("Relay JSON fraction is incomplete")
            }
            while index < bytes.count, Self.isDigit(bytes[index]) { index += 1 }
        }

        if index < bytes.count, bytes[index] == 0x65 || bytes[index] == 0x45 {
            index += 1
            if index < bytes.count, bytes[index] == 0x2B || bytes[index] == 0x2D { index += 1 }
            guard index < bytes.count, Self.isDigit(bytes[index]) else {
                throw error("Relay JSON exponent is incomplete")
            }
            while index < bytes.count, Self.isDigit(bytes[index]) { index += 1 }
        }

        let number = String(decoding: bytes[start..<index], as: UTF8.self)
        guard let value = Double(number), value.isFinite else {
            throw error("Relay JSON number exceeds the finite range")
        }
    }

    private mutating func skipWhitespace() {
        while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) {
            index += 1
        }
    }

    private mutating func consume(_ byte: UInt8) -> Bool {
        guard index < bytes.count, bytes[index] == byte else { return false }
        index += 1
        return true
    }

    private static func isDigit(_ byte: UInt8) -> Bool { (0x30...0x39).contains(byte) }

    private func hexCodeUnit(startingAt start: Int) -> UInt16? {
        guard start >= 0, start + 4 <= bytes.count else { return nil }
        var value: UInt16 = 0
        for position in start..<(start + 4) {
            guard let nibble = Self.hexNibble(bytes[position]) else { return nil }
            value = (value << 4) | UInt16(nibble)
        }
        return value
    }

    private static func hexNibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: return byte - 0x30
        case 0x41...0x46: return byte - 0x41 + 10
        case 0x61...0x66: return byte - 0x61 + 10
        default: return nil
        }
    }

    private func error(_ description: String) -> DecodingError {
        .dataCorrupted(.init(codingPath: [], debugDescription: description))
    }
}
