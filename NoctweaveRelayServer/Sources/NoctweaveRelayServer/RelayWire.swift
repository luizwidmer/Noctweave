import Foundation

enum RelayModuleID: String, Codable, CaseIterable {
    case core = "nw.core"
    case opaqueRoute = "nw.opaque-route"
    case rendezvousTransport = "nw.rendezvous-transport"
    case blobs = "nw.blobs"
    case federation = "nw.federation"

    var currentVersion: Int {
        switch self {
        case .core, .opaqueRoute, .rendezvousTransport: return 2
        case .blobs, .federation: return 1
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
    case publishDHT = "publish-dht"
    case listDHT = "list-dht"
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
        .federation: [.register, .list, .publishDHT, .listDHT]
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
    case publishDHTRecord(PublishOpenFederationDHTRecordRequest)
    case listDHTRecords(ListOpenFederationDHTRecordsRequest)

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
        case .publishDHTRecord: return .init(module: .federation, version: 1, method: .publishDHT)
        case .listDHTRecords: return .init(module: .federation, version: 1, method: .listDHT)
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
            return .uploadAttachment(try relayDecodeExact(UploadAttachmentRequest.self, from: decoder, keys: ["attachmentId", "chunkIndex", "payload", "ttlSeconds"]))
        case (.blobs, .fetch):
            return .fetchAttachment(try relayDecodeExact(FetchAttachmentRequest.self, from: decoder, keys: ["attachmentId", "chunkIndex"]))
        case (.federation, .register):
            return .registerFederationNode(try relayDecodeExact(FederationNodeRegistrationRequest.self, from: decoder, keys: ["endpoint", "relayInfo", "ttlSeconds"]))
        case (.federation, .list):
            return .listFederationNodes(try relayDecodeExact(ListFederationNodesRequest.self, from: decoder, keys: ["mode", "federationName", "onlyHealthy", "maxStalenessSeconds", "requireSignedSnapshot"]))
        case (.federation, .publishDHT):
            return .publishDHTRecord(try relayDecodeExact(PublishOpenFederationDHTRecordRequest.self, from: decoder, keys: ["namespace", "record"]))
        case (.federation, .listDHT):
            return .listDHTRecords(try relayDecodeExact(ListOpenFederationDHTRecordsRequest.self, from: decoder, keys: ["namespace", "limit"]))
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
        case .publishDHTRecord(let value):
            try container.encode(value.namespace, forKey: relayWireKey("namespace"))
            try container.encode(value.record, forKey: relayWireKey("record"))
        case .listDHTRecords(let value):
            try container.encode(value.namespace, forKey: relayWireKey("namespace"))
            try relayEncodeOptional(value.limit, key: "limit", into: &container)
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
    static func publishOpenFederationDHTRecord(_ value: PublishOpenFederationDHTRecordRequest) -> RelayRequest { make(.publishDHTRecord(value)) }
    static func listOpenFederationDHTRecords(_ value: ListOpenFederationDHTRecordsRequest) -> RelayRequest { make(.listDHTRecords(value)) }

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
}

enum RelaySuccessBody: Equatable {
    case empty
    case relayInfo(RelayInfo)
    case opaqueRoute(OpaqueReceiveRouteV2)
    case opaqueRouteAppend(OpaqueRouteAppendReceiptV2)
    case opaqueRouteSync(OpaqueRouteSyncResponseV2)
    case opaqueRouteCommit(OpaqueRouteCommitResponseV2)
    case rendezvousSync(RendezvousRelaySyncBatchV2)
    case attachment(AttachmentChunk)
    case federationNodes(FederationNodesResponseBody)
    case dhtRecords([OpenFederationDHTRecord])

    func supports(_ binding: RelayOperationBinding) -> Bool {
        switch self {
        case .empty:
            return binding == .init(module: .core, version: 2, method: .health)
                || binding == .init(module: .rendezvousTransport, version: 2, method: .register)
                || binding == .init(module: .rendezvousTransport, version: 2, method: .append)
                || binding == .init(module: .rendezvousTransport, version: 2, method: .delete)
                || binding == .init(module: .federation, version: 1, method: .publishDHT)
        case .relayInfo: return binding == .init(module: .core, version: 2, method: .info)
        case .opaqueRoute: return binding.module == .opaqueRoute && binding.version == 2 && [.create, .renew, .teardown].contains(binding.method)
        case .opaqueRouteAppend: return binding == .init(module: .opaqueRoute, version: 2, method: .append)
        case .opaqueRouteSync: return binding == .init(module: .opaqueRoute, version: 2, method: .sync)
        case .opaqueRouteCommit: return binding == .init(module: .opaqueRoute, version: 2, method: .commit)
        case .rendezvousSync: return binding == .init(module: .rendezvousTransport, version: 2, method: .sync)
        case .attachment: return binding.module == .blobs && binding.version == 1 && [.upload, .fetch].contains(binding.method)
        case .federationNodes: return binding.module == .federation && binding.version == 1 && [.register, .list].contains(binding.method)
        case .dhtRecords: return binding == .init(module: .federation, version: 1, method: .listDHT)
        }
    }

    static func decode(for binding: RelayOperationBinding, from decoder: Decoder) throws -> RelaySuccessBody {
        switch (binding.module, binding.method) {
        case (.core, .health), (.rendezvousTransport, .register), (.rendezvousTransport, .append), (.rendezvousTransport, .delete), (.federation, .publishDHT):
            try relayRequireExactObject(decoder, keys: [])
            return .empty
        case (.core, .info):
            return .relayInfo(try relayDecodeSingle(RelayInfo.self, from: decoder, key: "relayInfo"))
        case (.opaqueRoute, .create), (.opaqueRoute, .renew), (.opaqueRoute, .teardown):
            return .opaqueRoute(try relayDecodeSingle(OpaqueReceiveRouteV2.self, from: decoder, key: "route"))
        case (.opaqueRoute, .append):
            return .opaqueRouteAppend(try relayDecodeSingle(OpaqueRouteAppendReceiptV2.self, from: decoder, key: "receipt"))
        case (.opaqueRoute, .sync):
            return .opaqueRouteSync(try relayDecodeSingle(OpaqueRouteSyncResponseV2.self, from: decoder, key: "batch"))
        case (.opaqueRoute, .commit):
            return .opaqueRouteCommit(try relayDecodeSingle(OpaqueRouteCommitResponseV2.self, from: decoder, key: "commit"))
        case (.rendezvousTransport, .sync):
            return .rendezvousSync(try relayDecodeSingle(RendezvousRelaySyncBatchV2.self, from: decoder, key: "batch"))
        case (.blobs, .upload), (.blobs, .fetch):
            return .attachment(try relayDecodeSingle(AttachmentChunk.self, from: decoder, key: "chunk"))
        case (.federation, .register), (.federation, .list):
            try relayRequireExactObject(decoder, keys: ["nodes", "snapshot"])
            let container = try decoder.container(keyedBy: RelayWireCodingKey.self)
            return .federationNodes(.init(
                nodes: try container.decode([FederationNodeRecord].self, forKey: relayWireKey("nodes")),
                snapshot: try container.decodeIfPresent(FederationDirectorySnapshot.self, forKey: relayWireKey("snapshot"))
            ))
        case (.federation, .listDHT):
            return .dhtRecords(try relayDecodeSingle([OpenFederationDHTRecord].self, from: decoder, key: "records"))
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
        case .attachment(let value): try container.encode(value, forKey: relayWireKey("chunk"))
        case .federationNodes(let value):
            try container.encode(value.nodes, forKey: relayWireKey("nodes"))
            try relayEncodeOptional(value.snapshot, key: "snapshot", into: &container)
        case .dhtRecords(let value): try container.encode(value, forKey: relayWireKey("records"))
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
