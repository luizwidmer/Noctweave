import CryptoKit
import Foundation

public enum NoctweaveOpaqueRouteRelayStoreV2 {
    public static let maximumSyncPage = 256
    public static let maximumAcceptedPacketIdentifiers = 65_536
    public static let maximumReadRequestReceipts = 65_536
    public static let cursorBytes = 68
}

public enum OpaqueRouteRelayStoreV2Error: Error, Equatable {
    case routeNotFound
    case invalidRequest
    case invalidCursor
    case cursorExpired
    case cursorAheadOfRoute
    case packetIdentifierConflict
    case requestIdentifierConflict
    case routeQuotaExceeded
    case packetIdentifierLedgerExhausted
    case requestReceiptLedgerExhausted
    case sequenceExhausted
}

// MARK: - Opaque cursors and read requests

public struct OpaqueRouteCursorV2: Codable, Equatable, Hashable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let rawValue: Data

    private enum CodingKeys: String, CodingKey { case rawValue }

    init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let value = try container.decode(Data.self, forKey: .rawValue)
        guard value.count == NoctweaveOpaqueRouteRelayStoreV2.cursorBytes else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawValue,
                in: container,
                debugDescription: "Opaque route cursor has an invalid size"
            )
        }
        rawValue = value
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                rawValue,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Opaque route cursor has an invalid size"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rawValue, forKey: .rawValue)
    }

    public var isStructurallyValid: Bool {
        rawValue.count == NoctweaveOpaqueRouteRelayStoreV2.cursorBytes
    }

    public var description: String { "OpaqueRouteCursorV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

public struct OpaqueRouteSyncRequestV2: Codable, Equatable {
    public let routeID: OpaqueReceiveRouteIDV2
    public let requestID: OpaqueRouteIdempotencyKeyV2
    public let after: OpaqueRouteCursorV2?
    public let limit: UInt16
    public let authorization: OpaqueRouteAuthorizationProofV2

    init(
        routeID: OpaqueReceiveRouteIDV2,
        requestID: OpaqueRouteIdempotencyKeyV2,
        after: OpaqueRouteCursorV2?,
        limit: UInt16,
        authorization: OpaqueRouteAuthorizationProofV2
    ) {
        self.routeID = routeID
        self.requestID = requestID
        self.after = after
        self.limit = limit
        self.authorization = authorization
    }

    public var operationDigest: Data {
        opaqueRouteStoreDigest(
            domain: "org.noctweave.opaque-route.sync/v2",
            components: [
                routeID.rawValue,
                requestID.rawValue,
                after?.rawValue ?? Data([0]),
                opaqueRouteStoreIntegerBytes(limit),
            ]
        )
    }

    public var isStructurallyValid: Bool {
        routeID.isStructurallyValid
            && requestID.isStructurallyValid
            && after?.isStructurallyValid != false
            && limit > 0
            && limit <= UInt16(NoctweaveOpaqueRouteRelayStoreV2.maximumSyncPage)
            && authorization.isStructurallyValid
            && authorization.authority == .read
            && authorization.operationDigest == operationDigest
    }
}

public struct OpaqueRouteCommitRequestV2: Codable, Equatable {
    public let routeID: OpaqueReceiveRouteIDV2
    public let requestID: OpaqueRouteIdempotencyKeyV2
    public let cursor: OpaqueRouteCursorV2
    public let authorization: OpaqueRouteAuthorizationProofV2

    init(
        routeID: OpaqueReceiveRouteIDV2,
        requestID: OpaqueRouteIdempotencyKeyV2,
        cursor: OpaqueRouteCursorV2,
        authorization: OpaqueRouteAuthorizationProofV2
    ) {
        self.routeID = routeID
        self.requestID = requestID
        self.cursor = cursor
        self.authorization = authorization
    }

    public var operationDigest: Data {
        opaqueRouteStoreDigest(
            domain: "org.noctweave.opaque-route.commit/v2",
            components: [routeID.rawValue, requestID.rawValue, cursor.rawValue]
        )
    }

    public var isStructurallyValid: Bool {
        routeID.isStructurallyValid
            && requestID.isStructurallyValid
            && cursor.isStructurallyValid
            && authorization.isStructurallyValid
            && authorization.authority == .read
            && authorization.operationDigest == operationDigest
    }
}

public extension OpaqueRouteClientCapabilityMaterialV2 {
    func makeSyncRequest(
        after cursor: OpaqueRouteCursorV2?,
        limit: UInt16,
        requestID: OpaqueRouteIdempotencyKeyV2 = .generate(),
        authorizedAt: Date = Date(),
        nonce: OpaqueRouteProofNonceV2 = .generate()
    ) throws -> OpaqueRouteSyncRequestV2 {
        let provisional = OpaqueRouteSyncRequestV2(
            routeID: routeID,
            requestID: requestID,
            after: cursor,
            limit: limit,
            authorization: try makeReadAuthorization(
                operationDigest: Data(repeating: 0, count: NoctweaveOpaqueRoutesV2.digestBytes),
                authorizedAt: authorizedAt,
                nonce: nonce
            )
        )
        let proof = try makeReadAuthorization(
            operationDigest: provisional.operationDigest,
            authorizedAt: authorizedAt,
            nonce: nonce
        )
        return OpaqueRouteSyncRequestV2(
            routeID: routeID,
            requestID: requestID,
            after: cursor,
            limit: limit,
            authorization: proof
        )
    }

    func makeCommitRequest(
        cursor: OpaqueRouteCursorV2,
        requestID: OpaqueRouteIdempotencyKeyV2 = .generate(),
        authorizedAt: Date = Date(),
        nonce: OpaqueRouteProofNonceV2 = .generate()
    ) throws -> OpaqueRouteCommitRequestV2 {
        let provisional = OpaqueRouteCommitRequestV2(
            routeID: routeID,
            requestID: requestID,
            cursor: cursor,
            authorization: try makeReadAuthorization(
                operationDigest: Data(repeating: 0, count: NoctweaveOpaqueRoutesV2.digestBytes),
                authorizedAt: authorizedAt,
                nonce: nonce
            )
        )
        let proof = try makeReadAuthorization(
            operationDigest: provisional.operationDigest,
            authorizedAt: authorizedAt,
            nonce: nonce
        )
        return OpaqueRouteCommitRequestV2(
            routeID: routeID,
            requestID: requestID,
            cursor: cursor,
            authorization: proof
        )
    }
}

// MARK: - Relay responses

public struct OpaqueRouteAppendReceiptV2: Codable, Equatable {
    public let packetID: OpaqueRoutePacketIDV2
    public let acceptedCursor: OpaqueRouteCursorV2
    public let highWatermark: OpaqueRouteCursorV2
}

public struct OpaqueRouteReceivedPacketV2: Codable, Equatable {
    public let routeRevision: UInt64
    public let packet: OpaqueRoutePacketV2
}

public struct OpaqueRouteSyncResponseV2: Codable, Equatable {
    public let packets: [OpaqueRouteReceivedPacketV2]
    public let nextCursor: OpaqueRouteCursorV2
    public let highWatermark: OpaqueRouteCursorV2
    public let retentionFloor: OpaqueRouteCursorV2
    public let hasMore: Bool
}

public struct OpaqueRouteCommitResponseV2: Codable, Equatable {
    public let committedCursor: OpaqueRouteCursorV2
    public let highWatermark: OpaqueRouteCursorV2
    public let retentionFloor: OpaqueRouteCursorV2
}

// MARK: - Authoritative in-memory relay state

public actor OpaqueRouteRelayStoreV2 {
    private struct StoredPacket {
        let sequence: UInt64
        let routeRevision: UInt64
        let packet: OpaqueRoutePacketV2
        let expiresAt: Date
    }

    private struct AcceptedPacket {
        let operationDigest: Data
        let receipt: OpaqueRouteAppendReceiptV2
        let authorizationExpiresAt: Date
    }

    private struct CachedSync {
        let packetSequences: [UInt64]
        let response: OpaqueRouteSyncResponseV2
        let authorizationExpiresAt: Date
        let bodyExpiresAt: Date?
    }

    private enum CachedReadResult {
        case sync(CachedSync)
        case commit(OpaqueRouteCommitResponseV2)
    }

    private struct AcceptedReadRequest {
        let operationDigest: Data
        let result: CachedReadResult
        let authorizationExpiresAt: Date
    }

    private struct RouteState {
        var route: OpaqueReceiveRouteV2
        var replayLedger = OpaqueRouteAuthorizationReplayLedgerV2()
        var packets: [StoredPacket] = []
        var nextSequence: UInt64 = 1
        var retentionFloor: UInt64 = 0
        var committedSequence: UInt64 = 0
        var acceptedPackets: [OpaqueRoutePacketIDV2: AcceptedPacket] = [:]
        var acceptedReads: [OpaqueRouteIdempotencyKeyV2: AcceptedReadRequest] = [:]
        var observedAtHighWatermark: Date
    }

    private let cursorKey: SymmetricKey
    private var routes: [OpaqueReceiveRouteIDV2: RouteState] = [:]

    public init() {
        cursorKey = SymmetricKey(size: .bits256)
    }

    @discardableResult
    public func create(
        _ request: OpaqueRouteCreateRequestV2,
        presentedCapability: RouteRenewCapabilityV2,
        confidentialTransport: Bool,
        receivedAt: Date = Date()
    ) throws -> OpaqueReceiveRouteV2 {
        let existing = routes[request.routeID]?.route
        let route = try OpaqueReceiveRouteV2.creating(
            from: request,
            presentedRenewCapability: presentedCapability,
            existing: existing,
            confidentialTransport: confidentialTransport,
            receivedAt: receivedAt
        )
        if routes[request.routeID] == nil {
            routes[request.routeID] = RouteState(
                route: route,
                observedAtHighWatermark: receivedAt
            )
        } else if var state = routes[request.routeID] {
            state.observedAtHighWatermark = max(state.observedAtHighWatermark, receivedAt)
            routes[request.routeID] = state
        }
        return route
    }

    @discardableResult
    public func renew(
        _ request: OpaqueRouteRenewRequestV2,
        presentedCapability: RouteRenewCapabilityV2,
        confidentialTransport: Bool,
        receivedAt: Date = Date()
    ) throws -> OpaqueReceiveRouteV2 {
        guard var state = routes[request.routeID] else {
            throw OpaqueRouteRelayStoreV2Error.routeNotFound
        }
        let effectiveTime = try monotonicTime(&state, receivedAt: receivedAt)
        let route = try state.route.applyingRenewal(
            request,
            presentedCapability: presentedCapability,
            confidentialTransport: confidentialTransport,
            receivedAt: effectiveTime
        )
        state.route = route
        routes[request.routeID] = state
        return route
    }

    @discardableResult
    public func teardown(
        _ request: OpaqueRouteTeardownRequestV2,
        presentedCapability: RouteTeardownCapabilityV2,
        confidentialTransport: Bool,
        receivedAt: Date = Date()
    ) throws -> OpaqueReceiveRouteV2 {
        guard var state = routes[request.routeID] else {
            throw OpaqueRouteRelayStoreV2Error.routeNotFound
        }
        let effectiveTime = try monotonicTime(&state, receivedAt: receivedAt)
        let wasActive = state.route.status == .active
        let route = try state.route.applyingTeardown(
            request,
            presentedCapability: presentedCapability,
            confidentialTransport: confidentialTransport,
            receivedAt: effectiveTime
        )
        state.route = route
        if wasActive && route.status == .tornDown {
            state.retentionFloor = state.nextSequence - 1
            state.packets.removeAll(keepingCapacity: false)
            state.acceptedPackets.removeAll(keepingCapacity: false)
            state.acceptedReads.removeAll(keepingCapacity: false)
            state.replayLedger = OpaqueRouteAuthorizationReplayLedgerV2()
        }
        routes[request.routeID] = state
        return route
    }

    public func append(
        _ packet: OpaqueRoutePacketV2,
        presentedCapability: RouteSendCapabilityV2,
        confidentialTransport: Bool,
        receivedAt: Date = Date()
    ) throws -> OpaqueRouteAppendReceiptV2 {
        guard packet.isStructurallyValid else {
            throw OpaqueRouteRelayStoreV2Error.invalidRequest
        }
        guard var state = routes[packet.routeID] else {
            throw OpaqueRouteRelayStoreV2Error.routeNotFound
        }

        if let accepted = state.acceptedPackets[packet.packetID] {
            if accepted.operationDigest == packet.operationDigest {
                try state.route.authenticateAcceptedSendRetry(
                    packet.authorization,
                    operationDigest: packet.operationDigest,
                    presentedCapability: presentedCapability,
                    confidentialTransport: confidentialTransport
                )
                try advanceTimeAndCollect(&state, receivedAt: receivedAt)
                if state.acceptedPackets[packet.packetID] != nil {
                    routes[packet.routeID] = state
                    return accepted.receipt
                }
            } else {
                var ledger = state.replayLedger
                try state.route.authorizeSend(
                    packet.authorization,
                    operationDigest: packet.operationDigest,
                    presentedCapability: presentedCapability,
                    confidentialTransport: confidentialTransport,
                    receivedAt: try monotonicTime(&state, receivedAt: receivedAt),
                    replayLedger: &ledger
                )
                routes[packet.routeID] = state
                throw OpaqueRouteRelayStoreV2Error.packetIdentifierConflict
            }
        }

        let effectiveTime = try monotonicTime(&state, receivedAt: receivedAt)
        garbageCollect(&state, at: effectiveTime)
        var ledger = state.replayLedger
        try state.route.authorizeSend(
            packet.authorization,
            operationDigest: packet.operationDigest,
            presentedCapability: presentedCapability,
            confidentialTransport: confidentialTransport,
            receivedAt: effectiveTime,
            replayLedger: &ledger
        )
        guard packet.paddingBucket == state.route.lease.policy.paddingBucket else {
            routes[packet.routeID] = state
            throw OpaqueRouteRelayStoreV2Error.invalidRequest
        }
        guard state.packets.count < Int(state.route.lease.policy.quotaBucket.rawValue),
              UInt64(state.packets.count + 1) * UInt64(packet.sealedFrame.count)
                <= state.route.lease.policy.maximumStoredBytes else {
            routes[packet.routeID] = state
            throw OpaqueRouteRelayStoreV2Error.routeQuotaExceeded
        }
        guard state.acceptedPackets.count
                < NoctweaveOpaqueRouteRelayStoreV2.maximumAcceptedPacketIdentifiers else {
            routes[packet.routeID] = state
            throw OpaqueRouteRelayStoreV2Error.packetIdentifierLedgerExhausted
        }
        guard state.nextSequence < UInt64.max else {
            routes[packet.routeID] = state
            throw OpaqueRouteRelayStoreV2Error.sequenceExhausted
        }
        let expiry = effectiveTime.addingTimeInterval(
            TimeInterval(state.route.lease.policy.retentionBucket.rawValue)
        )
        guard expiry.timeIntervalSince1970.isFinite else {
            routes[packet.routeID] = state
            throw OpaqueRouteRelayStoreV2Error.invalidRequest
        }

        let sequence = state.nextSequence
        state.nextSequence += 1
        let cursor = try sealCursor(routeID: packet.routeID, position: sequence)
        let receipt = OpaqueRouteAppendReceiptV2(
            packetID: packet.packetID,
            acceptedCursor: cursor,
            highWatermark: cursor
        )
        state.packets.append(StoredPacket(
            sequence: sequence,
            routeRevision: state.route.lease.renewalSequence,
            packet: packet,
            expiresAt: expiry
        ))
        state.acceptedPackets[packet.packetID] = AcceptedPacket(
            operationDigest: packet.operationDigest,
            receipt: receipt,
            authorizationExpiresAt: packet.authorization.authorizedAt.addingTimeInterval(
                NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew
            )
        )
        state.replayLedger = ledger
        routes[packet.routeID] = state
        return receipt
    }

    public func sync(
        _ request: OpaqueRouteSyncRequestV2,
        presentedCredential: RouteReadCredentialV2,
        confidentialTransport: Bool,
        receivedAt: Date = Date()
    ) throws -> OpaqueRouteSyncResponseV2 {
        guard request.isStructurallyValid else {
            throw OpaqueRouteRelayStoreV2Error.invalidRequest
        }
        guard var state = routes[request.routeID] else {
            throw OpaqueRouteRelayStoreV2Error.routeNotFound
        }

        if let accepted = state.acceptedReads[request.requestID] {
            if accepted.operationDigest == request.operationDigest,
               case let .sync(cached) = accepted.result {
                try state.route.authenticateAcceptedReadRetry(
                    request.authorization,
                    operationDigest: request.operationDigest,
                    presentedCredential: presentedCredential,
                    confidentialTransport: confidentialTransport
                )
                try advanceTimeAndCollect(&state, receivedAt: receivedAt)
                if state.acceptedReads[request.requestID] != nil {
                    routes[request.routeID] = state
                    return cached.response
                }
            } else {
                try authenticateConflictingRead(
                    request.authorization,
                    operationDigest: request.operationDigest,
                    presentedCredential: presentedCredential,
                    confidentialTransport: confidentialTransport,
                    receivedAt: receivedAt,
                    state: &state
                )
                routes[request.routeID] = state
                throw OpaqueRouteRelayStoreV2Error.requestIdentifierConflict
            }
        }

        let effectiveTime = try monotonicTime(&state, receivedAt: receivedAt)
        garbageCollect(&state, at: effectiveTime)
        var ledger = state.replayLedger
        try state.route.authorizeRead(
            request.authorization,
            operationDigest: request.operationDigest,
            presentedCredential: presentedCredential,
            confidentialTransport: confidentialTransport,
            receivedAt: effectiveTime,
            replayLedger: &ledger
        )
        guard state.acceptedReads.count
                < NoctweaveOpaqueRouteRelayStoreV2.maximumReadRequestReceipts else {
            routes[request.routeID] = state
            throw OpaqueRouteRelayStoreV2Error.requestReceiptLedgerExhausted
        }

        let start: UInt64
        if let cursor = request.after {
            start = try openCursor(cursor, expectedRouteID: request.routeID)
            guard start >= state.retentionFloor else {
                routes[request.routeID] = state
                throw OpaqueRouteRelayStoreV2Error.cursorExpired
            }
            guard start <= state.nextSequence - 1 else {
                routes[request.routeID] = state
                throw OpaqueRouteRelayStoreV2Error.cursorAheadOfRoute
            }
        } else {
            start = state.retentionFloor
        }

        let page = state.packets
            .filter { $0.sequence > start }
            .prefix(Int(request.limit))
        let packetSequences = page.map(\.sequence)
        let nextPosition = packetSequences.last ?? start
        let highPosition = state.nextSequence - 1
        let nextCursor = try sealCursor(routeID: request.routeID, position: nextPosition)
        let highWatermark = try sealCursor(routeID: request.routeID, position: highPosition)
        let retentionFloor = try sealCursor(
            routeID: request.routeID,
            position: state.retentionFloor
        )
        let response = OpaqueRouteSyncResponseV2(
            packets: page.map {
                OpaqueRouteReceivedPacketV2(
                    routeRevision: $0.routeRevision,
                    packet: $0.packet
                )
            },
            nextCursor: nextCursor,
            highWatermark: highWatermark,
            retentionFloor: retentionFloor,
            hasMore: state.packets.contains(where: { $0.sequence > nextPosition })
        )
        let cached = CachedSync(
            packetSequences: packetSequences,
            response: response,
            authorizationExpiresAt: request.authorization.authorizedAt.addingTimeInterval(
                NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew
            ),
            bodyExpiresAt: page.map(\.expiresAt).min()
        )
        state.acceptedReads[request.requestID] = AcceptedReadRequest(
            operationDigest: request.operationDigest,
            result: .sync(cached),
            authorizationExpiresAt: cached.authorizationExpiresAt
        )
        state.replayLedger = ledger
        routes[request.routeID] = state
        return response
    }

    public func commit(
        _ request: OpaqueRouteCommitRequestV2,
        presentedCredential: RouteReadCredentialV2,
        confidentialTransport: Bool,
        receivedAt: Date = Date()
    ) throws -> OpaqueRouteCommitResponseV2 {
        guard request.isStructurallyValid else {
            throw OpaqueRouteRelayStoreV2Error.invalidRequest
        }
        guard var state = routes[request.routeID] else {
            throw OpaqueRouteRelayStoreV2Error.routeNotFound
        }

        if let accepted = state.acceptedReads[request.requestID] {
            if accepted.operationDigest == request.operationDigest,
               case let .commit(response) = accepted.result {
                try state.route.authenticateAcceptedReadRetry(
                    request.authorization,
                    operationDigest: request.operationDigest,
                    presentedCredential: presentedCredential,
                    confidentialTransport: confidentialTransport
                )
                try advanceTimeAndCollect(&state, receivedAt: receivedAt)
                if state.acceptedReads[request.requestID] != nil {
                    routes[request.routeID] = state
                    return response
                }
            } else {
                try authenticateConflictingRead(
                    request.authorization,
                    operationDigest: request.operationDigest,
                    presentedCredential: presentedCredential,
                    confidentialTransport: confidentialTransport,
                    receivedAt: receivedAt,
                    state: &state
                )
                routes[request.routeID] = state
                throw OpaqueRouteRelayStoreV2Error.requestIdentifierConflict
            }
        }

        let effectiveTime = try monotonicTime(&state, receivedAt: receivedAt)
        garbageCollect(&state, at: effectiveTime)
        var ledger = state.replayLedger
        try state.route.authorizeRead(
            request.authorization,
            operationDigest: request.operationDigest,
            presentedCredential: presentedCredential,
            confidentialTransport: confidentialTransport,
            receivedAt: effectiveTime,
            replayLedger: &ledger
        )
        guard state.acceptedReads.count
                < NoctweaveOpaqueRouteRelayStoreV2.maximumReadRequestReceipts else {
            routes[request.routeID] = state
            throw OpaqueRouteRelayStoreV2Error.requestReceiptLedgerExhausted
        }
        let position = try openCursor(request.cursor, expectedRouteID: request.routeID)
        let highPosition = state.nextSequence - 1
        guard position <= highPosition else {
            routes[request.routeID] = state
            throw OpaqueRouteRelayStoreV2Error.cursorAheadOfRoute
        }
        if position > state.committedSequence && position < state.retentionFloor {
            routes[request.routeID] = state
            throw OpaqueRouteRelayStoreV2Error.cursorExpired
        }
        state.committedSequence = max(state.committedSequence, position)
        garbageCollect(&state, at: effectiveTime)

        let response = OpaqueRouteCommitResponseV2(
            committedCursor: try sealCursor(
                routeID: request.routeID,
                position: state.committedSequence
            ),
            highWatermark: try sealCursor(
                routeID: request.routeID,
                position: highPosition
            ),
            retentionFloor: try sealCursor(
                routeID: request.routeID,
                position: state.retentionFloor
            )
        )
        state.acceptedReads[request.requestID] = AcceptedReadRequest(
            operationDigest: request.operationDigest,
            result: .commit(response),
            authorizationExpiresAt: request.authorization.authorizedAt.addingTimeInterval(
                NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew
            )
        )
        state.replayLedger = ledger
        routes[request.routeID] = state
        return response
    }

    // MARK: State helpers

    private func authenticateConflictingRead(
        _ proof: OpaqueRouteAuthorizationProofV2,
        operationDigest: Data,
        presentedCredential: RouteReadCredentialV2,
        confidentialTransport: Bool,
        receivedAt: Date,
        state: inout RouteState
    ) throws {
        let effectiveTime = try monotonicTime(&state, receivedAt: receivedAt)
        var ledger = state.replayLedger
        try state.route.authorizeRead(
            proof,
            operationDigest: operationDigest,
            presentedCredential: presentedCredential,
            confidentialTransport: confidentialTransport,
            receivedAt: effectiveTime,
            replayLedger: &ledger
        )
    }

    private func monotonicTime(
        _ state: inout RouteState,
        receivedAt: Date
    ) throws -> Date {
        guard receivedAt.timeIntervalSince1970.isFinite else {
            throw OpaqueRouteRelayStoreV2Error.invalidRequest
        }
        let effective = max(state.observedAtHighWatermark, receivedAt)
        state.observedAtHighWatermark = effective
        return effective
    }

    private func advanceTimeAndCollect(
        _ state: inout RouteState,
        receivedAt: Date
    ) throws {
        let effective = try monotonicTime(&state, receivedAt: receivedAt)
        garbageCollect(&state, at: effective)
    }

    private func garbageCollect(_ state: inout RouteState, at receivedAt: Date) {
        let highPosition = state.nextSequence - 1
        if state.route.status != .active || !state.route.lease.isActive(at: receivedAt) {
            state.packets.removeAll(keepingCapacity: false)
            state.retentionFloor = highPosition
            pruneReceipts(&state, at: receivedAt)
            return
        }
        var removedThrough = state.retentionFloor
        while let first = state.packets.first,
              first.sequence <= state.committedSequence || first.expiresAt <= receivedAt {
            removedThrough = first.sequence
            state.packets.removeFirst()
        }
        state.retentionFloor = max(state.retentionFloor, removedThrough)
        pruneReceipts(&state, at: receivedAt)
    }

    private func pruneReceipts(_ state: inout RouteState, at receivedAt: Date) {
        let retainedSequences = Set(state.packets.map(\.sequence))
        let retainedPacketIDs = Set(state.packets.map { $0.packet.packetID })
        state.acceptedPackets = state.acceptedPackets.filter { packetID, receipt in
            retainedPacketIDs.contains(packetID)
                || receipt.authorizationExpiresAt >= receivedAt
        }
        state.acceptedReads = state.acceptedReads.filter { _, receipt in
            switch receipt.result {
            case let .sync(sync):
                let bodiesRetained = !sync.packetSequences.isEmpty
                    && sync.packetSequences.allSatisfy(retainedSequences.contains)
                let responseWithinTTL = sync.bodyExpiresAt.map { $0 > receivedAt } ?? true
                return responseWithinTTL
                    && (bodiesRetained || sync.authorizationExpiresAt >= receivedAt)
            case .commit:
                return receipt.authorizationExpiresAt >= receivedAt
            }
        }
    }

    // MARK: Cursor codec

    private func sealCursor(
        routeID: OpaqueReceiveRouteIDV2,
        position: UInt64
    ) throws -> OpaqueRouteCursorV2 {
        var claims = Data()
        claims.reserveCapacity(40)
        claims.append(routeID.rawValue)
        opaqueRouteStoreAppend(position, to: &claims)
        let sealed = try AES.GCM.seal(
            claims,
            using: cursorKey,
            nonce: AES.GCM.Nonce(),
            authenticating: Data("org.noctweave.opaque-route.cursor/v2".utf8)
        )
        var token = Data(sealed.nonce)
        token.append(sealed.ciphertext)
        token.append(sealed.tag)
        guard token.count == NoctweaveOpaqueRouteRelayStoreV2.cursorBytes else {
            throw OpaqueRouteRelayStoreV2Error.invalidCursor
        }
        return OpaqueRouteCursorV2(rawValue: token)
    }

    private func openCursor(
        _ cursor: OpaqueRouteCursorV2,
        expectedRouteID: OpaqueReceiveRouteIDV2
    ) throws -> UInt64 {
        guard cursor.isStructurallyValid else {
            throw OpaqueRouteRelayStoreV2Error.invalidCursor
        }
        let nonceEnd = 12
        let tagStart = cursor.rawValue.count - 16
        let claims: Data
        do {
            let nonce = try AES.GCM.Nonce(data: cursor.rawValue.prefix(nonceEnd))
            let box = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: cursor.rawValue[nonceEnd..<tagStart],
                tag: cursor.rawValue[tagStart...]
            )
            claims = try AES.GCM.open(
                box,
                using: cursorKey,
                authenticating: Data("org.noctweave.opaque-route.cursor/v2".utf8)
            )
        } catch {
            throw OpaqueRouteRelayStoreV2Error.invalidCursor
        }
        guard claims.count == 40,
              Data(claims.prefix(32)) == expectedRouteID.rawValue else {
            throw OpaqueRouteRelayStoreV2Error.invalidCursor
        }
        return claims.suffix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }
}

// MARK: - Canonical operation digests

private func opaqueRouteStoreDigest(domain: String, components: [Data]) -> Data {
    var material = Data(domain.utf8)
    material.append(0)
    for component in components {
        opaqueRouteStoreAppend(UInt64(component.count), to: &material)
        material.append(component)
    }
    return Data(SHA256.hash(data: material))
}

private func opaqueRouteStoreIntegerBytes<T: FixedWidthInteger>(_ value: T) -> Data {
    var data = Data()
    opaqueRouteStoreAppend(value, to: &data)
    return data
}

private func opaqueRouteStoreAppend<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
    var bigEndian = value.bigEndian
    Swift.withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
}
