import CryptoKit
import Foundation

/// Fixed-size, route-encrypted packets for opaque relay routes.
///
/// The relay projection is intentionally limited to `routeID`, `packetID`,
/// `sealedFrame`, and `authorization`. Bundle identifiers, fragmentation
/// metadata, logical lengths, and payload bytes exist only inside the AEAD
/// frame. The payload key is independent from every relay authorization
/// capability and is never needed to authorize, store, or retrieve a packet.
public enum NoctweaveOpaqueRoutePacketsV2 {
    public static let version: UInt16 = 2
    public static let payloadKeyBytes = 32
    public static let identifierBytes = 32
    public static let digestBytes = 32
    public static let nonceBytes = 12
    public static let authenticationTagBytes = 16
    public static let minimumRandomPaddingBytes = 32
    public static let maximumFragmentCount = 4_096
    public static let maximumBundleBytes = 64 * 1_024 * 1_024

    fileprivate static let frameHeaderBytes = 90

    public static func maximumFragmentPayloadBytes(
        for bucket: OpaqueRoutePaddingBucketV2
    ) -> Int {
        Int(bucket.rawValue)
            - nonceBytes
            - authenticationTagBytes
            - frameHeaderBytes
            - minimumRandomPaddingBytes
    }
}

public enum OpaqueRoutePacketV2Error: Error, Equatable {
    case invalidPayloadKey
    case invalidIdentifier
    case invalidPacket
    case invalidBundle
    case emptyPayload
    case payloadTooLarge
    case fragmentCountExceeded
    case malformedFrame
    case decryptionFailed
    case packetIdentifierConflict
    case bundleConflict
    case fragmentConflict
    case reassemblyCapacityExceeded
    case bundleDigestMismatch
}

// MARK: - Client-only values

public struct OpaqueRoutePayloadKeyV2: Codable, Equatable, Hashable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let rawValue: Data

    private enum CodingKeys: String, CodingKey { case rawValue }

    init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public static func generate() -> OpaqueRoutePayloadKeyV2 {
        OpaqueRoutePayloadKeyV2(rawValue: opaquePacketRandomNonzeroValue())
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let value = try container.decode(Data.self, forKey: .rawValue)
        guard opaquePacketIsValidIdentifier(value) else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawValue,
                in: container,
                debugDescription: "Opaque route payload key must be a nonzero 32-byte value"
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
                    debugDescription: "Opaque route payload key must be a nonzero 32-byte value"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rawValue, forKey: .rawValue)
    }

    public var isStructurallyValid: Bool {
        opaquePacketIsValidIdentifier(rawValue)
    }

    public var description: String { "OpaqueRoutePayloadKeyV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

public struct OpaqueRoutePacketIDV2: Codable, Equatable, Hashable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let rawValue: Data

    private enum CodingKeys: String, CodingKey, CaseIterable { case rawValue }

    init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public static func generate() -> OpaqueRoutePacketIDV2 {
        OpaqueRoutePacketIDV2(rawValue: opaquePacketRandomNonzeroValue())
    }

    public init(from decoder: Decoder) throws {
        try opaquePacketRequireExactObject(
            decoder,
            keys: CodingKeys.allCases.map(\.rawValue)
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let value = try container.decode(Data.self, forKey: .rawValue)
        guard opaquePacketIsValidIdentifier(value) else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawValue,
                in: container,
                debugDescription: "Opaque route packet identifier must be a nonzero 32-byte value"
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
                    debugDescription: "Opaque route packet identifier must be a nonzero 32-byte value"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rawValue, forKey: .rawValue)
    }

    public var isStructurallyValid: Bool {
        opaquePacketIsValidIdentifier(rawValue)
    }

    public var description: String { "OpaqueRoutePacketIDV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

public struct OpaqueRouteBundleIDV2: Codable, Equatable, Hashable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let rawValue: Data

    private enum CodingKeys: String, CodingKey { case rawValue }

    init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public static func generate() -> OpaqueRouteBundleIDV2 {
        OpaqueRouteBundleIDV2(rawValue: opaquePacketRandomNonzeroValue())
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let value = try container.decode(Data.self, forKey: .rawValue)
        guard opaquePacketIsValidIdentifier(value) else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawValue,
                in: container,
                debugDescription: "Opaque route bundle identifier must be a nonzero 32-byte value"
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
                    debugDescription: "Opaque route bundle identifier must be a nonzero 32-byte value"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rawValue, forKey: .rawValue)
    }

    public var isStructurallyValid: Bool {
        opaquePacketIsValidIdentifier(rawValue)
    }

    public var description: String { "OpaqueRouteBundleIDV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

// MARK: - Relay projection

public struct OpaqueRoutePacketV2: Codable, Equatable {
    public let routeID: OpaqueReceiveRouteIDV2
    public let packetID: OpaqueRoutePacketIDV2
    public let sealedFrame: Data
    public let authorization: OpaqueRouteAuthorizationProofV2

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case routeID
        case packetID
        case sealedFrame
        case authorization
    }

    init(
        routeID: OpaqueReceiveRouteIDV2,
        packetID: OpaqueRoutePacketIDV2,
        sealedFrame: Data,
        authorization: OpaqueRouteAuthorizationProofV2
    ) {
        self.routeID = routeID
        self.packetID = packetID
        self.sealedFrame = sealedFrame
        self.authorization = authorization
    }

    public init(from decoder: Decoder) throws {
        try opaquePacketRequireExactObject(
            decoder,
            keys: CodingKeys.allCases.map(\.rawValue)
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        routeID = try container.decode(OpaqueReceiveRouteIDV2.self, forKey: .routeID)
        packetID = try container.decode(OpaqueRoutePacketIDV2.self, forKey: .packetID)
        sealedFrame = try container.decode(Data.self, forKey: .sealedFrame)
        authorization = try container.decode(
            OpaqueRouteAuthorizationProofV2.self,
            forKey: .authorization
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .sealedFrame,
                in: container,
                debugDescription: "Opaque route packet is malformed or its authorization is not bound to its relay projection"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Opaque route packet is malformed"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(routeID, forKey: .routeID)
        try container.encode(packetID, forKey: .packetID)
        try container.encode(sealedFrame, forKey: .sealedFrame)
        try container.encode(authorization, forKey: .authorization)
    }

    public var paddingBucket: OpaqueRoutePaddingBucketV2? {
        guard let rawValue = UInt32(exactly: sealedFrame.count) else { return nil }
        return OpaqueRoutePaddingBucketV2(rawValue: rawValue)
    }

    /// A deterministic, domain-separated digest over the complete relay
    /// projection except the proof itself. This is the digest authorized by
    /// the route send capability.
    public var operationDigest: Data {
        Self.operationDigest(
            routeID: routeID,
            packetID: packetID,
            sealedFrame: sealedFrame
        )
    }

    public var isStructurallyValid: Bool {
        routeID.isStructurallyValid
            && packetID.isStructurallyValid
            && paddingBucket != nil
            && authorization.isStructurallyValid
            && authorization.authority == .send
            && authorization.operationDigest == operationDigest
    }

    public func open(
        payloadKey: OpaqueRoutePayloadKeyV2,
        routeRevision: UInt64
    ) throws -> OpaqueRouteFragmentV2 {
        guard isStructurallyValid,
              payloadKey.isStructurallyValid,
              let bucket = paddingBucket else {
            throw OpaqueRoutePacketV2Error.invalidPacket
        }
        let nonceEnd = NoctweaveOpaqueRoutePacketsV2.nonceBytes
        let tagStart = sealedFrame.count - NoctweaveOpaqueRoutePacketsV2.authenticationTagBytes
        guard nonceEnd < tagStart else { throw OpaqueRoutePacketV2Error.invalidPacket }

        let authenticatedData = opaquePacketAuthenticatedData(
            routeID: routeID,
            packetID: packetID,
            routeRevision: routeRevision,
            bucket: bucket
        )
        let plaintext: Data
        do {
            let nonce = try AES.GCM.Nonce(data: sealedFrame.prefix(nonceEnd))
            let box = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: sealedFrame[nonceEnd..<tagStart],
                tag: sealedFrame[tagStart...]
            )
            plaintext = try AES.GCM.open(
                box,
                using: SymmetricKey(data: payloadKey.rawValue),
                authenticating: authenticatedData
            )
        } catch {
            throw OpaqueRoutePacketV2Error.decryptionFailed
        }
        return try opaquePacketDecodeFragment(
            plaintext,
            routeID: routeID,
            packetID: packetID,
            routeRevision: routeRevision,
            bucket: bucket
        )
    }

    static func operationDigest(
        routeID: OpaqueReceiveRouteIDV2,
        packetID: OpaqueRoutePacketIDV2,
        sealedFrame: Data
    ) -> Data {
        opaquePacketDigest(
            domain: "org.noctweave.opaque-route.packet-operation/v2",
            components: [routeID.rawValue, packetID.rawValue, sealedFrame]
        )
    }
}

// MARK: - Client-side sealed bundles

public struct OpaqueRouteFragmentV2: Equatable {
    public let routeID: OpaqueReceiveRouteIDV2
    public let packetID: OpaqueRoutePacketIDV2
    public let routeRevision: UInt64
    public let paddingBucket: OpaqueRoutePaddingBucketV2
    public let bundleID: OpaqueRouteBundleIDV2
    public let bundleDigest: Data
    public let fragmentIndex: UInt32
    public let fragmentCount: UInt32
    public let totalPayloadBytes: UInt64
    public let payload: Data

    public var isStructurallyValid: Bool {
        guard routeID.isStructurallyValid,
              packetID.isStructurallyValid,
              bundleID.isStructurallyValid,
              bundleDigest.count == NoctweaveOpaqueRoutePacketsV2.digestBytes,
              fragmentCount > 0,
              fragmentCount <= UInt32(NoctweaveOpaqueRoutePacketsV2.maximumFragmentCount),
              fragmentIndex < fragmentCount,
              totalPayloadBytes > 0,
              totalPayloadBytes <= UInt64(NoctweaveOpaqueRoutePacketsV2.maximumBundleBytes) else {
            return false
        }
        let capacity = NoctweaveOpaqueRoutePacketsV2.maximumFragmentPayloadBytes(
            for: paddingBucket
        )
        let total = Int(totalPayloadBytes)
        let expectedCount = (total + capacity - 1) / capacity
        guard Int(fragmentCount) == expectedCount else { return false }
        let expectedBytes: Int
        if Int(fragmentIndex) == expectedCount - 1 {
            expectedBytes = total - (expectedCount - 1) * capacity
        } else {
            expectedBytes = capacity
        }
        return payload.count == expectedBytes
    }
}

public struct OpaqueRouteSealedBundleV2: Equatable {
    public let bundleID: OpaqueRouteBundleIDV2
    public let bundleDigest: Data
    public let routeRevision: UInt64
    public let paddingBucket: OpaqueRoutePaddingBucketV2
    public let packets: [OpaqueRoutePacketV2]

    public static func seal(
        _ payload: Data,
        to sendRoute: OpaqueSendRouteV2,
        authorizedAt: Date = Date(),
        bundleID: OpaqueRouteBundleIDV2 = .generate()
    ) throws -> OpaqueRouteSealedBundleV2 {
        guard !payload.isEmpty else { throw OpaqueRoutePacketV2Error.emptyPayload }
        guard payload.count <= NoctweaveOpaqueRoutePacketsV2.maximumBundleBytes else {
            throw OpaqueRoutePacketV2Error.payloadTooLarge
        }
        guard sendRoute.isUsable(at: authorizedAt),
              bundleID.isStructurallyValid,
              authorizedAt.timeIntervalSince1970.isFinite else {
            throw OpaqueRoutePacketV2Error.invalidBundle
        }
        let routeRevision = sendRoute.routeRevision
        let paddingBucket = sendRoute.policy.paddingBucket
        let payloadKey = sendRoute.payloadKey
        let fragmentCapacity = NoctweaveOpaqueRoutePacketsV2.maximumFragmentPayloadBytes(
            for: paddingBucket
        )
        guard fragmentCapacity > 0 else { throw OpaqueRoutePacketV2Error.invalidBundle }
        let fragmentCount = (payload.count + fragmentCapacity - 1) / fragmentCapacity
        guard fragmentCount <= NoctweaveOpaqueRoutePacketsV2.maximumFragmentCount else {
            throw OpaqueRoutePacketV2Error.fragmentCountExceeded
        }

        let bundleDigest = opaquePacketBundleDigest(bundleID: bundleID, payload: payload)
        var packets: [OpaqueRoutePacketV2] = []
        packets.reserveCapacity(fragmentCount)
        var packetIDs = Set<OpaqueRoutePacketIDV2>()

        for index in 0..<fragmentCount {
            let lower = index * fragmentCapacity
            let upper = min(payload.count, lower + fragmentCapacity)
            let fragment = Data(payload[lower..<upper])
            var packetID = OpaqueRoutePacketIDV2.generate()
            while packetIDs.contains(packetID) {
                packetID = .generate()
            }
            packetIDs.insert(packetID)

            let frame = try opaquePacketEncodeFrame(
                bundleID: bundleID,
                bundleDigest: bundleDigest,
                fragmentIndex: UInt32(index),
                fragmentCount: UInt32(fragmentCount),
                totalPayloadBytes: UInt64(payload.count),
                fragment: fragment,
                bucket: paddingBucket
            )
            let authenticatedData = opaquePacketAuthenticatedData(
                routeID: sendRoute.routeID,
                packetID: packetID,
                routeRevision: routeRevision,
                bucket: paddingBucket
            )
            let sealed = try AES.GCM.seal(
                frame,
                using: SymmetricKey(data: payloadKey.rawValue),
                nonce: AES.GCM.Nonce(),
                authenticating: authenticatedData
            )
            var sealedFrame = Data(sealed.nonce)
            sealedFrame.append(sealed.ciphertext)
            sealedFrame.append(sealed.tag)
            guard sealedFrame.count == Int(paddingBucket.rawValue) else {
                throw OpaqueRoutePacketV2Error.invalidPacket
            }

            let operationDigest = OpaqueRoutePacketV2.operationDigest(
                routeID: sendRoute.routeID,
                packetID: packetID,
                sealedFrame: sealedFrame
            )
            let proof = try sendRoute.sendCapability.makeAuthorization(
                routeID: sendRoute.routeID,
                operationDigest: operationDigest,
                authorizedAt: authorizedAt
            )
            let packet = OpaqueRoutePacketV2(
                routeID: sendRoute.routeID,
                packetID: packetID,
                sealedFrame: sealedFrame,
                authorization: proof
            )
            guard packet.isStructurallyValid else {
                throw OpaqueRoutePacketV2Error.invalidPacket
            }
            packets.append(packet)
        }

        return OpaqueRouteSealedBundleV2(
            bundleID: bundleID,
            bundleDigest: bundleDigest,
            routeRevision: routeRevision,
            paddingBucket: paddingBucket,
            packets: packets
        )
    }

    public var isStructurallyValid: Bool {
        guard bundleID.isStructurallyValid,
              bundleDigest.count == NoctweaveOpaqueRoutePacketsV2.digestBytes,
              !packets.isEmpty,
              packets.count <= NoctweaveOpaqueRoutePacketsV2.maximumFragmentCount,
              Set(packets.map(\.packetID)).count == packets.count,
              let routeID = packets.first?.routeID else {
            return false
        }
        return packets.allSatisfy {
            $0.routeID == routeID
                && $0.paddingBucket == paddingBucket
                && $0.isStructurallyValid
        }
    }
}

// MARK: - Strict bounded reassembly

public struct OpaqueRouteReassembledBundleV2: Equatable {
    public let routeID: OpaqueReceiveRouteIDV2
    public let routeRevision: UInt64
    public let bundleID: OpaqueRouteBundleIDV2
    public let bundleDigest: Data
    public let payload: Data
}

public enum OpaqueRoutePacketReassemblyResultV2: Equatable {
    case accepted
    case duplicate
    case complete(OpaqueRouteReassembledBundleV2)
}

public struct OpaqueRoutePacketReassemblerV2 {
    public static let defaultMaximumBufferedBundles = 64
    public static let defaultMaximumBufferedBytes = 64 * 1_024 * 1_024
    public static let maximumRecentCompletedBundles = 1_024

    private struct PendingBundle {
        let routeID: OpaqueReceiveRouteIDV2
        let routeRevision: UInt64
        let paddingBucket: OpaqueRoutePaddingBucketV2
        let bundleDigest: Data
        let fragmentCount: UInt32
        let totalPayloadBytes: UInt64
        var fragments: [UInt32: Data]
        var packetIDs: Set<OpaqueRoutePacketIDV2>
    }

    private struct CompletedBundle {
        let routeID: OpaqueReceiveRouteIDV2
        let routeRevision: UInt64
        let bundleDigest: Data
    }

    public let maximumBufferedBundles: Int
    public let maximumBufferedBytes: Int

    private var pending: [OpaqueRouteBundleIDV2: PendingBundle] = [:]
    private var packetDigests: [OpaqueRoutePacketIDV2: Data] = [:]
    private var completed: [OpaqueRouteBundleIDV2: CompletedBundle] = [:]
    private var completedOrder: [OpaqueRouteBundleIDV2] = []
    private var bufferedBytes = 0

    public init(
        maximumBufferedBundles: Int = Self.defaultMaximumBufferedBundles,
        maximumBufferedBytes: Int = Self.defaultMaximumBufferedBytes
    ) throws {
        guard maximumBufferedBundles > 0,
              maximumBufferedBundles <= 256,
              maximumBufferedBytes > 0,
              maximumBufferedBytes <= NoctweaveOpaqueRoutePacketsV2.maximumBundleBytes else {
            throw OpaqueRoutePacketV2Error.reassemblyCapacityExceeded
        }
        self.maximumBufferedBundles = maximumBufferedBundles
        self.maximumBufferedBytes = maximumBufferedBytes
    }

    public var pendingBundleCount: Int { pending.count }
    public var bufferedPayloadBytes: Int { bufferedBytes }

    public mutating func consume(
        _ packet: OpaqueRoutePacketV2,
        payloadKey: OpaqueRoutePayloadKeyV2,
        routeRevision: UInt64
    ) throws -> OpaqueRoutePacketReassemblyResultV2 {
        guard packet.isStructurallyValid else {
            throw OpaqueRoutePacketV2Error.invalidPacket
        }
        let packetDigest = packet.operationDigest
        if let existing = packetDigests[packet.packetID] {
            guard existing == packetDigest else {
                throw OpaqueRoutePacketV2Error.packetIdentifierConflict
            }
            return .duplicate
        }

        let fragment = try packet.open(
            payloadKey: payloadKey,
            routeRevision: routeRevision
        )
        guard fragment.isStructurallyValid else {
            throw OpaqueRoutePacketV2Error.malformedFrame
        }
        if let prior = completed[fragment.bundleID] {
            guard prior.routeID == fragment.routeID,
                  prior.routeRevision == fragment.routeRevision,
                  prior.bundleDigest == fragment.bundleDigest else {
                throw OpaqueRoutePacketV2Error.bundleConflict
            }
            return .duplicate
        }

        if var state = pending[fragment.bundleID] {
            guard state.routeID == fragment.routeID,
                  state.routeRevision == fragment.routeRevision,
                  state.paddingBucket == fragment.paddingBucket,
                  state.bundleDigest == fragment.bundleDigest,
                  state.fragmentCount == fragment.fragmentCount,
                  state.totalPayloadBytes == fragment.totalPayloadBytes else {
                throw OpaqueRoutePacketV2Error.bundleConflict
            }
            if let existing = state.fragments[fragment.fragmentIndex] {
                guard existing == fragment.payload else {
                    throw OpaqueRoutePacketV2Error.fragmentConflict
                }
                return .duplicate
            }
            guard bufferedBytes <= maximumBufferedBytes - fragment.payload.count else {
                throw OpaqueRoutePacketV2Error.reassemblyCapacityExceeded
            }
            state.fragments[fragment.fragmentIndex] = fragment.payload
            state.packetIDs.insert(packet.packetID)
            pending[fragment.bundleID] = state
        } else {
            guard pending.count < maximumBufferedBundles,
                  fragment.totalPayloadBytes <= UInt64(maximumBufferedBytes),
                  fragment.payload.count <= maximumBufferedBytes - bufferedBytes else {
                throw OpaqueRoutePacketV2Error.reassemblyCapacityExceeded
            }
            pending[fragment.bundleID] = PendingBundle(
                routeID: fragment.routeID,
                routeRevision: fragment.routeRevision,
                paddingBucket: fragment.paddingBucket,
                bundleDigest: fragment.bundleDigest,
                fragmentCount: fragment.fragmentCount,
                totalPayloadBytes: fragment.totalPayloadBytes,
                fragments: [fragment.fragmentIndex: fragment.payload],
                packetIDs: [packet.packetID]
            )
        }
        packetDigests[packet.packetID] = packetDigest
        bufferedBytes += fragment.payload.count

        guard let state = pending[fragment.bundleID],
              state.fragments.count == Int(state.fragmentCount) else {
            return .accepted
        }

        var payload = Data()
        payload.reserveCapacity(Int(state.totalPayloadBytes))
        for index in 0..<state.fragmentCount {
            guard let part = state.fragments[index] else {
                throw OpaqueRoutePacketV2Error.malformedFrame
            }
            payload.append(part)
        }
        guard payload.count == Int(state.totalPayloadBytes) else {
            removePending(fragment.bundleID)
            throw OpaqueRoutePacketV2Error.malformedFrame
        }
        let digest = opaquePacketBundleDigest(bundleID: fragment.bundleID, payload: payload)
        guard digest == state.bundleDigest else {
            removePending(fragment.bundleID)
            throw OpaqueRoutePacketV2Error.bundleDigestMismatch
        }
        let completed = OpaqueRouteReassembledBundleV2(
            routeID: state.routeID,
            routeRevision: state.routeRevision,
            bundleID: fragment.bundleID,
            bundleDigest: state.bundleDigest,
            payload: payload
        )
        removePending(fragment.bundleID)
        rememberCompleted(completed)
        return .complete(completed)
    }

    private mutating func removePending(_ bundleID: OpaqueRouteBundleIDV2) {
        guard let removed = pending.removeValue(forKey: bundleID) else { return }
        for part in removed.fragments.values {
            bufferedBytes -= part.count
        }
        for packetID in removed.packetIDs {
            packetDigests.removeValue(forKey: packetID)
        }
    }

    private mutating func rememberCompleted(_ bundle: OpaqueRouteReassembledBundleV2) {
        completed[bundle.bundleID] = CompletedBundle(
            routeID: bundle.routeID,
            routeRevision: bundle.routeRevision,
            bundleDigest: bundle.bundleDigest
        )
        completedOrder.append(bundle.bundleID)
        if completedOrder.count > Self.maximumRecentCompletedBundles {
            let expired = completedOrder.removeFirst()
            completed.removeValue(forKey: expired)
        }
    }
}

// MARK: - Canonical frame encoding

private let opaquePacketFrameMagic = Data([0x4E, 0x57, 0x52, 0x50]) // NWRP

private func opaquePacketEncodeFrame(
    bundleID: OpaqueRouteBundleIDV2,
    bundleDigest: Data,
    fragmentIndex: UInt32,
    fragmentCount: UInt32,
    totalPayloadBytes: UInt64,
    fragment: Data,
    bucket: OpaqueRoutePaddingBucketV2
) throws -> Data {
    let frameBytes = Int(bucket.rawValue)
        - NoctweaveOpaqueRoutePacketsV2.nonceBytes
        - NoctweaveOpaqueRoutePacketsV2.authenticationTagBytes
    let capacity = NoctweaveOpaqueRoutePacketsV2.maximumFragmentPayloadBytes(for: bucket)
    guard bundleID.isStructurallyValid,
          bundleDigest.count == NoctweaveOpaqueRoutePacketsV2.digestBytes,
          fragmentCount > 0,
          fragmentCount <= UInt32(NoctweaveOpaqueRoutePacketsV2.maximumFragmentCount),
          fragmentIndex < fragmentCount,
          totalPayloadBytes > 0,
          totalPayloadBytes <= UInt64(NoctweaveOpaqueRoutePacketsV2.maximumBundleBytes),
          fragment.count <= capacity else {
        throw OpaqueRoutePacketV2Error.invalidBundle
    }

    var frame = Data()
    frame.reserveCapacity(frameBytes)
    frame.append(opaquePacketFrameMagic)
    opaquePacketAppend(NoctweaveOpaqueRoutePacketsV2.version, to: &frame)
    frame.append(bundleID.rawValue)
    frame.append(bundleDigest)
    opaquePacketAppend(fragmentIndex, to: &frame)
    opaquePacketAppend(fragmentCount, to: &frame)
    opaquePacketAppend(totalPayloadBytes, to: &frame)
    opaquePacketAppend(UInt32(fragment.count), to: &frame)
    frame.append(fragment)
    let paddingCount = frameBytes - frame.count
    guard paddingCount >= NoctweaveOpaqueRoutePacketsV2.minimumRandomPaddingBytes else {
        throw OpaqueRoutePacketV2Error.invalidBundle
    }
    frame.append(opaquePacketRandomBytes(count: paddingCount))
    guard frame.count == frameBytes else { throw OpaqueRoutePacketV2Error.invalidBundle }
    return frame
}

private func opaquePacketDecodeFragment(
    _ frame: Data,
    routeID: OpaqueReceiveRouteIDV2,
    packetID: OpaqueRoutePacketIDV2,
    routeRevision: UInt64,
    bucket: OpaqueRoutePaddingBucketV2
) throws -> OpaqueRouteFragmentV2 {
    let expectedFrameBytes = Int(bucket.rawValue)
        - NoctweaveOpaqueRoutePacketsV2.nonceBytes
        - NoctweaveOpaqueRoutePacketsV2.authenticationTagBytes
    guard frame.count == expectedFrameBytes,
          frame.prefix(opaquePacketFrameMagic.count) == opaquePacketFrameMagic else {
        throw OpaqueRoutePacketV2Error.malformedFrame
    }
    var offset = opaquePacketFrameMagic.count
    guard let version: UInt16 = opaquePacketRead(frame, offset: &offset),
          version == NoctweaveOpaqueRoutePacketsV2.version,
          let bundleIDBytes = opaquePacketReadBytes(
              frame,
              offset: &offset,
              count: NoctweaveOpaqueRoutePacketsV2.identifierBytes
          ),
          let bundleDigest = opaquePacketReadBytes(
              frame,
              offset: &offset,
              count: NoctweaveOpaqueRoutePacketsV2.digestBytes
          ),
          let fragmentIndex: UInt32 = opaquePacketRead(frame, offset: &offset),
          let fragmentCount: UInt32 = opaquePacketRead(frame, offset: &offset),
          let totalPayloadBytes: UInt64 = opaquePacketRead(frame, offset: &offset),
          let fragmentBytes: UInt32 = opaquePacketRead(frame, offset: &offset),
          Int(fragmentBytes) <= frame.count - offset,
          frame.count - offset - Int(fragmentBytes)
            >= NoctweaveOpaqueRoutePacketsV2.minimumRandomPaddingBytes else {
        throw OpaqueRoutePacketV2Error.malformedFrame
    }
    let bundleID = OpaqueRouteBundleIDV2(rawValue: bundleIDBytes)
    guard bundleID.isStructurallyValid else {
        throw OpaqueRoutePacketV2Error.malformedFrame
    }
    let payload = Data(frame[offset..<(offset + Int(fragmentBytes))])
    let fragment = OpaqueRouteFragmentV2(
        routeID: routeID,
        packetID: packetID,
        routeRevision: routeRevision,
        paddingBucket: bucket,
        bundleID: bundleID,
        bundleDigest: bundleDigest,
        fragmentIndex: fragmentIndex,
        fragmentCount: fragmentCount,
        totalPayloadBytes: totalPayloadBytes,
        payload: payload
    )
    guard fragment.isStructurallyValid else {
        throw OpaqueRoutePacketV2Error.malformedFrame
    }
    return fragment
}

private func opaquePacketAuthenticatedData(
    routeID: OpaqueReceiveRouteIDV2,
    packetID: OpaqueRoutePacketIDV2,
    routeRevision: UInt64,
    bucket: OpaqueRoutePaddingBucketV2
) -> Data {
    var data = Data("org.noctweave.opaque-route.packet-aad/v2".utf8)
    data.append(0)
    data.append(routeID.rawValue)
    data.append(packetID.rawValue)
    opaquePacketAppend(routeRevision, to: &data)
    opaquePacketAppend(bucket.rawValue, to: &data)
    return data
}

private func opaquePacketBundleDigest(
    bundleID: OpaqueRouteBundleIDV2,
    payload: Data
) -> Data {
    var payloadLength = Data()
    opaquePacketAppend(UInt64(payload.count), to: &payloadLength)
    return opaquePacketDigest(
        domain: "org.noctweave.opaque-route.bundle/v2",
        components: [bundleID.rawValue, payloadLength, payload]
    )
}

private func opaquePacketDigest(domain: String, components: [Data]) -> Data {
    var material = Data(domain.utf8)
    material.append(0)
    for component in components {
        opaquePacketAppend(UInt64(component.count), to: &material)
        material.append(component)
    }
    return Data(SHA256.hash(data: material))
}

private func opaquePacketIsValidIdentifier(_ value: Data) -> Bool {
    value.count == NoctweaveOpaqueRoutePacketsV2.identifierBytes
        && value.contains(where: { $0 != 0 })
}

private func opaquePacketRandomNonzeroValue() -> Data {
    while true {
        let value = opaquePacketRandomBytes(
            count: NoctweaveOpaqueRoutePacketsV2.identifierBytes
        )
        if opaquePacketIsValidIdentifier(value) { return value }
    }
}

private func opaquePacketRandomBytes(count: Int) -> Data {
    guard count > 0 else { return Data() }
    var generator = SystemRandomNumberGenerator()
    var data = Data(count: count)
    data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) in
        for index in 0..<buffer.count {
            buffer[index] = UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
        }
    }
    return data
}

private func opaquePacketAppend<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
    var bigEndian = value.bigEndian
    Swift.withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
}

private func opaquePacketRead<T: FixedWidthInteger>(
    _ data: Data,
    offset: inout Int
) -> T? {
    let count = MemoryLayout<T>.size
    guard offset >= 0, count <= data.count - offset else { return nil }
    var value: T = 0
    for byte in data[offset..<(offset + count)] {
        value = (value << 8) | T(byte)
    }
    offset += count
    return value
}

private func opaquePacketReadBytes(
    _ data: Data,
    offset: inout Int,
    count: Int
) -> Data? {
    guard count >= 0, offset >= 0, count <= data.count - offset else { return nil }
    let value = Data(data[offset..<(offset + count)])
    offset += count
    return value
}

private struct OpaquePacketExactCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private func opaquePacketRequireExactObject(
    _ decoder: Decoder,
    keys: [String]
) throws {
    let container = try decoder.container(keyedBy: OpaquePacketExactCodingKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == Set(keys) else {
        throw DecodingError.dataCorrupted(
            DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: "Opaque route packet fields must match the current protocol exactly"
            )
        )
    }
}
