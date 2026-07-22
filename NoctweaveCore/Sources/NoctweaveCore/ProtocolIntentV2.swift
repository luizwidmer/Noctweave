import CryptoKit
import Foundation

public enum ProtocolIntentKindV2: String, Codable, Equatable, CaseIterable {
    case sendEvent
    case uploadBlob
    case downloadBlob
    case rolloverRoute
    case renewRelationshipPrekey
}

public enum ProtocolIntentStateV2: String, Codable, Equatable, CaseIterable {
    case prepared
    case published
    case committed
    case finalized
    case permanentFailure

    public var isTerminal: Bool {
        self == .finalized || self == .permanentFailure
    }
}

public enum ProtocolIntentErrorClassV2: String, Codable, Equatable, CaseIterable {
    case networkUnavailable
    case relayUnavailable
    case relayRejected
    case epochConflict
    case dependencyUnavailable
    case dependencyFailed
    case expired
    case authorizationRejected
    case invalidPayload
    case unsupportedCapability
    case attemptLimitExceeded

    public var isRetryable: Bool {
        switch self {
        case .networkUnavailable, .relayUnavailable, .epochConflict, .dependencyUnavailable:
            return true
        case .relayRejected, .dependencyFailed, .expired, .authorizationRejected, .invalidPayload,
             .unsupportedCapability, .attemptLimitExceeded:
            return false
        }
    }
}

public struct ProtocolIntentIdempotencyKeyV2: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: Data

    public init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public static func generate(intentId: UUID, nonce: UUID = UUID()) -> ProtocolIntentIdempotencyKeyV2 {
        var material = Data("Noctweave/protocol-intent-idempotency/v2".utf8)
        material.append(Data(intentId.uuidString.lowercased().utf8))
        material.append(Data(nonce.uuidString.lowercased().utf8))
        return ProtocolIntentIdempotencyKeyV2(rawValue: Data(SHA256.hash(data: material)))
    }

    public var isStructurallyValid: Bool {
        rawValue.count == 32
    }
}

/// A bounded local mutation journal entry. It stores opaque identifiers and a
/// payload digest, not application plaintext or reusable private key material.
public struct ProtocolIntentV2: Codable, Equatable, Identifiable {
    public static let maximumTargetIdentifierBytes = 128

    public let id: UUID
    public let kind: ProtocolIntentKindV2
    public let targetIdentifier: Data?
    public let expectedEpoch: UInt64?
    public let idempotencyKey: ProtocolIntentIdempotencyKeyV2
    public let payloadDigest: Data
    public let dependencies: [UUID]
    public let state: ProtocolIntentStateV2
    public let attemptCount: UInt32
    public let lastAttemptId: UUID?
    public let lastAttemptAt: Date?
    public let lastErrorClass: ProtocolIntentErrorClassV2?
    public let nextAttemptNotBefore: Date?
    public let createdAt: Date
    public let updatedAt: Date
    public let expiresAt: Date?

    public init(
        id: UUID,
        kind: ProtocolIntentKindV2,
        targetIdentifier: Data? = nil,
        expectedEpoch: UInt64? = nil,
        idempotencyKey: ProtocolIntentIdempotencyKeyV2,
        payloadDigest: Data,
        dependencies: [UUID] = [],
        state: ProtocolIntentStateV2 = .prepared,
        attemptCount: UInt32 = 0,
        lastAttemptId: UUID? = nil,
        lastAttemptAt: Date? = nil,
        lastErrorClass: ProtocolIntentErrorClassV2? = nil,
        nextAttemptNotBefore: Date? = nil,
        createdAt: Date,
        updatedAt: Date,
        expiresAt: Date? = nil
    ) {
        self.id = id
        self.kind = kind
        self.targetIdentifier = targetIdentifier
        self.expectedEpoch = expectedEpoch
        self.idempotencyKey = idempotencyKey
        self.payloadDigest = payloadDigest
        self.dependencies = dependencies.sorted { $0.uuidString < $1.uuidString }
        self.state = state
        self.attemptCount = attemptCount
        self.lastAttemptId = lastAttemptId
        self.lastAttemptAt = lastAttemptAt
        self.lastErrorClass = lastErrorClass
        self.nextAttemptNotBefore = nextAttemptNotBefore
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.expiresAt = expiresAt
    }

    public static func prepare(
        id: UUID = UUID(),
        kind: ProtocolIntentKindV2,
        targetIdentifier: Data? = nil,
        expectedEpoch: UInt64? = nil,
        idempotencyKey: ProtocolIntentIdempotencyKeyV2? = nil,
        payloadDigest: Data,
        dependencies: [UUID] = [],
        createdAt: Date = Date(),
        expiresAt: Date? = nil
    ) -> ProtocolIntentV2 {
        ProtocolIntentV2(
            id: id,
            kind: kind,
            targetIdentifier: targetIdentifier,
            expectedEpoch: expectedEpoch,
            idempotencyKey: idempotencyKey ?? .generate(intentId: id),
            payloadDigest: payloadDigest,
            dependencies: dependencies,
            createdAt: createdAt,
            updatedAt: createdAt,
            expiresAt: expiresAt
        )
    }

    public var isStructurallyValid: Bool {
        guard targetIdentifier.map({
                  !$0.isEmpty && $0.count <= Self.maximumTargetIdentifierBytes
              }) ?? true,
              idempotencyKey.isStructurallyValid,
              payloadDigest.count == 32,
              dependencies.count <= NoctweaveArchitectureV2.maximumIntentDependencies,
              Set(dependencies).count == dependencies.count,
              !dependencies.contains(id),
              attemptCount <= UInt32(NoctweaveArchitectureV2.maximumIntentAttempts),
              createdAt.timeIntervalSince1970.isFinite,
              updatedAt.timeIntervalSince1970.isFinite,
              updatedAt >= createdAt,
              expiresAt?.timeIntervalSince1970.isFinite ?? true,
              expiresAt.map({ $0 > createdAt }) ?? true,
              lastAttemptAt?.timeIntervalSince1970.isFinite ?? true,
              nextAttemptNotBefore?.timeIntervalSince1970.isFinite ?? true else {
            return false
        }

        if attemptCount == 0 {
            guard lastAttemptId == nil,
                  lastAttemptAt == nil,
                  nextAttemptNotBefore == nil else {
                return false
            }
            if lastErrorClass != nil && state != .permanentFailure { return false }
        } else {
            guard lastAttemptId != nil,
                  let lastAttemptAt,
                  lastAttemptAt >= createdAt,
                  lastAttemptAt <= updatedAt else {
                return false
            }
        }

        if let nextAttemptNotBefore {
            guard !state.isTerminal,
                  lastErrorClass?.isRetryable == true,
                  nextAttemptNotBefore >= updatedAt else {
                return false
            }
        }
        if lastErrorClass?.isRetryable == true && !state.isTerminal && nextAttemptNotBefore == nil {
            return false
        }
        if !state.isTerminal, let lastErrorClass, !lastErrorClass.isRetryable { return false }
        if state.isTerminal && nextAttemptNotBefore != nil { return false }
        if state == .finalized && lastErrorClass != nil { return false }
        if state == .permanentFailure && lastErrorClass?.isRetryable != false { return false }
        return true
    }

    public func isReady(completedIntentIds: Set<UUID>, at date: Date) -> Bool {
        guard isStructurallyValid,
              date.timeIntervalSince1970.isFinite,
              !state.isTerminal,
              attemptCount < UInt32(NoctweaveArchitectureV2.maximumIntentAttempts),
              Set(dependencies).isSubset(of: completedIntentIds),
              expiresAt.map({ date < $0 }) ?? true,
              nextAttemptNotBefore.map({ date >= $0 }) ?? true else {
            return false
        }
        return true
    }

    /// Starts one retryable attempt. Replaying the same attempt identifier is a
    /// no-op, so crash recovery cannot inflate retry counters.
    public func beginningAttempt(
        id attemptId: UUID,
        completedIntentIds: Set<UUID>,
        at date: Date
    ) -> ProtocolIntentV2? {
        if lastAttemptId == attemptId { return self }
        guard isReady(completedIntentIds: completedIntentIds, at: date),
              date >= updatedAt else {
            return nil
        }
        return replacing(
            attemptCount: attemptCount + 1,
            lastAttemptId: attemptId,
            lastAttemptAt: date,
            lastErrorClass: nil,
            nextAttemptNotBefore: nil,
            updatedAt: date
        )
    }

    /// Records a retryable failure once for the current attempt. The retry
    /// deadline is durable and must pass before a new attempt may start.
    public func recordingTransientFailure(
        attemptId: UUID,
        errorClass: ProtocolIntentErrorClassV2,
        retryNotBefore: Date,
        at date: Date
    ) -> ProtocolIntentV2? {
        guard !state.isTerminal,
              errorClass.isRetryable,
              lastAttemptId == attemptId,
              let lastAttemptAt,
              date >= lastAttemptAt,
              date >= updatedAt,
              retryNotBefore >= date else {
            return nil
        }
        if lastErrorClass != nil { return self }
        return replacing(
            lastErrorClass: errorClass,
            nextAttemptNotBefore: retryNotBefore,
            updatedAt: date
        )
    }

    /// Advances exactly one durable stage. Skipping a stage is rejected, while
    /// replaying an already-applied stage is idempotent.
    public func advancing(
        to newState: ProtocolIntentStateV2,
        attemptId: UUID,
        at date: Date
    ) -> ProtocolIntentV2? {
        if state == newState { return lastAttemptId == attemptId ? self : nil }
        guard !newState.isTerminal || newState == .finalized,
              lastAttemptId == attemptId,
              lastErrorClass == nil,
              date >= updatedAt,
              Self.isDirectAdvance(from: state, to: newState) else {
            return nil
        }
        return replacing(
            state: newState,
            lastErrorClass: nil,
            nextAttemptNotBefore: nil,
            updatedAt: date
        )
    }

    public func failingPermanently(
        errorClass: ProtocolIntentErrorClassV2,
        at date: Date
    ) -> ProtocolIntentV2? {
        if state == .permanentFailure { return self }
        guard !state.isTerminal,
              !errorClass.isRetryable,
              date >= updatedAt else {
            return nil
        }
        return replacing(
            state: .permanentFailure,
            lastErrorClass: errorClass,
            nextAttemptNotBefore: nil,
            updatedAt: date
        )
    }

    public func expiring(at date: Date) -> ProtocolIntentV2? {
        if state == .permanentFailure { return self }
        guard !state.isTerminal,
              let expiresAt,
              date >= expiresAt,
              date >= updatedAt else {
            return nil
        }
        return replacing(
            state: .permanentFailure,
            lastErrorClass: .expired,
            nextAttemptNotBefore: nil,
            updatedAt: date
        )
    }

    /// Converts bounded retry exhaustion into an explicit terminal result.
    /// Exact authenticated payloads cannot be generically rearmed because
    /// their timestamps, leases, or authorization context may have expired.
    public func exhaustingAttempts(at date: Date) -> ProtocolIntentV2? {
        if state == .permanentFailure { return self }
        guard !state.isTerminal,
              attemptCount >= UInt32(NoctweaveArchitectureV2.maximumIntentAttempts),
              date.timeIntervalSince1970.isFinite,
              date >= updatedAt else {
            return nil
        }
        return failingPermanently(errorClass: .attemptLimitExceeded, at: date)
    }

    private static func isDirectAdvance(
        from oldState: ProtocolIntentStateV2,
        to newState: ProtocolIntentStateV2
    ) -> Bool {
        switch (oldState, newState) {
        case (.prepared, .published), (.published, .committed), (.committed, .finalized):
            return true
        default:
            return false
        }
    }

    private func replacing(
        state: ProtocolIntentStateV2? = nil,
        attemptCount: UInt32? = nil,
        lastAttemptId: UUID? = nil,
        lastAttemptAt: Date? = nil,
        lastErrorClass: ProtocolIntentErrorClassV2? = nil,
        nextAttemptNotBefore: Date? = nil,
        updatedAt: Date
    ) -> ProtocolIntentV2 {
        ProtocolIntentV2(
            id: id,
            kind: kind,
            targetIdentifier: targetIdentifier,
            expectedEpoch: expectedEpoch,
            idempotencyKey: idempotencyKey,
            payloadDigest: payloadDigest,
            dependencies: dependencies,
            state: state ?? self.state,
            attemptCount: attemptCount ?? self.attemptCount,
            lastAttemptId: lastAttemptId ?? self.lastAttemptId,
            lastAttemptAt: lastAttemptAt ?? self.lastAttemptAt,
            lastErrorClass: lastErrorClass,
            nextAttemptNotBefore: nextAttemptNotBefore,
            createdAt: createdAt,
            updatedAt: updatedAt,
            expiresAt: expiresAt
        )
    }
}
