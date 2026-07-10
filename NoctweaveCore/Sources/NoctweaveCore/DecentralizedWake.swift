import CryptoKit
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public enum DecentralizedWakeMode: String, Codable, CaseIterable {
    case pullOnly
    case longPoll
}

public struct DecentralizedWakeSupport: Codable, Equatable {
    public var mode: DecentralizedWakeMode
    public var minPollIntervalSeconds: Int
    public var maxPollIntervalSeconds: Int
    public var jitterPermille: Int
    public var longPollTimeoutSeconds: Int?

    public init(
        mode: DecentralizedWakeMode = .pullOnly,
        minPollIntervalSeconds: Int = 60,
        maxPollIntervalSeconds: Int = 300,
        jitterPermille: Int = 250,
        longPollTimeoutSeconds: Int? = nil
    ) {
        let normalizedMin = max(5, minPollIntervalSeconds)
        let normalizedMax = max(normalizedMin, maxPollIntervalSeconds)
        self.mode = mode
        self.minPollIntervalSeconds = normalizedMin
        self.maxPollIntervalSeconds = normalizedMax
        self.jitterPermille = min(max(0, jitterPermille), 1_000)
        if mode == .longPoll {
            self.longPollTimeoutSeconds = longPollTimeoutSeconds.map { min(max(5, $0), normalizedMax) } ?? normalizedMin
        } else {
            self.longPollTimeoutSeconds = nil
        }
    }
}

public struct DecentralizedWakePlan: Codable, Equatable {
    public let nextPollDelaySeconds: Int
    public let longPollTimeoutSeconds: Int?
    public let failureBackoffStep: Int

    public init(nextPollDelaySeconds: Int, longPollTimeoutSeconds: Int?, failureBackoffStep: Int) {
        self.nextPollDelaySeconds = nextPollDelaySeconds
        self.longPollTimeoutSeconds = longPollTimeoutSeconds
        self.failureBackoffStep = failureBackoffStep
    }
}

public struct DecentralizedWakeProfilePlan: Equatable {
    public let identitySeed: Data
    public let relayIdentifier: String
    public let plan: DecentralizedWakePlan

    public init(identitySeed: Data, relayIdentifier: String, plan: DecentralizedWakePlan) {
        self.identitySeed = identitySeed
        self.relayIdentifier = relayIdentifier
        self.plan = plan
    }
}

public struct DecentralizedWakeCyclePlan: Equatable {
    public let profilePlans: [DecentralizedWakeProfilePlan]
    public let nextPollDelaySeconds: Int
    public let longPollTimeoutSeconds: Int?

    public init(profilePlans: [DecentralizedWakeProfilePlan], nextPollDelaySeconds: Int, longPollTimeoutSeconds: Int?) {
        self.profilePlans = profilePlans
        self.nextPollDelaySeconds = nextPollDelaySeconds
        self.longPollTimeoutSeconds = longPollTimeoutSeconds
    }
}

public struct DecentralizedWakeProfile: Equatable {
    public let support: DecentralizedWakeSupport?
    public let identitySeed: Data
    public let relayIdentifier: String
    public let failureCount: Int

    public init(
        support: DecentralizedWakeSupport?,
        identitySeed: Data,
        relayIdentifier: String,
        failureCount: Int = 0
    ) {
        self.support = support
        self.identitySeed = identitySeed
        self.relayIdentifier = relayIdentifier
        self.failureCount = failureCount
    }
}

public enum DecentralizedPrefetchKind: String, Codable, Equatable {
    case directMessage
    case groupMessage
}

public enum DecentralizedPrefetchError: Error, Equatable {
    case invalidRelayIdentifier
    case invalidInboxId
    case invalidEnvelope
    case emptyBatch
    case invalidBatch
    case invalidProtectionKey
    case invalidStoredBatch
    case batchTooLarge
}

public struct DecentralizedPrefetchRecord: Codable, Equatable, Identifiable {
    public let id: UUID
    public let kind: DecentralizedPrefetchKind
    public let relayIdentifier: String
    public let inboxId: String
    public let groupId: UUID?
    public let stagedAt: Date
    public let sealedEnvelope: Data
    public let acknowledgementDeferred: Bool

    public init(
        id: UUID,
        kind: DecentralizedPrefetchKind,
        relayIdentifier: String,
        inboxId: String,
        groupId: UUID?,
        stagedAt: Date,
        sealedEnvelope: Data,
        acknowledgementDeferred: Bool = true
    ) {
        self.id = id
        self.kind = kind
        self.relayIdentifier = relayIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        self.inboxId = inboxId.trimmingCharacters(in: .whitespacesAndNewlines)
        self.groupId = groupId
        self.stagedAt = stagedAt
        self.sealedEnvelope = sealedEnvelope
        self.acknowledgementDeferred = acknowledgementDeferred
    }
}

public struct DecentralizedPrefetchBatch: Codable, Equatable {
    public let records: [DecentralizedPrefetchRecord]
    public let stagedAt: Date

    public var messageIds: [UUID] {
        records.map(\.id)
    }

    public var isCiphertextOnly: Bool {
        records.allSatisfy { !$0.sealedEnvelope.isEmpty && $0.acknowledgementDeferred }
    }

    public init(records: [DecentralizedPrefetchRecord], stagedAt: Date) {
        self.records = records
        self.stagedAt = stagedAt
    }
}

public struct DecentralizedPrefetchExecutionPolicy: Equatable {
    public var maxProfilesPerCycle: Int
    public var maxRecordsPerPullProfile: Int
    public var maxRecordsPerLongPollProfile: Int
    public var maxTotalRecordsPerCycle: Int

    public init(
        maxProfilesPerCycle: Int = 8,
        maxRecordsPerPullProfile: Int = 8,
        maxRecordsPerLongPollProfile: Int = 16,
        maxTotalRecordsPerCycle: Int = 64
    ) {
        self.maxProfilesPerCycle = max(1, maxProfilesPerCycle)
        self.maxRecordsPerPullProfile = max(1, maxRecordsPerPullProfile)
        self.maxRecordsPerLongPollProfile = max(
            self.maxRecordsPerPullProfile,
            maxRecordsPerLongPollProfile
        )
        self.maxTotalRecordsPerCycle = max(1, maxTotalRecordsPerCycle)
    }
}

public struct DecentralizedPrefetchProfileExecution: Equatable {
    public let identitySeed: Data
    public let relayIdentifier: String
    public let nextPollDelaySeconds: Int
    public let longPollTimeoutSeconds: Int?
    public let maxEnvelopeCount: Int

    public init(
        identitySeed: Data,
        relayIdentifier: String,
        nextPollDelaySeconds: Int,
        longPollTimeoutSeconds: Int?,
        maxEnvelopeCount: Int
    ) {
        self.identitySeed = identitySeed
        self.relayIdentifier = relayIdentifier
        self.nextPollDelaySeconds = nextPollDelaySeconds
        self.longPollTimeoutSeconds = longPollTimeoutSeconds
        self.maxEnvelopeCount = max(1, maxEnvelopeCount)
    }
}

public struct DecentralizedPrefetchExecutionPlan: Equatable {
    public let profileExecutions: [DecentralizedPrefetchProfileExecution]
    public let nextCycleDelaySeconds: Int
    public let longPollTimeoutSeconds: Int?
    public let maxTotalEnvelopeCount: Int

    public init(
        profileExecutions: [DecentralizedPrefetchProfileExecution],
        nextCycleDelaySeconds: Int,
        longPollTimeoutSeconds: Int?,
        maxTotalEnvelopeCount: Int
    ) {
        self.profileExecutions = profileExecutions
        self.nextCycleDelaySeconds = nextCycleDelaySeconds
        self.longPollTimeoutSeconds = longPollTimeoutSeconds
        self.maxTotalEnvelopeCount = max(0, maxTotalEnvelopeCount)
    }
}

public enum DecentralizedPrefetchStager {
    public static let maximumRecordsPerBatch = 128
    public static let maximumSealedEnvelopeBytes = 512 * 1024

    public static func stageDirectMessages(
        _ envelopes: [Envelope],
        inboxId: String,
        relayIdentifier: String,
        stagedAt: Date = Date()
    ) throws -> DecentralizedPrefetchBatch {
        guard !envelopes.isEmpty else { throw DecentralizedPrefetchError.emptyBatch }
        guard envelopes.count <= maximumRecordsPerBatch else { throw DecentralizedPrefetchError.batchTooLarge }
        let relayIdentifier = try normalizedRelayIdentifier(relayIdentifier)
        let inboxId = try normalizedInboxId(inboxId)
        let records = try envelopes.map { envelope in
            guard !envelope.payload.ciphertext.isEmpty else {
                throw DecentralizedPrefetchError.invalidEnvelope
            }
            let sealedEnvelope = try NoctweaveCoder.encode(envelope)
            guard sealedEnvelope.count <= maximumSealedEnvelopeBytes else {
                throw DecentralizedPrefetchError.invalidEnvelope
            }
            return DecentralizedPrefetchRecord(
                id: envelope.id,
                kind: .directMessage,
                relayIdentifier: relayIdentifier,
                inboxId: inboxId,
                groupId: nil,
                stagedAt: stagedAt,
                sealedEnvelope: sealedEnvelope,
                acknowledgementDeferred: true
            )
        }
        return DecentralizedPrefetchBatch(records: records, stagedAt: stagedAt)
    }

    public static func stageGroupMessages(
        _ envelopes: [GroupRatchetEnvelope],
        groupInboxId: String,
        relayIdentifier: String,
        stagedAt: Date = Date()
    ) throws -> DecentralizedPrefetchBatch {
        guard !envelopes.isEmpty else { throw DecentralizedPrefetchError.emptyBatch }
        guard envelopes.count <= maximumRecordsPerBatch else { throw DecentralizedPrefetchError.batchTooLarge }
        let relayIdentifier = try normalizedRelayIdentifier(relayIdentifier)
        let inboxId = try normalizedInboxId(groupInboxId)
        let records = try envelopes.map { envelope in
            guard !envelope.payload.ciphertext.isEmpty else {
                throw DecentralizedPrefetchError.invalidEnvelope
            }
            let sealedEnvelope = try NoctweaveCoder.encode(envelope)
            guard sealedEnvelope.count <= maximumSealedEnvelopeBytes else {
                throw DecentralizedPrefetchError.invalidEnvelope
            }
            return DecentralizedPrefetchRecord(
                id: envelope.id,
                kind: .groupMessage,
                relayIdentifier: relayIdentifier,
                inboxId: inboxId,
                groupId: envelope.groupId,
                stagedAt: stagedAt,
                sealedEnvelope: sealedEnvelope,
                acknowledgementDeferred: true
            )
        }
        return DecentralizedPrefetchBatch(records: records, stagedAt: stagedAt)
    }

    private static func normalizedRelayIdentifier(_ relayIdentifier: String) throws -> String {
        let trimmed = relayIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.utf8.count <= 512 else {
            throw DecentralizedPrefetchError.invalidRelayIdentifier
        }
        return trimmed
    }

    private static func normalizedInboxId(_ inboxId: String) throws -> String {
        let trimmed = inboxId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.utf8.count <= 256 else {
            throw DecentralizedPrefetchError.invalidInboxId
        }
        return trimmed
    }
}

public actor DecentralizedPrefetchBatchStore {
    public static let maximumStoredBytes = 96 * 1024 * 1024
    private let fileURL: URL
    private let protectionKey: SymmetricKey

    public init(fileURL: URL, protectionKey: Data) throws {
        guard protectionKey.count == 32 else {
            throw DecentralizedPrefetchError.invalidProtectionKey
        }
        self.fileURL = fileURL
        self.protectionKey = SymmetricKey(data: protectionKey)
    }

    public func save(_ batch: DecentralizedPrefetchBatch) throws {
        guard !batch.records.isEmpty else {
            throw DecentralizedPrefetchError.emptyBatch
        }
        guard Self.isValid(batch) else {
            throw DecentralizedPrefetchError.invalidBatch
        }

        var encodedBatch = try NoctweaveCoder.encode(batch)
        defer { encodedBatch.secureWipe() }
        let payload = try CryptoBox.encrypt(
            encodedBatch,
            key: protectionKey,
            authenticatedData: DecentralizedPrefetchBatchStore.authenticatedData
        )
        let stored = DecentralizedPrefetchStoredBatch(version: 1, payload: payload)
        var encodedStored = try NoctweaveCoder.encode(stored)
        defer { encodedStored.secureWipe() }
        guard encodedStored.count <= Self.maximumStoredBytes else {
            throw DecentralizedPrefetchError.batchTooLarge
        }

        let directory = fileURL.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        #if os(iOS)
        try encodedStored.write(to: fileURL, options: [.atomic, .completeFileProtection])
        #else
        try encodedStored.write(to: fileURL, options: [.atomic])
        #endif
        do {
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        } catch {
            try? FileManager.default.removeItem(at: fileURL)
            throw error
        }
    }

    public func load() throws -> DecentralizedPrefetchBatch? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        let values = try fileURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard values.isRegularFile == true,
              let fileSize = values.fileSize,
              fileSize >= 0,
              fileSize <= Self.maximumStoredBytes else {
            throw DecentralizedPrefetchError.invalidStoredBatch
        }
        var encodedStored = try Data(contentsOf: fileURL)
        defer { encodedStored.secureWipe() }
        guard encodedStored.count <= Self.maximumStoredBytes else {
            throw DecentralizedPrefetchError.invalidStoredBatch
        }
        guard let stored = try? NoctweaveCoder.decode(DecentralizedPrefetchStoredBatch.self, from: encodedStored) else {
            throw DecentralizedPrefetchError.invalidStoredBatch
        }
        guard stored.version == 1 else {
            throw DecentralizedPrefetchError.invalidStoredBatch
        }
        guard var encodedBatch = try? CryptoBox.decrypt(
            stored.payload,
            key: protectionKey,
            authenticatedData: DecentralizedPrefetchBatchStore.authenticatedData
        ) else {
            throw DecentralizedPrefetchError.invalidStoredBatch
        }
        defer { encodedBatch.secureWipe() }
        guard let batch = try? NoctweaveCoder.decode(DecentralizedPrefetchBatch.self, from: encodedBatch) else {
            throw DecentralizedPrefetchError.invalidStoredBatch
        }
        guard Self.isValid(batch) else {
            throw DecentralizedPrefetchError.invalidStoredBatch
        }
        return batch
    }

    public func remove() throws {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return
        }
        Self.bestEffortOverwriteFile(at: fileURL)
        try FileManager.default.removeItem(at: fileURL)
    }

    private static let authenticatedData = Data("NOCTYRA-DECENTRALIZED-PREFETCH-BATCH-V1".utf8)

    private static func isValid(_ batch: DecentralizedPrefetchBatch) -> Bool {
        guard !batch.records.isEmpty,
              batch.records.count <= DecentralizedPrefetchStager.maximumRecordsPerBatch,
              batch.isCiphertextOnly,
              Set(batch.records.map(\.id)).count == batch.records.count else {
            return false
        }
        return batch.records.allSatisfy { record in
            !record.relayIdentifier.isEmpty
                && record.relayIdentifier.utf8.count <= 512
                && !record.inboxId.isEmpty
                && record.inboxId.utf8.count <= 256
                && record.sealedEnvelope.count <= DecentralizedPrefetchStager.maximumSealedEnvelopeBytes
                && ((record.kind == .groupMessage) == (record.groupId != nil))
        }
    }

    private static func bestEffortOverwriteFile(at url: URL) {
        guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]),
              values.isRegularFile == true,
              let fileSize = values.fileSize,
              fileSize > 0,
              let handle = try? FileHandle(forWritingTo: url) else {
            return
        }

        defer {
            try? handle.close()
        }

        handle.seek(toFileOffset: 0)
        let chunkSize = 64 * 1024
        let zeros = Data(repeating: 0, count: min(chunkSize, fileSize))
        var remaining = fileSize
        while remaining > 0 {
            let writeCount = min(chunkSize, remaining)
            if writeCount == zeros.count {
                handle.write(zeros)
            } else {
                handle.write(zeros.prefix(writeCount))
            }
            remaining -= writeCount
        }
        handle.synchronizeFile()
    }
}

private struct DecentralizedPrefetchStoredBatch: Codable, Equatable {
    let version: Int
    let payload: EncryptedPayload
}

public enum DecentralizedPrefetchExecutionPlanner {
    public static func makePlan(
        for profiles: [DecentralizedWakeProfile],
        defaultDelaySeconds: Int,
        maxDelaySeconds: Int,
        policy: DecentralizedPrefetchExecutionPolicy = DecentralizedPrefetchExecutionPolicy(),
        now: Date = Date()
    ) -> DecentralizedPrefetchExecutionPlan {
        let cycle = DecentralizedWakePlanner.makeCyclePlan(
            for: profiles,
            defaultDelaySeconds: defaultDelaySeconds,
            maxDelaySeconds: maxDelaySeconds,
            now: now
        )
        return makePlan(from: cycle, policy: policy)
    }

    public static func makePlan(
        from cycle: DecentralizedWakeCyclePlan,
        policy: DecentralizedPrefetchExecutionPolicy = DecentralizedPrefetchExecutionPolicy()
    ) -> DecentralizedPrefetchExecutionPlan {
        var remainingRecords = policy.maxTotalRecordsPerCycle
        let selectedProfiles = cycle.profilePlans
            .sorted { lhs, rhs in
                if lhs.plan.nextPollDelaySeconds != rhs.plan.nextPollDelaySeconds {
                    return lhs.plan.nextPollDelaySeconds < rhs.plan.nextPollDelaySeconds
                }
                if lhs.relayIdentifier != rhs.relayIdentifier {
                    return lhs.relayIdentifier < rhs.relayIdentifier
                }
                return lhs.identitySeed.lexicographicallyPrecedes(rhs.identitySeed)
            }
            .prefix(policy.maxProfilesPerCycle)

        let executions = selectedProfiles.compactMap { profile -> DecentralizedPrefetchProfileExecution? in
            guard remainingRecords > 0 else { return nil }
            let profileCap = profile.plan.longPollTimeoutSeconds == nil
                ? policy.maxRecordsPerPullProfile
                : policy.maxRecordsPerLongPollProfile
            let envelopeCount = min(profileCap, remainingRecords)
            remainingRecords -= envelopeCount
            return DecentralizedPrefetchProfileExecution(
                identitySeed: profile.identitySeed,
                relayIdentifier: profile.relayIdentifier,
                nextPollDelaySeconds: profile.plan.nextPollDelaySeconds,
                longPollTimeoutSeconds: profile.plan.longPollTimeoutSeconds,
                maxEnvelopeCount: envelopeCount
            )
        }

        return DecentralizedPrefetchExecutionPlan(
            profileExecutions: executions,
            nextCycleDelaySeconds: cycle.nextPollDelaySeconds,
            longPollTimeoutSeconds: cycle.longPollTimeoutSeconds,
            maxTotalEnvelopeCount: policy.maxTotalRecordsPerCycle - remainingRecords
        )
    }
}

public enum DecentralizedWakePlanner {
    public static func makePlan(
        support: DecentralizedWakeSupport?,
        identitySeed: Data,
        relayIdentifier: String,
        failureCount: Int = 0,
        now: Date = Date()
    ) -> DecentralizedWakePlan {
        let policy = support ?? DecentralizedWakeSupport()
        let boundedFailures = min(max(0, failureCount), 6)
        let base = min(
            policy.maxPollIntervalSeconds,
            policy.minPollIntervalSeconds * (1 << boundedFailures)
        )
        let jitterWindow = max(0, base * policy.jitterPermille / 1_000)
        let jitter = jitterWindow == 0
            ? 0
            : deterministicJitter(
                upperBound: jitterWindow,
                identitySeed: identitySeed,
                relayIdentifier: relayIdentifier,
                now: now,
                failureCount: boundedFailures
            )
        let delay = min(policy.maxPollIntervalSeconds, base + jitter)
        let longPollTimeout = policy.longPollTimeoutSeconds.map { min($0, delay) }
        return DecentralizedWakePlan(
            nextPollDelaySeconds: delay,
            longPollTimeoutSeconds: longPollTimeout,
            failureBackoffStep: boundedFailures
        )
    }

    public static func nextPollDelaySeconds(
        for profiles: [DecentralizedWakeProfile],
        defaultDelaySeconds: Int,
        maxDelaySeconds: Int,
        now: Date = Date()
    ) -> Int {
        makeCyclePlan(
            for: profiles,
            defaultDelaySeconds: defaultDelaySeconds,
            maxDelaySeconds: maxDelaySeconds,
            now: now
        ).nextPollDelaySeconds
    }

    public static func makeCyclePlan(
        for profiles: [DecentralizedWakeProfile],
        defaultDelaySeconds: Int,
        maxDelaySeconds: Int,
        now: Date = Date()
    ) -> DecentralizedWakeCyclePlan {
        let defaultDelay = max(5, defaultDelaySeconds)
        let upperBound = max(defaultDelay, maxDelaySeconds)
        guard !profiles.isEmpty else {
            return DecentralizedWakeCyclePlan(
                profilePlans: [],
                nextPollDelaySeconds: min(defaultDelay, upperBound),
                longPollTimeoutSeconds: nil
            )
        }

        let profilePlans = Dictionary(grouping: profiles, by: profileKey)
            .values
            .compactMap { duplicates -> DecentralizedWakeProfilePlan? in
                guard let selected = duplicates.min(by: { lhs, rhs in
                    if lhs.failureCount == rhs.failureCount {
                        return lhs.relayIdentifier < rhs.relayIdentifier
                    }
                    return lhs.failureCount < rhs.failureCount
                }) else {
                    return nil
                }
                let relayIdentifier = normalizedRelayIdentifier(selected.relayIdentifier)
                let rawPlan: DecentralizedWakePlan
                if let support = selected.support {
                    rawPlan = makePlan(
                        support: support,
                        identitySeed: selected.identitySeed,
                        relayIdentifier: relayIdentifier,
                        failureCount: selected.failureCount,
                        now: now
                    )
                } else {
                    rawPlan = DecentralizedWakePlan(
                        nextPollDelaySeconds: defaultDelay,
                        longPollTimeoutSeconds: nil,
                        failureBackoffStep: min(max(0, selected.failureCount), 6)
                    )
                }
                let boundedDelay = min(max(rawPlan.nextPollDelaySeconds, 5), upperBound)
                let boundedLongPoll = rawPlan.longPollTimeoutSeconds.map { min($0, boundedDelay) }
                return DecentralizedWakeProfilePlan(
                    identitySeed: selected.identitySeed,
                    relayIdentifier: relayIdentifier,
                    plan: DecentralizedWakePlan(
                        nextPollDelaySeconds: boundedDelay,
                        longPollTimeoutSeconds: boundedLongPoll,
                        failureBackoffStep: rawPlan.failureBackoffStep
                    )
                )
            }
            .sorted {
                if $0.relayIdentifier == $1.relayIdentifier {
                    return $0.identitySeed.lexicographicallyPrecedes($1.identitySeed)
                }
                return $0.relayIdentifier < $1.relayIdentifier
            }
        let selectedDelay = profilePlans.map(\.plan.nextPollDelaySeconds).min() ?? defaultDelay
        let selectedLongPoll = profilePlans
            .filter { $0.plan.nextPollDelaySeconds == selectedDelay }
            .compactMap(\.plan.longPollTimeoutSeconds)
            .min()
        return DecentralizedWakeCyclePlan(
            profilePlans: profilePlans,
            nextPollDelaySeconds: selectedDelay,
            longPollTimeoutSeconds: selectedLongPoll
        )
    }

    private static func deterministicJitter(
        upperBound: Int,
        identitySeed: Data,
        relayIdentifier: String,
        now: Date,
        failureCount: Int
    ) -> Int {
        let minuteValue = now.timeIntervalSince1970 / 60
        let epochMinute: Int64
        if minuteValue.isFinite,
           minuteValue >= Double(Int64.min),
           minuteValue <= Double(Int64.max) {
            epochMinute = Int64(minuteValue.rounded(.towardZero))
        } else {
            epochMinute = 0
        }
        var data = Data("noctyra-decentralized-wake-v1".utf8)
        data.append(identitySeed)
        data.append(0)
        data.append(Data(relayIdentifier.utf8))
        data.append(0)
        data.append(Data("\(epochMinute):\(failureCount)".utf8))
        let digest = SHA256.hash(data: data)
        let value = digest.prefix(8).reduce(UInt64(0)) { partial, byte in
            (partial << 8) | UInt64(byte)
        }
        return Int(value % UInt64(upperBound + 1))
    }

    private static func profileKey(_ profile: DecentralizedWakeProfile) -> String {
        "\(profile.identitySeed.base64EncodedString())|\(normalizedRelayIdentifier(profile.relayIdentifier))"
    }

    private static func normalizedRelayIdentifier(_ relayIdentifier: String) -> String {
        let trimmed = relayIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "default-relay" : trimmed
    }
}
