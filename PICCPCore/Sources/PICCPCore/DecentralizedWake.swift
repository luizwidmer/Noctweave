import CryptoKit
import Foundation

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
        let defaultDelay = max(5, defaultDelaySeconds)
        let upperBound = max(defaultDelay, maxDelaySeconds)
        guard !profiles.isEmpty else {
            return min(defaultDelay, upperBound)
        }

        let delays = profiles.map { profile in
            guard let support = profile.support else {
                return defaultDelay
            }
            return makePlan(
                support: support,
                identitySeed: profile.identitySeed,
                relayIdentifier: profile.relayIdentifier,
                failureCount: profile.failureCount,
                now: now
            ).nextPollDelaySeconds
        }
        let delay = delays.min() ?? defaultDelay
        return min(max(delay, 5), upperBound)
    }

    private static func deterministicJitter(
        upperBound: Int,
        identitySeed: Data,
        relayIdentifier: String,
        now: Date,
        failureCount: Int
    ) -> Int {
        let epochMinute = Int(now.timeIntervalSince1970 / 60)
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
}
