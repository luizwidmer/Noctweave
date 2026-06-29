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

    private static func profileKey(_ profile: DecentralizedWakeProfile) -> String {
        "\(profile.identitySeed.base64EncodedString())|\(normalizedRelayIdentifier(profile.relayIdentifier))"
    }

    private static func normalizedRelayIdentifier(_ relayIdentifier: String) -> String {
        let trimmed = relayIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "default-relay" : trimmed
    }
}
