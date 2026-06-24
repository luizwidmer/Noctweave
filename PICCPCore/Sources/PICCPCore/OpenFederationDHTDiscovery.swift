import Foundation

public struct OpenFederationDHTDiscoveryConfiguration: Codable, Equatable {
    public var isEnabled: Bool
    public var federationName: String?
    public var requirePublicEndpoint: Bool
    public var maxRecords: Int
    public var maxRecordsPerHost: Int

    public init(
        isEnabled: Bool = false,
        federationName: String? = nil,
        requirePublicEndpoint: Bool = true,
        maxRecords: Int = 64,
        maxRecordsPerHost: Int = 4
    ) {
        self.isEnabled = isEnabled
        self.federationName = federationName
        self.requirePublicEndpoint = requirePublicEndpoint
        self.maxRecords = max(1, maxRecords)
        self.maxRecordsPerHost = max(1, maxRecordsPerHost)
    }
}

public enum OpenFederationDHTRecordRejectionReason: Equatable {
    case discoveryDisabled
    case validationFailed(OpenFederationDHTRecordError)
    case staleDuplicate
    case hostLimitExceeded
}

public struct OpenFederationDHTRecordRejection: Equatable {
    public let record: OpenFederationDHTRecord
    public let reason: OpenFederationDHTRecordRejectionReason

    public init(record: OpenFederationDHTRecord, reason: OpenFederationDHTRecordRejectionReason) {
        self.record = record
        self.reason = reason
    }
}

public struct OpenFederationDHTDiscoveryIngestResult: Equatable {
    public let accepted: [OpenFederationDHTRecord]
    public let rejected: [OpenFederationDHTRecordRejection]

    public init(
        accepted: [OpenFederationDHTRecord],
        rejected: [OpenFederationDHTRecordRejection]
    ) {
        self.accepted = accepted
        self.rejected = rejected
    }
}

public struct OpenFederationDHTCandidateCache: Equatable {
    public var configuration: OpenFederationDHTDiscoveryConfiguration
    private var recordsByRelayIdentity: [String: OpenFederationDHTRecord]

    public init(
        configuration: OpenFederationDHTDiscoveryConfiguration,
        records: [OpenFederationDHTRecord] = [],
        now: Date = Date()
    ) {
        self.configuration = configuration
        self.recordsByRelayIdentity = [:]
        _ = ingest(records, now: now)
    }

    public var count: Int {
        recordsByRelayIdentity.count
    }

    public mutating func ingest(
        _ records: [OpenFederationDHTRecord],
        now: Date = Date()
    ) -> OpenFederationDHTDiscoveryIngestResult {
        guard configuration.isEnabled else {
            return OpenFederationDHTDiscoveryIngestResult(
                accepted: [],
                rejected: records.map {
                    OpenFederationDHTRecordRejection(record: $0, reason: .discoveryDisabled)
                }
            )
        }

        evictExpired(now: now)

        var accepted: [OpenFederationDHTRecord] = []
        var rejected: [OpenFederationDHTRecordRejection] = []

        for record in records {
            do {
                try record.validate(
                    expectedFederationName: configuration.federationName,
                    now: now,
                    requirePublicEndpoint: configuration.requirePublicEndpoint
                )
            } catch let error as OpenFederationDHTRecordError {
                rejected.append(OpenFederationDHTRecordRejection(record: record, reason: .validationFailed(error)))
                continue
            } catch {
                rejected.append(OpenFederationDHTRecordRejection(record: record, reason: .validationFailed(.invalidSignature)))
                continue
            }

            if let existing = recordsByRelayIdentity[record.relayIdentityDigest] {
                guard shouldReplace(existing: existing, with: record) else {
                    rejected.append(OpenFederationDHTRecordRejection(record: record, reason: .staleDuplicate))
                    continue
                }
                recordsByRelayIdentity[record.relayIdentityDigest] = record
                accepted.append(record)
                continue
            }

            if countRecords(forHost: record.endpoint.host) >= configuration.maxRecordsPerHost {
                rejected.append(OpenFederationDHTRecordRejection(record: record, reason: .hostLimitExceeded))
                continue
            }

            recordsByRelayIdentity[record.relayIdentityDigest] = record
            enforceTotalLimit(now: now)
            accepted.append(record)
        }

        return OpenFederationDHTDiscoveryIngestResult(accepted: accepted, rejected: rejected)
    }

    public mutating func evictExpired(now: Date = Date()) {
        recordsByRelayIdentity = recordsByRelayIdentity.filter { _, record in
            record.expiresAt > now
        }
    }

    public func records(now: Date = Date()) -> [OpenFederationDHTRecord] {
        recordsByRelayIdentity.values
            .filter { $0.expiresAt > now }
            .sorted { lhs, rhs in
                if lhs.expiresAt != rhs.expiresAt {
                    return lhs.expiresAt > rhs.expiresAt
                }
                return lhs.relayIdentityDigest < rhs.relayIdentityDigest
            }
    }

    public func federationNodes(now: Date = Date()) -> [FederationNodeRecord] {
        records(now: now).map { record in
            FederationNodeRecord(
                endpoint: record.endpoint,
                relayInfo: RelayInfo(
                    kind: .standard,
                    federation: FederationDescriptor(mode: .open, name: record.federationName),
                    temporalBucketSeconds: 300,
                    tlsEnabled: record.endpoint.useTLS,
                    transport: record.endpoint.transport,
                    advertisedAt: record.issuedAt
                ),
                lastHeartbeatAt: record.issuedAt,
                expiresAt: record.expiresAt
            )
        }
    }

    private func countRecords(forHost host: String) -> Int {
        let normalizedHost = Self.normalizedHost(host)
        return recordsByRelayIdentity.values.filter {
            Self.normalizedHost($0.endpoint.host) == normalizedHost
        }.count
    }

    private func shouldReplace(
        existing: OpenFederationDHTRecord,
        with candidate: OpenFederationDHTRecord
    ) -> Bool {
        if candidate.issuedAt != existing.issuedAt {
            return candidate.issuedAt > existing.issuedAt
        }
        if candidate.expiresAt != existing.expiresAt {
            return candidate.expiresAt > existing.expiresAt
        }
        return candidate.signature.lexicographicallyPrecedes(existing.signature) == false
    }

    private mutating func enforceTotalLimit(now: Date) {
        guard recordsByRelayIdentity.count > configuration.maxRecords else { return }
        let keep = Set(records(now: now).prefix(configuration.maxRecords).map(\.relayIdentityDigest))
        recordsByRelayIdentity = recordsByRelayIdentity.filter { keep.contains($0.key) }
    }

    private static func normalizedHost(_ host: String) -> String {
        host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}
