import Foundation

struct OpenFederationDHTDiscoveryConfiguration: Codable, Equatable {
    static let maximumRecords = 256
    static let maximumRecordsPerHost = 16
    static let maximumQueryRecords = 512
    var isEnabled: Bool
    var federationName: String?
    var requirePublicEndpoint: Bool
    var maxRecords: Int
    var maxRecordsPerHost: Int
    var maxQueryRecords: Int

    init(
        isEnabled: Bool = false,
        federationName: String? = nil,
        requirePublicEndpoint: Bool = true,
        maxRecords: Int = 64,
        maxRecordsPerHost: Int = 4,
        maxQueryRecords: Int = 256
    ) {
        self.isEnabled = isEnabled
        self.federationName = federationName
        self.requirePublicEndpoint = requirePublicEndpoint
        self.maxRecords = min(Self.maximumRecords, max(1, maxRecords))
        self.maxRecordsPerHost = min(Self.maximumRecordsPerHost, max(1, maxRecordsPerHost))
        self.maxQueryRecords = min(Self.maximumQueryRecords, max(1, maxQueryRecords))
    }
}

enum OpenFederationDHTDiscoveryError: Error, Equatable {
    case disabled
    case transportUnavailable
    case invalidLocalAdvertisement(OpenFederationDHTRecordError)
}

enum OpenFederationDHTRecordRejectionReason: Equatable {
    case discoveryDisabled
    case validationFailed(OpenFederationDHTRecordError)
    case staleDuplicate
    case hostLimitExceeded
}

struct OpenFederationDHTRecordRejection: Equatable {
    let record: OpenFederationDHTRecord
    let reason: OpenFederationDHTRecordRejectionReason
}

struct OpenFederationDHTDiscoveryIngestResult: Equatable {
    let accepted: [OpenFederationDHTRecord]
    let rejected: [OpenFederationDHTRecordRejection]
}

protocol OpenFederationDHTTransport: AnyObject {
    func publish(_ record: OpenFederationDHTRecord, namespace: String) async throws
    func query(namespace: String, limit: Int) async throws -> [OpenFederationDHTRecord]
}

struct OpenFederationDHTDiscoveryCycleResult: Equatable {
    let publishedRecord: OpenFederationDHTRecord?
    let ingestResult: OpenFederationDHTDiscoveryIngestResult
    let nodes: [FederationNodeRecord]
}

struct OpenFederationDHTDiscoveryEngine {
    private(set) var cache: OpenFederationDHTCandidateCache

    init(configuration: OpenFederationDHTDiscoveryConfiguration) {
        self.cache = OpenFederationDHTCandidateCache(configuration: configuration)
    }

    mutating func refresh(
        transport: OpenFederationDHTTransport?,
        localEndpoint: RelayEndpoint?,
        privateKey: Data?,
        publicKey: Data?,
        now: Date = Date()
    ) async throws -> OpenFederationDHTDiscoveryCycleResult {
        let configuration = cache.configuration
        guard configuration.isEnabled else {
            throw OpenFederationDHTDiscoveryError.disabled
        }
        guard let transport else {
            throw OpenFederationDHTDiscoveryError.transportUnavailable
        }

        let namespace = OpenFederationDHTRecord.namespace(federationName: configuration.federationName)
        var publishedRecord: OpenFederationDHTRecord?
        var accepted: [OpenFederationDHTRecord] = []
        var rejected: [OpenFederationDHTRecordRejection] = []
        if let localEndpoint, let privateKey, let publicKey {
            let record = try OpenFederationDHTRecord.signed(
                endpoint: localEndpoint,
                federationName: configuration.federationName,
                privateKey: privateKey,
                publicKey: publicKey,
                issuedAt: now
            )
            do {
                try record.validate(
                    expectedFederationName: configuration.federationName,
                    now: now,
                    requirePublicEndpoint: configuration.requirePublicEndpoint
                )
            } catch let error as OpenFederationDHTRecordError {
                throw OpenFederationDHTDiscoveryError.invalidLocalAdvertisement(error)
            } catch {
                throw OpenFederationDHTDiscoveryError.invalidLocalAdvertisement(.invalidSignature)
            }
            try await transport.publish(record, namespace: namespace)
            publishedRecord = record
            let localIngest = cache.ingest([record], now: now)
            accepted.append(contentsOf: localIngest.accepted)
            rejected.append(contentsOf: localIngest.rejected)
        }

        do {
            let queriedRecords = try await transport.query(
                namespace: namespace,
                limit: configuration.maxQueryRecords
            )
            let queryIngest = cache.ingest(queriedRecords, now: now)
            accepted.append(contentsOf: queryIngest.accepted)
            rejected.append(contentsOf: queryIngest.rejected)
        } catch {
            cache.evictExpired(now: now)
        }

        let ingestResult = OpenFederationDHTDiscoveryIngestResult(
            accepted: accepted,
            rejected: rejected
        )
        return OpenFederationDHTDiscoveryCycleResult(
            publishedRecord: publishedRecord,
            ingestResult: ingestResult,
            nodes: cache.federationNodes(now: now)
        )
    }
}

struct OpenFederationDHTCandidateCache: Equatable {
    var configuration: OpenFederationDHTDiscoveryConfiguration
    private var recordsByRelayIdentity: [String: OpenFederationDHTRecord]

    init(
        configuration: OpenFederationDHTDiscoveryConfiguration,
        records: [OpenFederationDHTRecord] = [],
        now: Date = Date()
    ) {
        self.configuration = OpenFederationDHTDiscoveryConfiguration(
            isEnabled: configuration.isEnabled,
            federationName: configuration.federationName,
            requirePublicEndpoint: configuration.requirePublicEndpoint,
            maxRecords: configuration.maxRecords,
            maxRecordsPerHost: configuration.maxRecordsPerHost,
            maxQueryRecords: configuration.maxQueryRecords
        )
        self.recordsByRelayIdentity = [:]
        _ = ingest(records, now: now)
    }

    var count: Int {
        recordsByRelayIdentity.count
    }

    mutating func ingest(
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

        for record in records.prefix(configuration.maxQueryRecords) {
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
                if Self.normalizedHost(existing.endpoint.host) != Self.normalizedHost(record.endpoint.host),
                   countRecords(forHost: record.endpoint.host) >= configuration.maxRecordsPerHost {
                    rejected.append(OpenFederationDHTRecordRejection(record: record, reason: .hostLimitExceeded))
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

    mutating func evictExpired(now: Date = Date()) {
        recordsByRelayIdentity = recordsByRelayIdentity.filter { _, record in
            record.expiresAt > now
        }
    }

    func records(now: Date = Date()) -> [OpenFederationDHTRecord] {
        recordsByRelayIdentity.values
            .filter { $0.expiresAt > now }
            .sorted { lhs, rhs in
                if lhs.expiresAt != rhs.expiresAt {
                    return lhs.expiresAt > rhs.expiresAt
                }
                return lhs.relayIdentityDigest < rhs.relayIdentityDigest
            }
    }

    func federationNodes(now: Date = Date()) -> [FederationNodeRecord] {
        records(now: now).map { record in
            FederationNodeRecord(
                endpoint: record.endpoint,
                relayInfo: RelayInfo(
                    kind: .standard,
                    federation: FederationDescriptor(mode: .open, name: record.federationName),
                    tlsEnabled: record.endpoint.useTLS,
                    transport: record.endpoint.transport,
                    temporalBucketSeconds: 300,
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
