import CryptoKit
import Foundation

/// Default-off, process-local discovery for same-relay contact pairing.
///
/// The relay treats `announcement` as opaque bytes. Clients are responsible
/// for signing and validating the announcement and for carrying every pairing
/// request and invitation through independently encrypted disposable routes.
public enum PairingLobbyRelayLimitsV1 {
    public static let leaseIDBytes = 16
    public static let leaseCapabilityBytes = 32
    public static let maximumAnnouncementBytes = 12 * 1024
    public static let minimumLeaseSeconds = 30
    public static let maximumLeaseSeconds = 120
    public static let maximumListings = 32

    public static let advertisedRegistry: [String: UInt64] = [
        "maxAnnouncementBytes": UInt64(maximumAnnouncementBytes),
        "minLeaseSeconds": UInt64(minimumLeaseSeconds),
        "maxLeaseSeconds": UInt64(maximumLeaseSeconds),
        "maxListings": UInt64(maximumListings),
        "processLocal": 1,
        "requiresRealtimeRoute": 1,
    ]
}

private struct PairingLobbyRelayCodingKey: CodingKey {
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

private func requireExactPairingLobbyRelayFields(
    _ decoder: Decoder,
    _ expected: Set<String>
) throws {
    let container = try decoder.container(keyedBy: PairingLobbyRelayCodingKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == expected else {
        throw DecodingError.dataCorrupted(.init(
            codingPath: decoder.codingPath,
            debugDescription: "Pairing lobby relay object fields are not current"
        ))
    }
}

private func canonicalPairingLobbyRelayDate(_ value: Date) -> Date {
    Date(timeIntervalSince1970: floor(value.timeIntervalSince1970))
}

private func pairingLobbyRelayDateIsCanonical(_ value: Date) -> Bool {
    let seconds = value.timeIntervalSince1970
    return seconds.isFinite && seconds >= 0 && floor(seconds) == seconds
}

public struct PairingLobbyAcquireRequestV1: Codable, Equatable {
    public let leaseID: Data
    public let leaseCapability: Data
    public let announcement: Data
    public let ttlSeconds: Int

    public init(
        leaseID: Data,
        leaseCapability: Data,
        announcement: Data,
        ttlSeconds: Int = PairingLobbyRelayLimitsV1.maximumLeaseSeconds
    ) {
        self.leaseID = leaseID
        self.leaseCapability = leaseCapability
        self.announcement = announcement
        self.ttlSeconds = ttlSeconds
    }

    public var isStructurallyValid: Bool {
        leaseID.count == PairingLobbyRelayLimitsV1.leaseIDBytes
            && leaseID.contains { $0 != 0 }
            && leaseCapability.count == PairingLobbyRelayLimitsV1.leaseCapabilityBytes
            && leaseCapability.contains { $0 != 0 }
            && !announcement.isEmpty
            && announcement.count <= PairingLobbyRelayLimitsV1.maximumAnnouncementBytes
            && (PairingLobbyRelayLimitsV1.minimumLeaseSeconds
                ... PairingLobbyRelayLimitsV1.maximumLeaseSeconds).contains(ttlSeconds)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case leaseID
        case leaseCapability
        case announcement
        case ttlSeconds
    }

    public init(from decoder: Decoder) throws {
        try requireExactPairingLobbyRelayFields(
            decoder,
            Set(CodingKeys.allCases.map(\.rawValue))
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            leaseID: try values.decode(Data.self, forKey: .leaseID),
            leaseCapability: try values.decode(Data.self, forKey: .leaseCapability),
            announcement: try values.decode(Data.self, forKey: .announcement),
            ttlSeconds: try values.decode(Int.self, forKey: .ttlSeconds)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Pairing lobby acquire request is invalid"
            ))
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(self, .init(
                codingPath: encoder.codingPath,
                debugDescription: "Pairing lobby acquire request is invalid"
            ))
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(leaseID, forKey: .leaseID)
        try values.encode(leaseCapability, forKey: .leaseCapability)
        try values.encode(announcement, forKey: .announcement)
        try values.encode(ttlSeconds, forKey: .ttlSeconds)
    }
}

public struct PairingLobbyReleaseRequestV1: Codable, Equatable {
    public let leaseID: Data
    public let leaseCapability: Data

    public init(leaseID: Data, leaseCapability: Data) {
        self.leaseID = leaseID
        self.leaseCapability = leaseCapability
    }

    public var isStructurallyValid: Bool {
        leaseID.count == PairingLobbyRelayLimitsV1.leaseIDBytes
            && leaseID.contains { $0 != 0 }
            && leaseCapability.count == PairingLobbyRelayLimitsV1.leaseCapabilityBytes
            && leaseCapability.contains { $0 != 0 }
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case leaseID
        case leaseCapability
    }

    public init(from decoder: Decoder) throws {
        try requireExactPairingLobbyRelayFields(
            decoder,
            Set(CodingKeys.allCases.map(\.rawValue))
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            leaseID: try values.decode(Data.self, forKey: .leaseID),
            leaseCapability: try values.decode(Data.self, forKey: .leaseCapability)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Pairing lobby release request is invalid"
            ))
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(self, .init(
                codingPath: encoder.codingPath,
                debugDescription: "Pairing lobby release request is invalid"
            ))
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(leaseID, forKey: .leaseID)
        try values.encode(leaseCapability, forKey: .leaseCapability)
    }
}

public struct PairingLobbyListRequestV1: Codable, Equatable {
    public init() {}

    public init(from decoder: Decoder) throws {
        try requireExactPairingLobbyRelayFields(decoder, [])
    }

    public func encode(to encoder: Encoder) throws {
        _ = encoder.container(keyedBy: PairingLobbyRelayCodingKey.self)
    }
}

public struct PairingLobbyLeaseV1: Codable, Equatable {
    public let leaseID: Data
    public let announcement: Data
    public let expiresAt: Date

    public init(leaseID: Data, announcement: Data, expiresAt: Date) {
        self.leaseID = leaseID
        self.announcement = announcement
        self.expiresAt = canonicalPairingLobbyRelayDate(expiresAt)
    }

    public var isStructurallyValid: Bool {
        leaseID.count == PairingLobbyRelayLimitsV1.leaseIDBytes
            && leaseID.contains { $0 != 0 }
            && !announcement.isEmpty
            && announcement.count <= PairingLobbyRelayLimitsV1.maximumAnnouncementBytes
            && pairingLobbyRelayDateIsCanonical(expiresAt)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case leaseID
        case announcement
        case expiresAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactPairingLobbyRelayFields(
            decoder,
            Set(CodingKeys.allCases.map(\.rawValue))
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            leaseID: try values.decode(Data.self, forKey: .leaseID),
            announcement: try values.decode(Data.self, forKey: .announcement),
            expiresAt: try values.decode(Date.self, forKey: .expiresAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Pairing lobby lease is invalid"
            ))
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(self, .init(
                codingPath: encoder.codingPath,
                debugDescription: "Pairing lobby lease is invalid"
            ))
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(leaseID, forKey: .leaseID)
        try values.encode(announcement, forKey: .announcement)
        try values.encode(expiresAt, forKey: .expiresAt)
    }
}

private struct PairingLobbyStoredLeaseV1 {
    let capabilityDigest: Data
    let announcement: Data
    let expiresAt: Date
}

/// Process-local by design. Restarting a relay erases every listing and never
/// resurrects an expired pairing window from durable storage.
struct PairingLobbyRelayRuntimeV1 {
    private var leases: [String: PairingLobbyStoredLeaseV1] = [:]

    mutating func acquire(
        _ request: PairingLobbyAcquireRequestV1,
        now: Date = Date()
    ) throws -> PairingLobbyLeaseV1 {
        guard request.isStructurallyValid else {
            throw RealtimeRelayRuntimeError.invalidRequest
        }
        prune(now: now)
        let key = request.leaseID.base64EncodedString()
        if let existing = leases[key] {
            guard existing.capabilityDigest == capabilityDigest(request.leaseCapability),
                  existing.announcement == request.announcement else {
                throw RealtimeRelayRuntimeError.conflict
            }
            return PairingLobbyLeaseV1(
                leaseID: request.leaseID,
                announcement: existing.announcement,
                expiresAt: existing.expiresAt
            )
        }
        guard leases.count < PairingLobbyRelayLimitsV1.maximumListings else {
            throw RealtimeRelayRuntimeError.capacity
        }
        let expiresAt = canonicalPairingLobbyRelayDate(
            now.addingTimeInterval(TimeInterval(request.ttlSeconds))
        )
        leases[key] = PairingLobbyStoredLeaseV1(
            capabilityDigest: capabilityDigest(request.leaseCapability),
            announcement: request.announcement,
            expiresAt: expiresAt
        )
        return PairingLobbyLeaseV1(
            leaseID: request.leaseID,
            announcement: request.announcement,
            expiresAt: expiresAt
        )
    }

    mutating func release(
        _ request: PairingLobbyReleaseRequestV1,
        now: Date = Date()
    ) throws {
        guard request.isStructurallyValid else {
            throw RealtimeRelayRuntimeError.invalidRequest
        }
        prune(now: now)
        let key = request.leaseID.base64EncodedString()
        guard let existing = leases[key],
              existing.capabilityDigest == capabilityDigest(request.leaseCapability) else {
            throw RealtimeRelayRuntimeError.unauthorized
        }
        leases.removeValue(forKey: key)
    }

    mutating func list(
        _ request: PairingLobbyListRequestV1,
        now: Date = Date()
    ) -> [PairingLobbyLeaseV1] {
        _ = request
        prune(now: now)
        return leases.compactMap { key, value in
            guard let leaseID = Data(base64Encoded: key) else { return nil }
            return PairingLobbyLeaseV1(
                leaseID: leaseID,
                announcement: value.announcement,
                expiresAt: value.expiresAt
            )
        }.sorted {
            if $0.expiresAt != $1.expiresAt { return $0.expiresAt > $1.expiresAt }
            return $0.leaseID.lexicographicallyPrecedes($1.leaseID)
        }
    }

    mutating func prune(now: Date = Date()) {
        leases = leases.filter { $0.value.expiresAt > now }
    }

    private func capabilityDigest(_ capability: Data) -> Data {
        Data(SHA256.hash(
            data: Data("org.noctweave.pairing-lobby.lease-capability/v1".utf8)
                + capability
        ))
    }
}
