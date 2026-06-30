import Foundation

public enum ContactTrustKind: String, Codable, CaseIterable {
    case verified
    case revoked
}

public struct ContactTrustAssertion: Codable, Identifiable, Equatable {
    public let id: UUID
    public let kind: ContactTrustKind
    public let timestamp: Date
    public let fingerprint: String
    public let note: String?

    public init(
        id: UUID = UUID(),
        kind: ContactTrustKind,
        timestamp: Date = Date(),
        fingerprint: String,
        note: String? = nil
    ) {
        self.id = id
        self.kind = kind
        self.timestamp = timestamp
        self.fingerprint = fingerprint
        self.note = note
    }
}

public extension Contact {
    var lastTrustAssertion: ContactTrustAssertion? {
        trustAssertions.max(by: { $0.timestamp < $1.timestamp })
    }

    var lastVerifiedAssertion: ContactTrustAssertion? {
        trustAssertions
            .filter { $0.kind == .verified && $0.fingerprint == fingerprint }
            .max(by: { $0.timestamp < $1.timestamp })
    }

    var isTrusted: Bool {
        lastTrustAssertionForCurrentFingerprint()?.kind == .verified
    }

    func lastTrustAssertionForCurrentFingerprint() -> ContactTrustAssertion? {
        trustAssertions
            .filter { $0.fingerprint == fingerprint }
            .max(by: { $0.timestamp < $1.timestamp })
    }
}
