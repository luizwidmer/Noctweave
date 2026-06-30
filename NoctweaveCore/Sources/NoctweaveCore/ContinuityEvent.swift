import Foundation

public enum ContinuityEventKind: String, Codable, CaseIterable {
    case identityCreated
    case identityRotated
    case identityBurned
    case contactAdded
    case contactRemoved
    case contactRotationReceived
    case contactResetReceived
    case trustAsserted
    case trustRevoked
}

public struct ContinuityEvent: Codable, Identifiable, Equatable {
    public let id: UUID
    public let kind: ContinuityEventKind
    public let timestamp: Date
    public let contactId: UUID?
    public let contactDisplayName: String?
    public let note: String?
    public let oldFingerprint: String?
    public let newFingerprint: String?

    public init(
        id: UUID = UUID(),
        kind: ContinuityEventKind,
        timestamp: Date = Date(),
        contactId: UUID? = nil,
        contactDisplayName: String? = nil,
        note: String? = nil,
        oldFingerprint: String? = nil,
        newFingerprint: String? = nil
    ) {
        self.id = id
        self.kind = kind
        self.timestamp = timestamp
        self.contactId = contactId
        self.contactDisplayName = contactDisplayName
        self.note = note
        self.oldFingerprint = oldFingerprint
        self.newFingerprint = newFingerprint
    }
}
