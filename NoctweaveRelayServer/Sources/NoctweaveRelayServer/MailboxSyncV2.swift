import Crypto
import Foundation

struct MailboxCursor: RawRepresentable, Codable, Equatable, Hashable {
    let rawValue: String

    init(rawValue: String) {
        self.rawValue = rawValue
    }

    var isStructurallyValid: Bool {
        !rawValue.isEmpty
            && rawValue.utf8.count <= 512
            && rawValue.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
    }
}

struct MailboxConsumerId: RawRepresentable, Codable, Equatable, Hashable {
    let rawValue: String

    init(rawValue: String) {
        self.rawValue = rawValue
    }

    static func generate(nonce: UUID = UUID()) -> MailboxConsumerId {
        var material = Data("Noctweave/mailbox-consumer/v2".utf8)
        material.append(Data(nonce.uuidString.lowercased().utf8))
        return MailboxConsumerId(rawValue: Data(SHA256.hash(data: material)).base64EncodedString())
    }

    var isStructurallyValid: Bool {
        guard let bytes = Data(base64Encoded: rawValue), bytes.count == 32 else { return false }
        return bytes.base64EncodedString() == rawValue
    }
}

struct SequencedEnvelope: Codable, Equatable, Identifiable {
    var id: UUID { envelope.id }
    let sequence: UInt64
    let envelope: Envelope
    let storedAt: Date

    init(sequence: UInt64, envelope: Envelope, storedAt: Date) {
        self.sequence = sequence
        self.envelope = envelope
        self.storedAt = storedAt
    }

    var isStructurallyValid: Bool {
        sequence > 0 && storedAt.timeIntervalSince1970.isFinite
    }
}

struct MailboxSyncBatch: Codable, Equatable {
    let events: [SequencedEnvelope]
    let nextCursor: MailboxCursor
    let nextSequence: UInt64
    let highWatermark: UInt64
    let retentionFloor: UInt64
    let hasMore: Bool

    init(
        events: [SequencedEnvelope],
        nextCursor: MailboxCursor,
        nextSequence: UInt64,
        highWatermark: UInt64,
        retentionFloor: UInt64,
        hasMore: Bool
    ) {
        self.events = events
        self.nextCursor = nextCursor
        self.nextSequence = nextSequence
        self.highWatermark = highWatermark
        self.retentionFloor = retentionFloor
        self.hasMore = hasMore
    }

    var isStructurallyValid: Bool {
        nextCursor.isStructurallyValid
            && nextSequence <= highWatermark
            && retentionFloor <= highWatermark
            && events.allSatisfy(\.isStructurallyValid)
            && zip(events, events.dropFirst()).allSatisfy { $0.sequence < $1.sequence }
            && (events.last?.sequence ?? nextSequence) == nextSequence
            && events.allSatisfy { $0.sequence > retentionFloor && $0.sequence <= highWatermark }
    }
}

enum MailboxConsumerState: String, Codable, Equatable {
    case active
    case revoked
}

struct MailboxConsumerRegistration: Codable, Equatable {
    let consumerId: MailboxConsumerId
    let consumerSigningPublicKey: Data
    var state: MailboxConsumerState
    var committedSequence: UInt64
    let registeredAt: Date
    var revokedAt: Date?

    init(
        consumerId: MailboxConsumerId,
        consumerSigningPublicKey: Data,
        state: MailboxConsumerState = .active,
        committedSequence: UInt64,
        registeredAt: Date = Date(),
        revokedAt: Date? = nil
    ) {
        self.consumerId = consumerId
        self.consumerSigningPublicKey = consumerSigningPublicKey
        self.state = state
        self.committedSequence = committedSequence
        self.registeredAt = registeredAt
        self.revokedAt = revokedAt
    }

    var isStructurallyValid: Bool {
        guard consumerId.isStructurallyValid,
              consumerSigningPublicKey.count == OQSSignatureVerifier.mlDSA65PublicKeyBytes,
              registeredAt.timeIntervalSince1970.isFinite,
              revokedAt?.timeIntervalSince1970.isFinite ?? true else {
            return false
        }
        switch (state, revokedAt) {
        case (.active, nil), (.revoked, .some):
            return true
        default:
            return false
        }
    }
}

enum MailboxSyncError: Error, Equatable {
    case invalidConsumer
    case consumerNotFound
    case consumerRevoked
    case consumerCredentialMissing
    case consumerSigningKeyMismatch
    case consumerSponsorRequired
    case invalidConsumerSponsor
    case freshInboxRequired
    case invalidCursor
    case cursorExpired(retentionFloor: UInt64)
    case cursorRollback
    case sequenceOverflow
}

struct MailboxStreamState: Codable, Equatable {
    var nextSequence: UInt64
    var retentionFloor: UInt64
    var consumers: [String: MailboxConsumerRegistration]
    var isInstallationManaged: Bool
    let cursorAuthenticationKey: Data

    init(
        nextSequence: UInt64 = 1,
        retentionFloor: UInt64 = 0,
        consumers: [String: MailboxConsumerRegistration] = [:],
        isInstallationManaged: Bool = false,
        cursorAuthenticationKey: Data = MailboxStreamState.generateAuthenticationKey()
    ) {
        self.nextSequence = max(1, nextSequence)
        self.retentionFloor = retentionFloor
        self.consumers = consumers
        self.isInstallationManaged = isInstallationManaged || !consumers.isEmpty
        self.cursorAuthenticationKey = cursorAuthenticationKey
    }

    private enum CodingKeys: String, CodingKey {
        case nextSequence
        case retentionFloor
        case consumers
        case isInstallationManaged
        case cursorAuthenticationKey
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        nextSequence = try container.decode(UInt64.self, forKey: .nextSequence)
        retentionFloor = try container.decode(UInt64.self, forKey: .retentionFloor)
        consumers = try container.decode(
            [String: MailboxConsumerRegistration].self,
            forKey: .consumers
        )
        isInstallationManaged = try container.decode(
            Bool.self,
            forKey: .isInstallationManaged
        )
        cursorAuthenticationKey = try container.decode(
            Data.self,
            forKey: .cursorAuthenticationKey
        )
        guard nextSequence > 0,
              retentionFloor < nextSequence,
              cursorAuthenticationKey.count == SHA256.byteCount,
              isInstallationManaged || consumers.isEmpty,
              consumers.allSatisfy({ key, value in
                  key == value.consumerId.rawValue
                      && value.committedSequence < nextSequence
                      && value.isStructurallyValid
              }) else {
            throw DecodingError.dataCorruptedError(
                forKey: .consumers,
                in: container,
                debugDescription: "Invalid current mailbox stream state"
            )
        }
    }

    var highWatermark: UInt64 {
        nextSequence - 1
    }

    var hasActiveConsumers: Bool {
        consumers.values.contains { $0.state == .active }
    }

    static func generateAuthenticationKey() -> Data {
        SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    }
}

enum MailboxCursorAuthenticator {
    private static let domain = Data("Noctweave/mailbox-cursor/v2".utf8)

    static func make(
        inboxId: String,
        consumerId: MailboxConsumerId,
        sequence: UInt64,
        keyData: Data
    ) -> MailboxCursor {
        let sequenceData = encodedSequence(sequence)
        let authenticationCode = HMAC<SHA256>.authenticationCode(
            for: authenticatedMaterial(
                inboxId: inboxId,
                consumerId: consumerId,
                sequenceData: sequenceData
            ),
            using: SymmetricKey(data: keyData)
        )
        var token = sequenceData
        token.append(contentsOf: authenticationCode)
        return MailboxCursor(rawValue: token.base64EncodedString())
    }

    static func sequence(
        from cursor: MailboxCursor,
        inboxId: String,
        consumerId: MailboxConsumerId,
        keyData: Data
    ) -> UInt64? {
        guard cursor.isStructurallyValid,
              let token = Data(base64Encoded: cursor.rawValue),
              token.base64EncodedString() == cursor.rawValue,
              token.count == 40 else {
            return nil
        }
        let sequenceData = Data(token.prefix(8))
        let receivedCode = Data(token.suffix(32))
        let isValid = HMAC<SHA256>.isValidAuthenticationCode(
            receivedCode,
            authenticating: authenticatedMaterial(
                inboxId: inboxId,
                consumerId: consumerId,
                sequenceData: sequenceData
            ),
            using: SymmetricKey(data: keyData)
        )
        guard isValid else { return nil }
        return sequenceData.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    private static func authenticatedMaterial(
        inboxId: String,
        consumerId: MailboxConsumerId,
        sequenceData: Data
    ) -> Data {
        var material = domain
        material.append(Data(inboxId.utf8))
        material.append(0)
        material.append(Data(consumerId.rawValue.utf8))
        material.append(0)
        material.append(sequenceData)
        return material
    }

    private static func encodedSequence(_ sequence: UInt64) -> Data {
        var bigEndian = sequence.bigEndian
        return withUnsafeBytes(of: &bigEndian) { Data($0) }
    }
}
