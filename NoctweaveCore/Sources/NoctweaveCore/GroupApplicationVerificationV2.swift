import CryptoKit
import Foundation

private struct StrictApplicationVerificationKey: CodingKey {
    let stringValue: String
    var intValue: Int? { nil }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

private func requireExactVerificationKeys<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder, _ keys: Key.Type
) throws {
    let actual = try decoder.container(keyedBy: StrictApplicationVerificationKey.self)
    guard Set(actual.allKeys.map(\.stringValue))
            == Set(keys.allCases.map(\.stringValue)) else {
        throw DecodingError.dataCorrupted(.init(
            codingPath: decoder.codingPath,
            debugDescription: "Application verification fields must match exactly"
        ))
    }
}

/// A locally authenticated sender-chain position. `nextCounter == 0` is the
/// exact initial state before this credential has sent an envelope in the
/// epoch. These are local verification facts, not new wire authority.
public struct GroupApplicationVerificationFrontierV2: Codable, Equatable, Sendable {
    public let groupID: UUID
    public let epoch: UInt64
    public let transcriptHash: Data
    public let credentialHandle: GroupScopedCredentialHandleV2
    public let nextCounter: UInt64
    public let prefixDigest: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case groupID, epoch, transcriptHash, credentialHandle, nextCounter, prefixDigest
    }

    public init(
        groupID: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        credentialHandle: GroupScopedCredentialHandleV2,
        nextCounter: UInt64,
        prefixDigest: Data
    ) {
        self.groupID = groupID
        self.epoch = epoch
        self.transcriptHash = transcriptHash
        self.credentialHandle = credentialHandle
        self.nextCounter = nextCounter
        self.prefixDigest = prefixDigest
    }

    public init(from decoder: Decoder) throws {
        try requireExactVerificationKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            groupID: try values.decode(UUID.self, forKey: .groupID),
            epoch: try values.decode(UInt64.self, forKey: .epoch),
            transcriptHash: try values.decode(Data.self, forKey: .transcriptHash),
            credentialHandle: try values.decode(
                GroupScopedCredentialHandleV2.self, forKey: .credentialHandle
            ),
            nextCounter: try values.decode(UInt64.self, forKey: .nextCounter),
            prefixDigest: try values.decode(Data.self, forKey: .prefixDigest)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Invalid application verification frontier"
            ))
        }
    }

    public var isStructurallyValid: Bool {
        epoch > 0 && transcriptHash.count == SHA256.byteCount
            && credentialHandle.isStructurallyValid
            && prefixDigest.count == SHA256.byteCount
            && (nextCounter != 0 || prefixDigest == Self.initialDigest(
                groupID: groupID, epoch: epoch,
                transcriptHash: transcriptHash, credentialHandle: credentialHandle
            ))
    }

    public static func initial(
        groupID: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        credentialHandle: GroupScopedCredentialHandleV2
    ) -> Self {
        Self(groupID: groupID, epoch: epoch, transcriptHash: transcriptHash,
             credentialHandle: credentialHandle, nextCounter: 0,
             prefixDigest: initialDigest(
                 groupID: groupID, epoch: epoch,
                 transcriptHash: transcriptHash, credentialHandle: credentialHandle
             ))
    }

    static func initialDigest(
        groupID: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        credentialHandle: GroupScopedCredentialHandleV2
    ) -> Data {
        var epochBytes = epoch.bigEndian
        let epochData = withUnsafeBytes(of: &epochBytes) { Data($0) }
        return Data(SHA256.hash(data:
            Data("Noctweave/group-application-prefix/initial/v1\0".utf8)
                + Data(groupID.uuidString.utf8) + epochData + transcriptHash
                + Data(credentialHandle.rawValue.utf8)
        ))
    }

    static func precedes(
        _ lhs: GroupApplicationVerificationFrontierV2,
        _ rhs: GroupApplicationVerificationFrontierV2
    ) -> Bool {
        if lhs.epoch != rhs.epoch { return lhs.epoch < rhs.epoch }
        return lhs.credentialHandle.rawValue < rhs.credentialHandle.rawValue
    }
}

/// Evidence retained when Core consumes a signed, decrypted group envelope.
/// A rejected application payload still consumes its authenticated counter.
public struct GroupApplicationVerificationReceiptV2: Codable, Equatable, Sendable {
    public let eventID: UUID
    public let groupID: UUID
    public let eventDigest: Data?
    public let epoch: UInt64
    public let transcriptHash: Data
    public let credentialHandle: GroupScopedCredentialHandleV2
    public let messageCounter: UInt64
    public let envelopeDigest: Data
    public let previousPrefixDigest: Data
    public let prefixDigest: Data
    public let outcome: GroupApplicationProcessingOutcomeV2

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case eventID, groupID, eventDigest, epoch, transcriptHash,
             credentialHandle, messageCounter, envelopeDigest,
             previousPrefixDigest, prefixDigest, outcome
    }

    public init(
        eventID: UUID,
        groupID: UUID,
        eventDigest: Data?,
        epoch: UInt64,
        transcriptHash: Data,
        credentialHandle: GroupScopedCredentialHandleV2,
        messageCounter: UInt64,
        envelopeDigest: Data,
        previousPrefixDigest: Data,
        prefixDigest: Data,
        outcome: GroupApplicationProcessingOutcomeV2
    ) {
        self.eventID = eventID
        self.groupID = groupID
        self.eventDigest = eventDigest
        self.epoch = epoch
        self.transcriptHash = transcriptHash
        self.credentialHandle = credentialHandle
        self.messageCounter = messageCounter
        self.envelopeDigest = envelopeDigest
        self.previousPrefixDigest = previousPrefixDigest
        self.prefixDigest = prefixDigest
        self.outcome = outcome
    }

    public init(from decoder: Decoder) throws {
        try requireExactVerificationKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            eventID: try values.decode(UUID.self, forKey: .eventID),
            groupID: try values.decode(UUID.self, forKey: .groupID),
            eventDigest: try values.decodeIfPresent(Data.self, forKey: .eventDigest),
            epoch: try values.decode(UInt64.self, forKey: .epoch),
            transcriptHash: try values.decode(Data.self, forKey: .transcriptHash),
            credentialHandle: try values.decode(
                GroupScopedCredentialHandleV2.self, forKey: .credentialHandle
            ),
            messageCounter: try values.decode(UInt64.self, forKey: .messageCounter),
            envelopeDigest: try values.decode(Data.self, forKey: .envelopeDigest),
            previousPrefixDigest: try values.decode(Data.self, forKey: .previousPrefixDigest),
            prefixDigest: try values.decode(Data.self, forKey: .prefixDigest),
            outcome: try values.decode(
                GroupApplicationProcessingOutcomeV2.self, forKey: .outcome
            )
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Invalid application verification receipt"
            ))
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(self, .init(
                codingPath: encoder.codingPath,
                debugDescription: "Invalid application verification receipt"
            ))
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(eventID, forKey: .eventID)
        try values.encode(groupID, forKey: .groupID)
        try values.encode(eventDigest, forKey: .eventDigest)
        try values.encode(epoch, forKey: .epoch)
        try values.encode(transcriptHash, forKey: .transcriptHash)
        try values.encode(credentialHandle, forKey: .credentialHandle)
        try values.encode(messageCounter, forKey: .messageCounter)
        try values.encode(envelopeDigest, forKey: .envelopeDigest)
        try values.encode(previousPrefixDigest, forKey: .previousPrefixDigest)
        try values.encode(prefixDigest, forKey: .prefixDigest)
        try values.encode(outcome, forKey: .outcome)
    }

    public var isStructurallyValid: Bool {
        epoch > 0 && transcriptHash.count == SHA256.byteCount
            && credentialHandle.isStructurallyValid
            && messageCounter < UInt64.max
            && envelopeDigest.count == SHA256.byteCount
            && previousPrefixDigest.count == SHA256.byteCount
            && prefixDigest.count == SHA256.byteCount
            && ((outcome == .accepted) == (eventDigest?.count == SHA256.byteCount))
            && prefixDigest == Self.nextDigest(
                previous: previousPrefixDigest,
                eventID: eventID, groupID: groupID, epoch: epoch,
                transcriptHash: transcriptHash,
                credentialHandle: credentialHandle,
                messageCounter: messageCounter,
                envelopeDigest: envelopeDigest,
                eventDigest: eventDigest,
                outcome: outcome
            )
    }

    public var frontierAfter: GroupApplicationVerificationFrontierV2 {
        GroupApplicationVerificationFrontierV2(
            groupID: groupID, epoch: epoch, transcriptHash: transcriptHash,
            credentialHandle: credentialHandle,
            nextCounter: messageCounter + 1, prefixDigest: prefixDigest
        )
    }

    static func nextDigest(
        previous: Data,
        eventID: UUID,
        groupID: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        credentialHandle: GroupScopedCredentialHandleV2,
        messageCounter: UInt64,
        envelopeDigest: Data,
        eventDigest: Data?,
        outcome: GroupApplicationProcessingOutcomeV2
    ) -> Data {
        var epochBytes = epoch.bigEndian
        var counterBytes = messageCounter.bigEndian
        let epochData = withUnsafeBytes(of: &epochBytes) { Data($0) }
        let counterData = withUnsafeBytes(of: &counterBytes) { Data($0) }
        return Data(SHA256.hash(data:
            Data("Noctweave/group-application-prefix/step/v1\0".utf8)
                + previous + Data(groupID.uuidString.utf8)
                + Data(eventID.uuidString.utf8) + epochData
                + transcriptHash + Data(credentialHandle.rawValue.utf8)
                + counterData + envelopeDigest
                + Data([UInt8(outcome.rawValue.utf8.count)])
                + Data(outcome.rawValue.utf8)
                + Data([eventDigest == nil ? 0 : 1])
                + (eventDigest ?? Data())
        ))
    }
}

/// Durable local proof that a protected application event's signed frontier
/// values matched Core's authenticated receipts when it was pinned.
public struct GroupProtectedApplicationVerificationBindingV2: Codable, Equatable, Sendable {
    public let eventID: UUID
    public let frontiers: [GroupApplicationVerificationFrontierV2]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case eventID, frontiers
    }

    public init(eventID: UUID, frontiers: [GroupApplicationVerificationFrontierV2]) {
        self.eventID = eventID
        self.frontiers = frontiers
    }

    public init(from decoder: Decoder) throws {
        try requireExactVerificationKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            eventID: try values.decode(UUID.self, forKey: .eventID),
            frontiers: try values.decode(
                [GroupApplicationVerificationFrontierV2].self,
                forKey: .frontiers
            )
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Invalid protected application verification binding"
            ))
        }
    }

    public var isStructurallyValid: Bool {
        !frontiers.isEmpty && frontiers.count <= 256
            && frontiers.allSatisfy(\.isStructurallyValid)
            && frontiers == frontiers.sorted(by: GroupApplicationVerificationFrontierV2.precedes)
            && Set(frontiers.map {
                "\($0.epoch)\u{0}\($0.credentialHandle.rawValue)"
            }).count == frontiers.count
            && Set(frontiers.map(\.groupID)).count == 1
    }
}
