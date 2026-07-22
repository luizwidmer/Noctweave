import Foundation

public enum DirectPairingTransferV2Error: Error, Equatable, LocalizedError {
    case invalidTransfer
    case transferTooLarge

    public var errorDescription: String? {
        switch self {
        case .invalidTransfer:
            return "This is not a valid direct Noctweave pairing exchange."
        case .transferTooLarge:
            return "The direct pairing exchange exceeds the supported transfer size."
        }
    }
}

public enum DirectPairingTransferStageV2: String, Codable, Equatable, CaseIterable {
    case invitation
    case response
    case offer
    case confirmation
    case finalConfirmation
}

/// One bounded carrier item for a contact-pairing transcript transported
/// directly by QR, removable media, or a password-protected file. Relays are
/// not involved in this exchange; they are used only to provision each
/// participant's relationship-scoped receive route.
public struct DirectPairingTransferV2: Codable, Equatable {
    public static let version = 2
    public static let prefix = "noctweave-direct-pair-v2:"
    public static let maximumEncodedCharacters = QRCodeTransfer.maximumAssembledCharacters

    public let version: Int
    public let stage: DirectPairingTransferStageV2
    public let invitation: ContactPairingInvitationV2?
    public let openRequest: RendezvousOpenV2?
    public let frame: RendezvousFrameV2?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case stage
        case invitation
        case openRequest
        case frame
    }

    private init(
        stage: DirectPairingTransferStageV2,
        invitation: ContactPairingInvitationV2? = nil,
        openRequest: RendezvousOpenV2? = nil,
        frame: RendezvousFrameV2? = nil
    ) throws {
        version = Self.version
        self.stage = stage
        self.invitation = invitation
        self.openRequest = openRequest
        self.frame = frame
        guard isStructurallyValid else {
            throw DirectPairingTransferV2Error.invalidTransfer
        }
    }

    public static func invitation(
        _ invitation: ContactPairingInvitationV2
    ) throws -> DirectPairingTransferV2 {
        try DirectPairingTransferV2(stage: .invitation, invitation: invitation)
    }

    public static func response(
        openRequest: RendezvousOpenV2,
        acceptanceFrame: RendezvousFrameV2
    ) throws -> DirectPairingTransferV2 {
        try DirectPairingTransferV2(
            stage: .response,
            openRequest: openRequest,
            frame: acceptanceFrame
        )
    }

    public static func offer(
        _ frame: RendezvousFrameV2
    ) throws -> DirectPairingTransferV2 {
        try DirectPairingTransferV2(stage: .offer, frame: frame)
    }

    public static func confirmation(
        _ frame: RendezvousFrameV2
    ) throws -> DirectPairingTransferV2 {
        try DirectPairingTransferV2(stage: .confirmation, frame: frame)
    }

    public static func finalConfirmation(
        _ frame: RendezvousFrameV2
    ) throws -> DirectPairingTransferV2 {
        try DirectPairingTransferV2(stage: .finalConfirmation, frame: frame)
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: DirectPairingCodingKey.self)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedVersion = try container.decode(Int.self, forKey: .version)
        let decodedStage = try container.decode(
            DirectPairingTransferStageV2.self,
            forKey: .stage
        )
        let expectedKeys: Set<String>
        switch decodedStage {
        case .invitation:
            expectedKeys = ["version", "stage", "invitation"]
        case .response:
            expectedKeys = ["version", "stage", "openRequest", "frame"]
        case .offer, .confirmation, .finalConfirmation:
            expectedKeys = ["version", "stage", "frame"]
        }
        guard Set(strict.allKeys.map(\.stringValue)) == expectedKeys else {
            throw DirectPairingTransferV2Error.invalidTransfer
        }

        version = decodedVersion
        stage = decodedStage
        invitation = try container.decodeIfPresent(
            ContactPairingInvitationV2.self,
            forKey: .invitation
        )
        openRequest = try container.decodeIfPresent(
            RendezvousOpenV2.self,
            forKey: .openRequest
        )
        frame = try container.decodeIfPresent(RendezvousFrameV2.self, forKey: .frame)
        guard isStructurallyValid else {
            throw DirectPairingTransferV2Error.invalidTransfer
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw DirectPairingTransferV2Error.invalidTransfer
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(stage, forKey: .stage)
        switch stage {
        case .invitation:
            try container.encode(invitation, forKey: .invitation)
        case .response:
            try container.encode(openRequest, forKey: .openRequest)
            try container.encode(frame, forKey: .frame)
        case .offer, .confirmation, .finalConfirmation:
            try container.encode(frame, forKey: .frame)
        }
    }

    public var isStructurallyValid: Bool {
        guard version == Self.version else { return false }
        switch stage {
        case .invitation:
            return invitation?.isStructurallyValid == true
                && openRequest == nil
                && frame == nil
        case .response:
            return invitation == nil
                && openRequest?.isStructurallyValid == true
                && validFrame(
                    sender: .responder,
                    sequence: 1,
                    kind: .contactAcceptance
                )
        case .offer:
            return invitation == nil
                && openRequest == nil
                && validFrame(sender: .offerer, sequence: 1, kind: .contactOffer)
        case .confirmation:
            return invitation == nil
                && openRequest == nil
                && validFrame(sender: .responder, sequence: 2, kind: .confirmation)
        case .finalConfirmation:
            return invitation == nil
                && openRequest == nil
                && validFrame(sender: .offerer, sequence: 2, kind: .confirmation)
        }
    }

    public func encoded() throws -> String {
        guard isStructurallyValid else {
            throw DirectPairingTransferV2Error.invalidTransfer
        }
        let value = Self.prefix
            + (try NoctweaveCoder.encode(self, sortedKeys: true)).base64EncodedString()
        guard value.count <= Self.maximumEncodedCharacters else {
            throw DirectPairingTransferV2Error.transferTooLarge
        }
        return value
    }

    public static func decode(_ value: String) throws -> DirectPairingTransferV2 {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard normalized.hasPrefix(prefix),
              normalized.count <= maximumEncodedCharacters,
              let data = Data(base64Encoded: String(normalized.dropFirst(prefix.count))) else {
            throw DirectPairingTransferV2Error.invalidTransfer
        }
        do {
            return try NoctweaveCoder.decode(DirectPairingTransferV2.self, from: data)
        } catch let error as DirectPairingTransferV2Error {
            throw error
        } catch {
            throw DirectPairingTransferV2Error.invalidTransfer
        }
    }

    private func validFrame(
        sender: RendezvousRoleV2,
        sequence: UInt64,
        kind: RendezvousMessageKindV2
    ) -> Bool {
        frame?.isStructurallyValid == true
            && frame?.purpose == .contactPairing
            && frame?.senderRole == sender
            && frame?.sequence == sequence
            && frame?.messageKind == kind
    }
}

private struct DirectPairingCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil

    init?(stringValue: String) {
        self.stringValue = stringValue
    }

    init?(intValue: Int) {
        return nil
    }
}
