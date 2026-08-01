import CryptoKit
import Foundation

/// Experimental, transport-independent one-to-one call protocol.
///
/// Signaling is carried inside an authenticated direct-v4 application event.
/// Media keys are derived from fresh contributions supplied by both peers in
/// that encrypted transcript. A WebRTC, datagram, or relay transport therefore
/// carries only independently encrypted, padded media frames.
public enum NoctweaveCallV1 {
    public static let version = 1
    public static let module = "nw.call"
    public static let agreementPublicKeyBytes = 1_184
    public static let kemCiphertextBytes = 1_088
    public static let sharedSecretBytes = 32
    public static let digestBytes = 32
    public static let maximumTracks = 4
    public static let maximumCodecsPerTrack = 8
    public static let maximumCodecParameters = 16
    public static let maximumCandidates = 8
    public static let maximumCandidateDescriptorBytes = 4_096
    public static let maximumSignalLifetime: TimeInterval = 5 * 60
    public static let maximumCanonicalSequence: UInt64 = 9_007_199_254_740_991
    public static let maximumCallDurationSeconds: UInt32 = 4 * 60 * 60
    public static let minimumCallDurationSeconds: UInt32 = 30
    public static let maximumMediaPayloadBytes = 16_000
    public static let replayWindowSize: UInt64 = 256
    public static let allowedSealedMediaByteCounts = [512, 1_024, 2_048, 4_096, 8_192, 16_384]

    static let rootDomain = Data("org.noctweave.call.root/v1".utf8)
    static let transcriptDomain = Data("org.noctweave.call.transcript/v1".utf8)
    static let mediaKeyDomain = Data("org.noctweave.call.media-key/v1".utf8)
    static let mediaAADDomain = Data("org.noctweave.call.media-aad/v1".utf8)

    static func canonicalTimestamp(_ date: Date) -> Bool {
        let value = date.timeIntervalSince1970
        return value.isFinite && floor(value) == value
    }

    static func boundedIdentifier(_ value: String, maximumBytes: Int = 64) -> Bool {
        guard !value.isEmpty,
              value == value.trimmingCharacters(in: .whitespacesAndNewlines),
              value.utf8.count <= maximumBytes else {
            return false
        }
        let allowed = CharacterSet(
            charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        )
        return value.unicodeScalars.allSatisfy(allowed.contains)
    }
}

public enum CallRoleV1: String, Codable, CaseIterable, Equatable {
    case initiator
    case responder

    public var peer: CallRoleV1 { self == .initiator ? .responder : .initiator }
}

public enum CallMediaKindV1: String, Codable, CaseIterable, Equatable {
    case audio
    case video
}

public enum CallMediaDirectionV1: String, Codable, CaseIterable, Equatable {
    case sendReceive
    case sendOnly
    case receiveOnly
}

public enum CallTransportKindV1: String, Codable, CaseIterable, Equatable {
    case webRTC
    case datagram
    case relayWebSocket
}

public enum CallTransportPrivacyV1: String, Codable, CaseIterable, Equatable {
    /// The peer-to-peer path can reveal each endpoint's network address to the other peer.
    case peerAddressVisible
    /// Peers see only the intermediary; the intermediary still observes both network addresses.
    case relayMediated
}

public enum CallSignalKindV1: String, Codable, CaseIterable, Equatable {
    case offer
    case ringing
    case answer
    case candidate
    case connected
    case declined
    case canceled
    case ended
}

public enum CallTerminationReasonV1: String, Codable, CaseIterable, Equatable {
    case declined
    case canceled
    case completed
    case busy
    case unavailable
    case failed
    case securityError
    case expired
}

public struct CallCodecV1: Codable, Equatable, Hashable {
    public let identifier: String
    public let mediaKind: CallMediaKindV1
    public let clockRate: UInt32
    public let channels: UInt8
    public let parameters: [String: String]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case identifier
        case mediaKind
        case clockRate
        case channels
        case parameters
    }

    public init(
        identifier: String,
        mediaKind: CallMediaKindV1,
        clockRate: UInt32,
        channels: UInt8 = 1,
        parameters: [String: String] = [:]
    ) {
        self.identifier = identifier
        self.mediaKind = mediaKind
        self.clockRate = clockRate
        self.channels = channels
        self.parameters = parameters
    }

    public static let opus = CallCodecV1(
        identifier: "opus",
        mediaKind: .audio,
        clockRate: 48_000,
        channels: 2,
        parameters: ["frameDurationMs": "20"]
    )

    public var isStructurallyValid: Bool {
        NoctweaveCallV1.boundedIdentifier(identifier)
            && (8_000...192_000).contains(clockRate)
            && (1...8).contains(channels)
            && parameters.count <= NoctweaveCallV1.maximumCodecParameters
            && parameters.allSatisfy { key, value in
                NoctweaveCallV1.boundedIdentifier(key, maximumBytes: 96)
                    && value.utf8.count <= 256
                    && !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
            }
    }

    public init(from decoder: Decoder) throws {
        try callRequireExactFields(decoder, CodingKeys.self)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            identifier: try container.decode(String.self, forKey: .identifier),
            mediaKind: try container.decode(CallMediaKindV1.self, forKey: .mediaKind),
            clockRate: try container.decode(UInt32.self, forKey: .clockRate),
            channels: try container.decode(UInt8.self, forKey: .channels),
            parameters: try container.decode([String: String].self, forKey: .parameters)
        )
        guard isStructurallyValid else { throw callCodingError(decoder, "Invalid call codec") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw callCodingError(encoder, "Invalid call codec") }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(identifier, forKey: .identifier)
        try container.encode(mediaKind, forKey: .mediaKind)
        try container.encode(clockRate, forKey: .clockRate)
        try container.encode(channels, forKey: .channels)
        try container.encode(parameters, forKey: .parameters)
    }
}

public struct CallTrackOfferV1: Codable, Equatable {
    public let trackID: UInt16
    public let mediaKind: CallMediaKindV1
    public let direction: CallMediaDirectionV1
    public let codecs: [CallCodecV1]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case trackID
        case mediaKind
        case direction
        case codecs
    }

    public init(
        trackID: UInt16,
        mediaKind: CallMediaKindV1,
        direction: CallMediaDirectionV1 = .sendReceive,
        codecs: [CallCodecV1]
    ) {
        self.trackID = trackID
        self.mediaKind = mediaKind
        self.direction = direction
        self.codecs = codecs
    }

    public var isStructurallyValid: Bool {
        trackID > 0
            && !codecs.isEmpty
            && codecs.count <= NoctweaveCallV1.maximumCodecsPerTrack
            && Set(codecs.map(\.identifier)).count == codecs.count
            && codecs.allSatisfy { $0.isStructurallyValid && $0.mediaKind == mediaKind }
    }

    public init(from decoder: Decoder) throws {
        try callRequireExactFields(decoder, CodingKeys.self)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            trackID: try container.decode(UInt16.self, forKey: .trackID),
            mediaKind: try container.decode(CallMediaKindV1.self, forKey: .mediaKind),
            direction: try container.decode(CallMediaDirectionV1.self, forKey: .direction),
            codecs: try container.decode([CallCodecV1].self, forKey: .codecs)
        )
        guard isStructurallyValid else { throw callCodingError(decoder, "Invalid call track") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw callCodingError(encoder, "Invalid call track") }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(trackID, forKey: .trackID)
        try container.encode(mediaKind, forKey: .mediaKind)
        try container.encode(direction, forKey: .direction)
        try container.encode(codecs, forKey: .codecs)
    }
}

public struct CallTransportCandidateV1: Codable, Equatable {
    public let candidateID: UUID
    public let kind: CallTransportKindV1
    public let privacy: CallTransportPrivacyV1
    public let priority: UInt16
    /// Transport-specific bytes such as a canonical ICE candidate or an opaque
    /// relay route. They remain inside relationship encryption.
    public let descriptor: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case candidateID
        case kind
        case privacy
        case priority
        case descriptor
    }

    public init(
        candidateID: UUID = UUID(),
        kind: CallTransportKindV1,
        privacy: CallTransportPrivacyV1,
        priority: UInt16,
        descriptor: Data
    ) {
        self.candidateID = candidateID
        self.kind = kind
        self.privacy = privacy
        self.priority = priority
        self.descriptor = descriptor
    }

    public var isStructurallyValid: Bool {
        !descriptor.isEmpty
            && descriptor.count <= NoctweaveCallV1.maximumCandidateDescriptorBytes
            && (kind == .relayWebSocket ? privacy == .relayMediated : true)
    }

    public init(from decoder: Decoder) throws {
        try callRequireExactFields(decoder, CodingKeys.self)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            candidateID: try container.decode(UUID.self, forKey: .candidateID),
            kind: try container.decode(CallTransportKindV1.self, forKey: .kind),
            privacy: try container.decode(CallTransportPrivacyV1.self, forKey: .privacy),
            priority: try container.decode(UInt16.self, forKey: .priority),
            descriptor: try container.decode(Data.self, forKey: .descriptor)
        )
        guard isStructurallyValid else {
            throw callCodingError(decoder, "Invalid call transport candidate")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw callCodingError(encoder, "Invalid call transport candidate")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(candidateID, forKey: .candidateID)
        try container.encode(kind, forKey: .kind)
        try container.encode(privacy, forKey: .privacy)
        try container.encode(priority, forKey: .priority)
        try container.encode(descriptor, forKey: .descriptor)
    }
}

public struct CallOfferV1: Codable, Equatable {
    /// Fresh ML-KEM-768 public key generated solely for this call attempt.
    public let initiatorAgreementPublicKey: Data
    public let tracks: [CallTrackOfferV1]
    public let candidates: [CallTransportCandidateV1]
    public let maximumDurationSeconds: UInt32

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case initiatorAgreementPublicKey
        case tracks
        case candidates
        case maximumDurationSeconds
    }

    public init(
        initiatorAgreementPublicKey: Data,
        tracks: [CallTrackOfferV1],
        candidates: [CallTransportCandidateV1],
        maximumDurationSeconds: UInt32 = NoctweaveCallV1.maximumCallDurationSeconds
    ) {
        self.initiatorAgreementPublicKey = initiatorAgreementPublicKey
        self.tracks = tracks
        self.candidates = candidates
        self.maximumDurationSeconds = maximumDurationSeconds
    }

    public var isStructurallyValid: Bool {
        initiatorAgreementPublicKey.count == NoctweaveCallV1.agreementPublicKeyBytes
            && initiatorAgreementPublicKey.contains { $0 != 0 }
            && !tracks.isEmpty
            && tracks.count <= NoctweaveCallV1.maximumTracks
            && Set(tracks.map(\.trackID)).count == tracks.count
            && tracks.allSatisfy(\.isStructurallyValid)
            && !candidates.isEmpty
            && candidates.count <= NoctweaveCallV1.maximumCandidates
            && Set(candidates.map(\.candidateID)).count == candidates.count
            && candidates.allSatisfy(\.isStructurallyValid)
            && (NoctweaveCallV1.minimumCallDurationSeconds...NoctweaveCallV1.maximumCallDurationSeconds)
                .contains(maximumDurationSeconds)
    }

    public var canonicalDigest: Data? {
        guard isStructurallyValid,
              let bytes = try? NoctweaveCoder.encode(self, sortedKeys: true) else { return nil }
        return Data(SHA256.hash(data: bytes))
    }

    public init(from decoder: Decoder) throws {
        try callRequireExactFields(decoder, CodingKeys.self)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            initiatorAgreementPublicKey: try container.decode(
                Data.self,
                forKey: .initiatorAgreementPublicKey
            ),
            tracks: try container.decode([CallTrackOfferV1].self, forKey: .tracks),
            candidates: try container.decode([CallTransportCandidateV1].self, forKey: .candidates),
            maximumDurationSeconds: try container.decode(UInt32.self, forKey: .maximumDurationSeconds)
        )
        guard isStructurallyValid else { throw callCodingError(decoder, "Invalid call offer") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw callCodingError(encoder, "Invalid call offer") }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(initiatorAgreementPublicKey, forKey: .initiatorAgreementPublicKey)
        try container.encode(tracks, forKey: .tracks)
        try container.encode(candidates, forKey: .candidates)
        try container.encode(maximumDurationSeconds, forKey: .maximumDurationSeconds)
    }
}

public struct CallTrackSelectionV1: Codable, Equatable {
    public let trackID: UInt16
    public let codecIdentifier: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case trackID
        case codecIdentifier
    }

    public init(trackID: UInt16, codecIdentifier: String) {
        self.trackID = trackID
        self.codecIdentifier = codecIdentifier
    }

    public var isStructurallyValid: Bool {
        trackID > 0 && NoctweaveCallV1.boundedIdentifier(codecIdentifier)
    }

    public init(from decoder: Decoder) throws {
        try callRequireExactFields(decoder, CodingKeys.self)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            trackID: try container.decode(UInt16.self, forKey: .trackID),
            codecIdentifier: try container.decode(String.self, forKey: .codecIdentifier)
        )
        guard isStructurallyValid else { throw callCodingError(decoder, "Invalid call track selection") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw callCodingError(encoder, "Invalid call track selection") }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(trackID, forKey: .trackID)
        try container.encode(codecIdentifier, forKey: .codecIdentifier)
    }
}

public struct CallAnswerV1: Codable, Equatable {
    public let offerDigest: Data
    /// ML-KEM-768 encapsulation to the offer's fresh call public key.
    public let kemCiphertext: Data
    public let tracks: [CallTrackSelectionV1]
    public let selectedCandidateID: UUID
    public let responderCandidates: [CallTransportCandidateV1]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case offerDigest
        case kemCiphertext
        case tracks
        case selectedCandidateID
        case responderCandidates
    }

    public init(
        offerDigest: Data,
        kemCiphertext: Data,
        tracks: [CallTrackSelectionV1],
        selectedCandidateID: UUID,
        responderCandidates: [CallTransportCandidateV1] = []
    ) {
        self.offerDigest = offerDigest
        self.kemCiphertext = kemCiphertext
        self.tracks = tracks
        self.selectedCandidateID = selectedCandidateID
        self.responderCandidates = responderCandidates
    }

    public var isStructurallyValid: Bool {
        offerDigest.count == NoctweaveCallV1.digestBytes
            && kemCiphertext.count == NoctweaveCallV1.kemCiphertextBytes
            && kemCiphertext.contains { $0 != 0 }
            && !tracks.isEmpty
            && tracks.count <= NoctweaveCallV1.maximumTracks
            && Set(tracks.map(\.trackID)).count == tracks.count
            && tracks.allSatisfy(\.isStructurallyValid)
            && responderCandidates.count <= NoctweaveCallV1.maximumCandidates
            && Set(responderCandidates.map(\.candidateID)).count == responderCandidates.count
            && responderCandidates.allSatisfy(\.isStructurallyValid)
    }

    public func isCompatible(with offer: CallOfferV1) -> Bool {
        guard isStructurallyValid,
              let digest = offer.canonicalDigest,
              constantTimeEqual(digest, offerDigest),
              offer.candidates.contains(where: { $0.candidateID == selectedCandidateID }) else {
            return false
        }
        let offeredTracks = Dictionary(uniqueKeysWithValues: offer.tracks.map { ($0.trackID, $0) })
        return tracks.allSatisfy { selection in
            offeredTracks[selection.trackID]?.codecs.contains {
                $0.identifier == selection.codecIdentifier
            } == true
        }
    }

    public init(from decoder: Decoder) throws {
        try callRequireExactFields(decoder, CodingKeys.self)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            offerDigest: try container.decode(Data.self, forKey: .offerDigest),
            kemCiphertext: try container.decode(Data.self, forKey: .kemCiphertext),
            tracks: try container.decode([CallTrackSelectionV1].self, forKey: .tracks),
            selectedCandidateID: try container.decode(UUID.self, forKey: .selectedCandidateID),
            responderCandidates: try container.decode(
                [CallTransportCandidateV1].self,
                forKey: .responderCandidates
            )
        )
        guard isStructurallyValid else { throw callCodingError(decoder, "Invalid call answer") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw callCodingError(encoder, "Invalid call answer") }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(offerDigest, forKey: .offerDigest)
        try container.encode(kemCiphertext, forKey: .kemCiphertext)
        try container.encode(tracks, forKey: .tracks)
        try container.encode(selectedCandidateID, forKey: .selectedCandidateID)
        try container.encode(responderCandidates, forKey: .responderCandidates)
    }
}

public struct CallSignalV1: Codable, Equatable {
    public let version: Int
    public let callID: UUID
    public let senderRole: CallRoleV1
    public let sequence: UInt64
    public let kind: CallSignalKindV1
    public let createdAt: Date
    public let expiresAt: Date
    public let offer: CallOfferV1?
    public let answer: CallAnswerV1?
    public let candidate: CallTransportCandidateV1?
    public let terminationReason: CallTerminationReasonV1?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case callID
        case senderRole
        case sequence
        case kind
        case createdAt
        case expiresAt
        case offer
        case answer
        case candidate
        case terminationReason
    }

    public init(
        version: Int = NoctweaveCallV1.version,
        callID: UUID,
        senderRole: CallRoleV1,
        sequence: UInt64,
        kind: CallSignalKindV1,
        createdAt: Date,
        expiresAt: Date,
        offer: CallOfferV1? = nil,
        answer: CallAnswerV1? = nil,
        candidate: CallTransportCandidateV1? = nil,
        terminationReason: CallTerminationReasonV1? = nil
    ) {
        self.version = version
        self.callID = callID
        self.senderRole = senderRole
        self.sequence = sequence
        self.kind = kind
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.offer = offer
        self.answer = answer
        self.candidate = candidate
        self.terminationReason = terminationReason
    }

    public static func offer(
        callID: UUID = UUID(),
        offer: CallOfferV1,
        createdAt: Date = Date()
    ) -> CallSignalV1 {
        let canonical = Date(timeIntervalSince1970: floor(createdAt.timeIntervalSince1970))
        return CallSignalV1(
            callID: callID,
            senderRole: .initiator,
            sequence: 1,
            kind: .offer,
            createdAt: canonical,
            expiresAt: canonical.addingTimeInterval(NoctweaveCallV1.maximumSignalLifetime),
            offer: offer
        )
    }

    public static func answer(
        callID: UUID,
        sequence: UInt64,
        answer: CallAnswerV1,
        createdAt: Date = Date(),
        noLaterThan offerExpiry: Date
    ) throws -> CallSignalV1 {
        let canonical = Date(timeIntervalSince1970: floor(createdAt.timeIntervalSince1970))
        let expiresAt = min(
            canonical.addingTimeInterval(NoctweaveCallV1.maximumSignalLifetime),
            offerExpiry
        )
        let signal = CallSignalV1(
            callID: callID,
            senderRole: .responder,
            sequence: sequence,
            kind: .answer,
            createdAt: canonical,
            expiresAt: expiresAt,
            answer: answer
        )
        guard signal.isStructurallyValid else { throw CallProtocolV1Error.invalidAnswer }
        return signal
    }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveCallV1.version,
              sequence > 0,
              sequence <= NoctweaveCallV1.maximumCanonicalSequence,
              NoctweaveCallV1.canonicalTimestamp(createdAt),
              NoctweaveCallV1.canonicalTimestamp(expiresAt),
              expiresAt > createdAt,
              expiresAt.timeIntervalSince(createdAt) <= NoctweaveCallV1.maximumSignalLifetime else {
            return false
        }
        switch kind {
        case .offer:
            return senderRole == .initiator && sequence == 1 && offer?.isStructurallyValid == true
                && answer == nil && candidate == nil && terminationReason == nil
        case .answer:
            return senderRole == .responder && answer?.isStructurallyValid == true
                && offer == nil && candidate == nil && terminationReason == nil
        case .candidate:
            return candidate?.isStructurallyValid == true
                && offer == nil && answer == nil && terminationReason == nil
        case .ringing, .connected:
            return offer == nil && answer == nil && candidate == nil && terminationReason == nil
        case .declined:
            return senderRole == .responder
                && terminationReason.map { [.declined, .busy, .unavailable].contains($0) } == true
                && offer == nil && answer == nil && candidate == nil
        case .canceled:
            return senderRole == .initiator && terminationReason == .canceled
                && offer == nil && answer == nil && candidate == nil
        case .ended:
            return terminationReason != nil && offer == nil && answer == nil && candidate == nil
        }
    }

    public var canonicalDigest: Data? {
        guard isStructurallyValid,
              let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else { return nil }
        return Data(SHA256.hash(data: encoded))
    }

    public func isFresh(at now: Date = Date()) -> Bool {
        isStructurallyValid && now >= createdAt.addingTimeInterval(-30) && now < expiresAt
    }

    public init(from decoder: Decoder) throws {
        try callRequireExactFields(decoder, CodingKeys.self)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try container.decode(Int.self, forKey: .version),
            callID: try container.decode(UUID.self, forKey: .callID),
            senderRole: try container.decode(CallRoleV1.self, forKey: .senderRole),
            sequence: try container.decode(UInt64.self, forKey: .sequence),
            kind: try container.decode(CallSignalKindV1.self, forKey: .kind),
            createdAt: try container.decode(Date.self, forKey: .createdAt),
            expiresAt: try container.decode(Date.self, forKey: .expiresAt),
            offer: try container.decodeIfPresent(CallOfferV1.self, forKey: .offer),
            answer: try container.decodeIfPresent(CallAnswerV1.self, forKey: .answer),
            candidate: try container.decodeIfPresent(CallTransportCandidateV1.self, forKey: .candidate),
            terminationReason: try container.decodeIfPresent(
                CallTerminationReasonV1.self,
                forKey: .terminationReason
            )
        )
        guard isStructurallyValid else { throw callCodingError(decoder, "Invalid call signal") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw callCodingError(encoder, "Invalid call signal") }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(callID, forKey: .callID)
        try container.encode(senderRole, forKey: .senderRole)
        try container.encode(sequence, forKey: .sequence)
        try container.encode(kind, forKey: .kind)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(expiresAt, forKey: .expiresAt)
        try callEncodeOptional(offer, forKey: .offer, into: &container)
        try callEncodeOptional(answer, forKey: .answer, into: &container)
        try callEncodeOptional(candidate, forKey: .candidate, into: &container)
        try callEncodeOptional(terminationReason, forKey: .terminationReason, into: &container)
    }
}

public extension ContentTypeId {
    static let callSignal = ContentTypeId(
        authority: "org.noctweave.call",
        name: "signal",
        major: 1,
        minor: 0
    )
}

public extension EncodedContent {
    static func callSignal(_ signal: CallSignalV1) throws -> EncodedContent {
        guard signal.isStructurallyValid else { throw CallProtocolV1Error.invalidSignal }
        let content = EncodedContent(
            type: .callSignal,
            payload: try NoctweaveCoder.encode(signal, sortedKeys: true),
            fallbackText: nil,
            disposition: .silent
        )
        guard content.isStructurallyValid else { throw CallProtocolV1Error.invalidSignal }
        return content
    }

    func decodeCallSignalV1() throws -> CallSignalV1 {
        guard type == .callSignal, disposition == .silent else {
            throw CallProtocolV1Error.invalidSignal
        }
        let decoded = try NoctweaveCoder.decode(CallSignalV1.self, from: payload)
        guard try NoctweaveCoder.encode(decoded, sortedKeys: true) == payload else {
            throw CallProtocolV1Error.nonCanonicalSignal
        }
        return decoded
    }
}

public extension ProtocolCapabilityManifest {
    static let callV1ModuleCapability = ProtocolModuleCapability(
        module: NoctweaveCallV1.module,
        versions: [1],
        status: .experimental,
        limits: [
            "maxCallDurationSeconds": UInt64(NoctweaveCallV1.maximumCallDurationSeconds),
            "maxCandidates": UInt64(NoctweaveCallV1.maximumCandidates),
            "maxMediaPayloadBytes": UInt64(NoctweaveCallV1.maximumMediaPayloadBytes),
            "maxSignalLifetimeSeconds": UInt64(NoctweaveCallV1.maximumSignalLifetime),
            "maxTracks": UInt64(NoctweaveCallV1.maximumTracks),
            "replayWindow": NoctweaveCallV1.replayWindowSize
        ]
    )

    /// Explicit opt-in. Call support is intentionally absent from the direct-v4
    /// baseline until a client wires media permissions and a transport adapter.
    func enablingCallV1() -> ProtocolCapabilityManifest {
        ProtocolCapabilityManifest(
            architectureVersion: architectureVersion,
            modules: modules.filter { $0.module != NoctweaveCallV1.module }
                + [Self.callV1ModuleCapability],
            contentTypes: contentTypes.filter {
                $0.authority != ContentTypeId.callSignal.authority
                    || $0.name != ContentTypeId.callSignal.name
            } + [ContentTypeCapabilityV2(.callSignal)]
        )
    }

    var supportsCallV1: Bool {
        supports(module: NoctweaveCallV1.module, version: 1)
            && supports(contentType: .callSignal)
    }
}

public struct CallKeyMaterialV1: Equatable {
    public let callID: UUID
    public let transcriptDigest: Data
    public let rootKey: Data

    public var isStructurallyValid: Bool {
        transcriptDigest.count == NoctweaveCallV1.digestBytes
            && rootKey.count == NoctweaveCallV1.sharedSecretBytes
    }
}

public enum CallKeyScheduleV1 {
    public static func derive(
        offerSignal: CallSignalV1,
        answerSignal: CallSignalV1,
        sharedSecret: Data
    ) throws -> CallKeyMaterialV1 {
        guard sharedSecret.count == NoctweaveCallV1.sharedSecretBytes else {
            throw CallProtocolV1Error.invalidKeyMaterial
        }
        guard offerSignal.kind == .offer,
              answerSignal.kind == .answer,
              offerSignal.callID == answerSignal.callID,
              let offer = offerSignal.offer,
              let answer = answerSignal.answer,
              answer.isCompatible(with: offer) else {
            throw CallProtocolV1Error.transcriptMismatch
        }
        let offerBytes = try NoctweaveCoder.encode(offerSignal, sortedKeys: true)
        let answerBytes = try NoctweaveCoder.encode(answerSignal, sortedKeys: true)
        var transcript = NoctweaveCallV1.transcriptDomain
        transcript.append(0)
        transcript.append(offerBytes)
        transcript.append(0)
        transcript.append(answerBytes)
        let transcriptDigest = Data(SHA256.hash(data: transcript))

        var info = NoctweaveCallV1.rootDomain
        info.append(0)
        info.append(Data(offerSignal.callID.uuidString.uppercased().utf8))
        let root = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: transcriptDigest,
            info: info,
            outputByteCount: 32
        ).dataRepresentation
        return CallKeyMaterialV1(
            callID: offerSignal.callID,
            transcriptDigest: transcriptDigest,
            rootKey: root
        )
    }

    public static func mediaKey(
        material: CallKeyMaterialV1,
        senderRole: CallRoleV1,
        epoch: UInt32
    ) throws -> SymmetricKey {
        guard material.isStructurallyValid else { throw CallProtocolV1Error.invalidKeyMaterial }
        var info = NoctweaveCallV1.mediaKeyDomain
        info.append(0)
        info.append(Data(material.callID.uuidString.uppercased().utf8))
        info.append(0)
        info.append(Data(senderRole.rawValue.utf8))
        appendBigEndian(epoch, to: &info)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: material.rootKey),
            salt: material.transcriptDigest,
            info: info,
            outputByteCount: 32
        )
    }
}

/// Secret initiator state for one call attempt. Persist it only inside the
/// application's encrypted state store; the ML-KEM private key is never sent.
public struct PendingCallOfferV1: Codable {
    public let offerSignal: CallSignalV1
    private let agreementKey: AgreementKeyPair
    public private(set) var acceptedAnswerDigest: Data?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case offerSignal
        case agreementKey
        case acceptedAnswerDigest
    }

    private init(
        offerSignal: CallSignalV1,
        agreementKey: AgreementKeyPair,
        acceptedAnswerDigest: Data? = nil
    ) {
        self.offerSignal = offerSignal
        self.agreementKey = agreementKey
        self.acceptedAnswerDigest = acceptedAnswerDigest
    }

    public static func create(
        callID: UUID = UUID(),
        tracks: [CallTrackOfferV1],
        candidates: [CallTransportCandidateV1],
        maximumDurationSeconds: UInt32 = NoctweaveCallV1.maximumCallDurationSeconds,
        createdAt: Date = Date()
    ) throws -> PendingCallOfferV1 {
        let agreementKey = try AgreementKeyPair.generate()
        let offer = CallOfferV1(
            initiatorAgreementPublicKey: agreementKey.publicKeyData,
            tracks: tracks,
            candidates: candidates,
            maximumDurationSeconds: maximumDurationSeconds
        )
        guard offer.isStructurallyValid else { throw CallProtocolV1Error.invalidOffer }
        let pending = PendingCallOfferV1(
            offerSignal: .offer(callID: callID, offer: offer, createdAt: createdAt),
            agreementKey: agreementKey
        )
        guard pending.isStructurallyValid else { throw CallProtocolV1Error.invalidOffer }
        return pending
    }

    public var isStructurallyValid: Bool {
        offerSignal.kind == .offer
            && offerSignal.isStructurallyValid
            && offerSignal.offer?.initiatorAgreementPublicKey == agreementKey.publicKeyData
            && acceptedAnswerDigest.map { $0.count == NoctweaveCallV1.digestBytes } ?? true
    }

    /// Accepts an exact answer idempotently but refuses a competing answer for
    /// the same local call attempt.
    public mutating func accept(
        _ answerSignal: CallSignalV1,
        at now: Date = Date()
    ) throws -> CallKeyMaterialV1 {
        guard isStructurallyValid,
              answerSignal.callID == offerSignal.callID,
              answerSignal.isFresh(at: now),
              let answerDigest = answerSignal.canonicalDigest,
              let answer = answerSignal.answer,
              let offer = offerSignal.offer,
              answer.isCompatible(with: offer) else {
            throw CallProtocolV1Error.invalidAnswer
        }
        if let acceptedAnswerDigest,
           !constantTimeEqual(acceptedAnswerDigest, answerDigest) {
            throw CallProtocolV1Error.signalFork
        }
        var sharedSecret: Data
        do {
            sharedSecret = try agreementKey.decapsulate(ciphertext: answer.kemCiphertext)
        } catch {
            throw CallProtocolV1Error.invalidAnswer
        }
        defer { sharedSecret.secureWipe() }
        let material = try CallKeyScheduleV1.derive(
            offerSignal: offerSignal,
            answerSignal: answerSignal,
            sharedSecret: sharedSecret
        )
        acceptedAnswerDigest = answerDigest
        return material
    }

    public init(from decoder: Decoder) throws {
        try callRequireExactFields(decoder, CodingKeys.self)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            offerSignal: try container.decode(CallSignalV1.self, forKey: .offerSignal),
            agreementKey: try container.decode(AgreementKeyPair.self, forKey: .agreementKey),
            acceptedAnswerDigest: try container.decodeIfPresent(
                Data.self,
                forKey: .acceptedAnswerDigest
            )
        )
        guard isStructurallyValid else {
            throw callCodingError(decoder, "Invalid pending call offer")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw callCodingError(encoder, "Invalid pending call offer")
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(offerSignal, forKey: .offerSignal)
        try container.encode(agreementKey, forKey: .agreementKey)
        try callEncodeOptional(
            acceptedAnswerDigest,
            forKey: .acceptedAnswerDigest,
            into: &container
        )
    }
}

public struct CallResponderAcceptanceV1: Equatable {
    public let answerSignal: CallSignalV1
    public let keyMaterial: CallKeyMaterialV1
}

public enum CallResponderHandshakeV1 {
    /// Performs a fresh ML-KEM-768 encapsulation for this call and returns the
    /// answer plus media key material. The raw shared secret is wiped locally.
    public static func answer(
        _ offerSignal: CallSignalV1,
        tracks: [CallTrackSelectionV1],
        selectedCandidateID: UUID,
        responderCandidates: [CallTransportCandidateV1] = [],
        sequence: UInt64 = 1,
        at now: Date = Date()
    ) throws -> CallResponderAcceptanceV1 {
        guard offerSignal.kind == .offer,
              offerSignal.isFresh(at: now),
              let offer = offerSignal.offer,
              let offerDigest = offer.canonicalDigest else {
            throw CallProtocolV1Error.invalidOffer
        }
        var encapsulation: KEMOutput
        do {
            encapsulation = try AgreementKeyPair.encapsulate(
                to: offer.initiatorAgreementPublicKey
            )
        } catch {
            throw CallProtocolV1Error.invalidOffer
        }
        defer { encapsulation.sharedSecret.secureWipe() }
        let answer = CallAnswerV1(
            offerDigest: offerDigest,
            kemCiphertext: encapsulation.ciphertext,
            tracks: tracks,
            selectedCandidateID: selectedCandidateID,
            responderCandidates: responderCandidates
        )
        guard answer.isCompatible(with: offer) else {
            throw CallProtocolV1Error.invalidAnswer
        }
        let answerSignal = try CallSignalV1.answer(
            callID: offerSignal.callID,
            sequence: sequence,
            answer: answer,
            createdAt: now,
            noLaterThan: offerSignal.expiresAt
        )
        return CallResponderAcceptanceV1(
            answerSignal: answerSignal,
            keyMaterial: try CallKeyScheduleV1.derive(
                offerSignal: offerSignal,
                answerSignal: answerSignal,
                sharedSecret: encapsulation.sharedSecret
            )
        )
    }
}

public struct CallMediaFlagsV1: OptionSet, Equatable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let keyFrame = CallMediaFlagsV1(rawValue: 1 << 0)
    public static let comfortNoise = CallMediaFlagsV1(rawValue: 1 << 1)
    public static let endOfTrack = CallMediaFlagsV1(rawValue: 1 << 2)

    static let allowedMask: UInt8 = keyFrame.rawValue | comfortNoise.rawValue | endOfTrack.rawValue
    public var isStructurallyValid: Bool { rawValue & ~Self.allowedMask == 0 }
}

public struct CallMediaFrameV1: Equatable {
    public let trackID: UInt16
    public let timestamp: UInt64
    public let flags: CallMediaFlagsV1
    public let payload: Data

    public init(
        trackID: UInt16,
        timestamp: UInt64,
        flags: CallMediaFlagsV1 = [],
        payload: Data
    ) {
        self.trackID = trackID
        self.timestamp = timestamp
        self.flags = flags
        self.payload = payload
    }

    public var isStructurallyValid: Bool {
        trackID > 0
            && flags.isStructurallyValid
            && !payload.isEmpty
            && payload.count <= NoctweaveCallV1.maximumMediaPayloadBytes
    }
}

public struct SealedCallMediaFrameV1: Codable, Equatable {
    public let version: Int
    public let epoch: UInt32
    public let sequence: UInt64
    public let ciphertext: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case epoch
        case sequence
        case ciphertext
    }

    public init(
        version: Int = NoctweaveCallV1.version,
        epoch: UInt32,
        sequence: UInt64,
        ciphertext: Data
    ) {
        self.version = version
        self.epoch = epoch
        self.sequence = sequence
        self.ciphertext = ciphertext
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveCallV1.version
            && sequence > 0
            && sequence <= NoctweaveCallV1.maximumCanonicalSequence
            && NoctweaveCallV1.allowedSealedMediaByteCounts.contains(ciphertext.count)
    }

    public init(from decoder: Decoder) throws {
        try callRequireExactFields(decoder, CodingKeys.self)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try container.decode(Int.self, forKey: .version),
            epoch: try container.decode(UInt32.self, forKey: .epoch),
            sequence: try container.decode(UInt64.self, forKey: .sequence),
            ciphertext: try container.decode(Data.self, forKey: .ciphertext)
        )
        guard isStructurallyValid else { throw callCodingError(decoder, "Invalid sealed call frame") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw callCodingError(encoder, "Invalid sealed call frame") }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(epoch, forKey: .epoch)
        try container.encode(sequence, forKey: .sequence)
        try container.encode(ciphertext, forKey: .ciphertext)
    }
}

public enum CallMediaCipherV1 {
    private static let headerBytes = 14
    private static let tagBytes = 16

    public static func seal(
        _ frame: CallMediaFrameV1,
        material: CallKeyMaterialV1,
        senderRole: CallRoleV1,
        epoch: UInt32,
        sequence: UInt64,
        targetByteCount: Int? = nil,
        deterministicPadding: Data? = nil
    ) throws -> SealedCallMediaFrameV1 {
        guard frame.isStructurallyValid,
              sequence > 0,
              sequence <= NoctweaveCallV1.maximumCanonicalSequence else {
            throw CallProtocolV1Error.invalidMediaFrame
        }
        let minimum = headerBytes + frame.payload.count + tagBytes
        let sealedByteCount: Int
        if let targetByteCount {
            guard NoctweaveCallV1.allowedSealedMediaByteCounts.contains(targetByteCount),
                  targetByteCount >= minimum else {
                throw CallProtocolV1Error.invalidMediaFrame
            }
            sealedByteCount = targetByteCount
        } else if let selected = NoctweaveCallV1.allowedSealedMediaByteCounts.first(where: { $0 >= minimum }) {
            sealedByteCount = selected
        } else {
            throw CallProtocolV1Error.mediaPayloadTooLarge
        }

        let plaintextByteCount = sealedByteCount - tagBytes
        let paddingCount = plaintextByteCount - headerBytes - frame.payload.count
        var plaintext = Data()
        plaintext.reserveCapacity(plaintextByteCount)
        plaintext.append(UInt8(NoctweaveCallV1.version))
        appendBigEndian(frame.trackID, to: &plaintext)
        appendBigEndian(frame.timestamp, to: &plaintext)
        plaintext.append(frame.flags.rawValue)
        appendBigEndian(UInt16(frame.payload.count), to: &plaintext)
        plaintext.append(frame.payload)
        if let deterministicPadding {
            guard deterministicPadding.count == paddingCount else {
                throw CallProtocolV1Error.invalidMediaFrame
            }
            plaintext.append(deterministicPadding)
        } else {
            var generator = SystemRandomNumberGenerator()
            for _ in 0..<paddingCount {
                plaintext.append(UInt8.random(in: .min ... .max, using: &generator))
            }
        }

        let nonce = try AES.GCM.Nonce(data: mediaNonce(epoch: epoch, sequence: sequence))
        let aad = mediaAAD(
            material: material,
            senderRole: senderRole,
            epoch: epoch,
            sequence: sequence,
            sealedByteCount: sealedByteCount
        )
        let box = try AES.GCM.seal(
            plaintext,
            using: CallKeyScheduleV1.mediaKey(
                material: material,
                senderRole: senderRole,
                epoch: epoch
            ),
            nonce: nonce,
            authenticating: aad
        )
        var ciphertext = Data()
        ciphertext.reserveCapacity(sealedByteCount)
        ciphertext.append(contentsOf: box.ciphertext)
        ciphertext.append(contentsOf: box.tag)
        guard ciphertext.count == sealedByteCount else {
            throw CallProtocolV1Error.invalidMediaFrame
        }
        return SealedCallMediaFrameV1(epoch: epoch, sequence: sequence, ciphertext: ciphertext)
    }

    public static func open(
        _ sealed: SealedCallMediaFrameV1,
        material: CallKeyMaterialV1,
        senderRole: CallRoleV1
    ) throws -> CallMediaFrameV1 {
        guard sealed.isStructurallyValid, sealed.ciphertext.count > tagBytes else {
            throw CallProtocolV1Error.invalidMediaFrame
        }
        let ciphertextEnd = sealed.ciphertext.count - tagBytes
        let ciphertext = sealed.ciphertext.prefix(ciphertextEnd)
        let tag = sealed.ciphertext.suffix(tagBytes)
        let nonce = try AES.GCM.Nonce(
            data: mediaNonce(epoch: sealed.epoch, sequence: sealed.sequence)
        )
        let box = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(
                box,
                using: CallKeyScheduleV1.mediaKey(
                    material: material,
                    senderRole: senderRole,
                    epoch: sealed.epoch
                ),
                authenticating: mediaAAD(
                    material: material,
                    senderRole: senderRole,
                    epoch: sealed.epoch,
                    sequence: sealed.sequence,
                    sealedByteCount: sealed.ciphertext.count
                )
            )
        } catch {
            throw CallProtocolV1Error.authenticationFailed
        }
        let plaintextStart = plaintext.startIndex
        guard plaintext.count >= headerBytes,
              plaintext[plaintextStart] == UInt8(NoctweaveCallV1.version) else {
            throw CallProtocolV1Error.invalidMediaFrame
        }
        let trackID = readUInt16(plaintext, at: 1)
        let timestamp = readUInt64(plaintext, at: 3)
        let flagsIndex = plaintext.index(plaintextStart, offsetBy: 11)
        let flags = CallMediaFlagsV1(rawValue: plaintext[flagsIndex])
        let payloadLength = Int(readUInt16(plaintext, at: 12))
        guard payloadLength > 0,
              headerBytes + payloadLength <= plaintext.count else {
            throw CallProtocolV1Error.invalidMediaFrame
        }
        let payloadStart = plaintext.index(plaintextStart, offsetBy: headerBytes)
        let payloadEnd = plaintext.index(payloadStart, offsetBy: payloadLength)
        let frame = CallMediaFrameV1(
            trackID: trackID,
            timestamp: timestamp,
            flags: flags,
            payload: Data(plaintext[payloadStart..<payloadEnd])
        )
        guard frame.isStructurallyValid else { throw CallProtocolV1Error.invalidMediaFrame }
        return frame
    }

    private static func mediaNonce(epoch: UInt32, sequence: UInt64) -> Data {
        var nonce = Data()
        appendBigEndian(epoch, to: &nonce)
        appendBigEndian(sequence, to: &nonce)
        return nonce
    }

    private static func mediaAAD(
        material: CallKeyMaterialV1,
        senderRole: CallRoleV1,
        epoch: UInt32,
        sequence: UInt64,
        sealedByteCount: Int
    ) -> Data {
        var aad = NoctweaveCallV1.mediaAADDomain
        aad.append(0)
        aad.append(Data(material.callID.uuidString.uppercased().utf8))
        aad.append(0)
        aad.append(material.transcriptDigest)
        aad.append(0)
        aad.append(Data(senderRole.rawValue.utf8))
        appendBigEndian(epoch, to: &aad)
        appendBigEndian(sequence, to: &aad)
        appendBigEndian(UInt32(sealedByteCount), to: &aad)
        return aad
    }
}

public struct CallMediaSenderV1 {
    public let material: CallKeyMaterialV1
    public let role: CallRoleV1
    public private(set) var epoch: UInt32
    public private(set) var nextSequence: UInt64

    public init(material: CallKeyMaterialV1, role: CallRoleV1, epoch: UInt32 = 0) throws {
        guard material.isStructurallyValid else { throw CallProtocolV1Error.invalidKeyMaterial }
        self.material = material
        self.role = role
        self.epoch = epoch
        nextSequence = 1
    }

    public mutating func seal(
        _ frame: CallMediaFrameV1,
        targetByteCount: Int? = nil
    ) throws -> SealedCallMediaFrameV1 {
        guard nextSequence <= NoctweaveCallV1.maximumCanonicalSequence else {
            throw CallProtocolV1Error.sequenceExhausted
        }
        let sealed = try CallMediaCipherV1.seal(
            frame,
            material: material,
            senderRole: role,
            epoch: epoch,
            sequence: nextSequence,
            targetByteCount: targetByteCount
        )
        if nextSequence < NoctweaveCallV1.maximumCanonicalSequence {
            nextSequence += 1
        } else {
            nextSequence = NoctweaveCallV1.maximumCanonicalSequence + 1
        }
        return sealed
    }

    public mutating func rotateEpoch() throws {
        guard epoch < UInt32.max else { throw CallProtocolV1Error.sequenceExhausted }
        epoch += 1
        nextSequence = 1
    }
}

public struct CallMediaReceiverV1 {
    public let material: CallKeyMaterialV1
    public let remoteRole: CallRoleV1
    public private(set) var highestEpoch: UInt32?
    private var replayWindows: [UInt32: CallReplayWindowV1] = [:]

    public init(material: CallKeyMaterialV1, remoteRole: CallRoleV1) throws {
        guard material.isStructurallyValid else { throw CallProtocolV1Error.invalidKeyMaterial }
        self.material = material
        self.remoteRole = remoteRole
    }

    public mutating func open(_ sealed: SealedCallMediaFrameV1) throws -> CallMediaFrameV1 {
        if highestEpoch == nil {
            guard sealed.epoch == 0 else { throw CallProtocolV1Error.invalidEpoch }
        } else if let highestEpoch {
            let maximumAcceptedEpoch = highestEpoch == UInt32.max ? highestEpoch : highestEpoch + 1
            let minimumAcceptedEpoch = highestEpoch == 0 ? 0 : highestEpoch - 1
            guard sealed.epoch <= maximumAcceptedEpoch,
                  sealed.epoch >= minimumAcceptedEpoch else {
                throw CallProtocolV1Error.invalidEpoch
            }
        }
        var window = replayWindows[sealed.epoch] ?? CallReplayWindowV1()
        guard !window.contains(sealed.sequence) else { throw CallProtocolV1Error.replay }
        let frame = try CallMediaCipherV1.open(
            sealed,
            material: material,
            senderRole: remoteRole
        )
        guard window.insert(sealed.sequence) else { throw CallProtocolV1Error.replay }
        replayWindows[sealed.epoch] = window
        highestEpoch = max(highestEpoch ?? sealed.epoch, sealed.epoch)
        if let highestEpoch {
            replayWindows = replayWindows.filter { epoch, _ in
                epoch == highestEpoch || (highestEpoch > 0 && epoch == highestEpoch - 1)
            }
        }
        return frame
    }
}

public enum CallSessionPhaseV1: String, Codable, Equatable {
    case ringing
    case connecting
    case active
    case ended
}

public enum CallSignalApplyResultV1: Equatable {
    case applied
    case exactReplay
    case stale
}

public struct CallStateMachineV1 {
    public let callID: UUID
    public let offerSignal: CallSignalV1
    public private(set) var phase: CallSessionPhaseV1
    public private(set) var terminationReason: CallTerminationReasonV1?
    public private(set) var answerSignal: CallSignalV1?

    private var lastSequence: [CallRoleV1: UInt64]
    private var lastDigest: [CallRoleV1: Data]

    public init(offerSignal: CallSignalV1, now: Date = Date()) throws {
        guard offerSignal.kind == .offer,
              offerSignal.isFresh(at: now),
              let digest = offerSignal.canonicalDigest else {
            throw CallProtocolV1Error.invalidOffer
        }
        callID = offerSignal.callID
        self.offerSignal = offerSignal
        phase = .ringing
        terminationReason = nil
        answerSignal = nil
        lastSequence = [.initiator: offerSignal.sequence]
        lastDigest = [.initiator: digest]
    }

    public mutating func apply(
        _ signal: CallSignalV1,
        now: Date = Date()
    ) throws -> CallSignalApplyResultV1 {
        guard signal.callID == callID,
              signal.isFresh(at: now),
              let digest = signal.canonicalDigest else {
            throw CallProtocolV1Error.invalidSignal
        }
        if let previous = lastSequence[signal.senderRole] {
            if signal.sequence < previous { return .stale }
            if signal.sequence == previous {
                guard let priorDigest = lastDigest[signal.senderRole],
                      constantTimeEqual(priorDigest, digest) else {
                    throw CallProtocolV1Error.signalFork
                }
                return .exactReplay
            }
        }
        guard phase != .ended else { return .stale }

        switch signal.kind {
        case .offer:
            throw CallProtocolV1Error.invalidTransition
        case .ringing:
            guard phase == .ringing, signal.senderRole == .responder else {
                throw CallProtocolV1Error.invalidTransition
            }
        case .answer:
            guard phase == .ringing,
                  let answer = signal.answer,
                  let offer = offerSignal.offer,
                  answer.isCompatible(with: offer) else {
                throw CallProtocolV1Error.transcriptMismatch
            }
            answerSignal = signal
            phase = .connecting
        case .candidate:
            guard phase == .ringing || phase == .connecting || phase == .active else {
                throw CallProtocolV1Error.invalidTransition
            }
        case .connected:
            guard phase == .connecting || phase == .active else {
                throw CallProtocolV1Error.invalidTransition
            }
            phase = .active
        case .declined, .canceled, .ended:
            phase = .ended
            terminationReason = signal.terminationReason
        }
        lastSequence[signal.senderRole] = signal.sequence
        lastDigest[signal.senderRole] = digest
        return .applied
    }

}

public enum CallProtocolV1Error: Error, Equatable {
    case invalidOffer
    case invalidAnswer
    case invalidSignal
    case nonCanonicalSignal
    case transcriptMismatch
    case invalidKeyMaterial
    case invalidMediaFrame
    case mediaPayloadTooLarge
    case authenticationFailed
    case replay
    case invalidEpoch
    case sequenceExhausted
    case signalFork
    case invalidTransition
}

private struct CallReplayWindowV1 {
    private var highest: UInt64 = 0
    private var seen: Set<UInt64> = []

    func contains(_ sequence: UInt64) -> Bool {
        guard sequence > 0 else { return true }
        if highest >= NoctweaveCallV1.replayWindowSize,
           sequence <= highest - NoctweaveCallV1.replayWindowSize {
            return true
        }
        return seen.contains(sequence)
    }

    mutating func insert(_ sequence: UInt64) -> Bool {
        guard !contains(sequence) else { return false }
        highest = max(highest, sequence)
        let floor = highest > NoctweaveCallV1.replayWindowSize
            ? highest - NoctweaveCallV1.replayWindowSize
            : 0
        seen = Set(seen.filter { $0 > floor })
        seen.insert(sequence)
        return true
    }
}

private struct CallDynamicCodingKey: CodingKey, Hashable {
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

private func callRequireExactFields<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ keyType: Key.Type
) throws {
    let container = try decoder.container(keyedBy: CallDynamicCodingKey.self)
    let actual = Set(container.allKeys.map(\.stringValue))
    let expected = Set(Key.allCases.map(\.stringValue))
    guard actual == expected else { throw callCodingError(decoder, "Unexpected call protocol fields") }
}

private func callEncodeOptional<T: Encodable, Key: CodingKey>(
    _ value: T?,
    forKey key: Key,
    into container: inout KeyedEncodingContainer<Key>
) throws {
    if let value {
        try container.encode(value, forKey: key)
    } else {
        try container.encodeNil(forKey: key)
    }
}

private func callCodingError(_ decoder: Decoder, _ description: String) -> DecodingError {
    DecodingError.dataCorrupted(
        DecodingError.Context(codingPath: decoder.codingPath, debugDescription: description)
    )
}

private func callCodingError(_ encoder: Encoder, _ description: String) -> EncodingError {
    EncodingError.invalidValue(
        description,
        EncodingError.Context(codingPath: encoder.codingPath, debugDescription: description)
    )
}

private func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
    var bigEndian = value.bigEndian
    withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
}

private func readUInt16(_ data: Data, at offset: Int) -> UInt16 {
    let first = data.index(data.startIndex, offsetBy: offset)
    let second = data.index(after: first)
    return (UInt16(data[first]) << 8) | UInt16(data[second])
}

private func readUInt64(_ data: Data, at offset: Int) -> UInt64 {
    var result: UInt64 = 0
    let start = data.index(data.startIndex, offsetBy: offset)
    let end = data.index(start, offsetBy: 8)
    for index in start..<end {
        result = (result << 8) | UInt64(data[index])
    }
    return result
}

private func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
    guard left.count == right.count else { return false }
    var difference: UInt8 = 0
    for (leftByte, rightByte) in zip(left, right) {
        difference |= leftByte ^ rightByte
    }
    return difference == 0
}
