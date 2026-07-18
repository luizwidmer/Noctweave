import CryptoKit
import Foundation

/// Philosophy-safe rendezvous primitives. These objects establish one short-lived,
/// purpose-bound encrypted session. They do not authorize an identity generation,
/// endpoint membership, mailbox access, history import, or future participation.
public enum NoctweaveRendezvousV2 {
    public static let version = 2
    public static let maximumLifetime: TimeInterval = 10 * 60
    public static let tokenBytes = 32
    public static let tokenDigestBytes = 32
    public static let transportCapabilityBytes = 32
    public static let maximumKEMCiphertextBytes = 4_096
    public static let maximumFramesPerDirection: UInt16 = 32
    public static let maximumFramePlaintextBytes: UInt32 = 60 * 1_024
    public static let maximumLedgerEntries = 256
    public static let paddingBuckets = [4_096, 16_384, 65_536]

    /// Protocol transcripts use whole-second timestamps so Codable round trips do
    /// not silently change authenticated bytes on platforms with different date precision.
    public static func canonicalTimestamp(_ date: Date = Date()) -> Date {
        Date(timeIntervalSince1970: floor(date.timeIntervalSince1970))
    }
}

public enum RendezvousV2Error: Error, Equatable {
    case invalidOffer
    case invalidTransportCapability
    case invalidLimits
    case wrongPurpose
    case expired
    case invalidRedemptionSecret
    case invalidOpen
    case invalidLedger
    case alreadyRedeemed
    case ledgerFull
    case invalidFrame
    case wrongSession
    case wrongSenderRole
    case unexpectedSequence(expected: UInt64, actual: UInt64)
    case unsupportedMessageKind
    case payloadTooLarge
    case frameLimitExceeded
    case decryptionFailed
}

public enum RendezvousPurposeV2: String, Codable, Equatable, Hashable, CaseIterable {
    case contactPairing
}

/// A transport adapter may interpret this random capability, but the protocol
/// model deliberately carries no URL, provider name, account, inbox, or owner ID.
public struct RendezvousTransportCapabilityV2: Codable, Equatable, Hashable {
    public let opaqueValue: Data
    public let expiresAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case opaqueValue
        case expiresAt
    }

    public init(opaqueValue: Data, expiresAt: Date) throws {
        self.opaqueValue = opaqueValue
        self.expiresAt = expiresAt
        guard isStructurallyValid else {
            throw RendezvousV2Error.invalidTransportCapability
        }
    }

    public static func generate(expiresAt: Date) throws -> RendezvousTransportCapabilityV2 {
        try RendezvousTransportCapabilityV2(
            opaqueValue: SymmetricKey(size: .bits256).dataRepresentation,
            expiresAt: expiresAt
        )
    }

    public var isStructurallyValid: Bool {
        opaqueValue.count == NoctweaveRendezvousV2.transportCapabilityBytes
            && RendezvousCanonicalV2.isCanonicalTimestamp(expiresAt)
    }

    public init(from decoder: Decoder) throws {
        let container = try strictRendezvousContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Rendezvous transport capability"
        )
        opaqueValue = try container.decode(Data.self, forKey: .opaqueValue)
        expiresAt = try container.decode(Date.self, forKey: .expiresAt)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .opaqueValue,
                in: container,
                debugDescription: "Invalid rendezvous transport capability"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidRendezvousEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid rendezvous transport capability"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(opaqueValue, forKey: .opaqueValue)
        try container.encode(expiresAt, forKey: .expiresAt)
    }
}

public struct RendezvousLimitsV2: Codable, Equatable, Hashable {
    /// This limit applies independently in each direction.
    public let maximumFrames: UInt16
    public let maximumFramePlaintextBytes: UInt32

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case maximumFrames
        case maximumFramePlaintextBytes
    }

    public static let contactPairing = RendezvousLimitsV2(
        uncheckedMaximumFrames: 16,
        uncheckedMaximumFramePlaintextBytes: NoctweaveRendezvousV2.maximumFramePlaintextBytes
    )

    public init(maximumFrames: UInt16, maximumFramePlaintextBytes: UInt32) throws {
        self.maximumFrames = maximumFrames
        self.maximumFramePlaintextBytes = maximumFramePlaintextBytes
        guard isStructurallyValid else {
            throw RendezvousV2Error.invalidLimits
        }
    }

    private init(uncheckedMaximumFrames: UInt16, uncheckedMaximumFramePlaintextBytes: UInt32) {
        maximumFrames = uncheckedMaximumFrames
        maximumFramePlaintextBytes = uncheckedMaximumFramePlaintextBytes
    }

    public var isStructurallyValid: Bool {
        maximumFrames > 0
            && maximumFrames <= NoctweaveRendezvousV2.maximumFramesPerDirection
            && maximumFramePlaintextBytes > 0
            && maximumFramePlaintextBytes <= NoctweaveRendezvousV2.maximumFramePlaintextBytes
    }

    public init(from decoder: Decoder) throws {
        let container = try strictRendezvousContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Rendezvous limits"
        )
        maximumFrames = try container.decode(UInt16.self, forKey: .maximumFrames)
        maximumFramePlaintextBytes = try container.decode(
            UInt32.self,
            forKey: .maximumFramePlaintextBytes
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .maximumFrames,
                in: container,
                debugDescription: "Invalid rendezvous limits"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidRendezvousEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid rendezvous limits"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(maximumFrames, forKey: .maximumFrames)
        try container.encode(maximumFramePlaintextBytes, forKey: .maximumFramePlaintextBytes)
    }
}

/// This is the complete public offer. Its transcript intentionally contains no
/// generation, identity, endpoint, inbox, provider, or stable device identifier.
public struct RendezvousOfferV2: Codable, Equatable {
    public let version: Int
    public let purpose: RendezvousPurposeV2
    public let transportCapability: RendezvousTransportCapabilityV2
    public let oneTimeTokenDigest: Data
    public let ephemeralAgreementPublicKey: Data
    public let createdAt: Date
    public let expiresAt: Date
    public let limits: RendezvousLimitsV2

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case purpose
        case transportCapability
        case oneTimeTokenDigest
        case ephemeralAgreementPublicKey
        case createdAt
        case expiresAt
        case limits
    }

    public init(
        version: Int = NoctweaveRendezvousV2.version,
        purpose: RendezvousPurposeV2,
        transportCapability: RendezvousTransportCapabilityV2,
        oneTimeTokenDigest: Data,
        ephemeralAgreementPublicKey: Data,
        createdAt: Date,
        expiresAt: Date,
        limits: RendezvousLimitsV2 = .contactPairing
    ) throws {
        self.version = version
        self.purpose = purpose
        self.transportCapability = transportCapability
        self.oneTimeTokenDigest = oneTimeTokenDigest
        self.ephemeralAgreementPublicKey = ephemeralAgreementPublicKey
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.limits = limits
        guard isStructurallyValid else {
            throw RendezvousV2Error.invalidOffer
        }
    }

    public var isStructurallyValid: Bool {
        let lifetime = expiresAt.timeIntervalSince(createdAt)
        return version == NoctweaveRendezvousV2.version
            && transportCapability.isStructurallyValid
            && transportCapability.expiresAt == expiresAt
            && oneTimeTokenDigest.count == NoctweaveRendezvousV2.tokenDigestBytes
            && AgreementKeyPair.isValidPublicKey(ephemeralAgreementPublicKey)
            && RendezvousCanonicalV2.isCanonicalTimestamp(createdAt)
            && RendezvousCanonicalV2.isCanonicalTimestamp(expiresAt)
            && lifetime > 0
            && lifetime <= NoctweaveRendezvousV2.maximumLifetime
            && limits.isStructurallyValid
    }

    public func isUsable(
        at date: Date = Date(),
        for expectedPurpose: RendezvousPurposeV2
    ) -> Bool {
        isStructurallyValid
            && purpose == expectedPurpose
            && date.timeIntervalSince1970.isFinite
            && date >= createdAt
            && date < expiresAt
    }

    /// A digest of every public offer field, encoded with a deterministic binary profile.
    public var transcriptDigest: Data {
        Data(SHA256.hash(data: RendezvousCanonicalV2.offerTranscript(self)))
    }

    public init(from decoder: Decoder) throws {
        let container = try strictRendezvousContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Rendezvous offer"
        )
        version = try container.decode(Int.self, forKey: .version)
        purpose = try container.decode(RendezvousPurposeV2.self, forKey: .purpose)
        transportCapability = try container.decode(
            RendezvousTransportCapabilityV2.self,
            forKey: .transportCapability
        )
        oneTimeTokenDigest = try container.decode(Data.self, forKey: .oneTimeTokenDigest)
        ephemeralAgreementPublicKey = try container.decode(
            Data.self,
            forKey: .ephemeralAgreementPublicKey
        )
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        expiresAt = try container.decode(Date.self, forKey: .expiresAt)
        limits = try container.decode(RendezvousLimitsV2.self, forKey: .limits)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: container,
                debugDescription: "Invalid rendezvous offer"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidRendezvousEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid rendezvous offer"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(purpose, forKey: .purpose)
        try container.encode(transportCapability, forKey: .transportCapability)
        try container.encode(oneTimeTokenDigest, forKey: .oneTimeTokenDigest)
        try container.encode(ephemeralAgreementPublicKey, forKey: .ephemeralAgreementPublicKey)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(expiresAt, forKey: .expiresAt)
        try container.encode(limits, forKey: .limits)
    }
}

/// Sensitive bearer material delivered separately from the public offer through
/// the user-selected pairing channel. It is never placed in RendezvousOfferV2.
public struct RendezvousRedemptionSecretV2: Codable, Equatable {
    public let oneTimeToken: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case oneTimeToken
    }

    public init(oneTimeToken: Data) throws {
        self.oneTimeToken = oneTimeToken
        guard isStructurallyValid else {
            throw RendezvousV2Error.invalidRedemptionSecret
        }
    }

    public var isStructurallyValid: Bool {
        oneTimeToken.count == NoctweaveRendezvousV2.tokenBytes
    }

    public func matches(_ offer: RendezvousOfferV2) -> Bool {
        guard isStructurallyValid else { return false }
        let digest = Data(SHA256.hash(data: oneTimeToken))
        return RendezvousCanonicalV2.constantTimeEqual(digest, offer.oneTimeTokenDigest)
    }

    public init(from decoder: Decoder) throws {
        let container = try strictRendezvousContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Rendezvous redemption secret"
        )
        oneTimeToken = try container.decode(Data.self, forKey: .oneTimeToken)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .oneTimeToken,
                in: container,
                debugDescription: "Invalid rendezvous redemption secret"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidRendezvousEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid rendezvous redemption secret"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(oneTimeToken, forKey: .oneTimeToken)
    }
}

/// A locally persisted offer. It is secret state and must be protected by the
/// caller's encrypted state store. The ML-KEM private key and raw token never
/// appear in the public offer.
public struct PendingRendezvousOfferV2: Codable {
    public let offer: RendezvousOfferV2
    private let ephemeralAgreementKey: AgreementKeyPair
    private var oneTimeToken: Data
    public private(set) var redeemedAt: Date?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case offer
        case ephemeralAgreementKey
        case oneTimeToken
        case redeemedAt
    }

    private init(
        offer: RendezvousOfferV2,
        ephemeralAgreementKey: AgreementKeyPair,
        oneTimeToken: Data,
        redeemedAt: Date? = nil
    ) {
        self.offer = offer
        self.ephemeralAgreementKey = ephemeralAgreementKey
        self.oneTimeToken = oneTimeToken
        self.redeemedAt = redeemedAt
    }

    public static func create(
        purpose: RendezvousPurposeV2 = .contactPairing,
        transportCapability: RendezvousTransportCapabilityV2,
        createdAt: Date,
        limits: RendezvousLimitsV2 = .contactPairing
    ) throws -> PendingRendezvousOfferV2 {
        let ephemeralAgreementKey = try AgreementKeyPair.generate()
        let oneTimeToken = SymmetricKey(size: .bits256).dataRepresentation
        let offer = try RendezvousOfferV2(
            purpose: purpose,
            transportCapability: transportCapability,
            oneTimeTokenDigest: Data(SHA256.hash(data: oneTimeToken)),
            ephemeralAgreementPublicKey: ephemeralAgreementKey.publicKeyData,
            createdAt: createdAt,
            expiresAt: transportCapability.expiresAt,
            limits: limits
        )
        return PendingRendezvousOfferV2(
            offer: offer,
            ephemeralAgreementKey: ephemeralAgreementKey,
            oneTimeToken: oneTimeToken
        )
    }

    public init(from decoder: Decoder) throws {
        let container = try strictRendezvousContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Pending rendezvous offer"
        )
        offer = try container.decode(RendezvousOfferV2.self, forKey: .offer)
        ephemeralAgreementKey = try container.decode(AgreementKeyPair.self, forKey: .ephemeralAgreementKey)
        oneTimeToken = try container.decode(Data.self, forKey: .oneTimeToken)
        redeemedAt = try container.decodeIfPresent(Date.self, forKey: .redeemedAt)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .offer,
                in: container,
                debugDescription: "Invalid pending rendezvous state"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidRendezvousEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid pending rendezvous state"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(offer, forKey: .offer)
        try container.encode(ephemeralAgreementKey, forKey: .ephemeralAgreementKey)
        try container.encode(oneTimeToken, forKey: .oneTimeToken)
        try container.encode(redeemedAt, forKey: .redeemedAt)
    }

    public var isRedeemed: Bool { redeemedAt != nil }

    public var isStructurallyValid: Bool {
        guard offer.isStructurallyValid,
              ephemeralAgreementKey.publicKeyData == offer.ephemeralAgreementPublicKey,
              oneTimeToken.count == NoctweaveRendezvousV2.tokenBytes,
              RendezvousCanonicalV2.constantTimeEqual(
                Data(SHA256.hash(data: oneTimeToken)),
                offer.oneTimeTokenDigest
              ) else {
            return false
        }
        return redeemedAt.map {
            $0.timeIntervalSince1970.isFinite && $0 >= offer.createdAt && $0 < offer.expiresAt
        } ?? true
    }

    /// Explicitly exports only the one-use bearer secret, never the ML-KEM private key.
    public func redemptionSecret() throws -> RendezvousRedemptionSecretV2 {
        guard redeemedAt == nil else {
            throw RendezvousV2Error.alreadyRedeemed
        }
        return try RendezvousRedemptionSecretV2(oneTimeToken: oneTimeToken)
    }

    /// Accepting an open mutates both this pending record and the caller's durable
    /// redemption ledger. Callers must persist those two mutations atomically before
    /// treating the returned session as accepted.
    public mutating func accept(
        _ request: RendezvousOpenV2,
        ledger: inout RendezvousRedemptionLedgerV2,
        at date: Date = Date()
    ) throws -> RendezvousSessionV2 {
        guard isStructurallyValid else {
            throw RendezvousV2Error.invalidOffer
        }
        guard redeemedAt == nil else {
            throw RendezvousV2Error.alreadyRedeemed
        }
        try RendezvousCanonicalV2.validateOfferUse(
            offer,
            expectedPurpose: offer.purpose,
            at: date
        )
        guard request.isStructurallyValid(for: offer) else {
            throw RendezvousV2Error.invalidOpen
        }
        let proofMaterial = RendezvousCanonicalV2.openProofMaterial(request)
        guard HMAC<SHA256>.isValidAuthenticationCode(
            request.tokenProof,
            authenticating: proofMaterial,
            using: SymmetricKey(data: oneTimeToken)
        ) else {
            throw RendezvousV2Error.invalidOpen
        }

        var sharedSecret: Data
        do {
            sharedSecret = try ephemeralAgreementKey.decapsulate(ciphertext: request.kemCiphertext)
        } catch {
            throw RendezvousV2Error.invalidOpen
        }
        defer { sharedSecret.secureWipe() }

        let session = RendezvousSessionV2.make(
            role: .offerer,
            sharedSecret: sharedSecret,
            offer: offer,
            request: request
        )
        try ledger.register(
            offerDigest: offer.transcriptDigest,
            openDigest: request.transcriptDigest,
            redeemedAt: date,
            expiresAt: offer.expiresAt
        )
        redeemedAt = date
        return session
    }
}

public struct RendezvousOpenV2: Codable, Equatable {
    public let version: Int
    public let purpose: RendezvousPurposeV2
    public let offerDigest: Data
    public let kemCiphertext: Data
    public let tokenProof: Data
    public let openedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case purpose
        case offerDigest
        case kemCiphertext
        case tokenProof
        case openedAt
    }

    public init(
        version: Int = NoctweaveRendezvousV2.version,
        purpose: RendezvousPurposeV2,
        offerDigest: Data,
        kemCiphertext: Data,
        tokenProof: Data,
        openedAt: Date
    ) {
        self.version = version
        self.purpose = purpose
        self.offerDigest = offerDigest
        self.kemCiphertext = kemCiphertext
        self.tokenProof = tokenProof
        self.openedAt = openedAt
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveRendezvousV2.version
            && offerDigest.count == SHA256.byteCount
            && !kemCiphertext.isEmpty
            && kemCiphertext.count <= NoctweaveRendezvousV2.maximumKEMCiphertextBytes
            && tokenProof.count == SHA256.byteCount
            && RendezvousCanonicalV2.isCanonicalTimestamp(openedAt)
    }

    public func isStructurallyValid(for offer: RendezvousOfferV2) -> Bool {
        isStructurallyValid
            && offer.isStructurallyValid
            && purpose == offer.purpose
            && offerDigest == offer.transcriptDigest
            && openedAt >= offer.createdAt
            && openedAt < offer.expiresAt
    }

    public var transcriptDigest: Data {
        Data(SHA256.hash(data: RendezvousCanonicalV2.openTranscript(self)))
    }

    public init(from decoder: Decoder) throws {
        let container = try strictRendezvousContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Rendezvous open"
        )
        self.init(
            version: try container.decode(Int.self, forKey: .version),
            purpose: try container.decode(RendezvousPurposeV2.self, forKey: .purpose),
            offerDigest: try container.decode(Data.self, forKey: .offerDigest),
            kemCiphertext: try container.decode(Data.self, forKey: .kemCiphertext),
            tokenProof: try container.decode(Data.self, forKey: .tokenProof),
            openedAt: try container.decode(Date.self, forKey: .openedAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: container,
                debugDescription: "Invalid rendezvous open"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidRendezvousEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid rendezvous open"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(purpose, forKey: .purpose)
        try container.encode(offerDigest, forKey: .offerDigest)
        try container.encode(kemCiphertext, forKey: .kemCiphertext)
        try container.encode(tokenProof, forKey: .tokenProof)
        try container.encode(openedAt, forKey: .openedAt)
    }
}

public enum RendezvousResponderV2 {
    /// Encapsulates directly to the offer's ephemeral ML-KEM public key. The
    /// returned session proves key agreement when either side opens a frame.
    public static func createOpen(
        for offer: RendezvousOfferV2,
        redemptionSecret: RendezvousRedemptionSecretV2,
        expectedPurpose: RendezvousPurposeV2 = .contactPairing,
        at date: Date = Date()
    ) throws -> (request: RendezvousOpenV2, session: RendezvousSessionV2) {
        try RendezvousCanonicalV2.validateOfferUse(
            offer,
            expectedPurpose: expectedPurpose,
            at: date
        )
        guard redemptionSecret.matches(offer) else {
            throw RendezvousV2Error.invalidRedemptionSecret
        }
        let openedAt = NoctweaveRendezvousV2.canonicalTimestamp(date)
        var kemOutput = try AgreementKeyPair.encapsulate(to: offer.ephemeralAgreementPublicKey)
        defer { kemOutput.sharedSecret.secureWipe() }

        let requestWithoutProof = RendezvousOpenV2(
            purpose: offer.purpose,
            offerDigest: offer.transcriptDigest,
            kemCiphertext: kemOutput.ciphertext,
            tokenProof: Data(repeating: 0, count: SHA256.byteCount),
            openedAt: openedAt
        )
        let proof = Data(HMAC<SHA256>.authenticationCode(
            for: RendezvousCanonicalV2.openProofMaterial(requestWithoutProof),
            using: SymmetricKey(data: redemptionSecret.oneTimeToken)
        ))
        let request = RendezvousOpenV2(
            purpose: offer.purpose,
            offerDigest: offer.transcriptDigest,
            kemCiphertext: kemOutput.ciphertext,
            tokenProof: proof,
            openedAt: openedAt
        )
        guard request.isStructurallyValid(for: offer) else {
            throw RendezvousV2Error.invalidOpen
        }
        return (
            request,
            RendezvousSessionV2.make(
                role: .responder,
                sharedSecret: kemOutput.sharedSecret,
                offer: offer,
                request: request
            )
        )
    }
}

private struct RendezvousRedemptionRecordV2: Codable, Equatable {
    let offerDigest: Data
    let openDigest: Data
    let redeemedAt: Date
    let expiresAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case offerDigest
        case openDigest
        case redeemedAt
        case expiresAt
    }

    var isStructurallyValid: Bool {
        offerDigest.count == SHA256.byteCount
            && openDigest.count == SHA256.byteCount
            && redeemedAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && redeemedAt < expiresAt
    }

    init(
        offerDigest: Data,
        openDigest: Data,
        redeemedAt: Date,
        expiresAt: Date
    ) {
        self.offerDigest = offerDigest
        self.openDigest = openDigest
        self.redeemedAt = redeemedAt
        self.expiresAt = expiresAt
    }

    init(from decoder: Decoder) throws {
        let container = try strictRendezvousContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Rendezvous redemption record"
        )
        self.init(
            offerDigest: try container.decode(Data.self, forKey: .offerDigest),
            openDigest: try container.decode(Data.self, forKey: .openDigest),
            redeemedAt: try container.decode(Date.self, forKey: .redeemedAt),
            expiresAt: try container.decode(Date.self, forKey: .expiresAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .offerDigest,
                in: container,
                debugDescription: "Invalid rendezvous redemption record"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        try requireValidRendezvousEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid rendezvous redemption record"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(offerDigest, forKey: .offerDigest)
        try container.encode(openDigest, forKey: .openDigest)
        try container.encode(redeemedAt, forKey: .redeemedAt)
        try container.encode(expiresAt, forKey: .expiresAt)
    }
}

/// Bounded local replay state. It contains only public transcript digests and
/// timestamps, never the token, session key, or ML-KEM private key.
public struct RendezvousRedemptionLedgerV2: Codable, Equatable {
    private var records: [RendezvousRedemptionRecordV2]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case records
    }

    public init() {
        records = []
    }

    public var redemptionCount: Int { records.count }

    public var isStructurallyValid: Bool {
        records.count <= NoctweaveRendezvousV2.maximumLedgerEntries
            && Set(records.map(\.offerDigest)).count == records.count
            && records.allSatisfy(\.isStructurallyValid)
    }

    public func contains(offerDigest: Data) -> Bool {
        records.contains { $0.offerDigest == offerDigest }
    }

    public init(from decoder: Decoder) throws {
        let container = try strictRendezvousContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Rendezvous redemption ledger"
        )
        records = try container.decode([RendezvousRedemptionRecordV2].self, forKey: .records)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .records,
                in: container,
                debugDescription: "Invalid rendezvous redemption ledger"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidRendezvousEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid rendezvous redemption ledger"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(records, forKey: .records)
    }

    fileprivate mutating func register(
        offerDigest: Data,
        openDigest: Data,
        redeemedAt: Date,
        expiresAt: Date
    ) throws {
        guard isStructurallyValid else {
            throw RendezvousV2Error.invalidLedger
        }
        records.removeAll { $0.expiresAt <= redeemedAt }
        guard !records.contains(where: { $0.offerDigest == offerDigest }) else {
            throw RendezvousV2Error.alreadyRedeemed
        }
        guard records.count < NoctweaveRendezvousV2.maximumLedgerEntries else {
            throw RendezvousV2Error.ledgerFull
        }
        let record = RendezvousRedemptionRecordV2(
            offerDigest: offerDigest,
            openDigest: openDigest,
            redeemedAt: redeemedAt,
            expiresAt: expiresAt
        )
        guard record.isStructurallyValid else {
            throw RendezvousV2Error.invalidLedger
        }
        records.append(record)
    }
}

public enum RendezvousRoleV2: String, Codable, Equatable, Hashable {
    case offerer
    case responder

    fileprivate var opposite: RendezvousRoleV2 {
        self == .offerer ? .responder : .offerer
    }
}

public enum RendezvousMessageKindV2: String, Codable, Equatable, Hashable, CaseIterable {
    case contactOffer
    case contactAcceptance
    case confirmation
    case abort

    fileprivate func isAllowed(for purpose: RendezvousPurposeV2) -> Bool {
        purpose == .contactPairing
    }
}

public struct RendezvousSessionIDV2: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case rawValue
    }

    public init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public var isStructurallyValid: Bool {
        rawValue.count == SHA256.byteCount
    }

    public init(from decoder: Decoder) throws {
        let container = try strictRendezvousContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Rendezvous session identifier"
        )
        self.init(rawValue: try container.decode(Data.self, forKey: .rawValue))
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawValue,
                in: container,
                debugDescription: "Invalid rendezvous session identifier"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidRendezvousEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid rendezvous session identifier"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rawValue, forKey: .rawValue)
    }
}

public struct RendezvousFrameV2: Codable, Equatable {
    public let version: Int
    public let sessionId: RendezvousSessionIDV2
    public let purpose: RendezvousPurposeV2
    public let senderRole: RendezvousRoleV2
    public let sequence: UInt64
    public let messageKind: RendezvousMessageKindV2
    public let payload: EncryptedPayload

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case sessionId
        case purpose
        case senderRole
        case sequence
        case messageKind
        case payload
    }

    public init(
        version: Int = NoctweaveRendezvousV2.version,
        sessionId: RendezvousSessionIDV2,
        purpose: RendezvousPurposeV2,
        senderRole: RendezvousRoleV2,
        sequence: UInt64,
        messageKind: RendezvousMessageKindV2,
        payload: EncryptedPayload
    ) {
        self.version = version
        self.sessionId = sessionId
        self.purpose = purpose
        self.senderRole = senderRole
        self.sequence = sequence
        self.messageKind = messageKind
        self.payload = payload
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveRendezvousV2.version
            && sessionId.isStructurallyValid
            && messageKind.isAllowed(for: purpose)
            && sequence > 0
            && sequence <= UInt64(NoctweaveRendezvousV2.maximumFramesPerDirection)
            && payload.nonce.count == 12
            && payload.tag.count == 16
            && NoctweaveRendezvousV2.paddingBuckets.contains(payload.ciphertext.count)
    }

    public init(from decoder: Decoder) throws {
        let container = try strictRendezvousContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Rendezvous frame"
        )
        self.init(
            version: try container.decode(Int.self, forKey: .version),
            sessionId: try container.decode(RendezvousSessionIDV2.self, forKey: .sessionId),
            purpose: try container.decode(RendezvousPurposeV2.self, forKey: .purpose),
            senderRole: try container.decode(RendezvousRoleV2.self, forKey: .senderRole),
            sequence: try container.decode(UInt64.self, forKey: .sequence),
            messageKind: try container.decode(RendezvousMessageKindV2.self, forKey: .messageKind),
            payload: try container.decode(EncryptedPayload.self, forKey: .payload)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: container,
                debugDescription: "Invalid rendezvous frame"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidRendezvousEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid rendezvous frame"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(sessionId, forKey: .sessionId)
        try container.encode(purpose, forKey: .purpose)
        try container.encode(senderRole, forKey: .senderRole)
        try container.encode(sequence, forKey: .sequence)
        try container.encode(messageKind, forKey: .messageKind)
        try container.encode(payload, forKey: .payload)
    }
}

/// A live, non-Codable session. Persist the pending offer and redemption ledger,
/// not this key-bearing convenience object. Directional keys prevent reflection,
/// while exact receive sequencing fails closed on duplicates, gaps, and replays.
public struct RendezvousSessionV2 {
    public let sessionId: RendezvousSessionIDV2
    public let purpose: RendezvousPurposeV2
    public let localRole: RendezvousRoleV2
    public let transcriptDigest: Data
    public let openedAt: Date
    public let expiresAt: Date
    public let limits: RendezvousLimitsV2
    public private(set) var nextOutboundSequence: UInt64
    public private(set) var nextInboundSequence: UInt64

    private let sendKey: SymmetricKey
    private let receiveKey: SymmetricKey

    private init(
        sessionId: RendezvousSessionIDV2,
        purpose: RendezvousPurposeV2,
        localRole: RendezvousRoleV2,
        transcriptDigest: Data,
        openedAt: Date,
        expiresAt: Date,
        limits: RendezvousLimitsV2,
        sendKey: SymmetricKey,
        receiveKey: SymmetricKey
    ) {
        self.sessionId = sessionId
        self.purpose = purpose
        self.localRole = localRole
        self.transcriptDigest = transcriptDigest
        self.openedAt = openedAt
        self.expiresAt = expiresAt
        self.limits = limits
        self.sendKey = sendKey
        self.receiveKey = receiveKey
        nextOutboundSequence = 1
        nextInboundSequence = 1
    }

    fileprivate static func make(
        role: RendezvousRoleV2,
        sharedSecret: Data,
        offer: RendezvousOfferV2,
        request: RendezvousOpenV2
    ) -> RendezvousSessionV2 {
        let transcript = RendezvousCanonicalV2.sessionTranscript(offer: offer, request: request)
        let transcriptDigest = Data(SHA256.hash(data: transcript))
        var rootKeyData = CryptoBox.deriveChainKey(
            sharedSecret: sharedSecret,
            salt: offer.oneTimeTokenDigest,
            info: RendezvousCanonicalV2.domainSeparated(
                "Noctweave/rendezvous-v2/session-root",
                transcriptDigest
            )
        )
        var offererToResponder = CryptoBox.deriveChainKey(
            sharedSecret: rootKeyData,
            salt: transcriptDigest,
            info: Data("Noctweave/rendezvous-v2/offerer-to-responder".utf8)
        )
        var responderToOfferer = CryptoBox.deriveChainKey(
            sharedSecret: rootKeyData,
            salt: transcriptDigest,
            info: Data("Noctweave/rendezvous-v2/responder-to-offerer".utf8)
        )
        defer {
            rootKeyData.secureWipe()
            offererToResponder.secureWipe()
            responderToOfferer.secureWipe()
        }
        let sessionId = RendezvousSessionIDV2(
            rawValue: Data(SHA256.hash(data: RendezvousCanonicalV2.domainSeparated(
                "Noctweave/rendezvous-v2/session-id",
                transcriptDigest
            )))
        )
        let sendMaterial = role == .offerer ? offererToResponder : responderToOfferer
        let receiveMaterial = role == .offerer ? responderToOfferer : offererToResponder
        return RendezvousSessionV2(
            sessionId: sessionId,
            purpose: offer.purpose,
            localRole: role,
            transcriptDigest: transcriptDigest,
            openedAt: request.openedAt,
            expiresAt: offer.expiresAt,
            limits: offer.limits,
            sendKey: SymmetricKey(data: sendMaterial),
            receiveKey: SymmetricKey(data: receiveMaterial)
        )
    }

    public mutating func seal(
        _ plaintext: Data,
        kind: RendezvousMessageKindV2,
        at date: Date = Date()
    ) throws -> RendezvousFrameV2 {
        try validateActive(at: date)
        guard kind.isAllowed(for: purpose) else {
            throw RendezvousV2Error.unsupportedMessageKind
        }
        guard nextOutboundSequence <= UInt64(limits.maximumFrames) else {
            throw RendezvousV2Error.frameLimitExceeded
        }
        guard plaintext.count <= Int(limits.maximumFramePlaintextBytes) else {
            throw RendezvousV2Error.payloadTooLarge
        }
        guard let padded = RendezvousCanonicalV2.pad(plaintext) else {
            throw RendezvousV2Error.payloadTooLarge
        }
        let sequence = nextOutboundSequence
        let authenticatedData = RendezvousCanonicalV2.frameAuthenticatedData(
            sessionId: sessionId,
            transcriptDigest: transcriptDigest,
            purpose: purpose,
            senderRole: localRole,
            sequence: sequence,
            messageKind: kind
        )
        let payload = try CryptoBox.encrypt(
            padded,
            key: sendKey,
            authenticatedData: authenticatedData
        )
        nextOutboundSequence += 1
        return RendezvousFrameV2(
            sessionId: sessionId,
            purpose: purpose,
            senderRole: localRole,
            sequence: sequence,
            messageKind: kind,
            payload: payload
        )
    }

    public mutating func open(
        _ frame: RendezvousFrameV2,
        at date: Date = Date()
    ) throws -> Data {
        try validateActive(at: date)
        guard frame.isStructurallyValid else {
            throw RendezvousV2Error.invalidFrame
        }
        guard frame.sessionId == sessionId else {
            throw RendezvousV2Error.wrongSession
        }
        guard frame.purpose == purpose else {
            throw RendezvousV2Error.wrongPurpose
        }
        guard frame.senderRole == localRole.opposite else {
            throw RendezvousV2Error.wrongSenderRole
        }
        guard frame.sequence == nextInboundSequence else {
            throw RendezvousV2Error.unexpectedSequence(
                expected: nextInboundSequence,
                actual: frame.sequence
            )
        }
        guard frame.sequence <= UInt64(limits.maximumFrames) else {
            throw RendezvousV2Error.frameLimitExceeded
        }
        guard frame.messageKind.isAllowed(for: purpose) else {
            throw RendezvousV2Error.unsupportedMessageKind
        }
        let authenticatedData = RendezvousCanonicalV2.frameAuthenticatedData(
            sessionId: sessionId,
            transcriptDigest: transcriptDigest,
            purpose: purpose,
            senderRole: frame.senderRole,
            sequence: frame.sequence,
            messageKind: frame.messageKind
        )
        let padded: Data
        do {
            padded = try CryptoBox.decrypt(
                frame.payload,
                key: receiveKey,
                authenticatedData: authenticatedData
            )
        } catch {
            throw RendezvousV2Error.decryptionFailed
        }
        guard padded.count == frame.payload.ciphertext.count,
              let plaintext = RendezvousCanonicalV2.unpad(
                padded,
                maximumPlaintextBytes: limits.maximumFramePlaintextBytes
              ),
              RendezvousCanonicalV2.paddingBucket(forPlaintextBytes: plaintext.count) == padded.count else {
            throw RendezvousV2Error.invalidFrame
        }
        nextInboundSequence += 1
        return plaintext
    }

    private func validateActive(at date: Date) throws {
        guard purpose == .contactPairing else {
            throw RendezvousV2Error.wrongPurpose
        }
        guard date.timeIntervalSince1970.isFinite,
              date >= openedAt,
              date < expiresAt else {
            throw RendezvousV2Error.expired
        }
    }
}

private enum RendezvousCanonicalV2 {
    static func isCanonicalTimestamp(_ date: Date) -> Bool {
        let seconds = date.timeIntervalSince1970
        return seconds.isFinite && seconds >= 0 && floor(seconds) == seconds
    }

    static func validateOfferUse(
        _ offer: RendezvousOfferV2,
        expectedPurpose: RendezvousPurposeV2,
        at date: Date
    ) throws {
        guard offer.isStructurallyValid else {
            throw RendezvousV2Error.invalidOffer
        }
        guard offer.purpose == expectedPurpose else {
            throw RendezvousV2Error.wrongPurpose
        }
        guard date.timeIntervalSince1970.isFinite,
              date >= offer.createdAt,
              date < offer.expiresAt else {
            throw RendezvousV2Error.expired
        }
    }

    static func offerTranscript(_ offer: RendezvousOfferV2) -> Data {
        var data = Data()
        append("Noctweave/rendezvous-v2/public-offer", to: &data)
        append(UInt16(offer.version), to: &data)
        append(offer.purpose.rawValue, to: &data)
        append(offer.transportCapability.opaqueValue, to: &data)
        append(timestamp: offer.transportCapability.expiresAt, to: &data)
        append(offer.oneTimeTokenDigest, to: &data)
        append(offer.ephemeralAgreementPublicKey, to: &data)
        append(timestamp: offer.createdAt, to: &data)
        append(timestamp: offer.expiresAt, to: &data)
        append(offer.limits.maximumFrames, to: &data)
        append(offer.limits.maximumFramePlaintextBytes, to: &data)
        return data
    }

    static func openProofMaterial(_ request: RendezvousOpenV2) -> Data {
        var data = Data()
        append("Noctweave/rendezvous-v2/open-proof", to: &data)
        append(UInt16(request.version), to: &data)
        append(request.purpose.rawValue, to: &data)
        append(request.offerDigest, to: &data)
        append(request.kemCiphertext, to: &data)
        append(timestamp: request.openedAt, to: &data)
        return data
    }

    static func openTranscript(_ request: RendezvousOpenV2) -> Data {
        var data = openProofMaterial(request)
        append(request.tokenProof, to: &data)
        return data
    }

    static func sessionTranscript(
        offer: RendezvousOfferV2,
        request: RendezvousOpenV2
    ) -> Data {
        var data = Data()
        append("Noctweave/rendezvous-v2/session-transcript", to: &data)
        append(offer.transcriptDigest, to: &data)
        append(request.transcriptDigest, to: &data)
        return data
    }

    static func frameAuthenticatedData(
        sessionId: RendezvousSessionIDV2,
        transcriptDigest: Data,
        purpose: RendezvousPurposeV2,
        senderRole: RendezvousRoleV2,
        sequence: UInt64,
        messageKind: RendezvousMessageKindV2
    ) -> Data {
        var data = Data()
        append("Noctweave/rendezvous-v2/frame", to: &data)
        append(UInt16(NoctweaveRendezvousV2.version), to: &data)
        append(sessionId.rawValue, to: &data)
        append(transcriptDigest, to: &data)
        append(purpose.rawValue, to: &data)
        append(senderRole.rawValue, to: &data)
        append(sequence, to: &data)
        append(messageKind.rawValue, to: &data)
        return data
    }

    static func domainSeparated(_ domain: String, _ payload: Data) -> Data {
        var data = Data()
        append(domain, to: &data)
        append(payload, to: &data)
        return data
    }

    static func pad(_ plaintext: Data) -> Data? {
        guard let bucket = paddingBucket(forPlaintextBytes: plaintext.count) else {
            return nil
        }
        var data = Data()
        append(UInt32(plaintext.count), to: &data)
        data.append(plaintext)
        data.append(Data(repeating: 0, count: bucket - data.count))
        return data
    }

    static func unpad(_ padded: Data, maximumPlaintextBytes: UInt32) -> Data? {
        guard padded.count >= 4 else { return nil }
        let length = padded.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length <= maximumPlaintextBytes else { return nil }
        let end = 4 + Int(length)
        guard end <= padded.count,
              padded[end...].allSatisfy({ $0 == 0 }) else {
            return nil
        }
        return Data(padded[4..<end])
    }

    static func paddingBucket(forPlaintextBytes count: Int) -> Int? {
        guard count >= 0 else { return nil }
        return NoctweaveRendezvousV2.paddingBuckets.first { count + 4 <= $0 }
    }

    static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        var difference = lhs.count ^ rhs.count
        for index in 0..<max(lhs.count, rhs.count) {
            let left = index < lhs.count ? lhs[index] : 0
            let right = index < rhs.count ? rhs[index] : 0
            difference |= Int(left ^ right)
        }
        return difference == 0
    }

    private static func append(_ value: String, to data: inout Data) {
        append(Data(value.utf8), to: &data)
    }

    private static func append(_ value: Data, to data: inout Data) {
        precondition(value.count <= Int(UInt32.max))
        append(UInt32(value.count), to: &data)
        data.append(value)
    }

    private static func append(timestamp: Date, to data: inout Data) {
        append(UInt64(timestamp.timeIntervalSince1970), to: &data)
    }

    private static func append(_ value: UInt16, to data: inout Data) {
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    private static func append(_ value: UInt32, to data: inout Data) {
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    private static func append(_ value: UInt64, to data: inout Data) {
        data.append(UInt8((value >> 56) & 0xff))
        data.append(UInt8((value >> 48) & 0xff))
        data.append(UInt8((value >> 40) & 0xff))
        data.append(UInt8((value >> 32) & 0xff))
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }
}

private struct StrictRendezvousCodingKey: CodingKey, Hashable {
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

private func strictRendezvousContainer<Key>(
    _ decoder: Decoder,
    keyedBy keyType: Key.Type,
    description: String
) throws -> KeyedDecodingContainer<Key>
where Key: CodingKey & CaseIterable, Key.AllCases.Element == Key {
    let strict = try decoder.container(keyedBy: StrictRendezvousCodingKey.self)
    let actual = Set(strict.allKeys.map(\.stringValue))
    let expected = Set(Key.allCases.map(\.stringValue))
    guard actual == expected else {
        throw DecodingError.dataCorrupted(
            DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: "\(description) fields must match the current protocol exactly"
            )
        )
    }
    return try decoder.container(keyedBy: keyType)
}

private func requireValidRendezvousEncoding<Value>(
    _ isValid: Bool,
    value: Value,
    encoder: Encoder,
    description: String
) throws {
    guard isValid else {
        throw EncodingError.invalidValue(
            value,
            EncodingError.Context(
                codingPath: encoder.codingPath,
                debugDescription: description
            )
        )
    }
}
