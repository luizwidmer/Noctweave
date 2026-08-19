import CryptoKit
import Foundation

/// Experimental client-side protocol layered over `nw.pairing-lobby@1` and
/// `nw.realtime-route@1`. Relay-visible lobby bytes contain fresh session-only
/// public keys and random route authorities, never persona or relationship
/// identity material.
public enum PairingLobbyV1 {
    public static let version = 1
    public static let lifetimeSeconds = 120
    public static let maximumPairingLinkBytes = 96 * 1024
    public static let mlKEM768PublicKeyBytes = 1_184
    public static let mlKEM768CiphertextBytes = 1_088
    public static let mlDSA65PublicKeyBytes = 1_952
    public static let mlDSA65SignatureBytes = 3_309
    public static let nonceBytes = 12
    public static let tagBytes = 16
    public static let maximumSealedPayloadBytes = 192 * 1024

    static let announcementDomain = Data(
        "org.noctweave.pairing-lobby.announcement/v1\u{0}".utf8
    )
    static let announcementDigestDomain = Data(
        "org.noctweave.pairing-lobby.announcement-digest/v1\u{0}".utf8
    )
    static let requestDomain = Data(
        "org.noctweave.pairing-lobby.request/v1\u{0}".utf8
    )
    static let requestDigestDomain = Data(
        "org.noctweave.pairing-lobby.request-digest/v1\u{0}".utf8
    )
    static let responseDomain = Data(
        "org.noctweave.pairing-lobby.response/v1\u{0}".utf8
    )
    static let requestKDFDomain = Data(
        "org.noctweave.pairing-lobby.request-key/v1".utf8
    )
    static let responseKDFDomain = Data(
        "org.noctweave.pairing-lobby.response-key/v1".utf8
    )
    static let requestAADDomain = Data(
        "org.noctweave.pairing-lobby.request-aad/v1\u{0}".utf8
    )
    static let responseAADDomain = Data(
        "org.noctweave.pairing-lobby.response-aad/v1\u{0}".utf8
    )
    static let badgeDomain = Data(
        "org.noctweave.pairing-lobby.badge/v1\u{0}".utf8
    )
}

public enum PairingLobbyV1Error: Error, Equatable {
    case invalidAnnouncement
    case invalidRequest
    case invalidResponse
    case expired
    case replay
    case rejected
    case invalidState
}

private struct PairingLobbyCodingKey: CodingKey {
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

private func pairingLobbyRequireExactFields(
    _ decoder: Decoder,
    _ expected: Set<String>
) throws {
    let container = try decoder.container(keyedBy: PairingLobbyCodingKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == expected else {
        throw DecodingError.dataCorrupted(.init(
            codingPath: decoder.codingPath,
            debugDescription: "Pairing lobby fields are not current"
        ))
    }
}

private func pairingLobbyCanonicalDate(_ value: Date) -> Date {
    Date(timeIntervalSince1970: floor(value.timeIntervalSince1970))
}

private func pairingLobbyDateIsCanonical(_ value: Date) -> Bool {
    let seconds = value.timeIntervalSince1970
    return seconds.isFinite && seconds >= 0 && floor(seconds) == seconds
}

private func pairingLobbyDateSeconds(_ value: Date) -> UInt64 {
    UInt64(value.timeIntervalSince1970)
}

private func pairingLobbyUUIDBytes(_ value: UUID) -> Data {
    var uuid = value.uuid
    return withUnsafeBytes(of: &uuid) { Data($0) }
}

private func pairingLobbyAppendUInt16(_ value: UInt16, to data: inout Data) {
    var encoded = value.bigEndian
    withUnsafeBytes(of: &encoded) { data.append(contentsOf: $0) }
}

private func pairingLobbyAppendUInt32(_ value: UInt32, to data: inout Data) {
    var encoded = value.bigEndian
    withUnsafeBytes(of: &encoded) { data.append(contentsOf: $0) }
}

private func pairingLobbyAppendUInt64(_ value: UInt64, to data: inout Data) {
    var encoded = value.bigEndian
    withUnsafeBytes(of: &encoded) { data.append(contentsOf: $0) }
}

private func pairingLobbyAppendLengthPrefixed(_ value: Data, to data: inout Data) {
    pairingLobbyAppendUInt32(UInt32(value.count), to: &data)
    data.append(value)
}

private func pairingLobbyAppendString(_ value: String, to data: inout Data) {
    pairingLobbyAppendLengthPrefixed(Data(value.utf8), to: &data)
}

private func pairingLobbyKey(
    sharedSecret: Data,
    salt: Data,
    info: Data
) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: sharedSecret),
        salt: salt,
        info: info,
        outputByteCount: 32
    )
}

private func pairingLobbySeal(
    plaintext: Data,
    recipientPublicKey: Data,
    salt: Data,
    info: Data,
    authenticatedData: (Data) -> Data
) throws -> (kemCiphertext: Data, nonce: Data, ciphertext: Data, tag: Data) {
    var encapsulation = try AgreementKeyPair.encapsulate(to: recipientPublicKey)
    defer { encapsulation.sharedSecret.secureWipe() }
    let key = pairingLobbyKey(
        sharedSecret: encapsulation.sharedSecret,
        salt: salt,
        info: info
    )
    let box = try AES.GCM.seal(
        plaintext,
        using: key,
        authenticating: authenticatedData(encapsulation.ciphertext)
    )
    return (
        encapsulation.ciphertext,
        Data(box.nonce),
        box.ciphertext,
        box.tag
    )
}

private func pairingLobbyOpen(
    kemCiphertext: Data,
    nonce: Data,
    ciphertext: Data,
    tag: Data,
    recipientKey: AgreementKeyPair,
    salt: Data,
    info: Data,
    authenticatedData: Data
) throws -> Data {
    var sharedSecret = try recipientKey.decapsulate(ciphertext: kemCiphertext)
    defer { sharedSecret.secureWipe() }
    let key = pairingLobbyKey(sharedSecret: sharedSecret, salt: salt, info: info)
    let box = try AES.GCM.SealedBox(
        nonce: AES.GCM.Nonce(data: nonce),
        ciphertext: ciphertext,
        tag: tag
    )
    return try AES.GCM.open(box, using: key, authenticating: authenticatedData)
}

public struct PairingLobbyBadgeV1: Equatable, Hashable, Sendable {
    public let words: String
    public let comparisonCode: String

    public var displayText: String { "\(words) · \(comparisonCode)" }

    public static func make(signingPublicKey: Data) -> PairingLobbyBadgeV1 {
        let digest = Data(SHA256.hash(
            data: PairingLobbyV1.badgeDomain + signingPublicKey
        ))
        let words = [
            "Amber", "Birch", "Cedar", "Dawn", "Ember", "Fern", "Glacier", "Harbor",
            "Indigo", "Juniper", "Kestrel", "Lagoon", "Maple", "Nimbus", "Orchid", "Pine",
            "Quartz", "River", "Saffron", "Tide", "Umber", "Violet", "Willow", "Xenon",
            "Yarrow", "Zephyr", "Acorn", "Breeze", "Cobalt", "Drift", "Elm", "Flint",
        ]
        let first = words[Int(digest[0] & 31)]
        let second = words[Int(digest[1] & 31)]
        let number = (
            UInt32(digest[2]) << 24
                | UInt32(digest[3]) << 16
                | UInt32(digest[4]) << 8
                | UInt32(digest[5])
        ) % 1_000_000
        return PairingLobbyBadgeV1(
            words: "\(first) \(second)",
            comparisonCode: String(format: "%06d", number)
        )
    }
}

public struct PairingLobbyAnnouncementV1: Codable, Equatable {
    public let version: Int
    public let listingID: UUID
    public let requestRouteCapability: Data
    public let requestAppendCapability: Data
    public let agreementPublicKey: Data
    public let signingPublicKey: Data
    public let createdAt: Date
    public let expiresAt: Date
    public let signature: Data

    public init(
        version: Int = PairingLobbyV1.version,
        listingID: UUID,
        requestRouteCapability: Data,
        requestAppendCapability: Data,
        agreementPublicKey: Data,
        signingPublicKey: Data,
        createdAt: Date,
        expiresAt: Date,
        signature: Data
    ) {
        self.version = version
        self.listingID = listingID
        self.requestRouteCapability = requestRouteCapability
        self.requestAppendCapability = requestAppendCapability
        self.agreementPublicKey = agreementPublicKey
        self.signingPublicKey = signingPublicKey
        self.createdAt = pairingLobbyCanonicalDate(createdAt)
        self.expiresAt = pairingLobbyCanonicalDate(expiresAt)
        self.signature = signature
    }

    public var isStructurallyValid: Bool {
        version == PairingLobbyV1.version
            && OpaqueCapabilityV1.isValid(requestRouteCapability)
            && OpaqueCapabilityV1.isValid(requestAppendCapability)
            && requestRouteCapability != requestAppendCapability
            && agreementPublicKey.count == PairingLobbyV1.mlKEM768PublicKeyBytes
            && signingPublicKey.count == PairingLobbyV1.mlDSA65PublicKeyBytes
            && signature.count == PairingLobbyV1.mlDSA65SignatureBytes
            && pairingLobbyDateIsCanonical(createdAt)
            && pairingLobbyDateIsCanonical(expiresAt)
            && createdAt < expiresAt
            && expiresAt.timeIntervalSince(createdAt)
                <= TimeInterval(PairingLobbyRelayLimitsV1.maximumLeaseSeconds)
    }

    public var authenticatedTranscript: Data {
        var data = PairingLobbyV1.announcementDomain
        pairingLobbyAppendUInt16(UInt16(version), to: &data)
        data.append(pairingLobbyUUIDBytes(listingID))
        data.append(requestRouteCapability)
        data.append(requestAppendCapability)
        pairingLobbyAppendLengthPrefixed(agreementPublicKey, to: &data)
        pairingLobbyAppendLengthPrefixed(signingPublicKey, to: &data)
        pairingLobbyAppendUInt64(pairingLobbyDateSeconds(createdAt), to: &data)
        pairingLobbyAppendUInt64(pairingLobbyDateSeconds(expiresAt), to: &data)
        return data
    }

    public var digest: Data {
        Data(SHA256.hash(
            data: PairingLobbyV1.announcementDigestDomain
                + authenticatedTranscript
                + signature
        ))
    }

    public var badge: PairingLobbyBadgeV1 {
        PairingLobbyBadgeV1.make(signingPublicKey: signingPublicKey)
    }

    public func verify(at now: Date = Date()) throws {
        guard isStructurallyValid else {
            throw PairingLobbyV1Error.invalidAnnouncement
        }
        guard now >= createdAt.addingTimeInterval(-30), now < expiresAt else {
            throw PairingLobbyV1Error.expired
        }
        guard try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: authenticatedTranscript,
            publicKeyData: signingPublicKey
        ) else {
            throw PairingLobbyV1Error.invalidAnnouncement
        }
    }

    static func signed(
        listingID: UUID,
        requestRouteCapability: Data,
        requestAppendCapability: Data,
        agreementKey: AgreementKeyPair,
        signingKey: SigningKeyPair,
        createdAt: Date,
        expiresAt: Date
    ) throws -> PairingLobbyAnnouncementV1 {
        let unsigned = PairingLobbyAnnouncementV1(
            listingID: listingID,
            requestRouteCapability: requestRouteCapability,
            requestAppendCapability: requestAppendCapability,
            agreementPublicKey: agreementKey.publicKeyData,
            signingPublicKey: signingKey.publicKeyData,
            createdAt: createdAt,
            expiresAt: expiresAt,
            signature: Data(repeating: 0, count: PairingLobbyV1.mlDSA65SignatureBytes)
        )
        let signature = try signingKey.sign(unsigned.authenticatedTranscript)
        let result = PairingLobbyAnnouncementV1(
            listingID: listingID,
            requestRouteCapability: requestRouteCapability,
            requestAppendCapability: requestAppendCapability,
            agreementPublicKey: agreementKey.publicKeyData,
            signingPublicKey: signingKey.publicKeyData,
            createdAt: createdAt,
            expiresAt: expiresAt,
            signature: signature
        )
        try result.verify(at: result.createdAt)
        return result
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case listingID
        case requestRouteCapability
        case requestAppendCapability
        case agreementPublicKey
        case signingPublicKey
        case createdAt
        case expiresAt
        case signature
    }

    public init(from decoder: Decoder) throws {
        try pairingLobbyRequireExactFields(
            decoder,
            Set(CodingKeys.allCases.map(\.rawValue))
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            listingID: try values.decode(UUID.self, forKey: .listingID),
            requestRouteCapability: try values.decode(Data.self, forKey: .requestRouteCapability),
            requestAppendCapability: try values.decode(Data.self, forKey: .requestAppendCapability),
            agreementPublicKey: try values.decode(Data.self, forKey: .agreementPublicKey),
            signingPublicKey: try values.decode(Data.self, forKey: .signingPublicKey),
            createdAt: try values.decode(Date.self, forKey: .createdAt),
            expiresAt: try values.decode(Date.self, forKey: .expiresAt),
            signature: try values.decode(Data.self, forKey: .signature)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Pairing lobby announcement is invalid"
            ))
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(self, .init(
                codingPath: encoder.codingPath,
                debugDescription: "Pairing lobby announcement is invalid"
            ))
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(listingID, forKey: .listingID)
        try values.encode(requestRouteCapability, forKey: .requestRouteCapability)
        try values.encode(requestAppendCapability, forKey: .requestAppendCapability)
        try values.encode(agreementPublicKey, forKey: .agreementPublicKey)
        try values.encode(signingPublicKey, forKey: .signingPublicKey)
        try values.encode(createdAt, forKey: .createdAt)
        try values.encode(expiresAt, forKey: .expiresAt)
        try values.encode(signature, forKey: .signature)
    }
}

public struct PairingLobbyListingV1: Equatable, Identifiable {
    public var id: Data { announcement.digest }
    public let leaseID: Data
    public let announcement: PairingLobbyAnnouncementV1
    public let relayExpiresAt: Date

    public var expiresAt: Date { min(announcement.expiresAt, relayExpiresAt) }
    public var badge: PairingLobbyBadgeV1 { announcement.badge }

    public static func verified(
        _ lease: PairingLobbyLeaseV1,
        at now: Date = Date()
    ) throws -> PairingLobbyListingV1 {
        let announcement = try NoctweaveCoder.decode(
            PairingLobbyAnnouncementV1.self,
            from: lease.announcement
        )
        try announcement.verify(at: now)
        guard lease.isStructurallyValid, lease.expiresAt > now else {
            throw PairingLobbyV1Error.expired
        }
        return PairingLobbyListingV1(
            leaseID: lease.leaseID,
            announcement: announcement,
            relayExpiresAt: lease.expiresAt
        )
    }
}

public struct PairingLobbyJoinRequestV1: Codable, Equatable {
    public let version: Int
    public let requestID: UUID
    public let listingDigest: Data
    public let requesterAgreementPublicKey: Data
    public let requesterSigningPublicKey: Data
    public let responseRouteCapability: Data
    public let responseAppendCapability: Data
    public let createdAt: Date
    public let expiresAt: Date
    public let signature: Data

    public init(
        version: Int = PairingLobbyV1.version,
        requestID: UUID,
        listingDigest: Data,
        requesterAgreementPublicKey: Data,
        requesterSigningPublicKey: Data,
        responseRouteCapability: Data,
        responseAppendCapability: Data,
        createdAt: Date,
        expiresAt: Date,
        signature: Data
    ) {
        self.version = version
        self.requestID = requestID
        self.listingDigest = listingDigest
        self.requesterAgreementPublicKey = requesterAgreementPublicKey
        self.requesterSigningPublicKey = requesterSigningPublicKey
        self.responseRouteCapability = responseRouteCapability
        self.responseAppendCapability = responseAppendCapability
        self.createdAt = pairingLobbyCanonicalDate(createdAt)
        self.expiresAt = pairingLobbyCanonicalDate(expiresAt)
        self.signature = signature
    }

    public var isStructurallyValid: Bool {
        version == PairingLobbyV1.version
            && listingDigest.count == SHA256.byteCount
            && requesterAgreementPublicKey.count == PairingLobbyV1.mlKEM768PublicKeyBytes
            && requesterSigningPublicKey.count == PairingLobbyV1.mlDSA65PublicKeyBytes
            && OpaqueCapabilityV1.isValid(responseRouteCapability)
            && OpaqueCapabilityV1.isValid(responseAppendCapability)
            && responseRouteCapability != responseAppendCapability
            && pairingLobbyDateIsCanonical(createdAt)
            && pairingLobbyDateIsCanonical(expiresAt)
            && createdAt < expiresAt
            && expiresAt.timeIntervalSince(createdAt)
                <= TimeInterval(PairingLobbyRelayLimitsV1.maximumLeaseSeconds)
            && signature.count == PairingLobbyV1.mlDSA65SignatureBytes
    }

    public var authenticatedTranscript: Data {
        var data = PairingLobbyV1.requestDomain
        pairingLobbyAppendUInt16(UInt16(version), to: &data)
        data.append(pairingLobbyUUIDBytes(requestID))
        data.append(listingDigest)
        pairingLobbyAppendLengthPrefixed(requesterAgreementPublicKey, to: &data)
        pairingLobbyAppendLengthPrefixed(requesterSigningPublicKey, to: &data)
        data.append(responseRouteCapability)
        data.append(responseAppendCapability)
        pairingLobbyAppendUInt64(pairingLobbyDateSeconds(createdAt), to: &data)
        pairingLobbyAppendUInt64(pairingLobbyDateSeconds(expiresAt), to: &data)
        return data
    }

    public var digest: Data {
        Data(SHA256.hash(
            data: PairingLobbyV1.requestDigestDomain
                + authenticatedTranscript
                + signature
        ))
    }

    public var requesterBadge: PairingLobbyBadgeV1 {
        PairingLobbyBadgeV1.make(signingPublicKey: requesterSigningPublicKey)
    }

    public func verify(
        for announcement: PairingLobbyAnnouncementV1,
        at now: Date = Date()
    ) throws {
        guard isStructurallyValid,
              listingDigest == announcement.digest,
              createdAt >= announcement.createdAt.addingTimeInterval(-30),
              expiresAt <= announcement.expiresAt,
              now >= createdAt.addingTimeInterval(-30),
              now < expiresAt else {
            throw now >= expiresAt
                ? PairingLobbyV1Error.expired
                : PairingLobbyV1Error.invalidRequest
        }
        guard try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: authenticatedTranscript,
            publicKeyData: requesterSigningPublicKey
        ) else {
            throw PairingLobbyV1Error.invalidRequest
        }
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case requestID
        case listingDigest
        case requesterAgreementPublicKey
        case requesterSigningPublicKey
        case responseRouteCapability
        case responseAppendCapability
        case createdAt
        case expiresAt
        case signature
    }

    public init(from decoder: Decoder) throws {
        try pairingLobbyRequireExactFields(
            decoder,
            Set(CodingKeys.allCases.map(\.rawValue))
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            requestID: try values.decode(UUID.self, forKey: .requestID),
            listingDigest: try values.decode(Data.self, forKey: .listingDigest),
            requesterAgreementPublicKey: try values.decode(Data.self, forKey: .requesterAgreementPublicKey),
            requesterSigningPublicKey: try values.decode(Data.self, forKey: .requesterSigningPublicKey),
            responseRouteCapability: try values.decode(Data.self, forKey: .responseRouteCapability),
            responseAppendCapability: try values.decode(Data.self, forKey: .responseAppendCapability),
            createdAt: try values.decode(Date.self, forKey: .createdAt),
            expiresAt: try values.decode(Date.self, forKey: .expiresAt),
            signature: try values.decode(Data.self, forKey: .signature)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Pairing lobby request is invalid"
            ))
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(self, .init(
                codingPath: encoder.codingPath,
                debugDescription: "Pairing lobby request is invalid"
            ))
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(requestID, forKey: .requestID)
        try values.encode(listingDigest, forKey: .listingDigest)
        try values.encode(requesterAgreementPublicKey, forKey: .requesterAgreementPublicKey)
        try values.encode(requesterSigningPublicKey, forKey: .requesterSigningPublicKey)
        try values.encode(responseRouteCapability, forKey: .responseRouteCapability)
        try values.encode(responseAppendCapability, forKey: .responseAppendCapability)
        try values.encode(createdAt, forKey: .createdAt)
        try values.encode(expiresAt, forKey: .expiresAt)
        try values.encode(signature, forKey: .signature)
    }
}

public struct PairingLobbySealedRequestV1: Codable, Equatable {
    public let version: Int
    public let listingID: UUID
    public let requestID: UUID
    public let kemCiphertext: Data
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data

    public init(
        version: Int = PairingLobbyV1.version,
        listingID: UUID,
        requestID: UUID,
        kemCiphertext: Data,
        nonce: Data,
        ciphertext: Data,
        tag: Data
    ) {
        self.version = version
        self.listingID = listingID
        self.requestID = requestID
        self.kemCiphertext = kemCiphertext
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }

    public var isStructurallyValid: Bool {
        version == PairingLobbyV1.version
            && kemCiphertext.count == PairingLobbyV1.mlKEM768CiphertextBytes
            && nonce.count == PairingLobbyV1.nonceBytes
            && !ciphertext.isEmpty
            && ciphertext.count <= PairingLobbyV1.maximumSealedPayloadBytes
            && tag.count == PairingLobbyV1.tagBytes
    }

    public func authenticatedData(kemCiphertext: Data? = nil) -> Data {
        var data = PairingLobbyV1.requestAADDomain
        pairingLobbyAppendUInt16(UInt16(version), to: &data)
        data.append(pairingLobbyUUIDBytes(listingID))
        data.append(pairingLobbyUUIDBytes(requestID))
        pairingLobbyAppendLengthPrefixed(kemCiphertext ?? self.kemCiphertext, to: &data)
        return data
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version, listingID, requestID, kemCiphertext, nonce, ciphertext, tag
    }

    public init(from decoder: Decoder) throws {
        try pairingLobbyRequireExactFields(decoder, Set(CodingKeys.allCases.map(\.rawValue)))
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            listingID: try values.decode(UUID.self, forKey: .listingID),
            requestID: try values.decode(UUID.self, forKey: .requestID),
            kemCiphertext: try values.decode(Data.self, forKey: .kemCiphertext),
            nonce: try values.decode(Data.self, forKey: .nonce),
            ciphertext: try values.decode(Data.self, forKey: .ciphertext),
            tag: try values.decode(Data.self, forKey: .tag)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Sealed pairing lobby request is invalid"
            ))
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(self, .init(
                codingPath: encoder.codingPath,
                debugDescription: "Sealed pairing lobby request is invalid"
            ))
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(listingID, forKey: .listingID)
        try values.encode(requestID, forKey: .requestID)
        try values.encode(kemCiphertext, forKey: .kemCiphertext)
        try values.encode(nonce, forKey: .nonce)
        try values.encode(ciphertext, forKey: .ciphertext)
        try values.encode(tag, forKey: .tag)
    }
}

public enum PairingLobbyDecisionV1: String, Codable, Equatable {
    case accepted
    case rejected
}

public struct PairingLobbyDecisionResponseV1: Codable, Equatable {
    public let version: Int
    public let listingID: UUID
    public let requestID: UUID
    public let listingDigest: Data
    public let requestDigest: Data
    public let decision: PairingLobbyDecisionV1
    /// Empty for rejection; a one-use `NoctweavePairingLinkV1` when accepted.
    public let pairingLink: String
    public let respondedAt: Date
    public let expiresAt: Date
    public let signature: Data

    public init(
        version: Int = PairingLobbyV1.version,
        listingID: UUID,
        requestID: UUID,
        listingDigest: Data,
        requestDigest: Data,
        decision: PairingLobbyDecisionV1,
        pairingLink: String,
        respondedAt: Date,
        expiresAt: Date,
        signature: Data
    ) {
        self.version = version
        self.listingID = listingID
        self.requestID = requestID
        self.listingDigest = listingDigest
        self.requestDigest = requestDigest
        self.decision = decision
        self.pairingLink = pairingLink
        self.respondedAt = pairingLobbyCanonicalDate(respondedAt)
        self.expiresAt = pairingLobbyCanonicalDate(expiresAt)
        self.signature = signature
    }

    public var isStructurallyValid: Bool {
        let linkBytes = Data(pairingLink.utf8).count
        return version == PairingLobbyV1.version
            && listingDigest.count == SHA256.byteCount
            && requestDigest.count == SHA256.byteCount
            && ((decision == .accepted && linkBytes > 0)
                || (decision == .rejected && linkBytes == 0))
            && linkBytes <= PairingLobbyV1.maximumPairingLinkBytes
            && pairingLobbyDateIsCanonical(respondedAt)
            && pairingLobbyDateIsCanonical(expiresAt)
            && respondedAt < expiresAt
            && signature.count == PairingLobbyV1.mlDSA65SignatureBytes
    }

    public var authenticatedTranscript: Data {
        var data = PairingLobbyV1.responseDomain
        pairingLobbyAppendUInt16(UInt16(version), to: &data)
        data.append(pairingLobbyUUIDBytes(listingID))
        data.append(pairingLobbyUUIDBytes(requestID))
        data.append(listingDigest)
        data.append(requestDigest)
        data.append(decision == .accepted ? 1 : 0)
        pairingLobbyAppendString(pairingLink, to: &data)
        pairingLobbyAppendUInt64(pairingLobbyDateSeconds(respondedAt), to: &data)
        pairingLobbyAppendUInt64(pairingLobbyDateSeconds(expiresAt), to: &data)
        return data
    }

    public func verify(
        announcement: PairingLobbyAnnouncementV1,
        request: PairingLobbyJoinRequestV1,
        at now: Date = Date()
    ) throws {
        guard isStructurallyValid,
              listingID == announcement.listingID,
              requestID == request.requestID,
              listingDigest == announcement.digest,
              requestDigest == request.digest,
              respondedAt >= request.createdAt.addingTimeInterval(-30),
              expiresAt <= request.expiresAt,
              now >= respondedAt.addingTimeInterval(-30),
              now < expiresAt else {
            throw now >= expiresAt
                ? PairingLobbyV1Error.expired
                : PairingLobbyV1Error.invalidResponse
        }
        guard try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: authenticatedTranscript,
            publicKeyData: announcement.signingPublicKey
        ) else {
            throw PairingLobbyV1Error.invalidResponse
        }
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version, listingID, requestID, listingDigest, requestDigest
        case decision, pairingLink, respondedAt, expiresAt, signature
    }

    public init(from decoder: Decoder) throws {
        try pairingLobbyRequireExactFields(decoder, Set(CodingKeys.allCases.map(\.rawValue)))
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            listingID: try values.decode(UUID.self, forKey: .listingID),
            requestID: try values.decode(UUID.self, forKey: .requestID),
            listingDigest: try values.decode(Data.self, forKey: .listingDigest),
            requestDigest: try values.decode(Data.self, forKey: .requestDigest),
            decision: try values.decode(PairingLobbyDecisionV1.self, forKey: .decision),
            pairingLink: try values.decode(String.self, forKey: .pairingLink),
            respondedAt: try values.decode(Date.self, forKey: .respondedAt),
            expiresAt: try values.decode(Date.self, forKey: .expiresAt),
            signature: try values.decode(Data.self, forKey: .signature)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Pairing lobby decision response is invalid"
            ))
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(self, .init(
                codingPath: encoder.codingPath,
                debugDescription: "Pairing lobby decision response is invalid"
            ))
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(listingID, forKey: .listingID)
        try values.encode(requestID, forKey: .requestID)
        try values.encode(listingDigest, forKey: .listingDigest)
        try values.encode(requestDigest, forKey: .requestDigest)
        try values.encode(decision, forKey: .decision)
        try values.encode(pairingLink, forKey: .pairingLink)
        try values.encode(respondedAt, forKey: .respondedAt)
        try values.encode(expiresAt, forKey: .expiresAt)
        try values.encode(signature, forKey: .signature)
    }
}

public struct PairingLobbySealedResponseV1: Codable, Equatable {
    public let version: Int
    public let listingID: UUID
    public let requestID: UUID
    public let kemCiphertext: Data
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data

    public init(
        version: Int = PairingLobbyV1.version,
        listingID: UUID,
        requestID: UUID,
        kemCiphertext: Data,
        nonce: Data,
        ciphertext: Data,
        tag: Data
    ) {
        self.version = version
        self.listingID = listingID
        self.requestID = requestID
        self.kemCiphertext = kemCiphertext
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }

    public var isStructurallyValid: Bool {
        version == PairingLobbyV1.version
            && kemCiphertext.count == PairingLobbyV1.mlKEM768CiphertextBytes
            && nonce.count == PairingLobbyV1.nonceBytes
            && !ciphertext.isEmpty
            && ciphertext.count <= PairingLobbyV1.maximumSealedPayloadBytes
            && tag.count == PairingLobbyV1.tagBytes
    }

    public func authenticatedData(kemCiphertext: Data? = nil) -> Data {
        var data = PairingLobbyV1.responseAADDomain
        pairingLobbyAppendUInt16(UInt16(version), to: &data)
        data.append(pairingLobbyUUIDBytes(listingID))
        data.append(pairingLobbyUUIDBytes(requestID))
        pairingLobbyAppendLengthPrefixed(kemCiphertext ?? self.kemCiphertext, to: &data)
        return data
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version, listingID, requestID, kemCiphertext, nonce, ciphertext, tag
    }

    public init(from decoder: Decoder) throws {
        try pairingLobbyRequireExactFields(decoder, Set(CodingKeys.allCases.map(\.rawValue)))
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            listingID: try values.decode(UUID.self, forKey: .listingID),
            requestID: try values.decode(UUID.self, forKey: .requestID),
            kemCiphertext: try values.decode(Data.self, forKey: .kemCiphertext),
            nonce: try values.decode(Data.self, forKey: .nonce),
            ciphertext: try values.decode(Data.self, forKey: .ciphertext),
            tag: try values.decode(Data.self, forKey: .tag)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Sealed pairing lobby response is invalid"
            ))
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(self, .init(
                codingPath: encoder.codingPath,
                debugDescription: "Sealed pairing lobby response is invalid"
            ))
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(listingID, forKey: .listingID)
        try values.encode(requestID, forKey: .requestID)
        try values.encode(kemCiphertext, forKey: .kemCiphertext)
        try values.encode(nonce, forKey: .nonce)
        try values.encode(ciphertext, forKey: .ciphertext)
        try values.encode(tag, forKey: .tag)
    }
}

public struct PairingLobbyPendingRequestV1: Equatable, Identifiable {
    public var id: UUID { request.requestID }
    public let request: PairingLobbyJoinRequestV1
    public let requesterBadge: PairingLobbyBadgeV1
}

public struct PairingLobbyHostSessionV1 {
    public let announcement: PairingLobbyAnnouncementV1
    public let requestRouteCreateRequest: RealtimeRouteCreateRequestV1
    public let leaseAcquireRequest: PairingLobbyAcquireRequestV1
    public let leaseReleaseRequest: PairingLobbyReleaseRequestV1

    private let signingKey: SigningKeyPair
    private let agreementKey: AgreementKeyPair
    private let requestReadCapability: Data
    private var processedRequestIDs: Set<UUID>

    public var badge: PairingLobbyBadgeV1 { announcement.badge }

    public static func create(
        at now: Date = Date(),
        lifetimeSeconds: Int = PairingLobbyV1.lifetimeSeconds
    ) throws -> PairingLobbyHostSessionV1 {
        guard (PairingLobbyRelayLimitsV1.minimumLeaseSeconds
            ... PairingLobbyRelayLimitsV1.maximumLeaseSeconds).contains(lifetimeSeconds) else {
            throw PairingLobbyV1Error.invalidState
        }
        let createdAt = pairingLobbyCanonicalDate(now)
        let expiresAt = pairingLobbyCanonicalDate(
            createdAt.addingTimeInterval(TimeInterval(lifetimeSeconds))
        )
        let signingKey = try SigningKeyPair.generate()
        let agreementKey = try AgreementKeyPair.generate()
        let routeCapability = OpaqueCapabilityV1.generate()
        let appendCapability = OpaqueCapabilityV1.generate()
        let readCapability = OpaqueCapabilityV1.generate()
        let announcement = try PairingLobbyAnnouncementV1.signed(
            listingID: UUID(),
            requestRouteCapability: routeCapability,
            requestAppendCapability: appendCapability,
            agreementKey: agreementKey,
            signingKey: signingKey,
            createdAt: createdAt,
            expiresAt: expiresAt
        )
        let announcementData = try NoctweaveCoder.encode(announcement, sortedKeys: true)
        guard announcementData.count <= PairingLobbyRelayLimitsV1.maximumAnnouncementBytes else {
            throw PairingLobbyV1Error.invalidAnnouncement
        }
        let leaseCapability = OpaqueCapabilityV1.generate()
        let leaseID = Data(SHA256.hash(
            data: Data("org.noctweave.pairing-lobby.lease-id/v1".utf8)
                + leaseCapability
        )).prefix(PairingLobbyRelayLimitsV1.leaseIDBytes)
        return PairingLobbyHostSessionV1(
            announcement: announcement,
            requestRouteCreateRequest: RealtimeRouteCreateRequestV1(
                routeCapability: routeCapability,
                appendCapability: appendCapability,
                readCapability: readCapability,
                expiresAt: expiresAt
            ),
            leaseAcquireRequest: PairingLobbyAcquireRequestV1(
                leaseID: Data(leaseID),
                leaseCapability: leaseCapability,
                announcement: announcementData,
                ttlSeconds: lifetimeSeconds
            ),
            leaseReleaseRequest: PairingLobbyReleaseRequestV1(
                leaseID: Data(leaseID),
                leaseCapability: leaseCapability
            ),
            signingKey: signingKey,
            agreementKey: agreementKey,
            requestReadCapability: readCapability,
            processedRequestIDs: []
        )
    }

    private init(
        announcement: PairingLobbyAnnouncementV1,
        requestRouteCreateRequest: RealtimeRouteCreateRequestV1,
        leaseAcquireRequest: PairingLobbyAcquireRequestV1,
        leaseReleaseRequest: PairingLobbyReleaseRequestV1,
        signingKey: SigningKeyPair,
        agreementKey: AgreementKeyPair,
        requestReadCapability: Data,
        processedRequestIDs: Set<UUID>
    ) {
        self.announcement = announcement
        self.requestRouteCreateRequest = requestRouteCreateRequest
        self.leaseAcquireRequest = leaseAcquireRequest
        self.leaseReleaseRequest = leaseReleaseRequest
        self.signingKey = signingKey
        self.agreementKey = agreementKey
        self.requestReadCapability = requestReadCapability
        self.processedRequestIDs = processedRequestIDs
    }

    public func requestRouteSubscribeRequest(
        afterSequence: UInt64 = 0
    ) -> RealtimeRouteSubscribeRequestV1 {
        RealtimeRouteSubscribeRequestV1(
            routeCapability: announcement.requestRouteCapability,
            readCapability: requestReadCapability,
            afterSequence: afterSequence
        )
    }

    public mutating func openRequest(
        _ payload: Data,
        at now: Date = Date()
    ) throws -> PairingLobbyPendingRequestV1 {
        let outer: PairingLobbySealedRequestV1
        do {
            outer = try NoctweaveCoder.decode(PairingLobbySealedRequestV1.self, from: payload)
        } catch {
            throw PairingLobbyV1Error.invalidRequest
        }
        guard outer.listingID == announcement.listingID else {
            throw PairingLobbyV1Error.invalidRequest
        }
        guard !processedRequestIDs.contains(outer.requestID) else {
            throw PairingLobbyV1Error.replay
        }
        let plaintext: Data
        do {
            plaintext = try pairingLobbyOpen(
                kemCiphertext: outer.kemCiphertext,
                nonce: outer.nonce,
                ciphertext: outer.ciphertext,
                tag: outer.tag,
                recipientKey: agreementKey,
                salt: announcement.digest,
                info: PairingLobbyV1.requestKDFDomain,
                authenticatedData: outer.authenticatedData()
            )
        } catch let error as CryptoError {
            throw error
        } catch {
            throw PairingLobbyV1Error.invalidRequest
        }
        let request: PairingLobbyJoinRequestV1
        do {
            request = try NoctweaveCoder.decode(PairingLobbyJoinRequestV1.self, from: plaintext)
        } catch {
            throw PairingLobbyV1Error.invalidRequest
        }
        guard request.requestID == outer.requestID else {
            throw PairingLobbyV1Error.invalidRequest
        }
        try request.verify(for: announcement, at: now)
        processedRequestIDs.insert(request.requestID)
        return PairingLobbyPendingRequestV1(
            request: request,
            requesterBadge: request.requesterBadge
        )
    }

    public func decisionAppendRequest(
        for pending: PairingLobbyPendingRequestV1,
        decision: PairingLobbyDecisionV1,
        pairingLink: String = "",
        at now: Date = Date()
    ) throws -> RealtimeRouteAppendRequestV1 {
        guard pending.request.listingDigest == announcement.digest,
              now < pending.request.expiresAt else {
            throw PairingLobbyV1Error.expired
        }
        let respondedAt = pairingLobbyCanonicalDate(now)
        let unsigned = PairingLobbyDecisionResponseV1(
            listingID: announcement.listingID,
            requestID: pending.request.requestID,
            listingDigest: announcement.digest,
            requestDigest: pending.request.digest,
            decision: decision,
            pairingLink: decision == .accepted ? pairingLink : "",
            respondedAt: respondedAt,
            expiresAt: pending.request.expiresAt,
            signature: Data(repeating: 0, count: PairingLobbyV1.mlDSA65SignatureBytes)
        )
        guard unsigned.isStructurallyValid else {
            throw PairingLobbyV1Error.invalidResponse
        }
        let signature = try signingKey.sign(unsigned.authenticatedTranscript)
        let response = PairingLobbyDecisionResponseV1(
            listingID: unsigned.listingID,
            requestID: unsigned.requestID,
            listingDigest: unsigned.listingDigest,
            requestDigest: unsigned.requestDigest,
            decision: unsigned.decision,
            pairingLink: unsigned.pairingLink,
            respondedAt: unsigned.respondedAt,
            expiresAt: unsigned.expiresAt,
            signature: signature
        )
        let plaintext = try NoctweaveCoder.encode(response, sortedKeys: true)
        let sealed = try pairingLobbySeal(
            plaintext: plaintext,
            recipientPublicKey: pending.request.requesterAgreementPublicKey,
            salt: pending.request.digest,
            info: PairingLobbyV1.responseKDFDomain,
            authenticatedData: { kemCiphertext in
                PairingLobbySealedResponseV1(
                    listingID: self.announcement.listingID,
                    requestID: pending.request.requestID,
                    kemCiphertext: kemCiphertext,
                    nonce: Data(repeating: 0, count: PairingLobbyV1.nonceBytes),
                    ciphertext: Data([0]),
                    tag: Data(repeating: 0, count: PairingLobbyV1.tagBytes)
                ).authenticatedData(kemCiphertext: kemCiphertext)
            }
        )
        let outer = PairingLobbySealedResponseV1(
            listingID: announcement.listingID,
            requestID: pending.request.requestID,
            kemCiphertext: sealed.kemCiphertext,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )
        let payload = try NoctweaveCoder.encode(outer, sortedKeys: true)
        guard payload.count <= RealtimeRelayLimitsV1.maximumRecordBytes else {
            throw PairingLobbyV1Error.invalidResponse
        }
        return RealtimeRouteAppendRequestV1(
            routeCapability: pending.request.responseRouteCapability,
            appendCapability: pending.request.responseAppendCapability,
            recordID: pending.request.requestID,
            payload: payload
        )
    }
}

public struct PairingLobbyRequesterSessionV1 {
    public let announcement: PairingLobbyAnnouncementV1
    public let request: PairingLobbyJoinRequestV1
    public let responseRouteCreateRequest: RealtimeRouteCreateRequestV1
    public let requestAppendRequest: RealtimeRouteAppendRequestV1

    private let agreementKey: AgreementKeyPair
    private let responseReadCapability: Data
    private var consumed = false

    public var requesterBadge: PairingLobbyBadgeV1 { request.requesterBadge }
    public var hostBadge: PairingLobbyBadgeV1 { announcement.badge }

    public static func create(
        for listing: PairingLobbyListingV1,
        at now: Date = Date()
    ) throws -> PairingLobbyRequesterSessionV1 {
        try listing.announcement.verify(at: now)
        guard listing.expiresAt > now else { throw PairingLobbyV1Error.expired }
        let createdAt = pairingLobbyCanonicalDate(now)
        let expiresAt = min(
            listing.expiresAt,
            pairingLobbyCanonicalDate(
                createdAt.addingTimeInterval(TimeInterval(PairingLobbyV1.lifetimeSeconds))
            )
        )
        guard createdAt < expiresAt else { throw PairingLobbyV1Error.expired }
        let signingKey = try SigningKeyPair.generate()
        let agreementKey = try AgreementKeyPair.generate()
        let responseRouteCapability = OpaqueCapabilityV1.generate()
        let responseAppendCapability = OpaqueCapabilityV1.generate()
        let responseReadCapability = OpaqueCapabilityV1.generate()
        let requestID = UUID()
        let unsigned = PairingLobbyJoinRequestV1(
            requestID: requestID,
            listingDigest: listing.announcement.digest,
            requesterAgreementPublicKey: agreementKey.publicKeyData,
            requesterSigningPublicKey: signingKey.publicKeyData,
            responseRouteCapability: responseRouteCapability,
            responseAppendCapability: responseAppendCapability,
            createdAt: createdAt,
            expiresAt: expiresAt,
            signature: Data(repeating: 0, count: PairingLobbyV1.mlDSA65SignatureBytes)
        )
        let signature = try signingKey.sign(unsigned.authenticatedTranscript)
        let request = PairingLobbyJoinRequestV1(
            requestID: unsigned.requestID,
            listingDigest: unsigned.listingDigest,
            requesterAgreementPublicKey: unsigned.requesterAgreementPublicKey,
            requesterSigningPublicKey: unsigned.requesterSigningPublicKey,
            responseRouteCapability: unsigned.responseRouteCapability,
            responseAppendCapability: unsigned.responseAppendCapability,
            createdAt: unsigned.createdAt,
            expiresAt: unsigned.expiresAt,
            signature: signature
        )
        try request.verify(for: listing.announcement, at: createdAt)
        let plaintext = try NoctweaveCoder.encode(request, sortedKeys: true)
        let sealed = try pairingLobbySeal(
            plaintext: plaintext,
            recipientPublicKey: listing.announcement.agreementPublicKey,
            salt: listing.announcement.digest,
            info: PairingLobbyV1.requestKDFDomain,
            authenticatedData: { kemCiphertext in
                PairingLobbySealedRequestV1(
                    listingID: listing.announcement.listingID,
                    requestID: requestID,
                    kemCiphertext: kemCiphertext,
                    nonce: Data(repeating: 0, count: PairingLobbyV1.nonceBytes),
                    ciphertext: Data([0]),
                    tag: Data(repeating: 0, count: PairingLobbyV1.tagBytes)
                ).authenticatedData(kemCiphertext: kemCiphertext)
            }
        )
        let outer = PairingLobbySealedRequestV1(
            listingID: listing.announcement.listingID,
            requestID: requestID,
            kemCiphertext: sealed.kemCiphertext,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )
        let payload = try NoctweaveCoder.encode(outer, sortedKeys: true)
        guard payload.count <= RealtimeRelayLimitsV1.maximumRecordBytes else {
            throw PairingLobbyV1Error.invalidRequest
        }
        return PairingLobbyRequesterSessionV1(
            announcement: listing.announcement,
            request: request,
            responseRouteCreateRequest: RealtimeRouteCreateRequestV1(
                routeCapability: responseRouteCapability,
                appendCapability: responseAppendCapability,
                readCapability: responseReadCapability,
                expiresAt: expiresAt
            ),
            requestAppendRequest: RealtimeRouteAppendRequestV1(
                routeCapability: listing.announcement.requestRouteCapability,
                appendCapability: listing.announcement.requestAppendCapability,
                recordID: requestID,
                payload: payload
            ),
            agreementKey: agreementKey,
            responseReadCapability: responseReadCapability
        )
    }

    private init(
        announcement: PairingLobbyAnnouncementV1,
        request: PairingLobbyJoinRequestV1,
        responseRouteCreateRequest: RealtimeRouteCreateRequestV1,
        requestAppendRequest: RealtimeRouteAppendRequestV1,
        agreementKey: AgreementKeyPair,
        responseReadCapability: Data
    ) {
        self.announcement = announcement
        self.request = request
        self.responseRouteCreateRequest = responseRouteCreateRequest
        self.requestAppendRequest = requestAppendRequest
        self.agreementKey = agreementKey
        self.responseReadCapability = responseReadCapability
    }

    public func responseRouteSubscribeRequest(
        afterSequence: UInt64 = 0
    ) -> RealtimeRouteSubscribeRequestV1 {
        RealtimeRouteSubscribeRequestV1(
            routeCapability: request.responseRouteCapability,
            readCapability: responseReadCapability,
            afterSequence: afterSequence
        )
    }

    public mutating func openResponse(
        _ payload: Data,
        at now: Date = Date()
    ) throws -> PairingLobbyDecisionResponseV1 {
        guard !consumed else { throw PairingLobbyV1Error.replay }
        let outer: PairingLobbySealedResponseV1
        do {
            outer = try NoctweaveCoder.decode(PairingLobbySealedResponseV1.self, from: payload)
        } catch {
            throw PairingLobbyV1Error.invalidResponse
        }
        guard outer.listingID == announcement.listingID,
              outer.requestID == request.requestID else {
            throw PairingLobbyV1Error.invalidResponse
        }
        let plaintext: Data
        do {
            plaintext = try pairingLobbyOpen(
                kemCiphertext: outer.kemCiphertext,
                nonce: outer.nonce,
                ciphertext: outer.ciphertext,
                tag: outer.tag,
                recipientKey: agreementKey,
                salt: request.digest,
                info: PairingLobbyV1.responseKDFDomain,
                authenticatedData: outer.authenticatedData()
            )
        } catch let error as CryptoError {
            throw error
        } catch {
            throw PairingLobbyV1Error.invalidResponse
        }
        let response: PairingLobbyDecisionResponseV1
        do {
            response = try NoctweaveCoder.decode(
                PairingLobbyDecisionResponseV1.self,
                from: plaintext
            )
        } catch {
            throw PairingLobbyV1Error.invalidResponse
        }
        try response.verify(announcement: announcement, request: request, at: now)
        consumed = true
        return response
    }
}
