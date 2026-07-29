import Crypto
import Foundation

enum NoctweaveNetLimits {
    static let maximumPassthroughPayloadBytes = 512 * 1_024
    static let maximumHostObjectBytes = 1_024 * 1_024
    static let objectIDBytes = SHA256.byteCount
    static let capabilityDigestBytes = SHA256.byteCount
    static let releaseCapabilityBytes = 32
    static let idempotencyKeyBytes = 32
    static let minimumHostRetentionSeconds = 60
    static let maximumHostRetentionSeconds = 2_592_000
    static let maximumSiteLabelBytes = 48
    static let maximumPublisherIDBytes = 128
    static let maximumHeadIDBytes = 71
    static let maximumNameResolutionLifetime: TimeInterval = 5 * 60
}

func netCanonicalDate(_ value: Date) -> Date {
    Date(timeIntervalSince1970: floor(value.timeIntervalSince1970))
}

func netIsCanonicalDate(_ value: Date) -> Bool {
    let seconds = value.timeIntervalSince1970
    return seconds.isFinite
        && seconds >= 0
        && seconds <= 4_102_444_800
        && floor(seconds) == seconds
}

private func netHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

func netObjectIDIsValid(_ value: String) -> Bool {
    value.utf8.count == NoctweaveNetLimits.objectIDBytes * 2
        && value == value.lowercased()
        && value.unicodeScalars.allSatisfy {
            ("0"..."9").contains(Character($0)) || ("a"..."f").contains(Character($0))
        }
}

struct NoctweaveNetPassthroughRequest: Codable, Equatable {
    let destination: RelayEndpoint
    let payload: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case destination
        case payload
    }

    init(destination: RelayEndpoint, payload: Data) {
        self.destination = destination
        self.payload = payload
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Noctweave Net passthrough request")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            destination: try values.decode(RelayEndpoint.self, forKey: .destination),
            payload: try values.decode(Data.self, forKey: .payload)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .destination,
                in: values,
                debugDescription: "Noctweave Net passthrough request is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Noctweave Net passthrough request")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(destination, forKey: .destination)
        try values.encode(payload, forKey: .payload)
    }

    var isStructurallyValid: Bool {
        destination.isStructurallyValid
            && destination.transport == .http
            && !payload.isEmpty
            && payload.count <= NoctweaveNetLimits.maximumPassthroughPayloadBytes
    }
}

struct NoctweaveNetPassthroughResponse: Codable, Equatable {
    let payload: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case payload
    }

    init(payload: Data) {
        self.payload = payload
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Noctweave Net passthrough response")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(payload: try values.decode(Data.self, forKey: .payload))
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .payload,
                in: values,
                debugDescription: "Noctweave Net passthrough response is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Noctweave Net passthrough response")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(payload, forKey: .payload)
    }

    var isStructurallyValid: Bool {
        !payload.isEmpty
            && payload.count <= NoctweaveNetLimits.maximumPassthroughPayloadBytes
    }
}

struct NoctweaveNetHostPutRequest: Codable, Equatable {
    let objectID: String
    let payload: Data
    let ttlSeconds: Int?
    let releaseCapabilityDigest: Data
    let idempotencyKey: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case objectID
        case payload
        case ttlSeconds
        case releaseCapabilityDigest
        case idempotencyKey
    }

    init(
        objectID: String,
        payload: Data,
        ttlSeconds: Int? = nil,
        releaseCapabilityDigest: Data,
        idempotencyKey: Data
    ) {
        self.objectID = objectID
        self.payload = payload
        self.ttlSeconds = ttlSeconds
        self.releaseCapabilityDigest = releaseCapabilityDigest
        self.idempotencyKey = idempotencyKey
    }

    static func objectID(for payload: Data) -> String {
        netHex(Data(SHA256.hash(data: payload)))
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Noctweave Net host put request")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            objectID: try values.decode(String.self, forKey: .objectID),
            payload: try values.decode(Data.self, forKey: .payload),
            ttlSeconds: try values.decodeIfPresent(Int.self, forKey: .ttlSeconds),
            releaseCapabilityDigest: try values.decode(Data.self, forKey: .releaseCapabilityDigest),
            idempotencyKey: try values.decode(Data.self, forKey: .idempotencyKey)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .objectID,
                in: values,
                debugDescription: "Noctweave Net host put request is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Noctweave Net host put request")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(objectID, forKey: .objectID)
        try values.encode(payload, forKey: .payload)
        try values.encode(ttlSeconds, forKey: .ttlSeconds)
        try values.encode(releaseCapabilityDigest, forKey: .releaseCapabilityDigest)
        try values.encode(idempotencyKey, forKey: .idempotencyKey)
    }

    var isStructurallyValid: Bool {
        netObjectIDIsValid(objectID)
            && !payload.isEmpty
            && payload.count <= NoctweaveNetLimits.maximumHostObjectBytes
            && objectID == Self.objectID(for: payload)
            && (ttlSeconds.map {
                ClosedRange(
                    uncheckedBounds: (
                        NoctweaveNetLimits.minimumHostRetentionSeconds,
                        NoctweaveNetLimits.maximumHostRetentionSeconds
                    )
                ).contains($0)
            } ?? true)
            && releaseCapabilityDigest.count == NoctweaveNetLimits.capabilityDigestBytes
            && idempotencyKey.count == NoctweaveNetLimits.idempotencyKeyBytes
    }
}

struct NoctweaveNetHostObjectRequest: Codable, Equatable {
    let objectID: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case objectID
    }

    init(objectID: String) {
        self.objectID = objectID
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Noctweave Net host object request")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(objectID: try values.decode(String.self, forKey: .objectID))
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .objectID,
                in: values,
                debugDescription: "Noctweave Net object ID is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Noctweave Net host object request")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(objectID, forKey: .objectID)
    }

    var isStructurallyValid: Bool {
        netObjectIDIsValid(objectID)
    }
}

struct NoctweaveNetHostReleaseRequest: Codable, Equatable {
    let objectID: String
    let releaseCapability: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case objectID
        case releaseCapability
    }

    init(objectID: String, releaseCapability: Data) {
        self.objectID = objectID
        self.releaseCapability = releaseCapability
    }

    static func capabilityDigest(_ capability: Data) -> Data {
        var input = Data("org.noctweave.net/host-release/v1".utf8)
        input.append(0)
        input.append(capability)
        return Data(SHA256.hash(data: input))
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Noctweave Net host release request")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            objectID: try values.decode(String.self, forKey: .objectID),
            releaseCapability: try values.decode(Data.self, forKey: .releaseCapability)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .releaseCapability,
                in: values,
                debugDescription: "Noctweave Net host release request is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Noctweave Net host release request")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(objectID, forKey: .objectID)
        try values.encode(releaseCapability, forKey: .releaseCapability)
    }

    var isStructurallyValid: Bool {
        netObjectIDIsValid(objectID)
            && releaseCapability.count == NoctweaveNetLimits.releaseCapabilityBytes
    }
}

struct NoctweaveNetHostingReceipt: Codable, Equatable {
    static let signatureAlgorithm = "Ed25519"

    let objectID: String
    let byteCount: UInt64
    let storedAt: Date
    let expiresAt: Date
    let signingPublicKey: Data
    let signatureAlgorithm: String
    let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case objectID
        case byteCount
        case storedAt
        case expiresAt
        case signingPublicKey
        case signatureAlgorithm
        case signature
    }

    init(
        objectID: String,
        byteCount: UInt64,
        storedAt: Date,
        expiresAt: Date,
        signingPublicKey: Data,
        signatureAlgorithm: String = Self.signatureAlgorithm,
        signature: Data
    ) {
        self.objectID = objectID
        self.byteCount = byteCount
        self.storedAt = netCanonicalDate(storedAt)
        self.expiresAt = netCanonicalDate(expiresAt)
        self.signingPublicKey = signingPublicKey
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Noctweave Net hosting receipt")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let decodedStoredAt = try values.decode(Date.self, forKey: .storedAt)
        let decodedExpiresAt = try values.decode(Date.self, forKey: .expiresAt)
        self.init(
            objectID: try values.decode(String.self, forKey: .objectID),
            byteCount: try values.decode(UInt64.self, forKey: .byteCount),
            storedAt: decodedStoredAt,
            expiresAt: decodedExpiresAt,
            signingPublicKey: try values.decode(Data.self, forKey: .signingPublicKey),
            signatureAlgorithm: try values.decode(String.self, forKey: .signatureAlgorithm),
            signature: try values.decode(Data.self, forKey: .signature)
        )
        guard storedAt == decodedStoredAt,
              expiresAt == decodedExpiresAt,
              isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .signature,
                in: values,
                debugDescription: "Noctweave Net hosting receipt is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Noctweave Net hosting receipt")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(objectID, forKey: .objectID)
        try values.encode(byteCount, forKey: .byteCount)
        try values.encode(storedAt, forKey: .storedAt)
        try values.encode(expiresAt, forKey: .expiresAt)
        try values.encode(signingPublicKey, forKey: .signingPublicKey)
        try values.encode(signatureAlgorithm, forKey: .signatureAlgorithm)
        try values.encode(signature, forKey: .signature)
    }

    var isStructurallyValid: Bool {
        netObjectIDIsValid(objectID)
            && (1...UInt64(NoctweaveNetLimits.maximumHostObjectBytes)).contains(byteCount)
            && netIsCanonicalDate(storedAt)
            && netIsCanonicalDate(expiresAt)
            && expiresAt > storedAt
            && expiresAt.timeIntervalSince(storedAt)
                <= TimeInterval(NoctweaveNetLimits.maximumHostRetentionSeconds)
            && signingPublicKey.count == 32
            && signatureAlgorithm == Self.signatureAlgorithm
            && signature.count == 64
    }

    var isSignatureValid: Bool {
        guard isStructurallyValid,
              let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: signingPublicKey)
        else {
            return false
        }
        return publicKey.isValidSignature(signature, for: signingPayload)
    }

    var signingPayload: Data {
        var data = Data("org.noctweave.net/hosting-receipt/v1".utf8)
        data.append(0)
        data.append(Data(objectID.utf8))
        var bytes = byteCount.bigEndian
        withUnsafeBytes(of: &bytes) { data.append(contentsOf: $0) }
        var stored = UInt64(storedAt.timeIntervalSince1970).bigEndian
        withUnsafeBytes(of: &stored) { data.append(contentsOf: $0) }
        var expires = UInt64(expiresAt.timeIntervalSince1970).bigEndian
        withUnsafeBytes(of: &expires) { data.append(contentsOf: $0) }
        return data
    }
}

struct NoctweaveNetHostFetchResponse: Codable, Equatable {
    let receipt: NoctweaveNetHostingReceipt
    let payload: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case receipt
        case payload
    }

    init(receipt: NoctweaveNetHostingReceipt, payload: Data) {
        self.receipt = receipt
        self.payload = payload
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Noctweave Net host fetch response")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            receipt: try values.decode(NoctweaveNetHostingReceipt.self, forKey: .receipt),
            payload: try values.decode(Data.self, forKey: .payload)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .payload,
                in: values,
                debugDescription: "Noctweave Net host fetch response is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Noctweave Net host fetch response")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(receipt, forKey: .receipt)
        try values.encode(payload, forKey: .payload)
    }

    var isStructurallyValid: Bool {
        !payload.isEmpty
            && payload.count <= NoctweaveNetLimits.maximumHostObjectBytes
            && receipt.objectID == NoctweaveNetHostPutRequest.objectID(for: payload)
            && receipt.byteCount == UInt64(payload.count)
            && receipt.isSignatureValid
    }
}

struct NoctweaveNetHostPresence: Codable, Equatable {
    let objectID: String
    let present: Bool
    let expiresAt: Date?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case objectID
        case present
        case expiresAt
    }

    init(objectID: String, present: Bool, expiresAt: Date?) {
        self.objectID = objectID
        self.present = present
        self.expiresAt = expiresAt.map(netCanonicalDate)
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Noctweave Net host presence")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let decodedExpiresAt = try values.decodeIfPresent(Date.self, forKey: .expiresAt)
        self.init(
            objectID: try values.decode(String.self, forKey: .objectID),
            present: try values.decode(Bool.self, forKey: .present),
            expiresAt: decodedExpiresAt
        )
        guard expiresAt == decodedExpiresAt, isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .expiresAt,
                in: values,
                debugDescription: "Noctweave Net host presence is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Noctweave Net host presence")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(objectID, forKey: .objectID)
        try values.encode(present, forKey: .present)
        try values.encode(expiresAt, forKey: .expiresAt)
    }

    var isStructurallyValid: Bool {
        netObjectIDIsValid(objectID)
            && (present ? expiresAt.map(netIsCanonicalDate) == true : expiresAt == nil)
    }
}

struct NoctweaveNetHostReleaseReceipt: Codable, Equatable {
    let objectID: String
    let released: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case objectID
        case released
    }

    init(objectID: String, released: Bool) {
        self.objectID = objectID
        self.released = released
    }

    init(from decoder: Decoder) throws {
        try requireExactModelFields(decoder, CodingKeys.self, context: "Noctweave Net host release receipt")
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            objectID: try values.decode(String.self, forKey: .objectID),
            released: try values.decode(Bool.self, forKey: .released)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .objectID,
                in: values,
                debugDescription: "Noctweave Net host release receipt is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw invalidModelEncoding(self, encoder, context: "Noctweave Net host release receipt")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(objectID, forKey: .objectID)
        try values.encode(released, forKey: .released)
    }

    var isStructurallyValid: Bool {
        netObjectIDIsValid(objectID)
    }
}
