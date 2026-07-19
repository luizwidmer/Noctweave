import CryptoKit
import Foundation

public enum OnionTransportError: Error, Equatable {
    case emptyHopList
    case invalidHop
    case invalidPacket
    case invalidPayload
    case malformedLayer
    case resourceLimitExceeded
}

public struct OnionTransportSupport: Codable, Equatable {
    public var enabled: Bool
    public var maxHops: Int
    public var requiresFixedSizePackets: Bool

    public init(enabled: Bool = true, maxHops: Int = 3, requiresFixedSizePackets: Bool = true) {
        self.enabled = enabled
        self.maxHops = min(max(1, maxHops), 8)
        self.requiresFixedSizePackets = requiresFixedSizePackets
    }

    public var isStructurallyValid: Bool {
        (1...8).contains(maxHops)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case enabled
        case maxHops
        case requiresFixedSizePackets
    }

    public init(from decoder: Decoder) throws {
        try onionSupportRequireExactObject(decoder, keys: CodingKeys.allCases.map(\.rawValue))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try container.decode(Bool.self, forKey: .enabled)
        maxHops = try container.decode(Int.self, forKey: .maxHops)
        requiresFixedSizePackets = try container.decode(Bool.self, forKey: .requiresFixedSizePackets)
        guard isStructurallyValid else {
            throw onionSupportDecodingError(decoder, "Onion transport support is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Onion transport support is invalid")
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(enabled, forKey: .enabled)
        try container.encode(maxHops, forKey: .maxHops)
        try container.encode(requiresFixedSizePackets, forKey: .requiresFixedSizePackets)
    }
}

private struct OnionSupportCodingKey: CodingKey {
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

private func onionSupportRequireExactObject(_ decoder: Decoder, keys: [String]) throws {
    let container = try decoder.container(keyedBy: OnionSupportCodingKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == Set(keys) else {
        throw onionSupportDecodingError(
            decoder,
            "Onion transport support fields must match the current protocol exactly"
        )
    }
}

private func onionSupportDecodingError(
    _ decoder: Decoder,
    _ description: String
) -> DecodingError {
    DecodingError.dataCorrupted(
        .init(codingPath: decoder.codingPath, debugDescription: description)
    )
}

public enum OnionTransportPolicyIssue: String, Codable, Equatable, CaseIterable {
    case notAdvertised
    case disabled
    case insufficientHops
    case excessiveHops
    case fixedSizePacketsNotRequired
}

public enum OnionTransportPolicyValidator {
    public static func issues(
        for support: OnionTransportSupport?,
        minimumHops: Int = 2
    ) -> [OnionTransportPolicyIssue] {
        guard let support else {
            return [.notAdvertised]
        }

        var issues: [OnionTransportPolicyIssue] = []
        if !support.enabled {
            issues.append(.disabled)
        }
        if support.maxHops < max(2, minimumHops) {
            issues.append(.insufficientHops)
        }
        if support.maxHops > OnionTransport.maximumHops {
            issues.append(.excessiveHops)
        }
        if !support.requiresFixedSizePackets {
            issues.append(.fixedSizePacketsNotRequired)
        }
        return issues
    }

    public static func isUsable(
        _ support: OnionTransportSupport?,
        minimumHops: Int = 2
    ) -> Bool {
        issues(for: support, minimumHops: minimumHops).isEmpty
    }
}

public struct OnionHopDescriptor: Codable, Equatable {
    public let hopId: String
    public let publicKeyData: Data
    public let routingInstruction: String
    public let delayBucketSeconds: Int?

    public init(
        hopId: String,
        publicKeyData: Data,
        routingInstruction: String,
        delayBucketSeconds: Int? = nil
    ) {
        self.hopId = hopId
        self.publicKeyData = publicKeyData
        self.routingInstruction = routingInstruction
        self.delayBucketSeconds = delayBucketSeconds
    }
}

public struct OnionPacket: Codable, Equatable {
    public let version: Int
    public let entryHopId: String
    public let layer: OnionLayer

    public init(version: Int = 1, entryHopId: String, layer: OnionLayer) {
        self.version = version
        self.entryHopId = entryHopId
        self.layer = layer
    }
}

public struct OnionLayer: Codable, Equatable {
    public let hopId: String
    public let kemCiphertext: Data
    public let payload: EncryptedPayload

    public init(hopId: String, kemCiphertext: Data, payload: EncryptedPayload) {
        self.hopId = hopId
        self.kemCiphertext = kemCiphertext
        self.payload = payload
    }
}

public struct OnionPeeledLayer: Equatable {
    public let hopId: String
    public let routingInstruction: String
    public let delayBucketSeconds: Int?
    public let nextHopId: String?
    public let nextLayer: OnionLayer?
    public let finalPayload: Data?
}

private struct OnionLayerPlaintext: Codable, Equatable {
    let hopId: String
    let routingInstruction: String
    let delayBucketSeconds: Int?
    let nextHopId: String?
    let nextLayer: OnionLayer?
    let finalPayload: Data?
}

private struct OnionAAD: Codable {
    let version: Int
    let hopId: String
}

public enum OnionTransport {
    public static let currentVersion = 1
    static let layerKeyDerivationSalt = Data("org.noctweave.onion-transport.layer-key/v1".utf8)
    public static let maximumHops = 8
    public static let maximumFinalPayloadBytes = 256 * 1024
    public static let maximumLayerBytes = 2 * 1024 * 1024
    public static let maximumHopIdBytes = 256
    public static let maximumRoutingInstructionBytes = 4 * 1024
    public static let maximumDelayBucketSeconds = 3_600

    public static func seal(
        finalPayload: Data,
        hops: [OnionHopDescriptor]
    ) throws -> OnionPacket {
        guard !hops.isEmpty else {
            throw OnionTransportError.emptyHopList
        }
        guard !finalPayload.isEmpty else {
            throw OnionTransportError.invalidPayload
        }
        guard hops.count <= maximumHops,
              finalPayload.count <= maximumFinalPayloadBytes else {
            throw OnionTransportError.resourceLimitExceeded
        }

        var nextLayer: OnionLayer?
        var nextHopId: String?
        var seenHopIds = Set<String>()

        for hop in hops.reversed() {
            let trimmedHopId = hop.hopId.trimmingCharacters(in: .whitespacesAndNewlines)
            let trimmedInstruction = hop.routingInstruction.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmedHopId.isEmpty,
                  !trimmedInstruction.isEmpty,
                  try AgreementKeyPair.isValidPublicKeyThrowing(hop.publicKeyData) else {
                throw OnionTransportError.invalidHop
            }
            guard trimmedHopId.utf8.count <= maximumHopIdBytes,
                  trimmedInstruction.utf8.count <= maximumRoutingInstructionBytes,
                  hop.delayBucketSeconds.map({ (0...maximumDelayBucketSeconds).contains($0) }) ?? true,
                  seenHopIds.insert(trimmedHopId.lowercased()).inserted else {
                throw OnionTransportError.resourceLimitExceeded
            }

            let plaintext = OnionLayerPlaintext(
                hopId: trimmedHopId,
                routingInstruction: trimmedInstruction,
                delayBucketSeconds: hop.delayBucketSeconds,
                nextHopId: nextHopId,
                nextLayer: nextLayer,
                finalPayload: nextLayer == nil ? finalPayload : nil
            )
            var encodedPlaintext = try NoctweaveCoder.encode(plaintext, sortedKeys: true)
            defer { encodedPlaintext.secureWipe() }
            guard encodedPlaintext.count <= maximumLayerBytes else {
                throw OnionTransportError.resourceLimitExceeded
            }
            var kem = try AgreementKeyPair.encapsulate(to: hop.publicKeyData)
            var derivedKey = deriveLayerKey(sharedSecret: kem.sharedSecret, hopId: trimmedHopId)
            kem.sharedSecret.secureWipe()
            let key = SymmetricKey(data: derivedKey)
            derivedKey.secureWipe()
            let aad = try authenticatedData(hopId: trimmedHopId)
            let encryptedPayload = try CryptoBox.encrypt(encodedPlaintext, key: key, authenticatedData: aad)
            guard encryptedPayload.nonce.count == 12,
                  encryptedPayload.tag.count == 16,
                  encryptedPayload.ciphertext.count <= maximumLayerBytes else {
                throw OnionTransportError.resourceLimitExceeded
            }
            nextLayer = OnionLayer(hopId: trimmedHopId, kemCiphertext: kem.ciphertext, payload: encryptedPayload)
            nextHopId = trimmedHopId
        }

        guard let firstLayer = nextLayer, let entryHopId = nextHopId else {
            throw OnionTransportError.invalidPacket
        }
        return OnionPacket(version: currentVersion, entryHopId: entryHopId, layer: firstLayer)
    }

    public static func peel(layer: OnionLayer, using keyPair: AgreementKeyPair) throws -> OnionPeeledLayer {
        let canonicalHopId = layer.hopId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !canonicalHopId.isEmpty,
              canonicalHopId == layer.hopId,
              canonicalHopId.utf8.count <= maximumHopIdBytes,
              layer.kemCiphertext.count == 1_088,
              layer.payload.nonce.count == 12,
              layer.payload.tag.count == 16,
              !layer.payload.ciphertext.isEmpty,
              layer.payload.ciphertext.count <= maximumLayerBytes else {
            throw OnionTransportError.malformedLayer
        }
        var sharedSecret = try keyPair.decapsulate(ciphertext: layer.kemCiphertext)
        var derivedKey = deriveLayerKey(sharedSecret: sharedSecret, hopId: layer.hopId)
        sharedSecret.secureWipe()
        let key = SymmetricKey(data: derivedKey)
        derivedKey.secureWipe()

        let aad = try authenticatedData(hopId: layer.hopId)
        guard var opened = try? CryptoBox.decrypt(layer.payload, key: key, authenticatedData: aad) else {
            throw OnionTransportError.malformedLayer
        }
        defer { opened.secureWipe() }
        guard opened.count <= maximumLayerBytes,
              let plaintext = try? NoctweaveCoder.decode(OnionLayerPlaintext.self, from: opened),
              plaintext.hopId == layer.hopId,
              plaintext.routingInstruction.utf8.count <= maximumRoutingInstructionBytes,
              plaintext.delayBucketSeconds.map({ (0...maximumDelayBucketSeconds).contains($0) }) ?? true,
              plaintext.nextHopId.map({ !$0.isEmpty && $0.utf8.count <= maximumHopIdBytes }) ?? true,
              plaintext.finalPayload.map({ !$0.isEmpty && $0.count <= maximumFinalPayloadBytes }) ?? true,
              plaintext.nextLayer.map(isStructurallyBoundedLayer) ?? true,
              (plaintext.nextLayer == nil) == (plaintext.finalPayload != nil) else {
            throw OnionTransportError.malformedLayer
        }
        return OnionPeeledLayer(
            hopId: plaintext.hopId,
            routingInstruction: plaintext.routingInstruction,
            delayBucketSeconds: plaintext.delayBucketSeconds,
            nextHopId: plaintext.nextHopId,
            nextLayer: plaintext.nextLayer,
            finalPayload: plaintext.finalPayload
        )
    }

    private static func deriveLayerKey(sharedSecret: Data, hopId: String) -> Data {
        CryptoBox.deriveChainKey(
            sharedSecret: sharedSecret,
            salt: layerKeyDerivationSalt,
            info: Data("hop:\(hopId)".utf8)
        )
    }

    private static func authenticatedData(hopId: String) throws -> Data {
        try NoctweaveCoder.encode(
            OnionAAD(version: currentVersion, hopId: hopId),
            sortedKeys: true
        )
    }

    private static func isStructurallyBoundedLayer(_ layer: OnionLayer) -> Bool {
        !layer.hopId.isEmpty
            && layer.hopId.utf8.count <= maximumHopIdBytes
            && layer.kemCiphertext.count == 1_088
            && layer.payload.nonce.count == 12
            && layer.payload.tag.count == 16
            && !layer.payload.ciphertext.isEmpty
            && layer.payload.ciphertext.count <= maximumLayerBytes
    }
}
