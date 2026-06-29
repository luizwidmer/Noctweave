import CryptoKit
import Foundation

public enum OnionTransportError: Error, Equatable {
    case emptyHopList
    case invalidHop
    case invalidPacket
    case invalidPayload
    case malformedLayer
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
}

public enum OnionTransportPolicyIssue: String, Codable, Equatable, CaseIterable {
    case notAdvertised
    case disabled
    case insufficientHops
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

        var nextLayer: OnionLayer?
        var nextHopId: String?

        for hop in hops.reversed() {
            let trimmedHopId = hop.hopId.trimmingCharacters(in: .whitespacesAndNewlines)
            let trimmedInstruction = hop.routingInstruction.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmedHopId.isEmpty,
                  !trimmedInstruction.isEmpty,
                  AgreementKeyPair.isValidPublicKey(hop.publicKeyData) else {
                throw OnionTransportError.invalidHop
            }

            let plaintext = OnionLayerPlaintext(
                hopId: trimmedHopId,
                routingInstruction: trimmedInstruction,
                delayBucketSeconds: hop.delayBucketSeconds.map { max(0, $0) },
                nextHopId: nextHopId,
                nextLayer: nextLayer,
                finalPayload: nextLayer == nil ? finalPayload : nil
            )
            let encodedPlaintext = try PICCPCoder.encode(plaintext, sortedKeys: true)
            let kem = try AgreementKeyPair.encapsulate(to: hop.publicKeyData)
            let key = SymmetricKey(data: deriveLayerKey(sharedSecret: kem.sharedSecret, hopId: trimmedHopId))
            let aad = try authenticatedData(hopId: trimmedHopId)
            let encryptedPayload = try CryptoBox.encrypt(encodedPlaintext, key: key, authenticatedData: aad)
            nextLayer = OnionLayer(hopId: trimmedHopId, kemCiphertext: kem.ciphertext, payload: encryptedPayload)
            nextHopId = trimmedHopId
        }

        guard let firstLayer = nextLayer, let entryHopId = nextHopId else {
            throw OnionTransportError.invalidPacket
        }
        return OnionPacket(version: currentVersion, entryHopId: entryHopId, layer: firstLayer)
    }

    public static func peel(layer: OnionLayer, using keyPair: AgreementKeyPair) throws -> OnionPeeledLayer {
        guard !layer.hopId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw OnionTransportError.malformedLayer
        }
        let sharedSecret = try keyPair.decapsulate(ciphertext: layer.kemCiphertext)
        let key = SymmetricKey(data: deriveLayerKey(sharedSecret: sharedSecret, hopId: layer.hopId))

        let aad = try authenticatedData(hopId: layer.hopId)
        guard let opened = try? CryptoBox.decrypt(layer.payload, key: key, authenticatedData: aad),
              let plaintext = try? PICCPCoder.decode(OnionLayerPlaintext.self, from: opened),
              plaintext.hopId == layer.hopId,
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
            salt: Data("NoctyraOnionTransport-v1".utf8),
            info: Data("hop:\(hopId)".utf8)
        )
    }

    private static func authenticatedData(hopId: String) throws -> Data {
        try PICCPCoder.encode(
            OnionAAD(version: currentVersion, hopId: hopId),
            sortedKeys: true
        )
    }
}
