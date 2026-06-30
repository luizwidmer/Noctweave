import Foundation

public struct IdentityReset: Codable, Equatable {
    public let newOffer: ContactOffer
    public let signature: Data

    public static func create(newOffer: ContactOffer, signingKey: SigningKeyPair) throws -> IdentityReset {
        let payload = IdentityResetPayload(newOffer: newOffer)
        let data = try NoctweaveCoder.encode(payload, sortedKeys: true)
        let signature = try signingKey.sign(data)
        return IdentityReset(newOffer: newOffer, signature: signature)
    }

    public func verify(using publicSigningKey: Data) -> Bool {
        guard (try? newOffer.verified()) != nil else {
            return false
        }
        let payload = IdentityResetPayload(newOffer: newOffer)
        guard let data = try? NoctweaveCoder.encode(payload, sortedKeys: true) else {
            return false
        }
        return SigningKeyPair.verify(signature: signature, data: data, publicKeyData: publicSigningKey)
    }
}

private struct IdentityResetPayload: Codable {
    let newOffer: ContactOffer
}
