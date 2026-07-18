import CryptoKit
import Foundation

public enum RelationshipSafetyNumberV2Error: Error, Equatable {
    case invalidAuthorityKey
}

/// Human-verifiable digest of the two disposable authorities used by one
/// pairwise relationship. It is symmetric, relationship-local, and carries no
/// persona, account, device, installation, inbox, or provider identifier.
public enum RelationshipSafetyNumberV2 {
    public static func make(
        localAuthoritySigningPublicKey: Data,
        peerAuthoritySigningPublicKey: Data
    ) throws -> String {
        guard SigningKeyPair.isValidPublicKey(localAuthoritySigningPublicKey),
              SigningKeyPair.isValidPublicKey(peerAuthoritySigningPublicKey) else {
            throw RelationshipSafetyNumberV2Error.invalidAuthorityKey
        }
        let keys = [
            localAuthoritySigningPublicKey,
            peerAuthoritySigningPublicKey,
        ].sorted { $0.lexicographicallyPrecedes($1) }
        var transcript = Data("Noctweave/relationship-safety-number/v2".utf8)
        for key in keys {
            let length = UInt32(key.count)
            transcript.append(UInt8((length >> 24) & 0xFF))
            transcript.append(UInt8((length >> 16) & 0xFF))
            transcript.append(UInt8((length >> 8) & 0xFF))
            transcript.append(UInt8(length & 0xFF))
            transcript.append(key)
        }
        let digest = SHA256.hash(data: transcript)
        let hexadecimal = digest.prefix(24).map { String(format: "%02X", $0) }.joined()
        return stride(from: 0, to: hexadecimal.count, by: 4).map { offset in
            let start = hexadecimal.index(hexadecimal.startIndex, offsetBy: offset)
            let end = hexadecimal.index(start, offsetBy: min(4, hexadecimal.count - offset))
            return String(hexadecimal[start..<end])
        }.joined(separator: " ")
    }
}
