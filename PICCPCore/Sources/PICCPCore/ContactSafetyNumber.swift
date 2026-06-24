import CryptoKit
import Foundation

public enum ContactSafetyNumber {
    public static func make(
        localFingerprint: String,
        remoteFingerprint: String
    ) -> String {
        let fingerprints = [localFingerprint, remoteFingerprint].sorted()
        let transcript = [
            "noctyra-contact-safety-v1",
            fingerprints[0],
            fingerprints[1]
        ].joined(separator: "\n")
        let digest = SHA256.hash(data: Data(transcript.utf8))
        let hexadecimal = digest.prefix(24).map { String(format: "%02X", $0) }.joined()
        return stride(from: 0, to: hexadecimal.count, by: 4).map { offset in
            let start = hexadecimal.index(hexadecimal.startIndex, offsetBy: offset)
            let end = hexadecimal.index(start, offsetBy: min(4, hexadecimal.count - offset))
            return String(hexadecimal[start..<end])
        }.joined(separator: " ")
    }
}
