import CryptoKit
import Foundation
import Security

public enum ContactShareError: Error {
    case emptyPassword
    case unsupportedVersion
    case invalidKdfRounds
    case entropyUnavailable
}

public struct ContactSharePackage: Codable, Equatable {
    public let version: Int
    public let salt: Data
    public let kdfRounds: Int
    public let payload: EncryptedPayload

    public init(version: Int, salt: Data, kdfRounds: Int, payload: EncryptedPayload) {
        self.version = version
        self.salt = salt
        self.kdfRounds = kdfRounds
        self.payload = payload
    }
}

public enum ContactShare {
    public static let currentVersion = 2
    public static let defaultKdfRounds = 120_000
    public static let minimumKdfRounds = 60_000
    public static let maximumKdfRounds = 600_000
    private static let keyLength = 32

    public static func encode(_ offer: ContactOffer, password: String, kdfRounds: Int = defaultKdfRounds) throws -> Data {
        guard !password.isEmpty else {
            throw ContactShareError.emptyPassword
        }
        let salt = try randomSalt()
        let boundedRounds = boundedRounds(kdfRounds)
        let key = derivePBKDF2Key(password: password, salt: salt, rounds: boundedRounds)
        let offerData = try PICCPCoder.encode(offer)
        let payload = try CryptoBox.encrypt(
            offerData,
            key: key,
            authenticatedData: authenticatedData(for: currentVersion)
        )
        let package = ContactSharePackage(
            version: currentVersion,
            salt: salt,
            kdfRounds: boundedRounds,
            payload: payload
        )
        return try PICCPCoder.encode(package)
    }

    public static func decode(_ data: Data, password: String) throws -> ContactOffer {
        guard !password.isEmpty else {
            throw ContactShareError.emptyPassword
        }
        let package = try PICCPCoder.decode(ContactSharePackage.self, from: data)
        let key: SymmetricKey
        let aad: Data
        switch package.version {
        case 1:
            key = deriveLegacyKey(password: password, salt: package.salt, rounds: boundedRounds(package.kdfRounds))
            aad = authenticatedData(for: 1)
        case 2:
            key = derivePBKDF2Key(password: password, salt: package.salt, rounds: boundedRounds(package.kdfRounds))
            aad = authenticatedData(for: 2)
        default:
            throw ContactShareError.unsupportedVersion
        }
        let plaintext = try CryptoBox.decrypt(package.payload, key: key, authenticatedData: aad)
        let offer = try PICCPCoder.decode(ContactOffer.self, from: plaintext)
        return try offer.verified()
    }

    private static func authenticatedData(for version: Int) -> Data {
        Data("PICCPContactShare/v\(version)".utf8)
    }

    private static func boundedRounds(_ rounds: Int) -> Int {
        min(maximumKdfRounds, max(minimumKdfRounds, rounds))
    }

    private static func derivePBKDF2Key(password: String, salt: Data, rounds: Int) -> SymmetricKey {
        let bounded = boundedRounds(rounds)
        guard bounded > 0 else {
            return SymmetricKey(size: .bits256)
        }
        let passwordData = Data(password.utf8)
        var derived = Data()
        var blockIndex: UInt32 = 1
        while derived.count < keyLength {
            var blockInput = salt
            var beIndex = blockIndex.bigEndian
            withUnsafeBytes(of: &beIndex) { raw in
                blockInput.append(contentsOf: raw)
            }

            var u = hmacSHA256(keyData: passwordData, message: blockInput)
            var t = u
            if bounded > 1 {
                for _ in 2...bounded {
                    u = hmacSHA256(keyData: passwordData, message: u)
                    t.xorInPlace(with: u)
                }
            }
            derived.append(t)
            blockIndex &+= 1
        }
        return SymmetricKey(data: derived.prefix(keyLength))
    }

    private static func deriveLegacyKey(password: String, salt: Data, rounds: Int) -> SymmetricKey {
        let bounded = boundedRounds(rounds)
        var data = Data(password.utf8)
        data.append(salt)
        var digest = SHA256.hash(data: data)
        if bounded > 0 {
            for _ in 0..<bounded {
                var round = Data(digest)
                round.append(salt)
                digest = SHA256.hash(data: round)
            }
        }
        return SymmetricKey(data: Data(digest))
    }

    private static func hmacSHA256(keyData: Data, message: Data) -> Data {
        let key = SymmetricKey(data: keyData)
        return Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
    }

    private static func randomSalt() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw ContactShareError.entropyUnavailable
        }
        return Data(bytes)
    }
}

private extension Data {
    mutating func xorInPlace(with other: Data) {
        let count = Swift.min(self.count, other.count)
        guard count > 0 else { return }
        for index in 0..<count {
            self[index] ^= other[index]
        }
    }
}
