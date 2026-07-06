import CryptoKit
import Foundation
#if canImport(Security)
import Security
#endif

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
        var offerData = try NoctweaveCoder.encode(offer)
        defer { offerData.secureWipe() }
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
        return try NoctweaveCoder.encode(package)
    }

    public static func decode(_ data: Data, password: String) throws -> ContactOffer {
        guard !password.isEmpty else {
            throw ContactShareError.emptyPassword
        }
        let package = try NoctweaveCoder.decode(ContactSharePackage.self, from: data)
        let key: SymmetricKey
        let aad: Data
        switch package.version {
        case 2:
            key = derivePBKDF2Key(password: password, salt: package.salt, rounds: boundedRounds(package.kdfRounds))
            aad = authenticatedData(for: 2)
        default:
            throw ContactShareError.unsupportedVersion
        }
        var plaintext = try CryptoBox.decrypt(package.payload, key: key, authenticatedData: aad)
        defer { plaintext.secureWipe() }
        let offer = try NoctweaveCoder.decode(ContactOffer.self, from: plaintext)
        return try offer.verified()
    }

    private static func authenticatedData(for version: Int) -> Data {
        Data("NoctweaveContactShare/v\(version)".utf8)
    }

    private static func boundedRounds(_ rounds: Int) -> Int {
        min(maximumKdfRounds, max(minimumKdfRounds, rounds))
    }

    private static func derivePBKDF2Key(password: String, salt: Data, rounds: Int) -> SymmetricKey {
        let bounded = boundedRounds(rounds)
        guard bounded > 0 else {
            return SymmetricKey(size: .bits256)
        }
        var passwordData = Data(password.utf8)
        var derived = Data()
        defer {
            passwordData.secureWipe()
            derived.secureWipe()
        }
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
            blockInput.secureWipe()
            u.secureWipe()
            t.secureWipe()
            blockIndex &+= 1
        }
        var keyMaterial = Data(derived.prefix(keyLength))
        defer { keyMaterial.secureWipe() }
        return SymmetricKey(data: keyMaterial)
    }

    private static func hmacSHA256(keyData: Data, message: Data) -> Data {
        let key = SymmetricKey(data: keyData)
        return Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
    }

    private static func randomSalt() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        #if canImport(Security)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw ContactShareError.entropyUnavailable
        }
        #else
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: 0...255)
        }
        #endif
        return Data(bytes)
    }
}

private extension Data {
    mutating func secureWipe() {
        guard !isEmpty else { return }
        let byteCount = count
        withUnsafeMutableBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            #if canImport(Darwin)
            _ = memset_s(baseAddress, byteCount, 0, byteCount)
            #else
            _ = memset(baseAddress, 0, byteCount)
            #endif
        }
        removeAll(keepingCapacity: false)
    }

    mutating func xorInPlace(with other: Data) {
        let count = Swift.min(self.count, other.count)
        guard count > 0 else { return }
        for index in 0..<count {
            self[index] ^= other[index]
        }
    }
}
