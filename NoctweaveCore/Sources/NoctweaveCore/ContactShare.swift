import CryptoKit
import Foundation
#if canImport(Security)
import Security
#endif

public enum ContactShareError: Error, Equatable {
    case emptyPassword
    case invalidPassword
    case unsupportedVersion
    case invalidKdfRounds
    case invalidPackage
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
    public static let defaultKdfRounds = 310_000
    public static let minimumKdfRounds = 120_000
    public static let maximumKdfRounds = 600_000
    public static let maximumPackageBytes = 512 * 1024
    public static let minimumPasswordBytes = 12
    public static let maximumPasswordBytes = 1_024
    private static let keyLength = 32
    private static let saltLength = 16
    private static let maximumCiphertextBytes = 256 * 1024

    public static func encode(_ offer: ContactOffer, password: String, kdfRounds: Int = defaultKdfRounds) throws -> Data {
        try validatePassword(password)
        guard (minimumKdfRounds...maximumKdfRounds).contains(kdfRounds) else {
            throw ContactShareError.invalidKdfRounds
        }
        _ = try offer.verified()
        let salt = try randomSalt()
        let key = derivePBKDF2Key(password: password, salt: salt, rounds: kdfRounds)
        var offerData = try NoctweaveCoder.encode(offer)
        defer { offerData.secureWipe() }
        guard !offerData.isEmpty, offerData.count <= maximumCiphertextBytes else {
            throw ContactShareError.invalidPackage
        }
        let payload = try CryptoBox.encrypt(
            offerData,
            key: key,
            authenticatedData: authenticatedData(for: currentVersion)
        )
        let package = ContactSharePackage(
            version: currentVersion,
            salt: salt,
            kdfRounds: kdfRounds,
            payload: payload
        )
        let encoded = try NoctweaveCoder.encode(package)
        guard encoded.count <= maximumPackageBytes else {
            throw ContactShareError.invalidPackage
        }
        return encoded
    }

    public static func decode(_ data: Data, password: String) throws -> ContactOffer {
        try validatePassword(password)
        guard !data.isEmpty, data.count <= maximumPackageBytes else {
            throw ContactShareError.invalidPackage
        }
        let package = try NoctweaveCoder.decode(ContactSharePackage.self, from: data)
        guard package.salt.count == saltLength,
              (minimumKdfRounds...maximumKdfRounds).contains(package.kdfRounds),
              package.payload.nonce.count == 12,
              package.payload.tag.count == 16,
              !package.payload.ciphertext.isEmpty,
              package.payload.ciphertext.count <= maximumCiphertextBytes else {
            throw ContactShareError.invalidPackage
        }
        let key: SymmetricKey
        let aad: Data
        switch package.version {
        case 2:
            key = derivePBKDF2Key(password: password, salt: package.salt, rounds: package.kdfRounds)
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

    private static func validatePassword(_ password: String) throws {
        guard !password.isEmpty else {
            throw ContactShareError.emptyPassword
        }
        guard (minimumPasswordBytes...maximumPasswordBytes).contains(password.utf8.count) else {
            throw ContactShareError.invalidPassword
        }
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
        var bytes = [UInt8](repeating: 0, count: saltLength)
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
    mutating func xorInPlace(with other: Data) {
        let count = Swift.min(self.count, other.count)
        guard count > 0 else { return }
        for index in 0..<count {
            self[index] ^= other[index]
        }
    }
}
