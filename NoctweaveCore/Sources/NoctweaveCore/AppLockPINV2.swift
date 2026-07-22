import CryptoKit
import Foundation

public enum AppLockPINV2Error: Error, Equatable, LocalizedError {
    case invalidPIN
    case invalidSalt
    case invalidRounds

    public var errorDescription: String? {
        switch self {
        case .invalidPIN:
            return "The app-lock PIN must contain exactly six ASCII digits."
        case .invalidSalt:
            return "The app-lock PIN salt is outside the supported bounds."
        case .invalidRounds:
            return "The app-lock PIN work factor is outside the supported bounds."
        }
    }
}

public struct AppLockPINRecordV2: Equatable, Sendable {
    public let salt: Data
    public let encodedHash: Data

    public init(salt: Data, encodedHash: Data) {
        self.salt = salt
        self.encodedHash = encodedHash
    }
}

/// Versioned local PIN derivation used by app-lock settings.
///
/// The encoded value is `NPIN2 || rounds_be32 || digest32`. New records use a
/// bounded work factor while verification accepts the wider historical v2
/// range so an existing valid lock is not silently made unusable.
public enum AppLockPINV2 {
    public static let defaultRounds = 120_000
    public static let minimumCreationRounds = 60_000
    public static let maximumCreationRounds = 300_000

    private static let minimumVerificationRounds = 10_000
    private static let maximumVerificationRounds = 500_000
    private static let magic = Data("NPIN2".utf8)

    public static func makeRecord(
        pin: String,
        salt suppliedSalt: Data? = nil,
        rounds: Int = defaultRounds
    ) throws -> AppLockPINRecordV2 {
        guard let normalizedPIN = normalized(pin) else {
            throw AppLockPINV2Error.invalidPIN
        }
        guard (minimumCreationRounds...maximumCreationRounds).contains(rounds) else {
            throw AppLockPINV2Error.invalidRounds
        }
        let salt = suppliedSalt ?? SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        guard (16...128).contains(salt.count) else {
            throw AppLockPINV2Error.invalidSalt
        }
        let digest = stretchedDigest(pin: normalizedPIN, salt: salt, rounds: rounds)
        var encoded = magic
        var roundsBE = UInt32(rounds).bigEndian
        withUnsafeBytes(of: &roundsBE) { encoded.append(contentsOf: $0) }
        encoded.append(digest)
        return AppLockPINRecordV2(salt: salt, encodedHash: encoded)
    }

    public static func verify(pin: String, salt: Data, encodedHash: Data) -> Bool {
        guard let normalizedPIN = normalized(pin),
              (16...128).contains(salt.count),
              encodedHash.count == 41,
              encodedHash.prefix(magic.count) == magic else {
            return false
        }
        var rounds: UInt32 = 0
        for byte in encodedHash[magic.count..<(magic.count + 4)] {
            rounds = (rounds << 8) | UInt32(byte)
        }
        guard (minimumVerificationRounds...maximumVerificationRounds).contains(Int(rounds)) else {
            return false
        }
        let candidate = stretchedDigest(
            pin: normalizedPIN,
            salt: salt,
            rounds: Int(rounds)
        )
        let stored = Data(encodedHash.suffix(32))
        guard candidate.count == stored.count else { return false }
        var difference: UInt8 = 0
        for index in candidate.indices {
            difference |= candidate[index] ^ stored[index]
        }
        return difference == 0
    }

    private static func normalized(_ pin: String) -> String? {
        guard pin.utf8.count == 6,
              pin.utf8.allSatisfy({ (48...57).contains($0) }) else {
            return nil
        }
        return pin
    }

    private static func stretchedDigest(pin: String, salt: Data, rounds: Int) -> Data {
        let key = SymmetricKey(data: Data(pin.utf8))
        var block = Data(HMAC<SHA256>.authenticationCode(for: salt, using: key))
        var digest = block
        if rounds > 1 {
            for _ in 2...rounds {
                block = Data(HMAC<SHA256>.authenticationCode(for: block, using: key))
                for index in digest.indices {
                    digest[index] ^= block[index]
                }
            }
        }
        return digest
    }
}
