import CommonCrypto
import CryptoKit
import Foundation
import Security

public enum PasswordProtectedPairingPackageV1Error: Error, Equatable {
    case invalidInvitation
    case invalidPassword
    case invalidPackage
    case entropyUnavailable
    case keyDerivationFailed
    case decryptionFailed
}

/// A password-encrypted carrier for bounded one-use pairing data.
///
/// Relay Pairing uses it for the invitation handoff. Direct Pairing can use it
/// for each authenticated transcript stage, keeping that transcript out of a
/// rendezvous relay.
public enum PasswordProtectedPairingPackageV1 {
    public static let version = 1
    public static let minimumPasswordCharacters = 8
    public static let maximumPasswordBytes = 1_024
    public static let maximumInvitationBytes = 64 * 1_024
    public static let maximumPackageBytes = 128 * 1_024
    public static let pbkdf2Iterations: UInt32 = 600_000

    private static let saltBytes = 16
    private static let keyBytes = 32
    private static let kdfName = "PBKDF2-HMAC-SHA256"
    private static let cipherName = "AES-256-GCM"
    private static let authenticatedData = Data("noctweave-protected-pairing-v1".utf8)

    public static func seal(invitation: String, password: String) throws -> Data {
        guard let plaintext = invitation.data(using: .utf8),
              !plaintext.isEmpty,
              plaintext.count <= maximumInvitationBytes else {
            throw PasswordProtectedPairingPackageV1Error.invalidInvitation
        }
        let passwordData = try validatedPasswordData(password)
        let salt = try secureRandomData(count: saltBytes)
        let key = try deriveKey(password: passwordData, salt: salt, iterations: pbkdf2Iterations)
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: authenticatedData)
        guard let combined = box.combined else {
            throw PasswordProtectedPairingPackageV1Error.invalidPackage
        }
        let envelope = ProtectedPairingPackageEnvelopeV1(
            version: version,
            kdf: kdfName,
            iterations: pbkdf2Iterations,
            cipher: cipherName,
            salt: salt,
            sealed: combined
        )
        let encoded = try NoctweaveCoder.encode(envelope)
        guard encoded.count <= maximumPackageBytes else {
            throw PasswordProtectedPairingPackageV1Error.invalidPackage
        }
        return encoded
    }

    public static func open(package: Data, password: String) throws -> String {
        guard !package.isEmpty, package.count <= maximumPackageBytes else {
            throw PasswordProtectedPairingPackageV1Error.invalidPackage
        }
        let passwordData = try validatedPasswordData(password)
        let envelope: ProtectedPairingPackageEnvelopeV1
        do {
            envelope = try NoctweaveCoder.decode(
                ProtectedPairingPackageEnvelopeV1.self,
                from: package
            )
        } catch {
            throw PasswordProtectedPairingPackageV1Error.invalidPackage
        }
        guard envelope.version == version,
              envelope.kdf == kdfName,
              envelope.iterations == pbkdf2Iterations,
              envelope.cipher == cipherName,
              envelope.salt.count == saltBytes,
              envelope.sealed.count <= maximumInvitationBytes + 28 else {
            throw PasswordProtectedPairingPackageV1Error.invalidPackage
        }

        do {
            let key = try deriveKey(
                password: passwordData,
                salt: envelope.salt,
                iterations: envelope.iterations
            )
            let box = try AES.GCM.SealedBox(combined: envelope.sealed)
            let plaintext = try AES.GCM.open(
                box,
                using: key,
                authenticating: authenticatedData
            )
            guard !plaintext.isEmpty,
                  plaintext.count <= maximumInvitationBytes,
                  let invitation = String(data: plaintext, encoding: .utf8) else {
                throw PasswordProtectedPairingPackageV1Error.decryptionFailed
            }
            return invitation
        } catch let error as PasswordProtectedPairingPackageV1Error {
            throw error
        } catch {
            throw PasswordProtectedPairingPackageV1Error.decryptionFailed
        }
    }

    private static func validatedPasswordData(_ password: String) throws -> Data {
        let normalized = password.precomposedStringWithCanonicalMapping
        guard normalized.count >= minimumPasswordCharacters,
              let data = normalized.data(using: .utf8),
              data.count <= maximumPasswordBytes else {
            throw PasswordProtectedPairingPackageV1Error.invalidPassword
        }
        return data
    }

    private static func deriveKey(
        password: Data,
        salt: Data,
        iterations: UInt32
    ) throws -> SymmetricKey {
        var derived = [UInt8](repeating: 0, count: keyBytes)
        let status = password.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    UInt32(kCCPBKDF2),
                    passwordBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                    passwordBytes.count,
                    saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    saltBytes.count,
                    UInt32(kCCPRFHmacAlgSHA256),
                    iterations,
                    &derived,
                    derived.count
                )
            }
        }
        guard status == kCCSuccess else {
            throw PasswordProtectedPairingPackageV1Error.keyDerivationFailed
        }
        defer {
            _ = derived.withUnsafeMutableBytes { bytes in
                bytes.initializeMemory(as: UInt8.self, repeating: 0)
            }
        }
        return SymmetricKey(data: derived)
    }

    private static func secureRandomData(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw PasswordProtectedPairingPackageV1Error.entropyUnavailable
        }
        return Data(bytes)
    }
}

private struct ProtectedPairingPackageEnvelopeV1: Codable, Equatable {
    let version: Int
    let kdf: String
    let iterations: UInt32
    let cipher: String
    let salt: Data
    let sealed: Data
}
