// SPDX-License-Identifier: AGPL-3.0-or-later
import CryptoKit
import Foundation
import Security

/// These names scope local app access. They are never network endpoints or messaging identities.
public enum SecurityKeyApplication: String, Sendable {
    case noctweave
    case noctweaveJS

    public var relyingPartyID: String {
        switch self {
        case .noctweave: "noctweave-app-lock.invalid"
        case .noctweaveJS: "noctweavejs-app-lock.invalid"
        }
    }

    public var origin: String { "https://\(relyingPartyID)" }
    public var displayName: String { self == .noctweave ? "Noctweave App Unlock" : "NoctweaveJS Vault Unlock" }
}

public struct SecurityKeyCredential: Codable, Equatable, Sendable, Identifiable {
    public let id: UUID
    public var name: String
    public let relyingPartyID: String
    public let credentialID: Data
    public let publicKey: Data
    public var signatureCounter: UInt32

    public init(id: UUID = UUID(), name: String, relyingPartyID: String,
                credentialID: Data, publicKey: Data, signatureCounter: UInt32) {
        self.id = id
        self.name = name
        self.relyingPartyID = relyingPartyID
        self.credentialID = credentialID
        self.publicKey = publicKey
        self.signatureCounter = signatureCounter
    }

    public var isStructurallyValid: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && name.utf8.count <= 128
            && (1...253).contains(relyingPartyID.utf8.count)
            && (1...1_024).contains(credentialID.count)
            && publicKey.count == 65
            && (try? P256.Signing.PublicKey(x963Representation: publicKey)) != nil
    }
}

public struct SecurityKeyChallenge: Sendable {
    public let value: Data
    public let expiresAt: Date

    public init(value: Data, expiresAt: Date) {
        self.value = value
        self.expiresAt = expiresAt
    }

    public static func fresh() throws -> Self {
        Self(value: try secureRandomBytes(count: 32), expiresAt: Date().addingTimeInterval(60))
    }
}

public enum SecurityKeyError: String, Error, LocalizedError, Sendable {
    case invalidResponse, wrongKey, verificationFailed, expired, cancelled, unavailable
    case pinRequired, pinRejected, pinBlocked, pinNotSet, timedOut, unsupported, busy
    case randomUnavailable

    public var errorDescription: String? {
        switch self {
        case .invalidResponse, .verificationFailed: "The security key response could not be verified. The app remains locked."
        case .wrongKey: "This key is not registered for this app. Connect a registered key and try again."
        case .expired, .timedOut: "The security key request expired. Try again."
        case .cancelled: "Security key verification was cancelled."
        case .unavailable: "Connect your security key, then try again."
        case .pinRequired: "Enter your security key's PIN, then try again."
        case .pinRejected: "The security key PIN was not accepted. No automatic PIN retry was made."
        case .pinBlocked: "The security key has blocked PIN verification. Follow your key maker's recovery instructions."
        case .pinNotSet: "Set a FIDO2 PIN with your key's management app before registering it."
        case .unsupported: "This connection requires a FIDO2 key with PIN or built-in user verification."
        case .busy: "Another security key operation is in progress."
        case .randomUnavailable: "A secure authentication challenge could not be created."
        }
    }
}

func secureRandomBytes(count: Int) throws -> Data {
    var data = Data(count: count)
    let result = data.withUnsafeMutableBytes { bytes in
        SecRandomCopyBytes(kSecRandomDefault, count, bytes.baseAddress!)
    }
    guard result == errSecSuccess else { throw SecurityKeyError.randomUnavailable }
    return data
}

extension Data {
    var base64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    init(strictBase64URL value: String, maximum: Int = 65_536) throws {
        guard value.utf8.count <= maximum * 2,
              value.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0)
                  || (48...57).contains($0) || $0 == 45 || $0 == 95 }),
              value.count % 4 != 1 else { throw SecurityKeyError.invalidResponse }
        let padded = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let decoded = Data(base64Encoded: padded), decoded.count <= maximum,
              decoded.base64URL == value else { throw SecurityKeyError.invalidResponse }
        self = decoded
    }
}
