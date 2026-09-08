// SPDX-License-Identifier: AGPL-3.0-or-later
import CryptoKit
import Foundation

public enum SecurityKeyVerifier {
    /// Registration is provisional until a separate, fresh assertion proves possession.
    public static func registration(responseJSON: Data, challenge: SecurityKeyChallenge,
                                    application: SecurityKeyApplication, name: String,
                                    now: Date = Date()) throws -> SecurityKeyCredential {
        let response = try envelope(responseJSON)
        let inner = try responseBody(response)
        try verifyClientData(inner, challenge: challenge, application: application, type: "webauthn.create", now: now)
        let id = try binary(response, "rawId", maximum: 1_024)
        let attestation = try binary(inner, "attestationObject")
        var parser = try BoundedCBOR(attestation)
        guard let map = try parser.parse().map, parser.offset == attestation.count,
              let authData = map[.text("authData")]?.bytes else { throw SecurityKeyError.invalidResponse }
        let header = try authHeader(authData, application: application, registration: true)
        guard authData.count >= 55 else { throw SecurityKeyError.invalidResponse }
        let bytes = [UInt8](authData)
        let idLength = Int(bytes[53]) << 8 | Int(bytes[54])
        guard (1...1_024).contains(idLength), authData.count >= 55 + idLength,
              Data(bytes[55..<(55 + idLength)]) == id else { throw SecurityKeyError.invalidResponse }
        var keyParser = try BoundedCBOR(Data(bytes.dropFirst(55 + idLength)))
        guard let key = try keyParser.parse().map,
              key[.integer(1)]?.integer == 2, key[.integer(3)]?.integer == -7,
              key[.integer(-1)]?.integer == 1,
              let x = key[.integer(-2)]?.bytes, x.count == 32,
              let y = key[.integer(-3)]?.bytes, y.count == 32 else { throw SecurityKeyError.unsupported }
        try finishAuthenticatorData(parser: &keyParser, flags: header.flags)
        let credential = SecurityKeyCredential(name: name.trimmingCharacters(in: .whitespacesAndNewlines),
                                              relyingPartyID: application.relyingPartyID,
                                              credentialID: id, publicKey: Data([4]) + x + y,
                                              signatureCounter: header.counter)
        guard credential.isStructurallyValid else { throw SecurityKeyError.invalidResponse }
        return credential
    }

    /// A positive counter must advance; authenticators that always return zero remain supported.
    public static func assertion(responseJSON: Data, challenge: SecurityKeyChallenge,
                                 application: SecurityKeyApplication, credentials: [SecurityKeyCredential],
                                 now: Date = Date()) throws -> SecurityKeyCredential {
        guard (1...8).contains(credentials.count), credentials.allSatisfy(\.isStructurallyValid),
              Set(credentials.map(\.credentialID)).count == credentials.count,
              credentials.allSatisfy({ $0.relyingPartyID == application.relyingPartyID }) else {
            throw SecurityKeyError.invalidResponse
        }
        let response = try envelope(responseJSON)
        let inner = try responseBody(response)
        let clientData = try verifyClientData(inner, challenge: challenge, application: application,
                                              type: "webauthn.get", now: now)
        let id = try binary(response, "rawId", maximum: 1_024)
        guard var credential = credentials.first(where: { $0.credentialID == id }) else { throw SecurityKeyError.wrongKey }
        let authData = try binary(inner, "authenticatorData")
        let header = try authHeader(authData, application: application, registration: false)
        var extensions = try BoundedCBOR(Data(authData.dropFirst(37)))
        try finishAuthenticatorData(parser: &extensions, flags: header.flags)
        guard (credential.signatureCounter == 0 && header.counter == 0)
                || header.counter > credential.signatureCounter else { throw SecurityKeyError.verificationFailed }
        let signature = try P256.Signing.ECDSASignature(derRepresentation: binary(inner, "signature", maximum: 80))
        let publicKey = try P256.Signing.PublicKey(x963Representation: credential.publicKey)
        guard publicKey.isValidSignature(signature, for: authData + Data(SHA256.hash(data: clientData))) else {
            throw SecurityKeyError.verificationFailed
        }
        credential.signatureCounter = header.counter
        return credential
    }

    private static func envelope(_ data: Data) throws -> [String: Any] {
        guard data.count <= 131_072,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["type"] as? String == "public-key",
              object["authenticatorAttachment"] as? String == "cross-platform",
              let id = object["id"] as? String, id == object["rawId"] as? String else {
            throw SecurityKeyError.invalidResponse
        }
        return object
    }

    private static func responseBody(_ object: [String: Any]) throws -> [String: Any] {
        guard let response = object["response"] as? [String: Any] else { throw SecurityKeyError.invalidResponse }
        return response
    }

    @discardableResult
    private static func verifyClientData(_ response: [String: Any], challenge: SecurityKeyChallenge,
                                         application: SecurityKeyApplication, type: String, now: Date) throws -> Data {
        guard challenge.value.count == 32, now < challenge.expiresAt,
              challenge.expiresAt.timeIntervalSince(now) <= 61 else { throw SecurityKeyError.expired }
        let bytes = try binary(response, "clientDataJSON", maximum: 8_192)
        guard let json = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              json["type"] as? String == type, json["origin"] as? String == application.origin,
              json["challenge"] as? String == challenge.value.base64URL,
              json["topOrigin"] == nil,
              json["crossOrigin"] == nil || (json["crossOrigin"] as? Bool == false) else {
            throw SecurityKeyError.verificationFailed
        }
        return bytes
    }

    private static func authHeader(_ data: Data, application: SecurityKeyApplication,
                                   registration: Bool) throws -> (flags: UInt8, counter: UInt32) {
        guard (37...65_536).contains(data.count),
              Data(data.prefix(32)) == Data(SHA256.hash(data: Data(application.relyingPartyID.utf8))) else {
            throw SecurityKeyError.verificationFailed
        }
        let bytes = [UInt8](data)
        let flags = bytes[32]
        guard flags & 0x05 == 0x05, flags & 0x3A == 0,
              (flags & 0x40 != 0) == registration else { throw SecurityKeyError.verificationFailed }
        let counter = bytes[33...36].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        return (flags, counter)
    }

    private static func finishAuthenticatorData(parser: inout BoundedCBOR, flags: UInt8) throws {
        if flags & 0x80 != 0 {
            guard try parser.parse().map != nil else { throw SecurityKeyError.invalidResponse }
        }
        guard parser.offset == parser.bytes.count else { throw SecurityKeyError.invalidResponse }
    }

    private static func binary(_ object: [String: Any], _ key: String, maximum: Int = 65_536) throws -> Data {
        guard let text = object[key] as? String else { throw SecurityKeyError.invalidResponse }
        return try Data(strictBase64URL: text, maximum: maximum)
    }
}
