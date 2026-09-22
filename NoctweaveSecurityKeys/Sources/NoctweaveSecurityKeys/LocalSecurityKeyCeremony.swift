// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

enum LocalSecurityKeyReply {
    case next(Data)
    case complete
}

/// Both enrollment steps live inside one browser session. Native code controls
/// the phase change and verifies each response before issuing the next challenge.
@MainActor
final class LocalSecurityKeyCeremony {
    let isRegistration: Bool
    private(set) var options: Data
    private enum Phase {
        case registration(SecurityKeyChallenge, String, [SecurityKeyCredential])
        case assertion(SecurityKeyChallenge, [SecurityKeyCredential])
        case finished
    }
    private var phase: Phase
    private var verified: SecurityKeyCredential?
    private var failure: Error?
    private let freshChallenge: () throws -> SecurityKeyChallenge

    init(name: String, excluding credentials: [SecurityKeyCredential],
         freshChallenge: @escaping () throws -> SecurityKeyChallenge = SecurityKeyChallenge.fresh) throws {
        guard credentials.count < 8, credentials.allSatisfy(\.isStructurallyValid),
              Set(credentials.map(\.credentialID)).count == credentials.count,
              name.utf8.count <= 128, !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw SecurityKeyError.invalidResponse
        }
        let challenge = try freshChallenge()
        self.freshChallenge = freshChallenge
        isRegistration = true
        phase = .registration(challenge, name, credentials)
        options = try JSONSerialization.data(withJSONObject: [
            "challenge": challenge.value.base64URL,
            "rp": ["id": "localhost", "name": "Noct Gallery Unlock"],
            "user": ["id": try secureRandomBytes(count: 32).base64URL, "name": "local-gallery", "displayName": "Noct Gallery"],
            "pubKeyCredParams": [["type": "public-key", "alg": -7]],
            "authenticatorSelection": ["authenticatorAttachment": "cross-platform", "residentKey": "discouraged", "userVerification": "required"],
            "attestation": "none", "timeout": 60_000, "hints": ["security-key"],
            "excludeCredentials": Self.descriptors(credentials.filter { $0.relyingPartyID == "localhost" })
        ])
    }

    init(credentials: [SecurityKeyCredential],
         freshChallenge: @escaping () throws -> SecurityKeyChallenge = SecurityKeyChallenge.fresh) throws {
        guard (1...8).contains(credentials.count),
              credentials.allSatisfy({ $0.isStructurallyValid && $0.relyingPartyID == "localhost" }),
              Set(credentials.map(\.credentialID)).count == credentials.count else { throw SecurityKeyError.invalidResponse }
        let challenge = try freshChallenge()
        self.freshChallenge = freshChallenge
        isRegistration = false
        phase = .assertion(challenge, credentials)
        options = try Self.assertionOptions(challenge: challenge, credentials: credentials)
    }

    func respond(_ response: Data, port: UInt16, now: Date = Date()) -> LocalSecurityKeyReply {
        do {
            if let object = try JSONSerialization.jsonObject(with: response) as? [String: Any], let error = object["error"] as? String {
                switch error {
                case "NotAllowedError", "AbortError": throw SecurityKeyError.cancelled
                case "NotSupportedError": throw SecurityKeyError.unsupported
                default: throw SecurityKeyError.verificationFailed
                }
            }
            switch phase {
            case .registration(let challenge, let name, let credentials):
                let provisional = try SecurityKeyVerifier.registration(responseJSON: response, challenge: challenge,
                    application: .noctGalleryLocal, name: name, now: now, localPort: port)
                guard !credentials.contains(where: { $0.credentialID == provisional.credentialID }) else {
                    throw SecurityKeyError.invalidResponse
                }
                let proof = try freshChallenge()
                guard proof.value != challenge.value else { throw SecurityKeyError.invalidResponse }
                options = try Self.assertionOptions(challenge: proof, credentials: [provisional])
                phase = .assertion(proof, [provisional])
                return .next(options)
            case .assertion(let challenge, let credentials):
                verified = try SecurityKeyVerifier.assertion(responseJSON: response, challenge: challenge,
                    application: .noctGalleryLocal, credentials: credentials, now: now, localPort: port)
                phase = .finished
                return .complete
            case .finished: throw SecurityKeyError.invalidResponse
            }
        } catch {
            verified = nil
            failure = error
            phase = .finished
            return .complete
        }
    }

    func result() throws -> SecurityKeyCredential {
        if let failure { throw failure }
        guard case .finished = phase, let verified else { throw SecurityKeyError.verificationFailed }
        return verified
    }

    private static func descriptors(_ credentials: [SecurityKeyCredential]) -> [[String: Any]] {
        credentials.map { ["type": "public-key", "id": $0.credentialID.base64URL, "transports": ["usb"]] }
    }

    private static func assertionOptions(challenge: SecurityKeyChallenge, credentials: [SecurityKeyCredential]) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["challenge": challenge.value.base64URL, "rpId": "localhost",
            "allowCredentials": descriptors(credentials), "userVerification": "required", "timeout": 60_000, "hints": ["security-key"]])
    }
}
