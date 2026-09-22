// SPDX-License-Identifier: AGPL-3.0-or-later
import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveSecurityKeys

@MainActor
final class LocalSecurityKeyCeremonyTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let port: UInt16 = 49_152
    private let id = Data(repeating: 9, count: 32)

    private func enrollment(app: LocalSecurityKeyApp = .noctGallery) throws -> LocalSecurityKeyCeremony {
        var sequence: UInt8 = 41
        return try LocalSecurityKeyCeremony(app: app, name: "Test key", excluding: [], freshChallenge: {
            sequence += 1
            return SecurityKeyChallenge(value: Data(repeating: sequence, count: 32), expiresAt: self.now.addingTimeInterval(60))
        })
    }

    func testRegistrationCannotFinishUntilFreshSignedProofAndCannotLoop() throws {
        for app in LocalSecurityKeyApp.allCases {
            let key = P256.Signing.PrivateKey()
            let ceremony = try enrollment(app: app)
            XCTAssertThrowsError(try ceremony.result())
            guard case .next(let next) = ceremony.respond(try registration(key), port: port, now: now) else {
                return XCTFail("Valid registration did not advance to proof")
            }
            XCTAssertThrowsError(try ceremony.result(), "A provisional key must never enable protection")
            let options = try XCTUnwrap(JSONSerialization.jsonObject(with: next) as? [String: Any])
            XCTAssertEqual(options["challenge"] as? String, Data(repeating: 43, count: 32).base64URL)
            XCTAssertEqual(options["rpId"] as? String, "localhost")
            XCTAssertNil(options["user"], "The second step must be assertion, not another registration")
            guard case .complete = ceremony.respond(try assertion(key), port: port, now: now) else { return XCTFail("Proof restarted enrollment") }
            let verified = try ceremony.result()
            XCTAssertEqual(verified.credentialID, id)
            XCTAssertEqual(verified.signatureCounter, 1)
            XCTAssertEqual(verified.publicKey, key.publicKey.x963Representation)
            guard case .complete = ceremony.respond(try assertion(key), port: port, now: now) else { return XCTFail("Replay restarted enrollment") }
            XCTAssertThrowsError(try ceremony.result())
        }
    }

    func testRepeatedRegistrationAndFirstChallengeCannotSatisfyProof() throws {
        for app in LocalSecurityKeyApp.allCases {
            for repeatRegistration in [true, false] {
                let key = P256.Signing.PrivateKey()
                let ceremony = try enrollment(app: app)
                _ = ceremony.respond(try registration(key), port: port, now: now)
                let response = try repeatRegistration ? registration(key) : assertion(key, challengeByte: 42)
                guard case .complete = ceremony.respond(response, port: port, now: now) else { return XCTFail("Invalid proof repeated enrollment") }
                XCTAssertThrowsError(try ceremony.result())
            }
        }
    }

    func testWrongKeyCancelledOrExpiredProofCannotRegisterCredential() throws {
        let key = P256.Signing.PrivateKey()
        for app in LocalSecurityKeyApp.allCases {
            for (response, date) in [
                (try assertion(P256.Signing.PrivateKey()), now),
                (Data("{\"error\":\"NotAllowedError\"}".utf8), now),
                (try assertion(key), now.addingTimeInterval(61))
            ] {
                let ceremony = try enrollment(app: app)
                _ = ceremony.respond(try registration(key), port: port, now: now)
                _ = ceremony.respond(response, port: port, now: date)
                XCTAssertThrowsError(try ceremony.result())
            }
        }
    }

    private func registration(_ key: P256.Signing.PrivateKey) throws -> Data {
        let publicKey = key.publicKey.x963Representation
        var authData = Data(SHA256.hash(data: Data("localhost".utf8)))
        authData.append(contentsOf: [0x45, 0, 0, 0, 0])
        authData.append(Data(repeating: 0, count: 16))
        authData.append(contentsOf: [0, 32]); authData.append(id)
        authData.append(contentsOf: [0xA5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 32])
        authData.append(publicKey[1..<33])
        authData.append(contentsOf: [0x22, 0x58, 32]); authData.append(publicKey[33..<65])
        let attestation = Data([0xA1, 0x68]) + Data("authData".utf8) + Data([0x58, UInt8(authData.count)]) + authData
        return try envelope(["clientDataJSON": clientData(type: "webauthn.create", byte: 42).base64URL,
                             "attestationObject": attestation.base64URL])
    }

    private func assertion(_ key: P256.Signing.PrivateKey, challengeByte: UInt8 = 43) throws -> Data {
        let client = try clientData(type: "webauthn.get", byte: challengeByte)
        let authData = Data(SHA256.hash(data: Data("localhost".utf8))) + Data([5, 0, 0, 0, 1])
        let signature = try key.signature(for: authData + Data(SHA256.hash(data: client))).derRepresentation
        return try envelope(["clientDataJSON": client.base64URL, "authenticatorData": authData.base64URL, "signature": signature.base64URL])
    }

    private func clientData(type: String, byte: UInt8) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["type": type, "origin": "http://localhost:\(port)",
            "challenge": Data(repeating: byte, count: 32).base64URL, "crossOrigin": false])
    }

    private func envelope(_ response: [String: String]) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["type": "public-key", "authenticatorAttachment": "cross-platform",
            "id": id.base64URL, "rawId": id.base64URL, "response": response])
    }
}
