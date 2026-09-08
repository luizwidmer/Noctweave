// SPDX-License-Identifier: AGPL-3.0-or-later
import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveSecurityKeys

final class SecurityKeyVerifierTests: XCTestCase {
    let app = SecurityKeyApplication.noctweave
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    func testFreshSignedAssertionAdvancesCounter() throws {
        let fixture = try assertion()
        let verified = try verify(fixture)
        XCTAssertEqual(verified.signatureCounter, 2)
        XCTAssertEqual(verified.credentialID, fixture.credential.credentialID)
    }

    func testZeroCounterAuthenticatorRemainsSupported() throws {
        let fixture = try assertion(previous: 0, counter: 0)
        XCTAssertEqual(try verify(fixture).signatureCounter, 0)
    }

    func testRejectsReplayedOrRegressedCounters() throws {
        for counter: UInt32 in [0, 1] {
            XCTAssertThrowsError(try verify(assertion(previous: 1, counter: counter)))
        }
    }

    func testRejectsWrongChallengeOriginAndCeremony() throws {
        for field in ["challenge", "origin", "type"] {
            XCTAssertThrowsError(try verify(assertion(clientOverride: [field: "wrong"])))
        }
        XCTAssertThrowsError(try verify(assertion(clientOverride: ["crossOrigin": true])))
        XCTAssertThrowsError(try verify(assertion(clientOverride: ["topOrigin": app.origin])))
    }

    func testRejectsAbsentTouchVerificationAndBackupCredentials() throws {
        for flags: UInt8 in [0, 1, 4, 0x0D, 0x15, 0x25, 0x45] {
            XCTAssertThrowsError(try verify(assertion(flags: flags)))
        }
    }

    func testRejectsWrongRelyingPartyAndWrongKey() throws {
        XCTAssertThrowsError(try verify(assertion(rp: "another-app.invalid")))
        let fixture = try assertion()
        let other = SecurityKeyCredential(name: "Other", relyingPartyID: app.relyingPartyID,
                                          credentialID: Data([9]), publicKey: fixture.credential.publicKey, signatureCounter: 1)
        XCTAssertThrowsError(try SecurityKeyVerifier.assertion(responseJSON: fixture.json, challenge: fixture.challenge,
                                                              application: app, credentials: [other], now: now))
    }

    func testRejectsBadSignatureExpiredChallengeAndTrailingBytes() throws {
        XCTAssertThrowsError(try verify(assertion(corruptSignature: true)))
        XCTAssertThrowsError(try verify(assertion(trailing: Data([0]))))
        let fixture = try assertion()
        XCTAssertThrowsError(try SecurityKeyVerifier.assertion(responseJSON: fixture.json,
            challenge: .init(value: fixture.challenge.value, expiresAt: now), application: app,
            credentials: [fixture.credential], now: now))
    }

    func testRejectsPlatformAuthenticator() throws {
        var fixture = try assertion()
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with: fixture.json) as? [String: Any])
        json["authenticatorAttachment"] = "platform"
        fixture.json = try JSONSerialization.data(withJSONObject: json)
        XCTAssertThrowsError(try verify(fixture))
    }

    func testCBORRejectsDuplicateKeysIndefiniteLengthsAndLargeCollections() throws {
        for bytes: [UInt8] in [[0xA2, 1, 1, 1, 2], [0x9F, 0xFF], [0x98, 65], [0x18, 1], [0x58, 0xFF]] {
            var parser = try BoundedCBOR(Data(bytes))
            XCTAssertThrowsError(try parser.parse())
        }
    }

    func testRegistrationParsesOnlyBoundES256Credential() throws {
        let key = P256.Signing.PrivateKey()
        let publicKey = key.publicKey.x963Representation
        let id = Data(repeating: 7, count: 32)
        let challenge = SecurityKeyChallenge(value: Data(repeating: 42, count: 32), expiresAt: now.addingTimeInterval(60))
        var authData = Data(SHA256.hash(data: Data(app.relyingPartyID.utf8)))
        authData.append(contentsOf: [0x45, 0, 0, 0, 0])
        authData.append(Data(repeating: 0, count: 16))
        authData.append(contentsOf: [0, 32]); authData.append(id)
        authData.append(contentsOf: [0xA5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 32])
        authData.append(publicKey[1..<33])
        authData.append(contentsOf: [0x22, 0x58, 32]); authData.append(publicKey[33..<65])
        let attestation = Data([0xA1, 0x68]) + Data("authData".utf8) + Data([0x58, UInt8(authData.count)]) + authData
        let client = try JSONSerialization.data(withJSONObject: ["type": "webauthn.create", "origin": app.origin,
                                                                 "challenge": challenge.value.base64URL])
        var response: [String: Any] = ["type": "public-key", "authenticatorAttachment": "cross-platform",
            "id": id.base64URL, "rawId": id.base64URL,
            "response": ["clientDataJSON": client.base64URL, "attestationObject": attestation.base64URL]]
        let verified = try SecurityKeyVerifier.registration(responseJSON: JSONSerialization.data(withJSONObject: response),
            challenge: challenge, application: app, name: "Daily key", now: now)
        XCTAssertEqual(verified.publicKey, publicKey)
        XCTAssertEqual(verified.credentialID, id)
        response["id"] = Data([8]).base64URL; response["rawId"] = Data([8]).base64URL
        XCTAssertThrowsError(try SecurityKeyVerifier.registration(responseJSON: JSONSerialization.data(withJSONObject: response),
            challenge: challenge, application: app, name: "Daily key", now: now))
    }

    func testPINIsNeverSubmittedAgainAndCancellationIsNotMisreportedAsMissingPIN() async {
        let attempt = PINAttempt(pin: "example-only-pin")
        if case .pin(let value) = await attempt.reply() { XCTAssertEqual(value, "example-only-pin") }
        else { XCTFail("First request should provide the PIN") }
        let cancelled = await attempt.error(for: SecurityKeyError.cancelled)
        XCTAssertEqual(cancelled, .cancelled)
        if case .cancel = await attempt.reply() {} else { XCTFail("Do not retry a rejected PIN") }
        let rejected = await attempt.error(for: SecurityKeyError.cancelled)
        XCTAssertEqual(rejected, .pinRejected)
        let empty = PINAttempt(pin: "")
        if case .cancel = await empty.reply() {} else { XCTFail("Never submit an empty PIN") }
        let missing = await empty.error(for: SecurityKeyError.cancelled)
        XCTAssertEqual(missing, .pinRequired)
    }

    func testPresenceDoesNotAcceptMissingOrArbitraryRegistryIdentities() {
        XCTAssertFalse(SecurityKeyPresence(registryEntryID: 0).isConnected)
        XCTAssertFalse(SecurityKeyPresence(registryEntryID: UInt64.max).isConnected)
    }

    private struct Fixture {
        var json: Data
        let credential: SecurityKeyCredential
        let challenge: SecurityKeyChallenge
    }

    private func verify(_ fixture: Fixture) throws -> SecurityKeyCredential {
        try SecurityKeyVerifier.assertion(responseJSON: fixture.json, challenge: fixture.challenge,
                                           application: app, credentials: [fixture.credential], now: now)
    }

    private func assertion(previous: UInt32 = 1, counter: UInt32 = 2, flags: UInt8 = 5,
                           rp: String? = nil, clientOverride: [String: Any] = [:],
                           corruptSignature: Bool = false, trailing: Data = Data()) throws -> Fixture {
        let key = P256.Signing.PrivateKey()
        let challenge = SecurityKeyChallenge(value: Data(repeating: 42, count: 32), expiresAt: now.addingTimeInterval(60))
        let credential = SecurityKeyCredential(name: "Test key", relyingPartyID: app.relyingPartyID,
            credentialID: Data(repeating: 11, count: 32), publicKey: key.publicKey.x963Representation, signatureCounter: previous)
        var client: [String: Any] = ["type": "webauthn.get", "challenge": challenge.value.base64URL,
                                     "origin": app.origin, "crossOrigin": false]
        client.merge(clientOverride) { _, new in new }
        let clientData = try JSONSerialization.data(withJSONObject: client)
        var authData = Data(SHA256.hash(data: Data((rp ?? app.relyingPartyID).utf8)))
        authData.append(flags)
        authData.append(contentsOf: [UInt8(truncatingIfNeeded: counter >> 24), UInt8(truncatingIfNeeded: counter >> 16),
                                     UInt8(truncatingIfNeeded: counter >> 8), UInt8(truncatingIfNeeded: counter)])
        authData.append(trailing)
        var signature = try key.signature(for: authData + Data(SHA256.hash(data: clientData))).derRepresentation
        if corruptSignature { signature[signature.count - 1] ^= 1 }
        let json = try JSONSerialization.data(withJSONObject: [
            "type": "public-key", "authenticatorAttachment": "cross-platform",
            "id": credential.credentialID.base64URL, "rawId": credential.credentialID.base64URL,
            "response": ["clientDataJSON": clientData.base64URL, "authenticatorData": authData.base64URL,
                         "signature": signature.base64URL]
        ])
        return Fixture(json: json, credential: credential, challenge: challenge)
    }
}
