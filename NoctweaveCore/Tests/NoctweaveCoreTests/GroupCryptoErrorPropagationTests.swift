import CryptoKit
import XCTest
@testable import NoctweaveCore

final class GroupCryptoErrorPropagationTests: XCTestCase {
    func testKeyPairConstructorsRejectGenuineMismatchesAsInvalidPrivateKeys() throws {
        let signingA = try SigningKeyPair.generate()
        let signingB = try SigningKeyPair.generate()
        XCTAssertThrowsError(try SigningKeyPair(
            privateKeyData: signingA.privateKeyData,
            publicKeyData: signingB.publicKeyData
        )) { error in
            XCTAssertEqual(error as? CryptoError, .invalidPrivateKey)
        }

        let agreementA = try AgreementKeyPair.generate()
        let agreementB = try AgreementKeyPair.generate()
        XCTAssertThrowsError(try AgreementKeyPair(
            privateKeyData: agreementA.privateKeyData,
            publicKeyData: agreementB.publicKeyData
        )) { error in
            XCTAssertEqual(error as? CryptoError, .invalidPrivateKey)
        }
    }

    func testLocalGroupCredentialOffersThrowingAndDiagnosticPreflights() throws {
        let valid = LocalGroupCredentialV2(
            groupId: UUID(),
            memberHandle: .generate(),
            credentialHandle: .generate(),
            admissionDigest: Data(SHA256.hash(data: Data("admission".utf8))),
            signingKey: try SigningKeyPair.generate(),
            agreementKey: try AgreementKeyPair.generate()
        )
        XCTAssertTrue(try valid.isStructurallyValidThrowing)
        XCTAssertTrue(valid.isStructurallyValid)

        let malformed = LocalGroupCredentialV2(
            groupId: valid.groupId,
            memberHandle: valid.memberHandle,
            credentialHandle: valid.credentialHandle,
            admissionDigest: Data([0x01]),
            signingKey: valid.signingKey,
            agreementKey: valid.agreementKey
        )
        XCTAssertFalse(try malformed.isStructurallyValidThrowing)
        XCTAssertFalse(malformed.isStructurallyValid)
    }
}
