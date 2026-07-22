import XCTest
@testable import NoctweaveCore

final class PasswordProtectedPairingPackageV1Tests: XCTestCase {
    func testRoundTripPreservesInvitation() throws {
        let invitation = "noctweave-pair-v1:ZmFrZS1pbnZpdGF0aW9u"
        let package = try PasswordProtectedPairingPackageV1.seal(
            invitation: invitation,
            password: "correct horse battery staple"
        )

        XCTAssertEqual(
            try PasswordProtectedPairingPackageV1.open(
                package: package,
                password: "correct horse battery staple"
            ),
            invitation
        )
    }

    func testWrongPasswordAndTamperingAreRejected() throws {
        let package = try PasswordProtectedPairingPackageV1.seal(
            invitation: "noctweave-pair-v1:test",
            password: "separate secret"
        )

        XCTAssertThrowsError(
            try PasswordProtectedPairingPackageV1.open(
                package: package,
                password: "different secret"
            )
        ) { error in
            XCTAssertEqual(error as? PasswordProtectedPairingPackageV1Error, .decryptionFailed)
        }

        var corrupted = package
        corrupted[corrupted.index(before: corrupted.endIndex)] ^= 0x01
        XCTAssertThrowsError(
            try PasswordProtectedPairingPackageV1.open(
                package: corrupted,
                password: "separate secret"
            )
        )
    }

    func testSaltMakesPackagesUnlinkable() throws {
        let first = try PasswordProtectedPairingPackageV1.seal(
            invitation: "noctweave-pair-v1:test",
            password: "separate secret"
        )
        let second = try PasswordProtectedPairingPackageV1.seal(
            invitation: "noctweave-pair-v1:test",
            password: "separate secret"
        )

        XCTAssertNotEqual(first, second)
    }

    func testShortPasswordAndOversizedPackageAreRejected() {
        XCTAssertThrowsError(
            try PasswordProtectedPairingPackageV1.seal(
                invitation: "noctweave-pair-v1:test",
                password: "short"
            )
        ) { error in
            XCTAssertEqual(error as? PasswordProtectedPairingPackageV1Error, .invalidPassword)
        }

        let oversized = Data(
            repeating: 0,
            count: PasswordProtectedPairingPackageV1.maximumPackageBytes + 1
        )
        XCTAssertThrowsError(
            try PasswordProtectedPairingPackageV1.open(
                package: oversized,
                password: "separate secret"
            )
        ) { error in
            XCTAssertEqual(error as? PasswordProtectedPairingPackageV1Error, .invalidPackage)
        }
    }
}
