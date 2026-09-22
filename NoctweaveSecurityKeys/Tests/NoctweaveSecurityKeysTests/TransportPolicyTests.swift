// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
@testable import NoctweaveSecurityKeys

final class TransportPolicyTests: XCTestCase {
    func testLocalScopesNeverReachDirectHardwareTransport() async {
        for application: SecurityKeyApplication in [.noctGalleryLocal, .noctweaveLocal] {
            let client = HardwareSecurityKey()
            do {
                _ = try await client.register(application: application, name: "Test", excluding: [], pin: "", transport: .usb)
                XCTFail("Local enrollment must use its origin-bound verifier")
            } catch SecurityKeyError.unsupported {} catch { XCTFail("Unexpected error: \(error)") }
            do {
                _ = try await client.authenticate(application: application, credentials: [], pin: "", transport: .usb)
                XCTFail("Local authentication must use its origin-bound verifier")
            } catch SecurityKeyError.unsupported {} catch { XCTFail("Unexpected error: \(error)") }
        }
    }

    func testUSBOnlyClientRejectsNFCRegistrationBeforeConnecting() async {
        let client = HardwareSecurityKey(allowedTransports: [.usb])
        do {
            _ = try await client.register(application: .noctGallery, name: "Test key",
                                          excluding: [], pin: "test-only", transport: .nfc)
            XCTFail("A disabled transport must never start registration")
        } catch SecurityKeyError.unsupported {
            // Transport policy rejects the request before opening hardware.
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testUSBOnlyClientRejectsNFCAuthenticationBeforeConnecting() async {
        let client = HardwareSecurityKey(allowedTransports: [.usb])
        do {
            _ = try await client.authenticate(application: .noctGallery, credentials: [],
                                              pin: "test-only", transport: .nfc)
            XCTFail("A disabled transport must never start authentication")
        } catch SecurityKeyError.unsupported {
            // Even invalid credentials cannot cause the disabled transport to open.
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}
