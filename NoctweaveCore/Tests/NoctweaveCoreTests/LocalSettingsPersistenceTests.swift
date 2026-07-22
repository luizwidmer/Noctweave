import Foundation
import XCTest
@testable import NoctweaveCore

final class LocalSettingsPersistenceTests: XCTestCase {
    func testLocalSettingsPersistWithoutChangingPersonaState() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweave-local-settings-\(UUID().uuidString)",
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let store = ClientStateStore(
            fileURL: root.appendingPathComponent("state.json"),
            protection: .insecurePlaintextForTesting
        )
        let initial = try ClientState(
            displayName: "Settings Test",
            createdAt: Date(timeIntervalSince1970: 1_900_200_000)
        )
        try await store.save(initial, replacing: nil)
        let client = try HeadlessMessagingClient(stateStore: store, initialState: initial)
        let personaID = initial.activePersonaID

        let appearance = AppearanceSettings(theme: .glacierDark)
        let privacy = PrivacySettings(
            secureTypingEnabled: true,
            secureTypingKeyboard: .apple,
            useSecureCameraCapture: false,
            autoDownloadAttachments: false,
            hideSensitiveWhenUnfocused: true,
            macBlockWindowCapture: true
        )
        let pin = try AppLockPINV2.makeRecord(
            pin: "284915",
            salt: Data(repeating: 0xA7, count: 32),
            rounds: AppLockPINV2.minimumCreationRounds
        )
        let appLock = AppLockSettings(
            mode: .pinOnly,
            sessionTimeoutMinutes: 15,
            lockScreenMessage: "Return through the secure entry.",
            pinSalt: pin.salt,
            pinHash: pin.encodedHash
        )

        try await client.updateAppearanceSettings(appearance)
        try await client.updatePrivacySettings(privacy)
        try await client.updateAppLockSettings(appLock)

        let saved = await client.snapshot()
        XCTAssertEqual(saved.appearance, appearance)
        XCTAssertEqual(saved.privacy, privacy)
        XCTAssertEqual(saved.appLock, appLock)
        XCTAssertEqual(saved.activePersonaID, personaID)
        XCTAssertTrue(AppLockPINV2.verify(pin: "284915", salt: pin.salt, encodedHash: pin.encodedHash))
        XCTAssertFalse(AppLockPINV2.verify(pin: "284916", salt: pin.salt, encodedHash: pin.encodedHash))

        let loaded = try await store.load()
        let reopened = try XCTUnwrap(loaded)
        XCTAssertEqual(reopened.appearance, appearance)
        XCTAssertEqual(reopened.privacy, privacy)
        XCTAssertEqual(reopened.appLock, appLock)
        XCTAssertEqual(reopened.activePersonaID, personaID)
    }

    func testInvalidAppLockUpdateFailsWithoutReplacingState() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweave-invalid-lock-\(UUID().uuidString)",
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let store = ClientStateStore(
            fileURL: root.appendingPathComponent("state.json"),
            protection: .insecurePlaintextForTesting
        )
        let initial = try ClientState(displayName: "Settings Test")
        try await store.save(initial, replacing: nil)
        let client = try HeadlessMessagingClient(stateStore: store, initialState: initial)

        do {
            try await client.updateAppLockSettings(AppLockSettings(mode: .pinOnly))
            XCTFail("A PIN mode without a configured PIN must fail closed")
        } catch {
            XCTAssertEqual(error as? HeadlessMessagingClientError, .invalidState)
        }
        let unchanged = await client.snapshot()
        XCTAssertEqual(unchanged, initial)
    }

    func testPINRecordRejectsNonASCIIAndMalformedInputs() throws {
        XCTAssertThrowsError(try AppLockPINV2.makeRecord(pin: "１２３４５６"))
        XCTAssertThrowsError(
            try AppLockPINV2.makeRecord(
                pin: "123456",
                salt: Data(repeating: 0x01, count: 8)
            )
        )
        XCTAssertFalse(
            AppLockPINV2.verify(
                pin: "123456",
                salt: Data(repeating: 0x01, count: 32),
                encodedHash: Data(repeating: 0x02, count: 41)
            )
        )
    }
}
