import CryptoKit
import Foundation
import XCTest
#if canImport(Security)
import Security
#endif
@testable import NoctweaveCore

final class AppLockDuressTests: XCTestCase {
    #if canImport(Security)
    func testScopedKeyDeletionRemovesKeychainItemAndPreventsProcessRecreation() throws {
        let service = "org.noctweave.tests.duress.\(UUID().uuidString)"
        let account = "disposable-key"
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any]
        defer { SecItemDelete(query as CFDictionary) }
        _ = try SecureStorageKeyProvider.shared.loadOrCreateKey(service: service, account: account)
        try SecureStorageKeyProvider.shared.destroyKey(service: service, account: account)
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, nil), errSecItemNotFound)
        SecureStorageKeyProvider.shared.clearProcessCache()
        XCTAssertThrowsError(try SecureStorageKeyProvider.shared.loadOrCreateKey(service: service, account: account))
    }
    #endif
    func testOrdinaryFactorsRequireKeyThenBiometricsThenPINForEveryMode() {
        for mode in AppLockMode.allCases {
            var completed = Set<AppLockFactor>()
            for factor in mode.orderedFactors {
                XCTAssertTrue(mode.canAttempt(factor, completedFactors: completed))
                for later in mode.orderedFactors.drop(while: { $0 != factor }).dropFirst() {
                    XCTAssertFalse(mode.canAttempt(later, completedFactors: completed))
                }
                completed.insert(factor)
            }
            XCTAssertTrue(mode.accepts(completedFactors: completed))
        }
        XCTAssertEqual(AppLockMode.biometricsPinAndSecurityKey.orderedFactors, [.securityKey, .biometrics, .pin])
    }

    func testDuressVerifierIsIndependentOfUnlockFactorsAndRejectsWrongPassword() throws {
        let plan = try AppLockDuressPassword.makePlan(password: "654321", label: "Test", action: .decoy)
        XCTAssertTrue(AppLockDuressPassword.matches("654321", plan: plan))
        XCTAssertFalse(AppLockDuressPassword.matches("654320", plan: plan))
        XCTAssertFalse(AppLockDuressPassword.matches("", plan: plan))
        let restored = try JSONDecoder().decode(AppLockDuressPlan.self, from: JSONEncoder().encode(plan))
        XCTAssertEqual(plan, restored)
        var bad = plan; bad.salt = Data([1])
        XCTAssertThrowsError(try JSONEncoder().encode(bad))
        XCTAssertFalse(AppLockDuressPassword.isValid(String(repeating: "x", count: 129)))
        XCTAssertFalse(AppLockDuressPassword.isValid("123\n456"))
    }

    func testDuressPlansAreOptionalBoundedAndCannotEnableAnOffLock() throws {
        let plan = AppLockDuressPlan(label: "Test", salt: Data(repeating: 1, count: 32),
                                    verifier: Data(repeating: 2, count: 32), action: .decoy)
        XCTAssertFalse(AppLockSettings(duressPlans: [plan]).isStructurallyValid)
        var settings = AppLockSettings(mode: .biometrics, duressPlans: [plan])
        XCTAssertTrue(settings.isStructurallyValid)
        XCTAssertEqual(try JSONDecoder().decode(AppLockSettings.self, from: JSONEncoder().encode(settings)), settings)
        settings.duressPlans.append(plan)
        XCTAssertFalse(settings.isStructurallyValid)
        let legacy = try JSONEncoder().encode(AppLockSettings())
        XCTAssertFalse(String(decoding: legacy, as: UTF8.self).contains("duressPlans"))
    }

    func testKeyDestructionRetainsCiphertextAndRejectsLateWrites() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("noctweave-duress-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("state.nwstate")
        let anchor = VolatileClientStateRollbackAnchorStore()
        let key = SymmetricKey(size: .bits256)
        let store = ClientStateStore(fileURL: file, encryptionKey: key, rollbackAnchorStore: anchor)
        let state = try ClientState(displayName: "Disposable")
        try await store.save(state, replacing: nil)
        let ciphertext = try Data(contentsOf: file)
        try await store.destroyLocalEncryptionMaterial(preservingCiphertext: true)
        XCTAssertEqual(try Data(contentsOf: file), ciphertext)
        do { _ = try await store.load(); XCTFail("Retired store decrypted") } catch { }
        do { try await store.save(state, replacing: state); XCTFail("Retired writer recreated state") } catch { }
        let fresh = ClientStateStore(fileURL: file, encryptionKey: SymmetricKey(size: .bits256), rollbackAnchorStore: anchor)
        do { _ = try await fresh.load(); XCTFail("Different key decrypted") } catch { }
        // The caller deliberately retains the injected fixture key; copies outside
        // a store's authority are explicitly not covered by local key destruction.
    }

    func testWipeRemovesCiphertextAndPreventsRecreation() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("noctweave-duress-wipe-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("state.nwstate")
        let store = ClientStateStore(fileURL: file, encryptionKey: SymmetricKey(size: .bits256),
                                     rollbackAnchorStore: VolatileClientStateRollbackAnchorStore())
        let state = try ClientState(displayName: "Disposable")
        try await store.save(state, replacing: nil)
        try await store.destroyLocalEncryptionMaterial(preservingCiphertext: false)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
        do { try await store.save(state, replacing: nil); XCTFail("Retired writer recreated state") } catch { }
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }
}
