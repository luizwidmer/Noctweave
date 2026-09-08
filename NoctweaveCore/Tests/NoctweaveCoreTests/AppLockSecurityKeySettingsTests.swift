import XCTest
@testable import NoctweaveCore

final class AppLockSecurityKeySettingsTests: XCTestCase {
    func testEveryFactorCombinationRequiresAllItsChecks() {
        XCTAssertEqual(AppLockMode.allCases.count, 8)
        XCTAssertEqual(Set(AppLockMode.allCases.map(\.requiredFactors)).count, 8)
        for mode in AppLockMode.allCases {
            XCTAssertTrue(mode.accepts(completedFactors: mode.requiredFactors))
            for required in mode.requiredFactors {
                XCTAssertFalse(mode.accepts(completedFactors: mode.requiredFactors.subtracting([required])),
                               "\(mode) must require \(required)")
            }
            var settings = AppLockSettings(mode: mode, securityKeys: mode.requiresSecurityKey ? [record()] : [])
            if mode.requiresPIN { settings.pinSalt = Data(repeating: 1, count: 16); settings.pinHash = Data(repeating: 2, count: 32) }
            XCTAssertTrue(settings.isStructurallyValid)
            if mode.requiresPIN { settings.pinHash = nil; XCTAssertFalse(settings.isStructurallyValid) }
        }
    }

    func testContinuousPresenceRequiresAKeyModeAndRoundTripsWithoutChangingLegacyEncoding() throws {
        XCTAssertFalse(AppLockSettings(requireSecurityKeyPresence: true).isStructurallyValid)
        let protected = AppLockSettings(mode: .securityKey, securityKeys: [record()], requireSecurityKeyPresence: true)
        XCTAssertEqual(try JSONDecoder().decode(AppLockSettings.self, from: JSONEncoder().encode(protected)), protected)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(AppLockSettings())) as? [String: Any])
        XCTAssertNil(object["requireSecurityKeyPresence"])
        object["requireSecurityKeyPresence"] = NSNull()
        XCTAssertThrowsError(try JSONDecoder().decode(AppLockSettings.self, from: JSONSerialization.data(withJSONObject: object)))
    }

    private func record() -> AppLockSecurityKeyRecordV1 {
        .init(name: "Spare key", credentialID: Data(repeating: 7, count: 32),
              publicKey: Data([4]) + Data(repeating: 1, count: 64), signatureCounter: 10)
    }

    func testExistingSettingsKeepExactEncodingAndDecodeWithoutSecurityKeys() throws {
        let data = try JSONEncoder().encode(AppLockSettings())
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertNil(object["securityKeys"])
        XCTAssertEqual(try JSONDecoder().decode(AppLockSettings.self, from: data), AppLockSettings())
        for field in object.keys {
            var missing = object
            missing.removeValue(forKey: field)
            XCTAssertThrowsError(try JSONDecoder().decode(AppLockSettings.self,
                from: JSONSerialization.data(withJSONObject: missing)), field)
        }
    }

    func testKeyModeRoundTripsAndRequiresARegisteredKey() throws {
        XCTAssertThrowsError(try JSONEncoder().encode(AppLockSettings(mode: .securityKey)))
        let settings = AppLockSettings(mode: .securityKey, securityKeys: [record()])
        XCTAssertEqual(try JSONDecoder().decode(AppLockSettings.self, from: JSONEncoder().encode(settings)), settings)
    }

    func testRejectsDuplicateOrMalformedKeysAndUnknownSettings() throws {
        let key = record()
        XCTAssertFalse(AppLockSettings(mode: .securityKey, securityKeys: [key, key]).isStructurallyValid)
        var duplicate = key; duplicate.id = UUID()
        XCTAssertFalse(AppLockSettings(securityKeys: [key, duplicate]).isStructurallyValid)
        var invalid = key; invalid.publicKey = Data(repeating: 0, count: 65)
        XCTAssertFalse(AppLockSettings(securityKeys: [invalid]).isStructurallyValid)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(AppLockSettings())) as? [String: Any])
        object["securityKeys"] = NSNull()
        XCTAssertThrowsError(try JSONDecoder().decode(AppLockSettings.self, from: JSONSerialization.data(withJSONObject: object)))
        object.removeValue(forKey: "securityKeys"); object["fallback"] = true
        XCTAssertThrowsError(try JSONDecoder().decode(AppLockSettings.self, from: JSONSerialization.data(withJSONObject: object)))
    }
}
