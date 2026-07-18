import Foundation
import XCTest
@testable import NoctweaveCore

final class GroupScopedHandleStrictTests: XCTestCase {
    func testMemberHandleRequiresExactValidCurrentSchema() throws {
        try assertExactHandle(
            GroupScopedMemberHandleV2.generate(),
            decode: { try NoctweaveCoder.decode(GroupScopedMemberHandleV2.self, from: $0) },
            invalid: GroupScopedMemberHandleV2(rawValue: "not-a-handle")
        )
    }

    func testCredentialHandleRequiresExactValidCurrentSchema() throws {
        try assertExactHandle(
            GroupScopedCredentialHandleV2.generate(),
            decode: { try NoctweaveCoder.decode(GroupScopedCredentialHandleV2.self, from: $0) },
            invalid: GroupScopedCredentialHandleV2(rawValue: "not-a-handle")
        )
    }

    private func assertExactHandle<Handle: Codable & Equatable>(
        _ handle: Handle,
        decode: (Data) throws -> Handle,
        invalid: Handle,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let encoded = try NoctweaveCoder.encode(handle, sortedKeys: true)
        XCTAssertEqual(try decode(encoded), handle, file: file, line: line)

        var unknown = try jsonObject(encoded)
        unknown["legacy"] = true
        XCTAssertThrowsError(try decode(try jsonData(unknown)), file: file, line: line)

        var missing = try jsonObject(encoded)
        missing.removeValue(forKey: "rawValue")
        XCTAssertThrowsError(try decode(try jsonData(missing)), file: file, line: line)

        XCTAssertThrowsError(
            try NoctweaveCoder.encode(invalid),
            file: file,
            line: line
        )
    }

    private func jsonObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func jsonData(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
}
