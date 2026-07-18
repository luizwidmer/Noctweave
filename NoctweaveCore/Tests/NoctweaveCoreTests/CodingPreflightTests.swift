import Foundation
import XCTest
@testable import NoctweaveCore

final class CodingPreflightTests: XCTestCase {
    private struct ValidProbe: Decodable, Equatable {
        let value: Int
        let createdAt: Date
    }

    private struct ObjectPair: Decodable, Equatable {
        struct Member: Decodable, Equatable {
            let value: Int
        }

        let left: Member
        let right: Member
    }

    func testValidJSONPreservesDateAndEscapedKeyDecoding() throws {
        let probe = try NoctweaveCoder.decode(
            ValidProbe.self,
            from: Data(#"{"value":7,"createdAt":"2026-07-18T12:00:00Z"}"#.utf8)
        )
        XCTAssertEqual(probe.value, 7)
        XCTAssertEqual(
            probe.createdAt,
            ISO8601DateFormatter().date(from: "2026-07-18T12:00:00Z")
        )

        let escaped = try NoctweaveCoder.decode(
            [String: Int].self,
            from: Data(#"{"\u0076alue":9}"#.utf8)
        )
        XCTAssertEqual(escaped, ["value": 9])
    }

    func testSameKeyInDifferentObjectsRemainsValid() throws {
        let decoded = try NoctweaveCoder.decode(
            ObjectPair.self,
            from: Data(#"{"left":{"value":1},"right":{"value":2}}"#.utf8)
        )
        XCTAssertEqual(decoded.left.value, 1)
        XCTAssertEqual(decoded.right.value, 2)
    }

    func testRejectsLiteralDuplicateObjectKeys() {
        assertPreflightRejects(
            Data(#"{"value":1,"value":2}"#.utf8),
            containing: "duplicate object key"
        )
    }

    func testRejectsEscapedEquivalentObjectKeys() {
        let inputs = [
            #"{"value":1,"\u0076alue":2}"#,
            #"{"/":1,"\/":2}"#,
            #"{"😀":1,"\uD83D\uDE00":2}"#,
            #"{"é":1,"e\u0301":2}"#
        ]

        for input in inputs {
            assertPreflightRejects(
                Data(input.utf8),
                containing: "duplicate object key"
            )
        }
    }

    func testRejectsJSONBeyondMaximumNestingDepth() {
        let depth = NoctweaveCoder.maximumJSONNestingDepth + 1
        let input = String(repeating: "[", count: depth)
            + "0"
            + String(repeating: "]", count: depth)

        assertPreflightRejects(
            Data(input.utf8),
            containing: "maximum depth of \(NoctweaveCoder.maximumJSONNestingDepth)"
        )
    }

    func testRejectsUTF8ByteOrderMark() {
        assertPreflightRejects(
            Data([0xEF, 0xBB, 0xBF]) + Data(#"{"value":1}"#.utf8),
            containing: "malformed input"
        )
    }

    func testRejectsUnpairedUnicodeSurrogates() throws {
        for input in [#"{"value":"\uD800"}"#, #"{"value":"\uDC00"}"#] {
            assertPreflightRejects(Data(input.utf8), containing: "malformed input")
        }
        XCTAssertEqual(
            try NoctweaveCoder.decode(
                [String: String].self,
                from: Data(#"{"value":"\uD83D\uDE00"}"#.utf8)
            ),
            ["value": "😀"]
        )
    }

    private func assertPreflightRejects(
        _ data: Data,
        containing expectedDescription: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try NoctweaveCoder.decode([String: Int].self, from: data),
            file: file,
            line: line
        ) { error in
            guard case DecodingError.dataCorrupted(let context) = error else {
                return XCTFail("Expected dataCorrupted, got \(error)", file: file, line: line)
            }
            XCTAssertTrue(
                context.debugDescription.contains(expectedDescription),
                context.debugDescription,
                file: file,
                line: line
            )
        }
    }
}
