import Foundation
import XCTest
@testable import NoctweaveCore

final class CodingUTF8StorageTests: XCTestCase {
    func testCanonicalStringsPreserveEscapingNormalizationAndUTF8Runs() throws {
        let controls = String(String.UnicodeScalarView((0...31).map { UnicodeScalar($0)! }))
        let boundaryScalars: [UInt32] = [0x7F, 0x80, 0x7FF, 0x800, 0xD7FF, 0xE000, 0xFFFF, 0x10000, 0x10FFFF]
        let boundaries = String(String.UnicodeScalarView(boundaryScalars.map { UnicodeScalar($0)! }))
        let inputs = [
            "", "\"\\/", controls, boundaries,
            "e\u{301}/東京 😀\u{2028}\u{2029}",
            String(repeating: "abc123+/=", count: 8_192),
            "\"" + String(repeating: "a", count: 4_096) + "\\" + boundaries + controls + "z",
            (NSString(string: "\"e\u{301}東京\\") as String)
        ]
        for input in inputs {
            let normalized = input.precomposedStringWithCanonicalMapping
            let expected = Data(("{" + referenceJSONString(normalized) + ":"
                                 + referenceJSONString(normalized) + "}").utf8)
            let encoded = try NoctweaveCoder.encode([input: input], sortedKeys: true)
            XCTAssertEqual(encoded, expected)
            XCTAssertEqual(try NoctweaveCoder.decode([String: String].self, from: encoded),
                           [normalized: normalized])
            XCTAssertTrue(NoctweaveCanonicalJSON.isCanonical(encoded))
        }
    }

    func testPreflightRejectsEveryTruncatedPrefixOfEscapedJSON() throws {
        let valid = Data(#"{"\u0076alue":"ascii-run\n\t\uD83D\uDE00\\\"","other":"é"}"#.utf8)
        XCTAssertEqual(try NoctweaveCoder.decode([String: String].self, from: valid)["other"], "é")
        for length in 0..<valid.count {
            let truncated = Data(valid.prefix(length))
            XCTAssertThrowsError(try NoctweaveCanonicalJSON.canonicalize(truncated), "prefix \(length)")
            XCTAssertThrowsError(try NoctweaveCoder.decode([String: String].self, from: truncated), "prefix \(length)")
        }
    }

    func testBorrowedPreflightHandlesDataSlicesAndRejectsMalformedBytes() throws {
        let input = Data(#"{"value":"e\u0301/東京 😀"}"#.utf8)
        let framed = Data([0xFF, 0xFE]) + input + Data([0xFD])
        let slice = framed[2..<(2 + input.count)]
        XCTAssertEqual(slice.startIndex, 2)
        XCTAssertEqual(try NoctweaveCanonicalJSON.canonicalize(slice),
                       try NoctweaveCanonicalJSON.canonicalize(input))
        XCTAssertEqual(try NoctweaveCoder.decode([String: String].self, from: slice),
                       try NoctweaveCoder.decode([String: String].self, from: input))

        let malformed = [
            Data(), Data(#"{"value":"unclosed"#.utf8),
            Data(#"{"value":"\x"}"#.utf8),
            Data(#"{"value":"\uD800"}"#.utf8),
            Data(#"{"value":"\uDC00"}"#.utf8),
            Data(#"{"value":trueX}"#.utf8),
            Data(#"{"value":"one","\u0076alue":"two"}"#.utf8),
            Data(#"{"value":"abc"#.utf8) + Data([0x00]) + Data(#"def"}"#.utf8),
            Data(#"{"value":"abc"#.utf8) + Data([0xFF]) + Data(#"def"}"#.utf8),
            Data(#"{"abc"#.utf8) + Data([0xFF]) + Data(#"def":"value"}"#.utf8)
        ]
        for bytes in malformed {
            XCTAssertThrowsError(try NoctweaveCanonicalJSON.canonicalize(bytes))
            XCTAssertThrowsError(try NoctweaveCoder.decode([String: String].self, from: bytes))
        }
    }

    private func referenceJSONString(_ value: String) -> String {
        var result = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x22: result += "\\\""
            case 0x5C: result += "\\\\"
            case 0x08: result += "\\b"
            case 0x09: result += "\\t"
            case 0x0A: result += "\\n"
            case 0x0C: result += "\\f"
            case 0x0D: result += "\\r"
            case 0...0x1F: result += String(format: "\\u%04x", scalar.value)
            default: result.unicodeScalars.append(scalar)
            }
        }
        return result + "\""
    }
}
