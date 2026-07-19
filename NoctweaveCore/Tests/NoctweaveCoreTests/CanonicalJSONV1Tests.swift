import Foundation
import XCTest
@testable import NoctweaveCore

final class CanonicalJSONV1Tests: XCTestCase {
    func testSharedCanonicalCases() throws {
        let vectors = try loadVectors()
        XCTAssertEqual(vectors.profile, "ncj-1")

        for vector in vectors.canonicalCases {
            let input = Data(vector.input.utf8)
            let expected = Data(vector.canonical.utf8)
            XCTAssertEqual(
                try NoctweaveCanonicalJSON.canonicalize(input),
                expected,
                vector.name
            )
            XCTAssertTrue(NoctweaveCanonicalJSON.isCanonical(expected), vector.name)
        }
    }

    func testSharedRejectedCases() throws {
        for vector in try loadVectors().rejectedCases {
            XCTAssertThrowsError(
                try NoctweaveCanonicalJSON.canonicalize(Data(vector.input.utf8)),
                vector.name
            )
        }
    }

    func testSortedProtocolEncodingUsesNCJ1() throws {
        struct Example: Encodable {
            let z: String
            let a: [Int]
        }

        let bytes = try NoctweaveCoder.encode(
            Example(z: "e\u{301}/path", a: [2, 1]),
            sortedKeys: true
        )
        XCTAssertEqual(
            String(decoding: bytes, as: UTF8.self),
            #"{"a":[2,1],"z":"é/path"}"#
        )
        XCTAssertTrue(NoctweaveCanonicalJSON.isCanonical(bytes))
    }

    private func loadVectors() throws -> CanonicalJSONSharedVectors {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let vectorURL = repositoryRoot.appendingPathComponent(
            "NoctweaveDocumentation/test_vectors/canonical_json_v1.json"
        )
        return try JSONDecoder().decode(
            CanonicalJSONSharedVectors.self,
            from: Data(contentsOf: vectorURL)
        )
    }
}

private struct CanonicalJSONSharedVectors: Decodable {
    struct CanonicalCase: Decodable {
        let name: String
        let input: String
        let canonical: String
    }

    struct RejectedCase: Decodable {
        let name: String
        let input: String
    }

    let profile: String
    let canonicalCases: [CanonicalCase]
    let rejectedCases: [RejectedCase]
}
