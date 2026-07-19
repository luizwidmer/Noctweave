import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class AttachmentBlobStoreExactJSONTests: XCTestCase {
    func testExternalRecordRequiresExactValidCurrentSchema() throws {
        let record = AttachmentExternalRecord(
            backend: "ipfs",
            locator: "bafyexactrecord000000000000",
            byteCount: 512,
            sha256Hex: String(repeating: "a", count: 64),
            expiresAt: Date(timeIntervalSince1970: 2_000_000_000)
        )
        let encoded = try RelayCodec.encoder(sortedKeys: true).encode(record)
        XCTAssertEqual(try RelayCodec.decoder().decode(AttachmentExternalRecord.self, from: encoded), record)

        var unknown = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        unknown["legacy"] = true
        XCTAssertThrowsError(
            try RelayCodec.decoder().decode(
                AttachmentExternalRecord.self,
                from: JSONSerialization.data(withJSONObject: unknown, options: [.sortedKeys])
            )
        )

        var missing = unknown
        missing.removeValue(forKey: "legacy")
        missing.removeValue(forKey: "locator")
        XCTAssertThrowsError(
            try RelayCodec.decoder().decode(
                AttachmentExternalRecord.self,
                from: JSONSerialization.data(withJSONObject: missing, options: [.sortedKeys])
            )
        )

        let invalid = AttachmentExternalRecord(
            backend: "ipfs",
            locator: "../not-a-cid",
            byteCount: 512,
            sha256Hex: String(repeating: "a", count: 64),
            expiresAt: Date()
        )
        XCTAssertFalse(invalid.isStructurallyValid)
        XCTAssertThrowsError(try RelayCodec.encoder().encode(invalid))
    }

    func testIPFSCIDResponseRejectsAmbiguousJSON() {
        for input in [
            #"{"Hash":"bafyfirstvalue00000","Hash":"bafysecondvalue0000"}"#,
            #"{"Hash":"bafyfirstvalue00000","\u0048ash":"bafysecondvalue0000"}"#,
            #"{"Hash":"bafyfirstvalue00000","nested":{"x":1,"x":2}}"#
        ] {
            XCTAssertNil(IPFSAttachmentBlobStore.decodeCID(from: Data(input.utf8)))
        }
    }

    func testIPFSCIDResponseAcceptsExactWholeAndLineDelimitedJSON() {
        XCTAssertEqual(
            IPFSAttachmentBlobStore.decodeCID(
                from: Data(#"{"Name":"chunk","Hash":"bafywholevalue000000"}"#.utf8)
            ),
            "bafywholevalue000000"
        )
        XCTAssertEqual(
            IPFSAttachmentBlobStore.decodeCID(
                from: Data(
                    "{\"Name\":\"progress\"}\n{\"Hash\":\"bafylinevalue0000000\"}\n".utf8
                )
            ),
            "bafylinevalue0000000"
        )
    }

    func testIPFSCIDResponseRejectsInvalidUTF8() {
        XCTAssertNil(IPFSAttachmentBlobStore.decodeCID(from: Data([0xFF, 0xFE, 0xFD])))
    }
}
