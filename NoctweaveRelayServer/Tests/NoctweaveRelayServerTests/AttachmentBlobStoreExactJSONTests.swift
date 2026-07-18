import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class AttachmentBlobStoreExactJSONTests: XCTestCase {
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
