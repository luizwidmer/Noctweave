import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class RelayWireExactEnvelopeTests: XCTestCase {
    func testHealthEnvelopeIsExactAndCorrelated() throws {
        let requestID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
        let request = RelayRequest.health(requestID: requestID)
        let requestObject = try object(RelayCodec.encoder().encode(request))
        XCTAssertEqual(Set(requestObject.keys), ["requestID", "module", "version", "method", "body", "authToken"])
        XCTAssertEqual(requestObject["requestID"] as? String, requestID.uuidString)
        XCTAssertEqual(requestObject["module"] as? String, "nw.core")
        XCTAssertEqual(requestObject["version"] as? Int, 2)
        XCTAssertEqual(requestObject["method"] as? String, "health")
        XCTAssertEqual((requestObject["body"] as? [String: Any])?.count, 0)
        XCTAssertTrue(requestObject["authToken"] is NSNull)

        let response = RelayResponse.success(.empty, respondingTo: request)
        let responseObject = try object(RelayCodec.encoder().encode(response))
        XCTAssertEqual(Set(responseObject.keys), ["requestID", "module", "version", "method", "status", "body", "error"])
        XCTAssertTrue(responseObject["error"] is NSNull)
        XCTAssertTrue(try RelayCodec.decodeWire(RelayResponse.self, from: RelayCodec.encoder().encode(response)).isResponse(to: request))
    }

    func testRequestRejectsOldShapeUnknownFieldsAndBindingMismatches() throws {
        XCTAssertThrowsError(
            try RelayCodec.decodeWire(
                RelayRequest.self,
                from: Data(#"{"type":"health"}"#.utf8)
            )
        )

        var encoded = try object(RelayCodec.encoder().encode(RelayRequest.health()))
        encoded["legacy"] = true
        XCTAssertThrowsError(try decodeRequest(encoded))

        encoded.removeValue(forKey: "legacy")
        encoded["body"] = ["ok": true]
        XCTAssertThrowsError(try decodeRequest(encoded))

        encoded["body"] = [String: Any]()
        encoded["version"] = 1
        XCTAssertThrowsError(try decodeRequest(encoded))

        encoded["version"] = 2
        encoded["module"] = "nw.blobs"
        XCTAssertThrowsError(try decodeRequest(encoded))
    }

    func testErrorBranchesAreBoundedExactAndExclusive() throws {
        let request = RelayRequest.info()
        let response = RelayResponse.error(
            String(repeating: "x", count: RelayErrorBody.maximumMessageBytes + 1),
            code: .internalFailure,
            retryable: true,
            respondingTo: request
        )
        XCTAssertEqual(response.error?.message, "Relay request failed")
        var encoded = try object(RelayCodec.encoder().encode(response))
        XCTAssertTrue(encoded["body"] is NSNull)
        let error = try XCTUnwrap(encoded["error"] as? [String: Any])
        XCTAssertEqual(Set(error.keys), ["code", "message", "retryable"])

        encoded["body"] = [String: Any]()
        XCTAssertThrowsError(try decodeResponse(encoded))

        var malformed = try object(RelayCodec.encoder().encode(response))
        var malformedError = error
        malformedError["details"] = "not allowed"
        malformed["error"] = malformedError
        XCTAssertThrowsError(try decodeResponse(malformed))
    }

    func testRawWireDecoderRejectsRepeatedAndEscapedEquivalentMemberNames() throws {
        let repeatedRequest = Data(#"{"requestID":"11111111-2222-3333-4444-555555555555","module":"nw.core","version":2,"method":"health","method":"info","body":{},"authToken":null}"#.utf8)
        assertWireDecodeRejects(repeatedRequest, as: RelayRequest.self, containing: "duplicate object member")

        let escapedRequest = Data(#"{"requestID":"11111111-2222-3333-4444-555555555555","module":"nw.core","version":2,"method":"health","\u006dethod":"info","body":{},"authToken":null}"#.utf8)
        assertWireDecodeRejects(escapedRequest, as: RelayRequest.self, containing: "duplicate object member")

        let escapedResponse = Data(#"{"requestID":"11111111-2222-3333-4444-555555555555","module":"nw.core","version":2,"method":"health","status":"success","body":{},"\u0062ody":{},"error":null}"#.utf8)
        assertWireDecodeRejects(escapedResponse, as: RelayResponse.self, containing: "duplicate object member")
    }

    func testRawWireDecoderRejectsNestedDuplicatesAndExcessiveNesting() throws {
        let nestedDuplicate = Data(#"{"requestID":"11111111-2222-3333-4444-555555555555","module":"nw.core","version":2,"method":"health","body":{"x":null,"\u0078":null},"authToken":null}"#.utf8)
        assertWireDecodeRejects(nestedDuplicate, as: RelayRequest.self, containing: "duplicate object member")

        let nestedPrefix = String(repeating: #"{"x":"#, count: 129)
        let nestedSuffix = String(repeating: "}", count: 129)
        let tooDeep = Data(#"{"requestID":"11111111-2222-3333-4444-555555555555","module":"nw.core","version":2,"method":"health","body":\#(nestedPrefix){}\#(nestedSuffix),"authToken":null}"#.utf8)
        assertWireDecodeRejects(tooDeep, as: RelayRequest.self, containing: "maximum nesting depth")
    }

    func testRawWireDecoderPreservesValidEscapedMemberNames() throws {
        let escapedUniqueKey = Data(#"{"requestID":"11111111-2222-3333-4444-555555555555","m\u006fdule":"nw.core","version":2,"method":"health","body":{},"authToken":null}"#.utf8)
        let decoded = try RelayCodec.decodeWire(RelayRequest.self, from: escapedUniqueKey)
        XCTAssertEqual(decoded.binding, .init(module: .core, version: 2, method: .health))
    }

    func testRawWireDecoderRejectsUTF8ByteOrderMark() {
        let request = Data([0xEF, 0xBB, 0xBF])
            + Data(#"{"requestID":"11111111-2222-3333-4444-555555555555","module":"nw.core","version":2,"method":"health","body":{},"authToken":null}"#.utf8)
        assertWireDecodeRejects(request, as: RelayRequest.self, containing: "invalid value")
    }

    private func object(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func decodeRequest(_ value: [String: Any]) throws -> RelayRequest {
        try RelayCodec.decodeWire(
            RelayRequest.self,
            from: JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        )
    }

    private func decodeResponse(_ value: [String: Any]) throws -> RelayResponse {
        try RelayCodec.decodeWire(
            RelayResponse.self,
            from: JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        )
    }

    private func assertWireDecodeRejects<T: Decodable>(
        _ data: Data,
        as type: T.Type,
        containing expected: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try RelayCodec.decodeWire(type, from: data),
            file: file,
            line: line
        ) { error in
            XCTAssertTrue(
                String(describing: error).contains(expected),
                "Expected \(error) to contain \(expected)",
                file: file,
                line: line
            )
        }
    }
}
