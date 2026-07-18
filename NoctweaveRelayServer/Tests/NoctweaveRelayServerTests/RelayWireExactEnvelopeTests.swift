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
        XCTAssertTrue(try RelayCodec.decoder().decode(RelayResponse.self, from: RelayCodec.encoder().encode(response)).isResponse(to: request))
    }

    func testRequestRejectsOldShapeUnknownFieldsAndBindingMismatches() throws {
        XCTAssertThrowsError(
            try RelayCodec.decoder().decode(
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

    private func object(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func decodeRequest(_ value: [String: Any]) throws -> RelayRequest {
        try RelayCodec.decoder().decode(
            RelayRequest.self,
            from: JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        )
    }

    private func decodeResponse(_ value: [String: Any]) throws -> RelayResponse {
        try RelayCodec.decoder().decode(
            RelayResponse.self,
            from: JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        )
    }
}
