import Foundation
import XCTest
@testable import NoctweaveCore

final class RelayWireExactEnvelopeTests: XCTestCase {
    func testCoreHealthRequestUsesExactBoundEnvelope() throws {
        let requestID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
        let request = RelayRequest.health(requestID: requestID)
        let data = try NoctweaveCoder.encode(request)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(Set(object.keys), ["requestID", "module", "version", "method", "body", "authToken"])
        XCTAssertEqual(object["requestID"] as? String, requestID.uuidString)
        XCTAssertEqual(object["module"] as? String, "nw.core")
        XCTAssertEqual(object["version"] as? Int, 2)
        XCTAssertEqual(object["method"] as? String, "health")
        XCTAssertEqual((object["body"] as? [String: Any])?.count, 0)
        XCTAssertTrue(object["authToken"] is NSNull)
        XCTAssertEqual(try NoctweaveCoder.decode(RelayRequest.self, from: data), request)
    }

    func testRequestRejectsUnknownMissingAndMismatchedFields() throws {
        let encoded = try NoctweaveCoder.encode(RelayRequest.health())
        let base = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])

        var extraTopLevel = base
        extraTopLevel["type"] = "health"
        XCTAssertThrowsError(try decodeRequest(extraTopLevel))

        var missingAuth = base
        missingAuth.removeValue(forKey: "authToken")
        XCTAssertThrowsError(try decodeRequest(missingAuth))

        var extraBody = base
        extraBody["body"] = ["legacy": true]
        XCTAssertThrowsError(try decodeRequest(extraBody))

        var wrongVersion = base
        wrongVersion["version"] = 1
        XCTAssertThrowsError(try decodeRequest(wrongVersion))

        var wrongMethod = base
        wrongMethod["method"] = "append"
        XCTAssertThrowsError(try decodeRequest(wrongMethod))

        var wrongModule = base
        wrongModule["module"] = "nw.blobs"
        XCTAssertThrowsError(try decodeRequest(wrongModule))
    }

    func testOptionalRequestFieldsAreExplicitNulls() throws {
        let request = RelayRequest.listFederationNodes(ListFederationNodesRequest())
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: NoctweaveCoder.encode(request)) as? [String: Any]
        )
        let body = try XCTUnwrap(object["body"] as? [String: Any])
        XCTAssertEqual(
            Set(body.keys),
            ["mode", "federationName", "onlyHealthy", "maxStalenessSeconds", "requireSignedSnapshot"]
        )
        XCTAssertTrue(body.values.allSatisfy { $0 is NSNull })
    }

    func testAttachmentUploadRequiresExactBoundedEncryptedPayload() throws {
        let request = RelayRequest.uploadAttachment(
            UploadAttachmentRequest(
                attachmentId: UUID(),
                chunkIndex: 0,
                payload: EncryptedPayload(
                    nonce: Data(repeating: 0x11, count: EncryptedPayload.nonceByteCount),
                    ciphertext: Data([0x22]),
                    tag: Data(repeating: 0x33, count: EncryptedPayload.tagByteCount)
                )
            )
        )
        let encoded = try NoctweaveCoder.encode(request)
        let base = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        XCTAssertEqual(try NoctweaveCoder.decode(RelayRequest.self, from: encoded), request)

        var unknown = base
        var unknownBody = try XCTUnwrap(unknown["body"] as? [String: Any])
        var unknownPayload = try XCTUnwrap(unknownBody["payload"] as? [String: Any])
        unknownPayload["legacy"] = true
        unknownBody["payload"] = unknownPayload
        unknown["body"] = unknownBody
        XCTAssertThrowsError(try decodeRequest(unknown))

        var missing = base
        var missingBody = try XCTUnwrap(missing["body"] as? [String: Any])
        var missingPayload = try XCTUnwrap(missingBody["payload"] as? [String: Any])
        missingPayload.removeValue(forKey: "tag")
        missingBody["payload"] = missingPayload
        missing["body"] = missingBody
        XCTAssertThrowsError(try decodeRequest(missing))

        var malformed = base
        var malformedBody = try XCTUnwrap(malformed["body"] as? [String: Any])
        var malformedPayload = try XCTUnwrap(malformedBody["payload"] as? [String: Any])
        malformedPayload["nonce"] = Data(repeating: 0x11, count: 11).base64EncodedString()
        malformedBody["payload"] = malformedPayload
        malformed["body"] = malformedBody
        XCTAssertThrowsError(try decodeRequest(malformed))

        let empty = EncryptedPayload(
            nonce: Data(repeating: 0x11, count: EncryptedPayload.nonceByteCount),
            ciphertext: Data(),
            tag: Data(repeating: 0x33, count: EncryptedPayload.tagByteCount)
        )
        XCTAssertFalse(empty.isStructurallyValid)
        XCTAssertThrowsError(try NoctweaveCoder.encode(empty))

        let oversized = EncryptedPayload(
            nonce: Data(repeating: 0x11, count: EncryptedPayload.nonceByteCount),
            ciphertext: Data(
                repeating: 0x22,
                count: EncryptedPayload.maximumCiphertextBytes + 1
            ),
            tag: Data(repeating: 0x33, count: EncryptedPayload.tagByteCount)
        )
        XCTAssertFalse(oversized.isStructurallyValid)
        XCTAssertThrowsError(try NoctweaveCoder.encode(oversized))
    }

    func testOpenDiscoveryExclusivelyOwnsDHTBindings() throws {
        XCTAssertTrue(
            RelayOperationBinding(module: .federation, version: 1, method: .register).isCurrent
        )
        XCTAssertTrue(
            RelayOperationBinding(module: .federation, version: 1, method: .list).isCurrent
        )
        XCTAssertFalse(
            RelayOperationBinding(module: .federation, version: 1, method: .publishDHT).isCurrent
        )
        XCTAssertFalse(
            RelayOperationBinding(module: .federation, version: 1, method: .listDHT).isCurrent
        )
        XCTAssertTrue(
            RelayOperationBinding(module: .openDiscovery, version: 1, method: .publishDHT).isCurrent
        )
        XCTAssertTrue(
            RelayOperationBinding(module: .openDiscovery, version: 1, method: .listDHT).isCurrent
        )

        let request = RelayRequest.listOpenFederationDHTRecords(
            ListOpenFederationDHTRecordsRequest(namespace: "noctweave/open/example", limit: 4)
        )
        XCTAssertEqual(
            request.binding,
            RelayOperationBinding(module: .openDiscovery, version: 1, method: .listDHT)
        )
        let data = try NoctweaveCoder.encode(request)
        XCTAssertEqual(try NoctweaveCoder.decode(RelayRequest.self, from: data), request)

        var wrongModule = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        wrongModule["module"] = "nw.federation"
        XCTAssertThrowsError(try decodeRequest(wrongModule))
    }

    func testResponseIsExactAndBoundToItsRequest() throws {
        let request = RelayRequest.health()
        let response = RelayResponse.success(.empty, respondingTo: request)
        let data = try NoctweaveCoder.encode(response)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(Set(object.keys), ["requestID", "module", "version", "method", "status", "body", "error"])
        XCTAssertEqual(object["requestID"] as? String, request.requestID.uuidString)
        XCTAssertEqual(object["status"] as? String, "success")
        XCTAssertEqual((object["body"] as? [String: Any])?.count, 0)
        XCTAssertTrue(object["error"] is NSNull)

        let decoded = try NoctweaveCoder.decode(RelayResponse.self, from: data)
        XCTAssertTrue(decoded.isResponse(to: request))
        XCTAssertFalse(decoded.isResponse(to: .health()))

        var extraBody = object
        extraBody["body"] = ["ok": true]
        XCTAssertThrowsError(try decodeResponse(extraBody))

        var bothBranches = object
        bothBranches["error"] = ["code": "invalid-request", "message": "bad", "retryable": false]
        XCTAssertThrowsError(try decodeResponse(bothBranches))
    }

    func testErrorResponseIsBoundedAndMutuallyExclusive() throws {
        let request = RelayRequest.info()
        let response = RelayResponse.error(
            String(repeating: "x", count: RelayErrorBody.maximumMessageBytes + 1),
            code: .internalFailure,
            retryable: true,
            respondingTo: request
        )
        XCTAssertEqual(response.error?.message, "Relay request failed")

        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: NoctweaveCoder.encode(response)) as? [String: Any]
        )
        XCTAssertEqual(object["status"] as? String, "error")
        XCTAssertTrue(object["body"] is NSNull)
        let error = try XCTUnwrap(object["error"] as? [String: Any])
        XCTAssertEqual(Set(error.keys), ["code", "message", "retryable"])

        var unknownErrorField = object
        var malformedError = error
        malformedError["details"] = "not allowed"
        unknownErrorField["error"] = malformedError
        XCTAssertThrowsError(try decodeResponse(unknownErrorField))
    }

    private func decodeRequest(_ object: [String: Any]) throws -> RelayRequest {
        try NoctweaveCoder.decode(
            RelayRequest.self,
            from: JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        )
    }

    private func decodeResponse(_ object: [String: Any]) throws -> RelayResponse {
        try NoctweaveCoder.decode(
            RelayResponse.self,
            from: JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        )
    }
}
