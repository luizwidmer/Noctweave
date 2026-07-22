import Foundation
import XCTest
@testable import NoctweaveCore

final class OpaqueRouteCrossLanguageVectorTests: XCTestCase {
    func testJavaScriptCreateTransitionVectorMatchesSwift() throws {
        let capabilities = try OpaqueRouteClientCapabilityMaterialV2(
            routeID: fixed(OpaqueReceiveRouteIDV2.self, byte: 1),
            sendCapability: fixed(RouteSendCapabilityV2.self, byte: 2),
            readCredential: fixed(RouteReadCredentialV2.self, byte: 3),
            renewCapability: fixed(RouteRenewCapabilityV2.self, byte: 4),
            teardownCapability: fixed(RouteTeardownCapabilityV2.self, byte: 5)
        )
        let lease = try OpaqueRouteLeaseV2(
            issuedAt: try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-07-16T12:00:00Z")),
            expiresAt: try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-07-16T13:00:00Z")),
            policy: OpaqueRoutePolicyV2(
                paddingBucket: .bytes16384,
                retentionBucket: .oneDay,
                quotaBucket: .packets256
            )
        )
        let request = try capabilities.makeCreateRequest(
            lease: lease,
            idempotencyKey: fixed(OpaqueRouteIdempotencyKeyV2.self, byte: 6),
            nonce: fixed(OpaqueRouteProofNonceV2.self, byte: 7)
        )

        XCTAssertEqual(
            request.transitionDigest?.hexString,
            "ce632810482bc772d2ed2e9cc91bcf9fe2270fdf79de1cbd63945e114677c28a"
        )
        XCTAssertEqual(
            request.authorization.mac.hexString,
            "e45ad22b7f03adf99ed4ea88e3646589bd9a6f5376b3faa0380d4a9fa77b13a4"
        )

        let encoded = try NoctweaveCoder.encode(request)
        XCTAssertNoThrow(try NoctweaveCoder.decode(OpaqueRouteCreateRequestV2.self, from: encoded))
    }

    private func fixed<Value: Decodable>(_ type: Value.Type, byte: UInt8) throws -> Value {
        let value = Data(repeating: byte, count: NoctweaveOpaqueRoutesV2.credentialBytes)
            .base64EncodedString()
        return try NoctweaveCoder.decode(type, from: Data(#"{"rawValue":"\#(value)"}"#.utf8))
    }
}

private extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
