import Foundation
import XCTest
@testable import NoctweaveCore

final class StrictCurrentProtocolTests: XCTestCase {
    func testRelayEndpointRequiresEveryCurrentField() throws {
        let missingTransport = Data(
            #"{"host":"relay.example","port":443,"useTLS":true,"tlsCertificateFingerprintSHA256":null,"directorySigningPublicKey":null}"#.utf8
        )

        XCTAssertThrowsError(
            try NoctweaveCoder.decode(RelayEndpoint.self, from: missingTransport)
        )
    }

    func testRelayEndpointRejectsUnknownFields() throws {
        let endpoint = RelayEndpoint(
            host: "relay.example",
            port: 443,
            useTLS: true,
            transport: .websocket
        )
        let encoded = try NoctweaveCoder.encode(endpoint)
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        object["legacyTransport"] = "tcp"
        let tampered = try JSONSerialization.data(withJSONObject: object)

        XCTAssertThrowsError(
            try NoctweaveCoder.decode(RelayEndpoint.self, from: tampered)
        )
    }
}
