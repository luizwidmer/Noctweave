import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class RelayICEServiceV1Tests: XCTestCase {
    private let descriptor = RelayICEServiceDescriptorV1(
        urls: [
            "turn:turn.example.test:3478?transport=udp",
            "stun:turn.example.test:3478"
        ],
        credentialMode: .turnREST,
        credentialLifetimeSeconds: 600,
        realm: "turn.example.test",
        relayOnlySupported: true
    )

    func testLinuxICEURLValidationMatchesSharedBoundary() {
        for invalid in [
            "https://turn.example.test",
            "turn://turn.example.test",
            "turn:alice:secret@turn.example.test",
            "turn:turn.example.test#fragment",
            "turn:turn.example.test?transport=quic",
            "turn:?transport=udp",
            "turn:turn.example.test:0",
            "turn:turn.example.test:65536",
            "turn:turn.example.test/path",
            "turn:2001:db8::1:3478",
            "TURN:turn.example.test"
        ] {
            XCTAssertFalse(RelayICEServiceV1.isValidURL(invalid), invalid)
        }
        XCTAssertTrue(
            RelayICEServiceV1.isValidURL(
                "turn:[2001:db8::1]:3478?transport=udp"
            )
        )
    }

    func testLinuxCredentialIssuerMatchesSharedVector() throws {
        let issuer = try XCTUnwrap(CoturnCredentialIssuer(
            sharedSecret: "0123456789abcdef0123456789abcdef"
        ))
        let credentials = try XCTUnwrap(issuer.issue(
            request: RelayICECredentialRequestV1(
                nonce: Data(0...15),
                requestedLifetimeSeconds: 600
            ),
            descriptor: descriptor,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        ))

        XCTAssertEqual(credentials.username, "1700000600:AAECAwQFBgcICQoLDA0ODw")
        XCTAssertEqual(credentials.credential, "OuwuOy5Y+RcOI0kQ4foaGr+fx3k=")
        XCTAssertEqual(credentials.urls, ["turn:turn.example.test:3478?transport=udp"])
        XCTAssertEqual(credentials.expiresAt.timeIntervalSince(credentials.issuedAt), 600)
    }

    func testICEWireBindingIsExactAndCapabilityIsFeatureGated() throws {
        let body = RelayICECredentialRequestV1(
            nonce: Data(0...15),
            requestedLifetimeSeconds: nil
        )
        let request = RelayRequest.acquireICECredentialsV1(body)
            .withAuthToken("relay-password")
        XCTAssertEqual(request.binding, .init(module: .iceService, version: 1, method: .acquire))
        let encoded = try RelayCodec.encoder().encode(request)
        XCTAssertEqual(try RelayCodec.decodeWire(RelayRequest.self, from: encoded), request)
        let requestObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertEqual(
            Set(try XCTUnwrap(requestObject["body"] as? [String: Any]).keys),
            ["request"]
        )

        let credentials = try XCTUnwrap(CoturnCredentialIssuer(
            sharedSecret: "0123456789abcdef0123456789abcdef"
        )).issue(request: body, descriptor: descriptor)
        let response = RelayResponse.success(
            .iceCredentials(try XCTUnwrap(credentials)),
            respondingTo: request
        )
        let responseObject = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: RelayCodec.encoder().encode(response)
            ) as? [String: Any]
        )
        XCTAssertEqual(
            Set(try XCTUnwrap(responseObject["body"] as? [String: Any]).keys),
            ["credentials"]
        )

        let enabled = RelayConfiguration(iceService: descriptor).makeInfo()
        XCTAssertEqual(enabled.iceService, descriptor)
        XCTAssertTrue(try XCTUnwrap(enabled.protocolCapabilities).supports(
            module: "nw.ice-service",
            version: 1
        ))

        let disabled = RelayConfiguration().makeInfo()
        XCTAssertNil(disabled.iceService)
        XCTAssertFalse(try XCTUnwrap(disabled.protocolCapabilities).supports(
            module: "nw.ice-service",
            version: 1
        ))
    }

    func testOperatorUIExposesTraversalWithoutPersistingSecret() throws {
        XCTAssertTrue(OperatorWebUI.html.contains("STUN and TURN traversal"))
        XCTAssertTrue(OperatorWebUI.html.contains("NOCTWEAVE_TURN_SHARED_SECRET"))
        XCTAssertFalse(OperatorWebUI.html.contains("name=\"turnSharedSecret\""))

        let configuration = RelayConfiguration(iceService: descriptor)
        let editable = OperatorEditableConfiguration(configuration: configuration)
        let json = try JSONSerialization.jsonObject(
            with: JSONEncoder().encode(editable)
        ) as? [String: Any]
        XCTAssertNil(json?["turnSharedSecret"])
        XCTAssertEqual(json?["turnRealm"] as? String, "turn.example.test")
    }
}
