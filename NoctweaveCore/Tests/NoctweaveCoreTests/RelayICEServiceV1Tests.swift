import Foundation
import XCTest
@testable import NoctweaveCore

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

    func testDescriptorValidationIsCanonicalAndRejectsEmbeddedCredentials() throws {
        XCTAssertTrue(descriptor.isStructurallyValid)
        XCTAssertEqual(
            descriptor.urls,
            [
                "stun:turn.example.test:3478",
                "turn:turn.example.test:3478?transport=udp"
            ]
        )
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
        XCTAssertTrue(RelayICEServiceV1.isValidURL("turn:[2001:db8::1]:3478?transport=udp"))

        let data = try NoctweaveCoder.encode(descriptor, sortedKeys: true)
        XCTAssertEqual(try NoctweaveCoder.decode(RelayICEServiceDescriptorV1.self, from: data), descriptor)
    }

    func testCoturnRESTCredentialVectorIsStableAndBounded() throws {
        let issuer = try XCTUnwrap(CoturnCredentialIssuerV1(
            sharedSecret: "0123456789abcdef0123456789abcdef"
        ))
        let request = RelayICECredentialRequestV1(
            nonce: Data(0...15),
            requestedLifetimeSeconds: 600
        )
        let credentials = try XCTUnwrap(issuer.issue(
            request: request,
            descriptor: descriptor,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        ))

        XCTAssertEqual(credentials.username, "1700000600:AAECAwQFBgcICQoLDA0ODw")
        XCTAssertEqual(credentials.credential, "OuwuOy5Y+RcOI0kQ4foaGr+fx3k=")
        XCTAssertEqual(credentials.urls, ["turn:turn.example.test:3478?transport=udp"])
        XCTAssertEqual(credentials.issuedAt, Date(timeIntervalSince1970: 1_700_000_000))
        XCTAssertEqual(credentials.expiresAt, Date(timeIntervalSince1970: 1_700_000_600))
        XCTAssertTrue(credentials.isStructurallyValid)
        XCTAssertNil(CoturnCredentialIssuerV1(sharedSecret: "too-short"))
    }

    func testRelayAdvertisesAndServesICECredentialsOverLoopback() async throws {
        let configuration = RelayConfiguration(iceService: descriptor)
        let info = configuration.makeInfo(now: Date(timeIntervalSince1970: 1_700_000_000))
        XCTAssertEqual(info.iceService, descriptor)
        XCTAssertTrue(try XCTUnwrap(info.protocolCapabilities).supports(
            module: "nw.ice-service",
            version: 1
        ))

        let port = UInt16.random(in: 58_100...60_000)
        let server = RelayServer(
            store: RelayStore(),
            configuration: configuration,
            coturnCredentialIssuer: try XCTUnwrap(CoturnCredentialIssuerV1(
                sharedSecret: "0123456789abcdef0123456789abcdef"
            ))
        )
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 150_000_000)

        let requestBody = RelayICECredentialRequestV1(
            nonce: Data(0...15),
            requestedLifetimeSeconds: 300
        )
        let request = RelayRequest.acquireICECredentialsV1(
            requestBody,
            authToken: nil
        )
        XCTAssertEqual(request.binding.module, .iceService)
        XCTAssertEqual(request.binding.method, .acquire)
        let response = try await RelayClient(
            endpoint: RelayEndpoint(host: "127.0.0.1", port: port)
        ).send(request)
        guard case .iceCredentials(let credentials)? = response.successBody else {
            return XCTFail("Expected short-lived TURN credentials")
        }
        XCTAssertEqual(credentials.urls, ["turn:turn.example.test:3478?transport=udp"])
        XCTAssertEqual(credentials.expiresAt.timeIntervalSince(credentials.issuedAt), 300)
    }
}
