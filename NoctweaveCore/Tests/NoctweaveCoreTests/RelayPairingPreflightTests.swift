import Foundation
import XCTest
@testable import NoctweaveCore

final class RelayPairingPreflightTests: XCTestCase {
    func testCompatibleLoopbackRelayPassesFunctionalPairingProbe() async throws {
        let port = UInt16.random(in: 50_100...51_000)
        let server = RelayServer(
            store: RelayStore(),
            configuration: RelayConfiguration(rendezvousTransportEnabled: true)
        )
        let started = expectation(description: "relay started")
        server.onEvent = { event in
            if case .started = event { started.fulfill() }
        }
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2)

        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let readiness = try await RelayPairingPreflight.check(
            client: RelayClient(endpoint: endpoint)
        )

        XCTAssertEqual(readiness.endpoint, endpoint)
        XCTAssertEqual(readiness.requirement, .rendezvous)
        XCTAssertTrue(
            try XCTUnwrap(readiness.relayInfo.protocolCapabilities)
                .supports(module: "nw.rendezvous-transport", version: 2)
        )
    }

    func testOnlineRelayWithoutPairingCapabilityIsRejectedBeforeUse() async throws {
        let port = UInt16.random(in: 51_100...52_000)
        let server = RelayServer(store: RelayStore())
        let started = expectation(description: "relay started")
        server.onEvent = { event in
            if case .started = event { started.fulfill() }
        }
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2)

        do {
            _ = try await RelayPairingPreflight.check(
                client: RelayClient(
                    endpoint: RelayEndpoint(host: "127.0.0.1", port: port)
                )
            )
            XCTFail("Expected missing pairing capability to be rejected")
        } catch {
            XCTAssertEqual(
                error as? RelayPairingPreflightError,
                .rendezvousTransportUnsupported
            )
        }

        let directReadiness = try await RelayPairingPreflight.check(
            client: RelayClient(
                endpoint: RelayEndpoint(host: "127.0.0.1", port: port)
            ),
            requirement: .opaqueRouteOnly
        )
        XCTAssertEqual(directReadiness.requirement, .opaqueRouteOnly)
    }

    func testPasswordProtectedRelayChecksCredentialsWithTemporaryProbe() async throws {
        let port = UInt16.random(in: 52_100...53_000)
        let server = RelayServer(
            store: RelayStore(),
            configuration: RelayConfiguration(
                accessPassword: "correct horse battery staple",
                rendezvousTransportEnabled: true
            )
        )
        let started = expectation(description: "relay started")
        server.onEvent = { event in
            if case .started = event { started.fulfill() }
        }
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)

        do {
            _ = try await RelayPairingPreflight.check(
                client: RelayClient(endpoint: endpoint, authToken: "wrong password")
            )
            XCTFail("Expected wrong relay password to be rejected")
        } catch {
            XCTAssertEqual(error as? RelayPairingPreflightError, .authenticationRequired)
        }

        _ = try await RelayPairingPreflight.check(
            client: RelayClient(
                endpoint: endpoint,
                authToken: "correct horse battery staple"
            )
        )
    }

    func testRemotePlaintextRelayIsRejectedWithoutNetworkAccess() async throws {
        do {
            _ = try await RelayPairingPreflight.check(
                client: RelayClient(
                    endpoint: RelayEndpoint(
                        host: "relay.example.org",
                        port: 9339,
                        useTLS: false,
                        transport: .tcp
                    )
                ),
                timeout: 0.1
            )
            XCTFail("Expected plaintext remote relay to be rejected")
        } catch {
            XCTAssertEqual(
                error as? RelayPairingPreflightError,
                .confidentialTransportRequired
            )
        }
    }
}
