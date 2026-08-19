import Foundation
import XCTest
@testable import NoctweaveCore

final class RelayPairingPreflightTests: XCTestCase {
    func testCompatibleLoopbackRelayPassesFunctionalPairingProbe() async throws {
        let server = RelayServer(
            store: RelayStore(),
            configuration: RelayConfiguration(rendezvousTransportEnabled: true)
        )
        let port = try await startOnEphemeralLoopbackPort(server)
        defer { server.stop() }

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
        let server = RelayServer(store: RelayStore())
        let port = try await startOnEphemeralLoopbackPort(server)
        defer { server.stop() }

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
        let server = RelayServer(
            store: RelayStore(),
            configuration: RelayConfiguration(
                accessPassword: "correct horse battery staple",
                rendezvousTransportEnabled: true
            )
        )
        let port = try await startOnEphemeralLoopbackPort(server)
        defer { server.stop() }
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

    private func startOnEphemeralLoopbackPort(_ server: RelayServer) async throws -> UInt16 {
        let started = expectation(description: "relay started")
        var boundPort: UInt16?
        server.onEvent = { event in
            if case .started(let port) = event {
                boundPort = port
                started.fulfill()
            }
        }
        try server.start(host: "127.0.0.1", port: 0)
        await fulfillment(of: [started], timeout: 5)
        return try XCTUnwrap(boundPort)
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
