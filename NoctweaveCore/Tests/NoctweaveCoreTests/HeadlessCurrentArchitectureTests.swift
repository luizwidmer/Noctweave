import Foundation
import XCTest
@testable import NoctweaveCore

final class HeadlessCurrentArchitectureTests: XCTestCase {
    func testDefaultPairingIntroductionNeverLeaksLocalPersonaName() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let state = try ClientState(
            displayName: "Private local persona name",
            createdAt: Date(timeIntervalSince1970: 100)
        )
        let client = try HeadlessMessagingClient(
            stateStore: ClientStateStore(
                fileURL: directory.appendingPathComponent("state.json"),
                useEncryption: false
            ),
            initialState: state
        )

        let pending = try await client.prepareContactParticipant(
            relay: relay,
            createdAt: Date(timeIntervalSince1970: 101)
        )
        XCTAssertEqual(
            pending.localIdentity.relationshipPseudonym,
            "Noctweave peer"
        )
        XCTAssertNotEqual(
            pending.localIdentity.relationshipPseudonym,
            state.activePersona.displayName
        )

        let pseudonymous = try await client.prepareContactParticipant(
            relay: relay,
            relationshipPseudonym: "Night orchid",
            createdAt: Date(timeIntervalSince1970: 102)
        )
        XCTAssertEqual(
            pseudonymous.localIdentity.relationshipPseudonym,
            "Night orchid"
        )
    }

    func testPersonaBurnCreatesUnrelatedLocalContainerWithoutContinuityEvent() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ClientStateStore(
            fileURL: directory.appendingPathComponent("state.json"),
            useEncryption: false
        )
        let initial = try ClientState(
            displayName: "First local mask",
            createdAt: Date(timeIntervalSince1970: 100)
        )
        let originalID = initial.activePersonaID
        let client = try HeadlessMessagingClient(
            stateStore: store,
            initialState: initial
        )

        let replacement = try await client.burnActivePersona(
            replacementDisplayName: "Second local mask",
            at: Date(timeIntervalSince1970: 200)
        )
        let state = await client.snapshot()
        XCTAssertNotEqual(replacement.id, originalID)
        XCTAssertEqual(state.activePersonaID, replacement.id)
        XCTAssertEqual(state.personas.count, 1)
        XCTAssertFalse(state.personas.contains { $0.id == originalID })
        XCTAssertTrue(replacement.relationships.isEmpty)
        XCTAssertTrue(replacement.groupRuntimes.isEmpty)
    }

    private var relay: RelayEndpoint {
        RelayEndpoint(
            host: "relay.example",
            port: 443,
            useTLS: true,
            transport: .websocket
        )
    }

    private func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-headless-current-\(UUID().uuidString)")
    }
}
