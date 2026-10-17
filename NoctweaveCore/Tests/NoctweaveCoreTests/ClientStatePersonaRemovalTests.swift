import Foundation
import XCTest
@testable import NoctweaveCore

final class ClientStatePersonaRemovalTests: XCTestCase {
    func testRemovingInactivePersonaPreservesSurvivingIDsArchivesAndPreferences() throws {
        // The wire coder retains ISO-8601 whole seconds. Use representable
        // fixture dates so round-trip equality checks every retained field.
        let createdAt = Date(timeIntervalSince1970: 1_700_000_000)
        let relay = LocalRelayPreference(name: "Fixture relay", endpoint: .init(host: "relay.invalid", port: 443, useTLS: true), addedAt: createdAt)
        var state = try ClientState(displayName: "Archived", relayPreferences: [relay], createdAt: createdAt)
        let archivedID = state.activePersonaID
        let deleted = try state.addPersona(displayName: "Delete", createdAt: createdAt.addingTimeInterval(1))
        let active = try state.addPersona(displayName: "Active", createdAt: createdAt.addingTimeInterval(2))
        try state.archivePersona(archivedID)
        try state.setPreferredRelayPreference(relay.id, forPersonaID: archivedID)
        try state.setPreferredRelayPreference(relay.id, forPersonaID: deleted.id)
        try state.setPreferredRelayPreference(relay.id, forPersonaID: active.id)
        let retainedSelection = AppLockDecoyChat(personaID: archivedID, kind: .relationship, chatID: UUID())
        state.appLock = AppLockSettings(mode: .biometrics, duressPlans: [
            AppLockDuressPlan(label: "Retain chats", salt: Data(repeating: 1, count: 32),
                              verifier: Data(repeating: 2, count: 32), action: .decoy,
                              decoyChats: [retainedSelection])
        ])
        let before = state

        try state.removePersona(deleted.id)

        XCTAssertEqual(state.personas, before.personas.filter { $0.id != deleted.id })
        XCTAssertEqual(state.activePersonaID, active.id)
        XCTAssertEqual(state.archivedPersonaIDs, [archivedID])
        XCTAssertEqual(state.preferredRelayPreferenceIDsByPersonaID, [archivedID: relay.id, active.id: relay.id])
        XCTAssertEqual(state.appLock, before.appLock)
        XCTAssertTrue(state.personas.contains { $0.id == retainedSelection.personaID })
        XCTAssertEqual(state.relayPreferences, before.relayPreferences)
        XCTAssertEqual(state.chatList, before.chatList)
        XCTAssertEqual(state.appearance, before.appearance)
        XCTAssertEqual(state.privacy, before.privacy)
        XCTAssertTrue(try state.isStructurallyValidThrowing)
        XCTAssertEqual(try NoctweaveCoder.decode(ClientState.self, from: NoctweaveCoder.encode(state)), state)
    }

    func testRemovingArchivedPersonaClearsOnlyItsLocalMappings() throws {
        let relay = LocalRelayPreference(name: "Fixture relay", endpoint: .init(host: "relay.invalid", port: 443, useTLS: true))
        var state = try ClientState(displayName: "Delete", relayPreferences: [relay])
        let deletedID = state.activePersonaID
        let active = try state.addPersona(displayName: "Keep")
        try state.archivePersona(deletedID)
        try state.setPreferredRelayPreference(relay.id, forPersonaID: deletedID)

        try state.removePersona(deletedID)

        XCTAssertEqual(state.personas, [active])
        XCTAssertEqual(state.activePersonaID, active.id)
        XCTAssertTrue(state.archivedPersonaIDs.isEmpty)
        XCTAssertTrue(state.preferredRelayPreferenceIDsByPersonaID.isEmpty)
        XCTAssertEqual(state.relayPreferences, [relay])
    }

    func testRemovingActiveOrMissingPersonaFailsWithoutChangingState() throws {
        var state = try ClientState(displayName: "Keep")
        let before = state
        XCTAssertThrowsError(try state.removePersona(state.activePersonaID)) {
            XCTAssertEqual($0 as? ClientStateError, .activePersonaCannotBeRemoved)
        }
        XCTAssertEqual(state, before)
        XCTAssertThrowsError(try state.removePersona(UUID())) {
            XCTAssertEqual($0 as? ClientStateError, .personaNotFound)
        }
        XCTAssertEqual(state, before)
    }
}
