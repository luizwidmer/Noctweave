import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class ClientStateCurrentSchemaTests: XCTestCase {
    func testClientStateContainsOnlyCurrentPersonaAndLocalPreferenceFields() throws {
        let state = try makeState()
        let encoded = try NoctweaveCoder.encode(state, sortedKeys: true)
        let object = try jsonObject(encoded)

        XCTAssertEqual(
            Set(object.keys),
            Set([
                "version",
                "personas",
                "activePersonaID",
                "relayPreferences",
                "relaySourcePreferences",
                "appearance",
                "privacy",
                "appLock",
                "chatList",
                "relayCertificatePins",
                "hasCompletedOnboarding",
                "hasAcceptedPrivacyPolicy",
                "hasAcceptedTermsOfUse"
            ])
        )
        XCTAssertNil(object["identityProfiles"])
        XCTAssertNil(object["activeIdentityId"])
        XCTAssertNil(object["inboxId"])
        XCTAssertNil(object["device"])
        let personas = try XCTUnwrap(object["personas"] as? [[String: Any]])
        let persona = try XCTUnwrap(personas.first)
        XCTAssertEqual(
            Set(persona.keys),
            Set([
                "version",
                "id",
                "displayName",
                "relationships",
                "groupRuntimes",
                "createdAt"
            ])
        )
        XCTAssertNil(persona["identity"])
        XCTAssertNil(persona["inbox"])
        XCTAssertNil(persona["relay"])
        XCTAssertEqual(try NoctweaveCoder.decode(ClientState.self, from: encoded), state)

        var foreign = object
        foreign["unexpected"] = true
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(ClientState.self, from: try jsonData(foreign))
        )

        var incomplete = object
        incomplete.removeValue(forKey: "personas")
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(ClientState.self, from: try jsonData(incomplete))
        )
    }

    func testLocalSettingsUseExactCurrentSchemasAndExplicitNulls() throws {
        let state = try makeState()
        let object = try jsonObject(NoctweaveCoder.encode(state, sortedKeys: true))

        let appLock = try XCTUnwrap(object["appLock"] as? [String: Any])
        XCTAssertEqual(
            Set(appLock.keys),
            Set([
                "mode",
                "sessionTimeoutMinutes",
                "lockScreenMessage",
                "pinSalt",
                "pinHash",
                "actionPlans"
            ])
        )
        XCTAssertTrue(appLock["pinSalt"] is NSNull)
        XCTAssertTrue(appLock["pinHash"] is NSNull)

        var foreignPrivacy = try XCTUnwrap(object["privacy"] as? [String: Any])
        foreignPrivacy["unexpected"] = true
        var foreignState = object
        foreignState["privacy"] = foreignPrivacy
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(ClientState.self, from: try jsonData(foreignState))
        )

        var incompletePrivacy = try XCTUnwrap(object["privacy"] as? [String: Any])
        incompletePrivacy.removeValue(forKey: "secureTypingEnabled")
        var incompleteState = object
        incompleteState["privacy"] = incompletePrivacy
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(ClientState.self, from: try jsonData(incompleteState))
        )

        var relays = try XCTUnwrap(object["relayPreferences"] as? [[String: Any]])
        XCTAssertEqual(relays.count, 1)
        XCTAssertEqual(
            Set(relays[0].keys),
            Set([
                "id",
                "name",
                "endpoint",
                "note",
                "accessPassword",
                "region",
                "tags",
                "website",
                "origin",
                "sourceID",
                "addedAt"
            ])
        )
        XCTAssertTrue(relays[0]["accessPassword"] is NSNull)
        relays[0]["unexpected"] = true
        var foreignRelayState = object
        foreignRelayState["relayPreferences"] = relays
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(ClientState.self, from: try jsonData(foreignRelayState))
        )
    }

    func testStructurallyInvalidClientStateCannotBeEncodedOrSaved() async throws {
        var invalid = try makeState()
        invalid.personas.append(invalid.personas[0])
        XCTAssertFalse(invalid.isStructurallyValid)
        XCTAssertThrowsError(try NoctweaveCoder.encode(invalid))

        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ClientStateStore(
            fileURL: directory.appendingPathComponent("state.json"),
            useEncryption: false
        )
        do {
            try await store.save(invalid)
            XCTFail("Expected invalid current state to be rejected")
        } catch {
            XCTAssertEqual(error as? ClientStateError, .invalidState)
        }
    }

    func testPlaintextStoreRoundTripsCurrentStateAndRejectsIncompleteState() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("state.json")
        let store = ClientStateStore(fileURL: fileURL, useEncryption: false)
        let state = try makeState()

        try await store.save(state)
        let loaded = try await store.load()
        XCTAssertEqual(loaded, state)

        try jsonData(["version": ClientState.version]).write(to: fileURL, options: .atomic)
        do {
            _ = try await store.load()
            XCTFail("Expected incomplete state to be rejected")
        } catch {
            // Exact current-schema decoding failed closed.
        }
    }

    func testEncryptedStoreHidesStateAndRequiresExactEnvelopeAndKey() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("state.json")
        let key = SymmetricKey(data: Data(repeating: 0x47, count: 32))
        let store = ClientStateStore(fileURL: fileURL, useEncryption: true, encryptionKey: key)
        let state = try makeState(displayName: "Only Local Persona")

        try await store.save(state)
        let raw = try Data(contentsOf: fileURL)
        XCTAssertNil(raw.range(of: Data("Only Local Persona".utf8)))
        let envelope = try jsonObject(raw)
        XCTAssertEqual(Set(envelope.keys), Set(["version", "sealed"]))
        let loaded = try await store.load()
        XCTAssertEqual(loaded, state)

        let wrongKeyStore = ClientStateStore(
            fileURL: fileURL,
            useEncryption: true,
            encryptionKey: SymmetricKey(data: Data(repeating: 0x74, count: 32))
        )
        do {
            _ = try await wrongKeyStore.load()
            XCTFail("Expected the wrong state key to fail closed")
        } catch {
            // Ciphertext authentication failed.
        }

        var foreignEnvelope = envelope
        foreignEnvelope["legacy"] = true
        try jsonData(foreignEnvelope).write(to: fileURL, options: .atomic)
        do {
            _ = try await store.load()
            XCTFail("Expected a foreign encrypted envelope to be rejected")
        } catch {
            // Exact envelope decoding failed closed.
        }
    }

    func testEncryptedStoreRejectsPlaintextCurrentState() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("state.json")
        let state = try makeState()
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        try NoctweaveCoder.encode(state).write(to: fileURL, options: .atomic)

        let store = ClientStateStore(
            fileURL: fileURL,
            useEncryption: true,
            encryptionKey: SymmetricKey(data: Data(repeating: 0x21, count: 32))
        )
        do {
            _ = try await store.load()
            XCTFail("Expected plaintext in encrypted mode to be rejected")
        } catch {
            // The store never falls back to plaintext decoding.
        }
    }

    private func makeState(displayName: String = "Local Persona") throws -> ClientState {
        let relay = LocalRelayPreference(
            name: "Local relay preference",
            endpoint: RelayEndpoint(
                host: "relay.example",
                port: 443,
                useTLS: true,
                transport: .websocket
            ),
            addedAt: Date(timeIntervalSince1970: 100)
        )
        let source = LocalRelaySourcePreference(
            name: "Optional relay list",
            url: "https://relays.example/list.json"
        )
        let pin = RelayCertificatePinRecord(
            host: "relay.example",
            port: 443,
            useTLS: true,
            transport: .websocket,
            fingerprintSHA256: Data(repeating: 0xA5, count: 32),
            pinnedAt: Date(timeIntervalSince1970: 100),
            origin: .manual
        )
        return try ClientState(
            displayName: displayName,
            relayPreferences: [relay],
            relaySourcePreferences: [source],
            relayCertificatePins: [pin],
            createdAt: Date(timeIntervalSince1970: 100)
        )
    }

    private func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-client-state-\(UUID().uuidString)")
    }

    private func jsonObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func jsonData(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
}
