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
                "pendingGroupAdmissions",
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
            protection: .insecurePlaintextForTesting
        )
        do {
            try await store.save(invalid, replacing: nil)
            XCTFail("Expected invalid current state to be rejected")
        } catch {
            XCTAssertEqual(error as? ClientStateError, .invalidState)
        }
    }

    func testPlaintextStoreRoundTripsCurrentStateAndRejectsIncompleteState() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("state.json")
        let store = ClientStateStore(
            fileURL: fileURL,
            protection: .insecurePlaintextForTesting
        )
        let state = try makeState()

        try await store.save(state, replacing: nil)
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
        let anchorStore = VolatileClientStateRollbackAnchorStore()
        let store = ClientStateStore(
            fileURL: fileURL,
            protection: .encrypted,
            encryptionKey: key,
            rollbackAnchorStore: anchorStore
        )
        let state = try makeState(displayName: "Only Local Persona")

        try await store.save(state, replacing: nil)
        let raw = try Data(contentsOf: fileURL)
        XCTAssertNil(raw.range(of: Data("Only Local Persona".utf8)))
        let envelope = try jsonObject(raw)
        XCTAssertEqual(
            Set(envelope.keys),
            Set([
                "version",
                "generation",
                "previousStateDigest",
                "stateDigest",
                "sealed",
            ])
        )
        XCTAssertEqual(envelope["generation"] as? Int, 1)
        XCTAssertTrue(envelope["previousStateDigest"] is NSNull)
        let loaded = try await store.load()
        XCTAssertEqual(loaded, state)

        let wrongKeyStore = ClientStateStore(
            fileURL: fileURL,
            protection: .encrypted,
            encryptionKey: SymmetricKey(data: Data(repeating: 0x74, count: 32)),
            rollbackAnchorStore: anchorStore
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
            protection: .encrypted,
            encryptionKey: SymmetricKey(data: Data(repeating: 0x21, count: 32)),
            rollbackAnchorStore: VolatileClientStateRollbackAnchorStore()
        )
        do {
            _ = try await store.load()
            XCTFail("Expected plaintext in encrypted mode to be rejected")
        } catch {
            // The store never falls back to plaintext decoding.
        }
    }

    func testEncryptedStoreRejectsAReplayedOlderSnapshot() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("state.json")
        let key = SymmetricKey(data: Data(repeating: 0x35, count: 32))
        let anchorStore = VolatileClientStateRollbackAnchorStore()
        let store = ClientStateStore(
            fileURL: fileURL,
            encryptionKey: key,
            rollbackAnchorStore: anchorStore
        )

        let firstState = try makeState(displayName: "First")
        let secondState = try makeState(displayName: "Second")
        try await store.save(firstState, replacing: nil)
        let replayedSnapshot = try Data(contentsOf: fileURL)
        try await store.save(secondState, replacing: firstState)
        try replayedSnapshot.write(to: fileURL, options: .atomic)

        do {
            _ = try await store.load()
            XCTFail("Expected replay of an authenticated older snapshot to fail")
        } catch {
            XCTAssertEqual(error as? ClientStateStoreError, .rollbackDetected)
        }
    }

    func testEncryptedStoreRejectsMissingStateWhenAnchorExists() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("state.json")
        let anchorStore = VolatileClientStateRollbackAnchorStore()
        let store = ClientStateStore(
            fileURL: fileURL,
            encryptionKey: SymmetricKey(data: Data(repeating: 0x62, count: 32)),
            rollbackAnchorStore: anchorStore
        )

        try await store.save(try makeState(), replacing: nil)
        try FileManager.default.removeItem(at: fileURL)

        do {
            _ = try await store.load()
            XCTFail("Expected deletion of anchored state to fail closed")
        } catch {
            XCTAssertEqual(error as? ClientStateStoreError, .rollbackDetected)
        }
    }

    func testEncryptedStoreRecoversACommittedFileWithAStagedAnchor() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("state.json")
        let key = SymmetricKey(data: Data(repeating: 0x91, count: 32))
        let anchorStore = FinalizationFaultAnchorStore()
        let store = ClientStateStore(
            fileURL: fileURL,
            encryptionKey: key,
            rollbackAnchorStore: anchorStore
        )
        let state = try makeState(displayName: "Crash Recoverable")

        anchorStore.failNextFinalization = true
        do {
            try await store.save(state, replacing: nil)
            XCTFail("Expected the simulated post-rename anchor failure")
        } catch {
            XCTAssertEqual(error as? ClientStateStoreError, .concurrentUpdate)
        }
        XCTAssertNotNil(try anchorStore.load()?.pending)

        let recovered = try await store.load()
        XCTAssertEqual(recovered, state)
        XCTAssertNil(try anchorStore.load()?.pending)
        XCTAssertEqual(try anchorStore.load()?.current?.generation, 1)
    }

    func testEncryptedStoreRecoversAStagedFileBeforeRename() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("state.json")
        let key = SymmetricKey(data: Data(repeating: 0xB4, count: 32))
        let anchorStore = PreRenameFaultAnchorStore(fileURL: fileURL)
        let store = ClientStateStore(
            fileURL: fileURL,
            encryptionKey: key,
            rollbackAnchorStore: anchorStore
        )
        let state = try makeState(displayName: "Staged Before Rename")

        do {
            try await store.save(state, replacing: nil)
            XCTFail("Expected the simulated rename interruption")
        } catch {
            XCTAssertEqual(error as? ClientStateStoreError, .storageUnavailable)
        }
        XCTAssertNotNil(try anchorStore.load()?.pending)
        XCTAssertTrue(FileManager.default.fileExists(atPath: fileURL.appendingPathExtension("pending").path))
        try FileManager.default.removeItem(at: fileURL)

        let recovered = try await store.load()
        XCTAssertEqual(recovered, state)
        XCTAssertNil(try anchorStore.load()?.pending)
        XCTAssertEqual(try anchorStore.load()?.current?.generation, 1)
    }

    func testEncryptedStoreBindsCiphertextToItsLocalStorePath() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let sourceURL = directory.appendingPathComponent("source.json")
        let destinationURL = directory.appendingPathComponent("destination.json")
        let key = SymmetricKey(data: Data(repeating: 0x18, count: 32))
        let sourceAnchor = VolatileClientStateRollbackAnchorStore()
        let source = ClientStateStore(
            fileURL: sourceURL,
            encryptionKey: key,
            rollbackAnchorStore: sourceAnchor
        )
        try await source.save(try makeState(), replacing: nil)
        try FileManager.default.copyItem(at: sourceURL, to: destinationURL)

        let destination = ClientStateStore(
            fileURL: destinationURL,
            encryptionKey: key,
            rollbackAnchorStore: VolatileClientStateRollbackAnchorStore(
                record: try sourceAnchor.load()
            )
        )
        do {
            _ = try await destination.load()
            XCTFail("Expected a copied state file to remain bound to its original local path")
        } catch {
            XCTAssertEqual(error as? ClientStateStoreError, .rollbackDetected)
        }
    }

    func testEncryptedStoreRejectsAStaleIndependentWriter() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("state.json")
        let key = SymmetricKey(data: Data(repeating: 0xE7, count: 32))
        let anchorStore = VolatileClientStateRollbackAnchorStore()
        let first = ClientStateStore(
            fileURL: fileURL,
            encryptionKey: key,
            rollbackAnchorStore: anchorStore
        )
        let stale = ClientStateStore(
            fileURL: fileURL,
            encryptionKey: key,
            rollbackAnchorStore: anchorStore
        )
        let firstInitial = try await first.load()
        let staleInitial = try await stale.load()
        XCTAssertNil(firstInitial)
        XCTAssertNil(staleInitial)
        try await first.save(
            try makeState(displayName: "Committed"),
            replacing: firstInitial
        )

        do {
            try await stale.save(
                try makeState(displayName: "Stale overwrite"),
                replacing: staleInitial
            )
            XCTFail("Expected stale local state to require a fresh load")
        } catch {
            XCTAssertEqual(error as? ClientStateStoreError, .concurrentUpdate)
        }
        let committed = try await first.load()
        XCTAssertEqual(committed?.activePersona.displayName, "Committed")
    }

    func testSharedStoreRejectsStaleClientAfterPersonaBurn() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ClientStateStore(
            fileURL: directory.appendingPathComponent("state.json"),
            encryptionKey: SymmetricKey(data: Data(repeating: 0x5D, count: 32)),
            rollbackAnchorStore: VolatileClientStateRollbackAnchorStore()
        )
        let initial = try makeState(displayName: "Disposable")
        try await store.save(initial, replacing: nil)
        let current = try HeadlessMessagingClient(
            stateStore: store,
            initialState: initial
        )
        let stale = try HeadlessMessagingClient(
            stateStore: store,
            initialState: initial
        )

        _ = try await current.burnActivePersona(
            replacementDisplayName: "Fresh",
            at: Date(timeIntervalSince1970: 200)
        )
        do {
            _ = try await stale.burnActivePersona(
                replacementDisplayName: "Resurrected stale state",
                at: Date(timeIntervalSince1970: 201)
            )
            XCTFail("Expected the stale client aggregate to be rejected")
        } catch {
            XCTAssertEqual(error as? ClientStateStoreError, .concurrentUpdate)
        }

        let loadedState = try await store.load()
        let loaded = try XCTUnwrap(loadedState)
        XCTAssertEqual(loaded.activePersona.displayName, "Fresh")
        XCTAssertFalse(loaded.personas.contains {
            $0.displayName == "Resurrected stale state"
        })
    }

    func testIndependentStoresSerializeOneConcurrentGeneration() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("state.json")
        let key = SymmetricKey(data: Data(repeating: 0xD6, count: 32))
        let anchorStore = VolatileClientStateRollbackAnchorStore()
        let first = ClientStateStore(
            fileURL: fileURL,
            encryptionKey: key,
            rollbackAnchorStore: anchorStore
        )
        let second = ClientStateStore(
            fileURL: fileURL,
            encryptionKey: key,
            rollbackAnchorStore: anchorStore
        )
        let firstState = try makeState(displayName: "First writer")
        let secondState = try makeState(displayName: "Second writer")
        _ = try await first.load()
        _ = try await second.load()

        let firstTask = Task { () -> ClientStateStoreError? in
            do {
                try await first.save(firstState, replacing: nil)
                return nil
            } catch {
                return error as? ClientStateStoreError
            }
        }
        let secondTask = Task { () -> ClientStateStoreError? in
            do {
                try await second.save(secondState, replacing: nil)
                return nil
            } catch {
                return error as? ClientStateStoreError
            }
        }
        let outcomes = await [firstTask.value, secondTask.value]
        XCTAssertEqual(outcomes.filter { $0 == nil }.count, 1)
        XCTAssertEqual(outcomes.filter { $0 == .concurrentUpdate }.count, 1)
        XCTAssertEqual(try anchorStore.load()?.current?.generation, 1)
    }

    func testExplicitLocalEraseAdvancesATombstoneAndRejectsReplay() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("state.json")
        let key = SymmetricKey(data: Data(repeating: 0xA9, count: 32))
        let anchorStore = VolatileClientStateRollbackAnchorStore()
        let store = ClientStateStore(
            fileURL: fileURL,
            encryptionKey: key,
            rollbackAnchorStore: anchorStore
        )
        try await store.save(
            try makeState(displayName: "Disposable"),
            replacing: nil
        )
        let replayed = try Data(contentsOf: fileURL)

        try await store.eraseAllLocalState()
        let erasedAnchor = try XCTUnwrap(anchorStore.load()?.current)
        XCTAssertEqual(erasedAnchor.kind, .erased)
        XCTAssertEqual(erasedAnchor.generation, 2)
        let empty = try await store.load()
        XCTAssertNil(empty)

        try replayed.write(to: fileURL, options: .atomic)
        do {
            _ = try await store.load()
            XCTFail("Expected a pre-erase state replay to fail closed")
        } catch {
            XCTAssertEqual(error as? ClientStateStoreError, .rollbackDetected)
        }

        try await store.eraseAllLocalState()
        try await store.save(
            try makeState(displayName: "Fresh Local Persona"),
            replacing: nil
        )
        let fresh = try await store.load()
        XCTAssertEqual(fresh?.activePersona.displayName, "Fresh Local Persona")
        XCTAssertEqual(try anchorStore.load()?.current?.generation, 3)
    }

    func testExplicitLocalEraseRecoversAnInterruptedErase() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("state.json")
        let anchorStore = EraseStageFaultAnchorStore()
        let store = ClientStateStore(
            fileURL: fileURL,
            encryptionKey: SymmetricKey(data: Data(repeating: 0x6C, count: 32)),
            rollbackAnchorStore: anchorStore
        )
        try await store.save(try makeState(), replacing: nil)
        anchorStore.failAfterNextEraseStage = true

        do {
            try await store.eraseAllLocalState()
            XCTFail("Expected the simulated erase-stage interruption")
        } catch {
            XCTAssertEqual(
                error as? ClientStateRollbackAnchorError,
                .unavailable(status: -99)
            )
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: fileURL.path))
        XCTAssertEqual(try anchorStore.load()?.pending?.kind, .erased)

        let recovered = try await store.load()
        XCTAssertNil(recovered)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fileURL.path))
        XCTAssertEqual(try anchorStore.load()?.current?.kind, .erased)
        XCTAssertNil(try anchorStore.load()?.pending)
    }

    func testPendingStateMustChainFromItsTrustedCurrentAnchor() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("state.json")
        let key = SymmetricKey(data: Data(repeating: 0x73, count: 32))
        let sourceAnchor = VolatileClientStateRollbackAnchorStore()
        let source = ClientStateStore(
            fileURL: fileURL,
            encryptionKey: key,
            rollbackAnchorStore: sourceAnchor
        )
        let firstState = try makeState(displayName: "First")
        let secondState = try makeState(displayName: "Second")
        try await source.save(firstState, replacing: nil)
        try await source.save(secondState, replacing: firstState)
        let second = try XCTUnwrap(sourceAnchor.load()?.current)
        let fabricatedCurrent = try ClientStateRollbackAnchor(
            generation: 1,
            stateDigest: Data(repeating: 0xF1, count: 32)
        )
        let mismatchedRecord = try ClientStateRollbackAnchorRecord(
            current: fabricatedCurrent,
            pending: second
        )
        let reopened = ClientStateStore(
            fileURL: fileURL,
            encryptionKey: key,
            rollbackAnchorStore: VolatileClientStateRollbackAnchorStore(
                record: mismatchedRecord
            )
        )

        do {
            _ = try await reopened.load()
            XCTFail("Expected a pending state with a different predecessor to fail")
        } catch {
            XCTAssertEqual(error as? ClientStateStoreError, .rollbackDetected)
        }
    }

    func testUnanchoredPendingFileIsNeverPromoted() async throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("state.json")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let pendingURL = fileURL.appendingPathExtension("pending")
        try Data(repeating: 0x42, count: 64).write(to: pendingURL)
        let store = ClientStateStore(
            fileURL: fileURL,
            encryptionKey: SymmetricKey(data: Data(repeating: 0x22, count: 32)),
            rollbackAnchorStore: VolatileClientStateRollbackAnchorStore()
        )

        let loaded = try await store.load()
        XCTAssertNil(loaded)
        XCTAssertFalse(FileManager.default.fileExists(atPath: pendingURL.path))
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

private final class FinalizationFaultAnchorStore:
    ClientStateRollbackAnchorStore, @unchecked Sendable {
    private let lock = NSLock()
    private var record: ClientStateRollbackAnchorRecord?
    private var shouldFailNextFinalization = false

    var failNextFinalization: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return shouldFailNextFinalization
        }
        set {
            lock.lock()
            shouldFailNextFinalization = newValue
            lock.unlock()
        }
    }

    func load() throws -> ClientStateRollbackAnchorRecord? {
        lock.lock()
        defer { lock.unlock() }
        return record
    }

    func compareAndSwap(
        expected: ClientStateRollbackAnchorRecord?,
        replacement: ClientStateRollbackAnchorRecord
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        guard record == expected else {
            throw ClientStateRollbackAnchorError.compareAndSwapFailed
        }
        if shouldFailNextFinalization,
           expected?.pending != nil,
           replacement.pending == nil {
            shouldFailNextFinalization = false
            throw ClientStateRollbackAnchorError.compareAndSwapFailed
        }
        record = replacement
    }
}

private final class PreRenameFaultAnchorStore:
    ClientStateRollbackAnchorStore, @unchecked Sendable {
    private let lock = NSLock()
    private let fileURL: URL
    private var record: ClientStateRollbackAnchorRecord?
    private var shouldInterrupt = true

    init(fileURL: URL) {
        self.fileURL = fileURL
    }

    func load() throws -> ClientStateRollbackAnchorRecord? {
        lock.lock()
        defer { lock.unlock() }
        return record
    }

    func compareAndSwap(
        expected: ClientStateRollbackAnchorRecord?,
        replacement: ClientStateRollbackAnchorRecord
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        guard record == expected else {
            throw ClientStateRollbackAnchorError.compareAndSwapFailed
        }
        record = replacement
        if shouldInterrupt, replacement.pending != nil {
            shouldInterrupt = false
            try FileManager.default.createDirectory(at: fileURL, withIntermediateDirectories: false)
        }
    }
}

private final class EraseStageFaultAnchorStore:
    ClientStateRollbackAnchorStore, @unchecked Sendable {
    private let lock = NSLock()
    private var record: ClientStateRollbackAnchorRecord?
    private var shouldFailAfterEraseStage = false

    var failAfterNextEraseStage: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return shouldFailAfterEraseStage
        }
        set {
            lock.lock()
            shouldFailAfterEraseStage = newValue
            lock.unlock()
        }
    }

    func load() throws -> ClientStateRollbackAnchorRecord? {
        lock.lock()
        defer { lock.unlock() }
        return record
    }

    func compareAndSwap(
        expected: ClientStateRollbackAnchorRecord?,
        replacement: ClientStateRollbackAnchorRecord
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        guard record == expected else {
            throw ClientStateRollbackAnchorError.compareAndSwapFailed
        }
        record = replacement
        if shouldFailAfterEraseStage, replacement.pending?.kind == .erased {
            shouldFailAfterEraseStage = false
            throw ClientStateRollbackAnchorError.unavailable(status: -99)
        }
    }
}
