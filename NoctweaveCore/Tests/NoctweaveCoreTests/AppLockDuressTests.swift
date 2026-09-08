import CryptoKit
import Foundation
import XCTest
#if canImport(Security)
import Security
#endif
@testable import NoctweaveCore

final class AppLockDuressTests: XCTestCase {
    #if canImport(Security)
    func testScopedKeyDeletionRemovesKeychainItemAndRetiresOnlyTheOldProvider() throws {
        let service = "org.noctweave.tests.duress.\(UUID().uuidString)"
        let account = "disposable-key"
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any]
        defer { SecItemDelete(query as CFDictionary) }
        let oldKey = try SecureStorageKeyProvider.shared.loadOrCreateKey(service: service, account: account)
        try SecureStorageKeyProvider.shared.destroyKey(service: service, account: account)
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, nil), errSecItemNotFound)
        SecureStorageKeyProvider.shared.clearProcessCache()
        XCTAssertThrowsError(try SecureStorageKeyProvider.shared.loadOrCreateKey(service: service, account: account))
        let next = SecureStorageKeyProvider()
        let newKey = try next.loadOrCreateKey(service: service, account: account)
        XCTAssertNotEqual(oldKey.withUnsafeBytes { Data($0) }, newKey.withUnsafeBytes { Data($0) })
        XCTAssertThrowsError(try SecureStorageKeyProvider.shared.destroyKey(service: service, account: account))
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, nil), errSecSuccess)
    }
    #endif
    func testOrdinaryFactorsRequireKeyThenBiometricsThenPINForEveryMode() {
        for mode in AppLockMode.allCases {
            var completed = Set<AppLockFactor>()
            for factor in mode.orderedFactors {
                XCTAssertTrue(mode.canAttempt(factor, completedFactors: completed))
                for later in mode.orderedFactors.drop(while: { $0 != factor }).dropFirst() {
                    XCTAssertFalse(mode.canAttempt(later, completedFactors: completed))
                }
                completed.insert(factor)
            }
            XCTAssertTrue(mode.accepts(completedFactors: completed))
        }
        XCTAssertEqual(AppLockMode.biometricsPinAndSecurityKey.orderedFactors, [.securityKey, .biometrics, .pin])
    }

    func testDuressVerifierIsIndependentOfUnlockFactorsAndRejectsWrongPassword() throws {
        let plan = try AppLockDuressPassword.makePlan(password: "654321", label: "Test", action: .decoy)
        XCTAssertTrue(AppLockDuressPassword.matches("654321", plan: plan))
        XCTAssertFalse(AppLockDuressPassword.matches("654320", plan: plan))
        XCTAssertFalse(AppLockDuressPassword.matches("", plan: plan))
        let restored = try JSONDecoder().decode(AppLockDuressPlan.self, from: JSONEncoder().encode(plan))
        XCTAssertEqual(plan, restored)
        var bad = plan; bad.salt = Data([1])
        XCTAssertThrowsError(try JSONEncoder().encode(bad))
        XCTAssertFalse(AppLockDuressPassword.isValid(String(repeating: "x", count: 129)))
        XCTAssertFalse(AppLockDuressPassword.isValid("123\n456"))
    }

    func testDuressPlansAreOptionalBoundedAndCannotEnableAnOffLock() throws {
        let plan = AppLockDuressPlan(label: "Test", salt: Data(repeating: 1, count: 32),
                                    verifier: Data(repeating: 2, count: 32), action: .decoy)
        XCTAssertFalse(AppLockSettings(duressPlans: [plan]).isStructurallyValid)
        var settings = AppLockSettings(mode: .biometrics, duressPlans: [plan])
        XCTAssertTrue(settings.isStructurallyValid)
        XCTAssertEqual(try JSONDecoder().decode(AppLockSettings.self, from: JSONEncoder().encode(settings)), settings)
        settings.duressPlans.append(plan)
        XCTAssertFalse(settings.isStructurallyValid)
        let legacy = try JSONEncoder().encode(AppLockSettings())
        XCTAssertFalse(String(decoding: legacy, as: UTF8.self).contains("duressPlans"))
    }

    func testLegacyLockAndPlanEncodingRemainsCanonical() throws {
        let settings = AppLockSettings()
        let encoded = try NoctweaveCoder.encode(settings, sortedKeys: true)
        let restored = try NoctweaveCoder.decode(AppLockSettings.self, from: encoded)
        XCTAssertFalse(restored.hasCompletedSetup)
        XCTAssertEqual(try NoctweaveCoder.encode(restored, sortedKeys: true), encoded)
        var chosenOff = settings
        chosenOff.hasCompletedSetup = true
        XCTAssertTrue(try NoctweaveCoder.decode(AppLockSettings.self, from: NoctweaveCoder.encode(chosenOff)).hasCompletedSetup)
        let plan = try AppLockDuressPassword.makePlan(password: "654321", label: "Test", action: .decoy)
        let oldPlan = try NoctweaveCoder.encode(plan, sortedKeys: true)
        XCTAssertFalse(String(decoding: oldPlan, as: UTF8.self).contains("decoyChats"))
        XCTAssertEqual(try NoctweaveCoder.encode(NoctweaveCoder.decode(AppLockDuressPlan.self, from: oldPlan), sortedKeys: true), oldPlan)
    }

    func testDecoySelectionIsStrictAndBounded() throws {
        let selection = AppLockDecoyChat(personaID: UUID(), kind: .relationship, chatID: UUID())
        var plan = try AppLockDuressPassword.makePlan(password: "654321", label: "Test", action: .decoy, decoyChats: [selection])
        XCTAssertEqual(try NoctweaveCoder.decode(AppLockDuressPlan.self, from: NoctweaveCoder.encode(plan)), plan)
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with: NoctweaveCoder.encode(plan)) as? [String: Any])
        let selections = try XCTUnwrap(json["decoyChats"] as? [Any])
        json["decoyChats"] = selections + selections
        XCTAssertThrowsError(try NoctweaveCoder.decode(AppLockDuressPlan.self, from: JSONSerialization.data(withJSONObject: json)))
        plan.action = .wipeLocalData
        XCTAssertFalse(plan.isStructurallyValid)
    }

    func testSelectedRelationshipsAndGroupsKeepTheirKeysButOtherPersonasDisappear() throws {
        var state = try ClientState(displayName: "Retained persona", hasCompletedOnboarding: true,
            hasAcceptedPrivacyPolicy: true, hasAcceptedTermsOfUse: true)
        let keep = try makeRelationship()
        let erase = try makeRelationship()
        let group = try makeGenesisRecord(at: Date())
        let erasedGroup = try makeGenesisRecord(at: Date())
        try state.updateActivePersona {
            try $0.upsert(relationship: keep); try $0.upsert(relationship: erase)
            try $0.upsert(groupRuntime: group); try $0.upsert(groupRuntime: erasedGroup)
        }
        let personaID = state.activePersonaID
        _ = try state.addPersona(displayName: "Erase this persona")
        let plan = try AppLockDuressPassword.makePlan(password: "new ordinary password", label: "Test", action: .decoy,
            decoyChats: [.init(personaID: personaID, kind: .relationship, chatID: keep.id),
                         .init(personaID: personaID, kind: .group, chatID: group.groupId)])
        let result = try state.replacementAfterDuress(plan: plan, password: "new ordinary password")
        XCTAssertEqual(result.personas.count, 1)
        XCTAssertEqual(result.activePersonaID, personaID)
        XCTAssertEqual(result.personas[0].relationships, [keep])
        XCTAssertEqual(result.personas[0].groupRuntimes, [group])
        XCTAssertTrue(result.personas[0].pendingGroupAdmissions.isEmpty)
        XCTAssertTrue(result.relaySourcePreferences.isEmpty)
        XCTAssertTrue(result.hasCompletedOnboarding)
        XCTAssertEqual(result.appLock.mode, .pinOnly)
        XCTAssertTrue(result.appLock.duressPlans.isEmpty)
        XCTAssertTrue(result.appLock.securityKeys.isEmpty)
        XCTAssertTrue(result.appLock.hiddenUnlockFactors.isEmpty)
        XCTAssertTrue(AppLockPasswordV1.verify(password: "new ordinary password", salt: try XCTUnwrap(result.appLock.pinSalt), encodedHash: try XCTUnwrap(result.appLock.pinHash)))
        XCTAssertFalse(AppLockPasswordV1.verify(password: "123456", salt: try XCTUnwrap(result.appLock.pinSalt), encodedHash: try XCTUnwrap(result.appLock.pinHash)))
        XCTAssertFalse(AppLockPINV2.verify(pin: "123456", salt: try XCTUnwrap(result.appLock.pinSalt), encodedHash: try XCTUnwrap(result.appLock.pinHash)))
        let encoded = try NoctweaveCoder.encode(result)
        XCTAssertEqual(try NoctweaveCoder.encode(NoctweaveCoder.decode(ClientState.self, from: encoded), sortedKeys: true), try NoctweaveCoder.encode(result, sortedKeys: true))
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains(erase.id.uuidString.lowercased()))
    }

    func testRetainedChatCanEncryptAndReceiveNewMessagesAfterReopen() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let pair = try makePair()
        var original = try ClientState(displayName: "Local")
        try original.updateActivePersona { try $0.upsert(relationship: pair.offererRelationship) }
        let plan = try AppLockDuressPassword.makePlan(password: "future password", label: "Test", action: .decoy,
            decoyChats: [.init(personaID: original.activePersonaID, kind: .relationship, chatID: pair.relationshipID)])
        let replacement = try original.replacementAfterDuress(plan: plan, password: "future password")
        let store = ClientStateStore(fileURL: root.appendingPathComponent("retained"), encryptionKey: SymmetricKey(size: .bits256), rollbackAnchorStore: VolatileClientStateRollbackAnchorStore())
        try await store.save(replacement, replacing: nil)
        let sender = try await HeadlessMessagingClient.open(stateStore: store, displayName: "ignored")
        let prepared = try await sender.prepareSend(body: .text("New message after replacement"), relationshipID: pair.relationshipID,
            sentAt: Date(timeIntervalSince1970: 1_788_000_010))
        var remoteState = try ClientState(displayName: "Peer")
        try remoteState.updateActivePersona { try $0.upsert(relationship: pair.responderRelationship) }
        let remoteStore = ClientStateStore(fileURL: root.appendingPathComponent("remote"), protection: .insecurePlaintextForTesting)
        let remote = try HeadlessMessagingClient(stateStore: remoteStore, initialState: remoteState)
        let payload = try NoctweaveCoder.encode(prepared.envelope, sortedKeys: true)
        let route = try XCTUnwrap(pair.responderRelationship.localReceiveRoutes.first)
        let bundle = OpaqueRouteReassembledBundleV2(routeID: route.route.routeID,
            routeRevision: route.route.lease.renewalSequence, bundleID: .generate(),
            bundleDigest: Data(SHA256.hash(data: payload)), payload: payload)
        var receiver = pair.responderRelationship
        _ = try await remote.processInboundBundle(bundle, sourceRouteID: route.route.routeID,
            attachmentRelay: route.relay, receivedAt: Date(timeIntervalSince1970: 1_788_000_011), relationship: &receiver)
        XCTAssertTrue(receiver.events.contains { $0.id == prepared.event.id && $0.content == prepared.event.content })
        let reopened = try await store.load()
        XCTAssertTrue(reopened?.personas.first?.relationships.first?.events.contains { $0.id == prepared.event.id } == true)
    }

    func testEveryWiperCreatesFreshOnboardingWithOnlyTheUsedPassword() throws {
        let original = try ClientState(displayName: "Private persona", hasCompletedOnboarding: true,
            hasAcceptedPrivacyPolicy: true, hasAcceptedTermsOfUse: true)
        for action in AppLockDuressAction.allCases where action != .decoy {
            let plan = try AppLockDuressPassword.makePlan(password: "new password 123", label: "Test", action: action)
            let fresh = try original.replacementAfterDuress(plan: plan, password: "new password 123")
            XCTAssertFalse(fresh.hasCompletedOnboarding)
            XCTAssertTrue(fresh.appLock.hasCompletedSetup)
            XCTAssertTrue(fresh.personas.allSatisfy { $0.relationships.isEmpty && $0.groupRuntimes.isEmpty })
            XCTAssertNotEqual(fresh.activePersonaID, original.activePersonaID)
            XCTAssertEqual(fresh.appLock.mode, .pinOnly)
            XCTAssertTrue(fresh.appLock.duressPlans.isEmpty)
            XCTAssertTrue(AppLockPasswordV1.verify(password: "new password 123", salt: try XCTUnwrap(fresh.appLock.pinSalt), encodedHash: try XCTUnwrap(fresh.appLock.pinHash)))
            XCTAssertThrowsError(try original.replacementAfterDuress(plan: plan, password: "wrong password"))
        }
    }

    func testMobileDuressReplacementUsesOnlyTheExactNumericPIN() throws {
        let original = try ClientState(displayName: "Private persona", hasCompletedOnboarding: true,
            hasAcceptedPrivacyPolicy: true, hasAcceptedTermsOfUse: true)
        for action in AppLockDuressAction.allCases {
            let plan = try AppLockDuressPassword.makePlan(password: "065432", label: "Test", action: action)
            let replacement = try original.replacementAfterDuress(plan: plan, password: "065432", usesNumericPIN: true)
            let salt = try XCTUnwrap(replacement.appLock.pinSalt)
            let hash = try XCTUnwrap(replacement.appLock.pinHash)
            XCTAssertTrue(AppLockPINV2.isRecord(hash))
            XCTAssertFalse(AppLockPasswordV1.isRecord(hash))
            XCTAssertTrue(AppLockPINV2.verify(pin: "065432", salt: salt, encodedHash: hash))
            XCTAssertFalse(AppLockPINV2.verify(pin: "123456", salt: salt, encodedHash: hash))
            XCTAssertFalse(AppLockPINV2.verify(pin: "65432", salt: salt, encodedHash: hash))
            XCTAssertEqual(replacement.appLock.mode, .pinOnly)
            XCTAssertTrue(replacement.appLock.duressPlans.isEmpty)
            XCTAssertTrue(replacement.appLock.securityKeys.isEmpty)
        }
        let legacy = try AppLockDuressPassword.makePlan(password: "legacy password", label: "Test", action: .wipeLocalData)
        XCTAssertThrowsError(try original.replacementAfterDuress(plan: legacy, password: "legacy password", usesNumericPIN: true))
        let compatible = try original.replacementAfterDuress(plan: legacy, password: "legacy password")
        XCTAssertTrue(AppLockPasswordV1.verify(password: "legacy password", salt: try XCTUnwrap(compatible.appLock.pinSalt), encodedHash: try XCTUnwrap(compatible.appLock.pinHash)))
    }

    func testSuspendingTransitionReadsLatestStateAndRejectsQueuedWriters() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ClientStateStore(fileURL: directory.appendingPathComponent("state"), encryptionKey: SymmetricKey(size: .bits256), rollbackAnchorStore: VolatileClientStateRollbackAnchorStore())
        let initial = try ClientState(displayName: "First")
        try await store.save(initial, replacing: nil)
        var latest = initial
        try latest.renamePersona(latest.activePersonaID, displayName: "Latest")
        try await store.save(latest, replacing: initial)
        let frozen = try await store.suspendForLocalTransition()
        XCTAssertEqual(try NoctweaveCoder.encode(XCTUnwrap(frozen), sortedKeys: true), try NoctweaveCoder.encode(latest, sortedKeys: true))
        do { try await store.save(initial, replacing: latest); XCTFail("Late writer changed transition snapshot") } catch { }
        try await store.destroyLocalEncryptionMaterial(preservingCiphertext: false)
    }

    func testKeyDestructionRetainsCiphertextAndRejectsLateWrites() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("noctweave-duress-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("state.nwstate")
        let anchor = VolatileClientStateRollbackAnchorStore()
        let key = SymmetricKey(size: .bits256)
        let store = ClientStateStore(fileURL: file, encryptionKey: key, rollbackAnchorStore: anchor)
        let state = try ClientState(displayName: "Disposable")
        try await store.save(state, replacing: nil)
        let ciphertext = try Data(contentsOf: file)
        try await store.destroyLocalEncryptionMaterial(preservingCiphertext: true)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
        let retired = try FileManager.default.contentsOfDirectory(at: file.appendingPathExtension("retired"), includingPropertiesForKeys: nil)
        XCTAssertEqual(retired.count, 1)
        XCTAssertEqual(try Data(contentsOf: XCTUnwrap(retired.first)), ciphertext)
        do { _ = try await store.load(); XCTFail("Retired store decrypted") } catch { }
        do { try await store.save(state, replacing: state); XCTFail("Retired writer recreated state") } catch { }
        let fresh = ClientStateStore(fileURL: file, encryptionKey: SymmetricKey(size: .bits256), rollbackAnchorStore: anchor)
        let empty = try await fresh.load()
        XCTAssertNil(empty)
        let awaitingSetup = try await fresh.isAwaitingFreshState()
        XCTAssertTrue(awaitingSetup)
        let replacement = try ClientState(displayName: "Fresh profile")
        try await fresh.save(replacement, replacing: nil)
        do { try await store.eraseAllLocalState(); XCTFail("Retired store erased a fresh profile") } catch { }
        let reopened = try await fresh.load()
        XCTAssertEqual(try NoctweaveCoder.encode(XCTUnwrap(reopened), sortedKeys: true), try NoctweaveCoder.encode(replacement, sortedKeys: true))
        try ciphertext.write(to: file)
        do { _ = try await fresh.load(); XCTFail("Old ciphertext replay accepted") } catch { }
        // The caller deliberately retains the injected fixture key; copies outside
        // a store's authority are explicitly not covered by local key destruction.
    }

    func testWipeRemovesCiphertextAndPreventsRecreation() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("noctweave-duress-wipe-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("state.nwstate")
        let store = ClientStateStore(fileURL: file, encryptionKey: SymmetricKey(size: .bits256),
                                     rollbackAnchorStore: VolatileClientStateRollbackAnchorStore())
        let state = try ClientState(displayName: "Disposable")
        try await store.save(state, replacing: nil)
        try await store.destroyLocalEncryptionMaterial(preservingCiphertext: false)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
        do { try await store.save(state, replacing: nil); XCTFail("Retired writer recreated state") } catch { }
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }
    private func makeRelationship() throws -> PairwiseRelationshipV2 { try makePair().offererRelationship }

    private func makePair() throws -> ContactPairingResultV2 {
        var offer = try ContactPairingHandshakeV2.makeOffer(
            createdAt: Date(timeIntervalSince1970: 1_788_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_788_000_000).addingTimeInterval(300)
        )
        let first = try activateParticipant(name: "A", host: "a.example")
        let second = try activateParticipant(name: "B", host: "b.example")
        var ledger = RendezvousRedemptionLedgerV2()
        return try ContactPairingHandshakeV2.establish(
            pendingOffer: &offer.pending,
            invitation: offer.invitation,
            offerer: first,
            responder: second,
            ledger: &ledger,
            at: Date(timeIntervalSince1970: 1_788_000_000).addingTimeInterval(1)
        )
    }

    private func activateParticipant(
        name: String,
        host: String
    ) throws -> PreparedContactParticipantV2 {
        let pending = try PendingContactParticipantV2.prepare(
            relationshipPseudonym: name,
            relay: RelayEndpoint(
                host: host,
                port: 443,
                useTLS: true,
                transport: .websocket
            ),
            createdAt: Date(timeIntervalSince1970: 1_788_000_000)
        )
        let route = try OpaqueReceiveRouteV2.creating(
            from: pending.routeCreateRequest,
            presentedRenewCapability: pending.clientCapabilities.renewCapability,
            existing: nil,
            confidentialTransport: true,
            receivedAt: Date(timeIntervalSince1970: 1_788_000_000)
        )
        return try pending.activate(createdRoute: route)
    }


private func makeGenesisRecord(at date: Date) throws -> GroupRuntimeRecord {
    let groupID = UUID()
    let memberHandle = GroupScopedMemberHandleV2.generate()
    let signingKey = try SigningKeyPair.generate()
    let agreementKey = try AgreementKeyPair.generate()
    let admission = try GroupCredentialAdmissionV2.create(
        groupId: groupID,
        memberHandle: memberHandle,
        credentialHandle: .generate(),
        groupSigningKey: signingKey,
        groupAgreementKey: agreementKey,
        issuedAt: date,
        expiresAt: date.addingTimeInterval(24 * 60 * 60)
    )
    let leaf = try GroupMemberCredentialV2.fromVerifiedProjection(admission, addedEpoch: 1)
    let credential = LocalGroupCredentialV2(
        groupId: groupID,
        memberHandle: memberHandle,
        credentialHandle: leaf.credentialHandle,
        admissionDigest: leaf.admissionDigest,
        signingKey: signingKey,
        agreementKey: agreementKey
    )
    let creator = GroupMemberV2(id: memberHandle, role: .owner, addedEpoch: 1)
    let provider = NoctweavePQGroupExperimentalProviderV2()
    let membership = try provider.membership(
        groupId: groupID,
        epoch: 1,
        members: [creator],
        leaves: [leaf]
    )
    let prepared = try provider.prepareGenesis(
        membership: membership,
        localCredential: credential
    )
    let digest = try XCTUnwrap(prepared.providerCommitDigest)
    let state = try SignedGroupStateV2.initial(
        groupId: groupID,
        creator: creator,
        creatorAdmission: admission,
        providerGenesisDigest: digest,
        signingKey: signingKey,
        signedAt: date
    )
    let acceptance = GroupCryptoAcceptedEpochV2(
        proposal: prepared.proposal,
        providerCommitDigest: digest,
        signedCommitDigest: state.commitDigest,
        acceptedTranscriptHash: state.confirmedTranscriptHash
    )
    return GroupRuntimeRecord(
        groupId: groupID,
        localCredential: credential,
        signedState: state,
        cryptoState: try provider.finalizePreparedEpoch(prepared, acceptance: acceptance)
    )
}

}
