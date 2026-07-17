import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class NoctweavePQGroupRuntimeV2Tests: XCTestCase {
    func testClientStatePersistsOnlyCurrentGroupRuntimeRecords() throws {
        let fixture = try makeSignedFixture()
        var state = try makeCurrentClientState(
            identity: try Identity.generate(displayName: "Runtime profile"),
            relay: RelayEndpoint(host: "localhost", port: 9339)
        )
        try state.upsert(groupRuntime: fixture.record)

        XCTAssertEqual(state.groupRuntimes, [fixture.record])
        XCTAssertEqual(state.groupRuntime(for: fixture.record.groupId), fixture.record)
        XCTAssertTrue(state.isCurrentBaselineValid)

        let decoded = try NoctweaveCoder.decode(
            ClientState.self,
            from: NoctweaveCoder.encode(state, sortedKeys: true)
        )
        XCTAssertEqual(decoded.groupRuntimes, [fixture.record])

        let profileData = try NoctweaveCoder.encode(state.identityProfiles[0], sortedKeys: true)
        var profileObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: profileData) as? [String: Any]
        )
        profileObject.removeValue(forKey: "groupRuntimes")
        let missingCurrentField = try JSONSerialization.data(
            withJSONObject: profileObject,
            options: [.sortedKeys]
        )
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(IdentityProfile.self, from: missingCurrentField)
        )
    }

    func testProvisionalStateIsNominalAndApplicationRatchetsRejectReplayAndGaps() throws {
        let fixture = try makeSignedFixture()

        XCTAssertEqual(
            try fixture.provider.activationState(of: fixture.prepared.provisionalState),
            .provisional
        )
        XCTAssertThrowsError(try fixture.provider.encryptApplicationEvent(
            Data("blocked".utf8),
            state: fixture.prepared.provisionalState,
            signedState: fixture.state,
            localCredential: fixture.credential
        )) { error in
            XCTAssertEqual(
                error as? NoctweavePQGroupExperimentalErrorV2,
                .inactiveState
            )
        }

        let first = try fixture.provider.encryptApplicationEvent(
            Data("first".utf8),
            state: fixture.cryptoState,
            signedState: fixture.state,
            localCredential: fixture.credential,
            sentAt: fixture.now
        )
        let second = try fixture.provider.encryptApplicationEvent(
            Data("second".utf8),
            state: first.state,
            signedState: fixture.state,
            localCredential: fixture.credential,
            sentAt: fixture.now
        )
        let opened = try fixture.provider.decryptApplicationEvent(
            first.envelope,
            state: fixture.cryptoState,
            signedState: fixture.state
        )
        XCTAssertEqual(opened.plaintext, Data("first".utf8))
        XCTAssertThrowsError(try fixture.provider.decryptApplicationEvent(
            first.envelope,
            state: opened.state,
            signedState: fixture.state
        )) { error in
            XCTAssertEqual(error as? NoctweavePQGroupExperimentalErrorV2, .replay)
        }
        XCTAssertThrowsError(try fixture.provider.decryptApplicationEvent(
            second.envelope,
            state: fixture.cryptoState,
            signedState: fixture.state
        )) { error in
            XCTAssertEqual(error as? NoctweavePQGroupExperimentalErrorV2, .outOfOrder)
        }
    }

    func testWelcomeRequiresExactCredentialAndRemovalDoesNotRemoveSibling() throws {
        let provider = NoctweavePQGroupExperimentalProviderV2()
        let groupId = UUID()
        let ownerUserId = UUID()
        let siblingUserId = UUID()
        let owner = try makeCredential(groupId: groupId, userId: ownerUserId, marker: 1)
        let removed = try makeCredential(groupId: groupId, userId: siblingUserId, marker: 2)
        let retained = try makeCredential(groupId: groupId, userId: siblingUserId, marker: 3)
        let users = [
            GroupUser(id: ownerUserId, role: .owner, addedEpoch: 1),
            GroupUser(id: siblingUserId, role: .member, addedEpoch: 1)
        ]
        let leaves = [
            leaf(for: owner, addedEpoch: 1),
            leaf(for: removed, addedEpoch: 1),
            leaf(for: retained, addedEpoch: 1)
        ]
        let epochOne = try provider.membership(
            groupId: groupId,
            epoch: 1,
            users: users,
            leaves: leaves
        )
        let genesis = try provider.prepareGenesis(
            membership: epochOne,
            localCredential: owner
        )
        let genesisAcceptance = accepted(
            genesis,
            signedCommitDigest: bytes(0x41),
            transcriptHash: bytes(0x42)
        )
        let ownerState = try provider.finalizePreparedEpoch(
            genesis,
            acceptance: genesisAcceptance
        )
        let removedWelcome = try XCTUnwrap(genesis.welcomes.first {
            $0.destination == removed.clientHandle
        })
        let retainedWelcome = try XCTUnwrap(genesis.welcomes.first {
            $0.destination == retained.clientHandle
        })
        let removedState = try provider.processWelcome(
            removedWelcome,
            membership: epochOne,
            acceptance: genesisAcceptance,
            commitBytes: genesis.commitBytes,
            localCredential: removed
        )
        let retainedState = try provider.processWelcome(
            retainedWelcome,
            membership: epochOne,
            acceptance: genesisAcceptance,
            commitBytes: genesis.commitBytes,
            localCredential: retained
        )
        XCTAssertThrowsError(try provider.processWelcome(
            retainedWelcome,
            membership: epochOne,
            acceptance: genesisAcceptance,
            commitBytes: genesis.commitBytes,
            localCredential: owner
        )) { error in
            XCTAssertEqual(
                error as? NoctweavePQGroupExperimentalErrorV2,
                .wrongDestination
            )
        }

        let nextLeaves = [
            leaves[0],
            GroupClientLeafV2(
                userId: removed.groupUserId,
                clientHandle: removed.clientHandle,
                keyPackageDigest: removed.keyPackageDigest,
                signingPublicKey: removed.signingKey.publicKeyData,
                agreementPublicKey: removed.agreementKey.publicKeyData,
                addedEpoch: 1,
                removedEpoch: 2
            ),
            leaves[2]
        ]
        let epochTwo = try provider.membership(
            groupId: groupId,
            epoch: 2,
            users: users,
            leaves: nextLeaves
        )
        let prepared = try provider.prepareCommit(
            state: ownerState,
            currentMembership: epochOne,
            proposedMembership: epochTwo,
            localCredential: owner
        )
        let acceptance = accepted(
            prepared,
            signedCommitDigest: bytes(0x51),
            transcriptHash: bytes(0x52)
        )
        let retainedPackage = try XCTUnwrap(prepared.welcomes.first {
            $0.destination == retained.clientHandle
        })
        XCTAssertNoThrow(try provider.processCommit(
            state: retainedState,
            currentMembership: epochOne,
            proposedMembership: epochTwo,
            acceptance: acceptance,
            commitBytes: prepared.commitBytes,
            localPackage: retainedPackage,
            localCredential: retained
        ))
        XCTAssertNil(prepared.welcomes.first { $0.destination == removed.clientHandle })
        XCTAssertThrowsError(try provider.processCommit(
            state: removedState,
            currentMembership: epochOne,
            proposedMembership: epochTwo,
            acceptance: acceptance,
            commitBytes: prepared.commitBytes,
            localPackage: retainedPackage,
            localCredential: removed
        )) { error in
            XCTAssertEqual(
                error as? NoctweavePQGroupExperimentalErrorV2,
                .localClientRemoved
            )
        }
    }

    func testExperimentalProviderRejectsMoreThan128ActiveLeaves() throws {
        let provider = NoctweavePQGroupExperimentalProviderV2()
        let groupId = UUID()
        let userId = UUID()
        let credential = try makeCredential(groupId: groupId, userId: userId, marker: 9)
        var leaves: [GroupClientLeafV2] = []
        for index in 0...NoctweaveGroupArchitectureV2.maximumActiveExperimentalClientLeaves {
            var signingKey = credential.signingKey.publicKeyData
            var agreementKey = credential.agreementKey.publicKeyData
            signingKey[signingKey.count - 2] = UInt8((index >> 8) & 0xff)
            signingKey[signingKey.count - 1] = UInt8(index & 0xff)
            agreementKey[agreementKey.count - 2] = UInt8((index >> 8) & 0xff)
            agreementKey[agreementKey.count - 1] = UInt8(index & 0xff)
            leaves.append(GroupClientLeafV2(
                userId: userId,
                clientHandle: .generate(),
                keyPackageDigest: Data(SHA256.hash(data: Data("leaf-\(index)".utf8))),
                signingPublicKey: signingKey,
                agreementPublicKey: agreementKey,
                addedEpoch: 1
            ))
        }
        XCTAssertEqual(leaves.count, 129)
        XCTAssertThrowsError(try provider.membership(
            groupId: groupId,
            epoch: 1,
            users: [GroupUser(id: userId, role: .owner, addedEpoch: 1)],
            leaves: leaves
        )) { error in
            XCTAssertEqual(
                error as? NoctweavePQGroupExperimentalErrorV2,
                .invalidMembership
            )
        }
    }

    func testRuntimePersistsPreparedArtifactsAndResumesAfterCommitSaveFailure() async throws {
        let fixture = try makeSignedFixture()
        let store = TestGroupRuntimeStore(record: fixture.record, failOnSaveNumber: 2)
        let runtime = try NoctweavePQGroupRuntimeV2(
            record: fixture.record,
            persistence: store
        )
        let key = bytes(0x61)
        do {
            _ = try await runtime.prepareEpoch(
                operation: .updateMetadata,
                proposedUsers: fixture.state.users,
                proposedClientLeaves: fixture.state.clientLeaves,
                proposedPermissions: fixture.state.permissions,
                proposedMetadataDigest: bytes(0x62),
                idempotencyKey: key,
                createdAt: fixture.now.addingTimeInterval(1)
            )
            XCTFail("Expected the state-commit save to fail")
        } catch let error as TestGroupRuntimeStore.StoreError {
            XCTAssertEqual(error, .injectedFailure)
        }
        let loadedRecord = await store.load()
        let preparedRecord = try XCTUnwrap(loadedRecord)
        XCTAssertEqual(preparedRecord.signedState.epoch, 1)
        let preparedIntent = try XCTUnwrap(preparedRecord.epochIntents.first)
        XCTAssertEqual(preparedIntent.phase, .prepared)
        let expectedPublication = preparedIntent.publication

        await store.setFailOnSaveNumber(nil)
        let reopened = try await NoctweavePQGroupRuntimeV2.open(persistence: store)
        let resumed = try await reopened.resumePreparedEpoch(
            intentId: preparedIntent.id,
            at: fixture.now.addingTimeInterval(2)
        )
        XCTAssertEqual(resumed, expectedPublication)
        let committed = await reopened.snapshot()
        XCTAssertEqual(committed.signedState.epoch, 2)
        XCTAssertEqual(committed.epochIntents.first?.phase, .stateCommitted)
        XCTAssertEqual(committed.cryptoState, preparedIntent.nextCryptoState)
    }

    func testRuntimeRetriesExactArtifactsAndQuarantinesConflictingSameBaseCommit() async throws {
        let fixture = try makeSignedFixture()
        let store = TestGroupRuntimeStore(record: fixture.record)
        let runtime = try NoctweavePQGroupRuntimeV2(
            record: fixture.record,
            persistence: store
        )
        let key = bytes(0x71)
        let publication = try await runtime.prepareEpoch(
            operation: .updateMetadata,
            proposedUsers: fixture.state.users,
            proposedClientLeaves: fixture.state.clientLeaves,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: bytes(0x72),
            idempotencyKey: key,
            createdAt: fixture.now.addingTimeInterval(1)
        )
        let duplicate = try await runtime.prepareEpoch(
            operation: .updateMetadata,
            proposedUsers: [],
            proposedClientLeaves: [],
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: nil,
            idempotencyKey: key,
            createdAt: fixture.now.addingTimeInterval(2)
        )
        XCTAssertEqual(duplicate, publication)
        let observed = try await runtime.observeCommit(
            publication.signedCommit,
            at: fixture.now.addingTimeInterval(3)
        )
        XCTAssertEqual(observed, publication)

        try await runtime.markFanoutStored(
            intentId: publication.intentId,
            destinationClientHandle: fixture.credential.clientHandle,
            at: fixture.now.addingTimeInterval(4)
        )
        let fanoutSnapshot = await runtime.snapshot()
        XCTAssertEqual(fanoutSnapshot.epochIntents.first?.phase, .fanoutInProgress)
        try await runtime.finalizeEpoch(
            intentId: publication.intentId,
            at: fixture.now.addingTimeInterval(5)
        )
        let finalizedSnapshot = await runtime.snapshot()
        XCTAssertEqual(finalizedSnapshot.epochIntents.first?.phase, .finalized)

        let conflicting = try SignedGroupCommitV2.create(
            operation: .updateMetadata,
            currentState: fixture.state,
            proposedUsers: fixture.state.users,
            proposedClientLeaves: fixture.state.clientLeaves,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: bytes(0x73),
            authorClientHandle: fixture.credential.clientHandle,
            providerCommitDigest: bytes(0x74),
            idempotencyKey: bytes(0x75),
            signingKey: fixture.credential.signingKey,
            createdAt: fixture.now.addingTimeInterval(6)
        )
        await XCTAssertThrowsErrorAsync(try await runtime.observeCommit(
            conflicting,
            at: fixture.now.addingTimeInterval(7)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .conflictingCommitQuarantined)
        }
        let quarantined = await runtime.snapshot()
        XCTAssertEqual(quarantined.signedState.epoch, 2)
        XCTAssertEqual(quarantined.quarantinedForks.count, 1)
        XCTAssertEqual(
            quarantined.quarantinedForks.first?.conflictingCommit.digest,
            conflicting.digest
        )
    }
}

private struct SignedGroupRuntimeFixture {
    let now: Date
    let provider: NoctweavePQGroupExperimentalProviderV2
    let credential: LocalGroupClientCredential
    let membership: GroupProviderMembershipV2
    let prepared: GroupCryptoPreparedEpochV2
    let state: SignedGroupStateV2
    let cryptoState: GroupCryptoState
    let record: GroupRuntimeRecord
}

private func makeSignedFixture() throws -> SignedGroupRuntimeFixture {
    let now = Date(timeIntervalSince1970: 1_789_000_000)
    let groupId = UUID()
    let userId = UUID()
    let identityGenerationId = UUID()
    let identity = try Identity.generate(displayName: "Group fixture")
    let local = try LocalEndpointState.generate(
        identityGenerationId: identityGenerationId,
        createdAt: now.addingTimeInterval(-20)
    )
    let manifest = try EndpointSetManifest.create(
        identityGenerationId: identityGenerationId,
        epoch: 0,
        endpoints: [local.publicRecord(addedEpoch: 0)],
        identity: identity,
        issuedAt: now.addingTimeInterval(-10)
    )
    let signingKey = try SigningKeyPair.generate()
    let agreementKey = try AgreementKeyPair.generate()
    let package = try GroupClientKeyPackageV2.create(
        groupId: groupId,
        groupUserId: userId,
        clientHandle: .generate(),
        identity: identity,
        endpoint: local,
        manifest: manifest,
        groupSigningKey: signingKey,
        groupAgreementKey: agreementKey,
        issuedAt: now,
        expiresAt: now.addingTimeInterval(3_600)
    )
    let leaf = try GroupClientLeafV2.fromVerifiedPackage(package, addedEpoch: 1)
    let credential = LocalGroupClientCredential(
        groupId: groupId,
        groupUserId: userId,
        clientHandle: leaf.clientHandle,
        keyPackageDigest: leaf.keyPackageDigest,
        signingKey: signingKey,
        agreementKey: agreementKey
    )
    let creator = GroupUser(id: userId, role: .owner, addedEpoch: 1)
    let provider = NoctweavePQGroupExperimentalProviderV2()
    let membership = try provider.membership(
        groupId: groupId,
        epoch: 1,
        users: [creator],
        leaves: [leaf]
    )
    let prepared = try provider.prepareGenesis(
        membership: membership,
        localCredential: credential
    )
    let providerDigest = try XCTUnwrap(prepared.providerCommitDigest)
    let trust = GroupGenesisTrustV2(
        creatorUserId: userId,
        identityPublicKey: identity.signingKey.publicKeyData,
        currentManifest: manifest,
        creatorKeyPackage: package
    )
    let state = try SignedGroupStateV2.initial(
        groupId: groupId,
        creator: creator,
        creatorTrust: trust,
        providerGenesisDigest: providerDigest,
        signingKey: signingKey,
        signedAt: now
    )
    let acceptance = GroupCryptoAcceptedEpochV2(
        proposal: prepared.proposal,
        providerCommitDigest: providerDigest,
        signedCommitDigest: state.commitDigest,
        acceptedTranscriptHash: state.confirmedTranscriptHash
    )
    let cryptoState = try provider.finalizePreparedEpoch(
        prepared,
        acceptance: acceptance
    )
    let record = GroupRuntimeRecord(
        groupId: groupId,
        localCredential: credential,
        signedState: state,
        cryptoState: cryptoState
    )
    XCTAssertTrue(record.isStructurallyValid)
    return SignedGroupRuntimeFixture(
        now: now,
        provider: provider,
        credential: credential,
        membership: membership,
        prepared: prepared,
        state: state,
        cryptoState: cryptoState,
        record: record
    )
}

private func makeCredential(
    groupId: UUID,
    userId: UUID,
    marker: UInt8
) throws -> LocalGroupClientCredential {
    LocalGroupClientCredential(
        groupId: groupId,
        groupUserId: userId,
        clientHandle: .generate(),
        keyPackageDigest: Data(SHA256.hash(data: Data([marker]))),
        signingKey: try SigningKeyPair.generate(),
        agreementKey: try AgreementKeyPair.generate()
    )
}

private func leaf(
    for credential: LocalGroupClientCredential,
    addedEpoch: UInt64,
    removedEpoch: UInt64? = nil
) -> GroupClientLeafV2 {
    GroupClientLeafV2(
        userId: credential.groupUserId,
        clientHandle: credential.clientHandle,
        keyPackageDigest: credential.keyPackageDigest,
        signingPublicKey: credential.signingKey.publicKeyData,
        agreementPublicKey: credential.agreementKey.publicKeyData,
        addedEpoch: addedEpoch,
        removedEpoch: removedEpoch
    )
}

private func accepted(
    _ prepared: GroupCryptoPreparedEpochV2,
    signedCommitDigest: Data,
    transcriptHash: Data
) -> GroupCryptoAcceptedEpochV2 {
    GroupCryptoAcceptedEpochV2(
        proposal: prepared.proposal,
        providerCommitDigest: prepared.providerCommitDigest!,
        signedCommitDigest: signedCommitDigest,
        acceptedTranscriptHash: transcriptHash
    )
}

private func bytes(_ value: UInt8) -> Data {
    Data(repeating: value, count: 32)
}

private actor TestGroupRuntimeStore: GroupRuntimeRecordPersistence {
    enum StoreError: Error, Equatable {
        case injectedFailure
    }

    private var record: GroupRuntimeRecord?
    private var saveCount = 0
    private var failOnSaveNumber: Int?

    init(record: GroupRuntimeRecord, failOnSaveNumber: Int? = nil) {
        self.record = record
        self.failOnSaveNumber = failOnSaveNumber
    }

    func load() -> GroupRuntimeRecord? { record }

    func save(_ record: GroupRuntimeRecord) throws {
        saveCount += 1
        if saveCount == failOnSaveNumber { throw StoreError.injectedFailure }
        self.record = record
    }

    func setFailOnSaveNumber(_ number: Int?) {
        failOnSaveNumber = number
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ errorHandler: (Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("Expected expression to throw")
    } catch {
        errorHandler(error)
    }
}
