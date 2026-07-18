import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class NoctweavePQGroupRuntimeV2Tests: XCTestCase {
    func testRuntimePersistsExactApplicationOutboxAndIdempotentInboundReplay() async throws {
        let fixture = try makeSignedFixture()
        let senderStore = TestGroupRuntimeStore(record: fixture.record)
        let receiverStore = TestGroupRuntimeStore(record: fixture.record)
        let sender = try NoctweavePQGroupRuntimeV2(
            record: fixture.record,
            persistence: senderStore
        )
        let receiver = try NoctweavePQGroupRuntimeV2(
            record: fixture.record,
            persistence: receiverStore
        )
        let event = GroupConversationEventV2(
            groupID: fixture.record.groupId,
            createdAt: fixture.now,
            kind: .application,
            content: try XCTUnwrap(.text("group-scoped hello"))
        )

        let envelope = try await sender.prepareApplicationEvent(event, at: fixture.now)
        let exactRetry = try await sender.prepareApplicationEvent(event, at: fixture.now)
        XCTAssertEqual(exactRetry, envelope)
        var senderSnapshot = await sender.snapshot()
        XCTAssertEqual(senderSnapshot.events, [event])
        XCTAssertEqual(senderSnapshot.pendingApplicationPublications.count, 1)
        let pendingPublications = await sender.pendingApplicationPublications()
        XCTAssertEqual(
            pendingPublications.first?.envelope,
            envelope
        )

        let receivedEvent = try await receiver.processApplicationEnvelope(
            envelope,
            at: fixture.now
        )
        XCTAssertEqual(receivedEvent, event)
        let replaySnapshot = await receiver.snapshot()
        let replayedEvent = try await receiver.processApplicationEnvelope(
            envelope,
            at: fixture.now
        )
        XCTAssertEqual(replayedEvent, event)
        let replayedSnapshot = await receiver.snapshot()
        XCTAssertEqual(replayedSnapshot, replaySnapshot)

        var mutatedCiphertext = envelope.payload.ciphertext
        mutatedCiphertext[mutatedCiphertext.startIndex] ^= 0x01
        let conflicting = GroupApplicationEnvelopeV2(
            profile: envelope.profile,
            cipherSuite: envelope.cipherSuite,
            groupId: envelope.groupId,
            epoch: envelope.epoch,
            transcriptHash: envelope.transcriptHash,
            senderCredentialHandle: envelope.senderCredentialHandle,
            eventId: envelope.eventId,
            messageCounter: envelope.messageCounter,
            sentAt: envelope.sentAt,
            payload: EncryptedPayload(
                nonce: envelope.payload.nonce,
                ciphertext: mutatedCiphertext,
                tag: envelope.payload.tag
            ),
            signature: envelope.signature
        )
        XCTAssertTrue(conflicting.isStructurallyValid)
        do {
            _ = try await receiver.processApplicationEnvelope(conflicting, at: fixture.now)
            XCTFail("Expected conflicting group envelope rejection")
        } catch {
            XCTAssertEqual(error as? GroupRuntimeError, .conflictingApplicationEnvelope)
        }

        try await sender.markApplicationPublished(eventID: event.id)
        senderSnapshot = await sender.snapshot()
        XCTAssertTrue(senderSnapshot.pendingApplicationPublications.isEmpty)
        XCTAssertEqual(senderSnapshot.events, [event])
        try assertExactRoundTrip(
            try XCTUnwrap(replaySnapshot.processedApplicationEnvelopes.first),
            as: ProcessedGroupApplicationEnvelopeV2.self
        )
    }

    func testGroupEnvelopeFanoutCreatesPersistableExactOpaqueRoutePackets() throws {
        let fixture = try makeSignedFixture()
        let event = GroupConversationEventV2(
            groupID: fixture.record.groupId,
            createdAt: fixture.now,
            kind: .application,
            content: try XCTUnwrap(.text("opaque group fanout"))
        )
        let sealed = try fixture.provider.encryptApplicationEvent(
            try NoctweaveCoder.encode(event, sortedKeys: true),
            state: fixture.cryptoState,
            signedState: fixture.state,
            localCredential: fixture.credential,
            eventId: event.id,
            sentAt: fixture.now
        )
        let firstRoute = try makeGroupSendRoute(marker: 0x31, now: fixture.now)
        let secondRoute = try makeGroupSendRoute(marker: 0x32, now: fixture.now)
        let destination = GroupScopedCredentialHandleV2.generate()
        let plan = try GroupOpaqueRouteFanoutPlanV2.create(
            envelope: .groupApplicationV2(sealed.envelope),
            groupID: fixture.record.groupId,
            destinations: [
                GroupOpaqueRouteDestinationV2(
                    credentialHandle: destination,
                    routes: [firstRoute, secondRoute]
                )
            ],
            at: fixture.now
        )

        XCTAssertTrue(plan.isStructurallyValid)
        XCTAssertEqual(plan.publications.count, 2)
        XCTAssertEqual(Set(plan.publications.map(\.destinationCredentialHandle)), [destination])
        try assertExactRoundTrip(plan, as: GroupOpaqueRouteFanoutPlanV2.self)
        let encodedEnvelope = try NoctweaveCoder.encode(
            ProtocolEnvelopeV1.groupApplicationV2(sealed.envelope),
            sortedKeys: true
        )
        for publication in plan.publications {
            let route = publication.destinationRouteID == firstRoute.routeID
                ? firstRoute
                : secondRoute
            var reassembler = try OpaqueRoutePacketReassemblerV2()
            var reconstructed: OpaqueRouteReassembledBundleV2?
            for packet in publication.packets {
                if case let .complete(bundle) = try reassembler.consume(
                    packet,
                    payloadKey: route.payloadKey,
                    routeRevision: route.routeRevision
                ) {
                    reconstructed = bundle
                }
            }
            XCTAssertEqual(reconstructed?.payload, encodedEnvelope)
        }
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

    func testWelcomeRequiresExactCredentialAndReplacementIsAtomic() throws {
        let provider = NoctweavePQGroupExperimentalProviderV2()
        let groupId = UUID()
        let ownerMemberId = GroupScopedMemberHandleV2.generate()
        let memberId = GroupScopedMemberHandleV2.generate()
        let owner = try makeCredential(groupId: groupId, memberHandle: ownerMemberId, marker: 1)
        let previous = try makeCredential(groupId: groupId, memberHandle: memberId, marker: 2)
        let replacement = try makeCredential(groupId: groupId, memberHandle: memberId, marker: 3)
        let members = [
            GroupMemberV2(id: ownerMemberId, role: .owner, addedEpoch: 1),
            GroupMemberV2(id: memberId, role: .member, addedEpoch: 1)
        ]
        let leaves = [
            leaf(for: owner, addedEpoch: 1),
            leaf(for: previous, addedEpoch: 1)
        ]
        let epochOne = try provider.membership(
            groupId: groupId,
            epoch: 1,
            members: members,
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
        let previousWelcome = try XCTUnwrap(genesis.welcomes.first {
            $0.destination == previous.credentialHandle
        })
        let previousState = try provider.processWelcome(
            previousWelcome,
            membership: epochOne,
            acceptance: genesisAcceptance,
            commitBytes: genesis.commitBytes,
            localCredential: previous
        )
        XCTAssertThrowsError(try provider.processWelcome(
            previousWelcome,
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
            leaf(for: previous, addedEpoch: 1, removedEpoch: 2),
            leaf(for: replacement, addedEpoch: 2)
        ]
        let epochTwo = try provider.membership(
            groupId: groupId,
            epoch: 2,
            members: members,
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
        let ownerPackage = try XCTUnwrap(prepared.welcomes.first {
            $0.destination == owner.credentialHandle
        })
        XCTAssertNoThrow(try provider.processCommit(
            state: ownerState,
            currentMembership: epochOne,
            proposedMembership: epochTwo,
            acceptance: acceptance,
            commitBytes: prepared.commitBytes,
            localPackage: ownerPackage,
            localCredential: owner
        ))
        XCTAssertNil(prepared.welcomes.first { $0.destination == previous.credentialHandle })
        let replacementPackage = try XCTUnwrap(prepared.welcomes.first {
            $0.destination == replacement.credentialHandle
        })
        XCTAssertNoThrow(try provider.processWelcome(
            replacementPackage,
            membership: epochTwo,
            acceptance: acceptance,
            commitBytes: prepared.commitBytes,
            localCredential: replacement
        ))
        XCTAssertThrowsError(try provider.processCommit(
            state: previousState,
            currentMembership: epochOne,
            proposedMembership: epochTwo,
            acceptance: acceptance,
            commitBytes: prepared.commitBytes,
            localPackage: replacementPackage,
            localCredential: previous
        )) { error in
            XCTAssertEqual(
                error as? NoctweavePQGroupExperimentalErrorV2,
                .localCredentialRemoved
            )
        }
    }

    func testExperimentalProviderRejectsMoreThan128ActiveLeaves() throws {
        let provider = NoctweavePQGroupExperimentalProviderV2()
        let groupId = UUID()
        let credential = try makeCredential(
            groupId: groupId,
            memberHandle: .generate(),
            marker: 9
        )
        var members: [GroupMemberV2] = []
        var leaves: [GroupMemberCredentialV2] = []
        for index in 0...NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials {
            let memberHandle = GroupScopedMemberHandleV2.generate()
            var signingKey = credential.signingKey.publicKeyData
            var agreementKey = credential.agreementKey.publicKeyData
            signingKey[signingKey.count - 2] = UInt8((index >> 8) & 0xff)
            signingKey[signingKey.count - 1] = UInt8(index & 0xff)
            agreementKey[agreementKey.count - 2] = UInt8((index >> 8) & 0xff)
            agreementKey[agreementKey.count - 1] = UInt8(index & 0xff)
            members.append(GroupMemberV2(
                id: memberHandle,
                role: index == 0 ? .owner : .member,
                addedEpoch: 1
            ))
            leaves.append(GroupMemberCredentialV2(
                memberHandle: memberHandle,
                credentialHandle: .generate(),
                admissionDigest: Data(SHA256.hash(data: Data("leaf-\(index)".utf8))),
                signingPublicKey: signingKey,
                agreementPublicKey: agreementKey,
                addedEpoch: 1
            ))
        }
        XCTAssertEqual(leaves.count, 129)
        XCTAssertThrowsError(try provider.membership(
            groupId: groupId,
            epoch: 1,
            members: members,
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
                proposedMembers: fixture.state.members,
                proposedCredentials: fixture.state.memberCredentials,
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
            proposedMembers: fixture.state.members,
            proposedCredentials: fixture.state.memberCredentials,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: bytes(0x72),
            idempotencyKey: key,
            createdAt: fixture.now.addingTimeInterval(1)
        )
        let duplicate = try await runtime.prepareEpoch(
            operation: .updateMetadata,
            proposedMembers: [],
            proposedCredentials: [],
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
            destinationCredentialHandle: fixture.credential.credentialHandle,
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
            proposedMembers: fixture.state.members,
            proposedCredentials: fixture.state.memberCredentials,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: bytes(0x73),
            authorCredentialHandle: fixture.credential.credentialHandle,
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

    func testRuntimeCredentialReplacementSurvivesAtomicStateCommit() async throws {
        let fixture = try makeSignedFixture()
        let replacementSigningKey = try SigningKeyPair.generate()
        let replacementAgreementKey = try AgreementKeyPair.generate()
        let admission = try GroupCredentialAdmissionV2.create(
            groupId: fixture.state.groupId,
            memberHandle: fixture.credential.memberHandle,
            groupSigningKey: replacementSigningKey,
            groupAgreementKey: replacementAgreementKey,
            issuedAt: fixture.now,
            expiresAt: fixture.now.addingTimeInterval(3_600)
        )
        let replacementLeaf = try GroupMemberCredentialV2.fromVerifiedProjection(
            admission,
            addedEpoch: fixture.state.epoch + 1
        )
        let previous = try XCTUnwrap(fixture.state.activeCredentials.first)
        let retired = GroupMemberCredentialV2(
            memberHandle: previous.memberHandle,
            credentialHandle: previous.credentialHandle,
            admissionDigest: previous.admissionDigest,
            signingPublicKey: previous.signingPublicKey,
            agreementPublicKey: previous.agreementPublicKey,
            addedEpoch: previous.addedEpoch,
            removedEpoch: fixture.state.epoch + 1
        )
        let replacementCredential = LocalGroupCredentialV2(
            groupId: fixture.state.groupId,
            memberHandle: fixture.credential.memberHandle,
            credentialHandle: replacementLeaf.credentialHandle,
            admissionDigest: replacementLeaf.admissionDigest,
            signingKey: replacementSigningKey,
            agreementKey: replacementAgreementKey
        )
        let store = TestGroupRuntimeStore(record: fixture.record)
        let runtime = try NoctweavePQGroupRuntimeV2(
            record: fixture.record,
            persistence: store
        )
        let publication = try await runtime.prepareEpoch(
            operation: .replaceCredential,
            proposedMembers: fixture.state.members,
            proposedCredentials: [retired, replacementLeaf],
            admissionProjection: admission,
            replacementLocalCredential: replacementCredential,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: fixture.state.metadataDigest,
            idempotencyKey: bytes(0x81),
            createdAt: fixture.now.addingTimeInterval(1)
        )
        let snapshot = await runtime.snapshot()
        XCTAssertEqual(snapshot.localCredential, replacementCredential)
        XCTAssertEqual(snapshot.signedState.epoch, 2)
        XCTAssertEqual(snapshot.signedState.activeCredentials, [replacementLeaf])
        XCTAssertEqual(
            publication.signedCommit.operation,
            .replaceCredential
        )
        XCTAssertNoThrow(try fixture.provider.validateActiveState(
            snapshot.cryptoState,
            signedState: snapshot.signedState,
            localCredential: replacementCredential
        ))
    }

    func testGroupEpochIntentCompactionPreservesUnfinishedRecoveryState() async throws {
        let fixture = try makeSignedFixture()
        let runtime = try NoctweavePQGroupRuntimeV2(
            record: fixture.record,
            persistence: TestGroupRuntimeStore(record: fixture.record)
        )
        let publication = try await runtime.prepareEpoch(
            operation: .updateMetadata,
            proposedMembers: fixture.state.members,
            proposedCredentials: fixture.state.memberCredentials,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: bytes(0xa1),
            idempotencyKey: bytes(0xa2),
            createdAt: fixture.now.addingTimeInterval(1)
        )
        try await runtime.finalizeEpoch(
            intentId: publication.intentId,
            at: fixture.now.addingTimeInterval(2)
        )
        let snapshot = await runtime.snapshot()
        let template = try XCTUnwrap(snapshot.epochIntents.first)
        XCTAssertEqual(template.phase, .finalized)

        var intents: [GroupEpochIntent] = []
        intents.reserveCapacity(NoctweaveArchitectureV2.maximumGroupEpochIntents)
        for index in 0..<NoctweaveArchitectureV2.maximumGroupEpochIntents {
            let date = fixture.now.addingTimeInterval(TimeInterval(100 + index))
            intents.append(GroupEpochIntent(
                id: UUID(),
                idempotencyKey: Data(SHA256.hash(data: Data("group-intent-\(index)".utf8))),
                groupId: template.groupId,
                baseEpoch: template.baseEpoch,
                nextEpoch: template.nextEpoch,
                signedCommitDigest: template.signedCommitDigest,
                phase: index == 0 ? .stateCommitted : .finalized,
                signedCommit: template.signedCommit,
                nextSignedState: template.nextSignedState,
                nextCryptoState: template.nextCryptoState,
                localCredentialAfterCommit: template.localCredentialAfterCommit,
                providerCommitBytes: template.providerCommitBytes,
                signedWelcomes: template.signedWelcomes,
                createdAt: date,
                updatedAt: date
            ))
        }
        let unfinishedID = intents[0].id
        let discardedOldFinalizedID = intents[1].id
        let newestFinalizedID = try XCTUnwrap(intents.last?.id)
        let full = GroupRuntimeRecord(
            groupId: snapshot.groupId,
            localCredential: snapshot.localCredential,
            signedState: snapshot.signedState,
            cryptoState: snapshot.cryptoState,
            epochIntents: intents,
            quarantinedForks: snapshot.quarantinedForks
        )
        XCTAssertTrue(full.isStructurallyValid)

        let compacted = try full.compactedDurableState()

        XCTAssertTrue(compacted.isStructurallyValid)
        XCTAssertEqual(
            compacted.epochIntents.count,
            NoctweaveArchitectureV2.groupEpochIntentRecentWindow + 1
        )
        XCTAssertTrue(compacted.epochIntents.contains { $0.id == unfinishedID })
        XCTAssertFalse(compacted.epochIntents.contains { $0.id == discardedOldFinalizedID })
        XCTAssertTrue(compacted.epochIntents.contains { $0.id == newestFinalizedID })
    }

    func testPersistedRuntimeTypesRejectUnknownFields() async throws {
        let fixture = try makeSignedFixture()
        let runtime = try NoctweavePQGroupRuntimeV2(
            record: fixture.record,
            persistence: TestGroupRuntimeStore(record: fixture.record)
        )
        let publication = try await runtime.prepareEpoch(
            operation: .updateMetadata,
            proposedMembers: fixture.state.members,
            proposedCredentials: fixture.state.memberCredentials,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: bytes(0x91),
            idempotencyKey: bytes(0x92),
            createdAt: fixture.now.addingTimeInterval(1)
        )
        let snapshot = await runtime.snapshot()
        let intent = try XCTUnwrap(snapshot.epochIntents.first)
        try assertExactRoundTrip(intent, as: GroupEpochIntent.self)

        let conflicting = try SignedGroupCommitV2.create(
            operation: .updateMetadata,
            currentState: fixture.state,
            proposedMembers: fixture.state.members,
            proposedCredentials: fixture.state.memberCredentials,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: bytes(0x93),
            authorCredentialHandle: fixture.credential.credentialHandle,
            providerCommitDigest: bytes(0x94),
            idempotencyKey: bytes(0x95),
            signingKey: fixture.credential.signingKey,
            createdAt: fixture.now.addingTimeInterval(2)
        )
        let quarantine = GroupEpochForkQuarantine(
            groupId: fixture.state.groupId,
            baseEpoch: fixture.state.epoch,
            acceptedCommitDigest: try XCTUnwrap(publication.signedCommit.digest),
            conflictingCommitDigest: try XCTUnwrap(conflicting.digest),
            conflictingCommit: conflicting,
            quarantinedAt: fixture.now.addingTimeInterval(3)
        )
        XCTAssertTrue(quarantine.isStructurallyValid)
        try assertExactRoundTrip(quarantine, as: GroupEpochForkQuarantine.self)
        try assertExactRoundTrip(snapshot, as: GroupRuntimeRecord.self)
    }
}

private struct SignedGroupRuntimeFixture {
    let now: Date
    let provider: NoctweavePQGroupExperimentalProviderV2
    let credential: LocalGroupCredentialV2
    let membership: GroupProviderMembershipV2
    let prepared: GroupCryptoPreparedEpochV2
    let state: SignedGroupStateV2
    let cryptoState: GroupCryptoState
    let record: GroupRuntimeRecord
}

private func makeSignedFixture() throws -> SignedGroupRuntimeFixture {
    let now = Date(timeIntervalSince1970: 1_789_000_000)
    let groupId = UUID()
    let memberHandle = GroupScopedMemberHandleV2.generate()
    let signingKey = try SigningKeyPair.generate()
    let agreementKey = try AgreementKeyPair.generate()
    let admission = try GroupCredentialAdmissionV2.create(
        groupId: groupId,
        memberHandle: memberHandle,
        credentialHandle: .generate(),
        groupSigningKey: signingKey,
        groupAgreementKey: agreementKey,
        issuedAt: now,
        expiresAt: now.addingTimeInterval(3_600)
    )
    let leaf = try GroupMemberCredentialV2.fromVerifiedProjection(admission, addedEpoch: 1)
    let credential = LocalGroupCredentialV2(
        groupId: groupId,
        memberHandle: memberHandle,
        credentialHandle: leaf.credentialHandle,
        admissionDigest: leaf.admissionDigest,
        signingKey: signingKey,
        agreementKey: agreementKey
    )
    let creator = GroupMemberV2(id: memberHandle, role: .owner, addedEpoch: 1)
    let provider = NoctweavePQGroupExperimentalProviderV2()
    let membership = try provider.membership(
        groupId: groupId,
        epoch: 1,
        members: [creator],
        leaves: [leaf]
    )
    let prepared = try provider.prepareGenesis(
        membership: membership,
        localCredential: credential
    )
    let providerDigest = try XCTUnwrap(prepared.providerCommitDigest)
    let state = try SignedGroupStateV2.initial(
        groupId: groupId,
        creator: creator,
        creatorAdmission: admission,
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
    memberHandle: GroupScopedMemberHandleV2,
    marker: UInt8
) throws -> LocalGroupCredentialV2 {
    LocalGroupCredentialV2(
        groupId: groupId,
        memberHandle: memberHandle,
        credentialHandle: .generate(),
        admissionDigest: Data(SHA256.hash(data: Data([marker]))),
        signingKey: try SigningKeyPair.generate(),
        agreementKey: try AgreementKeyPair.generate()
    )
}

private func leaf(
    for credential: LocalGroupCredentialV2,
    addedEpoch: UInt64,
    removedEpoch: UInt64? = nil
) -> GroupMemberCredentialV2 {
    GroupMemberCredentialV2(
        memberHandle: credential.memberHandle,
        credentialHandle: credential.credentialHandle,
        admissionDigest: credential.admissionDigest,
        signingPublicKey: credential.signingKey.publicKeyData,
        agreementPublicKey: credential.agreementKey.publicKeyData,
        addedEpoch: addedEpoch,
        removedEpoch: removedEpoch
    )
}

private func makeGroupSendRoute(marker: UInt8, now: Date) throws -> OpaqueSendRouteV2 {
    try OpaqueSendRouteV2(
        routeID: OpaqueReceiveRouteIDV2(
            rawValue: Data(repeating: marker, count: 32)
        ),
        relay: RelayEndpoint(host: "127.0.0.1", port: 9_340),
        sendCapability: .generate(),
        payloadKey: .generate(),
        routeRevision: 0,
        policy: OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .sixHours,
            quotaBucket: .packets256
        ),
        validFrom: now,
        expiresAt: now.addingTimeInterval(3_600),
        state: .active,
        testedAt: now
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

private func assertExactRoundTrip<T: Codable & Equatable>(
    _ value: T,
    as type: T.Type,
    file: StaticString = #filePath,
    line: UInt = #line
) throws {
    let encoded = try NoctweaveCoder.encode(value, sortedKeys: true)
    XCTAssertEqual(
        try NoctweaveCoder.decode(type, from: encoded),
        value,
        file: file,
        line: line
    )
    var object = try XCTUnwrap(
        JSONSerialization.jsonObject(with: encoded) as? [String: Any],
        file: file,
        line: line
    )
    object["unknownState"] = true
    let unknown = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    XCTAssertThrowsError(
        try NoctweaveCoder.decode(type, from: unknown),
        file: file,
        line: line
    )
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
