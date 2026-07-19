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
            authorMemberHandle: fixture.credential.memberHandle,
            authorCredentialHandle: fixture.credential.credentialHandle,
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
        try assertExactRoundTrip(event, as: GroupConversationEventV2.self)
        try assertExactRoundTrip(
            try XCTUnwrap(replaySnapshot.processedApplicationEnvelopes.first),
            as: ProcessedGroupApplicationEnvelopeV2.self
        )
    }

    func testGroupEnvelopeFanoutCreatesPersistableExactOpaqueRoutePackets() throws {
        let fixture = try makeSignedFixture()
        let event = GroupConversationEventV2(
            groupID: fixture.record.groupId,
            authorMemberHandle: fixture.credential.memberHandle,
            authorCredentialHandle: fixture.credential.credentialHandle,
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

    func testAuthenticatedAuthorMismatchIsDurablyRejectedWithoutPinningSenderChain() async throws {
        let fixture = try makeSignedFixture()
        let store = TestGroupRuntimeStore(record: fixture.record)
        let receiver = try NoctweavePQGroupRuntimeV2(
            record: fixture.record,
            persistence: store
        )
        let poison = GroupConversationEventV2(
            groupID: fixture.record.groupId,
            authorMemberHandle: .generate(),
            authorCredentialHandle: fixture.credential.credentialHandle,
            createdAt: fixture.now,
            kind: .application,
            content: try XCTUnwrap(.text("wrong group member handle"))
        )
        let poisonSeal = try fixture.provider.encryptApplicationEvent(
            try NoctweaveCoder.encode(poison, sortedKeys: true),
            state: fixture.cryptoState,
            signedState: fixture.state,
            localCredential: fixture.credential,
            eventId: poison.id,
            sentAt: fixture.now
        )

        await XCTAssertThrowsErrorAsync(try await receiver.processApplicationEnvelope(
            poisonSeal.envelope,
            at: fixture.now.addingTimeInterval(1)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .conflictingApplicationEnvelope)
        }
        let rejected = await receiver.snapshot()
        XCTAssertTrue(rejected.events.isEmpty)
        XCTAssertEqual(
            rejected.processedApplicationEnvelopes.first?.outcome,
            .rejectedConflictingEnvelope
        )
        await XCTAssertThrowsErrorAsync(try await receiver.processApplicationEnvelope(
            poisonSeal.envelope,
            at: fixture.now.addingTimeInterval(2)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .conflictingApplicationEnvelope)
        }
        let replaySnapshot = await receiver.snapshot()
        XCTAssertEqual(replaySnapshot, rejected)

        let valid = GroupConversationEventV2(
            groupID: fixture.record.groupId,
            authorMemberHandle: fixture.credential.memberHandle,
            authorCredentialHandle: fixture.credential.credentialHandle,
            createdAt: fixture.now,
            kind: .application,
            content: try XCTUnwrap(.text("chain continues"))
        )
        let validSeal = try fixture.provider.encryptApplicationEvent(
            try NoctweaveCoder.encode(valid, sortedKeys: true),
            state: poisonSeal.state,
            signedState: fixture.state,
            localCredential: fixture.credential,
            eventId: valid.id,
            sentAt: fixture.now
        )
        let validResult = try await receiver.processApplicationEnvelope(
            validSeal.envelope,
            at: fixture.now.addingTimeInterval(3)
        )
        XCTAssertEqual(validResult, valid)
    }

    func testPerAuthorClientTransactionReplayIsBoundedAndDoesNotPinChain() async throws {
        let fixture = try makeSignedFixture()
        let store = TestGroupRuntimeStore(record: fixture.record)
        let receiver = try NoctweavePQGroupRuntimeV2(
            record: fixture.record,
            persistence: store
        )
        let transactionID = UUID()
        let first = GroupConversationEventV2(
            clientTransactionID: transactionID,
            groupID: fixture.record.groupId,
            authorMemberHandle: fixture.credential.memberHandle,
            authorCredentialHandle: fixture.credential.credentialHandle,
            createdAt: fixture.now,
            kind: .application,
            content: try XCTUnwrap(.text("first logical send"))
        )
        let firstSeal = try fixture.provider.encryptApplicationEvent(
            try NoctweaveCoder.encode(first, sortedKeys: true),
            state: fixture.cryptoState,
            signedState: fixture.state,
            localCredential: fixture.credential,
            eventId: first.id,
            sentAt: fixture.now
        )
        let firstResult = try await receiver.processApplicationEnvelope(
            firstSeal.envelope,
            at: fixture.now
        )
        XCTAssertEqual(firstResult, first)

        let replay = GroupConversationEventV2(
            clientTransactionID: transactionID,
            groupID: fixture.record.groupId,
            authorMemberHandle: fixture.credential.memberHandle,
            authorCredentialHandle: fixture.credential.credentialHandle,
            createdAt: fixture.now,
            kind: .application,
            content: try XCTUnwrap(.text("conflicting logical send"))
        )
        let replaySeal = try fixture.provider.encryptApplicationEvent(
            try NoctweaveCoder.encode(replay, sortedKeys: true),
            state: firstSeal.state,
            signedState: fixture.state,
            localCredential: fixture.credential,
            eventId: replay.id,
            sentAt: fixture.now
        )
        await XCTAssertThrowsErrorAsync(try await receiver.processApplicationEnvelope(
            replaySeal.envelope,
            at: fixture.now.addingTimeInterval(1)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .conflictingClientTransaction)
        }
        let afterReplay = await receiver.snapshot()
        XCTAssertEqual(afterReplay.events, [first])
        XCTAssertEqual(
            afterReplay.processedApplicationEnvelopes.last?.outcome,
            .rejectedClientTransaction
        )

        let next = GroupConversationEventV2(
            groupID: fixture.record.groupId,
            authorMemberHandle: fixture.credential.memberHandle,
            authorCredentialHandle: fixture.credential.credentialHandle,
            createdAt: fixture.now,
            kind: .application,
            content: try XCTUnwrap(.text("next unique send"))
        )
        let nextSeal = try fixture.provider.encryptApplicationEvent(
            try NoctweaveCoder.encode(next, sortedKeys: true),
            state: replaySeal.state,
            signedState: fixture.state,
            localCredential: fixture.credential,
            eventId: next.id,
            sentAt: fixture.now
        )
        let nextResult = try await receiver.processApplicationEnvelope(
            nextSeal.envelope,
            at: fixture.now.addingTimeInterval(2)
        )
        XCTAssertEqual(nextResult, next)

        let outbound = try NoctweavePQGroupRuntimeV2(
            record: fixture.record,
            persistence: TestGroupRuntimeStore(record: fixture.record)
        )
        _ = try await outbound.prepareApplicationEvent(first, at: fixture.now)
        await XCTAssertThrowsErrorAsync(try await outbound.prepareApplicationEvent(
            replay,
            at: fixture.now
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .conflictingClientTransaction)
        }
    }

    func testAuthenticatedRejectionAndRatchetAdvanceAreAtomicAcrossSaveFailure() async throws {
        let fixture = try makeSignedFixture()
        let store = TestGroupRuntimeStore(record: fixture.record, failOnSaveNumber: 1)
        let receiver = try NoctweavePQGroupRuntimeV2(
            record: fixture.record,
            persistence: store
        )
        let poison = GroupConversationEventV2(
            groupID: fixture.record.groupId,
            authorMemberHandle: .generate(),
            authorCredentialHandle: fixture.credential.credentialHandle,
            createdAt: fixture.now,
            kind: .application,
            content: try XCTUnwrap(.text("atomic rejection"))
        )
        let sealed = try fixture.provider.encryptApplicationEvent(
            try NoctweaveCoder.encode(poison, sortedKeys: true),
            state: fixture.cryptoState,
            signedState: fixture.state,
            localCredential: fixture.credential,
            eventId: poison.id,
            sentAt: fixture.now
        )

        await XCTAssertThrowsErrorAsync(try await receiver.processApplicationEnvelope(
            sealed.envelope,
            at: fixture.now.addingTimeInterval(1)
        )) { error in
            XCTAssertEqual(error as? TestGroupRuntimeStore.StoreError, .injectedFailure)
        }
        let inMemoryAfterFailure = await receiver.snapshot()
        let durableAfterFailure = await store.load()
        XCTAssertEqual(inMemoryAfterFailure, fixture.record)
        XCTAssertEqual(durableAfterFailure, fixture.record)

        await store.setFailOnSaveNumber(nil)
        await XCTAssertThrowsErrorAsync(try await receiver.processApplicationEnvelope(
            sealed.envelope,
            at: fixture.now.addingTimeInterval(2)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .conflictingApplicationEnvelope)
        }
        let persisted = await receiver.snapshot()
        XCTAssertEqual(
            persisted.processedApplicationEnvelopes.first?.outcome,
            .rejectedConflictingEnvelope
        )
    }

    func testEventCompactionUsesAuthenticatedAppendOrderNotPeerCreatedAt() throws {
        let fixture = try makeSignedFixture()
        let count = NoctweaveArchitectureV2.groupEventRecentWindow + 2
        let content = try XCTUnwrap(EncodedContent.text("append ordered"))
        let events = (0..<count).map { index in
            GroupConversationEventV2(
                clientTransactionID: UUID(),
                groupID: fixture.record.groupId,
                authorMemberHandle: fixture.credential.memberHandle,
                authorCredentialHandle: fixture.credential.credentialHandle,
                createdAt: fixture.now.addingTimeInterval(TimeInterval(count - index)),
                kind: .application,
                content: content
            )
        }
        let record = GroupRuntimeRecord(
            groupId: fixture.record.groupId,
            localCredential: fixture.credential,
            signedState: fixture.state,
            cryptoState: fixture.cryptoState,
            events: events
        )

        XCTAssertTrue(record.isStructurallyValid)
        XCTAssertEqual(record.events, events)
        XCTAssertEqual(
            try record.compactedDurableState().events,
            Array(events.suffix(NoctweaveArchitectureV2.groupEventRecentWindow))
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
            quarantined.quarantinedForks.first?.conflictingCommitDigest,
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
            quarantinedAt: fixture.now.addingTimeInterval(3)
        )
        XCTAssertTrue(quarantine.isStructurallyValid)
        try assertExactRoundTrip(quarantine, as: GroupEpochForkQuarantine.self)
        try assertExactRoundTrip(snapshot, as: GroupRuntimeRecord.self)
    }

    func testPeerEpochConvergesAtomicallyAcrossFailureRestartReplayAndFork() async throws {
        let fixture = try await makeTwoMemberRuntimeFixture()
        let ownerBase = await fixture.owner.snapshot()
        let firstOwner = try NoctweavePQGroupRuntimeV2(
            record: ownerBase,
            persistence: TestGroupRuntimeStore(record: ownerBase)
        )
        let forkOwner = try NoctweavePQGroupRuntimeV2(
            record: ownerBase,
            persistence: TestGroupRuntimeStore(record: ownerBase)
        )
        let accepted = try await firstOwner.prepareEpoch(
            operation: .updateMetadata,
            proposedMembers: ownerBase.signedState.members,
            proposedCredentials: ownerBase.signedState.memberCredentials,
            proposedPermissions: ownerBase.signedState.permissions,
            proposedMetadataDigest: bytes(0xA1),
            idempotencyKey: bytes(0xA2),
            createdAt: fixture.now.addingTimeInterval(2)
        )
        let acceptedWelcome = try XCTUnwrap(accepted.signedWelcomes.first(where: {
            $0.destinationCredentialHandle == fixture.memberCredential.credentialHandle
        }))

        await fixture.memberStore.setFailOnSaveNumber(2)
        await XCTAssertThrowsErrorAsync(try await fixture.member.processPeerEpoch(
            accepted.transition,
            welcome: acceptedWelcome,
            observedAt: fixture.now.addingTimeInterval(2)
        )) { error in
            XCTAssertEqual(error as? TestGroupRuntimeStore.StoreError, .injectedFailure)
        }
        var memberSnapshot = await fixture.member.snapshot()
        XCTAssertEqual(memberSnapshot.signedState.epoch, 2)
        XCTAssertTrue(memberSnapshot.peerEpochJournal.count == 1)

        await fixture.memberStore.setFailOnSaveNumber(nil)
        let acceptedOutcome = try await fixture.member.processPeerEpoch(
            accepted.transition,
            welcome: acceptedWelcome,
            observedAt: fixture.now.addingTimeInterval(2)
        )
        XCTAssertEqual(acceptedOutcome, .active)
        memberSnapshot = await fixture.member.snapshot()
        XCTAssertEqual(memberSnapshot.signedState.epoch, 3)
        XCTAssertEqual(memberSnapshot.peerEpochJournal.count, 2)
        try assertExactRoundTrip(accepted.transition, as: GroupEpochTransitionEnvelopeV2.self)
        let protocolEnvelope = ProtocolEnvelopeV1.groupCommitV2(accepted.transition)
        try assertExactRoundTrip(protocolEnvelope, as: ProtocolEnvelopeV1.self)
        var obsoleteCommitEnvelope = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: NoctweaveCoder.encode(protocolEnvelope, sortedKeys: true)
            ) as? [String: Any]
        )
        obsoleteCommitEnvelope["groupCommitV2"] = try JSONSerialization.jsonObject(
            with: NoctweaveCoder.encode(accepted.signedCommit, sortedKeys: true)
        )
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            ProtocolEnvelopeV1.self,
            from: JSONSerialization.data(
                withJSONObject: obsoleteCommitEnvelope,
                options: [.sortedKeys]
            )
        ))
        try assertExactRoundTrip(
            try XCTUnwrap(memberSnapshot.peerEpochJournal.last),
            as: GroupPeerEpochJournalEntryV2.self
        )

        let reopened = try await NoctweavePQGroupRuntimeV2.open(
            persistence: fixture.memberStore
        )
        let beforeReplay = await reopened.snapshot()
        let replayOutcome = try await reopened.processPeerEpoch(
            accepted.transition,
            welcome: acceptedWelcome,
            observedAt: fixture.now.addingTimeInterval(3)
        )
        XCTAssertEqual(replayOutcome, .active)
        let afterReplay = await reopened.snapshot()
        XCTAssertEqual(afterReplay, beforeReplay)

        let fork = try await forkOwner.prepareEpoch(
            operation: .updateMetadata,
            proposedMembers: ownerBase.signedState.members,
            proposedCredentials: ownerBase.signedState.memberCredentials,
            proposedPermissions: ownerBase.signedState.permissions,
            proposedMetadataDigest: bytes(0xB1),
            idempotencyKey: bytes(0xB2),
            createdAt: fixture.now.addingTimeInterval(2)
        )
        let forkWelcome = try XCTUnwrap(fork.signedWelcomes.first(where: {
            $0.destinationCredentialHandle == fixture.memberCredential.credentialHandle
        }))
        await XCTAssertThrowsErrorAsync(try await reopened.processPeerEpoch(
            fork.transition,
            welcome: forkWelcome,
            observedAt: fixture.now.addingTimeInterval(3)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .conflictingCommitQuarantined)
        }
        let quarantined = await reopened.snapshot()
        XCTAssertEqual(quarantined.signedState.epoch, 3)
        XCTAssertEqual(quarantined.peerForkQuarantines.count, 1)
        try assertExactRoundTrip(
            try XCTUnwrap(quarantined.peerForkQuarantines.first),
            as: GroupPeerEpochForkQuarantineV2.self
        )
    }

    func testPeerRemovalIsDurableTerminalAndClearsSendableWork() async throws {
        let fixture = try await makeTwoMemberRuntimeFixture()
        let memberBefore = await fixture.member.snapshot()
        let pendingEvent = GroupConversationEventV2(
            groupID: memberBefore.groupId,
            authorMemberHandle: fixture.memberCredential.memberHandle,
            authorCredentialHandle: fixture.memberCredential.credentialHandle,
            createdAt: fixture.now.addingTimeInterval(2),
            kind: .application,
            content: try XCTUnwrap(.text("will be retired with local access"))
        )
        _ = try await fixture.member.prepareApplicationEvent(
            pendingEvent,
            at: fixture.now.addingTimeInterval(2)
        )

        let ownerState = await fixture.owner.snapshot().signedState
        let removalEpoch = ownerState.epoch + 1
        let removedMembers = ownerState.members.map { member in
            member.id == fixture.memberCredential.memberHandle
                ? GroupMemberV2(
                    id: member.id,
                    role: member.role,
                    addedEpoch: member.addedEpoch,
                    removedEpoch: removalEpoch
                )
                : member
        }
        let removedCredentials = ownerState.memberCredentials.map { credential in
            credential.credentialHandle == fixture.memberCredential.credentialHandle
                ? GroupMemberCredentialV2(
                    memberHandle: credential.memberHandle,
                    credentialHandle: credential.credentialHandle,
                    admissionDigest: credential.admissionDigest,
                    signingPublicKey: credential.signingPublicKey,
                    agreementPublicKey: credential.agreementPublicKey,
                    contentTypes: credential.contentTypes,
                    addedEpoch: credential.addedEpoch,
                    removedEpoch: removalEpoch
                )
                : credential
        }
        let removal = try await fixture.owner.prepareEpoch(
            operation: .removeMember,
            proposedMembers: removedMembers,
            proposedCredentials: removedCredentials,
            proposedPermissions: ownerState.permissions,
            proposedMetadataDigest: ownerState.metadataDigest,
            idempotencyKey: bytes(0xC1),
            createdAt: fixture.now.addingTimeInterval(3)
        )
        XCTAssertNil(removal.signedWelcomes.first(where: {
            $0.destinationCredentialHandle == fixture.memberCredential.credentialHandle
        }))
        let removalOutcome = try await fixture.member.processPeerEpoch(
            removal.transition,
            welcome: nil,
            observedAt: fixture.now.addingTimeInterval(3)
        )
        XCTAssertEqual(removalOutcome, .localRemoved)
        let terminal = await fixture.member.snapshot()
        XCTAssertEqual(terminal.localRemoval?.acceptedEpoch, removal.signedState.epoch)
        XCTAssertTrue(terminal.pendingApplicationPublications.isEmpty)
        XCTAssertTrue(terminal.epochIntents.isEmpty)
        XCTAssertTrue(terminal.isStructurallyValid)

        await XCTAssertThrowsErrorAsync(try await fixture.member.prepareApplicationEvent(
            pendingEvent,
            at: fixture.now.addingTimeInterval(4)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .localCredentialRemoved)
        }
        await XCTAssertThrowsErrorAsync(try await fixture.member.prepareEpoch(
            operation: .updateMetadata,
            proposedMembers: terminal.signedState.members,
            proposedCredentials: terminal.signedState.memberCredentials,
            proposedPermissions: terminal.signedState.permissions,
            proposedMetadataDigest: bytes(0xC2),
            idempotencyKey: bytes(0xC3),
            createdAt: fixture.now.addingTimeInterval(4)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .localCredentialRemoved)
        }
        let beforeReplay = await fixture.member.snapshot()
        let replayOutcome = try await fixture.member.processPeerEpoch(
            removal.transition,
            welcome: nil,
            observedAt: fixture.now.addingTimeInterval(4)
        )
        XCTAssertEqual(replayOutcome, .localRemoved)
        let afterReplay = await fixture.member.snapshot()
        XCTAssertEqual(afterReplay, beforeReplay)

        let reopened = try await NoctweavePQGroupRuntimeV2.open(
            persistence: fixture.memberStore
        )
        let reopenedState = await reopened.snapshot()
        XCTAssertEqual(reopenedState.localRemoval, terminal.localRemoval)
        XCTAssertTrue(reopenedState.isStructurallyValid)
    }

    func testJoinRequiresExplicitPinnedGroupOnlyInvitationAnchor() async throws {
        let base = try makeSignedFixture()
        let invitation = try await makeAddMemberInvitation(base: base)
        let store = TestGroupRuntimeStore(record: nil)
        let joined = try await NoctweavePQGroupRuntimeV2.join(
            anchor: invitation.anchor,
            transition: invitation.publication.transition,
            welcome: invitation.welcome,
            localCredential: invitation.memberCredential,
            observedAt: base.now.addingTimeInterval(1),
            persistence: store
        )
        let joinedSnapshot = await joined.snapshot()
        XCTAssertEqual(joinedSnapshot.originJoinAnchorID, invitation.anchor.id)

        await XCTAssertThrowsErrorAsync(try await NoctweavePQGroupRuntimeV2.join(
            anchor: invitation.anchor,
            transition: invitation.publication.transition,
            welcome: invitation.welcome,
            localCredential: invitation.memberCredential,
            observedAt: base.now.addingTimeInterval(1),
            persistence: store
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .unsolicitedJoin)
        }

        let unrelated = try makeSignedFixture()
        let unrelatedAnchor = try GroupJoinAnchorV2(
            baseState: unrelated.state,
            destinationMemberHandle: invitation.memberCredential.memberHandle,
            destinationCredentialHandle: invitation.memberCredential.credentialHandle,
            destinationAdmissionDigest: invitation.memberCredential.admissionDigest,
            issuedAt: base.now,
            expiresAt: base.now.addingTimeInterval(3_600)
        )
        await XCTAssertThrowsErrorAsync(try await NoctweavePQGroupRuntimeV2.join(
            anchor: unrelatedAnchor,
            transition: invitation.publication.transition,
            welcome: invitation.welcome,
            localCredential: invitation.memberCredential,
            observedAt: base.now.addingTimeInterval(1),
            persistence: TestGroupRuntimeStore(record: nil)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .unsolicitedJoin)
        }
        try assertExactRoundTrip(invitation.anchor, as: GroupJoinAnchorV2.self)
    }

    func testInboundEpochRacingDurableLocalPreparationConvergesOrQuarantines() async throws {
        let base = try makeSignedFixture()
        let exactStore = TestGroupRuntimeStore(record: base.record, failOnSaveNumber: 2)
        let exactRuntime = try NoctweavePQGroupRuntimeV2(
            record: base.record,
            persistence: exactStore
        )
        await XCTAssertThrowsErrorAsync(try await exactRuntime.prepareEpoch(
            operation: .updateMetadata,
            proposedMembers: base.state.members,
            proposedCredentials: base.state.memberCredentials,
            proposedPermissions: base.state.permissions,
            proposedMetadataDigest: bytes(0xE1),
            idempotencyKey: bytes(0xE2),
            createdAt: base.now.addingTimeInterval(1)
        )) { error in
            XCTAssertEqual(error as? TestGroupRuntimeStore.StoreError, .injectedFailure)
        }
        let preparedSnapshot = await exactRuntime.snapshot()
        let preparedIntent = try XCTUnwrap(preparedSnapshot.epochIntents.first(where: {
            $0.phase == .prepared
        }))
        let exactWelcome = try XCTUnwrap(preparedIntent.signedWelcomes.first(where: {
            $0.destinationCredentialHandle == base.credential.credentialHandle
        }))
        await exactStore.setFailOnSaveNumber(nil)
        let outcome = try await exactRuntime.processPeerEpoch(
            preparedIntent.publication.transition,
            welcome: exactWelcome,
            observedAt: base.now.addingTimeInterval(1)
        )
        XCTAssertEqual(outcome, .active)
        let converged = await exactRuntime.snapshot()
        XCTAssertEqual(converged.signedState.epoch, 2)
        XCTAssertEqual(converged.peerEpochJournal.count, 1)
        XCTAssertEqual(converged.epochIntents.first?.phase, .stateCommitted)

        let conflictStore = TestGroupRuntimeStore(record: base.record, failOnSaveNumber: 2)
        let conflictRuntime = try NoctweavePQGroupRuntimeV2(
            record: base.record,
            persistence: conflictStore
        )
        await XCTAssertThrowsErrorAsync(try await conflictRuntime.prepareEpoch(
            operation: .updateMetadata,
            proposedMembers: base.state.members,
            proposedCredentials: base.state.memberCredentials,
            proposedPermissions: base.state.permissions,
            proposedMetadataDigest: bytes(0xE3),
            idempotencyKey: bytes(0xE4),
            createdAt: base.now.addingTimeInterval(1)
        )) { error in
            XCTAssertEqual(error as? TestGroupRuntimeStore.StoreError, .injectedFailure)
        }
        await conflictStore.setFailOnSaveNumber(nil)
        await XCTAssertThrowsErrorAsync(try await conflictRuntime.processPeerEpoch(
            preparedIntent.publication.transition,
            welcome: exactWelcome,
            observedAt: base.now.addingTimeInterval(1)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .conflictingCommitQuarantined)
        }
        let quarantined = await conflictRuntime.snapshot()
        XCTAssertEqual(quarantined.signedState.epoch, 1)
        XCTAssertEqual(quarantined.epochIntents.first?.phase, .prepared)
        XCTAssertEqual(quarantined.peerForkQuarantines.count, 1)
    }

    func testGroupRuntimeRejectsCountValidStateOverAggregateDurableByteBudget() throws {
        let fixture = try makeSignedFixture()
        let maximalContent = EncodedContent(
            type: .text,
            payload: Data(
                repeating: 0xF1,
                count: NoctweaveArchitectureV2.maximumContentPayloadBytes
            )
        )
        XCTAssertTrue(maximalContent.isStructurallyValid)
        let events = (0..<385).map { offset in
            GroupConversationEventV2(
                groupID: fixture.record.groupId,
                authorMemberHandle: fixture.credential.memberHandle,
                authorCredentialHandle: fixture.credential.credentialHandle,
                createdAt: fixture.now.addingTimeInterval(Double(offset)),
                kind: .application,
                content: maximalContent
            )
        }
        XCTAssertLessThan(events.count, NoctweaveArchitectureV2.maximumGroupEvents)
        XCTAssertTrue(events.allSatisfy(\.isStructurallyValid))
        let oversized = GroupRuntimeRecord(
            groupId: fixture.record.groupId,
            localCredential: fixture.credential,
            signedState: fixture.state,
            cryptoState: fixture.cryptoState,
            events: events
        )
        XCTAssertFalse(oversized.isStructurallyValid)
        XCTAssertThrowsError(try NoctweaveCoder.encode(oversized, sortedKeys: true))
    }

    func testLocalDeletionPersistsExactOutboxClearsWorkAndReopensTerminal() async throws {
        let fixture = try makeSignedFixture()
        let store = TestGroupRuntimeStore(record: fixture.record)
        let runtime = try NoctweavePQGroupRuntimeV2(
            record: fixture.record,
            persistence: store
        )
        let event = GroupConversationEventV2(
            groupID: fixture.record.groupId,
            authorMemberHandle: fixture.credential.memberHandle,
            authorCredentialHandle: fixture.credential.credentialHandle,
            createdAt: fixture.now,
            kind: .application,
            content: try XCTUnwrap(.text("pending before terminal deletion"))
        )
        let pendingEnvelope = try await runtime.prepareApplicationEvent(
            event,
            at: fixture.now
        )
        let pendingReplacement = try makeCredential(
            groupId: fixture.record.groupId,
            memberHandle: fixture.credential.memberHandle,
            marker: 0x71
        )
        try await runtime.registerPendingLocalCredential(pendingReplacement)

        await XCTAssertThrowsErrorAsync(try await runtime.prepareEpoch(
            operation: .updateMetadata,
            proposedMembers: fixture.state.members,
            proposedCredentials: fixture.state.memberCredentials,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: bytes(0x72),
            idempotencyKey: bytes(0x73),
            createdAt: fixture.now.addingTimeInterval(1)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .pendingEpoch)
        }
        let preparedSnapshot = await runtime.snapshot()
        XCTAssertTrue(preparedSnapshot.epochIntents.isEmpty)

        let reasonDigest = bytes(0x74)
        let idempotencyKey = bytes(0x75)
        let tombstone = try await runtime.prepareDeletion(
            reasonDigest: reasonDigest,
            idempotencyKey: idempotencyKey,
            createdAt: fixture.now.addingTimeInterval(2)
        )
        let terminal = await runtime.snapshot()
        XCTAssertEqual(terminal.deletionState?.publicationState, .pending)
        XCTAssertEqual(terminal.deletionState?.deletedState.tombstone, tombstone)
        XCTAssertTrue(terminal.epochIntents.isEmpty)
        XCTAssertTrue(terminal.pendingApplicationPublications.isEmpty)
        XCTAssertTrue(terminal.pendingLocalCredentials.isEmpty)
        XCTAssertTrue(try terminal.isStructurallyValidThrowing)
        let pendingDeletion = await runtime.pendingDeletionPublication()
        XCTAssertEqual(pendingDeletion, tombstone)

        let exactRetry = try await runtime.prepareDeletion(
            reasonDigest: reasonDigest,
            idempotencyKey: idempotencyKey,
            createdAt: fixture.now.addingTimeInterval(20)
        )
        XCTAssertEqual(exactRetry, tombstone)
        let afterExactRetry = await runtime.snapshot()
        XCTAssertEqual(afterExactRetry, terminal)

        await XCTAssertThrowsErrorAsync(try await runtime.prepareApplicationEvent(
            event,
            at: fixture.now.addingTimeInterval(3)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .groupDeleted)
        }
        await XCTAssertThrowsErrorAsync(try await runtime.processApplicationEnvelope(
            pendingEnvelope,
            at: fixture.now.addingTimeInterval(3)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .groupDeleted)
        }
        await XCTAssertThrowsErrorAsync(try await runtime.registerPendingLocalCredential(
            pendingReplacement
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .groupDeleted)
        }
        await XCTAssertThrowsErrorAsync(try await runtime.markApplicationPublished(
            eventID: event.id
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .groupDeleted)
        }

        let reopenedPending = try await NoctweavePQGroupRuntimeV2.open(persistence: store)
        let reopenedOutbox = await reopenedPending.pendingDeletionPublication()
        XCTAssertEqual(reopenedOutbox, tombstone)
        try await reopenedPending.markDeletionPublished(
            tombstoneID: tombstone.id,
            at: fixture.now.addingTimeInterval(3)
        )
        let completedOutbox = await reopenedPending.pendingDeletionPublication()
        XCTAssertNil(completedOutbox)
        let published = await reopenedPending.snapshot()
        XCTAssertEqual(published.deletionState?.publicationState, .published)
        try await reopenedPending.markDeletionPublished(
            tombstoneID: tombstone.id,
            at: fixture.now.addingTimeInterval(4)
        )
        let afterCompletionReplay = await reopenedPending.snapshot()
        XCTAssertEqual(afterCompletionReplay, published)

        let reopenedPublished = try await NoctweavePQGroupRuntimeV2.open(persistence: store)
        let reopenedPublishedSnapshot = await reopenedPublished.snapshot()
        XCTAssertEqual(reopenedPublishedSnapshot, published)
        try assertExactRoundTrip(
            try XCTUnwrap(published.deletionState),
            as: GroupRuntimeDeletionStateV2.self
        )
        try assertExactRoundTrip(published, as: GroupRuntimeRecord.self)
    }

    func testInboundDeletionIsAtomicReplayableAndRejectsConflictsAndResurrection() async throws {
        let fixture = try await makeTwoMemberRuntimeFixture()
        let ownerBase = await fixture.owner.snapshot()
        let resurrectionRuntime = try NoctweavePQGroupRuntimeV2(
            record: ownerBase,
            persistence: TestGroupRuntimeStore(record: ownerBase)
        )
        let resurrection = try await resurrectionRuntime.prepareEpoch(
            operation: .updateMetadata,
            proposedMembers: ownerBase.signedState.members,
            proposedCredentials: ownerBase.signedState.memberCredentials,
            proposedPermissions: ownerBase.signedState.permissions,
            proposedMetadataDigest: bytes(0x81),
            idempotencyKey: bytes(0x82),
            createdAt: fixture.now.addingTimeInterval(2)
        )
        let conflictingRuntime = try NoctweavePQGroupRuntimeV2(
            record: ownerBase,
            persistence: TestGroupRuntimeStore(record: ownerBase)
        )
        let conflictingTombstone = try await conflictingRuntime.prepareDeletion(
            reasonDigest: bytes(0x83),
            idempotencyKey: bytes(0x84),
            createdAt: fixture.now.addingTimeInterval(3)
        )
        let acceptedTombstone = try await fixture.owner.prepareDeletion(
            reasonDigest: bytes(0x85),
            idempotencyKey: bytes(0x86),
            createdAt: fixture.now.addingTimeInterval(3)
        )

        let memberState = await fixture.member.snapshot()
        let pendingEvent = GroupConversationEventV2(
            groupID: memberState.groupId,
            authorMemberHandle: fixture.memberCredential.memberHandle,
            authorCredentialHandle: fixture.memberCredential.credentialHandle,
            createdAt: fixture.now.addingTimeInterval(2),
            kind: .application,
            content: try XCTUnwrap(.text("cleared by inbound deletion"))
        )
        let pendingEnvelope = try await fixture.member.prepareApplicationEvent(
            pendingEvent,
            at: fixture.now.addingTimeInterval(2)
        )
        await fixture.memberStore.setFailOnSaveNumber(3)
        await XCTAssertThrowsErrorAsync(try await fixture.member.processDeletionTombstone(
            acceptedTombstone,
            observedAt: fixture.now.addingTimeInterval(3)
        )) { error in
            XCTAssertEqual(error as? TestGroupRuntimeStore.StoreError, .injectedFailure)
        }
        var afterFailure = await fixture.member.snapshot()
        XCTAssertNil(afterFailure.deletionState)
        XCTAssertEqual(afterFailure.signedState.epoch, 2)
        XCTAssertEqual(afterFailure.pendingApplicationPublications.count, 1)

        await fixture.memberStore.setFailOnSaveNumber(nil)
        let deletedState = try await fixture.member.processDeletionTombstone(
            acceptedTombstone,
            observedAt: fixture.now.addingTimeInterval(3)
        )
        var terminal = await fixture.member.snapshot()
        XCTAssertEqual(terminal.deletionState?.origin, .peer)
        XCTAssertEqual(terminal.deletionState?.publicationState, .notApplicable)
        XCTAssertEqual(terminal.deletionState?.deletedState, deletedState)
        XCTAssertTrue(terminal.pendingApplicationPublications.isEmpty)

        let beforeReplay = terminal
        let replay = try await fixture.member.processDeletionTombstone(
            acceptedTombstone,
            observedAt: fixture.now.addingTimeInterval(4)
        )
        XCTAssertEqual(replay, deletedState)
        let afterReplay = await fixture.member.snapshot()
        XCTAssertEqual(afterReplay, beforeReplay)

        await XCTAssertThrowsErrorAsync(try await fixture.member.processDeletionTombstone(
            conflictingTombstone,
            observedAt: fixture.now.addingTimeInterval(4)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .conflictingDeletionQuarantined)
        }
        await XCTAssertThrowsErrorAsync(try await fixture.member.processPeerEpoch(
            resurrection.transition,
            welcome: resurrection.signedWelcomes.first(where: {
                $0.destinationCredentialHandle == fixture.memberCredential.credentialHandle
            }),
            observedAt: fixture.now.addingTimeInterval(5)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .groupDeleted)
        }
        await XCTAssertThrowsErrorAsync(try await fixture.member.observeCommit(
            resurrection.signedCommit,
            at: fixture.now.addingTimeInterval(6)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .groupDeleted)
        }
        await XCTAssertThrowsErrorAsync(try await fixture.member.processApplicationEnvelope(
            pendingEnvelope,
            at: fixture.now.addingTimeInterval(6)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .groupDeleted)
        }
        terminal = await fixture.member.snapshot()
        XCTAssertEqual(terminal.deletionState?.conflictEvidence.count, 1)
        XCTAssertTrue(terminal.deletionState?.conflictEvidence.allSatisfy({
            $0.artifactDigest.count == SHA256.byteCount
        }) == true)
        XCTAssertTrue(try terminal.isStructurallyValidThrowing)

        let reopened = try await NoctweavePQGroupRuntimeV2.open(
            persistence: fixture.memberStore
        )
        let reopenedSnapshot = await reopened.snapshot()
        XCTAssertEqual(reopenedSnapshot, terminal)
        afterFailure = await reopened.snapshot()
        XCTAssertNotNil(afterFailure.deletionState)
    }

    func testGroupRouteSetIsCredentialBoundStrictAndHashChained() throws {
        let fixture = try makeSignedFixture()
        let firstRoute = try makeGroupSendRoute(marker: 0x21, now: fixture.now)
        let initial = try SignedGroupOpaqueRouteSetV2.create(
            groupID: fixture.record.groupId,
            ownerCredentialHandle: fixture.credential.credentialHandle,
            ownerAdmissionDigest: fixture.credential.admissionDigest,
            routes: [firstRoute],
            issuedAt: fixture.now,
            expiresAt: fixture.now.addingTimeInterval(3_600),
            signingKey: fixture.credential.signingKey
        )
        XCTAssertTrue(initial.verify(
            ownerSigningPublicKey: fixture.credential.signingKey.publicKeyData
        ))
        XCTAssertNil(initial.previousDigest)

        let successor = try initial.successor(
            routes: [firstRoute],
            issuedAt: fixture.now.addingTimeInterval(1),
            expiresAt: fixture.now.addingTimeInterval(3_600),
            signingKey: fixture.credential.signingKey
        )
        XCTAssertEqual(successor.revision, 1)
        XCTAssertEqual(successor.previousDigest, initial.digest)
        XCTAssertTrue(successor.isValidSuccessor(
            of: initial,
            ownerSigningPublicKey: fixture.credential.signingKey.publicKeyData
        ))
        try assertExactRoundTrip(successor, as: SignedGroupOpaqueRouteSetV2.self)

        let encoded = try NoctweaveCoder.encode(successor, sortedKeys: true)
        let wire = String(decoding: encoded, as: UTF8.self).lowercased()
        for banned in ["persona", "account", "identity", "device", "installation", "inbox", "recovery"] {
            XCTAssertFalse(wire.contains(banned), "unexpected non-group field: \(banned)")
        }
    }

    func testApplicationTransportPersistsExactRetryAndRequiresAppendReceipts() async throws {
        let fixture = try await makeTwoMemberRuntimeFixture()
        let ownerSnapshot = await fixture.owner.snapshot()
        let store = TestGroupRuntimeStore(record: ownerSnapshot)
        let runtime = try NoctweavePQGroupRuntimeV2(
            record: ownerSnapshot,
            persistence: store
        )
        let event = GroupConversationEventV2(
            groupID: ownerSnapshot.groupId,
            authorMemberHandle: ownerSnapshot.localCredential.memberHandle,
            authorCredentialHandle: ownerSnapshot.localCredential.credentialHandle,
            createdAt: fixture.now.addingTimeInterval(10),
            kind: .application,
            content: try XCTUnwrap(.text("durable group route retry"))
        )
        _ = try await runtime.prepareApplicationEvent(
            event,
            at: fixture.now.addingTimeInterval(10)
        )
        let routeSet = try makeGroupRouteSet(
            credential: fixture.memberCredential,
            groupID: ownerSnapshot.groupId,
            marker: 0x41,
            now: fixture.now
        )
        let preparedOperation = try await runtime.prepareApplicationTransport(
            eventID: event.id,
            routeSets: [routeSet],
            at: fixture.now.addingTimeInterval(11)
        )
        let operation = try XCTUnwrap(preparedOperation)
        let eligible = try await runtime.eligibleOutboundTransportPublications(
            operationID: operation.id
        )
        let candidate = try XCTUnwrap(eligible.first)
        await store.failNextSave()
        await XCTAssertThrowsErrorAsync(try await runtime.recordOutboundTransportAttempt(
            operationID: operation.id,
            publicationID: candidate.id,
            at: fixture.now.addingTimeInterval(12)
        )) { error in
            XCTAssertEqual(error as? TestGroupRuntimeStore.StoreError, .injectedFailure)
        }
        await store.setFailOnSaveNumber(nil)
        let afterFailedAttempt = await runtime.snapshot()
        XCTAssertEqual(
            afterFailedAttempt.outboundTransportOperations.first(where: {
                $0.id == operation.id
            })?.deliveries.first?.attempts.first?.attemptCount,
            0
        )
        let exactAttempt = try await runtime.recordOutboundTransportAttempt(
            operationID: operation.id,
            publicationID: candidate.id,
            at: fixture.now.addingTimeInterval(12)
        )
        XCTAssertEqual(exactAttempt, candidate)

        let reopened = try await NoctweavePQGroupRuntimeV2.open(persistence: store)
        let reopenedEligible = try await reopened.eligibleOutboundTransportPublications(
            operationID: operation.id
        )
        let reopenedCandidate = try XCTUnwrap(reopenedEligible.first)
        XCTAssertEqual(reopenedCandidate, candidate)
        await XCTAssertThrowsErrorAsync(try await reopened.markApplicationPublished(
            eventID: event.id
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .incompleteFanout)
        }

        await store.failNextSave()
        await XCTAssertThrowsErrorAsync(try await reopened.recordOutboundTransportAcceptance(
            operationID: operation.id,
            publicationID: candidate.id,
            receipts: transportReceipts(for: candidate, marker: 0x42),
            at: fixture.now.addingTimeInterval(13)
        )) { error in
            XCTAssertEqual(error as? TestGroupRuntimeStore.StoreError, .injectedFailure)
        }
        await store.setFailOnSaveNumber(nil)
        let afterFailedAcceptance = await reopened.snapshot()
        XCTAssertNil(
            afterFailedAcceptance.outboundTransportOperations.first(where: {
                $0.id == operation.id
            })?.deliveries.first?.attempts.first?.acceptance
        )
        try await reopened.recordOutboundTransportAcceptance(
            operationID: operation.id,
            publicationID: candidate.id,
            receipts: transportReceipts(for: candidate, marker: 0x42),
            at: fixture.now.addingTimeInterval(13)
        )
        try await reopened.markApplicationPublished(eventID: event.id)
        let completed = await reopened.snapshot()
        XCTAssertTrue(completed.pendingApplicationPublications.isEmpty)
        XCTAssertEqual(
            completed.outboundTransportOperations.first(where: { $0.id == operation.id })?
                .isComplete,
            true
        )
    }

    func testEpochTransportOrdersTransitionBeforeWelcomeAndBlocksNextEpochTraffic() async throws {
        let fixture = try await makeTwoMemberRuntimeFixture()
        let ownerState = await fixture.owner.snapshot()
        let publication = try await fixture.owner.prepareEpoch(
            operation: .updateMetadata,
            proposedMembers: ownerState.signedState.members,
            proposedCredentials: ownerState.signedState.memberCredentials,
            proposedPermissions: ownerState.signedState.permissions,
            proposedMetadataDigest: bytes(0x51),
            idempotencyKey: bytes(0x52),
            createdAt: fixture.now.addingTimeInterval(20)
        )
        let blockedEvent = GroupConversationEventV2(
            groupID: ownerState.groupId,
            authorMemberHandle: ownerState.localCredential.memberHandle,
            authorCredentialHandle: ownerState.localCredential.credentialHandle,
            createdAt: fixture.now.addingTimeInterval(21),
            kind: .application,
            content: try XCTUnwrap(.text("must wait for epoch transport"))
        )
        await XCTAssertThrowsErrorAsync(try await fixture.owner.prepareApplicationEvent(
            blockedEvent,
            at: fixture.now.addingTimeInterval(21)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .pendingEpoch)
        }

        let routeSet = try makeGroupRouteSet(
            credential: fixture.memberCredential,
            groupID: ownerState.groupId,
            marker: 0x53,
            now: fixture.now
        )
        let preparedOperation = try await fixture.owner.prepareEpochTransport(
            intentID: publication.intentId,
            routeSets: [routeSet],
            at: fixture.now.addingTimeInterval(22)
        )
        let operation = try XCTUnwrap(preparedOperation)
        let welcomeAttempt = try XCTUnwrap(operation.deliveries.first(where: {
            $0.artifactKind == .epochWelcome
        })?.attempts.first)
        await XCTAssertThrowsErrorAsync(try await fixture.owner.recordOutboundTransportAttempt(
            operationID: operation.id,
            publicationID: welcomeAttempt.id,
            at: fixture.now.addingTimeInterval(23)
        )) { error in
            XCTAssertEqual(
                error as? GroupOpaqueRouteTransportV2Error,
                .publicationNotEligible
            )
        }
        await XCTAssertThrowsErrorAsync(try await fixture.owner.markFanoutStored(
            intentId: publication.intentId,
            destinationCredentialHandle: fixture.memberCredential.credentialHandle,
            at: fixture.now.addingTimeInterval(23)
        )) { error in
            XCTAssertEqual(error as? GroupRuntimeError, .incompleteFanout)
        }

        let initiallyEligible = try await fixture.owner
            .eligibleOutboundTransportPublications(operationID: operation.id)
        let transition = try XCTUnwrap(initiallyEligible.first)
        _ = try await fixture.owner.recordOutboundTransportAttempt(
            operationID: operation.id,
            publicationID: transition.id,
            at: fixture.now.addingTimeInterval(23)
        )
        try await fixture.owner.recordOutboundTransportAcceptance(
            operationID: operation.id,
            publicationID: transition.id,
            receipts: transportReceipts(for: transition, marker: 0x54),
            at: fixture.now.addingTimeInterval(24)
        )
        let nowEligible = try await fixture.owner
            .eligibleOutboundTransportPublications(operationID: operation.id)
        XCTAssertEqual(nowEligible.map(\.id), [welcomeAttempt.id])
        _ = try await fixture.owner.recordOutboundTransportAttempt(
            operationID: operation.id,
            publicationID: welcomeAttempt.id,
            at: fixture.now.addingTimeInterval(25)
        )
        try await fixture.owner.recordOutboundTransportAcceptance(
            operationID: operation.id,
            publicationID: welcomeAttempt.id,
            receipts: transportReceipts(for: welcomeAttempt.publication, marker: 0x55),
            at: fixture.now.addingTimeInterval(26)
        )
        try await fixture.owner.finalizeEpoch(
            intentId: publication.intentId,
            at: fixture.now.addingTimeInterval(27)
        )
        let completed = await fixture.owner.snapshot()
        let completedOperation = try XCTUnwrap(
            completed.outboundTransportOperations.first(where: { $0.id == operation.id })
        )
        XCTAssertTrue(completedOperation.isComplete)
        XCTAssertEqual(
            completed.epochIntents.first(where: { $0.id == publication.intentId })?.phase,
            .finalized
        )
        try assertExactRoundTrip(
            completedOperation,
            as: GroupOpaqueRouteOutboundOperationV2.self
        )
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

private struct AddMemberInvitationFixture {
    let owner: NoctweavePQGroupRuntimeV2
    let publication: GroupEpochPublication
    let welcome: SignedGroupWelcomeV2
    let memberCredential: LocalGroupCredentialV2
    let anchor: GroupJoinAnchorV2
}

private struct TwoMemberRuntimeFixture {
    let now: Date
    let owner: NoctweavePQGroupRuntimeV2
    let member: NoctweavePQGroupRuntimeV2
    let memberStore: TestGroupRuntimeStore
    let memberCredential: LocalGroupCredentialV2
}

private func makeAddMemberInvitation(
    base: SignedGroupRuntimeFixture
) async throws -> AddMemberInvitationFixture {
    let memberHandle = GroupScopedMemberHandleV2.generate()
    let signingKey = try SigningKeyPair.generate()
    let agreementKey = try AgreementKeyPair.generate()
    let admission = try GroupCredentialAdmissionV2.create(
        groupId: base.state.groupId,
        memberHandle: memberHandle,
        credentialHandle: .generate(),
        groupSigningKey: signingKey,
        groupAgreementKey: agreementKey,
        issuedAt: base.now,
        expiresAt: base.now.addingTimeInterval(3_600)
    )
    let memberLeaf = try GroupMemberCredentialV2.fromVerifiedProjection(
        admission,
        addedEpoch: 2
    )
    let memberCredential = LocalGroupCredentialV2(
        groupId: base.state.groupId,
        memberHandle: memberHandle,
        credentialHandle: memberLeaf.credentialHandle,
        admissionDigest: memberLeaf.admissionDigest,
        signingKey: signingKey,
        agreementKey: agreementKey
    )
    let owner = try NoctweavePQGroupRuntimeV2(
        record: base.record,
        persistence: TestGroupRuntimeStore(record: base.record)
    )
    let publication = try await owner.prepareEpoch(
        operation: .addMember,
        proposedMembers: base.state.members + [
            GroupMemberV2(id: memberHandle, role: .member, addedEpoch: 2)
        ],
        proposedCredentials: base.state.memberCredentials + [memberLeaf],
        admissionProjection: admission,
        proposedPermissions: base.state.permissions,
        proposedMetadataDigest: base.state.metadataDigest,
        idempotencyKey: bytes(0xD1),
        createdAt: base.now.addingTimeInterval(1)
    )
    let route = try makeGroupSendRoute(marker: 0xD2, now: base.now)
    let routeSet = try SignedGroupOpaqueRouteSetV2.create(
        groupID: base.state.groupId,
        ownerCredentialHandle: memberCredential.credentialHandle,
        ownerAdmissionDigest: memberCredential.admissionDigest,
        routes: [route],
        issuedAt: base.now,
        expiresAt: base.now.addingTimeInterval(3_600),
        signingKey: memberCredential.signingKey
    )
    let preparedTransport = try await owner.prepareEpochTransport(
        intentID: publication.intentId,
        routeSets: [routeSet],
        at: base.now.addingTimeInterval(1)
    )
    let transport = try XCTUnwrap(preparedTransport)
    var transportDate = base.now.addingTimeInterval(1)
    while true {
        let eligible = try await owner.eligibleOutboundTransportPublications(
            operationID: transport.id
        )
        guard let candidate = eligible.first else { break }
        transportDate = transportDate.addingTimeInterval(0.01)
        let exact = try await owner.recordOutboundTransportAttempt(
            operationID: transport.id,
            publicationID: candidate.id,
            at: transportDate
        )
        let receipts = exact.packets.map {
            OpaqueRouteAppendReceiptV2(
                packetID: $0.packetID,
                acceptedCursor: OpaqueRouteCursorV2(
                    rawValue: Data(repeating: 0xD3, count: 68)
                ),
                highWatermark: OpaqueRouteCursorV2(
                    rawValue: Data(repeating: 0xD4, count: 68)
                )
            )
        }
        transportDate = transportDate.addingTimeInterval(0.01)
        try await owner.recordOutboundTransportAcceptance(
            operationID: transport.id,
            publicationID: candidate.id,
            receipts: receipts,
            at: transportDate
        )
    }
    try await owner.finalizeEpoch(
        intentId: publication.intentId,
        at: transportDate.addingTimeInterval(0.01)
    )
    let welcome = try XCTUnwrap(publication.signedWelcomes.first(where: {
        $0.destinationCredentialHandle == memberCredential.credentialHandle
    }))
    let anchor = try GroupJoinAnchorV2(
        baseState: base.state,
        destinationMemberHandle: memberCredential.memberHandle,
        destinationCredentialHandle: memberCredential.credentialHandle,
        destinationAdmissionDigest: memberCredential.admissionDigest,
        issuedAt: base.now,
        expiresAt: base.now.addingTimeInterval(3_600)
    )
    return AddMemberInvitationFixture(
        owner: owner,
        publication: publication,
        welcome: welcome,
        memberCredential: memberCredential,
        anchor: anchor
    )
}

private func makeTwoMemberRuntimeFixture() async throws -> TwoMemberRuntimeFixture {
    let base = try makeSignedFixture()
    let invitation = try await makeAddMemberInvitation(base: base)
    let memberStore = TestGroupRuntimeStore(record: nil)
    let member = try await NoctweavePQGroupRuntimeV2.join(
        anchor: invitation.anchor,
        transition: invitation.publication.transition,
        welcome: invitation.welcome,
        localCredential: invitation.memberCredential,
        observedAt: base.now.addingTimeInterval(1),
        persistence: memberStore
    )
    return TwoMemberRuntimeFixture(
        now: base.now,
        owner: invitation.owner,
        member: member,
        memberStore: memberStore,
        memberCredential: invitation.memberCredential
    )
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

private func makeGroupRouteSet(
    credential: LocalGroupCredentialV2,
    groupID: UUID,
    marker: UInt8,
    now: Date
) throws -> SignedGroupOpaqueRouteSetV2 {
    try SignedGroupOpaqueRouteSetV2.create(
        groupID: groupID,
        ownerCredentialHandle: credential.credentialHandle,
        ownerAdmissionDigest: credential.admissionDigest,
        routes: [try makeGroupSendRoute(marker: marker, now: now)],
        issuedAt: now,
        expiresAt: now.addingTimeInterval(3_600),
        signingKey: credential.signingKey
    )
}

private func transportReceipts(
    for publication: GroupOpaqueRoutePublicationV2,
    marker: UInt8
) -> [OpaqueRouteAppendReceiptV2] {
    publication.packets.map {
        OpaqueRouteAppendReceiptV2(
            packetID: $0.packetID,
            acceptedCursor: OpaqueRouteCursorV2(
                rawValue: Data(repeating: marker, count: 68)
            ),
            highWatermark: OpaqueRouteCursorV2(
                rawValue: Data(repeating: marker &+ 1, count: 68)
            )
        )
    }
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

    init(record: GroupRuntimeRecord? = nil, failOnSaveNumber: Int? = nil) {
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

    func failNextSave() {
        failOnSaveNumber = saveCount + 1
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
