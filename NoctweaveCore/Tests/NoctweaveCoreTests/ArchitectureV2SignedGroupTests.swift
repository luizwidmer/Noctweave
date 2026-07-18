import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2SignedGroupTests: XCTestCase {
    func testGroupAdmissionBindsGroupMemberClientAndGroupKeyPossession() throws {
        let now = Date()
        let groupId = UUID()
        let memberHandle = GroupScopedMemberHandleV2.generate()
        let groupSigningKey = try SigningKeyPair.generate()
        let groupAgreementKey = try AgreementKeyPair.generate()
        let admission = try GroupCredentialAdmissionV2.create(
            groupId: groupId,
            memberHandle: memberHandle,
            credentialHandle: .generate(),
            groupSigningKey: groupSigningKey,
            groupAgreementKey: groupAgreementKey,
            issuedAt: now,
            expiresAt: now.addingTimeInterval(3_600)
        )

        XCTAssertNoThrow(try admission.verified(
            forGroupId: groupId,
            memberHandle: memberHandle,
            selection: .currentExperimental,
            now: now
        ))
        XCTAssertThrowsError(try admission.verified(
            forGroupId: UUID(),
            memberHandle: memberHandle,
            selection: .currentExperimental,
            now: now
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidContext)
        }

        let tampered = copy(
            admission,
            credentialSignature: flipped(admission.credentialPossessionSignature)
        )
        XCTAssertThrowsError(try tampered.verified(
            forGroupId: groupId,
            memberHandle: memberHandle,
            selection: .currentExperimental,
            now: now
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidCredentialSignature)
        }
    }

    func testCredentialReplacementDerivesExactLeafAndRetiresPreviousCredential() throws {
        let fixture = try makeFixture()
        let admission = try makeAdmission(
            groupId: fixture.state.groupId,
            memberHandle: fixture.member.id,
            addedEpoch: fixture.state.epoch + 1,
            issuedAt: fixture.state.signedAt
        )
        var proposedLeaves = fixture.state.memberCredentials
        replaceLeaf(
            &proposedLeaves,
            removed(fixture.memberLeaves[0], at: fixture.state.epoch + 1)
        )
        proposedLeaves.append(admission.leaf)
        let commit = try makeCommit(
            operation: .replaceCredential,
            state: fixture.state,
            members: fixture.state.members,
            leaves: proposedLeaves,
            admissionProjection: admission.projection,
            permissions: fixture.state.permissions,
            metadata: fixture.state.metadataDigest,
            author: fixture.memberLeaves[0].credentialHandle,
            key: fixture.memberKeys[0],
            marker: 60
        )

        XCTAssertNoThrow(try commit.verifiedTransition(
            from: fixture.state,
            observedAt: commit.createdAt
        ))
        let next = try SignedGroupStateV2.applying(
            commit,
            to: fixture.state,
            observedAt: commit.createdAt,
            signingKey: fixture.memberKeys[0]
        )
        XCTAssertEqual(
            next.memberCredentials.first { $0.credentialHandle == admission.projection.credentialHandle },
            admission.leaf
        )
        XCTAssertEqual(
            next.activeCredentials.filter { $0.memberHandle == fixture.member.id }.count,
            1
        )

        let replacement = try makeAdmission(
            groupId: fixture.state.groupId,
            memberHandle: fixture.member.id,
            addedEpoch: fixture.state.epoch + 1,
            issuedAt: fixture.state.signedAt
        )
        let projectionTamperedAfterSigning = copy(
            commit,
            admissionProjection: replacement.projection
        )
        XCTAssertThrowsError(try projectionTamperedAfterSigning
            .verifiedTransition(
                from: fixture.state,
                observedAt: projectionTamperedAfterSigning.createdAt
            )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidCommitSignature)
        }
    }

    func testCommitTamperingRollbackAndForkFailClosed() throws {
        let fixture = try makeFixture()
        let metadataA = Data(repeating: 0x31, count: 32)
        let metadataB = Data(repeating: 0x32, count: 32)
        let commitA = try makeCommit(
            operation: .updateMetadata,
            state: fixture.state,
            members: fixture.state.members,
            leaves: fixture.state.memberCredentials,
            permissions: fixture.state.permissions,
            metadata: metadataA,
            author: fixture.ownerLeaf.credentialHandle,
            key: fixture.ownerKey,
            marker: 1
        )
        let commitB = try makeCommit(
            operation: .updateMetadata,
            state: fixture.state,
            members: fixture.state.members,
            leaves: fixture.state.memberCredentials,
            permissions: fixture.state.permissions,
            metadata: metadataB,
            author: fixture.ownerLeaf.credentialHandle,
            key: fixture.ownerKey,
            marker: 2
        )
        XCTAssertNoThrow(try commitA.verifiedTransition(
            from: fixture.state,
            observedAt: commitA.createdAt
        ))
        XCTAssertNoThrow(try commitB.verifiedTransition(
            from: fixture.state,
            observedAt: commitB.createdAt
        ))

        let tampered = copy(commitA, metadata: metadataB)
        XCTAssertThrowsError(try tampered.verifiedTransition(
            from: fixture.state,
            observedAt: tampered.createdAt
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidCommitSignature)
        }

        let next = try SignedGroupStateV2.applying(
            commitA,
            to: fixture.state,
            observedAt: commitA.createdAt,
            signingKey: fixture.ownerKey
        )
        XCTAssertNoThrow(try next.verified(
            previousState: fixture.state,
            commit: commitA,
            observedAt: commitA.createdAt
        ))
        XCTAssertThrowsError(try commitA.verifiedTransition(
            from: next,
            observedAt: commitA.createdAt
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .staleEpoch)
        }
        XCTAssertThrowsError(try commitB.verifiedTransition(
            from: next,
            observedAt: commitB.createdAt
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .staleEpoch)
        }
    }

    func testCommitAndDeletionFreshnessUseReceiverObservedTime() throws {
        let fixture = try makeFixture()
        let observedAt = fixture.state.signedAt.addingTimeInterval(10)
        let boundedPeerTime = observedAt.addingTimeInterval(
            NoctweaveSignedGroupV2.maximumClockSkewSeconds
        )
        let farFuturePeerTime = boundedPeerTime.addingTimeInterval(1)
        let boundedCommit = try makeCommit(
            operation: .updateMetadata,
            state: fixture.state,
            members: fixture.state.members,
            leaves: fixture.state.memberCredentials,
            permissions: fixture.state.permissions,
            metadata: Data(repeating: 0xD1, count: 32),
            author: fixture.ownerLeaf.credentialHandle,
            key: fixture.ownerKey,
            marker: 0xD2,
            createdAt: boundedPeerTime
        )
        XCTAssertNoThrow(try boundedCommit.verifiedTransition(
            from: fixture.state,
            observedAt: observedAt
        ))

        let farFutureCommit = try makeCommit(
            operation: .updateMetadata,
            state: fixture.state,
            members: fixture.state.members,
            leaves: fixture.state.memberCredentials,
            permissions: fixture.state.permissions,
            metadata: Data(repeating: 0xD3, count: 32),
            author: fixture.ownerLeaf.credentialHandle,
            key: fixture.ownerKey,
            marker: 0xD4,
            createdAt: farFuturePeerTime
        )
        XCTAssertThrowsError(try farFutureCommit.verifiedTransition(
            from: fixture.state,
            observedAt: observedAt
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidTimestamp)
        }

        let boundedDeletion = try SignedGroupDeletionTombstoneV2.create(
            currentState: fixture.state,
            authorCredentialHandle: fixture.ownerLeaf.credentialHandle,
            idempotencyKey: Data(repeating: 0xD5, count: 32),
            signingKey: fixture.ownerKey,
            createdAt: boundedPeerTime
        )
        XCTAssertNoThrow(try boundedDeletion.verified(
            against: fixture.state,
            observedAt: observedAt
        ))
        let historical = try SignedDeletedGroupStateV2.create(
            tombstone: boundedDeletion,
            from: fixture.state,
            observedAt: observedAt
        )
        XCTAssertEqual(historical.observedAt, observedAt)
        XCTAssertNoThrow(try historical.verified(previousState: fixture.state))

        let farFutureDeletion = try SignedGroupDeletionTombstoneV2.create(
            currentState: fixture.state,
            authorCredentialHandle: fixture.ownerLeaf.credentialHandle,
            idempotencyKey: Data(repeating: 0xD6, count: 32),
            signingKey: fixture.ownerKey,
            createdAt: farFuturePeerTime
        )
        XCTAssertThrowsError(try farFutureDeletion.verified(
            against: fixture.state,
            observedAt: observedAt
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidTimestamp)
        }
        XCTAssertThrowsError(try SignedDeletedGroupStateV2.create(
            tombstone: farFutureDeletion,
            from: fixture.state,
            observedAt: observedAt
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidTimestamp)
        }
    }

    func testMemberCannotChangePolicyAndStateTamperingBreaksTranscript() throws {
        let fixture = try makeFixture()
        let permissive = policy(updateMetadata: .everyone)
        XCTAssertThrowsError(try makeCommit(
            operation: .changePolicy,
            state: fixture.state,
            members: fixture.state.members,
            leaves: fixture.state.memberCredentials,
            permissions: permissive,
            metadata: fixture.state.metadataDigest,
            author: fixture.memberLeaves[0].credentialHandle,
            key: fixture.memberKeys[0],
            marker: 3
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .unauthorized)
        }

        let tamperedMembers = fixture.state.members.map { member in
            member.id == fixture.member.id
                ? GroupMemberV2(id: member.id, role: .admin, addedEpoch: member.addedEpoch)
                : member
        }
        let tamperedState = copy(fixture.state, members: tamperedMembers)
        XCTAssertFalse(tamperedState.isStructurallyValid)
        XCTAssertThrowsError(try tamperedState.verified(
            observedAt: fixture.state.signedAt
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidStructure)
        }
    }

    func testChangeRoleRejectsHigherAndEqualTargetsUnderAdminPolicy() throws {
        let fixture = try makeRoleFixture(updatePolicy: .admin)
        let attempts: [(RoleParticipant, RoleParticipant, GroupRole, UInt8)] = [
            (fixture.adminA, fixture.ownerB, .member, 71),
            (fixture.adminA, fixture.adminB, .member, 72),
            (fixture.ownerA, fixture.ownerB, .admin, 73)
        ]

        for (actor, target, newRole, marker) in attempts {
            XCTAssertThrowsError(try makeCommit(
                operation: .changeRole,
                state: fixture.state,
                members: changingRole(
                    target.member.id,
                    to: newRole,
                    in: fixture.state.members
                ),
                leaves: fixture.state.memberCredentials,
                permissions: fixture.state.permissions,
                metadata: fixture.state.metadataDigest,
                author: actor.leaf.credentialHandle,
                key: actor.key,
                marker: marker
            )) { error in
                XCTAssertEqual(error as? SignedGroupV2Error, .unauthorized)
            }
        }
    }

    func testChangeRoleEveryonePolicyDoesNotOverrideHierarchyOrAllowSelfEscalation() throws {
        let fixture = try makeRoleFixture(updatePolicy: .everyone)
        let attempts: [(RoleParticipant, RoleParticipant, GroupRole, UInt8)] = [
            (fixture.member, fixture.adminB, .member, 74),
            (fixture.member, fixture.member, .admin, 75),
            (fixture.adminA, fixture.adminA, .owner, 76)
        ]

        for (actor, target, newRole, marker) in attempts {
            XCTAssertThrowsError(try makeCommit(
                operation: .changeRole,
                state: fixture.state,
                members: changingRole(
                    target.member.id,
                    to: newRole,
                    in: fixture.state.members
                ),
                leaves: fixture.state.memberCredentials,
                permissions: fixture.state.permissions,
                metadata: fixture.state.metadataDigest,
                author: actor.leaf.credentialHandle,
                key: actor.key,
                marker: marker
            )) { error in
                XCTAssertEqual(error as? SignedGroupV2Error, .unauthorized)
            }
        }
    }

    func testChangeRoleAllowsSelfDemotionAndChangingLowerRoleWithinActorCeiling() throws {
        let fixture = try makeRoleFixture(updatePolicy: .admin)
        let adminSelfDemotion = try makeCommit(
            operation: .changeRole,
            state: fixture.state,
            members: changingRole(
                fixture.adminB.member.id,
                to: .member,
                in: fixture.state.members
            ),
            leaves: fixture.state.memberCredentials,
            permissions: fixture.state.permissions,
            metadata: fixture.state.metadataDigest,
            author: fixture.adminB.leaf.credentialHandle,
            key: fixture.adminB.key,
            marker: 77
        )
        let state2 = try SignedGroupStateV2.applying(
            adminSelfDemotion,
            to: fixture.state,
            observedAt: adminSelfDemotion.createdAt,
            signingKey: fixture.adminB.key
        )
        XCTAssertEqual(state2.members.first { $0.id == fixture.adminB.member.id }?.role, .member)

        let ownerSelfDemotion = try makeCommit(
            operation: .changeRole,
            state: state2,
            members: changingRole(
                fixture.ownerB.member.id,
                to: .admin,
                in: state2.members
            ),
            leaves: state2.memberCredentials,
            permissions: state2.permissions,
            metadata: state2.metadataDigest,
            author: fixture.ownerB.leaf.credentialHandle,
            key: fixture.ownerB.key,
            marker: 78
        )
        let state3 = try SignedGroupStateV2.applying(
            ownerSelfDemotion,
            to: state2,
            observedAt: ownerSelfDemotion.createdAt,
            signingKey: fixture.ownerB.key
        )
        XCTAssertEqual(state3.members.first { $0.id == fixture.ownerB.member.id }?.role, .admin)
        XCTAssertEqual(state3.activeMembers.filter { $0.role == .owner }.map(\.id), [fixture.ownerA.member.id])

        let promoteLowerMember = try makeCommit(
            operation: .changeRole,
            state: state3,
            members: changingRole(
                fixture.member.member.id,
                to: .admin,
                in: state3.members
            ),
            leaves: state3.memberCredentials,
            permissions: state3.permissions,
            metadata: state3.metadataDigest,
            author: fixture.adminA.leaf.credentialHandle,
            key: fixture.adminA.key,
            marker: 79
        )
        let state4 = try SignedGroupStateV2.applying(
            promoteLowerMember,
            to: state3,
            observedAt: promoteLowerMember.createdAt,
            signingKey: fixture.adminA.key
        )
        XCTAssertEqual(state4.members.first { $0.id == fixture.member.member.id }?.role, .admin)
    }

    func testParallelCredentialForOneMemberIsRejected() throws {
        let fixture = try makeFixture()
        let parallel = try makeAdmission(
            groupId: fixture.state.groupId,
            memberHandle: fixture.member.id,
            addedEpoch: fixture.state.epoch + 1,
            issuedAt: fixture.state.signedAt
        )
        XCTAssertThrowsError(try makeCommit(
            operation: .replaceCredential,
            state: fixture.state,
            members: fixture.state.members,
            leaves: fixture.state.memberCredentials + [parallel.leaf],
            admissionProjection: parallel.projection,
            permissions: fixture.state.permissions,
            metadata: fixture.state.metadataDigest,
            author: fixture.memberLeaves[0].credentialHandle,
            key: fixture.memberKeys[0],
            marker: 5
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidStructure)
        }
    }

    func testLastOwnerCannotBeDemotedOrRemoved() throws {
        let fixture = try makeFixture()
        let demotedUsers = fixture.state.members.map { member in
            member.id == fixture.ownerMember.id
                ? GroupMemberV2(id: member.id, role: .member, addedEpoch: member.addedEpoch)
                : member
        }
        XCTAssertThrowsError(try makeCommit(
            operation: .changeRole,
            state: fixture.state,
            members: demotedUsers,
            leaves: fixture.state.memberCredentials,
            permissions: fixture.state.permissions,
            metadata: fixture.state.metadataDigest,
            author: fixture.ownerLeaf.credentialHandle,
            key: fixture.ownerKey,
            marker: 6
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .wouldRemoveLastOwner)
        }

        let removedMembers = fixture.state.members.map { member in
            member.id == fixture.ownerMember.id
                ? GroupMemberV2(
                    id: member.id,
                    role: member.role,
                    addedEpoch: member.addedEpoch,
                    removedEpoch: fixture.state.epoch + 1
                )
                : member
        }
        var removedLeaves = fixture.state.memberCredentials
        replaceLeaf(
            &removedLeaves,
            removed(fixture.ownerLeaf, at: fixture.state.epoch + 1)
        )
        XCTAssertThrowsError(try makeCommit(
            operation: .removeMember,
            state: fixture.state,
            members: removedMembers,
            leaves: removedLeaves,
            permissions: fixture.state.permissions,
            metadata: fixture.state.metadataDigest,
            author: fixture.ownerLeaf.credentialHandle,
            key: fixture.ownerKey,
            marker: 7
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .wouldRemoveLastOwner)
        }
    }

    func testAddUserRolePolicyMetadataAndRemoveUserTransitionsAreAuthorized() throws {
        let fixture = try makeFixture()
        let newcomer = GroupMemberV2(
            id: .generate(),
            role: .member,
            addedEpoch: fixture.state.epoch + 1
        )
        let admission = try makeAdmission(
            groupId: fixture.state.groupId,
            memberHandle: newcomer.id,
            addedEpoch: fixture.state.epoch + 1,
            issuedAt: fixture.state.signedAt
        )
        let newcomerLeaf = admission.leaf
        let add = try makeCommit(
            operation: .addMember,
            state: fixture.state,
            members: fixture.state.members + [newcomer],
            leaves: fixture.state.memberCredentials + [newcomerLeaf],
            admissionProjection: admission.projection,
            permissions: fixture.state.permissions,
            metadata: fixture.state.metadataDigest,
            author: fixture.ownerLeaf.credentialHandle,
            key: fixture.ownerKey,
            marker: 8
        )
        let state2 = try SignedGroupStateV2.applying(
            add,
            to: fixture.state,
            observedAt: add.createdAt,
            signingKey: fixture.ownerKey
        )

        let promotedUsers = state2.members.map { member in
            member.id == newcomer.id
                ? GroupMemberV2(id: member.id, role: .admin, addedEpoch: member.addedEpoch)
                : member
        }
        let promote = try makeCommit(
            operation: .changeRole,
            state: state2,
            members: promotedUsers,
            leaves: state2.memberCredentials,
            permissions: state2.permissions,
            metadata: state2.metadataDigest,
            author: fixture.ownerLeaf.credentialHandle,
            key: fixture.ownerKey,
            marker: 9
        )
        let state3 = try SignedGroupStateV2.applying(
            promote,
            to: state2,
            observedAt: promote.createdAt,
            signingKey: fixture.ownerKey
        )

        let permissive = policy(updateMetadata: .everyone)
        let policyCommit = try makeCommit(
            operation: .changePolicy,
            state: state3,
            members: state3.members,
            leaves: state3.memberCredentials,
            permissions: permissive,
            metadata: state3.metadataDigest,
            author: fixture.ownerLeaf.credentialHandle,
            key: fixture.ownerKey,
            marker: 10
        )
        let state4 = try SignedGroupStateV2.applying(
            policyCommit,
            to: state3,
            observedAt: policyCommit.createdAt,
            signingKey: fixture.ownerKey
        )
        let metadataCommit = try makeCommit(
            operation: .updateMetadata,
            state: state4,
            members: state4.members,
            leaves: state4.memberCredentials,
            permissions: state4.permissions,
            metadata: Data(repeating: 0x51, count: 32),
            author: fixture.memberLeaves[0].credentialHandle,
            key: fixture.memberKeys[0],
            marker: 11
        )
        let state5 = try SignedGroupStateV2.applying(
            metadataCommit,
            to: state4,
            observedAt: metadataCommit.createdAt,
            signingKey: fixture.memberKeys[0]
        )
        XCTAssertEqual(state5.metadataDigest, Data(repeating: 0x51, count: 32))

        let removedMembers = state5.members.map { member in
            member.id == newcomer.id
                ? GroupMemberV2(
                    id: member.id,
                    role: member.role,
                    addedEpoch: member.addedEpoch,
                    removedEpoch: state5.epoch + 1
                )
                : member
        }
        var removedLeaves = state5.memberCredentials
        replaceLeaf(
            &removedLeaves,
            removed(newcomerLeaf, at: state5.epoch + 1)
        )
        let remove = try makeCommit(
            operation: .removeMember,
            state: state5,
            members: removedMembers,
            leaves: removedLeaves,
            permissions: state5.permissions,
            metadata: state5.metadataDigest,
            author: fixture.ownerLeaf.credentialHandle,
            key: fixture.ownerKey,
            marker: 12
        )
        let state6 = try SignedGroupStateV2.applying(
            remove,
            to: state5,
            observedAt: remove.createdAt,
            signingKey: fixture.ownerKey
        )
        XCTAssertFalse(state6.activeMembers.contains { $0.id == newcomer.id })
        XCTAssertFalse(state6.activeCredentials.contains { $0.memberHandle == newcomer.id })
    }

    func testGenesisRequiresPinnedGroupOnlyCreatorAdmission() throws {
        let groupId = UUID()
        let signedAt = Date(timeIntervalSince1970: 20_000)
        let owner = GroupMemberV2(id: .generate(), role: .owner, addedEpoch: 1)
        let ownerKey = try SigningKeyPair.generate()
        let genesis = try makeAdmission(
            groupId: groupId,
            memberHandle: owner.id,
            addedEpoch: 1,
            issuedAt: signedAt,
            groupSigningKey: ownerKey
        )
        let trust = genesis.projection
        let state = try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: owner,
            creatorAdmission: trust,
            metadataDigest: Data(repeating: 0x20, count: 32),
            providerGenesisDigest: Data(repeating: 0x10, count: 32),
            signingKey: ownerKey,
            signedAt: signedAt
        )

        XCTAssertNoThrow(try state.verified(
            genesisAdmission: trust,
            observedAt: signedAt
        ))
        XCTAssertEqual(state.members, [owner])
        XCTAssertEqual(state.memberCredentials, [genesis.leaf])
        XCTAssertEqual(state.authorCredentialHandle, genesis.projection.credentialHandle)
        XCTAssertThrowsError(try state.verified(observedAt: signedAt)) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .genesisAdmissionRequired)
        }

        let forgedAdmission = copy(
            genesis.projection,
            credentialSignature: flipped(genesis.projection.credentialPossessionSignature)
        )
        XCTAssertThrowsError(try state.verified(
            genesisAdmission: forgedAdmission,
            observedAt: signedAt
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidCredentialSignature)
        }

        let attacker = GroupMemberV2(id: .generate(), role: .owner, addedEpoch: 1)
        let attackerKey = try SigningKeyPair.generate()
        let attackerGenesis = try makeAdmission(
            groupId: groupId,
            memberHandle: attacker.id,
            addedEpoch: 1,
            issuedAt: signedAt,
            groupSigningKey: attackerKey
        )
        let attackerState = try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: attacker,
            creatorAdmission: attackerGenesis.projection,
            providerGenesisDigest: Data(repeating: 0x11, count: 32),
            signingKey: attackerKey,
            signedAt: signedAt
        )
        XCTAssertNoThrow(try attackerState.verified(
            genesisAdmission: attackerGenesis.projection,
            observedAt: signedAt
        ))
        XCTAssertThrowsError(try attackerState.verified(
            genesisAdmission: trust,
            observedAt: signedAt
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidTransition)
        }

        XCTAssertThrowsError(try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: GroupMemberV2(id: owner.id, role: .member, addedEpoch: 1),
            creatorAdmission: trust,
            providerGenesisDigest: Data(repeating: 0x12, count: 32),
            signingKey: ownerKey,
            signedAt: signedAt
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidTransition)
        }
        XCTAssertThrowsError(try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: owner,
            creatorAdmission: trust,
            providerGenesisDigest: Data(repeating: 0x13, count: 32),
            signingKey: attackerKey,
            signedAt: signedAt
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .unknownAuthor)
        }
    }

    func testSignedWelcomeBindsCiphertextDestinationAndAcceptedState() throws {
        let fixture = try makeFixture()
        let now = fixture.state.signedAt
        let welcome = try SignedGroupWelcomeV2.create(
            state: fixture.state,
            destinationCredentialHandle: fixture.memberLeaves[0].credentialHandle,
            encryptedWelcome: Data(repeating: 0xA5, count: 1_024),
            signingKey: fixture.ownerKey,
            createdAt: now,
            expiresAt: now.addingTimeInterval(3_600)
        )
        XCTAssertNoThrow(try welcome.verified(against: fixture.state, now: now))
        let tampered = copy(welcome, encryptedWelcome: Data(repeating: 0xA6, count: 1_024))
        XCTAssertThrowsError(try tampered.verified(against: fixture.state, now: now)) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidWelcomeSignature)
        }
    }

    func testSignedControlsRequireExactCanonicalEncoding() throws {
        let fixture = try makeFixture()
        let commit = try makeCommit(
            operation: .updateMetadata,
            state: fixture.state,
            members: fixture.state.members,
            leaves: fixture.state.memberCredentials,
            permissions: fixture.state.permissions,
            metadata: Data(repeating: 0xC1, count: 32),
            author: fixture.ownerLeaf.credentialHandle,
            key: fixture.ownerKey,
            marker: 0xC2
        )
        let welcome = try SignedGroupWelcomeV2.create(
            state: fixture.state,
            destinationCredentialHandle: fixture.memberLeaves[0].credentialHandle,
            encryptedWelcome: Data(repeating: 0xC3, count: 128),
            signingKey: fixture.ownerKey,
            createdAt: fixture.state.signedAt,
            expiresAt: fixture.state.signedAt.addingTimeInterval(3_600)
        )
        let tombstone = try SignedGroupDeletionTombstoneV2.create(
            currentState: fixture.state,
            authorCredentialHandle: fixture.ownerLeaf.credentialHandle,
            reasonDigest: Data(repeating: 0xC4, count: 32),
            idempotencyKey: Data(repeating: 0xC5, count: 32),
            signingKey: fixture.ownerKey,
            createdAt: fixture.state.signedAt.addingTimeInterval(1)
        )
        let deleted = try SignedDeletedGroupStateV2.create(
            tombstone: tombstone,
            from: fixture.state,
            observedAt: tombstone.createdAt
        )

        try assertExactRoundTrip(fixture.state, as: SignedGroupStateV2.self)
        try assertExactRoundTrip(commit, as: SignedGroupCommitV2.self)
        try assertExactRoundTrip(welcome, as: SignedGroupWelcomeV2.self)
        try assertExactRoundTrip(tombstone, as: SignedGroupDeletionTombstoneV2.self)
        try assertExactRoundTrip(deleted, as: SignedDeletedGroupStateV2.self)

        let encodedState = try NoctweaveCoder.encode(fixture.state, sortedKeys: true)
        var stateObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encodedState) as? [String: Any]
        )
        var members = try XCTUnwrap(stateObject["members"] as? [Any])
        members.reverse()
        stateObject["members"] = members
        let nonCanonical = try JSONSerialization.data(
            withJSONObject: stateObject,
            options: [.sortedKeys]
        )
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(SignedGroupStateV2.self, from: nonCanonical)
        )
    }
}

private extension ArchitectureV2SignedGroupTests {
    struct RoleParticipant {
        let member: GroupMemberV2
        let leaf: GroupMemberCredentialV2
        let key: SigningKeyPair
    }

    struct RoleFixture {
        let state: SignedGroupStateV2
        let ownerA: RoleParticipant
        let ownerB: RoleParticipant
        let adminA: RoleParticipant
        let adminB: RoleParticipant
        let member: RoleParticipant
    }

    struct Admission {
        let projection: GroupCredentialAdmissionV2
        let leaf: GroupMemberCredentialV2
        let groupSigningKey: SigningKeyPair
    }

    struct Fixture {
        let state: SignedGroupStateV2
        let ownerMember: GroupMemberV2
        let member: GroupMemberV2
        let ownerLeaf: GroupMemberCredentialV2
        let memberLeaves: [GroupMemberCredentialV2]
        let ownerKey: SigningKeyPair
        let memberKeys: [SigningKeyPair]
    }

    func makeRoleFixture(updatePolicy rule: GroupPermissionRule) throws -> RoleFixture {
        let groupId = UUID()
        let signedAt = Date(timeIntervalSince1970: 10_000)
        let ownerAMember = GroupMemberV2(id: .generate(), role: .owner, addedEpoch: 1)
        let ownerAKey = try SigningKeyPair.generate()
        let ownerAGenesis = try makeAdmission(
            groupId: groupId,
            memberHandle: ownerAMember.id,
            addedEpoch: 1,
            issuedAt: signedAt,
            groupSigningKey: ownerAKey
        )
        let ownerA = RoleParticipant(
            member: ownerAMember,
            leaf: ownerAGenesis.leaf,
            key: ownerAKey
        )
        var state = try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: ownerAMember,
            creatorAdmission: ownerAGenesis.projection,
            permissions: policy(updatePolicy: rule),
            metadataDigest: Data(repeating: 0x20, count: 32),
            providerGenesisDigest: Data(repeating: 0x10, count: 32),
            signingKey: ownerA.key,
            signedAt: signedAt
        )
        var marker: UInt8 = 180
        func addParticipant(role: GroupRole) throws -> RoleParticipant {
            let nextEpoch = state.epoch + 1
            let member = GroupMemberV2(id: .generate(), role: role, addedEpoch: nextEpoch)
            let admission = try makeAdmission(
                groupId: groupId,
                memberHandle: member.id,
                addedEpoch: nextEpoch,
                issuedAt: state.signedAt
            )
            let commit = try makeCommit(
                operation: .addMember,
                state: state,
                members: state.members + [member],
                leaves: state.memberCredentials + [admission.leaf],
                admissionProjection: admission.projection,
                permissions: state.permissions,
                metadata: state.metadataDigest,
                author: ownerA.leaf.credentialHandle,
                key: ownerA.key,
                marker: marker
            )
            state = try SignedGroupStateV2.applying(
                commit,
                to: state,
                observedAt: commit.createdAt,
                signingKey: ownerA.key
            )
            marker &+= 1
            return RoleParticipant(
                member: member,
                leaf: admission.leaf,
                key: admission.groupSigningKey
            )
        }
        let ownerB = try addParticipant(role: .owner)
        let adminA = try addParticipant(role: .admin)
        let adminB = try addParticipant(role: .admin)
        let member = try addParticipant(role: .member)
        return RoleFixture(
            state: state,
            ownerA: ownerA,
            ownerB: ownerB,
            adminA: adminA,
            adminB: adminB,
            member: member
        )
    }

    func changingRole(
        _ memberHandle: GroupScopedMemberHandleV2,
        to role: GroupRole,
        in members: [GroupMemberV2]
    ) -> [GroupMemberV2] {
        members.map { member in
            guard member.id == memberHandle else { return member }
            return GroupMemberV2(
                id: member.id,
                role: role,
                addedEpoch: member.addedEpoch,
                removedEpoch: member.removedEpoch
            )
        }
    }

    func makeFixture() throws -> Fixture {
        let groupId = UUID()
        let signedAt = Date(timeIntervalSince1970: 10_000)
        let owner = GroupMemberV2(id: .generate(), role: .owner, addedEpoch: 1)
        let ownerKey = try SigningKeyPair.generate()
        let ownerGenesis = try makeAdmission(
            groupId: groupId,
            memberHandle: owner.id,
            addedEpoch: 1,
            issuedAt: signedAt,
            groupSigningKey: ownerKey
        )
        let ownerLeaf = ownerGenesis.leaf
        var state = try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: owner,
            creatorAdmission: ownerGenesis.projection,
            metadataDigest: Data(repeating: 0x20, count: 32),
            providerGenesisDigest: Data(repeating: 0x10, count: 32),
            signingKey: ownerKey,
            signedAt: signedAt
        )
        let nextEpoch = state.epoch + 1
        let member = GroupMemberV2(id: .generate(), role: .member, addedEpoch: nextEpoch)
        let admission = try makeAdmission(
            groupId: groupId,
            memberHandle: member.id,
            addedEpoch: nextEpoch,
            issuedAt: state.signedAt
        )
        let commit = try makeCommit(
            operation: .addMember,
            state: state,
            members: state.members + [member],
            leaves: state.memberCredentials + [admission.leaf],
            admissionProjection: admission.projection,
            permissions: state.permissions,
            metadata: state.metadataDigest,
            author: ownerLeaf.credentialHandle,
            key: ownerKey,
            marker: 200
        )
        state = try SignedGroupStateV2.applying(
            commit,
            to: state,
            observedAt: commit.createdAt,
            signingKey: ownerKey
        )
        return Fixture(
            state: state,
            ownerMember: owner,
            member: member,
            ownerLeaf: ownerLeaf,
            memberLeaves: [admission.leaf],
            ownerKey: ownerKey,
            memberKeys: [admission.groupSigningKey]
        )
    }

    func leaf(
        memberHandle: GroupScopedMemberHandleV2,
        marker: UInt8,
        signingKey: SigningKeyPair,
        epoch: UInt64
    ) throws -> GroupMemberCredentialV2 {
        GroupMemberCredentialV2(
            memberHandle: memberHandle,
            credentialHandle: GroupScopedCredentialHandleV2(
                rawValue: Data(repeating: marker, count: 32).base64EncodedString()
            ),
            admissionDigest: Data(repeating: marker &+ 80, count: 32),
            signingPublicKey: signingKey.publicKeyData,
            agreementPublicKey: try AgreementKeyPair.generate().publicKeyData,
            addedEpoch: epoch
        )
    }

    func makeAdmission(
        groupId: UUID,
        memberHandle: GroupScopedMemberHandleV2,
        addedEpoch: UInt64,
        issuedAt: Date,
        expiresAt: Date? = nil,
        credentialHandle: GroupScopedCredentialHandleV2? = nil,
        groupSigningKey requestedGroupSigningKey: SigningKeyPair? = nil
    ) throws -> Admission {
        let groupSigningKey = try requestedGroupSigningKey ?? SigningKeyPair.generate()
        let groupAgreementKey = try AgreementKeyPair.generate()
        let resolvedCredentialHandle = credentialHandle ?? .generate()
        let projection = try GroupCredentialAdmissionV2.create(
            groupId: groupId,
            memberHandle: memberHandle,
            credentialHandle: resolvedCredentialHandle,
            groupSigningKey: groupSigningKey,
            groupAgreementKey: groupAgreementKey,
            issuedAt: issuedAt,
            expiresAt: expiresAt ?? issuedAt.addingTimeInterval(3_600)
        )
        return Admission(
            projection: projection,
            leaf: try GroupMemberCredentialV2.fromVerifiedProjection(
                projection,
                addedEpoch: addedEpoch
            ),
            groupSigningKey: groupSigningKey
        )
    }

    func makeCommit(
        operation: SignedGroupCommitOperationV2,
        state: SignedGroupStateV2,
        members: [GroupMemberV2],
        leaves: [GroupMemberCredentialV2],
        admissionProjection: GroupCredentialAdmissionV2? = nil,
        permissions: GroupPermissionPolicy,
        metadata: Data?,
        author: GroupScopedCredentialHandleV2,
        key: SigningKeyPair,
        marker: UInt8,
        createdAt: Date? = nil
    ) throws -> SignedGroupCommitV2 {
        return try SignedGroupCommitV2.create(
            operation: operation,
            currentState: state,
            proposedMembers: members,
            proposedCredentials: leaves,
            admissionProjection: admissionProjection,
            proposedPermissions: permissions,
            proposedMetadataDigest: metadata,
            authorCredentialHandle: author,
            providerCommitDigest: Data(repeating: marker, count: 32),
            idempotencyKey: Data(repeating: marker &+ 100, count: 32),
            signingKey: key,
            createdAt: createdAt ?? state.signedAt.addingTimeInterval(1)
        )
    }

    func removed(_ leaf: GroupMemberCredentialV2, at epoch: UInt64) -> GroupMemberCredentialV2 {
        GroupMemberCredentialV2(
            memberHandle: leaf.memberHandle,
            credentialHandle: leaf.credentialHandle,
            admissionDigest: leaf.admissionDigest,
            signingPublicKey: leaf.signingPublicKey,
            agreementPublicKey: leaf.agreementPublicKey,
            addedEpoch: leaf.addedEpoch,
            removedEpoch: epoch
        )
    }

    func replaceLeaf(_ leaves: inout [GroupMemberCredentialV2], _ replacement: GroupMemberCredentialV2) {
        let index = leaves.firstIndex { $0.credentialHandle == replacement.credentialHandle }!
        leaves[index] = replacement
    }

    func policy(updateMetadata rule: GroupPermissionRule) -> GroupPermissionPolicy {
        GroupPermissionPolicy(entries: GroupPermission.allCases.map { permission in
            GroupPermissionEntry(
                permission: permission,
                rule: permission == .updateMetadata
                    ? rule
                    : GroupPermissionPolicy.default.rule(for: permission)!
            )
        })
    }

    func policy(updatePolicy rule: GroupPermissionRule) -> GroupPermissionPolicy {
        GroupPermissionPolicy(entries: GroupPermission.allCases.map { permission in
            GroupPermissionEntry(
                permission: permission,
                rule: permission == .updatePolicy
                    ? rule
                    : GroupPermissionPolicy.default.rule(for: permission)!
            )
        })
    }

    func flipped(_ data: Data) -> Data {
        var result = data
        result[0] ^= 0x01
        return result
    }

    func copy(
        _ admission: GroupCredentialAdmissionV2,
        credentialSignature: Data
    ) -> GroupCredentialAdmissionV2 {
        GroupCredentialAdmissionV2(
            id: admission.id,
            groupId: admission.groupId,
            memberHandle: admission.memberHandle,
            credentialHandle: admission.credentialHandle,
            selection: admission.selection,
            groupSigningPublicKey: admission.groupSigningPublicKey,
            groupAgreementPublicKey: admission.groupAgreementPublicKey,
            issuedAt: admission.issuedAt,
            expiresAt: admission.expiresAt,
            credentialPossessionSignature: credentialSignature
        )
    }

    func copy(_ commit: SignedGroupCommitV2, metadata: Data?) -> SignedGroupCommitV2 {
        SignedGroupCommitV2(
            id: commit.id,
            profile: commit.profile,
            cipherSuite: commit.cipherSuite,
            groupId: commit.groupId,
            operation: commit.operation,
            baseEpoch: commit.baseEpoch,
            nextEpoch: commit.nextEpoch,
            previousTranscriptHash: commit.previousTranscriptHash,
            proposedMembers: commit.proposedMembers,
            proposedCredentials: commit.proposedCredentials,
            admissionProjection: commit.admissionProjection,
            proposedPermissions: commit.proposedPermissions,
            proposedMetadataDigest: metadata,
            authorCredentialHandle: commit.authorCredentialHandle,
            providerCommitDigest: commit.providerCommitDigest,
            idempotencyKey: commit.idempotencyKey,
            createdAt: commit.createdAt,
            signature: commit.signature
        )
    }

    func copy(
        _ commit: SignedGroupCommitV2,
        admissionProjection: GroupCredentialAdmissionV2?
    ) -> SignedGroupCommitV2 {
        SignedGroupCommitV2(
            id: commit.id,
            profile: commit.profile,
            cipherSuite: commit.cipherSuite,
            groupId: commit.groupId,
            operation: commit.operation,
            baseEpoch: commit.baseEpoch,
            nextEpoch: commit.nextEpoch,
            previousTranscriptHash: commit.previousTranscriptHash,
            proposedMembers: commit.proposedMembers,
            proposedCredentials: commit.proposedCredentials,
            admissionProjection: admissionProjection,
            proposedPermissions: commit.proposedPermissions,
            proposedMetadataDigest: commit.proposedMetadataDigest,
            authorCredentialHandle: commit.authorCredentialHandle,
            providerCommitDigest: commit.providerCommitDigest,
            idempotencyKey: commit.idempotencyKey,
            createdAt: commit.createdAt,
            signature: commit.signature
        )
    }

    func copy(_ state: SignedGroupStateV2, members: [GroupMemberV2]) -> SignedGroupStateV2 {
        SignedGroupStateV2(
            profile: state.profile,
            cipherSuite: state.cipherSuite,
            groupId: state.groupId,
            epoch: state.epoch,
            previousTranscriptHash: state.previousTranscriptHash,
            members: members,
            memberCredentials: state.memberCredentials,
            permissions: state.permissions,
            metadataDigest: state.metadataDigest,
            authorCredentialHandle: state.authorCredentialHandle,
            commitDigest: state.commitDigest,
            confirmedTranscriptHash: state.confirmedTranscriptHash,
            signedAt: state.signedAt,
            signature: state.signature
        )
    }

    func copy(_ welcome: SignedGroupWelcomeV2, encryptedWelcome: Data) -> SignedGroupWelcomeV2 {
        SignedGroupWelcomeV2(
            id: welcome.id,
            profile: welcome.profile,
            cipherSuite: welcome.cipherSuite,
            groupId: welcome.groupId,
            epoch: welcome.epoch,
            stateTranscriptHash: welcome.stateTranscriptHash,
            commitDigest: welcome.commitDigest,
            authorCredentialHandle: welcome.authorCredentialHandle,
            destinationCredentialHandle: welcome.destinationCredentialHandle,
            destinationAdmissionDigest: welcome.destinationAdmissionDigest,
            encryptedWelcome: encryptedWelcome,
            createdAt: welcome.createdAt,
            expiresAt: welcome.expiresAt,
            signature: welcome.signature
        )
    }

    func assertExactRoundTrip<T: Codable & Equatable>(
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
        object["unknownControl"] = true
        let unknown = try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys]
        )
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(type, from: unknown),
            file: file,
            line: line
        )
    }
}
