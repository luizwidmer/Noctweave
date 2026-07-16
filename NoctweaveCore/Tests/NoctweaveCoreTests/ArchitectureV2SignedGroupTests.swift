import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2SignedGroupTests: XCTestCase {
    func testGroupClientKeyPackageBindsGroupIdentityInstallationAndGroupKeyPossession() throws {
        let now = Date()
        let identityGenerationId = UUID()
        let identity = try Identity.generate(displayName: "Owner")
        let installation = try LocalInstallationState.generate(
            identityGenerationId: identityGenerationId,
            createdAt: now.addingTimeInterval(-20)
        )
        let manifest = try InstallationManifest.create(
            identityGenerationId: identityGenerationId,
            epoch: 0,
            installations: [installation.publicRecord(addedEpoch: 0)],
            identity: identity,
            issuedAt: now.addingTimeInterval(-10)
        )
        let groupId = UUID()
        let userId = UUID()
        let groupSigningKey = try SigningKeyPair.generate()
        let groupAgreementKey = try AgreementKeyPair.generate()
        let package = try GroupClientKeyPackageV2.create(
            groupId: groupId,
            groupUserId: userId,
            clientHandle: .generate(groupId: groupId, installationId: installation.id),
            identity: identity,
            installation: installation,
            manifest: manifest,
            groupSigningKey: groupSigningKey,
            groupAgreementKey: groupAgreementKey,
            issuedAt: now,
            expiresAt: now.addingTimeInterval(3_600)
        )

        XCTAssertNoThrow(try package.verified(
            forGroupId: groupId,
            groupUserId: userId,
            identityPublicKey: identity.signingKey.publicKeyData,
            manifest: manifest,
            now: now
        ))
        XCTAssertThrowsError(try package.verified(
            forGroupId: UUID(),
            groupUserId: userId,
            identityPublicKey: identity.signingKey.publicKeyData,
            manifest: manifest,
            now: now
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidContext)
        }

        let tampered = copy(package, installationSignature: flipped(package.installationPossessionSignature))
        XCTAssertThrowsError(try tampered.verified(
            forGroupId: groupId,
            groupUserId: userId,
            identityPublicKey: identity.signingKey.publicKeyData,
            manifest: manifest,
            now: now
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidInstallationSignature)
        }
    }

    func testAddClientDerivesExactLeafFromPrivacyProjection() throws {
        let fixture = try makeFixture(memberLeafCount: 1)
        let admission = try makeAdmission(
            groupId: fixture.state.groupId,
            userId: fixture.memberUser.id,
            addedEpoch: fixture.state.epoch + 1,
            issuedAt: fixture.state.signedAt
        )
        let consent = try GroupSiblingClientConsentV2.create(
            projection: admission.projection,
            currentState: fixture.state,
            consentingClientHandle: fixture.memberLeaves[0].clientHandle,
            signingKey: fixture.memberKeys[0],
            signedAt: fixture.state.signedAt.addingTimeInterval(0.5)
        )
        let commit = try makeCommit(
            operation: .addClient,
            state: fixture.state,
            users: fixture.state.users,
            leaves: fixture.state.clientLeaves + [admission.leaf],
            admissionProjection: admission.projection,
            siblingClientConsent: consent,
            permissions: fixture.state.permissions,
            metadata: fixture.state.metadataDigest,
            author: fixture.ownerLeaf.clientHandle,
            key: fixture.ownerKey,
            marker: 60
        )

        XCTAssertNoThrow(try commit.verifiedTransition(from: fixture.state))
        let next = try SignedGroupStateV2.applying(
            commit,
            to: fixture.state,
            signingKey: fixture.ownerKey
        )
        XCTAssertEqual(
            next.clientLeaves.first { $0.clientHandle == admission.projection.clientHandle },
            admission.leaf
        )

        let replacement = try makeAdmission(
            groupId: fixture.state.groupId,
            userId: fixture.memberUser.id,
            addedEpoch: fixture.state.epoch + 1,
            issuedAt: fixture.state.signedAt
        )
        let projectionTamperedAfterSigning = copy(
            commit,
            admissionProjection: replacement.projection
        )
        XCTAssertThrowsError(try projectionTamperedAfterSigning
            .verifiedTransition(from: fixture.state)) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidCommitSignature)
        }
    }

    func testCommitTamperingRollbackAndForkFailClosed() throws {
        let fixture = try makeFixture(memberLeafCount: 1)
        let metadataA = Data(repeating: 0x31, count: 32)
        let metadataB = Data(repeating: 0x32, count: 32)
        let commitA = try makeCommit(
            operation: .updateMetadata,
            state: fixture.state,
            users: fixture.state.users,
            leaves: fixture.state.clientLeaves,
            permissions: fixture.state.permissions,
            metadata: metadataA,
            author: fixture.ownerLeaf.clientHandle,
            key: fixture.ownerKey,
            marker: 1
        )
        let commitB = try makeCommit(
            operation: .updateMetadata,
            state: fixture.state,
            users: fixture.state.users,
            leaves: fixture.state.clientLeaves,
            permissions: fixture.state.permissions,
            metadata: metadataB,
            author: fixture.ownerLeaf.clientHandle,
            key: fixture.ownerKey,
            marker: 2
        )
        XCTAssertNoThrow(try commitA.verifiedTransition(from: fixture.state))
        XCTAssertNoThrow(try commitB.verifiedTransition(from: fixture.state))

        let tampered = copy(commitA, metadata: metadataB)
        XCTAssertThrowsError(try tampered.verifiedTransition(from: fixture.state)) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidCommitSignature)
        }

        let next = try SignedGroupStateV2.applying(commitA, to: fixture.state, signingKey: fixture.ownerKey)
        XCTAssertNoThrow(try next.verified(previousState: fixture.state, commit: commitA))
        XCTAssertThrowsError(try commitA.verifiedTransition(from: next)) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .staleEpoch)
        }
        XCTAssertThrowsError(try commitB.verifiedTransition(from: next)) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .staleEpoch)
        }
    }

    func testMemberCannotChangePolicyAndStateTamperingBreaksTranscript() throws {
        let fixture = try makeFixture(memberLeafCount: 1)
        let permissive = policy(updateMetadata: .everyone)
        XCTAssertThrowsError(try makeCommit(
            operation: .changePolicy,
            state: fixture.state,
            users: fixture.state.users,
            leaves: fixture.state.clientLeaves,
            permissions: permissive,
            metadata: fixture.state.metadataDigest,
            author: fixture.memberLeaves[0].clientHandle,
            key: fixture.memberKeys[0],
            marker: 3
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .unauthorized)
        }

        let tamperedUsers = fixture.state.users.map { user in
            user.id == fixture.memberUser.id
                ? GroupUser(id: user.id, role: .admin, addedEpoch: user.addedEpoch)
                : user
        }
        let tamperedState = copy(fixture.state, users: tamperedUsers)
        XCTAssertFalse(tamperedState.isStructurallyValid)
        XCTAssertThrowsError(try tamperedState.verified()) { error in
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
                users: changingRole(
                    target.user.id,
                    to: newRole,
                    in: fixture.state.users
                ),
                leaves: fixture.state.clientLeaves,
                permissions: fixture.state.permissions,
                metadata: fixture.state.metadataDigest,
                author: actor.leaf.clientHandle,
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
                users: changingRole(
                    target.user.id,
                    to: newRole,
                    in: fixture.state.users
                ),
                leaves: fixture.state.clientLeaves,
                permissions: fixture.state.permissions,
                metadata: fixture.state.metadataDigest,
                author: actor.leaf.clientHandle,
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
            users: changingRole(
                fixture.adminB.user.id,
                to: .member,
                in: fixture.state.users
            ),
            leaves: fixture.state.clientLeaves,
            permissions: fixture.state.permissions,
            metadata: fixture.state.metadataDigest,
            author: fixture.adminB.leaf.clientHandle,
            key: fixture.adminB.key,
            marker: 77
        )
        let state2 = try SignedGroupStateV2.applying(
            adminSelfDemotion,
            to: fixture.state,
            signingKey: fixture.adminB.key
        )
        XCTAssertEqual(state2.users.first { $0.id == fixture.adminB.user.id }?.role, .member)

        let ownerSelfDemotion = try makeCommit(
            operation: .changeRole,
            state: state2,
            users: changingRole(
                fixture.ownerB.user.id,
                to: .admin,
                in: state2.users
            ),
            leaves: state2.clientLeaves,
            permissions: state2.permissions,
            metadata: state2.metadataDigest,
            author: fixture.ownerB.leaf.clientHandle,
            key: fixture.ownerB.key,
            marker: 78
        )
        let state3 = try SignedGroupStateV2.applying(
            ownerSelfDemotion,
            to: state2,
            signingKey: fixture.ownerB.key
        )
        XCTAssertEqual(state3.users.first { $0.id == fixture.ownerB.user.id }?.role, .admin)
        XCTAssertEqual(state3.activeUsers.filter { $0.role == .owner }.map(\.id), [fixture.ownerA.user.id])

        let promoteLowerMember = try makeCommit(
            operation: .changeRole,
            state: state3,
            users: changingRole(
                fixture.member.user.id,
                to: .admin,
                in: state3.users
            ),
            leaves: state3.clientLeaves,
            permissions: state3.permissions,
            metadata: state3.metadataDigest,
            author: fixture.adminA.leaf.clientHandle,
            key: fixture.adminA.key,
            marker: 79
        )
        let state4 = try SignedGroupStateV2.applying(
            promoteLowerMember,
            to: state3,
            signingKey: fixture.adminA.key
        )
        XCTAssertEqual(state4.users.first { $0.id == fixture.member.user.id }?.role, .admin)
    }

    func testRemovingOneClientPreservesSiblingAndRemovingLastClientIsRejected() throws {
        let fixture = try makeFixture(memberLeafCount: 2)
        var leaves = fixture.state.clientLeaves
        replaceLeaf(
            &leaves,
            removed(fixture.memberLeaves[0], at: fixture.state.epoch + 1)
        )
        let removeFirst = try makeCommit(
            operation: .removeClient,
            state: fixture.state,
            users: fixture.state.users,
            leaves: leaves,
            permissions: fixture.state.permissions,
            metadata: fixture.state.metadataDigest,
            author: fixture.ownerLeaf.clientHandle,
            key: fixture.ownerKey,
            marker: 4
        )
        let next = try SignedGroupStateV2.applying(
            removeFirst,
            to: fixture.state,
            signingKey: fixture.ownerKey
        )
        XCTAssertFalse(next.activeClientLeaves.contains { $0.id == fixture.memberLeaves[0].id })
        XCTAssertTrue(next.activeClientLeaves.contains { $0.id == fixture.memberLeaves[1].id })
        XCTAssertTrue(next.activeUsers.contains { $0.id == fixture.memberUser.id })

        var finalLeaves = next.clientLeaves
        replaceLeaf(
            &finalLeaves,
            removed(fixture.memberLeaves[1], at: next.epoch + 1)
        )
        XCTAssertThrowsError(try makeCommit(
            operation: .removeClient,
            state: next,
            users: next.users,
            leaves: finalLeaves,
            permissions: next.permissions,
            metadata: next.metadataDigest,
            author: fixture.ownerLeaf.clientHandle,
            key: fixture.ownerKey,
            marker: 5
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidTransition)
        }
    }

    func testLastOwnerCannotBeDemotedOrRemoved() throws {
        let fixture = try makeFixture(memberLeafCount: 1)
        let demotedUsers = fixture.state.users.map { user in
            user.id == fixture.ownerUser.id
                ? GroupUser(id: user.id, role: .member, addedEpoch: user.addedEpoch)
                : user
        }
        XCTAssertThrowsError(try makeCommit(
            operation: .changeRole,
            state: fixture.state,
            users: demotedUsers,
            leaves: fixture.state.clientLeaves,
            permissions: fixture.state.permissions,
            metadata: fixture.state.metadataDigest,
            author: fixture.ownerLeaf.clientHandle,
            key: fixture.ownerKey,
            marker: 6
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .wouldRemoveLastOwner)
        }

        let removedUsers = fixture.state.users.map { user in
            user.id == fixture.ownerUser.id
                ? GroupUser(
                    id: user.id,
                    role: user.role,
                    addedEpoch: user.addedEpoch,
                    removedEpoch: fixture.state.epoch + 1
                )
                : user
        }
        var removedLeaves = fixture.state.clientLeaves
        replaceLeaf(
            &removedLeaves,
            removed(fixture.ownerLeaf, at: fixture.state.epoch + 1)
        )
        XCTAssertThrowsError(try makeCommit(
            operation: .removeUser,
            state: fixture.state,
            users: removedUsers,
            leaves: removedLeaves,
            permissions: fixture.state.permissions,
            metadata: fixture.state.metadataDigest,
            author: fixture.ownerLeaf.clientHandle,
            key: fixture.ownerKey,
            marker: 7
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .wouldRemoveLastOwner)
        }
    }

    func testAddUserRolePolicyMetadataAndRemoveUserTransitionsAreAuthorized() throws {
        let fixture = try makeFixture(memberLeafCount: 1)
        let newcomer = GroupUser(
            id: UUID(),
            role: .member,
            addedEpoch: fixture.state.epoch + 1
        )
        let admission = try makeAdmission(
            groupId: fixture.state.groupId,
            userId: newcomer.id,
            addedEpoch: fixture.state.epoch + 1,
            issuedAt: fixture.state.signedAt
        )
        let newcomerLeaf = admission.leaf
        let add = try makeCommit(
            operation: .addUser,
            state: fixture.state,
            users: fixture.state.users + [newcomer],
            leaves: fixture.state.clientLeaves + [newcomerLeaf],
            admissionProjection: admission.projection,
            permissions: fixture.state.permissions,
            metadata: fixture.state.metadataDigest,
            author: fixture.ownerLeaf.clientHandle,
            key: fixture.ownerKey,
            marker: 8
        )
        let state2 = try SignedGroupStateV2.applying(
            add,
            to: fixture.state,
            signingKey: fixture.ownerKey
        )

        let promotedUsers = state2.users.map { user in
            user.id == newcomer.id
                ? GroupUser(id: user.id, role: .admin, addedEpoch: user.addedEpoch)
                : user
        }
        let promote = try makeCommit(
            operation: .changeRole,
            state: state2,
            users: promotedUsers,
            leaves: state2.clientLeaves,
            permissions: state2.permissions,
            metadata: state2.metadataDigest,
            author: fixture.ownerLeaf.clientHandle,
            key: fixture.ownerKey,
            marker: 9
        )
        let state3 = try SignedGroupStateV2.applying(promote, to: state2, signingKey: fixture.ownerKey)

        let permissive = policy(updateMetadata: .everyone)
        let policyCommit = try makeCommit(
            operation: .changePolicy,
            state: state3,
            users: state3.users,
            leaves: state3.clientLeaves,
            permissions: permissive,
            metadata: state3.metadataDigest,
            author: fixture.ownerLeaf.clientHandle,
            key: fixture.ownerKey,
            marker: 10
        )
        let state4 = try SignedGroupStateV2.applying(policyCommit, to: state3, signingKey: fixture.ownerKey)
        let metadataCommit = try makeCommit(
            operation: .updateMetadata,
            state: state4,
            users: state4.users,
            leaves: state4.clientLeaves,
            permissions: state4.permissions,
            metadata: Data(repeating: 0x51, count: 32),
            author: fixture.memberLeaves[0].clientHandle,
            key: fixture.memberKeys[0],
            marker: 11
        )
        let state5 = try SignedGroupStateV2.applying(
            metadataCommit,
            to: state4,
            signingKey: fixture.memberKeys[0]
        )
        XCTAssertEqual(state5.metadataDigest, Data(repeating: 0x51, count: 32))

        let removedUsers = state5.users.map { user in
            user.id == newcomer.id
                ? GroupUser(
                    id: user.id,
                    role: user.role,
                    addedEpoch: user.addedEpoch,
                    removedEpoch: state5.epoch + 1
                )
                : user
        }
        var removedLeaves = state5.clientLeaves
        replaceLeaf(
            &removedLeaves,
            removed(newcomerLeaf, at: state5.epoch + 1)
        )
        let remove = try makeCommit(
            operation: .removeUser,
            state: state5,
            users: removedUsers,
            leaves: removedLeaves,
            permissions: state5.permissions,
            metadata: state5.metadataDigest,
            author: fixture.ownerLeaf.clientHandle,
            key: fixture.ownerKey,
            marker: 12
        )
        let state6 = try SignedGroupStateV2.applying(remove, to: state5, signingKey: fixture.ownerKey)
        XCTAssertFalse(state6.activeUsers.contains { $0.id == newcomer.id })
        XCTAssertFalse(state6.activeClientLeaves.contains { $0.userId == newcomer.id })
    }

    func testGenesisRequiresPinnedCreatorPackageAuthorityAndManifest() throws {
        let groupId = UUID()
        let signedAt = Date(timeIntervalSince1970: 20_000)
        let owner = GroupUser(id: UUID(), role: .owner, addedEpoch: 1)
        let ownerKey = try SigningKeyPair.generate()
        let genesis = try makeAdmission(
            groupId: groupId,
            userId: owner.id,
            addedEpoch: 1,
            issuedAt: signedAt,
            groupSigningKey: ownerKey
        )
        let trust = genesis.genesisTrust
        let state = try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: owner,
            creatorTrust: trust,
            metadataDigest: Data(repeating: 0x20, count: 32),
            providerGenesisDigest: Data(repeating: 0x10, count: 32),
            signingKey: ownerKey,
            signedAt: signedAt
        )

        XCTAssertNoThrow(try state.verified(genesisTrust: trust))
        XCTAssertEqual(state.users, [owner])
        XCTAssertEqual(state.clientLeaves, [genesis.packageLeaf])
        XCTAssertEqual(state.authorClientHandle, genesis.package.clientHandle)
        XCTAssertThrowsError(try state.verified()) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .genesisTrustRequired)
        }

        let forgedPackageTrust = GroupGenesisTrustV2(
            creatorUserId: owner.id,
            identityPublicKey: genesis.identity.signingKey.publicKeyData,
            currentManifest: genesis.manifest,
            creatorKeyPackage: copy(
                genesis.package,
                clientSignature: flipped(genesis.package.groupClientPossessionSignature)
            )
        )
        XCTAssertThrowsError(try state.verified(genesisTrust: forgedPackageTrust)) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidClientSignature)
        }

        let attacker = GroupUser(id: UUID(), role: .owner, addedEpoch: 1)
        let attackerKey = try SigningKeyPair.generate()
        let attackerGenesis = try makeAdmission(
            groupId: groupId,
            userId: attacker.id,
            addedEpoch: 1,
            issuedAt: signedAt,
            groupSigningKey: attackerKey
        )
        let attackerState = try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: attacker,
            creatorTrust: attackerGenesis.genesisTrust,
            providerGenesisDigest: Data(repeating: 0x11, count: 32),
            signingKey: attackerKey,
            signedAt: signedAt
        )
        XCTAssertNoThrow(try attackerState.verified(genesisTrust: attackerGenesis.genesisTrust))
        XCTAssertThrowsError(try attackerState.verified(genesisTrust: trust)) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidTransition)
        }

        XCTAssertThrowsError(try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: GroupUser(id: owner.id, role: .member, addedEpoch: 1),
            creatorTrust: trust,
            providerGenesisDigest: Data(repeating: 0x12, count: 32),
            signingKey: ownerKey,
            signedAt: signedAt
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidTransition)
        }
        XCTAssertThrowsError(try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: owner,
            creatorTrust: trust,
            providerGenesisDigest: Data(repeating: 0x13, count: 32),
            signingKey: attackerKey,
            signedAt: signedAt
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .unknownAuthor)
        }
    }

    func testSignedWelcomeBindsCiphertextDestinationAndAcceptedState() throws {
        let fixture = try makeFixture(memberLeafCount: 1)
        let now = fixture.state.signedAt
        let welcome = try SignedGroupWelcomeV2.create(
            state: fixture.state,
            destinationClientHandle: fixture.memberLeaves[0].clientHandle,
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
}

private extension ArchitectureV2SignedGroupTests {
    struct RoleParticipant {
        let user: GroupUser
        let leaf: GroupClientLeafV2
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
        let identity: Identity
        let installation: LocalInstallationState
        let manifest: InstallationManifest
        let package: GroupClientKeyPackageV2
        let projection: GroupClientAdmissionProjectionV2
        let packageLeaf: GroupClientLeafV2
        let leaf: GroupClientLeafV2
        let trust: GroupClientAdmissionTrustV2
        let groupSigningKey: SigningKeyPair

        var genesisTrust: GroupGenesisTrustV2 {
            GroupGenesisTrustV2(
                creatorUserId: package.groupUserId,
                identityPublicKey: identity.signingKey.publicKeyData,
                currentManifest: manifest,
                creatorKeyPackage: package
            )
        }
    }

    struct Fixture {
        let state: SignedGroupStateV2
        let ownerUser: GroupUser
        let memberUser: GroupUser
        let ownerLeaf: GroupClientLeafV2
        let memberLeaves: [GroupClientLeafV2]
        let ownerKey: SigningKeyPair
        let memberKeys: [SigningKeyPair]
    }

    func makeRoleFixture(updatePolicy rule: GroupPermissionRule) throws -> RoleFixture {
        let groupId = UUID()
        let signedAt = Date(timeIntervalSince1970: 10_000)
        let ownerAUser = GroupUser(id: UUID(), role: .owner, addedEpoch: 1)
        let ownerAKey = try SigningKeyPair.generate()
        let ownerAGenesis = try makeAdmission(
            groupId: groupId,
            userId: ownerAUser.id,
            addedEpoch: 1,
            issuedAt: signedAt,
            groupSigningKey: ownerAKey
        )
        let ownerA = RoleParticipant(
            user: ownerAUser,
            leaf: ownerAGenesis.packageLeaf,
            key: ownerAKey
        )
        var state = try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: ownerAUser,
            creatorTrust: ownerAGenesis.genesisTrust,
            permissions: policy(updatePolicy: rule),
            metadataDigest: Data(repeating: 0x20, count: 32),
            providerGenesisDigest: Data(repeating: 0x10, count: 32),
            signingKey: ownerA.key,
            signedAt: signedAt
        )
        var marker: UInt8 = 180
        func addParticipant(role: GroupRole) throws -> RoleParticipant {
            let nextEpoch = state.epoch + 1
            let user = GroupUser(id: UUID(), role: role, addedEpoch: nextEpoch)
            let admission = try makeAdmission(
                groupId: groupId,
                userId: user.id,
                addedEpoch: nextEpoch,
                issuedAt: state.signedAt
            )
            let commit = try makeCommit(
                operation: .addUser,
                state: state,
                users: state.users + [user],
                leaves: state.clientLeaves + [admission.leaf],
                admissionProjection: admission.projection,
                permissions: state.permissions,
                metadata: state.metadataDigest,
                author: ownerA.leaf.clientHandle,
                key: ownerA.key,
                marker: marker
            )
            state = try SignedGroupStateV2.applying(
                commit,
                to: state,
                signingKey: ownerA.key
            )
            marker &+= 1
            return RoleParticipant(
                user: user,
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
        _ userId: UUID,
        to role: GroupRole,
        in users: [GroupUser]
    ) -> [GroupUser] {
        users.map { user in
            guard user.id == userId else { return user }
            return GroupUser(
                id: user.id,
                role: role,
                addedEpoch: user.addedEpoch,
                removedEpoch: user.removedEpoch
            )
        }
    }

    func makeFixture(memberLeafCount: Int) throws -> Fixture {
        precondition(memberLeafCount > 0)
        let groupId = UUID()
        let signedAt = Date(timeIntervalSince1970: 10_000)
        let owner = GroupUser(id: UUID(), role: .owner, addedEpoch: 1)
        let ownerKey = try SigningKeyPair.generate()
        let ownerGenesis = try makeAdmission(
            groupId: groupId,
            userId: owner.id,
            addedEpoch: 1,
            issuedAt: signedAt,
            groupSigningKey: ownerKey
        )
        let ownerLeaf = ownerGenesis.packageLeaf
        var state = try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: owner,
            creatorTrust: ownerGenesis.genesisTrust,
            metadataDigest: Data(repeating: 0x20, count: 32),
            providerGenesisDigest: Data(repeating: 0x10, count: 32),
            signingKey: ownerKey,
            signedAt: signedAt
        )
        let memberId = UUID()
        var member: GroupUser?
        var memberKeys: [SigningKeyPair] = []
        var memberLeaves: [GroupClientLeafV2] = []
        for index in 0..<memberLeafCount {
            let nextEpoch = state.epoch + 1
            let admission = try makeAdmission(
                groupId: groupId,
                userId: memberId,
                addedEpoch: nextEpoch,
                issuedAt: state.signedAt
            )
            let operation: SignedGroupCommitOperationV2
            let proposedUsers: [GroupUser]
            if index == 0 {
                let addedUser = GroupUser(
                    id: memberId,
                    role: .member,
                    addedEpoch: nextEpoch
                )
                member = addedUser
                operation = .addUser
                proposedUsers = state.users + [addedUser]
            } else {
                operation = .addClient
                proposedUsers = state.users
            }
            let siblingConsent = index == 0 ? nil : try GroupSiblingClientConsentV2.create(
                projection: admission.projection,
                currentState: state,
                consentingClientHandle: memberLeaves[0].clientHandle,
                signingKey: memberKeys[0],
                signedAt: state.signedAt.addingTimeInterval(0.5)
            )
            let commit = try makeCommit(
                operation: operation,
                state: state,
                users: proposedUsers,
                leaves: state.clientLeaves + [admission.leaf],
                admissionProjection: admission.projection,
                siblingClientConsent: siblingConsent,
                permissions: state.permissions,
                metadata: state.metadataDigest,
                author: ownerLeaf.clientHandle,
                key: ownerKey,
                marker: UInt8(200 + index)
            )
            state = try SignedGroupStateV2.applying(
                commit,
                to: state,
                signingKey: ownerKey
            )
            memberKeys.append(admission.groupSigningKey)
            memberLeaves.append(admission.leaf)
        }
        return Fixture(
            state: state,
            ownerUser: owner,
            memberUser: try XCTUnwrap(member),
            ownerLeaf: ownerLeaf,
            memberLeaves: memberLeaves,
            ownerKey: ownerKey,
            memberKeys: memberKeys
        )
    }

    func leaf(
        userId: UUID,
        marker: UInt8,
        signingKey: SigningKeyPair,
        epoch: UInt64
    ) throws -> GroupClientLeafV2 {
        GroupClientLeafV2(
            userId: userId,
            clientHandle: GroupScopedClientHandleV2(
                rawValue: Data(repeating: marker, count: 32).base64EncodedString()
            ),
            keyPackageDigest: Data(repeating: marker &+ 80, count: 32),
            signingPublicKey: signingKey.publicKeyData,
            agreementPublicKey: try AgreementKeyPair.generate().publicKeyData,
            addedEpoch: epoch
        )
    }

    func makeAdmission(
        groupId: UUID,
        userId: UUID,
        addedEpoch: UInt64,
        issuedAt: Date,
        expiresAt: Date? = nil,
        clientHandle: GroupScopedClientHandleV2? = nil,
        groupSigningKey requestedGroupSigningKey: SigningKeyPair? = nil
    ) throws -> Admission {
        let identityGenerationId = UUID()
        let identity = try Identity.generate(displayName: "Admitted user")
        let installation = try LocalInstallationState.generate(
            identityGenerationId: identityGenerationId,
            createdAt: issuedAt.addingTimeInterval(-20)
        )
        let manifest = try InstallationManifest.create(
            identityGenerationId: identityGenerationId,
            epoch: 0,
            installations: [installation.publicRecord(addedEpoch: 0)],
            identity: identity,
            issuedAt: issuedAt.addingTimeInterval(-10)
        )
        let groupSigningKey = try requestedGroupSigningKey ?? SigningKeyPair.generate()
        let groupAgreementKey = try AgreementKeyPair.generate()
        let resolvedClientHandle = clientHandle ?? .generate()
        let package = try GroupClientKeyPackageV2.create(
            groupId: groupId,
            groupUserId: userId,
            clientHandle: resolvedClientHandle,
            identity: identity,
            installation: installation,
            manifest: manifest,
            groupSigningKey: groupSigningKey,
            groupAgreementKey: groupAgreementKey,
            issuedAt: issuedAt,
            expiresAt: expiresAt ?? issuedAt.addingTimeInterval(3_600)
        )
        let projection = try GroupClientAdmissionProjectionV2.create(
            groupId: groupId,
            groupUserId: userId,
            clientHandle: resolvedClientHandle,
            groupSigningKey: groupSigningKey,
            groupAgreementKey: groupAgreementKey,
            issuedAt: issuedAt,
            expiresAt: expiresAt ?? issuedAt.addingTimeInterval(3_600)
        )
        return Admission(
            identity: identity,
            installation: installation,
            manifest: manifest,
            package: package,
            projection: projection,
            packageLeaf: try GroupClientLeafV2.fromVerifiedPackage(
                package,
                addedEpoch: addedEpoch
            ),
            leaf: try GroupClientLeafV2.fromVerifiedProjection(
                projection,
                addedEpoch: addedEpoch
            ),
            trust: GroupClientAdmissionTrustV2(
                groupUserId: userId,
                identityPublicKey: identity.signingKey.publicKeyData,
                currentManifest: manifest
            ),
            groupSigningKey: groupSigningKey
        )
    }

    func makeCommit(
        operation: SignedGroupCommitOperationV2,
        state: SignedGroupStateV2,
        users: [GroupUser],
        leaves: [GroupClientLeafV2],
        admissionProjection: GroupClientAdmissionProjectionV2? = nil,
        siblingClientConsent: GroupSiblingClientConsentV2? = nil,
        permissions: GroupPermissionPolicy,
        metadata: Data?,
        author: GroupScopedClientHandleV2,
        key: SigningKeyPair,
        marker: UInt8
    ) throws -> SignedGroupCommitV2 {
        return try SignedGroupCommitV2.create(
            operation: operation,
            currentState: state,
            proposedUsers: users,
            proposedClientLeaves: leaves,
            admissionProjection: admissionProjection,
            siblingClientConsent: siblingClientConsent,
            proposedPermissions: permissions,
            proposedMetadataDigest: metadata,
            authorClientHandle: author,
            providerCommitDigest: Data(repeating: marker, count: 32),
            idempotencyKey: Data(repeating: marker &+ 100, count: 32),
            signingKey: key,
            createdAt: state.signedAt.addingTimeInterval(1)
        )
    }

    func removed(_ leaf: GroupClientLeafV2, at epoch: UInt64) -> GroupClientLeafV2 {
        GroupClientLeafV2(
            userId: leaf.userId,
            clientHandle: leaf.clientHandle,
            keyPackageDigest: leaf.keyPackageDigest,
            signingPublicKey: leaf.signingPublicKey,
            agreementPublicKey: leaf.agreementPublicKey,
            addedEpoch: leaf.addedEpoch,
            removedEpoch: epoch
        )
    }

    func replaceLeaf(_ leaves: inout [GroupClientLeafV2], _ replacement: GroupClientLeafV2) {
        let index = leaves.firstIndex { $0.clientHandle == replacement.clientHandle }!
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
        _ package: GroupClientKeyPackageV2,
        groupId: UUID? = nil,
        groupUserId: UUID? = nil,
        clientHandle: GroupScopedClientHandleV2? = nil,
        authoritySignature: Data? = nil,
        installationSignature: Data? = nil,
        clientSignature: Data? = nil
    ) -> GroupClientKeyPackageV2 {
        GroupClientKeyPackageV2(
            id: package.id,
            groupId: groupId ?? package.groupId,
            groupUserId: groupUserId ?? package.groupUserId,
            clientHandle: clientHandle ?? package.clientHandle,
            identityGenerationId: package.identityGenerationId,
            manifestEpoch: package.manifestEpoch,
            manifestDigest: package.manifestDigest,
            installationId: package.installationId,
            installationSigningPublicKey: package.installationSigningPublicKey,
            installationAgreementPublicKey: package.installationAgreementPublicKey,
            groupSigningPublicKey: package.groupSigningPublicKey,
            groupAgreementPublicKey: package.groupAgreementPublicKey,
            capabilities: package.capabilities,
            issuedAt: package.issuedAt,
            expiresAt: package.expiresAt,
            authoritySignature: authoritySignature ?? package.authoritySignature,
            installationPossessionSignature:
                installationSignature ?? package.installationPossessionSignature,
            groupClientPossessionSignature:
                clientSignature ?? package.groupClientPossessionSignature
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
            proposedUsers: commit.proposedUsers,
            proposedClientLeaves: commit.proposedClientLeaves,
            admissionProjection: commit.admissionProjection,
            siblingClientConsent: commit.siblingClientConsent,
            proposedPermissions: commit.proposedPermissions,
            proposedMetadataDigest: metadata,
            authorClientHandle: commit.authorClientHandle,
            providerCommitDigest: commit.providerCommitDigest,
            idempotencyKey: commit.idempotencyKey,
            createdAt: commit.createdAt,
            signature: commit.signature
        )
    }

    func copy(
        _ commit: SignedGroupCommitV2,
        admissionProjection: GroupClientAdmissionProjectionV2?
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
            proposedUsers: commit.proposedUsers,
            proposedClientLeaves: commit.proposedClientLeaves,
            admissionProjection: admissionProjection,
            siblingClientConsent: commit.siblingClientConsent,
            proposedPermissions: commit.proposedPermissions,
            proposedMetadataDigest: commit.proposedMetadataDigest,
            authorClientHandle: commit.authorClientHandle,
            providerCommitDigest: commit.providerCommitDigest,
            idempotencyKey: commit.idempotencyKey,
            createdAt: commit.createdAt,
            signature: commit.signature
        )
    }

    func copy(_ state: SignedGroupStateV2, users: [GroupUser]) -> SignedGroupStateV2 {
        SignedGroupStateV2(
            profile: state.profile,
            cipherSuite: state.cipherSuite,
            groupId: state.groupId,
            epoch: state.epoch,
            previousTranscriptHash: state.previousTranscriptHash,
            users: users,
            clientLeaves: state.clientLeaves,
            permissions: state.permissions,
            metadataDigest: state.metadataDigest,
            authorClientHandle: state.authorClientHandle,
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
            authorClientHandle: welcome.authorClientHandle,
            destinationClientHandle: welcome.destinationClientHandle,
            destinationKeyPackageDigest: welcome.destinationKeyPackageDigest,
            encryptedWelcome: encryptedWelcome,
            createdAt: welcome.createdAt,
            expiresAt: welcome.expiresAt,
            signature: welcome.signature
        )
    }
}
