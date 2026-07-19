import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2GroupBoundaryTests: XCTestCase {
    func testAdmissionProjectionCommitsOnlyGroupScopedMaterial() throws {
        let fixture = try makeGenesis()
        let newMember = GroupMemberV2(
            id: .generate(),
            role: .member,
            addedEpoch: fixture.state.epoch + 1
        )
        let newClientKey = try SigningKeyPair.generate()
        let projection = try GroupCredentialAdmissionV2.create(
            groupId: fixture.state.groupId,
            memberHandle: newMember.id,
            groupSigningKey: newClientKey,
            groupAgreementKey: try AgreementKeyPair.generate(),
            issuedAt: fixture.state.signedAt,
            expiresAt: fixture.state.signedAt.addingTimeInterval(3_600)
        )
        let newLeaf = try GroupMemberCredentialV2.fromVerifiedProjection(
            projection,
            addedEpoch: fixture.state.epoch + 1
        )
        let commit = try SignedGroupCommitV2.create(
            operation: .addMember,
            currentState: fixture.state,
            proposedMembers: fixture.state.members + [newMember],
            proposedCredentials: fixture.state.memberCredentials + [newLeaf],
            admissionProjection: projection,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: fixture.state.metadataDigest,
            authorCredentialHandle: fixture.ownerLeaf.credentialHandle,
            providerCommitDigest: bytes(0x31),
            idempotencyKey: bytes(0x32),
            signingKey: fixture.ownerKey,
            createdAt: fixture.state.signedAt.addingTimeInterval(1)
        )

        let encoded = try NoctweaveCoder.encode(commit, sortedKeys: true)
        let serialized = try XCTUnwrap(String(data: encoded, encoding: .utf8)).lowercased()
        XCTAssertNotNil(commit.admissionProjection)
        XCTAssertFalse(serialized.contains("identity"))
        XCTAssertFalse(serialized.contains("endpoint"))
        XCTAssertFalse(serialized.contains("manifest"))
        XCTAssertFalse(serialized.contains("relationship"))
        XCTAssertFalse(serialized.contains("inbox"))
        XCTAssertFalse(serialized.contains("route"))
        XCTAssertFalse(serialized.contains("\"capabilities\""))
    }


    func testDeletionTombstoneIsTerminalAndRejectsResurrection() throws {
        let fixture = try makeGenesis()
        let tombstone = try SignedGroupDeletionTombstoneV2.create(
            currentState: fixture.state,
            authorCredentialHandle: fixture.ownerLeaf.credentialHandle,
            reasonDigest: bytes(0x41),
            idempotencyKey: bytes(0x42),
            signingKey: fixture.ownerKey,
            createdAt: fixture.state.signedAt.addingTimeInterval(1)
        )
        let deleted = try SignedDeletedGroupStateV2.create(
            tombstone: tombstone,
            from: fixture.state,
            observedAt: tombstone.createdAt
        )
        XCTAssertTrue(deleted.isStructurallyValid)
        XCTAssertEqual(tombstone.operation, .deleteGroup)

        XCTAssertThrowsError(try deleted.rejectResurrection(fixture.state)) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .groupDeleted)
        }
        let ordinaryCommit = try SignedGroupCommitV2.create(
            operation: .updateMetadata,
            currentState: fixture.state,
            proposedMembers: fixture.state.members,
            proposedCredentials: fixture.state.memberCredentials,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: bytes(0x43),
            authorCredentialHandle: fixture.ownerLeaf.credentialHandle,
            providerCommitDigest: bytes(0x44),
            idempotencyKey: bytes(0x45),
            signingKey: fixture.ownerKey,
            createdAt: fixture.state.signedAt.addingTimeInterval(1)
        )
        XCTAssertThrowsError(try deleted.applying(ordinaryCommit)) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .groupDeleted)
        }
    }

    func testNegotiationRequiresExactImplementedProfileAndCipherSuite() throws {
        XCTAssertEqual(
            try GroupProtocolNegotiationV2.negotiate(
                local: .currentExperimental,
                peer: .currentExperimental
            ),
            .currentExperimental
        )

        let wrongSuite = GroupProtocolOfferV2(suites: [
            GroupProtocolSuiteOfferV2(
                profile: .noctweavePQExperimentalV2,
                cipherSuite: NoctweaveSignedGroupV2.experimentalCipherSuite + "-different"
            )
        ])
        XCTAssertThrowsError(try GroupProtocolNegotiationV2.negotiate(
            local: .currentExperimental,
            peer: wrongSuite
        )) { error in
            XCTAssertEqual(error as? GroupProtocolNegotiationErrorV2, .noSharedProfile)
        }
        XCTAssertThrowsError(try GroupProtocolNegotiationV2.negotiate(
            local: .currentExperimental,
            peer: wrongSuite,
            required: .currentExperimental
        )) { error in
            XCTAssertEqual(error as? GroupProtocolNegotiationErrorV2, .downgradeRejected)
        }

        let unimplementedReservedProfile = GroupProtocolOfferV2(suites: [
            GroupProtocolSuiteOfferV2(
                profile: .mlsRFC9420V1,
                cipherSuite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
            )
        ])
        XCTAssertThrowsError(try GroupProtocolNegotiationV2.negotiate(
            local: unimplementedReservedProfile,
            peer: unimplementedReservedProfile
        )) { error in
            XCTAssertEqual(error as? GroupProtocolNegotiationErrorV2, .noSharedProfile)
        }
    }

    func testMemberHasOneCredentialAndReplacementMustBeSelfSignedCommit() throws {
        let fixture = try makeGenesis()
        let member = GroupMemberV2(
            id: .generate(),
            role: .member,
            addedEpoch: fixture.state.epoch + 1
        )
        let memberKey = try SigningKeyPair.generate()
        let memberProjection = try GroupCredentialAdmissionV2.create(
            groupId: fixture.state.groupId,
            memberHandle: member.id,
            groupSigningKey: memberKey,
            groupAgreementKey: try AgreementKeyPair.generate(),
            issuedAt: fixture.state.signedAt,
            expiresAt: fixture.state.signedAt.addingTimeInterval(3_600)
        )
        let memberLeaf = try GroupMemberCredentialV2.fromVerifiedProjection(
            memberProjection,
            addedEpoch: fixture.state.epoch + 1
        )
        let addMember = try SignedGroupCommitV2.create(
            operation: .addMember,
            currentState: fixture.state,
            proposedMembers: fixture.state.members + [member],
            proposedCredentials: fixture.state.memberCredentials + [memberLeaf],
            admissionProjection: memberProjection,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: fixture.state.metadataDigest,
            authorCredentialHandle: fixture.ownerLeaf.credentialHandle,
            providerCommitDigest: bytes(0x51),
            idempotencyKey: bytes(0x52),
            signingKey: fixture.ownerKey,
            createdAt: fixture.state.signedAt.addingTimeInterval(1)
        )
        let stateWithMember = try SignedGroupStateV2.applying(
            addMember,
            to: fixture.state,
            observedAt: addMember.createdAt,
            signingKey: fixture.ownerKey
        )

        let replacementKey = try SigningKeyPair.generate()
        let replacementProjection = try GroupCredentialAdmissionV2.create(
            groupId: stateWithMember.groupId,
            memberHandle: member.id,
            groupSigningKey: replacementKey,
            groupAgreementKey: try AgreementKeyPair.generate(),
            issuedAt: stateWithMember.signedAt,
            expiresAt: stateWithMember.signedAt.addingTimeInterval(3_600)
        )
        let replacementLeaf = try GroupMemberCredentialV2.fromVerifiedProjection(
            replacementProjection,
            addedEpoch: stateWithMember.epoch + 1
        )
        let parallelLeaves = stateWithMember.memberCredentials + [replacementLeaf]

        XCTAssertThrowsError(try SignedGroupCommitV2.create(
            operation: .replaceCredential,
            currentState: stateWithMember,
            proposedMembers: stateWithMember.members,
            proposedCredentials: parallelLeaves,
            admissionProjection: replacementProjection,
            proposedPermissions: stateWithMember.permissions,
            proposedMetadataDigest: stateWithMember.metadataDigest,
            authorCredentialHandle: fixture.ownerLeaf.credentialHandle,
            providerCommitDigest: bytes(0x53),
            idempotencyKey: bytes(0x54),
            signingKey: fixture.ownerKey,
            createdAt: stateWithMember.signedAt.addingTimeInterval(1)
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .invalidStructure)
        }

        let retiredMemberCredential = GroupMemberCredentialV2(
            memberHandle: memberLeaf.memberHandle,
            credentialHandle: memberLeaf.credentialHandle,
            admissionDigest: memberLeaf.admissionDigest,
            signingPublicKey: memberLeaf.signingPublicKey,
            agreementPublicKey: memberLeaf.agreementPublicKey,
            addedEpoch: memberLeaf.addedEpoch,
            removedEpoch: stateWithMember.epoch + 1
        )
        var replacementLeaves = stateWithMember.memberCredentials
        replacementLeaves[try XCTUnwrap(replacementLeaves.firstIndex {
            $0.credentialHandle == memberLeaf.credentialHandle
        })] = retiredMemberCredential
        replacementLeaves.append(replacementLeaf)
        let replaceCredential = try SignedGroupCommitV2.create(
            operation: .replaceCredential,
            currentState: stateWithMember,
            proposedMembers: stateWithMember.members,
            proposedCredentials: replacementLeaves,
            admissionProjection: replacementProjection,
            proposedPermissions: stateWithMember.permissions,
            proposedMetadataDigest: stateWithMember.metadataDigest,
            authorCredentialHandle: memberLeaf.credentialHandle,
            providerCommitDigest: bytes(0x55),
            idempotencyKey: bytes(0x56),
            signingKey: memberKey,
            createdAt: stateWithMember.signedAt.addingTimeInterval(1)
        )
        let next = try SignedGroupStateV2.applying(
            replaceCredential,
            to: stateWithMember,
            observedAt: replaceCredential.createdAt,
            signingKey: memberKey
        )
        XCTAssertEqual(next.activeCredentials.filter { $0.memberHandle == member.id }, [replacementLeaf])
        XCTAssertFalse(try XCTUnwrap(next.memberCredentials.first {
            $0.credentialHandle == memberLeaf.credentialHandle
        }).isActive(at: next.epoch))
    }
}

private extension ArchitectureV2GroupBoundaryTests {
    struct GenesisFixture {
        let state: SignedGroupStateV2
        let ownerLeaf: GroupMemberCredentialV2
        let ownerKey: SigningKeyPair
    }

    func makeGenesis() throws -> GenesisFixture {
        let groupId = UUID()
        let signedAt = Date(timeIntervalSince1970: 10_000)
        let owner = GroupMemberV2(id: .generate(), role: .owner, addedEpoch: 1)
        let ownerKey = try SigningKeyPair.generate()
        let admission = try GroupCredentialAdmissionV2.create(
            groupId: groupId,
            memberHandle: owner.id,
            groupSigningKey: ownerKey,
            groupAgreementKey: try AgreementKeyPair.generate(),
            issuedAt: signedAt,
            expiresAt: signedAt.addingTimeInterval(3_600)
        )
        let state = try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: owner,
            creatorAdmission: admission,
            metadataDigest: bytes(0x21),
            providerGenesisDigest: bytes(0x22),
            signingKey: ownerKey,
            signedAt: signedAt
        )
        return GenesisFixture(
            state: state,
            ownerLeaf: try XCTUnwrap(state.memberCredentials.first),
            ownerKey: ownerKey
        )
    }

    func bytes(_ marker: UInt8) -> Data {
        Data(repeating: marker, count: 32)
    }
}
