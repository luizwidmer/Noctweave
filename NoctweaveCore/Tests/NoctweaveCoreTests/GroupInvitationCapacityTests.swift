import Foundation
import XCTest
@testable import NoctweaveCore

final class GroupInvitationCapacityTests: XCTestCase {
    func testCumulativeInvitationsAreBoundedIdempotentAndCapacityTracksMembership() async throws {
        let store = RelayStore()
        let creator = "creator"
        let permanentMember = "member"
        var group = try await store.createGroup(
            title: "Bounded invitations",
            creatorFingerprint: creator,
            memberFingerprints: [permanentMember]
        )
        let firstBatch = (0..<100).map { "invite-\($0)" }
        group = try await store.inviteGroupMembers(
            InviteGroupMembersRequest(
                groupId: group.id,
                actorFingerprint: creator,
                invitedFingerprints: firstBatch
            )
        )
        let originalInvitations = await store.listGroupInvitations(
            ListGroupInvitationsRequest(invitedFingerprint: firstBatch[0])
        )
        let originalInvitation = try XCTUnwrap(originalInvitations.first)

        let secondBatch = firstBatch + (100..<254).map { "invite-\($0)" }
        group = try await store.inviteGroupMembers(
            InviteGroupMembersRequest(
                groupId: group.id,
                actorFingerprint: creator,
                invitedFingerprints: secondBatch
            )
        )
        let retainedInvitations = await store.listGroupInvitations(
            ListGroupInvitationsRequest(invitedFingerprint: firstBatch[0])
        )
        let retainedInvitation = try XCTUnwrap(retainedInvitations.first)
        XCTAssertEqual(retainedInvitation.id, originalInvitation.id)
        XCTAssertEqual(retainedInvitation.invitedAt, originalInvitation.invitedAt)

        let idempotent = try await store.inviteGroupMembers(
            InviteGroupMembersRequest(
                groupId: group.id,
                actorFingerprint: creator,
                invitedFingerprints: Array(secondBatch.reversed())
            )
        )
        XCTAssertEqual(idempotent, group)

        await assertCapacityExceeded {
            _ = try await store.inviteGroupMembers(
                InviteGroupMembersRequest(
                    groupId: group.id,
                    actorFingerprint: creator,
                    invitedFingerprints: ["overflow"]
                )
            )
        }
        let afterRejectedInvite = await store.fetchGroup(groupId: group.id)
        XCTAssertEqual(afterRejectedInvite, group)
        let overflowInvitations = await store.listGroupInvitations(
            ListGroupInvitationsRequest(invitedFingerprint: "overflow")
        )
        XCTAssertTrue(overflowInvitations.isEmpty)

        let scopedInvitee = RelayGroupMemberProfile(
            fingerprint: "scoped-invitee",
            displayName: nil,
            inboxId: nil,
            relay: nil,
            signingPublicKey: Data([0x01]),
            agreementPublicKey: Data([0x02])
        )
        let accepted = try await store.acceptGroupInvitation(
            RequestGroupJoinRequest(
                groupId: group.id,
                requesterProfile: scopedInvitee,
                invitedFingerprint: firstBatch[0],
                groupCommit: SignedGroupCommit(
                    operation: .joinApprove,
                    groupId: group.id,
                    actorFingerprint: scopedInvitee.fingerprint,
                    baseEpoch: group.epoch,
                    previousTranscriptHash: group.mlsEpochState.confirmedTranscriptHash,
                    addMemberFingerprints: [scopedInvitee.fingerprint],
                    addMemberProfiles: [scopedInvitee]
                )
            )
        )
        let consumedInvitations = await store.listGroupInvitations(
            ListGroupInvitationsRequest(invitedFingerprint: firstBatch[0])
        )
        XCTAssertTrue(consumedInvitations.isEmpty)
        await assertCapacityExceeded {
            _ = try await store.inviteGroupMembers(
                InviteGroupMembersRequest(
                    groupId: group.id,
                    actorFingerprint: creator,
                    invitedFingerprints: ["overflow"]
                )
            )
        }

        let removed = try await store.updateGroup(
            UpdateGroupRequest(
                groupId: group.id,
                actorFingerprint: creator,
                removeMemberFingerprints: [scopedInvitee.fingerprint],
                groupCommit: SignedGroupCommit(
                    operation: .removeMembers,
                    groupId: group.id,
                    actorFingerprint: creator,
                    baseEpoch: accepted.epoch,
                    previousTranscriptHash: accepted.mlsEpochState.confirmedTranscriptHash,
                    removeMemberFingerprints: [scopedInvitee.fingerprint]
                )
            )
        )
        XCTAssertFalse(removed.members.contains { $0.fingerprint == scopedInvitee.fingerprint })
        _ = try await store.inviteGroupMembers(
            InviteGroupMembersRequest(
                groupId: group.id,
                actorFingerprint: creator,
                invitedFingerprints: ["overflow"]
            )
        )
    }

    func testCreateAndReloadPreserveTheCombinedParticipantBound() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("relay.sqlite")
        let groupId = UUID()
        let store = RelayStore(storeURL: storeURL)

        await assertCapacityExceeded {
            _ = try await store.createGroup(
                groupId: groupId,
                title: "Too many",
                creatorFingerprint: "creator",
                memberFingerprints: ["member"],
                invitedFingerprints: (0..<255).map { "invite-\($0)" }
            )
        }
        let rejectedGroup = await store.fetchGroup(groupId: groupId)
        XCTAssertNil(rejectedGroup)

        let created = try await store.createGroup(
            groupId: groupId,
            title: "At capacity",
            creatorFingerprint: "creator",
            memberFingerprints: ["member"],
            invitedFingerprints: (0..<254).map { "invite-\($0)" }
        )
        let reloaded = RelayStore(storeURL: storeURL)
        try await reloaded.loadFromDisk()
        let reloadedGroup = await reloaded.fetchGroup(groupId: groupId)
        XCTAssertEqual(reloadedGroup?.id, created.id)
        await assertCapacityExceeded {
            _ = try await reloaded.inviteGroupMembers(
                InviteGroupMembersRequest(
                    groupId: groupId,
                    actorFingerprint: "creator",
                    invitedFingerprints: ["overflow"]
                )
            )
        }
    }

    func testPerIdentityInvitationBucketRejectsWithoutEvictionAndDeleteFreesCapacity() async throws {
        let store = RelayStore()
        var firstGroup: RelayGroupDescriptor?
        for index in 0..<256 {
            let group = try await store.createGroup(
                title: "Group \(index)",
                creatorFingerprint: "creator-\(index)",
                memberFingerprints: [],
                invitedFingerprints: ["same-invitee"]
            )
            firstGroup = firstGroup ?? group
        }
        let rejectedGroupId = UUID()
        await assertCapacityExceeded {
            _ = try await store.createGroup(
                groupId: rejectedGroupId,
                title: "Rejected",
                creatorFingerprint: "creator-overflow",
                memberFingerprints: [],
                invitedFingerprints: ["same-invitee"]
            )
        }
        let rejectedGroup = await store.fetchGroup(groupId: rejectedGroupId)
        XCTAssertNil(rejectedGroup)
        let retainedInvitations = await store.listGroupInvitations(
            ListGroupInvitationsRequest(invitedFingerprint: "same-invitee")
        )
        XCTAssertEqual(retainedInvitations.count, 256)

        let removable = try XCTUnwrap(firstGroup)
        try await store.deleteGroup(
            DeleteGroupRequest(groupId: removable.id, actorFingerprint: removable.createdByFingerprint)
        )
        _ = try await store.createGroup(
            groupId: rejectedGroupId,
            title: "Accepted after delete",
            creatorFingerprint: "creator-overflow",
            memberFingerprints: [],
            invitedFingerprints: ["same-invitee"]
        )
    }

    private func assertCapacityExceeded(
        _ operation: () async throws -> Void,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            try await operation()
            XCTFail("Expected group capacity rejection", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? RelayStoreError, .groupCapacityExceeded, file: file, line: line)
        }
    }
}
