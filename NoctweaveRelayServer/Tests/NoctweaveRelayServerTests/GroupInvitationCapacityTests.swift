import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class GroupInvitationCapacityTests: XCTestCase {
    func testCumulativeInvitationsAreBoundedIdempotentAndCapacityTracksMembership() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil)
        let creator = "creator"
        var group = try store.createGroup(
            title: "Bounded invitations",
            creatorFingerprint: creator,
            memberFingerprints: ["member"]
        )
        let firstBatch = (0..<100).map { "invite-\($0)" }
        group = try store.inviteGroupMembers(
            InviteGroupMembersRequest(
                groupId: group.id,
                actorFingerprint: creator,
                invitedFingerprints: firstBatch
            )
        )
        let originalInvitation = try XCTUnwrap(
            store.listGroupInvitations(
                ListGroupInvitationsRequest(invitedFingerprint: firstBatch[0])
            ).first
        )

        let secondBatch = firstBatch + (100..<254).map { "invite-\($0)" }
        group = try store.inviteGroupMembers(
            InviteGroupMembersRequest(
                groupId: group.id,
                actorFingerprint: creator,
                invitedFingerprints: secondBatch
            )
        )
        let retainedInvitation = try XCTUnwrap(
            store.listGroupInvitations(
                ListGroupInvitationsRequest(invitedFingerprint: firstBatch[0])
            ).first
        )
        XCTAssertEqual(retainedInvitation.id, originalInvitation.id)
        XCTAssertEqual(retainedInvitation.invitedAt, originalInvitation.invitedAt)
        XCTAssertEqual(
            try store.inviteGroupMembers(
                InviteGroupMembersRequest(
                    groupId: group.id,
                    actorFingerprint: creator,
                    invitedFingerprints: Array(secondBatch.reversed())
                )
            ),
            group
        )
        assertCapacityExceeded {
            _ = try store.inviteGroupMembers(
                InviteGroupMembersRequest(
                    groupId: group.id,
                    actorFingerprint: creator,
                    invitedFingerprints: ["overflow"]
                )
            )
        }
        XCTAssertEqual(store.fetchGroup(groupId: group.id), group)
        XCTAssertTrue(
            store.listGroupInvitations(
                ListGroupInvitationsRequest(invitedFingerprint: "overflow")
            ).isEmpty
        )

        let scopedInvitee = RelayGroupMemberProfile(
            fingerprint: "scoped-invitee",
            displayName: nil,
            inboxId: nil,
            relay: nil,
            signingPublicKey: Data([0x01]),
            agreementPublicKey: Data([0x02])
        )
        let accepted = try store.acceptGroupInvitation(
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
        XCTAssertTrue(
            store.listGroupInvitations(
                ListGroupInvitationsRequest(invitedFingerprint: firstBatch[0])
            ).isEmpty
        )
        assertCapacityExceeded {
            _ = try store.inviteGroupMembers(
                InviteGroupMembersRequest(
                    groupId: group.id,
                    actorFingerprint: creator,
                    invitedFingerprints: ["overflow"]
                )
            )
        }

        let removed = try store.updateGroup(
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
        _ = try store.inviteGroupMembers(
            InviteGroupMembersRequest(
                groupId: group.id,
                actorFingerprint: creator,
                invitedFingerprints: ["overflow"]
            )
        )
    }

    func testCreateAndReloadPreserveTheCombinedParticipantBound() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("relay.sqlite")
        let groupId = UUID()
        let store = RelayStore(fileURL: storeURL, maxInboxMessages: nil)

        assertCapacityExceeded {
            _ = try store.createGroup(
                groupId: groupId,
                title: "Too many",
                creatorFingerprint: "creator",
                memberFingerprints: ["member"],
                invitedFingerprints: (0..<255).map { "invite-\($0)" }
            )
        }
        XCTAssertNil(store.fetchGroup(groupId: groupId))

        let created = try store.createGroup(
            groupId: groupId,
            title: "At capacity",
            creatorFingerprint: "creator",
            memberFingerprints: ["member"],
            invitedFingerprints: (0..<254).map { "invite-\($0)" }
        )
        let reloaded = RelayStore(fileURL: storeURL, maxInboxMessages: nil)
        try reloaded.load()
        XCTAssertEqual(reloaded.fetchGroup(groupId: groupId)?.id, created.id)
        assertCapacityExceeded {
            _ = try reloaded.inviteGroupMembers(
                InviteGroupMembersRequest(
                    groupId: groupId,
                    actorFingerprint: "creator",
                    invitedFingerprints: ["overflow"]
                )
            )
        }
    }

    func testPerIdentityInvitationBucketRejectsWithoutEvictionAndDeleteFreesCapacity() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil)
        var firstGroup: RelayGroupDescriptor?
        for index in 0..<256 {
            let group = try store.createGroup(
                title: "Group \(index)",
                creatorFingerprint: "creator-\(index)",
                memberFingerprints: [],
                invitedFingerprints: ["same-invitee"]
            )
            firstGroup = firstGroup ?? group
        }
        let rejectedGroupId = UUID()
        assertCapacityExceeded {
            _ = try store.createGroup(
                groupId: rejectedGroupId,
                title: "Rejected",
                creatorFingerprint: "creator-overflow",
                memberFingerprints: [],
                invitedFingerprints: ["same-invitee"]
            )
        }
        XCTAssertNil(store.fetchGroup(groupId: rejectedGroupId))
        XCTAssertEqual(
            store.listGroupInvitations(
                ListGroupInvitationsRequest(invitedFingerprint: "same-invitee")
            ).count,
            256
        )

        let removable = try XCTUnwrap(firstGroup)
        try store.deleteGroup(
            DeleteGroupRequest(groupId: removable.id, actorFingerprint: removable.createdByFingerprint)
        )
        _ = try store.createGroup(
            groupId: rejectedGroupId,
            title: "Accepted after delete",
            creatorFingerprint: "creator-overflow",
            memberFingerprints: [],
            invitedFingerprints: ["same-invitee"]
        )
    }

    private func assertCapacityExceeded(
        _ operation: () throws -> Void,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            XCTAssertEqual(error as? RelayStoreError, .groupCapacityExceeded, file: file, line: line)
        }
    }
}
