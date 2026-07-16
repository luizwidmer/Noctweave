import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class GroupInvitationParityTests: XCTestCase {
    func testInvitationsRemainSeparateFromMembershipAndAcceptIntoScopedProfile() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil)
        let creatorFingerprint = "creator-fingerprint"
        let invitedFingerprint = "invitee-identity-fingerprint"
        let scopedFingerprint = "invitee-group-scoped-fingerprint"

        let created = try store.createGroup(
            title: "Private group",
            creatorFingerprint: creatorFingerprint,
            memberFingerprints: [],
            invitedFingerprints: ["  \(invitedFingerprint)  ", invitedFingerprint]
        )

        XCTAssertEqual(created.members.map(\.fingerprint), [creatorFingerprint])
        XCTAssertTrue(store.listGroups(memberFingerprint: invitedFingerprint, limit: nil).isEmpty)
        let invitations = store.listGroupInvitations(
            ListGroupInvitationsRequest(invitedFingerprint: invitedFingerprint)
        )
        XCTAssertEqual(invitations.count, 1)
        XCTAssertEqual(invitations.first?.groupId, created.id)
        XCTAssertEqual(invitations.first?.invitedFingerprint, invitedFingerprint)
        XCTAssertTrue(
            store.listGroupInvitations(
                ListGroupInvitationsRequest(invitedFingerprint: "different-identity")
            ).isEmpty
        )

        XCTAssertThrowsError(
            try store.inviteGroupMembers(
                InviteGroupMembersRequest(
                    groupId: created.id,
                    actorFingerprint: "not-the-creator",
                    invitedFingerprints: ["another-invitee"]
                )
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .unauthorizedGroupMutation)
        }

        let requester = RelayGroupMemberProfile(
            fingerprint: scopedFingerprint,
            displayName: "Scoped invitee",
            inboxId: nil,
            relay: nil,
            signingPublicKey: Data([0x01]),
            agreementPublicKey: Data([0x02])
        )
        let commit = SignedGroupCommit(
            operation: .joinApprove,
            groupId: created.id,
            actorFingerprint: scopedFingerprint,
            baseEpoch: created.epoch,
            previousTranscriptHash: created.mlsEpochState.confirmedTranscriptHash,
            addMemberFingerprints: [scopedFingerprint],
            addMemberProfiles: [requester],
            ratchetSecretDistribution: nil,
            actorProof: nil
        )
        let accepted = try store.acceptGroupInvitation(
            RequestGroupJoinRequest(
                groupId: created.id,
                requesterProfile: requester,
                invitedFingerprint: invitedFingerprint,
                groupCommit: commit
            )
        )

        XCTAssertTrue(accepted.members.contains(where: { $0.fingerprint == scopedFingerprint }))
        XCTAssertFalse(accepted.members.contains(where: { $0.fingerprint == invitedFingerprint }))
        XCTAssertTrue(
            store.listGroupInvitations(
                ListGroupInvitationsRequest(invitedFingerprint: invitedFingerprint)
            ).isEmpty
        )
    }

    func testInvitationsPersistAndAreRemovedWithDeletedGroup() throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let storeURL = tempDirectory.appendingPathComponent("relay-store.sqlite")
        let creatorFingerprint = "creator-fingerprint"
        let invitedFingerprint = "invitee-fingerprint"
        let firstStore = RelayStore(fileURL: storeURL, maxInboxMessages: nil)
        let created = try firstStore.createGroup(
            title: "Persistent invitation",
            creatorFingerprint: creatorFingerprint,
            memberFingerprints: [],
            invitedFingerprints: [invitedFingerprint]
        )

        let reloadedStore = RelayStore(fileURL: storeURL, maxInboxMessages: nil)
        try reloadedStore.load()
        XCTAssertEqual(
            reloadedStore.listGroupInvitations(
                ListGroupInvitationsRequest(invitedFingerprint: invitedFingerprint)
            ).map(\.groupId),
            [created.id]
        )

        try reloadedStore.deleteGroup(
            DeleteGroupRequest(groupId: created.id, actorFingerprint: creatorFingerprint)
        )
        let postDeleteStore = RelayStore(fileURL: storeURL, maxInboxMessages: nil)
        try postDeleteStore.load()
        XCTAssertTrue(
            postDeleteStore.listGroupInvitations(
                ListGroupInvitationsRequest(invitedFingerprint: invitedFingerprint)
            ).isEmpty
        )
    }

    func testInvitationRequestAndResponseWireFieldsRoundTrip() throws {
        let invitationRequest = RelayRequest.inviteGroupMembers(
            InviteGroupMembersRequest(
                groupId: UUID(),
                actorFingerprint: "creator-fingerprint",
                invitedFingerprints: ["invitee-b", "invitee-a"]
            )
        )
        let decodedRequest = try RelayCodec.decoder().decode(
            RelayRequest.self,
            from: RelayCodec.encoder(sortedKeys: true).encode(invitationRequest)
        )
        XCTAssertEqual(decodedRequest.type, .inviteGroupMembers)
        XCTAssertEqual(decodedRequest.inviteGroupMembers?.invitedFingerprints, ["invitee-b", "invitee-a"])

        let now = Date()
        let invitation = RelayGroupInvitation(
            groupId: UUID(),
            title: "Wire invitation",
            createdByFingerprint: "creator-fingerprint",
            invitedFingerprint: "invitee-fingerprint",
            inboxId: "group-inbox",
            epoch: 3,
            createdAt: now,
            updatedAt: now,
            invitedAt: now
        )
        let response = RelayResponse.groupInvitations([invitation])
        let decodedResponse = try RelayCodec.decoder().decode(
            RelayResponse.self,
            from: RelayCodec.encoder(sortedKeys: true).encode(response)
        )
        XCTAssertEqual(decodedResponse.type, .groupInvitations)
        XCTAssertEqual(decodedResponse.groupInvitations?.map(\.id), [invitation.id])
        XCTAssertEqual(decodedResponse.groupInvitations?.map(\.groupId), [invitation.groupId])
        XCTAssertEqual(decodedResponse.groupInvitations?.map(\.invitedFingerprint), [invitation.invitedFingerprint])
    }

    func testInvitationListingRouteRequiresInviteeProof() throws {
        let harness = try RelayTCPHarness()
        defer { try? harness.shutdown() }

        let response = try harness.send(
            .listGroupInvitations(
                ListGroupInvitationsRequest(invitedFingerprint: "invitee-fingerprint")
            )
        )

        XCTAssertEqual(response.type, .error)
        XCTAssertEqual(response.error, "Missing actor proof.")
    }
}
