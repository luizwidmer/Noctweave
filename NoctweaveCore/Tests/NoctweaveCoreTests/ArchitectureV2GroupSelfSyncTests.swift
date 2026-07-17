import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2GroupSelfSyncTests: XCTestCase {
    func testLegacyGroupEngineAdvertisesAnExplicitExperimentalNoctweaveProfile() {
        XCTAssertEqual(MLSGroupEpochState.currentProtocolVersion, "noctweave-pq-group-experimental-2")
        XCTAssertEqual(
            MLSGroupEpochState.currentCipherSuite,
            "Noctweave-PQ-Group-Experimental-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-2"
        )
        XCTAssertFalse(MLSGroupEpochState.currentProtocolVersion.lowercased().contains("mls"))
    }

    func testGroupPermissionPolicyMakesRoleDecisionsExplicit() {
        let policy = GroupPermissionPolicy.default

        XCTAssertTrue(policy.isStructurallyValid)
        XCTAssertTrue(policy.allows(.addClient, for: .admin))
        XCTAssertTrue(policy.allows(.removeClient, for: .owner))
        XCTAssertFalse(policy.allows(.removeClient, for: .member))
        XCTAssertFalse(policy.allows(.updatePolicy, for: .admin))
        XCTAssertTrue(policy.allows(.updatePolicy, for: .owner))
    }

    func testRevokingOneGroupClientLeafPreservesSiblingEndpoint() throws {
        let owner = GroupUser(id: UUID(), role: .owner, addedEpoch: 1)
        let member = GroupUser(id: UUID(), role: .member, addedEpoch: 1)
        let ownerLeaf = clientLeaf(userId: owner.id, marker: 1)
        let revokedLeaf = clientLeaf(userId: member.id, marker: 2)
        let siblingLeaf = clientLeaf(userId: member.id, marker: 3)
        let initial = GroupMembershipState(
            id: UUID(),
            profile: .noctweavePQExperimentalV2,
            epoch: 1,
            users: [owner, member],
            clientLeaves: [ownerLeaf, revokedLeaf, siblingLeaf],
            confirmedTranscriptHash: Data(repeating: 10, count: 32)
        )

        XCTAssertTrue(initial.isStructurallyValid)
        let next = try initial.revokingClient(
            revokedLeaf.id,
            authorizedBy: ownerLeaf.id,
            nextEpoch: 2,
            confirmedTranscriptHash: Data(repeating: 11, count: 32)
        )

        XCTAssertEqual(next.epoch, 2)
        XCTAssertFalse(next.activeClientLeaves.contains { $0.id == revokedLeaf.id })
        XCTAssertTrue(next.activeClientLeaves.contains { $0.id == siblingLeaf.id })
        XCTAssertTrue(next.activeUsers.contains { $0.id == member.id })

        XCTAssertThrowsError(
            try initial.revokingClient(
                ownerLeaf.id,
                authorizedBy: ownerLeaf.id,
                nextEpoch: 2,
                confirmedTranscriptHash: Data(repeating: 12, count: 32)
            )
        ) { error in
            XCTAssertEqual(error as? GroupArchitectureError, .wouldRemoveLastOwnerClient)
        }
    }

    private func clientLeaf(userId: UUID, marker: UInt8) -> GroupClientLeaf {
        GroupClientLeaf(
            id: UUID(),
            userId: userId,
            endpointHandle: RelationshipEndpointHandle(
                rawValue: Data(repeating: marker, count: 32).base64EncodedString()
            ),
            keyPackageDigest: Data(repeating: marker, count: 32),
            addedEpoch: 1
        )
    }
}
