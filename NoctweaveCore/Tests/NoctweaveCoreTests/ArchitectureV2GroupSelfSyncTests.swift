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

    func testRevokingOneGroupClientLeafPreservesSiblingInstallation() throws {
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

    func testSelfSyncEventsAndSnapshotsAreValidatedAndPaddedInsideCiphertext() throws {
        let identityGenerationId = UUID()
        let installationId = UUID()
        let event = SelfSyncEvent(
            identityGenerationId: identityGenerationId,
            sourceInstallationId: installationId,
            sourceSequence: 1,
            createdAt: Date(timeIntervalSince1970: 1_000),
            kind: .consentChanged,
            encodedPayload: Data("accepted".utf8)
        )
        let snapshot = SelfSyncSnapshot(
            identityGenerationId: identityGenerationId,
            sourceInstallationId: installationId,
            createdAt: Date(timeIntervalSince1970: 1_001),
            through: [SelfSyncInstallationCursor(installationId: installationId, throughSequence: 1)],
            encodedReplicatedState: Data("replicated-state".utf8)
        )
        let invalidEvent = SelfSyncEvent(
            identityGenerationId: identityGenerationId,
            sourceInstallationId: installationId,
            sourceSequence: 0,
            kind: .consentChanged,
            encodedPayload: Data("accepted".utf8)
        )

        XCTAssertTrue(event.isStructurallyValid)
        XCTAssertTrue(snapshot.isStructurallyValid)
        XCTAssertFalse(invalidEvent.isStructurallyValid)

        let stream = SelfSyncStreamHandle(
            rawValue: Data(repeating: 21, count: 32).base64EncodedString()
        )
        let key = SymmetricKey(size: .bits256)
        let sealed = try EncryptedSelfSyncRecord.seal(
            .event(event),
            stream: stream,
            key: key,
            storedAt: Date(timeIntervalSince1970: 1_059)
        )

        XCTAssertTrue(sealed.isStructurallyValid)
        XCTAssertTrue(NoctweaveSelfSyncV2.paddingBuckets.contains(sealed.payload.ciphertext.count))
        XCTAssertEqual(sealed.storedAtBucket, Date(timeIntervalSince1970: 1_020))
        let opened = try sealed.open(
            key: key,
            expectedStream: stream,
            expectedIdentityGenerationId: identityGenerationId
        )
        XCTAssertEqual(opened, .event(event))

        let wrongStream = SelfSyncStreamHandle(
            rawValue: Data(repeating: 22, count: 32).base64EncodedString()
        )
        XCTAssertThrowsError(
            try sealed.open(
                key: key,
                expectedStream: wrongStream,
                expectedIdentityGenerationId: identityGenerationId
            )
        ) { error in
            XCTAssertEqual(error as? SelfSyncV2Error, .wrongStream)
        }
    }

    func testRendezvousIsPurposeBoundAndExpiresExactlyAtDeadline() throws {
        let createdAt = Date(timeIntervalSince1970: 2_000)
        let offer = RendezvousOffer(
            purpose: .endpointAdmission,
            ephemeralAgreementPublicKey: try AgreementKeyPair.generate().publicKeyData,
            temporaryRoute: "https://relay.example/rendezvous/opaque",
            oneTimeToken: Data(repeating: 31, count: 32),
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(300)
        )

        XCTAssertTrue(offer.isStructurallyValid)
        XCTAssertTrue(
            offer.isUsable(
                at: createdAt.addingTimeInterval(299),
                for: .endpointAdmission
            )
        )
        XCTAssertFalse(
            offer.isUsable(
                at: createdAt.addingTimeInterval(299),
                for: .contactPairing
            )
        )
        XCTAssertFalse(
            offer.isUsable(
                at: createdAt.addingTimeInterval(300),
                for: .endpointAdmission
            )
        )

        let key = SymmetricKey(size: .bits256)
        let encrypted = try EncryptedRendezvousPayload.seal(
            Data("installation package".utf8),
            for: offer,
            key: key,
            at: createdAt.addingTimeInterval(1)
        )
        XCTAssertThrowsError(
            try encrypted.open(
                for: offer,
                expectedPurpose: .contactPairing,
                key: key,
                at: createdAt.addingTimeInterval(2)
            )
        ) { error in
            XCTAssertEqual(error as? SelfSyncV2Error, .invalidRendezvous)
        }

        let tooLong = RendezvousOffer(
            purpose: .endpointAdmission,
            ephemeralAgreementPublicKey: offer.ephemeralAgreementPublicKey,
            temporaryRoute: offer.temporaryRoute,
            oneTimeToken: offer.oneTimeToken,
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(NoctweaveSelfSyncV2.maximumRendezvousLifetime + 1)
        )
        XCTAssertFalse(tooLong.isStructurallyValid)
    }

    func testHistoryGrantNeverAuthorizesFutureParticipation() {
        let createdAt = Date(timeIntervalSince1970: 3_000)
        let grant = HistoryAccessGrant(
            archiveId: UUID(),
            archiveManifestDigest: Data(repeating: 41, count: 32),
            identityGenerationId: UUID(),
            recipientInstallationId: UUID(),
            wrappedArchiveKey: Data(repeating: 42, count: 64),
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(600)
        )

        XCTAssertTrue(grant.isStructurallyValid)
        XCTAssertTrue(grant.canImportHistory(at: createdAt.addingTimeInterval(599)))
        XCTAssertFalse(grant.authorizesFutureParticipation)
    }

    private func clientLeaf(userId: UUID, marker: UInt8) -> GroupClientLeaf {
        GroupClientLeaf(
            id: UUID(),
            userId: userId,
            installationHandle: RelationshipInstallationHandle(
                rawValue: Data(repeating: marker, count: 32).base64EncodedString()
            ),
            keyPackageDigest: Data(repeating: marker, count: 32),
            addedEpoch: 1
        )
    }
}
