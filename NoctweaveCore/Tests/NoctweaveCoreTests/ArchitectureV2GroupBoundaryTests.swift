import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2GroupBoundaryTests: XCTestCase {
    func testPrivacyProjectionDoesNotCommitEndpointEvidence() throws {
        let fixture = try makeGenesis()
        let localGenerationId = UUID()
        let localEndpoint = try LocalEndpointState.generate(
            identityGenerationId: localGenerationId,
            createdAt: fixture.state.signedAt.addingTimeInterval(-20)
        )
        let localIdentity = try Identity.generate(displayName: "Local admission evidence")
        let privateModuleName = "nw.local-only.\(UUID().uuidString.lowercased())"
        let localCapabilities = ProtocolCapabilityManifest(
            modules: ProtocolCapabilityManifest.defaultActiveEndpointModules + [
                ProtocolModuleCapability(
                    module: privateModuleName,
                    versions: [1],
                    status: .experimental
                )
            ]
        )
        let localManifest = try EndpointSetManifest.create(
            identityGenerationId: localGenerationId,
            epoch: 0,
            endpoints: [localEndpoint.publicRecord(
                addedEpoch: 0,
                capabilities: localCapabilities
            )],
            identity: localIdentity,
            issuedAt: fixture.state.signedAt.addingTimeInterval(-10)
        )
        XCTAssertTrue(localManifest.verify(
            identityPublicKey: localIdentity.signingKey.publicKeyData
        ))

        let newUser = GroupUser(
            id: UUID(),
            role: .member,
            addedEpoch: fixture.state.epoch + 1
        )
        let newClientKey = try SigningKeyPair.generate()
        let projection = try GroupClientAdmissionProjectionV2.create(
            groupId: fixture.state.groupId,
            groupUserId: newUser.id,
            groupSigningKey: newClientKey,
            groupAgreementKey: try AgreementKeyPair.generate(),
            issuedAt: fixture.state.signedAt,
            expiresAt: fixture.state.signedAt.addingTimeInterval(3_600)
        )
        let newLeaf = try GroupClientLeafV2.fromVerifiedProjection(
            projection,
            addedEpoch: fixture.state.epoch + 1
        )
        let commit = try SignedGroupCommitV2.create(
            operation: .addUser,
            currentState: fixture.state,
            proposedUsers: fixture.state.users + [newUser],
            proposedClientLeaves: fixture.state.clientLeaves + [newLeaf],
            admissionProjection: projection,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: fixture.state.metadataDigest,
            authorClientHandle: fixture.ownerLeaf.clientHandle,
            providerCommitDigest: bytes(0x31),
            idempotencyKey: bytes(0x32),
            signingKey: fixture.ownerKey,
            createdAt: fixture.state.signedAt.addingTimeInterval(1)
        )

        let encoded = try NoctweaveCoder.encode(commit, sortedKeys: true)
        let serialized = try XCTUnwrap(String(data: encoded, encoding: .utf8)).lowercased()
        XCTAssertNotNil(commit.admissionProjection)
        XCTAssertFalse(serialized.contains("\"addedkeypackage\""))
        XCTAssertFalse(serialized.contains("identitygenerationid"))
        XCTAssertFalse(serialized.contains("endpointid"))
        XCTAssertFalse(serialized.contains("manifestdigest"))
        XCTAssertFalse(serialized.contains(localGenerationId.uuidString.lowercased()))
        XCTAssertFalse(serialized.contains(localEndpoint.id.uuidString.lowercased()))
        XCTAssertFalse(serialized.contains(
            localEndpoint.signingKey.publicKeyData.base64EncodedString().lowercased()
        ))
        XCTAssertFalse(serialized.contains(privateModuleName))
        XCTAssertFalse(serialized.contains("\"capabilities\""))
    }


    func testDeletionTombstoneIsTerminalAndRejectsResurrection() throws {
        let fixture = try makeGenesis()
        let tombstone = try SignedGroupDeletionTombstoneV2.create(
            currentState: fixture.state,
            authorClientHandle: fixture.ownerLeaf.clientHandle,
            reasonDigest: bytes(0x41),
            idempotencyKey: bytes(0x42),
            signingKey: fixture.ownerKey,
            createdAt: fixture.state.signedAt.addingTimeInterval(1)
        )
        let deleted = try SignedDeletedGroupStateV2.create(
            tombstone: tombstone,
            from: fixture.state
        )
        XCTAssertTrue(deleted.isStructurallyValid)
        XCTAssertEqual(tombstone.operation, .deleteGroup)

        XCTAssertThrowsError(try deleted.rejectResurrection(fixture.state)) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .groupDeleted)
        }
        let ordinaryCommit = try SignedGroupCommitV2.create(
            operation: .updateMetadata,
            currentState: fixture.state,
            proposedUsers: fixture.state.users,
            proposedClientLeaves: fixture.state.clientLeaves,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: bytes(0x43),
            authorClientHandle: fixture.ownerLeaf.clientHandle,
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

    func testAddingSiblingClientRequiresExistingSiblingConsent() throws {
        let fixture = try makeGenesis()
        let memberUser = GroupUser(
            id: UUID(),
            role: .member,
            addedEpoch: fixture.state.epoch + 1
        )
        let memberKey = try SigningKeyPair.generate()
        let memberProjection = try GroupClientAdmissionProjectionV2.create(
            groupId: fixture.state.groupId,
            groupUserId: memberUser.id,
            groupSigningKey: memberKey,
            groupAgreementKey: try AgreementKeyPair.generate(),
            issuedAt: fixture.state.signedAt,
            expiresAt: fixture.state.signedAt.addingTimeInterval(3_600)
        )
        let memberLeaf = try GroupClientLeafV2.fromVerifiedProjection(
            memberProjection,
            addedEpoch: fixture.state.epoch + 1
        )
        let addMember = try SignedGroupCommitV2.create(
            operation: .addUser,
            currentState: fixture.state,
            proposedUsers: fixture.state.users + [memberUser],
            proposedClientLeaves: fixture.state.clientLeaves + [memberLeaf],
            admissionProjection: memberProjection,
            proposedPermissions: fixture.state.permissions,
            proposedMetadataDigest: fixture.state.metadataDigest,
            authorClientHandle: fixture.ownerLeaf.clientHandle,
            providerCommitDigest: bytes(0x51),
            idempotencyKey: bytes(0x52),
            signingKey: fixture.ownerKey,
            createdAt: fixture.state.signedAt.addingTimeInterval(1)
        )
        let stateWithMember = try SignedGroupStateV2.applying(
            addMember,
            to: fixture.state,
            signingKey: fixture.ownerKey
        )

        let siblingKey = try SigningKeyPair.generate()
        let siblingProjection = try GroupClientAdmissionProjectionV2.create(
            groupId: stateWithMember.groupId,
            groupUserId: memberUser.id,
            groupSigningKey: siblingKey,
            groupAgreementKey: try AgreementKeyPair.generate(),
            issuedAt: stateWithMember.signedAt,
            expiresAt: stateWithMember.signedAt.addingTimeInterval(3_600)
        )
        let siblingLeaf = try GroupClientLeafV2.fromVerifiedProjection(
            siblingProjection,
            addedEpoch: stateWithMember.epoch + 1
        )
        let proposedLeaves = stateWithMember.clientLeaves + [siblingLeaf]

        XCTAssertThrowsError(try SignedGroupCommitV2.create(
            operation: .addClient,
            currentState: stateWithMember,
            proposedUsers: stateWithMember.users,
            proposedClientLeaves: proposedLeaves,
            admissionProjection: siblingProjection,
            proposedPermissions: stateWithMember.permissions,
            proposedMetadataDigest: stateWithMember.metadataDigest,
            authorClientHandle: fixture.ownerLeaf.clientHandle,
            providerCommitDigest: bytes(0x53),
            idempotencyKey: bytes(0x54),
            signingKey: fixture.ownerKey,
            createdAt: stateWithMember.signedAt.addingTimeInterval(1)
        )) { error in
            XCTAssertEqual(error as? SignedGroupV2Error, .unauthorized)
        }

        let consent = try GroupSiblingClientConsentV2.create(
            projection: siblingProjection,
            currentState: stateWithMember,
            consentingClientHandle: memberLeaf.clientHandle,
            signingKey: memberKey,
            signedAt: stateWithMember.signedAt.addingTimeInterval(1)
        )
        let addSibling = try SignedGroupCommitV2.create(
            operation: .addClient,
            currentState: stateWithMember,
            proposedUsers: stateWithMember.users,
            proposedClientLeaves: proposedLeaves,
            admissionProjection: siblingProjection,
            siblingClientConsent: consent,
            proposedPermissions: stateWithMember.permissions,
            proposedMetadataDigest: stateWithMember.metadataDigest,
            authorClientHandle: fixture.ownerLeaf.clientHandle,
            providerCommitDigest: bytes(0x55),
            idempotencyKey: bytes(0x56),
            signingKey: fixture.ownerKey,
            createdAt: stateWithMember.signedAt.addingTimeInterval(1)
        )
        let next = try SignedGroupStateV2.applying(
            addSibling,
            to: stateWithMember,
            signingKey: fixture.ownerKey
        )
        XCTAssertEqual(next.activeClientLeaves.filter { $0.userId == memberUser.id }.count, 2)
    }
}

private extension ArchitectureV2GroupBoundaryTests {
    struct GenesisFixture {
        let state: SignedGroupStateV2
        let ownerLeaf: GroupClientLeafV2
        let ownerKey: SigningKeyPair
    }

    func makeGenesis() throws -> GenesisFixture {
        let groupId = UUID()
        let signedAt = Date(timeIntervalSince1970: 10_000)
        let owner = GroupUser(id: UUID(), role: .owner, addedEpoch: 1)
        let identityGenerationId = UUID()
        let identity = try Identity.generate(displayName: "Ephemeral group creator")
        let endpoint = try LocalEndpointState.generate(
            identityGenerationId: identityGenerationId,
            createdAt: signedAt.addingTimeInterval(-20)
        )
        let manifest = try EndpointSetManifest.create(
            identityGenerationId: identityGenerationId,
            epoch: 0,
            endpoints: [endpoint.publicRecord(addedEpoch: 0)],
            identity: identity,
            issuedAt: signedAt.addingTimeInterval(-10)
        )
        let ownerKey = try SigningKeyPair.generate()
        let package = try GroupClientKeyPackageV2.create(
            groupId: groupId,
            groupUserId: owner.id,
            clientHandle: .generate(),
            identity: identity,
            endpoint: endpoint,
            manifest: manifest,
            groupSigningKey: ownerKey,
            groupAgreementKey: try AgreementKeyPair.generate(),
            issuedAt: signedAt,
            expiresAt: signedAt.addingTimeInterval(3_600)
        )
        let trust = GroupGenesisTrustV2(
            creatorUserId: owner.id,
            identityPublicKey: identity.signingKey.publicKeyData,
            currentManifest: manifest,
            creatorKeyPackage: package
        )
        let state = try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: owner,
            creatorTrust: trust,
            metadataDigest: bytes(0x21),
            providerGenesisDigest: bytes(0x22),
            signingKey: ownerKey,
            signedAt: signedAt
        )
        return GenesisFixture(
            state: state,
            ownerLeaf: try XCTUnwrap(state.clientLeaves.first),
            ownerKey: ownerKey
        )
    }

    func bytes(_ marker: UInt8) -> Data {
        Data(repeating: marker, count: 32)
    }
}
