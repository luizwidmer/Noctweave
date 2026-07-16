import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2GroupBoundaryTests: XCTestCase {
    func testPrivacyProjectionDoesNotCommitEndpointEvidence() throws {
        let fixture = try makeGenesis()
        let localGenerationId = UUID()
        let localEndpoint = try LocalInstallationState.generate(
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
        let localManifest = try InstallationManifest.create(
            identityGenerationId: localGenerationId,
            epoch: 0,
            installations: [localEndpoint.publicRecord(
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
        let commit = try SignedGroupCommitV2.createPrivacyPreserving(
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
        XCTAssertNil(commit.addedKeyPackage)
        XCTAssertNotNil(commit.admissionProjection)
        XCTAssertFalse(serialized.contains(localGenerationId.uuidString.lowercased()))
        XCTAssertFalse(serialized.contains(localEndpoint.id.uuidString.lowercased()))
        XCTAssertFalse(serialized.contains(
            localEndpoint.signingKey.publicKeyData.base64EncodedString().lowercased()
        ))
        XCTAssertFalse(serialized.contains(privateModuleName))
        XCTAssertFalse(serialized.contains("\"capabilities\""))
    }

    func testStatefulProviderReturnsReplacementStateAndProcessesWelcome() throws {
        let provider = StatefulTestGroupProvider()
        let groupId = UUID()
        let handle = GroupScopedClientHandleV2.generate()
        let client = GroupProviderClientV2(
            userId: UUID(),
            clientHandle: handle,
            keyPackageDigest: bytes(0x11),
            signingPublicKey: try SigningKeyPair.generate().publicKeyData,
            agreementPublicKey: try AgreementKeyPair.generate().publicKeyData
        )
        let membership = GroupProviderMembershipV2(
            groupId: groupId,
            epoch: 1,
            selection: .currentExperimental,
            clients: [client],
            membershipDigest: bytes(0x12)
        )
        let prepared = try provider.prepareGenesis(
            membership: membership,
            localClientHandle: handle
        )
        let acceptance = GroupCryptoAcceptedEpochV2(
            proposal: prepared.proposal,
            providerCommitDigest: try XCTUnwrap(prepared.providerCommitDigest),
            signedCommitDigest: bytes(0x13),
            acceptedTranscriptHash: bytes(0x14)
        )
        let initial = try provider.finalizePreparedEpoch(prepared, acceptance: acceptance)
        let sealed = try provider.encryptApplicationEvent(
            Data("hello".utf8),
            authenticatedContext: bytes(0x15),
            state: initial
        )
        XCTAssertNotEqual(sealed.state, initial)
        let opened = try provider.decryptApplicationEvent(
            sealed.ciphertext,
            authenticatedContext: bytes(0x15),
            state: sealed.state
        )
        XCTAssertEqual(opened.plaintext, Data("hello".utf8))
        XCTAssertNotEqual(opened.state, sealed.state)

        let welcomed = try provider.processWelcome(
            GroupWelcomePackage(destination: handle, bytes: Data([0x77])),
            membership: membership,
            acceptance: acceptance,
            localClientHandle: handle
        )
        XCTAssertEqual(welcomed.selection, .currentExperimental)
        XCTAssertEqual(welcomed.groupId, groupId)
        XCTAssertEqual(welcomed.epoch, 1)
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
        let ordinaryCommit = try SignedGroupCommitV2.createPrivacyPreserving(
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
        let addMember = try SignedGroupCommitV2.createPrivacyPreserving(
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

        XCTAssertThrowsError(try SignedGroupCommitV2.createPrivacyPreserving(
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
        let addSibling = try SignedGroupCommitV2.createPrivacyPreserving(
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
        let endpoint = try LocalInstallationState.generate(
            identityGenerationId: identityGenerationId,
            createdAt: signedAt.addingTimeInterval(-20)
        )
        let manifest = try InstallationManifest.create(
            identityGenerationId: identityGenerationId,
            epoch: 0,
            installations: [endpoint.publicRecord(addedEpoch: 0)],
            identity: identity,
            issuedAt: signedAt.addingTimeInterval(-10)
        )
        let ownerKey = try SigningKeyPair.generate()
        let package = try GroupClientKeyPackageV2.create(
            groupId: groupId,
            groupUserId: owner.id,
            clientHandle: .generate(),
            identity: identity,
            installation: endpoint,
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

private struct StatefulTestGroupProvider: GroupCryptoProvider {
    let selection = GroupProtocolSelectionV2.currentExperimental

    func prepareGenesis(
        membership: GroupProviderMembershipV2,
        localClientHandle: GroupScopedClientHandleV2
    ) throws -> GroupCryptoPreparedEpochV2 {
        guard membership.isStructurallyValid,
              membership.epoch == 1,
              membership.clients.contains(where: { $0.clientHandle == localClientHandle }) else {
            throw GroupArchitectureError.invalidState
        }
        let proposal = GroupCryptoEpochProposalV2(
            groupId: membership.groupId,
            baseEpoch: 0,
            nextEpoch: 1,
            selection: selection,
            currentMembershipDigest: nil,
            proposedMembershipDigest: membership.membershipDigest,
            authorClientHandle: localClientHandle
        )
        return GroupCryptoPreparedEpochV2(
            proposal: proposal,
            provisionalState: GroupCryptoState(
                selection: selection,
                groupId: membership.groupId,
                epoch: 1,
                opaqueState: Data([0x01])
            ),
            commitBytes: Data([0x10]),
            welcomes: []
        )
    }

    func prepareCommit(
        state: GroupCryptoState,
        currentMembership: GroupProviderMembershipV2,
        proposedMembership: GroupProviderMembershipV2,
        authorClientHandle: GroupScopedClientHandleV2
    ) throws -> GroupCryptoPreparedEpochV2 {
        guard state.isStructurallyValid,
              state.groupId == currentMembership.groupId,
              state.epoch == currentMembership.epoch,
              proposedMembership.groupId == state.groupId,
              proposedMembership.epoch == state.epoch + 1 else {
            throw GroupArchitectureError.invalidState
        }
        let proposal = GroupCryptoEpochProposalV2(
            groupId: state.groupId,
            baseEpoch: state.epoch,
            nextEpoch: proposedMembership.epoch,
            selection: selection,
            currentMembershipDigest: currentMembership.membershipDigest,
            proposedMembershipDigest: proposedMembership.membershipDigest,
            authorClientHandle: authorClientHandle
        )
        return GroupCryptoPreparedEpochV2(
            proposal: proposal,
            provisionalState: advanced(state, epoch: proposedMembership.epoch),
            commitBytes: Data([0x20]),
            welcomes: []
        )
    }

    func finalizePreparedEpoch(
        _ prepared: GroupCryptoPreparedEpochV2,
        acceptance: GroupCryptoAcceptedEpochV2
    ) throws -> GroupCryptoState {
        guard prepared.isStructurallyValid,
              acceptance.isStructurallyValid,
              acceptance.proposal == prepared.proposal,
              acceptance.providerCommitDigest == prepared.providerCommitDigest else {
            throw GroupArchitectureError.invalidState
        }
        return advanced(prepared.provisionalState)
    }

    func processCommit(
        state: GroupCryptoState,
        currentMembership: GroupProviderMembershipV2,
        proposedMembership: GroupProviderMembershipV2,
        acceptance: GroupCryptoAcceptedEpochV2,
        commitBytes: Data
    ) throws -> GroupCryptoState {
        guard acceptance.isStructurallyValid,
              acceptance.providerCommitDigest == Data(SHA256.hash(data: commitBytes)),
              acceptance.proposal.groupId == state.groupId,
              currentMembership.epoch == state.epoch,
              proposedMembership.epoch == acceptance.proposal.nextEpoch else {
            throw GroupArchitectureError.invalidState
        }
        return advanced(state, epoch: proposedMembership.epoch)
    }

    func processWelcome(
        _ welcome: GroupWelcomePackage,
        membership: GroupProviderMembershipV2,
        acceptance: GroupCryptoAcceptedEpochV2,
        localClientHandle: GroupScopedClientHandleV2
    ) throws -> GroupCryptoState {
        guard welcome.isStructurallyValid,
              welcome.destination == localClientHandle,
              membership.isStructurallyValid,
              acceptance.isStructurallyValid,
              acceptance.proposal.groupId == membership.groupId,
              acceptance.proposal.nextEpoch == membership.epoch else {
            throw GroupArchitectureError.invalidState
        }
        return GroupCryptoState(
            selection: selection,
            groupId: membership.groupId,
            epoch: membership.epoch,
            opaqueState: welcome.bytes
        )
    }

    func encryptApplicationEvent(
        _ event: Data,
        authenticatedContext: Data,
        state: GroupCryptoState
    ) throws -> GroupCryptoSealResultV2 {
        guard state.isStructurallyValid, authenticatedContext.count == 32 else {
            throw GroupArchitectureError.invalidState
        }
        return GroupCryptoSealResultV2(
            state: advanced(state),
            ciphertext: Data(event.reversed())
        )
    }

    func decryptApplicationEvent(
        _ ciphertext: Data,
        authenticatedContext: Data,
        state: GroupCryptoState
    ) throws -> GroupCryptoOpenResultV2 {
        guard state.isStructurallyValid, authenticatedContext.count == 32 else {
            throw GroupArchitectureError.invalidState
        }
        return GroupCryptoOpenResultV2(
            state: advanced(state),
            plaintext: Data(ciphertext.reversed())
        )
    }

    private func advanced(
        _ state: GroupCryptoState,
        epoch: UInt64? = nil
    ) -> GroupCryptoState {
        var opaque = state.opaqueState
        opaque.append(UInt8(truncatingIfNeeded: opaque.count + 1))
        return GroupCryptoState(
            selection: state.selection,
            groupId: state.groupId,
            epoch: epoch ?? state.epoch,
            opaqueState: opaque
        )
    }
}
