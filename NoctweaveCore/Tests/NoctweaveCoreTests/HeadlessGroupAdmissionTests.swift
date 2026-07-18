import Foundation
import XCTest
@testable import NoctweaveCore

final class HeadlessGroupAdmissionTests: XCTestCase {
    func testWelcomeFirstAdmissionSurvivesRestartAndAtomicallyInstallsOnlyCompletedGroup()
        async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweave-group-admission-\(UUID().uuidString)"
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let port = UInt16.random(in: 40_000...57_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(
            store: RelayStore(),
            opaqueRouteStore: OpaqueRouteRelayStoreV2()
        )
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 100_000_000)

        let startedAt = NoctweaveRendezvousV2.canonicalTimestamp(
            Date().addingTimeInterval(-10)
        )
        let groupID = UUID()
        let ownerRecord = try makeAdmissionOwnerRecord(groupID: groupID, at: startedAt)
        let ownerStore = GroupAdmissionOwnerStore(record: ownerRecord)
        let owner = try NoctweavePQGroupRuntimeV2(
            record: ownerRecord,
            persistence: ownerStore
        )
        let stateStore = ClientStateStore(
            fileURL: root.appendingPathComponent("member.json"),
            useEncryption: false
        )
        var member = try await HeadlessMessagingClient.open(
            stateStore: stateStore,
            displayName: "member"
        )
        let binding = Data(repeating: 0x61, count: 32)
        let expiresAt = startedAt.addingTimeInterval(24 * 60 * 60)
        let preparation = try await member.prepareGroupAdmission(
            groupID: groupID,
            invitationBindingDigest: binding,
            relay: endpoint,
            expiresAt: expiresAt,
            createdAt: startedAt.addingTimeInterval(1)
        )
        let unrelated = try await member.prepareGroupAdmission(
            groupID: UUID(),
            invitationBindingDigest: Data(repeating: 0x62, count: 32),
            relay: endpoint,
            expiresAt: expiresAt,
            createdAt: startedAt.addingTimeInterval(1.1)
        )
        var snapshot = await member.snapshot()
        XCTAssertTrue(snapshot.activePersona.groupRuntimes.isEmpty)
        XCTAssertEqual(snapshot.activePersona.pendingGroupAdmissions.count, 2)
        let durablePrepared = try XCTUnwrap(
            snapshot.activePersona.pendingGroupAdmissions.first {
                $0.id == preparation.admissionID
            }
        )
        XCTAssertNotNil(durablePrepared.pendingRoute)
        XCTAssertNil(durablePrepared.activeRoute)
        XCTAssertEqual(durablePrepared.admission, preparation.admission)

        let route = try await member.resumeGroupAdmissionRoute(
            admissionID: preparation.admissionID,
            at: startedAt.addingTimeInterval(2)
        )
        XCTAssertFalse(route.completed)
        XCTAssertEqual(route.routeSet.ownerCredentialHandle, preparation.admission.credentialHandle)

        let memberLeaf = try GroupMemberCredentialV2.fromVerifiedProjection(
            preparation.admission,
            addedEpoch: ownerRecord.signedState.epoch + 1
        )
        let epoch = try await owner.prepareEpoch(
            operation: .addMember,
            proposedMembers: ownerRecord.signedState.members + [
                GroupMemberV2(
                    id: preparation.admission.memberHandle,
                    role: .member,
                    addedEpoch: ownerRecord.signedState.epoch + 1
                )
            ],
            proposedCredentials: ownerRecord.signedState.memberCredentials + [memberLeaf],
            admissionProjection: preparation.admission,
            proposedPermissions: ownerRecord.signedState.permissions,
            proposedMetadataDigest: ownerRecord.signedState.metadataDigest,
            idempotencyKey: Data(repeating: 0x71, count: 32),
            createdAt: startedAt.addingTimeInterval(4)
        )
        let welcome = try XCTUnwrap(epoch.signedWelcomes.first {
            $0.destinationCredentialHandle == preparation.admission.credentialHandle
        })
        let anchor = try GroupJoinAnchorV2(
            baseState: ownerRecord.signedState,
            destinationMemberHandle: preparation.admission.memberHandle,
            destinationCredentialHandle: preparation.admission.credentialHandle,
            destinationAdmissionDigest: try XCTUnwrap(preparation.admission.digest),
            issuedAt: startedAt.addingTimeInterval(3),
            expiresAt: startedAt.addingTimeInterval(12 * 60 * 60)
        )

        await XCTAssertAdmissionThrowsErrorAsync(try await member.pinGroupJoinAnchor(
            admissionID: preparation.admissionID,
            anchor: anchor,
            invitationBindingDigest: Data(repeating: 0xFF, count: 32),
            observedAt: startedAt.addingTimeInterval(3.1)
        ))
        _ = try await member.pinGroupJoinAnchor(
            admissionID: preparation.admissionID,
            anchor: anchor,
            invitationBindingDigest: binding,
            observedAt: startedAt.addingTimeInterval(3.1)
        )
        let welcomeProgress = try await member.acceptGroupAdmissionWelcome(
            admissionID: preparation.admissionID,
            welcome: welcome,
            observedAt: startedAt.addingTimeInterval(5)
        )
        XCTAssertTrue(welcomeProgress.welcomeStaged)
        XCTAssertFalse(welcomeProgress.transitionStaged)
        XCTAssertFalse(welcomeProgress.completed)

        member = try await HeadlessMessagingClient.open(
            stateStore: stateStore,
            displayName: "ignored"
        )
        let reopened = await member.pendingGroupAdmissionProgress()
        XCTAssertEqual(reopened.count, 2)
        XCTAssertTrue(try XCTUnwrap(reopened.first {
            $0.admissionID == preparation.admissionID
        }).welcomeStaged)

        let completed = try await member.acceptGroupAdmissionTransition(
            admissionID: preparation.admissionID,
            transition: epoch.transition,
            observedAt: startedAt.addingTimeInterval(5.1)
        )
        XCTAssertTrue(completed.completed)

        snapshot = await member.snapshot()
        XCTAssertEqual(snapshot.activePersona.pendingGroupAdmissions.map(\.id), [unrelated.admissionID])
        let joined = try XCTUnwrap(snapshot.activePersona.groupRuntimes.first {
            $0.groupId == groupID
        })
        XCTAssertEqual(joined.originJoinAnchorID, anchor.id)
        XCTAssertEqual(joined.localCredential.memberHandle, preparation.admission.memberHandle)
        XCTAssertEqual(
            joined.localCredential.signingKey.publicKeyData,
            preparation.admission.groupSigningPublicKey
        )
        XCTAssertEqual(joined.inboundTransport.localRoutes.count, 1)
        XCTAssertEqual(joined.inboundTransport.advertisedRouteSet, route.routeSet)
        let encoded = try NoctweaveCoder.encode(snapshot, sortedKeys: true)
        let decoded = try NoctweaveCoder.decode(ClientState.self, from: encoded)
        XCTAssertTrue(try decoded.isStructurallyValidThrowing)
        XCTAssertEqual(
            try NoctweaveCoder.encode(decoded, sortedKeys: true),
            encoded
        )
    }
}

private func XCTAssertAdmissionThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected async expression to throw", file: file, line: line)
    } catch {}
}

private actor GroupAdmissionOwnerStore: GroupRuntimeRecordPersistence {
    private var record: GroupRuntimeRecord?

    init(record: GroupRuntimeRecord?) { self.record = record }
    func load() -> GroupRuntimeRecord? { record }
    func save(_ record: GroupRuntimeRecord) { self.record = record }
}

private func makeAdmissionOwnerRecord(groupID: UUID, at date: Date) throws -> GroupRuntimeRecord {
    let memberHandle = GroupScopedMemberHandleV2.generate()
    let signingKey = try SigningKeyPair.generate()
    let agreementKey = try AgreementKeyPair.generate()
    let admission = try GroupCredentialAdmissionV2.create(
        groupId: groupID,
        memberHandle: memberHandle,
        credentialHandle: .generate(),
        groupSigningKey: signingKey,
        groupAgreementKey: agreementKey,
        issuedAt: date,
        expiresAt: date.addingTimeInterval(24 * 60 * 60)
    )
    let leaf = try GroupMemberCredentialV2.fromVerifiedProjection(admission, addedEpoch: 1)
    let credential = LocalGroupCredentialV2(
        groupId: groupID,
        memberHandle: memberHandle,
        credentialHandle: leaf.credentialHandle,
        admissionDigest: leaf.admissionDigest,
        signingKey: signingKey,
        agreementKey: agreementKey
    )
    let creator = GroupMemberV2(id: memberHandle, role: .owner, addedEpoch: 1)
    let provider = NoctweavePQGroupExperimentalProviderV2()
    let membership = try provider.membership(
        groupId: groupID,
        epoch: 1,
        members: [creator],
        leaves: [leaf]
    )
    let prepared = try provider.prepareGenesis(
        membership: membership,
        localCredential: credential
    )
    let digest = try XCTUnwrap(prepared.providerCommitDigest)
    let state = try SignedGroupStateV2.initial(
        groupId: groupID,
        creator: creator,
        creatorAdmission: admission,
        providerGenesisDigest: digest,
        signingKey: signingKey,
        signedAt: date
    )
    let acceptance = GroupCryptoAcceptedEpochV2(
        proposal: prepared.proposal,
        providerCommitDigest: digest,
        signedCommitDigest: state.commitDigest,
        acceptedTranscriptHash: state.confirmedTranscriptHash
    )
    return GroupRuntimeRecord(
        groupId: groupID,
        localCredential: credential,
        signedState: state,
        cryptoState: try provider.finalizePreparedEpoch(prepared, acceptance: acceptance)
    )
}
