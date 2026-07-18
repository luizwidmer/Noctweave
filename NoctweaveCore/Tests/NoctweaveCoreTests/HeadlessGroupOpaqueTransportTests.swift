import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class HeadlessGroupOpaqueTransportTests: XCTestCase {
    func testLiveEpochAndRestartedApplicationUseDurableExactRelayEvidence() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweave-headless-group-\(UUID().uuidString)"
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

        let now = NoctweaveRendezvousV2.canonicalTimestamp(
            Date().addingTimeInterval(-2)
        )
        let ownerRecord = try makeOwnerRecord(at: now)
        let peer = try makePeerCredential(
            groupID: ownerRecord.groupId,
            at: now
        )
        let peerRoute = try await createLiveRoute(
            endpoint: endpoint,
            at: now
        )
        let peerRouteSet = try SignedGroupOpaqueRouteSetV2.create(
            groupID: ownerRecord.groupId,
            ownerCredentialHandle: peer.local.credentialHandle,
            ownerAdmissionDigest: peer.local.admissionDigest,
            routes: [peerRoute],
            issuedAt: now,
            expiresAt: now.addingTimeInterval(3_600),
            signingKey: peer.local.signingKey
        )

        let store = ClientStateStore(
            fileURL: root.appendingPathComponent("state.json"),
            useEncryption: false
        )
        var state = try ClientState(displayName: "local only", createdAt: now)
        try state.updateActivePersona {
            try $0.upsert(groupRuntime: ownerRecord)
        }
        try await store.save(state)
        let client = try HeadlessMessagingClient(
            stateStore: store,
            initialState: state
        )

        let epochPrepared = try await client.prepareGroupEpoch(
            groupID: ownerRecord.groupId,
            operation: .addMember,
            proposedMembers: ownerRecord.signedState.members + [
                GroupMemberV2(
                    id: peer.local.memberHandle,
                    role: .member,
                    addedEpoch: 2
                )
            ],
            proposedCredentials: ownerRecord.signedState.memberCredentials + [peer.leaf],
            admissionProjection: peer.admission,
            proposedPermissions: ownerRecord.signedState.permissions,
            proposedMetadataDigest: ownerRecord.signedState.metadataDigest,
            idempotencyKey: Data(repeating: 0xA1, count: 32),
            routeSets: [peerRouteSet],
            createdAt: now.addingTimeInterval(1)
        )
        let epochOperation = try XCTUnwrap(epochPrepared.transportOperation)
        let epochResult = try await client.resumeGroupTransport(
            groupID: ownerRecord.groupId,
            operationID: epochOperation.id
        )
        XCTAssertTrue(epochResult.complete)
        XCTAssertEqual(epochResult.disposition, .complete)
        XCTAssertEqual(
            epochResult.acceptedCredentialHandles,
            [peer.local.credentialHandle]
        )
        let afterEpoch = await client.snapshot().activePersona.groupRuntimes.first {
            $0.groupId == ownerRecord.groupId
        }
        XCTAssertEqual(
            try XCTUnwrap(afterEpoch).epochIntents.first {
                $0.id == epochPrepared.publication.intentId
            }?.phase,
            .finalized
        )

        let currentRecord = try XCTUnwrap(afterEpoch)
        let eventDate = NoctweaveRendezvousV2.canonicalTimestamp(Date())
        let event = GroupConversationEventV2(
            groupID: currentRecord.groupId,
            authorMemberHandle: currentRecord.localCredential.memberHandle,
            authorCredentialHandle: currentRecord.localCredential.credentialHandle,
            createdAt: eventDate,
            kind: .application,
            content: try XCTUnwrap(.text("restart-safe group delivery"))
        )
        let applicationPrepared = try await client.prepareGroupApplication(
            event,
            routeSets: [peerRouteSet],
            at: eventDate
        )
        let applicationOperation = try XCTUnwrap(
            applicationPrepared.transportOperation
        )
        let runtimeBeforeCrash = try await client.openGroupRuntime(
            groupID: currentRecord.groupId
        )
        let eligible = try await runtimeBeforeCrash.eligibleOutboundTransportPublications(
            operationID: applicationOperation.id
        )
        let exactPublication = try await runtimeBeforeCrash.recordOutboundTransportAttempt(
            operationID: applicationOperation.id,
            publicationID: try XCTUnwrap(eligible.first).id,
            at: Date()
        )
        try await appendExact(exactPublication)
        let exactPackets = exactPublication.packets

        let reopened = try await HeadlessMessagingClient.open(
            stateStore: store,
            displayName: "ignored"
        )
        let resumedOperations = try await reopened.resumePendingGroupTransports(
            groupID: currentRecord.groupId
        )
        let resumed = try XCTUnwrap(resumedOperations.first {
            $0.operationID == applicationOperation.id
        })
        XCTAssertTrue(resumed.complete)
        XCTAssertEqual(resumed.disposition, .complete)
        XCTAssertEqual(resumed.acceptedCredentialHandles, [peer.local.credentialHandle])
        XCTAssertGreaterThanOrEqual(resumed.attemptedPublicationCount, 1)

        let reopenedRuntime = try await reopened.openGroupRuntime(
            groupID: currentRecord.groupId
        )
        let reopenedSnapshot = await reopenedRuntime.snapshot()
        XCTAssertFalse(reopenedSnapshot.pendingApplicationPublications.contains {
            $0.event.id == event.id
        })
        let persistedOperation = try XCTUnwrap(
            reopenedSnapshot.outboundTransportOperations.first {
                $0.id == applicationOperation.id
            }
        )
        XCTAssertEqual(
            persistedOperation.deliveries.flatMap { $0.plan.publications }
                .flatMap(\.packets),
            exactPackets
        )
        XCTAssertTrue(persistedOperation.isComplete)
    }

    private func makeOwnerRecord(at date: Date) throws -> GroupRuntimeRecord {
        let groupID = UUID()
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
            expiresAt: date.addingTimeInterval(3_600)
        )
        let leaf = try GroupMemberCredentialV2.fromVerifiedProjection(
            admission,
            addedEpoch: 1
        )
        let credential = LocalGroupCredentialV2(
            groupId: groupID,
            memberHandle: memberHandle,
            credentialHandle: leaf.credentialHandle,
            admissionDigest: leaf.admissionDigest,
            signingKey: signingKey,
            agreementKey: agreementKey
        )
        let creator = GroupMemberV2(
            id: memberHandle,
            role: .owner,
            addedEpoch: 1
        )
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
        let providerDigest = try XCTUnwrap(prepared.providerCommitDigest)
        let state = try SignedGroupStateV2.initial(
            groupId: groupID,
            creator: creator,
            creatorAdmission: admission,
            providerGenesisDigest: providerDigest,
            signingKey: signingKey,
            signedAt: date
        )
        let acceptance = GroupCryptoAcceptedEpochV2(
            proposal: prepared.proposal,
            providerCommitDigest: providerDigest,
            signedCommitDigest: state.commitDigest,
            acceptedTranscriptHash: state.confirmedTranscriptHash
        )
        return GroupRuntimeRecord(
            groupId: groupID,
            localCredential: credential,
            signedState: state,
            cryptoState: try provider.finalizePreparedEpoch(
                prepared,
                acceptance: acceptance
            )
        )
    }

    private func makePeerCredential(
        groupID: UUID,
        at date: Date
    ) throws -> (
        admission: GroupCredentialAdmissionV2,
        leaf: GroupMemberCredentialV2,
        local: LocalGroupCredentialV2
    ) {
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
            expiresAt: date.addingTimeInterval(3_600)
        )
        let leaf = try GroupMemberCredentialV2.fromVerifiedProjection(
            admission,
            addedEpoch: 2
        )
        return (
            admission,
            leaf,
            LocalGroupCredentialV2(
                groupId: groupID,
                memberHandle: memberHandle,
                credentialHandle: leaf.credentialHandle,
                admissionDigest: leaf.admissionDigest,
                signingKey: signingKey,
                agreementKey: agreementKey
            )
        )
    }

    private func createLiveRoute(
        endpoint: RelayEndpoint,
        at date: Date
    ) async throws -> OpaqueSendRouteV2 {
        let pending = try PendingLocalOpaqueReceiveRouteV2.prepare(
            relay: endpoint,
            createdAt: date
        )
        let response = try await RelayClient(endpoint: endpoint).send(
            .createOpaqueRouteV2(
                CreateOpaqueRouteRelayRequestV2(
                    request: pending.createRequest,
                    renewCapability: pending.clientCapabilities.renewCapability
                )
            )
        )
        guard case .opaqueRoute(let created)? = response.successBody else {
            throw HeadlessMessagingClientError.invalidRelayResponse
        }
        return try pending.activate(createdRoute: created).peerSendRoute()
    }

    private func appendExact(
        _ publication: GroupOpaqueRoutePublicationV2
    ) async throws {
        let relay = RelayClient(endpoint: publication.destinationRelay)
        for packet in publication.packets {
            let response = try await relay.send(
                .appendOpaqueRouteV2(
                    AppendOpaqueRouteRelayRequestV2(
                        packet: packet,
                        sendCapability: publication.sendCapability
                    )
                )
            )
            guard case .opaqueRouteAppend(let receipt)? = response.successBody,
                  receipt.packetID == packet.packetID else {
                throw HeadlessMessagingClientError.invalidRelayResponse
            }
        }
    }
}
