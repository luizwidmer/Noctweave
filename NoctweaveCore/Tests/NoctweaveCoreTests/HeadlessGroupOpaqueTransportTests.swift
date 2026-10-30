import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class HeadlessGroupOpaqueTransportTests: XCTestCase {
    func testLegacyOrDirectOrphanIntentWithoutRoutesFailsClosed() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweave-unbound-epoch-\(UUID().uuidString)"
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let now = NoctweaveRendezvousV2.canonicalTimestamp(Date().addingTimeInterval(-2))
        let ownerRecord = try makeOwnerRecord(at: now)
        let store = ClientStateStore(
            fileURL: root.appendingPathComponent("state.json"),
            protection: .insecurePlaintextForTesting
        )
        var state = try ClientState(displayName: "local only", createdAt: now)
        try state.updateActivePersona { try $0.upsert(groupRuntime: ownerRecord) }
        try await store.save(state, replacing: nil)
        let client = try HeadlessMessagingClient(stateStore: store, initialState: state)
        let runtime = try await client.openGroupRuntime(groupID: ownerRecord.groupId)
        _ = try await runtime.prepareEpoch(
            operation: .updateMetadata,
            proposedMembers: ownerRecord.signedState.members,
            proposedCredentials: ownerRecord.signedState.memberCredentials,
            proposedPermissions: ownerRecord.signedState.permissions,
            proposedMetadataDigest: Data(repeating: 0x45, count: 32),
            idempotencyKey: Data(repeating: 0x46, count: 32),
            createdAt: now.addingTimeInterval(1)
        )
        let legacySnapshot = await runtime.snapshot()
        let legacyIntent = try XCTUnwrap(legacySnapshot.epochIntents.first)
        XCTAssertNil(legacyIntent.transportRouteSets)
        let encoded = try JSONEncoder().encode(legacyIntent)
        XCTAssertEqual(try JSONDecoder().decode(GroupEpochIntent.self, from: encoded), legacyIntent)

        let reopened = try await HeadlessMessagingClient.open(
            stateStore: store,
            displayName: "ignored"
        )
        do {
            _ = try await reopened.maintainGroup(groupID: ownerRecord.groupId)
            XCTFail("An unbound epoch intent cannot be silently marked complete")
        } catch HeadlessMessagingClientError.invalidState {
            let unchanged = await reopened.snapshot().activePersona.groupRuntimes.first {
                $0.groupId == ownerRecord.groupId
            }
            XCTAssertEqual(unchanged?.epochIntents.first?.phase, .stateCommitted)
            XCTAssertTrue(unchanged?.outboundTransportOperations.isEmpty == true)
        }
    }

    func testOrphanOwnerOnlyEpochIntentFinalizesAfterRestart() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweave-orphan-owner-epoch-\(UUID().uuidString)"
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let now = NoctweaveRendezvousV2.canonicalTimestamp(Date().addingTimeInterval(-2))
        let ownerRecord = try makeOwnerRecord(at: now)
        let store = ClientStateStore(
            fileURL: root.appendingPathComponent("state.json"),
            protection: .insecurePlaintextForTesting
        )
        var state = try ClientState(displayName: "local only", createdAt: now)
        try state.updateActivePersona { try $0.upsert(groupRuntime: ownerRecord) }
        try await store.save(state, replacing: nil)
        let client = try HeadlessMessagingClient(stateStore: store, initialState: state)
        let runtime = try await client.openGroupRuntime(groupID: ownerRecord.groupId)
        let publication = try await runtime.prepareEpoch(
            operation: .updateMetadata,
            proposedMembers: ownerRecord.signedState.members,
            proposedCredentials: ownerRecord.signedState.memberCredentials,
            proposedPermissions: ownerRecord.signedState.permissions,
            proposedMetadataDigest: Data(repeating: 0x42, count: 32),
            idempotencyKey: Data(repeating: 0x43, count: 32),
            transportRouteSets: [],
            createdAt: now.addingTimeInterval(1)
        )
        let before = await runtime.snapshot()
        XCTAssertEqual(before.epochIntents.first?.phase, .stateCommitted)
        XCTAssertTrue(before.outboundTransportOperations.isEmpty)

        let reopened = try await HeadlessMessagingClient.open(
            stateStore: store,
            displayName: "ignored"
        )
        let report = try await reopened.maintainGroup(groupID: ownerRecord.groupId)
        XCTAssertFalse(report.requiresFollowUp)
        let recovered = await reopened.snapshot().activePersona.groupRuntimes.first {
            $0.groupId == ownerRecord.groupId
        }
        XCTAssertEqual(recovered?.epochIntents.first?.id, publication.intentId)
        XCTAssertEqual(recovered?.epochIntents.first?.phase, .finalized)

        let reopenedRuntime = try await reopened.openGroupRuntime(groupID: ownerRecord.groupId)
        let applicationDate = NoctweaveRendezvousV2.canonicalTimestamp(Date())
        let application = GroupConversationEventV2(
            groupID: ownerRecord.groupId,
            authorMemberHandle: ownerRecord.localCredential.memberHandle,
            authorCredentialHandle: ownerRecord.localCredential.credentialHandle,
            createdAt: applicationDate,
            kind: .application,
            content: try XCTUnwrap(.text("owner-only crash recovery"))
        )
        _ = try await reopenedRuntime.prepareApplicationEvent(
            application, transportRouteSets: [], at: applicationDate
        )
        let reopenedAgain = try await HeadlessMessagingClient.open(
            stateStore: store, displayName: "ignored"
        )
        _ = try await reopenedAgain.maintainGroup(groupID: ownerRecord.groupId)
        let afterApplication = await reopenedAgain.snapshot().activePersona.groupRuntimes.first {
            $0.groupId == ownerRecord.groupId
        }
        XCTAssertFalse(afterApplication?.pendingApplicationPublications.contains {
            $0.event.id == application.id
        } ?? true)

        let directRuntime = try await reopenedAgain.openGroupRuntime(
            groupID: ownerRecord.groupId
        )
        let legacyDate = NoctweaveRendezvousV2.canonicalTimestamp(Date())
        let legacyEvent = GroupConversationEventV2(
            groupID: ownerRecord.groupId,
            authorMemberHandle: ownerRecord.localCredential.memberHandle,
            authorCredentialHandle: ownerRecord.localCredential.credentialHandle,
            createdAt: legacyDate,
            kind: .application,
            content: try XCTUnwrap(.text("caller-managed legacy pending"))
        )
        _ = try await directRuntime.prepareApplicationEvent(legacyEvent, at: legacyDate)
        let legacySnapshot = await directRuntime.snapshot()
        let legacyPending = try XCTUnwrap(legacySnapshot.pendingApplicationPublications.first)
        XCTAssertNil(legacyPending.transportRouteSets)
        XCTAssertEqual(
            try JSONDecoder().decode(
                PendingGroupApplicationPublicationV2.self,
                from: JSONEncoder().encode(legacyPending)
            ), legacyPending
        )
        let reopenedLegacy = try await HeadlessMessagingClient.open(
            stateStore: store, displayName: "ignored"
        )
        do {
            _ = try await reopenedLegacy.maintainGroup(groupID: ownerRecord.groupId)
            XCTFail("A caller-managed application without an outbox must fail closed")
        } catch HeadlessMessagingClientError.invalidState {
            let unchanged = await reopenedLegacy.snapshot().activePersona.groupRuntimes.first {
                $0.groupId == ownerRecord.groupId
            }
            XCTAssertEqual(unchanged?.pendingApplicationPublications.first?.event.id,
                           legacyEvent.id)
        }
    }

    func testOrphanAddMemberEpochRebuildsExactTransportAfterRestart() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweave-orphan-remote-epoch-\(UUID().uuidString)"
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

        let now = NoctweaveRendezvousV2.canonicalTimestamp(Date().addingTimeInterval(-2))
        let ownerRecord = try makeOwnerRecord(at: now)
        let peer = try makePeerCredential(groupID: ownerRecord.groupId, at: now)
        let peerRoute = try await createLiveRoute(endpoint: endpoint, at: now)
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
            protection: .insecurePlaintextForTesting
        )
        var state = try ClientState(displayName: "local only", createdAt: now)
        try state.updateActivePersona { try $0.upsert(groupRuntime: ownerRecord) }
        try await store.save(state, replacing: nil)
        let client = try HeadlessMessagingClient(stateStore: store, initialState: state)
        let runtime = try await client.openGroupRuntime(groupID: ownerRecord.groupId)
        do {
            _ = try await client.prepareGroupEpoch(
                groupID: ownerRecord.groupId,
                operation: .addMember,
                proposedMembers: ownerRecord.signedState.members + [
                    GroupMemberV2(id: peer.local.memberHandle, role: .member, addedEpoch: 2)
                ],
                proposedCredentials: ownerRecord.signedState.memberCredentials + [peer.leaf],
                admissionProjection: peer.admission,
                proposedPermissions: ownerRecord.signedState.permissions,
                proposedMetadataDigest: ownerRecord.signedState.metadataDigest,
                idempotencyKey: Data(repeating: 0x47, count: 32),
                createdAt: now.addingTimeInterval(1)
            )
            XCTFail("A missing destination route must fail before epoch commit")
        } catch GroupRouteSetAnnouncementV2Error.routeSetMissing {
            let unchanged = await runtime.snapshot()
            XCTAssertEqual(unchanged.signedState.epoch, 1)
            XCTAssertTrue(unchanged.epochIntents.isEmpty)
        }
        let publication = try await runtime.prepareEpoch(
            operation: .addMember,
            proposedMembers: ownerRecord.signedState.members + [
                GroupMemberV2(id: peer.local.memberHandle, role: .member, addedEpoch: 2)
            ],
            proposedCredentials: ownerRecord.signedState.memberCredentials + [peer.leaf],
            admissionProjection: peer.admission,
            proposedPermissions: ownerRecord.signedState.permissions,
            proposedMetadataDigest: ownerRecord.signedState.metadataDigest,
            idempotencyKey: Data(repeating: 0x44, count: 32),
            transportRouteSets: [peerRouteSet],
            createdAt: now.addingTimeInterval(1)
        )
        let before = await runtime.snapshot()
        XCTAssertEqual(before.epochIntents.first?.phase, .stateCommitted)
        XCTAssertEqual(before.epochIntents.first?.transportRouteSets, [peerRouteSet])
        XCTAssertTrue(before.outboundTransportOperations.isEmpty)

        let reopened = try await HeadlessMessagingClient.open(
            stateStore: store,
            displayName: "ignored"
        )
        let report = try await reopened.maintainGroup(groupID: ownerRecord.groupId)
        XCTAssertEqual(report.transportResults.count, 1)
        XCTAssertTrue(report.transportResults[0].complete)
        XCTAssertFalse(report.requiresFollowUp)
        let recovered = await reopened.snapshot().activePersona.groupRuntimes.first {
            $0.groupId == ownerRecord.groupId
        }
        XCTAssertEqual(recovered?.epochIntents.first?.id, publication.intentId)
        XCTAssertEqual(recovered?.epochIntents.first?.phase, .finalized)
        XCTAssertNil(recovered?.epochIntents.first?.transportRouteSets)
        let exact = try XCTUnwrap(recovered?.outboundTransportOperations.first)
        XCTAssertEqual(exact.kind, .epoch)
        XCTAssertEqual(exact.destinationSnapshots.first?.routeSet, peerRouteSet)
    }

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
            protection: .insecurePlaintextForTesting
        )
        var state = try ClientState(displayName: "local only", createdAt: now)
        try state.updateActivePersona {
            try $0.upsert(groupRuntime: ownerRecord)
        }
        try await store.save(state, replacing: nil)
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

        let orphanDate = NoctweaveRendezvousV2.canonicalTimestamp(Date())
        let orphan = GroupConversationEventV2(
            groupID: currentRecord.groupId,
            authorMemberHandle: currentRecord.localCredential.memberHandle,
            authorCredentialHandle: currentRecord.localCredential.credentialHandle,
            createdAt: orphanDate,
            kind: .application,
            content: try XCTUnwrap(.text("orphan outbox after restart"))
        )
        _ = try await reopenedRuntime.prepareApplicationEvent(
            orphan, transportRouteSets: [peerRouteSet], at: orphanDate
        )
        let beforeOrphanRecovery = await reopenedRuntime.snapshot()
        XCTAssertTrue(beforeOrphanRecovery.pendingApplicationPublications.contains {
            $0.event.id == orphan.id
        })
        XCTAssertFalse(beforeOrphanRecovery.outboundTransportOperations.contains {
            $0.kind == .application && $0.logicalID == orphan.id
        })
        let reopenedAgain = try await HeadlessMessagingClient.open(
            stateStore: store, displayName: "ignored"
        )
        let recoveredOrphan = try await reopenedAgain.maintainGroup(
            groupID: currentRecord.groupId
        )
        XCTAssertEqual(recoveredOrphan.transportResults.count, 1)
        XCTAssertTrue(recoveredOrphan.transportResults[0].complete)
        let afterOrphan = await reopenedAgain.snapshot().activePersona.groupRuntimes.first {
            $0.groupId == currentRecord.groupId
        }
        XCTAssertFalse(afterOrphan?.pendingApplicationPublications.contains {
            $0.event.id == orphan.id
        } ?? true)
        XCTAssertEqual(afterOrphan?.outboundTransportOperations.first {
            $0.kind == .application && $0.logicalID == orphan.id
        }?.destinationSnapshots.first?.routeSet, peerRouteSet)

        let retryDate = NoctweaveRendezvousV2.canonicalTimestamp(Date())
        let retryEvent = GroupConversationEventV2(
            groupID: currentRecord.groupId,
            authorMemberHandle: currentRecord.localCredential.memberHandle,
            authorCredentialHandle: currentRecord.localCredential.credentialHandle,
            createdAt: retryDate,
            kind: .application,
            content: try XCTUnwrap(.text("idempotent pending retry"))
        )
        let retryRuntime = try await reopenedAgain.openGroupRuntime(
            groupID: currentRecord.groupId
        )
        let exactEnvelope = try await retryRuntime.prepareApplicationEvent(
            retryEvent, transportRouteSets: [peerRouteSet], at: retryDate
        )
        let reopenedRetry = try await HeadlessMessagingClient.open(
            stateStore: store, displayName: "ignored"
        )
        let preparedRetry = try await reopenedRetry.prepareGroupApplication(
            retryEvent, at: retryDate
        )
        XCTAssertEqual(preparedRetry.envelope, exactEnvelope)
        let retryOperation = try XCTUnwrap(preparedRetry.transportOperation)
        let retryResult = try await reopenedRetry.resumeGroupTransport(
            groupID: currentRecord.groupId, operationID: retryOperation.id
        )
        XCTAssertTrue(retryResult.complete)
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
