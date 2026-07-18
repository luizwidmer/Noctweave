import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class GroupOpaqueRouteInboundTests: XCTestCase {
    func testLocalGroupReceiveRouteRejectsDeadRevokedState() throws {
        let now = Date()
        let pending = try PendingLocalOpaqueReceiveRouteV2.prepare(
            relay: RelayEndpoint(host: "127.0.0.1", port: 9_340),
            createdAt: now
        )
        let created = try OpaqueReceiveRouteV2.creating(
            from: pending.createRequest,
            presentedRenewCapability: pending.clientCapabilities.renewCapability,
            existing: nil,
            confidentialTransport: true,
            receivedAt: now
        )
        let local = try pending.activate(createdRoute: created)

        XCTAssertThrowsError(try GroupLocalOpaqueReceiveRouteV2(
            localRoute: local,
            advertisedState: .revoked,
            activatedAt: now
        ))
    }

    func testLiveInboundRouteStagesEpochSurvivesRestartAndProcessesDeletion() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweave-group-inbound-\(UUID().uuidString)"
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

        let fixture = try await makeTwoMemberFixture(
            at: NoctweaveRendezvousV2.canonicalTimestamp(
                Date().addingTimeInterval(-3)
            )
        )
        let ownerStore = ClientStateStore(
            fileURL: root.appendingPathComponent("owner.json"),
            useEncryption: false
        )
        let memberStore = ClientStateStore(
            fileURL: root.appendingPathComponent("member.json"),
            useEncryption: false
        )
        let owner = try await makeClient(
            record: fixture.ownerRecord,
            store: ownerStore,
            name: "owner"
        )
        var member = try await makeClient(
            record: fixture.memberRecord,
            store: memberStore,
            name: "member"
        )
        let route = try await member.registerGroupReceiveRoute(
            groupID: fixture.ownerRecord.groupId,
            relay: endpoint
        )
        XCTAssertEqual(route.routeSet.ownerCredentialHandle, fixture.memberCredential.credentialHandle)
        XCTAssertEqual(route.routeSet.routes.count, 1)

        let sentAt = NoctweaveRendezvousV2.canonicalTimestamp(Date())
        let event = GroupConversationEventV2(
            groupID: fixture.ownerRecord.groupId,
            authorMemberHandle: fixture.ownerRecord.localCredential.memberHandle,
            authorCredentialHandle: fixture.ownerRecord.localCredential.credentialHandle,
            createdAt: sentAt,
            kind: .application,
            content: try XCTUnwrap(.text("durable group receive"))
        )
        let prepared = try await owner.prepareGroupApplication(
            event,
            routeSets: [route.routeSet],
            at: sentAt
        )
        let appOperation = try XCTUnwrap(prepared.transportOperation)
        let appResume = try await owner.resumeGroupTransport(
            groupID: event.groupID,
            operationID: appOperation.id
        )
        XCTAssertTrue(appResume.complete)
        let appSync = try await member.syncGroup(groupID: event.groupID)
        XCTAssertEqual(appSync.flatMap(\.receivedEvents).map(\.id), [event.id])

        let ownerSnapshot = await owner.snapshot()
        let ownerAfterApplication = try XCTUnwrap(
            ownerSnapshot.activePersona.groupRuntimes.first { $0.groupId == event.groupID }
        )
        let epochAt = NoctweaveRendezvousV2.canonicalTimestamp(
            Date().addingTimeInterval(0.1)
        )
        let epoch = try await owner.prepareGroupEpoch(
            groupID: event.groupID,
            operation: .updateMetadata,
            proposedMembers: ownerAfterApplication.signedState.members,
            proposedCredentials: ownerAfterApplication.signedState.memberCredentials,
            proposedPermissions: ownerAfterApplication.signedState.permissions,
            proposedMetadataDigest: Data(repeating: 0xA7, count: 32),
            idempotencyKey: Data(repeating: 0xB7, count: 32),
            routeSets: [route.routeSet],
            createdAt: epochAt
        )
        let epochOperation = try XCTUnwrap(epoch.transportOperation)
        let epochResume = try await owner.resumeGroupTransport(
            groupID: event.groupID,
            operationID: epochOperation.id
        )
        XCTAssertTrue(epochResume.complete)
        _ = try await member.syncGroup(groupID: event.groupID)
        let memberEpochSnapshot = await member.snapshot()
        let memberAfterEpoch = try XCTUnwrap(
            memberEpochSnapshot.activePersona.groupRuntimes.first {
                $0.groupId == event.groupID
            }
        )
        XCTAssertEqual(memberAfterEpoch.signedState.epoch, epoch.publication.signedState.epoch)
        XCTAssertTrue(memberAfterEpoch.inboundTransport.epochStaging.transitions.isEmpty)
        XCTAssertTrue(memberAfterEpoch.inboundTransport.epochStaging.welcomes.isEmpty)

        member = try await HeadlessMessagingClient.open(
            stateStore: memberStore,
            displayName: "ignored"
        )
        let replay = try await member.syncGroup(groupID: event.groupID)
        XCTAssertTrue(replay.flatMap(\.receivedEvents).isEmpty)
        let memberReplaySnapshot = await member.snapshot()
        XCTAssertEqual(
            memberReplaySnapshot.activePersona.groupRuntimes.first {
                $0.groupId == event.groupID
            }?.events.filter { $0.id == event.id }.count,
            1
        )

        let deletion = try await owner.prepareGroupDeletion(
            groupID: event.groupID,
            reasonDigest: Data(SHA256.hash(data: Data("owner-requested".utf8))),
            idempotencyKey: Data(repeating: 0xC7, count: 32),
            routeSets: [route.routeSet],
            createdAt: Date()
        )
        let deletionOperation = try XCTUnwrap(deletion.transportOperation)
        let deletionResume = try await owner.resumeGroupTransport(
            groupID: event.groupID,
            operationID: deletionOperation.id
        )
        XCTAssertTrue(deletionResume.complete)
        let ownerDeletionSnapshot = await owner.snapshot()
        let ownerDeletionRecord = ownerDeletionSnapshot.activePersona.groupRuntimes.filter {
            $0.groupId == event.groupID
        }.first
        XCTAssertEqual(
            ownerDeletionRecord?.deletionState?.publicationState,
            .published
        )
        _ = try await member.syncGroup(groupID: event.groupID)
        let memberDeletionSnapshot = await member.snapshot()
        XCTAssertNotNil(
            memberDeletionSnapshot.activePersona.groupRuntimes.first {
                $0.groupId == event.groupID
            }?.deletionState
        )
    }

    func testExpiredGroupPacketProofRefreshPersistsExactCiphertext() async throws {
        let fixture = try await makeTwoMemberFixture(
            at: NoctweaveRendezvousV2.canonicalTimestamp(
                Date().addingTimeInterval(-15 * 60)
            )
        )
        let now = Date()
        let route = try makeSendRoute(
            endpoint: RelayEndpoint(host: "127.0.0.1", port: 9_340),
            at: fixture.startedAt,
            expiresAt: now.addingTimeInterval(60 * 60)
        )
        let routeSet = try SignedGroupOpaqueRouteSetV2.create(
            groupID: fixture.ownerRecord.groupId,
            ownerCredentialHandle: fixture.memberCredential.credentialHandle,
            ownerAdmissionDigest: fixture.memberCredential.admissionDigest,
            routes: [route],
            issuedAt: fixture.startedAt,
            expiresAt: now.addingTimeInterval(60 * 60),
            signingKey: fixture.memberCredential.signingKey
        )
        let store = GroupInboundTestStore(record: fixture.ownerRecord)
        let runtime = try NoctweavePQGroupRuntimeV2(
            record: fixture.ownerRecord,
            persistence: store
        )
        let event = GroupConversationEventV2(
            groupID: fixture.ownerRecord.groupId,
            authorMemberHandle: fixture.ownerRecord.localCredential.memberHandle,
            authorCredentialHandle: fixture.ownerRecord.localCredential.credentialHandle,
            createdAt: fixture.startedAt.addingTimeInterval(2),
            kind: .application,
            content: try XCTUnwrap(.text("refresh proof only"))
        )
        _ = try await runtime.prepareApplicationEvent(event, at: event.createdAt)
        let preparedOperation = try await runtime.prepareApplicationTransport(
            eventID: event.id,
            routeSets: [routeSet],
            at: event.createdAt
        )
        let operation = try XCTUnwrap(preparedOperation)
        let before = try XCTUnwrap(operation.eligiblePublications.first)
        XCTAssertLessThan(
            try XCTUnwrap(before.packets.first).authorization.authorizedAt,
            now.addingTimeInterval(-NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew)
        )
        let attempted = try await runtime.recordOutboundTransportAttempt(
            operationID: operation.id,
            publicationID: before.id,
            at: now
        )
        XCTAssertEqual(attempted.packets.map(\.packetID), before.packets.map(\.packetID))
        XCTAssertEqual(attempted.packets.map(\.sealedFrame), before.packets.map(\.sealedFrame))
        XCTAssertEqual(attempted.packets.map(\.operationDigest), before.packets.map(\.operationDigest))
        XCTAssertTrue(attempted.packets.allSatisfy { $0.authorization.authorizedAt == now })
        let loaded = await store.load()
        let saved = try XCTUnwrap(loaded)
        let persisted = try XCTUnwrap(saved.outboundTransportOperations.first {
            $0.id == operation.id
        }?.deliveries.flatMap(\.attempts).first { $0.id == before.id }?.publication)
        XCTAssertEqual(persisted, attempted)
    }

    func testExpiredDirectPacketProofRefreshPreservesExactCiphertext() throws {
        let now = Date()
        let originalAuthorizationAt = NoctweaveRendezvousV2.canonicalTimestamp(
            now.addingTimeInterval(-15 * 60)
        )
        let route = try makeSendRoute(
            endpoint: RelayEndpoint(host: "127.0.0.1", port: 9_340),
            at: originalAuthorizationAt.addingTimeInterval(-1),
            expiresAt: now.addingTimeInterval(60 * 60)
        )
        let payload = Data("direct proof refresh".utf8)
        let bundle = try OpaqueRouteSealedBundleV2.seal(
            payload,
            to: route,
            authorizedAt: originalAuthorizationAt
        )
        let intentID = UUID()
        let delivery = try PendingOpaqueRouteDeliveryV2(
            id: intentID,
            intentID: intentID,
            logicalEventID: UUID(),
            relationshipID: UUID(),
            directSessionID: "direct-session",
            messageCounter: 7,
            destinationRelay: route.relay,
            payloadDigest: Data(SHA256.hash(data: payload)),
            sealedBundle: bundle,
            queuedAt: originalAuthorizationAt
        )

        let refreshed = try delivery.refreshingExpiredAuthorizations(
            sendCapability: route.sendCapability,
            at: now
        )

        XCTAssertEqual(refreshed.id, delivery.id)
        XCTAssertEqual(refreshed.bundleID, delivery.bundleID)
        XCTAssertEqual(refreshed.packets.map { $0.packetID }, delivery.packets.map { $0.packetID })
        XCTAssertEqual(refreshed.packets.map { $0.sealedFrame }, delivery.packets.map { $0.sealedFrame })
        XCTAssertEqual(
            refreshed.packets.map { $0.operationDigest },
            delivery.packets.map { $0.operationDigest }
        )
        XCTAssertTrue(refreshed.packets.allSatisfy { $0.authorization.authorizedAt == now })
    }
}

private struct GroupInboundFixture {
    let startedAt: Date
    let ownerRecord: GroupRuntimeRecord
    let memberRecord: GroupRuntimeRecord
    let memberCredential: LocalGroupCredentialV2
}

private func makeTwoMemberFixture(at date: Date) async throws -> GroupInboundFixture {
    let ownerRecord = try makeGenesisRecord(at: date)
    let memberHandle = GroupScopedMemberHandleV2.generate()
    let signingKey = try SigningKeyPair.generate()
    let agreementKey = try AgreementKeyPair.generate()
    let admission = try GroupCredentialAdmissionV2.create(
        groupId: ownerRecord.groupId,
        memberHandle: memberHandle,
        credentialHandle: .generate(),
        groupSigningKey: signingKey,
        groupAgreementKey: agreementKey,
        issuedAt: date,
        expiresAt: date.addingTimeInterval(24 * 60 * 60)
    )
    let memberLeaf = try GroupMemberCredentialV2.fromVerifiedProjection(
        admission,
        addedEpoch: 2
    )
    let memberCredential = LocalGroupCredentialV2(
        groupId: ownerRecord.groupId,
        memberHandle: memberHandle,
        credentialHandle: memberLeaf.credentialHandle,
        admissionDigest: memberLeaf.admissionDigest,
        signingKey: signingKey,
        agreementKey: agreementKey
    )
    let ownerStore = GroupInboundTestStore(record: ownerRecord)
    let owner = try NoctweavePQGroupRuntimeV2(
        record: ownerRecord,
        persistence: ownerStore
    )
    let publication = try await owner.prepareEpoch(
        operation: .addMember,
        proposedMembers: ownerRecord.signedState.members + [
            GroupMemberV2(id: memberHandle, role: .member, addedEpoch: 2)
        ],
        proposedCredentials: ownerRecord.signedState.memberCredentials + [memberLeaf],
        admissionProjection: admission,
        proposedPermissions: ownerRecord.signedState.permissions,
        proposedMetadataDigest: ownerRecord.signedState.metadataDigest,
        idempotencyKey: Data(repeating: 0x81, count: 32),
        createdAt: date.addingTimeInterval(1)
    )
    let route = try makeSendRoute(
        endpoint: RelayEndpoint(host: "127.0.0.1", port: 9_340),
        at: date,
        expiresAt: date.addingTimeInterval(24 * 60 * 60)
    )
    let routeSet = try SignedGroupOpaqueRouteSetV2.create(
        groupID: ownerRecord.groupId,
        ownerCredentialHandle: memberCredential.credentialHandle,
        ownerAdmissionDigest: memberCredential.admissionDigest,
        routes: [route],
        issuedAt: date,
        expiresAt: date.addingTimeInterval(24 * 60 * 60),
        signingKey: memberCredential.signingKey
    )
    let preparedTransport = try await owner.prepareEpochTransport(
        intentID: publication.intentId,
        routeSets: [routeSet],
        at: date.addingTimeInterval(1)
    )
    let transport = try XCTUnwrap(preparedTransport)
    var acceptanceAt = date.addingTimeInterval(1.1)
    while let candidate = try await owner.eligibleOutboundTransportPublications(
        operationID: transport.id
    ).first {
        let attempted = try await owner.recordOutboundTransportAttempt(
            operationID: transport.id,
            publicationID: candidate.id,
            at: acceptanceAt
        )
        acceptanceAt = acceptanceAt.addingTimeInterval(0.01)
        try await owner.recordOutboundTransportAcceptance(
            operationID: transport.id,
            publicationID: candidate.id,
            receipts: attempted.packets.map {
                OpaqueRouteAppendReceiptV2(
                    packetID: $0.packetID,
                    acceptedCursor: OpaqueRouteCursorV2(
                        rawValue: Data(repeating: 0x91, count: 68)
                    ),
                    highWatermark: OpaqueRouteCursorV2(
                        rawValue: Data(repeating: 0x92, count: 68)
                    )
                )
            },
            at: acceptanceAt
        )
        acceptanceAt = acceptanceAt.addingTimeInterval(0.01)
    }
    try await owner.finalizeEpoch(intentId: publication.intentId, at: acceptanceAt)
    let currentOwner = await owner.snapshot()
    let welcome = try XCTUnwrap(publication.signedWelcomes.first {
        $0.destinationCredentialHandle == memberCredential.credentialHandle
    })
    let anchor = try GroupJoinAnchorV2(
        baseState: ownerRecord.signedState,
        destinationMemberHandle: memberCredential.memberHandle,
        destinationCredentialHandle: memberCredential.credentialHandle,
        destinationAdmissionDigest: memberCredential.admissionDigest,
        issuedAt: date,
        expiresAt: date.addingTimeInterval(60 * 60)
    )
    let memberStore = GroupInboundTestStore(record: nil)
    let member = try await NoctweavePQGroupRuntimeV2.join(
        anchor: anchor,
        transition: publication.transition,
        welcome: welcome,
        localCredential: memberCredential,
        observedAt: date.addingTimeInterval(1),
        persistence: memberStore
    )
    return GroupInboundFixture(
        startedAt: date,
        ownerRecord: currentOwner,
        memberRecord: await member.snapshot(),
        memberCredential: memberCredential
    )
}

private func makeGenesisRecord(at date: Date) throws -> GroupRuntimeRecord {
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

private func makeSendRoute(
    endpoint: RelayEndpoint,
    at date: Date,
    expiresAt: Date
) throws -> OpaqueSendRouteV2 {
    try OpaqueSendRouteV2(
        routeID: .generate(),
        relay: endpoint,
        sendCapability: .generate(),
        payloadKey: .generate(),
        routeRevision: 0,
        policy: OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .sixHours,
            quotaBucket: .packets256
        ),
        validFrom: date,
        expiresAt: expiresAt,
        state: .active,
        testedAt: date
    )
}

private func makeClient(
    record: GroupRuntimeRecord,
    store: ClientStateStore,
    name: String
) async throws -> HeadlessMessagingClient {
    var state = try ClientState(displayName: name, createdAt: Date())
    try state.updateActivePersona { try $0.upsert(groupRuntime: record) }
    try await store.save(state)
    return try HeadlessMessagingClient(stateStore: store, initialState: state)
}

private actor GroupInboundTestStore: GroupRuntimeRecordPersistence {
    private var record: GroupRuntimeRecord?

    init(record: GroupRuntimeRecord?) { self.record = record }

    func load() -> GroupRuntimeRecord? { record }
    func save(_ record: GroupRuntimeRecord) { self.record = record }
}
