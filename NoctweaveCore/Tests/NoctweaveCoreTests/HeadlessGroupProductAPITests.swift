import Foundation
import XCTest
@testable import NoctweaveCore

final class HeadlessGroupProductAPITests: XCTestCase {
    func testCustomApplicationContentCapabilityIsPreparedForCreatorsAndJoiners() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweave-group-custom-content-\(UUID().uuidString)"
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

        let custom = ContentTypeCapabilityV2(
            authority: "org.example.community",
            name: "event",
            majorVersions: [1]
        )
        let capabilities = ProtocolCapabilityManifest.defaultContentTypes + [custom]
        let owner = try await HeadlessMessagingClient.open(
            stateStore: ClientStateStore(
                fileURL: root.appendingPathComponent("owner.json"),
                protection: .insecurePlaintextForTesting
            ),
            displayName: "owner"
        )
        let created = try await owner.createGroup(
            relay: endpoint,
            contentTypes: capabilities
        )
        XCTAssertTrue(created.signedState.activeCredentials.allSatisfy {
            $0.contentTypes.contains(custom)
        })

        let joiner = try await HeadlessMessagingClient.open(
            stateStore: ClientStateStore(
                fileURL: root.appendingPathComponent("joiner.json"),
                protection: .insecurePlaintextForTesting
            ),
            displayName: "joiner"
        )
        let prepared = try await joiner.prepareGroupAdmission(
            groupID: created.groupID,
            invitationBindingDigest: Data(repeating: 0xA9, count: 32),
            relay: endpoint,
            contentTypes: capabilities,
            expiresAt: Date().addingTimeInterval(3_600)
        )
        XCTAssertTrue(prepared.admission.contentTypes.contains(custom))
    }

    func testCreateInviteJoinSendAndMaintainWithoutManualRuntimeRecords() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweave-group-product-api-\(UUID().uuidString)"
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

        let ownerStore = ClientStateStore(
            fileURL: root.appendingPathComponent("owner.json"),
            protection: .insecurePlaintextForTesting
        )
        let owner = try await HeadlessMessagingClient.open(
            stateStore: ownerStore,
            displayName: "owner"
        )
        let member = try await HeadlessMessagingClient.open(
            stateStore: ClientStateStore(
                fileURL: root.appendingPathComponent("member.json"),
                protection: .insecurePlaintextForTesting
            ),
            displayName: "member"
        )
        let startedAt = NoctweaveRendezvousV2.canonicalTimestamp(
            Date().addingTimeInterval(-2)
        )
        let created = try await owner.createGroup(
            relay: endpoint,
            createdAt: startedAt
        )
        XCTAssertEqual(created.signedState.epoch, 1)
        XCTAssertEqual(created.receiveRoute.announcement.stateEpoch, 1)

        let binding = Data(repeating: 0xA1, count: 32)
        let admission = try await member.prepareGroupAdmission(
            groupID: created.groupID,
            invitationBindingDigest: binding,
            relay: endpoint,
            expiresAt: startedAt.addingTimeInterval(24 * 60 * 60),
            createdAt: startedAt.addingTimeInterval(0.2)
        )
        let memberRoute = try await member.resumeGroupAdmissionRoute(
            admissionID: admission.admissionID,
            at: startedAt.addingTimeInterval(0.4)
        )
        let reopenedOwner = try await HeadlessMessagingClient.open(
            stateStore: ownerStore,
            displayName: "owner"
        )
        let preparedAddition = try await reopenedOwner.prepareGroupMemberAddition(
            groupID: created.groupID,
            admission: admission.admission,
            initialRouteSet: memberRoute.routeSet,
            idempotencyKey: Data(repeating: 0xA2, count: 32),
            createdAt: startedAt.addingTimeInterval(0.6)
        )
        XCTAssertEqual(preparedAddition.existingMemberRouteAnnouncements.count, 1)
        XCTAssertEqual(
            preparedAddition.existingMemberRouteAnnouncements[0],
            created.receiveRoute.announcement
        )

        _ = try await member.pinGroupJoinAnchor(
            admissionID: admission.admissionID,
            anchor: preparedAddition.anchor,
            invitationBindingDigest: binding,
            observedAt: startedAt.addingTimeInterval(0.7)
        )
        for announcement in preparedAddition.existingMemberRouteAnnouncements {
            _ = try await member.acceptGroupAdmissionRouteAnnouncement(
                admissionID: admission.admissionID,
                announcement: announcement,
                observedAt: startedAt.addingTimeInterval(0.8)
            )
        }
        _ = try await member.acceptGroupAdmissionTransition(
            admissionID: admission.admissionID,
            transition: preparedAddition.transition,
            observedAt: startedAt.addingTimeInterval(0.9)
        )
        let joined = try await member.acceptGroupAdmissionWelcome(
            admissionID: admission.admissionID,
            welcome: preparedAddition.welcome,
            observedAt: startedAt.addingTimeInterval(1)
        )
        XCTAssertTrue(joined.completed)

        if let operation = preparedAddition.transportOperation {
            let ownerTransport = try await reopenedOwner.resumeGroupTransport(
                groupID: created.groupID,
                operationID: operation.id
            )
            XCTAssertTrue(ownerTransport.complete)
        }
        let memberMaintenance = try await member.maintainGroup(
            groupID: created.groupID
        )
        XCTAssertFalse(memberMaintenance.requiresFollowUp)
        _ = try await reopenedOwner.syncGroup(groupID: created.groupID)

        let sent = try await reopenedOwner.sendGroupText(
            groupID: created.groupID,
            text: "high-level group send"
        )
        XCTAssertTrue(sent.complete)
        XCTAssertEqual(sent.disposition, .complete)
        let received = try await member.syncGroup(groupID: created.groupID)
            .flatMap(\.receivedEvents)
        XCTAssertEqual(received.map(\.id), [sent.event.id])

        let ownerMaintenance = try await reopenedOwner.maintainGroup(
            groupID: created.groupID
        )
        XCTAssertFalse(ownerMaintenance.requiresFollowUp)
    }
}
