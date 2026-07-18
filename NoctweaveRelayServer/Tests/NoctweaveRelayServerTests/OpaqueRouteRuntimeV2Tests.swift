import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class OpaqueRouteRuntimeV2Tests: XCTestCase {
    func testFixedOpaquePacketRoundTripsWithoutChangingBytes() throws {
        let fixture = Fixture()
        let packet = try fixture.packet(at: fixture.now, fill: 0xA5)
        XCTAssertTrue(packet.isStructurallyValid)
        XCTAssertEqual(packet.sealedFrame.count, 4_096)

        let request = RelayRequest.appendOpaqueRouteV2(
            OpaqueRouteAppendSubmissionV2(packet: packet, sendCapability: fixture.send)
        )
        let encoded = try RelayCodec.encoder(sortedKeys: true).encode(request)
        let decoded = try RelayCodec.decoder().decode(RelayRequest.self, from: encoded)
        guard case .appendOpaqueRoute(let submission) = decoded.body else {
            return XCTFail("Expected opaque route append request body")
        }
        XCTAssertEqual(submission.packet.sealedFrame, packet.sealedFrame)
        XCTAssertEqual(decoded, request)

        let malformed = OpaqueRoutePacketV2(
            routeID: packet.routeID,
            packetID: packet.packetID,
            sealedFrame: Data(packet.sealedFrame.dropLast()),
            authorization: packet.authorization
        )
        XCTAssertFalse(malformed.isStructurallyValid)
    }

    func testPersistenceRestartIdempotencyCursorAndByteFidelity() throws {
        let fixture = Fixture()
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("opaque-routes.sqlite")

        let writer = RelayStore(fileURL: url)
        let create = try fixture.create(at: fixture.now)
        let route = try writer.createOpaqueRouteV2(create, confidentialTransport: true, receivedAt: fixture.now)
        XCTAssertEqual(route.lease.renewalSequence, 0)

        let packet = try fixture.packet(at: fixture.now.addingTimeInterval(1), fill: 0xD3)
        let append = OpaqueRouteAppendSubmissionV2(packet: packet, sendCapability: fixture.send)
        let firstReceipt = try writer.appendOpaqueRouteV2(
            append,
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(1)
        )
        XCTAssertEqual(
            try writer.appendOpaqueRouteV2(
                append,
                confidentialTransport: true,
                receivedAt: fixture.now.addingTimeInterval(2)
            ),
            firstReceipt
        )

        let reader = RelayStore(fileURL: url)
        try reader.load()
        XCTAssertEqual(
            try reader.appendOpaqueRouteV2(
                append,
                confidentialTransport: true,
                receivedAt: fixture.now.addingTimeInterval(3)
            ),
            firstReceipt
        )

        let sync = try fixture.sync(at: fixture.now.addingTimeInterval(4), discriminator: 0x61)
        let page = try reader.syncOpaqueRouteV2(
            sync,
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(4)
        )
        XCTAssertEqual(page.packets.count, 1)
        XCTAssertEqual(page.packets[0].sequence, 1)
        XCTAssertEqual(page.packets[0].routeRevision, 0)
        XCTAssertEqual(page.packets[0].packet.sealedFrame, packet.sealedFrame)
        XCTAssertEqual(page.startsAfterSequence, 0)
        XCTAssertEqual(page.nextSequence, 1)
        XCTAssertEqual(page.highWatermarkSequence, 1)
        XCTAssertEqual(page.retentionFloorSequence, 0)
        XCTAssertEqual(page.packets[0].previousRecordDigest, page.startsAfterRecordDigest)
        XCTAssertEqual(page.packets[0].recordDigest, page.nextRecordDigest)
        XCTAssertTrue(page.isStructurallyValid)

        let commit = try fixture.commit(
            cursor: page.nextCursor,
            at: fixture.now.addingTimeInterval(5),
            discriminator: 0x62
        )
        let committed = try reader.commitOpaqueRouteV2(
            commit,
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(5)
        )
        XCTAssertEqual(committed.committedCursor.rawValue.count, 68)

        let sqliteBytes = try Data(contentsOf: url)
        XCTAssertNil(sqliteBytes.range(of: fixture.send.rawValue))
        XCTAssertNil(sqliteBytes.range(of: fixture.read.rawValue))
        XCTAssertNil(sqliteBytes.range(of: fixture.renew.rawValue))
        XCTAssertNil(sqliteBytes.range(of: fixture.teardown.rawValue))
    }

    func testPersistenceFailureRollsBackAppendForExactRetry() throws {
        let fixture = Fixture()
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("opaque-routes.sqlite")
        let store = RelayStore(fileURL: url)
        _ = try store.createOpaqueRouteV2(
            fixture.create(at: fixture.now),
            confidentialTransport: true,
            receivedAt: fixture.now
        )

        let packet = try fixture.packet(at: fixture.now.addingTimeInterval(1), fill: 0x7C)
        let append = OpaqueRouteAppendSubmissionV2(packet: packet, sendCapability: fixture.send)
        store.failNextPersistenceForTesting()
        XCTAssertThrowsError(try store.appendOpaqueRouteV2(
            append,
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(1)
        ))

        let receipt = try store.appendOpaqueRouteV2(
            append,
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(1)
        )
        let reloaded = RelayStore(fileURL: url)
        try reloaded.load()
        XCTAssertEqual(
            try reloaded.appendOpaqueRouteV2(
                append,
                confidentialTransport: true,
                receivedAt: fixture.now.addingTimeInterval(2)
            ),
            receipt
        )
    }

    func testTeardownIsDurableNonResurrectableTombstone() throws {
        let fixture = Fixture()
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("opaque-routes.sqlite")
        let store = RelayStore(fileURL: url)
        let create = try fixture.create(at: fixture.now)
        let route = try store.createOpaqueRouteV2(
            create,
            confidentialTransport: true,
            receivedAt: fixture.now
        )
        let teardown = try fixture.teardownRoute(
            route,
            at: fixture.now.addingTimeInterval(2)
        )
        let tombstone = try store.teardownOpaqueRouteV2(
            teardown,
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(2)
        )
        XCTAssertEqual(tombstone.status, .tornDown)

        let reloaded = RelayStore(fileURL: url)
        try reloaded.load()
        XCTAssertThrowsError(try reloaded.createOpaqueRouteV2(
            create,
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(3)
        )) { error in
            XCTAssertEqual(error as? OpaqueRouteV2Error, .routeTornDown)
        }
    }

    func testConfidentialTransportIsRequiredBeforeMutation() throws {
        let fixture = Fixture()
        let store = RelayStore(fileURL: nil)
        XCTAssertThrowsError(try store.createOpaqueRouteV2(
            fixture.create(at: fixture.now),
            confidentialTransport: false,
            receivedAt: fixture.now
        )) { error in
            XCTAssertEqual(error as? OpaqueRouteV2Error, .confidentialTransportRequired)
        }
    }

    func testRenewalRevisionRetentionFloorAndQuotaSemantics() throws {
        let fixture = Fixture()
        let store = RelayStore(fileURL: nil)
        let route = try store.createOpaqueRouteV2(
            fixture.create(at: fixture.now, leaseDuration: 10_800),
            confidentialTransport: true,
            receivedAt: fixture.now
        )
        let first = try fixture.packet(at: fixture.now.addingTimeInterval(1), fill: 0x81)
        _ = try store.appendOpaqueRouteV2(
            OpaqueRouteAppendSubmissionV2(packet: first, sendCapability: fixture.send),
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(1)
        )
        let renewed = try store.renewOpaqueRouteV2(
            fixture.renewRoute(
                route,
                at: fixture.now.addingTimeInterval(2),
                through: fixture.now.addingTimeInterval(14_400)
            ),
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(2)
        )
        XCTAssertEqual(renewed.lease.renewalSequence, 1)
        let second = try fixture.packet(at: fixture.now.addingTimeInterval(3), fill: 0x82)
        _ = try store.appendOpaqueRouteV2(
            OpaqueRouteAppendSubmissionV2(packet: second, sendCapability: fixture.send),
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(3)
        )
        let page = try store.syncOpaqueRouteV2(
            fixture.sync(at: fixture.now.addingTimeInterval(4), discriminator: 0x83),
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(4)
        )
        XCTAssertEqual(page.packets.map(\.routeRevision), [0, 1])

        let quotaStore = RelayStore(fileURL: nil)
        _ = try quotaStore.createOpaqueRouteV2(
            fixture.create(at: fixture.now),
            confidentialTransport: true,
            receivedAt: fixture.now
        )
        for marker in UInt8(1) ... UInt8(64) {
            let packet = try fixture.packet(at: fixture.now.addingTimeInterval(1), fill: marker)
            _ = try quotaStore.appendOpaqueRouteV2(
                OpaqueRouteAppendSubmissionV2(packet: packet, sendCapability: fixture.send),
                confidentialTransport: true,
                receivedAt: fixture.now.addingTimeInterval(1)
            )
        }
        let overQuota = try fixture.packet(at: fixture.now.addingTimeInterval(1), fill: 65)
        XCTAssertThrowsError(try quotaStore.appendOpaqueRouteV2(
            OpaqueRouteAppendSubmissionV2(packet: overQuota, sendCapability: fixture.send),
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(1)
        )) { error in
            XCTAssertEqual(error as? OpaqueRouteRelayStoreV2Error, .routeQuotaExceeded)
        }
    }

    func testExpiredPacketAdvancesRetentionFloorAndRejectsStaleCursor() throws {
        let fixture = Fixture()
        let store = RelayStore(fileURL: nil)
        _ = try store.createOpaqueRouteV2(
            fixture.create(at: fixture.now, leaseDuration: 7_200),
            confidentialTransport: true,
            receivedAt: fixture.now
        )
        let empty = try store.syncOpaqueRouteV2(
            fixture.sync(at: fixture.now.addingTimeInterval(1), discriminator: 0x91),
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(1)
        )
        let packet = try fixture.packet(at: fixture.now.addingTimeInterval(2), fill: 0x92)
        _ = try store.appendOpaqueRouteV2(
            OpaqueRouteAppendSubmissionV2(packet: packet, sendCapability: fixture.send),
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(2)
        )
        let stale = try fixture.sync(
            after: empty.nextCursor,
            at: fixture.now.addingTimeInterval(3_603),
            discriminator: 0x93
        )
        XCTAssertThrowsError(try store.syncOpaqueRouteV2(
            stale,
            confidentialTransport: true,
            receivedAt: fixture.now.addingTimeInterval(3_603)
        )) { error in
            XCTAssertEqual(error as? OpaqueRouteRelayStoreV2Error, .cursorExpired)
        }
    }

    func testCapabilityAdvertisementIsExplicit() {
        let disabled = RelayConfiguration(opaqueRouteRuntimeEnabled: false)
            .makeInfo().protocolCapabilities
        let enabled = RelayConfiguration(opaqueRouteRuntimeEnabled: true)
            .makeInfo().protocolCapabilities
        XCTAssertFalse(disabled?.supports(module: "nw.opaque-route", version: 2) == true)
        XCTAssertTrue(enabled?.supports(module: "nw.opaque-route", version: 2) == true)
    }

    func testStableRuntimeConfigurationDefaultsOnAndCanBeDisabled() {
        XCTAssertTrue(ServerConfig.parse(arguments: [], environment: [:]).opaqueRouteRuntimeEnabled)
        XCTAssertFalse(
            ServerConfig.parse(
                arguments: [],
                environment: ["NOCTWEAVE_OPAQUE_ROUTE_RUNTIME": "false"]
            ).opaqueRouteRuntimeEnabled
        )
        XCTAssertFalse(
            ServerConfig.parse(
                arguments: ["--opaque-route-runtime", "false"],
                environment: [:]
            ).opaqueRouteRuntimeEnabled
        )
    }
}

private struct Fixture {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let routeID = OpaqueReceiveRouteIDV2(rawValue: Data(repeating: 0x11, count: 32))
    let send = RouteSendCapabilityV2(rawValue: Data(repeating: 0x21, count: 32))
    let read = RouteReadCredentialV2(rawValue: Data(repeating: 0x22, count: 32))
    let renew = RouteRenewCapabilityV2(rawValue: Data(repeating: 0x23, count: 32))
    let teardown = RouteTeardownCapabilityV2(rawValue: Data(repeating: 0x24, count: 32))

    func create(
        at date: Date,
        leaseDuration: TimeInterval = 3_600
    ) throws -> OpaqueRouteCreateSubmissionV2 {
        let lease = OpaqueRouteLeaseV2(
            issuedAt: date,
            expiresAt: date.addingTimeInterval(leaseDuration),
            policy: OpaqueRoutePolicyV2(
                paddingBucket: .bytes4096,
                retentionBucket: .oneHour,
                quotaBucket: .packets64
            )
        )
        let idempotency = key(0x31)
        let dummy = proof(
            authority: .renew,
            digest: Data(repeating: 0, count: 32),
            at: date,
            nonce: 0x41
        )
        let provisional = OpaqueRouteCreateRequestV2(
            version: 2,
            routeID: routeID,
            sendCapabilityDigest: opaqueRouteCredentialDigest(.send, send.rawValue),
            readCredentialDigest: opaqueRouteCredentialDigest(.read, read.rawValue),
            renewCapabilityDigest: opaqueRouteCredentialDigest(.renew, renew.rawValue),
            teardownCapabilityDigest: opaqueRouteCredentialDigest(.teardown, teardown.rawValue),
            lease: lease,
            idempotencyKey: idempotency,
            authorization: dummy
        )
        let request = OpaqueRouteCreateRequestV2(
            version: provisional.version,
            routeID: provisional.routeID,
            sendCapabilityDigest: provisional.sendCapabilityDigest,
            readCredentialDigest: provisional.readCredentialDigest,
            renewCapabilityDigest: provisional.renewCapabilityDigest,
            teardownCapabilityDigest: provisional.teardownCapabilityDigest,
            lease: provisional.lease,
            idempotencyKey: provisional.idempotencyKey,
            authorization: try OpaqueRouteAuthorizationProofV2.make(
                authority: .renew,
                routeID: routeID,
                operationDigest: try XCTUnwrap(provisional.transitionDigest),
                authorizedAt: date,
                nonce: nonce(0x41),
                secret: renew.rawValue
            )
        )
        return OpaqueRouteCreateSubmissionV2(request: request, renewCapability: renew)
    }

    func packet(at date: Date, fill: UInt8) throws -> OpaqueRoutePacketV2 {
        let packetID = OpaqueRoutePacketIDV2(rawValue: Data(repeating: fill ^ 0xFF, count: 32))
        let frame = Data(repeating: fill, count: 4_096)
        let provisional = OpaqueRoutePacketV2(
            routeID: routeID,
            packetID: packetID,
            sealedFrame: frame,
            authorization: proof(
                authority: .send,
                digest: Data(repeating: 0, count: 32),
                at: date,
                nonce: fill
            )
        )
        return OpaqueRoutePacketV2(
            routeID: routeID,
            packetID: packetID,
            sealedFrame: frame,
            authorization: try OpaqueRouteAuthorizationProofV2.make(
                authority: .send,
                routeID: routeID,
                operationDigest: provisional.operationDigest,
                authorizedAt: date,
                nonce: nonce(fill),
                secret: send.rawValue
            )
        )
    }

    func sync(
        after cursor: OpaqueRouteCursorV2? = nil,
        at date: Date,
        discriminator: UInt8
    ) throws -> OpaqueRouteSyncSubmissionV2 {
        let provisional = OpaqueRouteSyncRequestV2(
            routeID: routeID,
            requestID: key(discriminator),
            after: cursor,
            limit: 32,
            authorization: proof(
                authority: .read,
                digest: Data(repeating: 0, count: 32),
                at: date,
                nonce: discriminator
            )
        )
        let request = OpaqueRouteSyncRequestV2(
            routeID: routeID,
            requestID: provisional.requestID,
            after: cursor,
            limit: provisional.limit,
            authorization: try OpaqueRouteAuthorizationProofV2.make(
                authority: .read,
                routeID: routeID,
                operationDigest: provisional.operationDigest,
                authorizedAt: date,
                nonce: nonce(discriminator),
                secret: read.rawValue
            )
        )
        return OpaqueRouteSyncSubmissionV2(request: request, readCredential: read)
    }

    func renewRoute(
        _ route: OpaqueReceiveRouteV2,
        at date: Date,
        through newExpiry: Date
    ) throws -> OpaqueRouteRenewSubmissionV2 {
        let provisional = OpaqueRouteRenewRequestV2(
            version: 2,
            routeID: routeID,
            renewalSequence: route.lease.renewalSequence + 1,
            previousTransitionDigest: route.lastTransitionDigest,
            newExpiry: newExpiry,
            authorizedAt: date,
            idempotencyKey: key(0x73),
            authorization: proof(
                authority: .renew,
                digest: Data(repeating: 0, count: 32),
                at: date,
                nonce: 0x74
            )
        )
        let request = OpaqueRouteRenewRequestV2(
            version: provisional.version,
            routeID: provisional.routeID,
            renewalSequence: provisional.renewalSequence,
            previousTransitionDigest: provisional.previousTransitionDigest,
            newExpiry: provisional.newExpiry,
            authorizedAt: provisional.authorizedAt,
            idempotencyKey: provisional.idempotencyKey,
            authorization: try OpaqueRouteAuthorizationProofV2.make(
                authority: .renew,
                routeID: routeID,
                operationDigest: try XCTUnwrap(provisional.transitionDigest),
                authorizedAt: date,
                nonce: nonce(0x74),
                secret: renew.rawValue
            )
        )
        return OpaqueRouteRenewSubmissionV2(request: request, renewCapability: renew)
    }

    func commit(
        cursor: OpaqueRouteCursorV2,
        at date: Date,
        discriminator: UInt8
    ) throws -> OpaqueRouteCommitSubmissionV2 {
        let provisional = OpaqueRouteCommitRequestV2(
            routeID: routeID,
            requestID: key(discriminator),
            cursor: cursor,
            authorization: proof(
                authority: .read,
                digest: Data(repeating: 0, count: 32),
                at: date,
                nonce: discriminator
            )
        )
        let request = OpaqueRouteCommitRequestV2(
            routeID: routeID,
            requestID: provisional.requestID,
            cursor: cursor,
            authorization: try OpaqueRouteAuthorizationProofV2.make(
                authority: .read,
                routeID: routeID,
                operationDigest: provisional.operationDigest,
                authorizedAt: date,
                nonce: nonce(discriminator),
                secret: read.rawValue
            )
        )
        return OpaqueRouteCommitSubmissionV2(request: request, readCredential: read)
    }

    func teardownRoute(
        _ route: OpaqueReceiveRouteV2,
        at date: Date
    ) throws -> OpaqueRouteTeardownSubmissionV2 {
        let provisional = OpaqueRouteTeardownRequestV2(
            version: 2,
            routeID: routeID,
            renewalSequence: route.lease.renewalSequence,
            previousTransitionDigest: route.lastTransitionDigest,
            authorizedAt: date,
            idempotencyKey: key(0x71),
            authorization: proof(
                authority: .teardown,
                digest: Data(repeating: 0, count: 32),
                at: date,
                nonce: 0x72
            )
        )
        let request = OpaqueRouteTeardownRequestV2(
            version: provisional.version,
            routeID: provisional.routeID,
            renewalSequence: provisional.renewalSequence,
            previousTransitionDigest: provisional.previousTransitionDigest,
            authorizedAt: provisional.authorizedAt,
            idempotencyKey: provisional.idempotencyKey,
            authorization: try OpaqueRouteAuthorizationProofV2.make(
                authority: .teardown,
                routeID: routeID,
                operationDigest: try XCTUnwrap(provisional.transitionDigest),
                authorizedAt: date,
                nonce: nonce(0x72),
                secret: teardown.rawValue
            )
        )
        return OpaqueRouteTeardownSubmissionV2(
            request: request,
            teardownCapability: teardown
        )
    }

    private func key(_ value: UInt8) -> OpaqueRouteIdempotencyKeyV2 {
        OpaqueRouteIdempotencyKeyV2(rawValue: Data(repeating: value, count: 32))
    }

    private func nonce(_ value: UInt8) -> OpaqueRouteProofNonceV2 {
        OpaqueRouteProofNonceV2(rawValue: Data(repeating: value, count: 32))
    }

    private func proof(
        authority: OpaqueRouteAuthorityV2,
        digest: Data,
        at date: Date,
        nonce value: UInt8
    ) -> OpaqueRouteAuthorizationProofV2 {
        OpaqueRouteAuthorizationProofV2(
            authority: authority,
            nonce: nonce(value),
            operationDigest: digest,
            authorizedAt: date,
            mac: Data(repeating: 0, count: 32)
        )
    }
}
