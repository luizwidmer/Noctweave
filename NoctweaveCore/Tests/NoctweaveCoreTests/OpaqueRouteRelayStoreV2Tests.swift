import Foundation
import XCTest
@testable import NoctweaveCore

final class OpaqueRouteRelayStoreV2Tests: XCTestCase {
    private let origin = Date(timeIntervalSince1970: 300_000)

    func testAppendSyncCommitAndExactExpiredRetries() async throws {
        let fixture = try await makeFixture()
        let first = try makePacket(
            Data("first".utf8),
            fixture: fixture,
            authorizedAt: origin.addingTimeInterval(10)
        )
        let second = try makePacket(
            Data("second".utf8),
            fixture: fixture,
            authorizedAt: origin.addingTimeInterval(10)
        )
        let firstReceipt = try await fixture.store.append(
            first,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(10)
        )
        _ = try await fixture.store.append(
            second,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(10)
        )

        XCTAssertEqual(firstReceipt.packetID, first.packetID)
        XCTAssertEqual(firstReceipt.acceptedCursor.rawValue.count, 68)
        XCTAssertEqual(String(describing: firstReceipt.acceptedCursor), "OpaqueRouteCursorV2(<redacted>)")
        XCTAssertTrue(Mirror(reflecting: firstReceipt.acceptedCursor).children.isEmpty)
        XCTAssertFalse(firstReceipt.acceptedCursor.rawValue.containsSubsequence(
            fixture.material.routeID.rawValue
        ))

        let syncRequest = try fixture.material.makeSyncRequest(
            after: nil,
            limit: 1,
            authorizedAt: origin.addingTimeInterval(20)
        )
        let firstPage = try await fixture.store.sync(
            syncRequest,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(20)
        )
        XCTAssertEqual(firstPage.packets.map(\.packet), [first])
        XCTAssertEqual(firstPage.packets.map(\.routeRevision), [0])
        XCTAssertTrue(firstPage.hasMore)

        let expiredProofRetry = try await fixture.store.sync(
            syncRequest,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(400)
        )
        XCTAssertEqual(expiredProofRetry, firstPage)

        let appendRetry = try await fixture.store.append(
            first,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(401)
        )
        XCTAssertEqual(appendRetry, firstReceipt)

        let commitRequest = try fixture.material.makeCommitRequest(
            cursor: firstPage.nextCursor,
            authorizedAt: origin.addingTimeInterval(401)
        )
        _ = try await fixture.store.commit(
            commitRequest,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(401)
        )
        await XCTAssertOpaqueRouteStoreThrows(try await fixture.store.commit(
            commitRequest,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(800)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteV2Error, .authorizationExpired)
        }
        let refreshedCommit = try fixture.material.makeCommitRequest(
            cursor: firstPage.nextCursor,
            authorizedAt: origin.addingTimeInterval(800)
        )
        _ = try await fixture.store.commit(
            refreshedCommit,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(800)
        )

        let secondRequest = try fixture.material.makeSyncRequest(
            after: nil,
            limit: 8,
            authorizedAt: origin.addingTimeInterval(800)
        )
        let secondPage = try await fixture.store.sync(
            secondRequest,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(800)
        )
        XCTAssertEqual(secondPage.packets.map(\.packet), [second])
        XCTAssertEqual(secondPage.packets.map(\.routeRevision), [0])
        XCTAssertFalse(secondPage.hasMore)

        let finish = try fixture.material.makeCommitRequest(
            cursor: secondPage.nextCursor,
            authorizedAt: origin.addingTimeInterval(801)
        )
        _ = try await fixture.store.commit(
            finish,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(801)
        )
        let emptyRequest = try fixture.material.makeSyncRequest(
            after: nil,
            limit: 8,
            authorizedAt: origin.addingTimeInterval(802)
        )
        let empty = try await fixture.store.sync(
            emptyRequest,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(802)
        )
        XCTAssertTrue(empty.packets.isEmpty)
        XCTAssertFalse(empty.hasMore)
    }

    func testPacketIdentifierConflictRequiresValidAuthorization() async throws {
        let fixture = try await makeFixture()
        let first = try makePacket(
            Data("retained".utf8),
            fixture: fixture,
            authorizedAt: origin.addingTimeInterval(10)
        )
        let other = try makePacket(
            Data("different".utf8),
            fixture: fixture,
            authorizedAt: origin.addingTimeInterval(11)
        )
        _ = try await fixture.store.append(
            first,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(10)
        )

        let operationDigest = OpaqueRoutePacketV2.operationDigest(
            routeID: fixture.material.routeID,
            packetID: first.packetID,
            sealedFrame: other.sealedFrame
        )
        let proof = try fixture.material.makeSendAuthorization(
            operationDigest: operationDigest,
            authorizedAt: origin.addingTimeInterval(11)
        )
        let conflict = OpaqueRoutePacketV2(
            routeID: fixture.material.routeID,
            packetID: first.packetID,
            sealedFrame: other.sealedFrame,
            authorization: proof
        )
        await XCTAssertOpaqueRouteStoreThrows(try await fixture.store.append(
            conflict,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(11)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteRelayStoreV2Error, .packetIdentifierConflict)
        }
        await XCTAssertOpaqueRouteStoreThrows(try await fixture.store.append(
            conflict,
            presentedCapability: RouteSendCapabilityV2.generate(),
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(11)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteV2Error, .invalidAuthorization)
        }
    }

    func testSyncCarriesRouteRevisionAcrossRenewal() async throws {
        let fixture = try await makeFixture()
        let before = try makePacket(
            Data("before-renewal".utf8),
            fixture: fixture,
            authorizedAt: origin.addingTimeInterval(10),
            routeRevision: 0
        )
        _ = try await fixture.store.append(
            before,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(10)
        )
        let renewal = try fixture.material.makeRenewRequest(
            current: fixture.route,
            newExpiry: origin.addingTimeInterval(8_000),
            authorizedAt: origin.addingTimeInterval(20),
            idempotencyKey: .generate()
        )
        let renewed = try await fixture.store.renew(
            renewal,
            presentedCapability: fixture.material.renewCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(20)
        )
        XCTAssertEqual(renewed.lease.renewalSequence, 1)

        let after = try makePacket(
            Data("after-renewal".utf8),
            fixture: fixture,
            authorizedAt: origin.addingTimeInterval(21),
            routeRevision: 1
        )
        _ = try await fixture.store.append(
            after,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(21)
        )
        let request = try fixture.material.makeSyncRequest(
            after: nil,
            limit: 8,
            authorizedAt: origin.addingTimeInterval(22)
        )
        let response = try await fixture.store.sync(
            request,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(22)
        )
        XCTAssertEqual(response.packets.map(\.routeRevision), [0, 1])
        let openedBefore = try response.packets[0].packet.open(
            payloadKey: fixture.payloadKey,
            routeRevision: response.packets[0].routeRevision
        )
        let openedAfter = try response.packets[1].packet.open(
            payloadKey: fixture.payloadKey,
            routeRevision: response.packets[1].routeRevision
        )
        XCTAssertEqual(openedBefore.payload, Data("before-renewal".utf8))
        XCTAssertEqual(openedAfter.payload, Data("after-renewal".utf8))
        XCTAssertThrowsError(try response.packets[1].packet.open(
            payloadKey: fixture.payloadKey,
            routeRevision: 0
        )) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .decryptionFailed)
        }
    }

    func testCursorAuthenticationAndRequestIdentifierConflict() async throws {
        let fixture = try await makeFixture()
        let packet = try makePacket(
            Data("cursor-bound".utf8),
            fixture: fixture,
            authorizedAt: origin.addingTimeInterval(10)
        )
        let receipt = try await fixture.store.append(
            packet,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(10)
        )

        var tamperedBytes = receipt.acceptedCursor.rawValue
        tamperedBytes[tamperedBytes.startIndex + 20] ^= 0x80
        let tampered = OpaqueRouteCursorV2(rawValue: tamperedBytes)
        let tamperedCommit = try fixture.material.makeCommitRequest(
            cursor: tampered,
            authorizedAt: origin.addingTimeInterval(20)
        )
        await XCTAssertOpaqueRouteStoreThrows(try await fixture.store.commit(
            tamperedCommit,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(20)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteRelayStoreV2Error, .invalidCursor)
        }

        let requestID = OpaqueRouteIdempotencyKeyV2.generate()
        let first = try fixture.material.makeSyncRequest(
            after: nil,
            limit: 1,
            requestID: requestID,
            authorizedAt: origin.addingTimeInterval(21)
        )
        _ = try await fixture.store.sync(
            first,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(21)
        )
        let conflict = try fixture.material.makeSyncRequest(
            after: nil,
            limit: 2,
            requestID: requestID,
            authorizedAt: origin.addingTimeInterval(22)
        )
        await XCTAssertOpaqueRouteStoreThrows(try await fixture.store.sync(
            conflict,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(22)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteRelayStoreV2Error, .requestIdentifierConflict)
        }
        await XCTAssertOpaqueRouteStoreThrows(try await fixture.store.sync(
            conflict,
            presentedCredential: RouteReadCredentialV2.generate(),
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(22)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteV2Error, .invalidAuthorization)
        }
    }

    func testTTLAdvancesRetentionFloorAndExpiresOldCursor() async throws {
        let fixture = try await makeFixture(leaseDuration: 7_200)
        let initialRequest = try fixture.material.makeSyncRequest(
            after: nil,
            limit: 8,
            authorizedAt: origin.addingTimeInterval(1)
        )
        let initial = try await fixture.store.sync(
            initialRequest,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(1)
        )
        XCTAssertTrue(initial.packets.isEmpty)

        let packet = try makePacket(
            Data("expires".utf8),
            fixture: fixture,
            authorizedAt: origin.addingTimeInterval(2)
        )
        let receipt = try await fixture.store.append(
            packet,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(2)
        )

        let afterExpiry = origin.addingTimeInterval(3_603)
        let expiredCursorRequest = try fixture.material.makeSyncRequest(
            after: initial.nextCursor,
            limit: 8,
            authorizedAt: afterExpiry
        )
        await XCTAssertOpaqueRouteStoreThrows(try await fixture.store.sync(
            expiredCursorRequest,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: afterExpiry
        )) {
            XCTAssertEqual($0 as? OpaqueRouteRelayStoreV2Error, .cursorExpired)
        }

        let currentRequest = try fixture.material.makeSyncRequest(
            after: nil,
            limit: 8,
            authorizedAt: afterExpiry
        )
        let current = try await fixture.store.sync(
            currentRequest,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: afterExpiry
        )
        XCTAssertTrue(current.packets.isEmpty)
        XCTAssertFalse(current.hasMore)

        await XCTAssertOpaqueRouteStoreThrows(try await fixture.store.append(
            packet,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: afterExpiry
        )) {
            XCTAssertEqual($0 as? OpaqueRouteV2Error, .authorizationExpired)
        }
        let replacement = try makePacket(
            Data("fresh".utf8),
            fixture: fixture,
            authorizedAt: afterExpiry
        )
        let replacementReceipt = try await fixture.store.append(
            replacement,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: afterExpiry
        )
        XCTAssertNotEqual(replacementReceipt.packetID, receipt.packetID)
    }

    func testQuotaAndPaddingPolicyAreEnforcedWithoutConsumingFailedProof() async throws {
        let fixture = try await makeFixture()
        let wrongBucket = try XCTUnwrap(OpaqueRouteSealedBundleV2.seal(
            Data("wrong-bucket".utf8),
            routeRevision: 0,
            paddingBucket: .bytes16384,
            payloadKey: fixture.payloadKey,
            routeCapabilities: fixture.material,
            authorizedAt: origin.addingTimeInterval(5)
        ).packets.first)
        await XCTAssertOpaqueRouteStoreThrows(try await fixture.store.append(
            wrongBucket,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(5)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteRelayStoreV2Error, .invalidRequest)
        }

        var lastReceipt: OpaqueRouteAppendReceiptV2?
        for index in 0..<64 {
            let packet = try makePacket(
                Data([UInt8(index)]),
                fixture: fixture,
                authorizedAt: origin.addingTimeInterval(10)
            )
            lastReceipt = try await fixture.store.append(
                packet,
                presentedCapability: fixture.material.sendCapability,
                confidentialTransport: true,
                receivedAt: origin.addingTimeInterval(10)
            )
        }
        let overflow = try makePacket(
            Data([0xFF]),
            fixture: fixture,
            authorizedAt: origin.addingTimeInterval(10)
        )
        await XCTAssertOpaqueRouteStoreThrows(try await fixture.store.append(
            overflow,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(10)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteRelayStoreV2Error, .routeQuotaExceeded)
        }

        let commit = try fixture.material.makeCommitRequest(
            cursor: try XCTUnwrap(lastReceipt).acceptedCursor,
            authorizedAt: origin.addingTimeInterval(11)
        )
        _ = try await fixture.store.commit(
            commit,
            presentedCredential: fixture.material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(11)
        )
        _ = try await fixture.store.append(
            overflow,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(12)
        )
    }

    func testTeardownIsPermanentAndExactlyRetryable() async throws {
        let fixture = try await makeFixture()
        let acceptedPacket = try makePacket(
            Data("accepted-before-teardown".utf8),
            fixture: fixture,
            authorizedAt: origin.addingTimeInterval(5)
        )
        _ = try await fixture.store.append(
            acceptedPacket,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(5)
        )
        let teardown = try fixture.material.makeTeardownRequest(
            current: fixture.route,
            authorizedAt: origin.addingTimeInterval(10),
            idempotencyKey: .generate()
        )
        let tombstone = try await fixture.store.teardown(
            teardown,
            presentedCapability: fixture.material.teardownCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(10)
        )
        XCTAssertEqual(tombstone.status, .tornDown)
        let retry = try await fixture.store.teardown(
            teardown,
            presentedCapability: fixture.material.teardownCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(400)
        )
        XCTAssertEqual(retry, tombstone)

        await XCTAssertOpaqueRouteStoreThrows(try await fixture.store.append(
            acceptedPacket,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(400)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteV2Error, .routeTornDown)
        }

        await XCTAssertOpaqueRouteStoreThrows(try await fixture.store.create(
            fixture.createRequest,
            presentedCapability: fixture.material.renewCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(401)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteV2Error, .routeTornDown)
        }
        let packet = try makePacket(
            Data("blocked".utf8),
            fixture: fixture,
            authorizedAt: origin.addingTimeInterval(401)
        )
        await XCTAssertOpaqueRouteStoreThrows(try await fixture.store.append(
            packet,
            presentedCapability: fixture.material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(401)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteV2Error, .routeTornDown)
        }
    }

    func testEveryOperationRequiresConfidentialTransport() async throws {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let policy = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .oneHour,
            quotaBucket: .packets64
        )
        let lease = try OpaqueRouteLeaseV2(
            issuedAt: origin,
            expiresAt: origin.addingTimeInterval(7_200),
            policy: policy
        )
        let create = try material.makeCreateRequest(
            lease: lease,
            idempotencyKey: .generate()
        )
        let store = OpaqueRouteRelayStoreV2()
        await XCTAssertOpaqueRouteStoreThrows(try await store.create(
            create,
            presentedCapability: material.renewCapability,
            confidentialTransport: false,
            receivedAt: origin
        )) {
            XCTAssertEqual($0 as? OpaqueRouteV2Error, .confidentialTransportRequired)
        }
        let route = try await store.create(
            create,
            presentedCapability: material.renewCapability,
            confidentialTransport: true,
            receivedAt: origin
        )
        let key = OpaqueRoutePayloadKeyV2.generate()
        let packet = try XCTUnwrap(OpaqueRouteSealedBundleV2.seal(
            Data("transport".utf8),
            routeRevision: 0,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: origin.addingTimeInterval(10)
        ).packets.first)
        await XCTAssertOpaqueRouteStoreThrows(try await store.append(
            packet,
            presentedCapability: material.sendCapability,
            confidentialTransport: false,
            receivedAt: origin.addingTimeInterval(10)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteV2Error, .confidentialTransportRequired)
        }
        let receipt = try await store.append(
            packet,
            presentedCapability: material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(10)
        )
        let sync = try material.makeSyncRequest(
            after: nil,
            limit: 1,
            authorizedAt: origin.addingTimeInterval(11)
        )
        await XCTAssertOpaqueRouteStoreThrows(try await store.sync(
            sync,
            presentedCredential: material.readCredential,
            confidentialTransport: false,
            receivedAt: origin.addingTimeInterval(11)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteV2Error, .confidentialTransportRequired)
        }
        let commit = try material.makeCommitRequest(
            cursor: receipt.acceptedCursor,
            authorizedAt: origin.addingTimeInterval(12)
        )
        await XCTAssertOpaqueRouteStoreThrows(try await store.commit(
            commit,
            presentedCredential: material.readCredential,
            confidentialTransport: false,
            receivedAt: origin.addingTimeInterval(12)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteV2Error, .confidentialTransportRequired)
        }
        let renew = try material.makeRenewRequest(
            current: route,
            newExpiry: origin.addingTimeInterval(8_000),
            authorizedAt: origin.addingTimeInterval(13),
            idempotencyKey: .generate()
        )
        await XCTAssertOpaqueRouteStoreThrows(try await store.renew(
            renew,
            presentedCapability: material.renewCapability,
            confidentialTransport: false,
            receivedAt: origin.addingTimeInterval(13)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteV2Error, .confidentialTransportRequired)
        }
        let teardown = try material.makeTeardownRequest(
            current: route,
            authorizedAt: origin.addingTimeInterval(14),
            idempotencyKey: .generate()
        )
        await XCTAssertOpaqueRouteStoreThrows(try await store.teardown(
            teardown,
            presentedCapability: material.teardownCapability,
            confidentialTransport: false,
            receivedAt: origin.addingTimeInterval(14)
        )) {
            XCTAssertEqual($0 as? OpaqueRouteV2Error, .confidentialTransportRequired)
        }
    }

    private struct Fixture {
        let store: OpaqueRouteRelayStoreV2
        let material: OpaqueRouteClientCapabilityMaterialV2
        let payloadKey: OpaqueRoutePayloadKeyV2
        let createRequest: OpaqueRouteCreateRequestV2
        let route: OpaqueReceiveRouteV2
    }

    private func makeFixture(leaseDuration: TimeInterval = 7_200) async throws -> Fixture {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let policy = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .oneHour,
            quotaBucket: .packets64
        )
        let lease = try OpaqueRouteLeaseV2(
            issuedAt: origin,
            expiresAt: origin.addingTimeInterval(leaseDuration),
            policy: policy
        )
        let request = try material.makeCreateRequest(
            lease: lease,
            idempotencyKey: .generate()
        )
        let store = OpaqueRouteRelayStoreV2()
        let route = try await store.create(
            request,
            presentedCapability: material.renewCapability,
            confidentialTransport: true,
            receivedAt: origin
        )
        return Fixture(
            store: store,
            material: material,
            payloadKey: .generate(),
            createRequest: request,
            route: route
        )
    }

    private func makePacket(
        _ payload: Data,
        fixture: Fixture,
        authorizedAt: Date,
        routeRevision: UInt64 = 0
    ) throws -> OpaqueRoutePacketV2 {
        try XCTUnwrap(OpaqueRouteSealedBundleV2.seal(
            payload,
            routeRevision: routeRevision,
            paddingBucket: .bytes4096,
            payloadKey: fixture.payloadKey,
            routeCapabilities: fixture.material,
            authorizedAt: authorizedAt
        ).packets.first)
    }
}

private extension Data {
    func containsSubsequence(_ candidate: Data) -> Bool {
        guard !candidate.isEmpty, candidate.count <= count else { return false }
        for start in 0...(count - candidate.count) {
            if self[start..<(start + candidate.count)] == candidate[...] {
                return true
            }
        }
        return false
    }
}

private func XCTAssertOpaqueRouteStoreThrows<T>(
    _ expression: @autoclosure () async throws -> T,
    _ errorHandler: (Error) -> Void = { _ in },
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected expression to throw", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}
