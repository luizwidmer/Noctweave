import CryptoKit
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2RouteIntentTests: XCTestCase {
    func testCapabilityRoutesRequireConfidentialTransportExceptLiteralLoopback() {
        let handle = RelationshipInstallationHandle(
            rawValue: Data(repeating: 0x31, count: 32).base64EncodedString()
        )
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let insecureRemote = RelationshipRouteV2.active(
            id: routeId(byte: 0xE1),
            installationHandle: handle,
            relay: RelayEndpoint(host: "relay.example", port: 9340, useTLS: false),
            inboxCapability: capability(byte: 0xE2),
            at: now
        )
        let secureRemote = RelationshipRouteV2.active(
            id: routeId(byte: 0xE3),
            installationHandle: handle,
            relay: RelayEndpoint(host: "relay.example", port: 9340, useTLS: true),
            inboxCapability: capability(byte: 0xE4),
            at: now
        )
        let localDevelopment = RelationshipRouteV2.active(
            id: routeId(byte: 0xE5),
            installationHandle: handle,
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340, useTLS: false),
            inboxCapability: capability(byte: 0xE6),
            at: now
        )

        XCTAssertFalse(insecureRemote.isStructurallyValid)
        XCTAssertTrue(secureRemote.isStructurallyValid)
        XCTAssertTrue(localDevelopment.isStructurallyValid)
    }

    func testDeliveryStateRequiresMonotonicStateAndProcessingTime() async throws {
        let handle = RelationshipInstallationHandle(rawValue: Data(repeating: 0x31, count: 32).base64EncodedString())
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        var record = DeliveryStateRecord(
            eventId: UUID(),
            destinationInstallation: handle,
            state: .locallyPersisted,
            updatedAt: start
        )
        XCTAssertTrue(record.isStructurallyValid)
        XCTAssertTrue(record.advance(to: .relayAccepted, at: start.addingTimeInterval(2)))
        XCTAssertFalse(record.advance(to: .locallyPersisted, at: start.addingTimeInterval(3)))
        XCTAssertFalse(record.advance(to: .peerEndpointStored, at: start.addingTimeInterval(1)))
        XCTAssertEqual(record.state, .relayAccepted)
        XCTAssertEqual(record.updatedAt, start.addingTimeInterval(2))
    }

    func testRouteRotationIsSignedIdempotentAndMakeBeforeBreak() throws {
        let signingKey = try SigningKeyPair.generate()
        let relationshipId = UUID(uuidString: "10000000-0000-0000-0000-000000000001")!
        let handle = RelationshipInstallationHandle.generate(
            identityGenerationId: UUID(uuidString: "10000000-0000-0000-0000-000000000002")!,
            installationId: UUID(uuidString: "10000000-0000-0000-0000-000000000003")!,
            relationshipId: relationshipId,
            nonce: UUID(uuidString: "10000000-0000-0000-0000-000000000004")!
        )
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let oldRoute = RelationshipRouteV2.active(
            id: routeId(byte: 1),
            installationHandle: handle,
            relay: relay(host: "old-relay.example"),
            inboxCapability: capability(byte: 11),
            at: start
        )
        let initial = try RelationshipRouteSetV2.createInitial(
            relationshipId: relationshipId,
            ownerInstallationHandle: handle,
            route: oldRoute,
            signingKey: signingKey,
            issuedAt: start
        )
        XCTAssertTrue(initial.isStructurallyValid)
        XCTAssertTrue(initial.verify(ownerSigningPublicKey: signingKey.publicKeyData))
        XCTAssertEqual(initial.usableRoutes(at: start).map(\.id), [oldRoute.id])

        let stagedAt = start.addingTimeInterval(10)
        let newRoute = RelationshipRouteV2.testing(
            id: routeId(byte: 2),
            installationHandle: handle,
            relay: relay(host: "new-relay.example"),
            inboxCapability: capability(byte: 12),
            at: stagedAt
        )
        let staged = try XCTUnwrap(try initial.addingTestingRoute(
            newRoute,
            signingKey: signingKey,
            issuedAt: stagedAt
        ))
        XCTAssertEqual(staged.revision, 2)
        XCTAssertEqual(staged.previousDigest, initial.digest)
        XCTAssertEqual(staged.usableRoutes(at: stagedAt).map(\.id), [oldRoute.id])
        XCTAssertEqual(
            try staged.addingTestingRoute(newRoute, signingKey: signingKey, issuedAt: stagedAt),
            staged
        )

        let testedAt = stagedAt.addingTimeInterval(5)
        let tested = try XCTUnwrap(try staged.markingRouteTested(
            newRoute.id,
            signingKey: signingKey,
            testedAt: testedAt
        ))
        XCTAssertEqual(
            try tested.markingRouteTested(newRoute.id, signingKey: signingKey, testedAt: testedAt),
            tested
        )

        let promotedAt = testedAt.addingTimeInterval(5)
        let overlapUntil = promotedAt.addingTimeInterval(60)
        let promoted = try XCTUnwrap(try tested.promotingTestedRoute(
            newRoute.id,
            replacing: [oldRoute.id],
            overlapUntil: overlapUntil,
            signingKey: signingKey,
            issuedAt: promotedAt
        ))
        XCTAssertEqual(promoted.routes.first(where: { $0.id == oldRoute.id })?.state, .draining)
        XCTAssertEqual(promoted.routes.first(where: { $0.id == newRoute.id })?.state, .active)
        XCTAssertEqual(Set(promoted.usableRoutes(at: promotedAt).map(\.id)), [oldRoute.id, newRoute.id])
        XCTAssertNil(try promoted.revokingDrainedRoute(
            oldRoute.id,
            signingKey: signingKey,
            issuedAt: overlapUntil.addingTimeInterval(-1)
        ))

        let retired = try XCTUnwrap(try promoted.revokingDrainedRoute(
            oldRoute.id,
            signingKey: signingKey,
            issuedAt: overlapUntil
        ))
        XCTAssertEqual(retired.routes.first(where: { $0.id == oldRoute.id })?.state, .revoked)
        XCTAssertEqual(retired.usableRoutes(at: overlapUntil).map(\.id), [newRoute.id])
        XCTAssertTrue(retired.verify(ownerSigningPublicKey: signingKey.publicKeyData))

        let encoded = try NoctweaveCoder.encode(retired, sortedKeys: true)
        let decoded = try NoctweaveCoder.decode(RelationshipRouteSetV2.self, from: encoded)
        XCTAssertEqual(decoded, retired)
        XCTAssertTrue(decoded.verify(ownerSigningPublicKey: signingKey.publicKeyData))
    }

    func testRouteSetRejectsTamperingDuplicatesAndRouteIdReuse() throws {
        let signingKey = try SigningKeyPair.generate()
        let relationshipId = UUID(uuidString: "20000000-0000-0000-0000-000000000001")!
        let handle = RelationshipInstallationHandle.generate(
            identityGenerationId: UUID(uuidString: "20000000-0000-0000-0000-000000000002")!,
            installationId: UUID(uuidString: "20000000-0000-0000-0000-000000000003")!,
            relationshipId: relationshipId,
            nonce: UUID(uuidString: "20000000-0000-0000-0000-000000000004")!
        )
        let start = Date(timeIntervalSince1970: 1_700_100_000)
        let route = RelationshipRouteV2.active(
            id: routeId(byte: 3),
            installationHandle: handle,
            relay: relay(host: "relay.example"),
            inboxCapability: capability(byte: 13),
            at: start
        )
        let original = try RelationshipRouteSetV2.createInitial(
            relationshipId: relationshipId,
            ownerInstallationHandle: handle,
            route: route,
            signingKey: signingKey,
            issuedAt: start
        )
        let tamperedRoute = RelationshipRouteV2.active(
            id: route.id,
            installationHandle: handle,
            relay: route.relay,
            inboxCapability: route.inboxCapability,
            priority: 1,
            at: start
        )
        let tampered = RelationshipRouteSetV2(
            relationshipId: relationshipId,
            ownerInstallationHandle: handle,
            revision: original.revision,
            previousDigest: original.previousDigest,
            routes: [tamperedRoute],
            issuedAt: original.issuedAt,
            signature: original.signature
        )
        XCTAssertTrue(tampered.isStructurallyValid)
        XCTAssertFalse(tampered.verify(ownerSigningPublicKey: signingKey.publicKeyData))

        let duplicated = RelationshipRouteSetV2(
            relationshipId: relationshipId,
            ownerInstallationHandle: handle,
            revision: original.revision,
            previousDigest: original.previousDigest,
            routes: [route, route],
            issuedAt: original.issuedAt,
            signature: original.signature
        )
        XCTAssertFalse(duplicated.isStructurallyValid)

        let reusedId = RelationshipRouteV2.testing(
            id: route.id,
            installationHandle: handle,
            relay: relay(host: "attacker.example"),
            inboxCapability: capability(byte: 14),
            at: start.addingTimeInterval(1)
        )
        XCTAssertNil(try original.addingTestingRoute(
            reusedId,
            signingKey: signingKey,
            issuedAt: start.addingTimeInterval(1)
        ))
    }

    func testProtocolIntentLifecycleAndAttemptReplayAreIdempotent() throws {
        let createdAt = Date(timeIntervalSince1970: 1_700_200_000)
        let intentId = UUID(uuidString: "30000000-0000-0000-0000-000000000001")!
        let dependency = UUID(uuidString: "30000000-0000-0000-0000-000000000002")!
        let attemptId = UUID(uuidString: "30000000-0000-0000-0000-000000000003")!
        let intent = ProtocolIntentV2.prepare(
            id: intentId,
            kind: .rotateRoute,
            targetIdentifier: Data(repeating: 7, count: 32),
            expectedEpoch: 9,
            idempotencyKey: ProtocolIntentIdempotencyKeyV2(rawValue: Data(repeating: 8, count: 32)),
            payloadDigest: digest("route rotation"),
            dependencies: [dependency],
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(300)
        )
        XCTAssertTrue(intent.isStructurallyValid)
        XCTAssertFalse(intent.isReady(completedIntentIds: [], at: createdAt))
        XCTAssertTrue(intent.isReady(completedIntentIds: [dependency], at: createdAt))

        let attempting = try XCTUnwrap(intent.beginningAttempt(
            id: attemptId,
            completedIntentIds: [dependency],
            at: createdAt.addingTimeInterval(1)
        ))
        XCTAssertEqual(attempting.attemptCount, 1)
        XCTAssertEqual(
            attempting.beginningAttempt(
                id: attemptId,
                completedIntentIds: [dependency],
                at: createdAt.addingTimeInterval(2)
            ),
            attempting
        )
        XCTAssertNil(attempting.advancing(
            to: .committed,
            attemptId: attemptId,
            at: createdAt.addingTimeInterval(2)
        ))

        let published = try XCTUnwrap(attempting.advancing(
            to: .published,
            attemptId: attemptId,
            at: createdAt.addingTimeInterval(2)
        ))
        XCTAssertEqual(
            published.advancing(
                to: .published,
                attemptId: attemptId,
                at: createdAt.addingTimeInterval(3)
            ),
            published
        )
        let committed = try XCTUnwrap(published.advancing(
            to: .committed,
            attemptId: attemptId,
            at: createdAt.addingTimeInterval(3)
        ))
        let finalized = try XCTUnwrap(committed.advancing(
            to: .finalized,
            attemptId: attemptId,
            at: createdAt.addingTimeInterval(4)
        ))
        XCTAssertTrue(finalized.isStructurallyValid)
        XCTAssertTrue(finalized.state.isTerminal)
        XCTAssertFalse(finalized.isReady(completedIntentIds: [dependency], at: createdAt.addingTimeInterval(5)))

        let encoded = try NoctweaveCoder.encode(finalized, sortedKeys: true)
        XCTAssertEqual(
            try NoctweaveCoder.decode(ProtocolIntentV2.self, from: encoded),
            finalized
        )
    }

    func testProtocolIntentRetryDeadlinePermanentFailureAndBounds() throws {
        let createdAt = Date(timeIntervalSince1970: 1_700_300_000)
        let attemptOne = UUID(uuidString: "40000000-0000-0000-0000-000000000001")!
        let attemptTwo = UUID(uuidString: "40000000-0000-0000-0000-000000000002")!
        let intent = ProtocolIntentV2.prepare(
            kind: .sendEvent,
            payloadDigest: digest("ciphertext event"),
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(100)
        )
        let attempting = try XCTUnwrap(intent.beginningAttempt(
            id: attemptOne,
            completedIntentIds: [],
            at: createdAt.addingTimeInterval(1)
        ))
        let failedAt = createdAt.addingTimeInterval(2)
        let retryAt = createdAt.addingTimeInterval(20)
        let waiting = try XCTUnwrap(attempting.recordingTransientFailure(
            attemptId: attemptOne,
            errorClass: .networkUnavailable,
            retryNotBefore: retryAt,
            at: failedAt
        ))
        XCTAssertTrue(waiting.isStructurallyValid)
        XCTAssertFalse(waiting.isReady(completedIntentIds: [], at: retryAt.addingTimeInterval(-1)))
        XCTAssertEqual(
            waiting.recordingTransientFailure(
                attemptId: attemptOne,
                errorClass: .networkUnavailable,
                retryNotBefore: retryAt,
                at: failedAt
            ),
            waiting
        )

        let retrying = try XCTUnwrap(waiting.beginningAttempt(
            id: attemptTwo,
            completedIntentIds: [],
            at: retryAt
        ))
        XCTAssertEqual(retrying.attemptCount, 2)
        XCTAssertNil(retrying.lastErrorClass)
        XCTAssertNil(retrying.nextAttemptNotBefore)
        let rejected = try XCTUnwrap(retrying.failingPermanently(
            errorClass: .authorizationRejected,
            at: retryAt.addingTimeInterval(1)
        ))
        XCTAssertTrue(rejected.isStructurallyValid)
        XCTAssertEqual(rejected.state, .permanentFailure)

        let expiring = ProtocolIntentV2.prepare(
            kind: .uploadBlob,
            payloadDigest: digest("encrypted blob"),
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(5)
        )
        let expired = try XCTUnwrap(expiring.expiring(at: createdAt.addingTimeInterval(5)))
        XCTAssertTrue(expired.isStructurallyValid)
        XCTAssertEqual(expired.lastErrorClass, .expired)
        let rearmedExpiredAt = createdAt.addingTimeInterval(10)
        let rearmedExpired = try XCTUnwrap(expired.rearming(at: rearmedExpiredAt))
        XCTAssertEqual(
            rearmedExpired.expiresAt,
            rearmedExpiredAt.addingTimeInterval(5)
        )
        XCTAssertTrue(rearmedExpired.isReady(completedIntentIds: [], at: rearmedExpiredAt))

        let duplicateDependency = UUID(uuidString: "40000000-0000-0000-0000-000000000003")!
        let invalid = ProtocolIntentV2(
            id: UUID(uuidString: "40000000-0000-0000-0000-000000000004")!,
            kind: .sendEvent,
            idempotencyKey: ProtocolIntentIdempotencyKeyV2(rawValue: Data(repeating: 1, count: 32)),
            payloadDigest: digest("payload"),
            dependencies: [duplicateDependency, duplicateDependency],
            createdAt: createdAt,
            updatedAt: createdAt
        )
        XCTAssertFalse(invalid.isStructurallyValid)

        let maximumAttempts = ProtocolIntentV2(
            id: UUID(),
            kind: .sendEvent,
            idempotencyKey: ProtocolIntentIdempotencyKeyV2(rawValue: Data(repeating: 2, count: 32)),
            payloadDigest: digest("bounded retry"),
            state: .prepared,
            attemptCount: UInt32(NoctweaveArchitectureV2.maximumIntentAttempts),
            lastAttemptId: attemptTwo,
            lastAttemptAt: retryAt,
            createdAt: createdAt,
            updatedAt: retryAt
        )
        XCTAssertTrue(maximumAttempts.isStructurallyValid)
        XCTAssertFalse(maximumAttempts.isReady(completedIntentIds: [], at: retryAt))
        XCTAssertNil(maximumAttempts.beginningAttempt(
            id: UUID(),
            completedIntentIds: [],
            at: retryAt.addingTimeInterval(1)
        ))
        let rearmedAt = retryAt.addingTimeInterval(2)
        let rearmed = try XCTUnwrap(maximumAttempts.rearming(at: rearmedAt))
        XCTAssertTrue(rearmed.isStructurallyValid)
        XCTAssertEqual(rearmed.id, maximumAttempts.id)
        XCTAssertEqual(rearmed.idempotencyKey, maximumAttempts.idempotencyKey)
        XCTAssertEqual(rearmed.payloadDigest, maximumAttempts.payloadDigest)
        XCTAssertEqual(rearmed.state, .prepared)
        XCTAssertEqual(rearmed.attemptCount, 0)
        XCTAssertNotNil(rearmed.beginningAttempt(
            id: UUID(),
            completedIntentIds: [],
            at: rearmedAt
        ))

        let rearmedRejected = try XCTUnwrap(rejected.rearming(at: rearmedAt))
        XCTAssertEqual(rearmedRejected.payloadDigest, rejected.payloadDigest)
        XCTAssertNil(rearmedRejected.lastErrorClass)
        XCTAssertEqual(rearmedRejected.state, .prepared)
    }

    private func routeId(byte: UInt8) -> RelationshipRouteID {
        RelationshipRouteID(rawValue: Data(repeating: byte, count: 32))
    }

    private func capability(byte: UInt8) -> InboxRouteCapabilityV2 {
        InboxRouteCapabilityV2(rawValue: Data(repeating: byte, count: 32))
    }

    private func relay(host: String) -> RelayEndpoint {
        RelayEndpoint(host: host, port: 9340, useTLS: true, transport: .websocket)
    }

    private func digest(_ value: String) -> Data {
        Data(SHA256.hash(data: Data(value.utf8)))
    }
}
