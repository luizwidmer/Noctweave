import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2OpaqueRouteTests: XCTestCase {
    private let origin = Date(timeIntervalSince1970: 100_000)

    func testRelayProjectionIsOpaqueDigestOnlyAndModuleRemainsDisabled() throws {
        XCTAssertFalse(NoctweaveOpaqueRoutesV2.advertisedByDefault)

        let (material, route, _) = try makeRoute()
        XCTAssertTrue(route.isStructurallyValid)
        XCTAssertEqual(material.routeID.rawValue.count, 32)
        XCTAssertEqual(material.sendCapability.rawValue.count, 32)
        XCTAssertEqual(material.readCredential.rawValue.count, 32)
        XCTAssertEqual(material.renewCapability.rawValue.count, 32)
        XCTAssertEqual(material.teardownCapability.rawValue.count, 32)
        XCTAssertEqual(Set([
            material.sendCapability.rawValue,
            material.readCredential.rawValue,
            material.renewCapability.rawValue,
            material.teardownCapability.rawValue,
        ]).count, 4)
        XCTAssertEqual(route.lease.policy.paddingBucket, .bytes16384)
        XCTAssertEqual(route.lease.policy.retentionBucket, .sixHours)
        XCTAssertEqual(route.lease.policy.quotaBucket, .envelopes256)
        XCTAssertEqual(route.lease.policy.maximumStoredBytes, 4_194_304)
        XCTAssertEqual(
            route.lease.policy.transportRequirement,
            .confidentialAuthenticated
        )

        let encoded = try NoctweaveCoder.encode(route, sortedKeys: true)
        let json = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        let lowered = json.lowercased()
        for forbidden in [
            "inbox", "generation", "identity", "endpoint",
            "relationship", "provider", "owner",
        ] {
            XCTAssertFalse(lowered.contains(forbidden), "relay projection leaked \(forbidden)")
        }
        for secret in [
            material.sendCapability.rawValue,
            material.readCredential.rawValue,
            material.renewCapability.rawValue,
            material.teardownCapability.rawValue,
        ] {
            XCTAssertFalse(json.contains(secret.base64EncodedString()))
        }
        let decoded = try NoctweaveCoder.decode(OpaqueReceiveRouteV2.self, from: encoded)
        XCTAssertEqual(decoded, route)
        XCTAssertTrue(decoded.isStructurallyValid)

        let clientJSON = try NoctweaveCoder.encode(material, sortedKeys: true)
        XCTAssertNotEqual(clientJSON, encoded)
        XCTAssertEqual(String(describing: material), "OpaqueRouteClientCapabilityMaterialV2(<redacted>)")
        XCTAssertTrue(Mirror(reflecting: material).children.isEmpty)
        XCTAssertFalse(String(describing: material.sendCapability).contains(
            material.sendCapability.rawValue.base64EncodedString()
        ))
        XCTAssertTrue(Mirror(reflecting: material.sendCapability).children.isEmpty)
    }

    func testCreateRequiresConfidentialTransportAndIsExactlyIdempotent() throws {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let lease = try makeLease()
        let idempotencyKey = OpaqueRouteIdempotencyKeyV2.generate()
        let request = try material.makeCreateRequest(
            lease: lease,
            idempotencyKey: idempotencyKey
        )

        XCTAssertThrowsError(try OpaqueReceiveRouteV2.creating(
            from: request,
            presentedRenewCapability: material.renewCapability,
            existing: nil,
            confidentialTransport: false,
            receivedAt: origin
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .confidentialTransportRequired) }

        let wrongMaterial = try OpaqueRouteClientCapabilityMaterialV2()
        XCTAssertThrowsError(try OpaqueReceiveRouteV2.creating(
            from: request,
            presentedRenewCapability: wrongMaterial.renewCapability,
            existing: nil,
            confidentialTransport: true,
            receivedAt: origin
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .invalidAuthorization) }

        let route = try OpaqueReceiveRouteV2.creating(
            from: request,
            presentedRenewCapability: material.renewCapability,
            existing: nil,
            confidentialTransport: true,
            receivedAt: origin
        )
        let replay = try OpaqueReceiveRouteV2.creating(
            from: request,
            presentedRenewCapability: material.renewCapability,
            existing: route,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(1)
        )
        XCTAssertEqual(replay, route)
        XCTAssertEqual(route.creationDigest, request.transitionDigest)
        XCTAssertEqual(route.lastTransitionDigest, request.transitionDigest)

        let conflictingLease = try OpaqueRouteLeaseV2(
            issuedAt: origin,
            expiresAt: origin.addingTimeInterval(4_000),
            policy: lease.policy
        )
        let conflictingRequest = try material.makeCreateRequest(
            lease: conflictingLease,
            idempotencyKey: idempotencyKey
        )
        XCTAssertThrowsError(try OpaqueReceiveRouteV2.creating(
            from: conflictingRequest,
            presentedRenewCapability: material.renewCapability,
            existing: route,
            confidentialTransport: true,
            receivedAt: origin
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .idempotencyConflict) }
    }

    func testRenewalDigestChainRejectsOutOfOrderForkStaleExpiryAndConflicts() throws {
        let (material, initial, _) = try makeRoute()
        let firstKey = OpaqueRouteIdempotencyKeyV2.generate()
        let first = try material.makeRenewRequest(
            current: initial,
            newExpiry: origin.addingTimeInterval(4_000),
            authorizedAt: origin.addingTimeInterval(100),
            idempotencyKey: firstKey
        )
        let fork = try material.makeRenewRequest(
            current: initial,
            newExpiry: origin.addingTimeInterval(4_100),
            authorizedAt: origin.addingTimeInterval(101),
            idempotencyKey: .generate()
        )
        let conflict = try material.makeRenewRequest(
            current: initial,
            newExpiry: origin.addingTimeInterval(4_200),
            authorizedAt: origin.addingTimeInterval(102),
            idempotencyKey: firstKey
        )

        let renewed = try initial.applyingRenewal(
            first,
            presentedCapability: material.renewCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(100)
        )
        XCTAssertEqual(renewed.lease.renewalSequence, 1)
        XCTAssertEqual(renewed.lastTransitionDigest, first.transitionDigest)
        XCTAssertEqual(renewed.lease.expiresAt, origin.addingTimeInterval(4_000))

        let replay = try renewed.applyingRenewal(
            first,
            presentedCapability: material.renewCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(200)
        )
        XCTAssertEqual(replay, renewed)

        XCTAssertThrowsError(try renewed.applyingRenewal(
            conflict,
            presentedCapability: material.renewCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(102)
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .idempotencyConflict) }
        XCTAssertThrowsError(try renewed.applyingRenewal(
            fork,
            presentedCapability: material.renewCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(101)
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .transitionFork) }

        let second = try material.makeRenewRequest(
            current: renewed,
            newExpiry: origin.addingTimeInterval(5_000),
            authorizedAt: origin.addingTimeInterval(200),
            idempotencyKey: .generate()
        )
        XCTAssertThrowsError(try initial.applyingRenewal(
            second,
            presentedCapability: material.renewCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(200)
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .transitionOutOfOrder) }

        let renewedTwice = try renewed.applyingRenewal(
            second,
            presentedCapability: material.renewCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(200)
        )
        XCTAssertThrowsError(try renewedTwice.applyingRenewal(
            first,
            presentedCapability: material.renewCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(201)
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .staleTransition) }

        XCTAssertThrowsError(try renewed.applyingRenewal(
            first,
            presentedCapability: RouteRenewCapabilityV2.generate(),
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(200)
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .invalidAuthorization) }

        let late = try material.makeRenewRequest(
            current: initial,
            newExpiry: origin.addingTimeInterval(5_000),
            authorizedAt: origin.addingTimeInterval(3_500),
            idempotencyKey: .generate()
        )
        XCTAssertThrowsError(try initial.applyingRenewal(
            late,
            presentedCapability: material.renewCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(3_601)
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .routeExpired) }
    }

    func testTeardownIsTerminalIdempotentAndCannotResurrect() throws {
        let (material, initial, create) = try makeRoute()
        let pendingRenewal = try material.makeRenewRequest(
            current: initial,
            newExpiry: origin.addingTimeInterval(4_000),
            authorizedAt: origin.addingTimeInterval(100),
            idempotencyKey: .generate()
        )
        let teardown = try material.makeTeardownRequest(
            current: initial,
            authorizedAt: origin.addingTimeInterval(100),
            idempotencyKey: .generate()
        )
        let tombstone = try initial.applyingTeardown(
            teardown,
            presentedCapability: material.teardownCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(100)
        )
        XCTAssertEqual(tombstone.status, .tornDown)

        let replay = try tombstone.applyingTeardown(
            teardown,
            presentedCapability: material.teardownCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(200)
        )
        XCTAssertEqual(replay, tombstone)

        XCTAssertThrowsError(try tombstone.applyingRenewal(
            pendingRenewal,
            presentedCapability: material.renewCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(101)
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .routeTornDown) }

        XCTAssertThrowsError(try OpaqueReceiveRouteV2.creating(
            from: create,
            presentedRenewCapability: material.renewCapability,
            existing: tombstone,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(200)
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .routeTornDown) }

        let differentCreate = try material.makeCreateRequest(
            lease: try makeLease(),
            idempotencyKey: .generate()
        )
        XCTAssertThrowsError(try OpaqueReceiveRouteV2.creating(
            from: differentCreate,
            presentedRenewCapability: material.renewCapability,
            existing: tombstone,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(200)
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .routeTornDown) }
    }

    func testSendAndReadProofsAreAuthoritySeparatedFreshAndTransportBound() throws {
        let (material, route, _) = try makeRoute()
        let operationDigest = digest("one-envelope")
        let sendProof = try material.makeSendAuthorization(
            operationDigest: operationDigest,
            authorizedAt: origin.addingTimeInterval(10)
        )
        var ledger = OpaqueRouteAuthorizationReplayLedgerV2()

        try route.authorizeSend(
            sendProof,
            operationDigest: operationDigest,
            presentedCapability: material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(10),
            replayLedger: &ledger
        )
        XCTAssertEqual(ledger.count, 1)
        XCTAssertThrowsError(try route.authorizeSend(
            sendProof,
            operationDigest: operationDigest,
            presentedCapability: material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(11),
            replayLedger: &ledger
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .authorizationReplay) }

        var separateLedger = OpaqueRouteAuthorizationReplayLedgerV2()
        XCTAssertThrowsError(try route.authorizeRead(
            sendProof,
            operationDigest: operationDigest,
            presentedCredential: material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(10),
            replayLedger: &separateLedger
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .invalidAuthorization) }

        let readProof = try material.makeReadAuthorization(
            operationDigest: operationDigest,
            authorizedAt: origin.addingTimeInterval(10)
        )
        XCTAssertThrowsError(try route.authorizeRead(
            readProof,
            operationDigest: operationDigest,
            presentedCredential: material.readCredential,
            confidentialTransport: false,
            receivedAt: origin.addingTimeInterval(10),
            replayLedger: &separateLedger
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .confidentialTransportRequired) }

        XCTAssertThrowsError(try route.authorizeRead(
            readProof,
            operationDigest: operationDigest,
            presentedCredential: material.readCredential,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(311),
            replayLedger: &separateLedger
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .authorizationExpired) }
    }

    func testAuthorizationReplayLedgerPersistsAcrossRestart() throws {
        let (material, route, _) = try makeRoute()
        let operationDigest = digest("persisted-envelope")
        let proof = try material.makeSendAuthorization(
            operationDigest: operationDigest,
            authorizedAt: origin.addingTimeInterval(10)
        )
        var ledger = OpaqueRouteAuthorizationReplayLedgerV2()

        try route.authorizeSend(
            proof,
            operationDigest: operationDigest,
            presentedCapability: material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(10),
            replayLedger: &ledger
        )

        let persisted = try NoctweaveCoder.encode(ledger, sortedKeys: true)
        var restored = try NoctweaveCoder.decode(
            OpaqueRouteAuthorizationReplayLedgerV2.self,
            from: persisted
        )
        XCTAssertEqual(restored, ledger)
        XCTAssertThrowsError(try route.authorizeSend(
            proof,
            operationDigest: operationDigest,
            presentedCapability: material.sendCapability,
            confidentialTransport: true,
            receivedAt: origin.addingTimeInterval(11),
            replayLedger: &restored
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .authorizationReplay) }

        let duplicateDigestJSON = Data("""
        {"consumedDigests":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]}
        """.utf8)
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            OpaqueRouteAuthorizationReplayLedgerV2.self,
            from: duplicateDigestJSON
        ))
    }

    func testLeaseRejectsNonBucketAndUnboundedWireValues() throws {
        let policy = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .oneHour,
            quotaBucket: .envelopes64
        )
        XCTAssertThrowsError(try OpaqueRouteLeaseV2(
            issuedAt: origin,
            expiresAt: origin.addingTimeInterval(299),
            policy: policy
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .invalidLease) }
        XCTAssertThrowsError(try OpaqueRouteLeaseV2(
            issuedAt: origin,
            expiresAt: origin.addingTimeInterval(
                NoctweaveOpaqueRoutesV2.maximumLeaseDuration + 1
            ),
            policy: policy
        )) { XCTAssertEqual($0 as? OpaqueRouteV2Error, .invalidLease) }

        let invalidPolicyJSON = Data("""
        {"paddingBucket":12345,"quotaBucket":64,"retentionBucket":3600,"transportRequirement":"confidentialAuthenticated"}
        """.utf8)
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            OpaqueRoutePolicyV2.self,
            from: invalidPolicyJSON
        ))
    }

    private func makeLease() throws -> OpaqueRouteLeaseV2 {
        try OpaqueRouteLeaseV2(
            issuedAt: origin,
            expiresAt: origin.addingTimeInterval(3_600),
            policy: OpaqueRoutePolicyV2(
                paddingBucket: .bytes16384,
                retentionBucket: .sixHours,
                quotaBucket: .envelopes256
            )
        )
    }

    private func makeRoute() throws -> (
        OpaqueRouteClientCapabilityMaterialV2,
        OpaqueReceiveRouteV2,
        OpaqueRouteCreateRequestV2
    ) {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let request = try material.makeCreateRequest(
            lease: try makeLease(),
            idempotencyKey: .generate()
        )
        let route = try OpaqueReceiveRouteV2.creating(
            from: request,
            presentedRenewCapability: material.renewCapability,
            existing: nil,
            confidentialTransport: true,
            receivedAt: origin
        )
        return (material, route, request)
    }

    private func digest(_ string: String) -> Data {
        Data(SHA256.hash(data: Data(string.utf8)))
    }
}
