import Foundation
import XCTest
@testable import NoctweaveCore

final class OpaqueRoutePacketV2Tests: XCTestCase {
    private let authorizedAt = Date(timeIntervalSince1970: 200_000)

    func testFrozenSharedVectorMatchesSwiftCodec() throws {
        let vector = try loadOpaquePacketVector()
        XCTAssertEqual(vector.version, 2)
        let routeID = OpaqueReceiveRouteIDV2(
            rawValue: try decodeBase64(vector.routeId)
        )
        let packetID = OpaqueRoutePacketIDV2(
            rawValue: try decodeBase64(vector.packetId)
        )
        let payloadKey = OpaqueRoutePayloadKeyV2(
            rawValue: try decodeBase64(vector.payloadKey)
        )
        let operationDigest = try decodeBase64(vector.operationDigest)
        let authorizedAt = try XCTUnwrap(
            ISO8601DateFormatter().date(from: vector.authorization.authorizedAt)
        )
        let packet = OpaqueRoutePacketV2(
            routeID: routeID,
            packetID: packetID,
            sealedFrame: try decodeBase64(vector.sealedFrame),
            authorization: OpaqueRouteAuthorizationProofV2(
                authority: try XCTUnwrap(
                    OpaqueRouteAuthorityV2(rawValue: vector.authorization.authority)
                ),
                nonce: OpaqueRouteProofNonceV2(
                    rawValue: try decodeBase64(vector.authorization.nonce)
                ),
                operationDigest: operationDigest,
                authorizedAt: authorizedAt,
                mac: try decodeBase64(vector.authorization.mac)
            )
        )

        XCTAssertTrue(packet.isStructurallyValid)
        XCTAssertEqual(packet.operationDigest, operationDigest)
        XCTAssertEqual(packet.paddingBucket?.rawValue, vector.paddingBucket)
        XCTAssertEqual(packet.sealedFrame.count, Int(vector.paddingBucket))

        let fragment = try packet.open(
            payloadKey: payloadKey,
            routeRevision: vector.routeRevision
        )
        XCTAssertEqual(fragment.routeID, routeID)
        XCTAssertEqual(fragment.packetID, packetID)
        XCTAssertEqual(fragment.bundleID.rawValue, try decodeBase64(vector.bundleId))
        XCTAssertEqual(fragment.bundleDigest, try decodeBase64(vector.expected.bundleDigest))
        XCTAssertEqual(fragment.fragmentIndex, vector.expected.fragmentIndex)
        XCTAssertEqual(fragment.fragmentCount, vector.expected.fragmentCount)
        XCTAssertEqual(fragment.totalPayloadBytes, vector.expected.totalPayloadBytes)
        XCTAssertEqual(fragment.payload, try decodeBase64(vector.payload))

        var reassembler = try OpaqueRoutePacketReassemblerV2()
        let reassembled = try reassembler.consume(
            packet,
            payloadKey: payloadKey,
            routeRevision: vector.routeRevision
        )
        guard case let .complete(bundle) = reassembled else {
            return XCTFail("Expected the single vector fragment to complete its bundle")
        }
        XCTAssertEqual(bundle.bundleDigest, try decodeBase64(vector.expected.bundleDigest))
        XCTAssertEqual(bundle.payload, try decodeBase64(vector.payload))

        let material = try fixedVectorCapabilities(
            routeID: routeID,
            sendCapability: try decodeBase64(vector.sendCapability)
        )
        let lease = try OpaqueRouteLeaseV2(
            issuedAt: authorizedAt,
            expiresAt: authorizedAt.addingTimeInterval(3_600),
            policy: OpaqueRoutePolicyV2(
                paddingBucket: .bytes4096,
                retentionBucket: .oneHour,
                quotaBucket: .packets64
            )
        )
        let create = try material.makeCreateRequest(
            lease: lease,
            idempotencyKey: .generate()
        )
        let route = try OpaqueReceiveRouteV2.creating(
            from: create,
            presentedRenewCapability: material.renewCapability,
            existing: nil,
            confidentialTransport: true,
            receivedAt: authorizedAt
        )
        var replayLedger = OpaqueRouteAuthorizationReplayLedgerV2()
        try route.authorizeSend(
            packet.authorization,
            operationDigest: operationDigest,
            presentedCapability: material.sendCapability,
            confidentialTransport: true,
            receivedAt: authorizedAt,
            replayLedger: &replayLedger
        )

        XCTAssertThrowsError(try packet.open(
            payloadKey: payloadKey,
            routeRevision: vector.routeRevision + 1
        )) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .decryptionFailed)
        }
        XCTAssertThrowsError(try packet.open(
            payloadKey: OpaqueRoutePayloadKeyV2(rawValue: Data(repeating: 0x23, count: 32)),
            routeRevision: vector.routeRevision
        )) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .decryptionFailed)
        }

        let wrongRouteID = OpaqueReceiveRouteIDV2(rawValue: Data(repeating: 0x12, count: 32))
        let wrongRouteMaterial = try fixedVectorCapabilities(
            routeID: wrongRouteID,
            sendCapability: try decodeBase64(vector.sendCapability)
        )
        let wrongRouteDigest = OpaqueRoutePacketV2.operationDigest(
            routeID: wrongRouteID,
            packetID: packetID,
            sealedFrame: packet.sealedFrame
        )
        let wrongRoutePacket = OpaqueRoutePacketV2(
            routeID: wrongRouteID,
            packetID: packetID,
            sealedFrame: packet.sealedFrame,
            authorization: try wrongRouteMaterial.makeSendAuthorization(
                operationDigest: wrongRouteDigest,
                authorizedAt: authorizedAt
            )
        )
        XCTAssertTrue(wrongRoutePacket.isStructurallyValid)
        XCTAssertThrowsError(try wrongRoutePacket.open(
            payloadKey: payloadKey,
            routeRevision: vector.routeRevision
        )) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .decryptionFailed)
        }
    }

    func testRelayProjectionContainsOnlyOpaqueRoutingFields() throws {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let key = OpaqueRoutePayloadKeyV2.generate()
        let payload = Data("private event and relation metadata".utf8)
        let bundle = try OpaqueRouteSealedBundleV2.seal(
            payload,
            routeRevision: 7,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )
        let packet = try XCTUnwrap(bundle.packets.first)

        XCTAssertTrue(bundle.isStructurallyValid)
        XCTAssertTrue(packet.isStructurallyValid)
        XCTAssertEqual(packet.sealedFrame.count, 4_096)
        XCTAssertEqual(packet.authorization.operationDigest, packet.operationDigest)
        XCTAssertEqual(packet.authorization.authority, .send)

        let encoded = try NoctweaveCoder.encode(packet, sortedKeys: true)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertEqual(
            Set(object.keys),
            Set(["routeID", "packetID", "sealedFrame", "authorization"])
        )
        let json = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        for forbidden in [
            "bundleID", "bundleDigest", "fragmentIndex", "fragmentCount",
            "totalPayloadBytes", "routeRevision", "generation", "endpoint",
            "relationship",
        ] {
            XCTAssertFalse(json.contains(forbidden), "relay projection leaked \(forbidden)")
        }
        XCTAssertFalse(json.contains(payload.base64EncodedString()))
        XCTAssertFalse(json.contains(key.rawValue.base64EncodedString()))
        XCTAssertEqual(String(describing: key), "OpaqueRoutePayloadKeyV2(<redacted>)")
        XCTAssertTrue(Mirror(reflecting: key).children.isEmpty)

        let decoded = try NoctweaveCoder.decode(OpaqueRoutePacketV2.self, from: encoded)
        XCTAssertEqual(decoded, packet)
        XCTAssertEqual(decoded.operationDigest, packet.operationDigest)
    }

    func testFixedBucketsFragmentAndReassembleOutOfOrder() throws {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let key = OpaqueRoutePayloadKeyV2.generate()
        let capacity = NoctweaveOpaqueRoutePacketsV2.maximumFragmentPayloadBytes(
            for: .bytes4096
        )
        XCTAssertGreaterThan(capacity, 0)
        let payload = Data((0..<(capacity + 173)).map { UInt8($0 % 251) })
        let bundle = try OpaqueRouteSealedBundleV2.seal(
            payload,
            routeRevision: 11,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )

        XCTAssertEqual(bundle.packets.count, 2)
        XCTAssertTrue(bundle.packets.allSatisfy { $0.sealedFrame.count == 4_096 })
        XCTAssertEqual(Set(bundle.packets.map(\.sealedFrame.count)), [4_096])

        let last = try bundle.packets[1].open(payloadKey: key, routeRevision: 11)
        XCTAssertEqual(last.bundleID, bundle.bundleID)
        XCTAssertEqual(last.bundleDigest, bundle.bundleDigest)
        XCTAssertEqual(last.fragmentIndex, 1)
        XCTAssertEqual(last.fragmentCount, 2)
        XCTAssertEqual(last.totalPayloadBytes, UInt64(payload.count))
        XCTAssertEqual(last.payload.count, 173)

        var reassembler = try OpaqueRoutePacketReassemblerV2()
        XCTAssertEqual(
            try reassembler.consume(
                bundle.packets[1],
                payloadKey: key,
                routeRevision: 11
            ),
            .accepted
        )
        XCTAssertEqual(reassembler.pendingBundleCount, 1)
        XCTAssertEqual(reassembler.bufferedPayloadBytes, 173)
        XCTAssertEqual(
            try reassembler.consume(
                bundle.packets[1],
                payloadKey: key,
                routeRevision: 11
            ),
            .duplicate
        )

        let result = try reassembler.consume(
            bundle.packets[0],
            payloadKey: key,
            routeRevision: 11
        )
        guard case let .complete(completed) = result else {
            return XCTFail("Expected complete bundle")
        }
        XCTAssertEqual(completed.payload, payload)
        XCTAssertEqual(completed.bundleID, bundle.bundleID)
        XCTAssertEqual(completed.bundleDigest, bundle.bundleDigest)
        XCTAssertEqual(completed.routeRevision, 11)
        XCTAssertEqual(reassembler.pendingBundleCount, 0)
        XCTAssertEqual(reassembler.bufferedPayloadBytes, 0)

        XCTAssertEqual(
            try reassembler.consume(
                bundle.packets[0],
                payloadKey: key,
                routeRevision: 11
            ),
            .duplicate
        )
    }

    func testReassemblerPersistsPartialFragmentsAndResumesAfterRoundTrip() throws {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let key = OpaqueRoutePayloadKeyV2.generate()
        let capacity = NoctweaveOpaqueRoutePacketsV2.maximumFragmentPayloadBytes(
            for: .bytes4096
        )
        let completedBundle = try OpaqueRouteSealedBundleV2.seal(
            Data("already completed".utf8),
            routeRevision: 31,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )
        let payload = Data((0..<(capacity + 137)).map { UInt8($0 % 251) })
        let partialBundle = try OpaqueRouteSealedBundleV2.seal(
            payload,
            routeRevision: 31,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )

        var original = try OpaqueRoutePacketReassemblerV2()
        guard case .complete = try original.consume(
            completedBundle.packets[0],
            payloadKey: key,
            routeRevision: 31
        ) else {
            return XCTFail("Expected the one-packet bundle to complete")
        }
        XCTAssertEqual(
            try original.consume(
                partialBundle.packets[0],
                payloadKey: key,
                routeRevision: 31
            ),
            .accepted
        )

        let encoded = try NoctweaveCoder.encode(original, sortedKeys: true)
        var restored = try NoctweaveCoder.decode(
            OpaqueRoutePacketReassemblerV2.self,
            from: encoded
        )
        XCTAssertEqual(restored, original)
        XCTAssertTrue(restored.isStructurallyValid)
        XCTAssertEqual(restored.pendingBundleCount, 1)
        XCTAssertEqual(restored.bufferedPayloadBytes, capacity)
        XCTAssertEqual(
            String(describing: restored),
            "OpaqueRoutePacketReassemblerV2(<redacted>)"
        )
        XCTAssertTrue(Mirror(reflecting: restored).children.isEmpty)

        XCTAssertEqual(
            try restored.consume(
                completedBundle.packets[0],
                payloadKey: key,
                routeRevision: 31
            ),
            .duplicate
        )
        XCTAssertEqual(
            try restored.consume(
                partialBundle.packets[0],
                payloadKey: key,
                routeRevision: 31
            ),
            .duplicate
        )
        guard case .complete(let resumed) = try restored.consume(
            partialBundle.packets[1],
            payloadKey: key,
            routeRevision: 31
        ) else {
            return XCTFail("Expected persisted fragments to resume the bundle")
        }
        XCTAssertEqual(resumed.payload, payload)
        XCTAssertEqual(restored.pendingBundleCount, 0)
        XCTAssertEqual(restored.bufferedPayloadBytes, 0)
    }

    func testPendingInsertionOrderIsDeterministicAndSurvivesRoundTrip() throws {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let key = OpaqueRoutePayloadKeyV2.generate()
        let capacity = NoctweaveOpaqueRoutePacketsV2.maximumFragmentPayloadBytes(
            for: .bytes4096
        )
        let firstBundleID = OpaqueRouteBundleIDV2(
            rawValue: Data(repeating: 0xF1, count: 32)
        )
        let secondBundleID = OpaqueRouteBundleIDV2(
            rawValue: Data(repeating: 0x01, count: 32)
        )
        let completedBundle = try OpaqueRouteSealedBundleV2.seal(
            Data("completed replay entry".utf8),
            routeRevision: 32,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )
        let firstBundle = try OpaqueRouteSealedBundleV2.seal(
            Data(repeating: 0x61, count: capacity + 1),
            routeRevision: 32,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt,
            bundleID: firstBundleID
        )
        let secondBundle = try OpaqueRouteSealedBundleV2.seal(
            Data(repeating: 0x62, count: capacity + 1),
            routeRevision: 32,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt,
            bundleID: secondBundleID
        )
        let conflictingFirstBundle = try OpaqueRouteSealedBundleV2.seal(
            Data(repeating: 0x63, count: capacity + 1),
            routeRevision: 32,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt,
            bundleID: firstBundleID
        )

        var original = try OpaqueRoutePacketReassemblerV2()
        _ = try original.consume(
            completedBundle.packets[0],
            payloadKey: key,
            routeRevision: 32
        )
        _ = try original.consume(firstBundle.packets[0], payloadKey: key, routeRevision: 32)
        _ = try original.consume(secondBundle.packets[0], payloadKey: key, routeRevision: 32)

        let encoded = try NoctweaveCoder.encode(original, sortedKeys: true)
        XCTAssertEqual(
            encoded,
            try NoctweaveCoder.encode(original, sortedKeys: true)
        )
        var restored = try NoctweaveCoder.decode(
            OpaqueRoutePacketReassemblerV2.self,
            from: encoded
        )
        XCTAssertEqual(restored, original)

        let firstDiscarded = try XCTUnwrap(restored.discardOldestPendingBundle())
        XCTAssertEqual(firstDiscarded, firstBundleID)
        XCTAssertEqual(
            String(describing: firstDiscarded),
            "OpaqueRouteBundleIDV2(<redacted>)"
        )
        XCTAssertEqual(restored.pendingBundleCount, 1)
        XCTAssertEqual(restored.bufferedPayloadBytes, capacity)
        let retiredEncoded = try NoctweaveCoder.encode(restored, sortedKeys: true)
        var afterEviction = try NoctweaveCoder.decode(
            OpaqueRoutePacketReassemblerV2.self,
            from: retiredEncoded
        )
        XCTAssertEqual(afterEviction, restored)
        XCTAssertEqual(
            try afterEviction.consume(
                firstBundle.packets[1],
                payloadKey: key,
                routeRevision: 32
            ),
            .duplicate
        )
        XCTAssertThrowsError(try afterEviction.consume(
            conflictingFirstBundle.packets[0],
            payloadKey: key,
            routeRevision: 32
        )) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .bundleConflict)
        }
        XCTAssertEqual(
            try afterEviction.consume(
                completedBundle.packets[0],
                payloadKey: key,
                routeRevision: 32
            ),
            .duplicate
        )
        XCTAssertEqual(afterEviction.discardOldestPendingBundle(), secondBundleID)
        XCTAssertNil(afterEviction.discardOldestPendingBundle())
        XCTAssertEqual(afterEviction.pendingBundleCount, 0)
        XCTAssertEqual(afterEviction.bufferedPayloadBytes, 0)
        XCTAssertTrue(afterEviction.isStructurallyValid)
    }

    func testDiscardPendingBundleRetiresOnlyTheTargetBundle() throws {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let key = OpaqueRoutePayloadKeyV2.generate()
        let capacity = NoctweaveOpaqueRoutePacketsV2.maximumFragmentPayloadBytes(
            for: .bytes4096
        )
        let retainedPayload = Data(repeating: 0x81, count: capacity + 11)
        let targetPayload = Data(repeating: 0x82, count: capacity + 17)
        let retainedBundle = try OpaqueRouteSealedBundleV2.seal(
            retainedPayload,
            routeRevision: 35,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt,
            bundleID: OpaqueRouteBundleIDV2(rawValue: Data(repeating: 0x81, count: 32))
        )
        let targetBundleID = OpaqueRouteBundleIDV2(
            rawValue: Data(repeating: 0x82, count: 32)
        )
        let targetBundle = try OpaqueRouteSealedBundleV2.seal(
            targetPayload,
            routeRevision: 35,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt,
            bundleID: targetBundleID
        )
        let conflictingTarget = try OpaqueRouteSealedBundleV2.seal(
            Data(repeating: 0x83, count: capacity + 17),
            routeRevision: 35,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt,
            bundleID: targetBundleID
        )
        let completedBundle = try OpaqueRouteSealedBundleV2.seal(
            Data("preexisting completed entry".utf8),
            routeRevision: 35,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )

        var reassembler = try OpaqueRoutePacketReassemblerV2()
        _ = try reassembler.consume(
            completedBundle.packets[0],
            payloadKey: key,
            routeRevision: 35
        )
        _ = try reassembler.consume(
            retainedBundle.packets[0],
            payloadKey: key,
            routeRevision: 35
        )
        _ = try reassembler.consume(
            targetBundle.packets[0],
            payloadKey: key,
            routeRevision: 35
        )

        XCTAssertFalse(reassembler.discardPendingBundle(.generate()))
        XCTAssertTrue(reassembler.discardPendingBundle(targetBundleID))
        XCTAssertFalse(reassembler.discardPendingBundle(targetBundleID))
        XCTAssertEqual(reassembler.pendingBundleCount, 1)
        XCTAssertEqual(reassembler.bufferedPayloadBytes, capacity)
        XCTAssertEqual(
            try reassembler.consume(
                targetBundle.packets[1],
                payloadKey: key,
                routeRevision: 35
            ),
            .duplicate
        )
        XCTAssertThrowsError(try reassembler.consume(
            conflictingTarget.packets[0],
            payloadKey: key,
            routeRevision: 35
        )) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .bundleConflict)
        }
        XCTAssertEqual(
            try reassembler.consume(
                completedBundle.packets[0],
                payloadKey: key,
                routeRevision: 35
            ),
            .duplicate
        )
        guard case .complete(let retained) = try reassembler.consume(
            retainedBundle.packets[1],
            payloadKey: key,
            routeRevision: 35
        ) else {
            return XCTFail("Expected unrelated partial bundle to remain resumable")
        }
        XCTAssertEqual(retained.payload, retainedPayload)
        XCTAssertTrue(reassembler.isStructurallyValid)
    }

    func testReassemblerRejectsMalformedPersistedStateExactly() throws {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let key = OpaqueRoutePayloadKeyV2.generate()
        let capacity = NoctweaveOpaqueRoutePacketsV2.maximumFragmentPayloadBytes(
            for: .bytes4096
        )
        let bundle = try OpaqueRouteSealedBundleV2.seal(
            Data(repeating: 0x71, count: capacity + 1),
            routeRevision: 33,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )
        var reassembler = try OpaqueRoutePacketReassemblerV2()
        _ = try reassembler.consume(bundle.packets[0], payloadKey: key, routeRevision: 33)
        let encoded = try NoctweaveCoder.encode(reassembler, sortedKeys: true)
        let original = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )

        var unknownField = original
        unknownField["legacyPendingState"] = true
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            OpaqueRoutePacketReassemblerV2.self,
            from: JSONSerialization.data(withJSONObject: unknownField)
        ))

        var unknownNestedField = original
        var nestedPending = try XCTUnwrap(
            unknownNestedField["pendingBundles"] as? [[String: Any]]
        )
        nestedPending[0]["legacyFragmentMap"] = [:]
        unknownNestedField["pendingBundles"] = nestedPending
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            OpaqueRoutePacketReassemblerV2.self,
            from: JSONSerialization.data(withJSONObject: unknownNestedField)
        ))

        var duplicateFragment = original
        var duplicatePending = try XCTUnwrap(
            duplicateFragment["pendingBundles"] as? [[String: Any]]
        )
        var fragments = try XCTUnwrap(
            duplicatePending[0]["fragments"] as? [[String: Any]]
        )
        fragments.append(fragments[0])
        duplicatePending[0]["fragments"] = fragments
        duplicateFragment["pendingBundles"] = duplicatePending
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            OpaqueRoutePacketReassemblerV2.self,
            from: JSONSerialization.data(withJSONObject: duplicateFragment)
        ))

        var impossibleCapacity = original
        impossibleCapacity["maximumBufferedBytes"] = 1
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            OpaqueRoutePacketReassemblerV2.self,
            from: JSONSerialization.data(withJSONObject: impossibleCapacity)
        ))
    }

    func testDiscardPendingBundlesPreservesCompletedReplayCache() throws {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let key = OpaqueRoutePayloadKeyV2.generate()
        let capacity = NoctweaveOpaqueRoutePacketsV2.maximumFragmentPayloadBytes(
            for: .bytes4096
        )
        let completedBundle = try OpaqueRouteSealedBundleV2.seal(
            Data("complete before discard".utf8),
            routeRevision: 34,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )
        let partialPayload = Data(repeating: 0x72, count: capacity + 19)
        let partialBundle = try OpaqueRouteSealedBundleV2.seal(
            partialPayload,
            routeRevision: 34,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )
        var reassembler = try OpaqueRoutePacketReassemblerV2()
        _ = try reassembler.consume(
            completedBundle.packets[0],
            payloadKey: key,
            routeRevision: 34
        )
        _ = try reassembler.consume(
            partialBundle.packets[0],
            payloadKey: key,
            routeRevision: 34
        )

        reassembler.discardPendingBundles()
        XCTAssertTrue(reassembler.isStructurallyValid)
        XCTAssertEqual(reassembler.pendingBundleCount, 0)
        XCTAssertEqual(reassembler.bufferedPayloadBytes, 0)
        XCTAssertEqual(
            try reassembler.consume(
                completedBundle.packets[0],
                payloadKey: key,
                routeRevision: 34
            ),
            .duplicate
        )
        XCTAssertEqual(
            try reassembler.consume(
                partialBundle.packets[0],
                payloadKey: key,
                routeRevision: 34
            ),
            .accepted
        )
        guard case .complete(let completed) = try reassembler.consume(
            partialBundle.packets[1],
            payloadKey: key,
            routeRevision: 34
        ) else {
            return XCTFail("Expected discarded pending state to be safely rebuilt")
        }
        XCTAssertEqual(completed.payload, partialPayload)
    }

    func testAADBindsRevisionAndWrongPayloadKeyFailsClosed() throws {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let key = OpaqueRoutePayloadKeyV2.generate()
        let bundle = try OpaqueRouteSealedBundleV2.seal(
            Data("sealed".utf8),
            routeRevision: 19,
            paddingBucket: .bytes16384,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )
        let packet = try XCTUnwrap(bundle.packets.first)
        XCTAssertEqual(packet.sealedFrame.count, 16_384)

        XCTAssertThrowsError(try packet.open(payloadKey: key, routeRevision: 20)) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .decryptionFailed)
        }
        XCTAssertThrowsError(try packet.open(
            payloadKey: .generate(),
            routeRevision: 19
        )) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .decryptionFailed)
        }

        var changedFrame = packet.sealedFrame
        changedFrame[changedFrame.startIndex + 20] ^= 0x01
        let changedDigest = OpaqueRoutePacketV2.operationDigest(
            routeID: packet.routeID,
            packetID: packet.packetID,
            sealedFrame: changedFrame
        )
        let changedProof = try material.makeSendAuthorization(
            operationDigest: changedDigest,
            authorizedAt: authorizedAt
        )
        let changedPacket = OpaqueRoutePacketV2(
            routeID: packet.routeID,
            packetID: packet.packetID,
            sealedFrame: changedFrame,
            authorization: changedProof
        )
        XCTAssertTrue(changedPacket.isStructurallyValid)
        XCTAssertThrowsError(try changedPacket.open(
            payloadKey: key,
            routeRevision: 19
        )) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .decryptionFailed)
        }
    }

    func testRelayAuthorizationUsesPacketDigestWithoutPayloadKey() throws {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let policy = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .oneHour,
            quotaBucket: .packets64
        )
        let lease = try OpaqueRouteLeaseV2(
            issuedAt: authorizedAt,
            expiresAt: authorizedAt.addingTimeInterval(3_600),
            policy: policy
        )
        let create = try material.makeCreateRequest(
            lease: lease,
            idempotencyKey: .generate()
        )
        let route = try OpaqueReceiveRouteV2.creating(
            from: create,
            presentedRenewCapability: material.renewCapability,
            existing: nil,
            confidentialTransport: true,
            receivedAt: authorizedAt
        )
        let packet = try XCTUnwrap(OpaqueRouteSealedBundleV2.seal(
            Data("relay-opaque".utf8),
            routeRevision: 2,
            paddingBucket: .bytes4096,
            payloadKey: .generate(),
            routeCapabilities: material,
            authorizedAt: authorizedAt.addingTimeInterval(10)
        ).packets.first)

        var ledger = OpaqueRouteAuthorizationReplayLedgerV2()
        try route.authorizeSend(
            packet.authorization,
            operationDigest: packet.operationDigest,
            presentedCapability: material.sendCapability,
            confidentialTransport: true,
            receivedAt: authorizedAt.addingTimeInterval(10),
            replayLedger: &ledger
        )
        XCTAssertEqual(ledger.count, 1)
        XCTAssertThrowsError(try route.authorizeSend(
            packet.authorization,
            operationDigest: packet.operationDigest,
            presentedCapability: material.sendCapability,
            confidentialTransport: true,
            receivedAt: authorizedAt.addingTimeInterval(11),
            replayLedger: &ledger
        )) {
            XCTAssertEqual($0 as? OpaqueRouteV2Error, .authorizationReplay)
        }
    }

    func testPacketAndBundleConflictsAreRejected() throws {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let key = OpaqueRoutePayloadKeyV2.generate()
        let capacity = NoctweaveOpaqueRoutePacketsV2.maximumFragmentPayloadBytes(
            for: .bytes4096
        )
        let first = try OpaqueRouteSealedBundleV2.seal(
            Data(repeating: 0x11, count: capacity + 1),
            routeRevision: 3,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )
        let second = try OpaqueRouteSealedBundleV2.seal(
            Data(repeating: 0x22, count: capacity + 1),
            routeRevision: 3,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )

        var reassembler = try OpaqueRoutePacketReassemblerV2()
        XCTAssertEqual(
            try reassembler.consume(
                first.packets[0],
                payloadKey: key,
                routeRevision: 3
            ),
            .accepted
        )

        let conflictingDigest = OpaqueRoutePacketV2.operationDigest(
            routeID: material.routeID,
            packetID: first.packets[0].packetID,
            sealedFrame: second.packets[0].sealedFrame
        )
        let conflictingProof = try material.makeSendAuthorization(
            operationDigest: conflictingDigest,
            authorizedAt: authorizedAt
        )
        let conflictingPacketID = OpaqueRoutePacketV2(
            routeID: material.routeID,
            packetID: first.packets[0].packetID,
            sealedFrame: second.packets[0].sealedFrame,
            authorization: conflictingProof
        )
        XCTAssertThrowsError(try reassembler.consume(
            conflictingPacketID,
            payloadKey: key,
            routeRevision: 3
        )) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .packetIdentifierConflict)
        }

        let reusedBundleID = OpaqueRouteBundleIDV2.generate()
        let bundleA = try OpaqueRouteSealedBundleV2.seal(
            Data(repeating: 0x33, count: capacity + 1),
            routeRevision: 4,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt,
            bundleID: reusedBundleID
        )
        let bundleB = try OpaqueRouteSealedBundleV2.seal(
            Data(repeating: 0x44, count: capacity + 1),
            routeRevision: 4,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt,
            bundleID: reusedBundleID
        )
        var bundleReassembler = try OpaqueRoutePacketReassemblerV2()
        _ = try bundleReassembler.consume(
            bundleA.packets[0],
            payloadKey: key,
            routeRevision: 4
        )
        XCTAssertThrowsError(try bundleReassembler.consume(
            bundleB.packets[0],
            payloadKey: key,
            routeRevision: 4
        )) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .bundleConflict)
        }
    }

    func testReassemblyCapacityAndInputBoundsAreEnforced() throws {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let key = OpaqueRoutePayloadKeyV2.generate()
        XCTAssertThrowsError(try OpaqueRouteSealedBundleV2.seal(
            Data(),
            routeRevision: 0,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .emptyPayload)
        }
        XCTAssertThrowsError(try OpaqueRoutePacketReassemblerV2(
            maximumBufferedBundles: 0,
            maximumBufferedBytes: 1
        )) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .reassemblyCapacityExceeded)
        }

        let capacity = NoctweaveOpaqueRoutePacketsV2.maximumFragmentPayloadBytes(
            for: .bytes4096
        )
        let oversizedForReceiver = try OpaqueRouteSealedBundleV2.seal(
            Data(repeating: 0x55, count: capacity + 1),
            routeRevision: 8,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )
        var byteBounded = try OpaqueRoutePacketReassemblerV2(
            maximumBufferedBundles: 2,
            maximumBufferedBytes: capacity
        )
        XCTAssertThrowsError(try byteBounded.consume(
            oversizedForReceiver.packets[0],
            payloadKey: key,
            routeRevision: 8
        )) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .reassemblyCapacityExceeded)
        }

        let first = try OpaqueRouteSealedBundleV2.seal(
            Data(repeating: 0x66, count: capacity + 1),
            routeRevision: 9,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )
        let second = try OpaqueRouteSealedBundleV2.seal(
            Data(repeating: 0x77, count: capacity + 1),
            routeRevision: 9,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt
        )
        var bundleBounded = try OpaqueRoutePacketReassemblerV2(
            maximumBufferedBundles: 1,
            maximumBufferedBytes: capacity * 3
        )
        _ = try bundleBounded.consume(
            first.packets[0],
            payloadKey: key,
            routeRevision: 9
        )
        XCTAssertThrowsError(try bundleBounded.consume(
            second.packets[0],
            payloadKey: key,
            routeRevision: 9
        )) {
            XCTAssertEqual($0 as? OpaqueRoutePacketV2Error, .reassemblyCapacityExceeded)
        }
    }

    func testEachPacketUsesFreshNonceAndRandomPadding() throws {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let key = OpaqueRoutePayloadKeyV2.generate()
        let bundleID = OpaqueRouteBundleIDV2.generate()
        let payload = Data("same logical payload".utf8)
        let first = try OpaqueRouteSealedBundleV2.seal(
            payload,
            routeRevision: 1,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt,
            bundleID: bundleID
        )
        let second = try OpaqueRouteSealedBundleV2.seal(
            payload,
            routeRevision: 1,
            paddingBucket: .bytes4096,
            payloadKey: key,
            routeCapabilities: material,
            authorizedAt: authorizedAt,
            bundleID: bundleID
        )
        XCTAssertEqual(first.bundleDigest, second.bundleDigest)
        XCTAssertNotEqual(first.packets[0].packetID, second.packets[0].packetID)
        XCTAssertNotEqual(first.packets[0].sealedFrame, second.packets[0].sealedFrame)
        XCTAssertEqual(first.packets[0].sealedFrame.count, second.packets[0].sealedFrame.count)

        let openedA = try first.packets[0].open(payloadKey: key, routeRevision: 1)
        let openedB = try second.packets[0].open(payloadKey: key, routeRevision: 1)
        XCTAssertEqual(openedA.payload, openedB.payload)
        XCTAssertEqual(openedA.bundleDigest, openedB.bundleDigest)
    }

    private func loadOpaquePacketVector() throws -> OpaqueRoutePacketSharedVector {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let url = repositoryRoot.appendingPathComponent(
            "NoctweaveDocumentation/test_vectors/opaque_route_packet_v2.json"
        )
        return try JSONDecoder().decode(
            OpaqueRoutePacketSharedVector.self,
            from: Data(contentsOf: url)
        )
    }

    private func decodeBase64(_ value: String) throws -> Data {
        try XCTUnwrap(Data(base64Encoded: value))
    }

    private func fixedVectorCapabilities(
        routeID: OpaqueReceiveRouteIDV2,
        sendCapability: Data
    ) throws -> OpaqueRouteClientCapabilityMaterialV2 {
        try OpaqueRouteClientCapabilityMaterialV2(
            routeID: routeID,
            sendCapability: RouteSendCapabilityV2(rawValue: sendCapability),
            readCredential: RouteReadCredentialV2(rawValue: Data(repeating: 0x44, count: 32)),
            renewCapability: RouteRenewCapabilityV2(rawValue: Data(repeating: 0x55, count: 32)),
            teardownCapability: RouteTeardownCapabilityV2(rawValue: Data(repeating: 0x66, count: 32))
        )
    }
}

private struct OpaqueRoutePacketSharedVector: Decodable {
    struct Authorization: Decodable {
        let authority: String
        let authorizedAt: String
        let mac: String
        let nonce: String
    }

    struct Expected: Decodable {
        let bundleDigest: String
        let fragmentCount: UInt32
        let fragmentIndex: UInt32
        let totalPayloadBytes: UInt64
    }

    let version: Int
    let routeId: String
    let packetId: String
    let payloadKey: String
    let sendCapability: String
    let routeRevision: UInt64
    let paddingBucket: UInt32
    let payload: String
    let bundleId: String
    let sealedFrame: String
    let operationDigest: String
    let authorization: Authorization
    let expected: Expected
}

private extension OpaqueRouteSealedBundleV2 {
    static func seal(
        _ payload: Data,
        routeRevision: UInt64,
        paddingBucket: OpaqueRoutePaddingBucketV2,
        payloadKey: OpaqueRoutePayloadKeyV2,
        routeCapabilities: OpaqueRouteClientCapabilityMaterialV2,
        authorizedAt: Date,
        bundleID: OpaqueRouteBundleIDV2 = .generate()
    ) throws -> OpaqueRouteSealedBundleV2 {
        let sendRoute = try OpaqueSendRouteV2(
            routeID: routeCapabilities.routeID,
            relay: RelayEndpoint(
                host: "relay.example",
                port: 443,
                useTLS: true,
                transport: .websocket
            ),
            sendCapability: routeCapabilities.sendCapability,
            payloadKey: payloadKey,
            routeRevision: routeRevision,
            policy: OpaqueRoutePolicyV2(
                paddingBucket: paddingBucket,
                retentionBucket: .sixHours,
                quotaBucket: .packets256
            ),
            validFrom: authorizedAt,
            expiresAt: authorizedAt.addingTimeInterval(3_600),
            state: .active,
            testedAt: authorizedAt
        )
        return try seal(
            payload,
            to: sendRoute,
            authorizedAt: authorizedAt,
            bundleID: bundleID
        )
    }
}
