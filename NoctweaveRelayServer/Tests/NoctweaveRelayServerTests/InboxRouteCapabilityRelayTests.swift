import Foundation
import Crypto
import XCTest
@testable import NoctweaveRelayServer

final class InboxRouteCapabilityRelayTests: XCTestCase {
    func testRouteCapabilityProtocolIsDisabledByDefault() throws {
        let harness = try RelayTCPHarness(compatibilityProfiles: [])
        defer { try? harness.shutdown() }
        let response = try harness.send(
            .deliver(
                DeliverRequest(
                    inboxCapability: routeCapability(0x70),
                    envelope: envelope(69)
                )
            )
        )
        XCTAssertEqual(
            response.error,
            "Experimental opaque route capabilities are disabled"
        )

        let signer = try makeSignerOrSkip()
        let inboxId = InboxAddress.derived(from: signer.publicKey)
        let unsignedRegistration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey
        )
        let registration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey,
            accessProof: try signer.proof {
                try unsignedRegistration.signableData(for: $0)
            }
        )
        let registrationResponse = try harness.send(.registerInbox(registration))
        XCTAssertEqual(registrationResponse.type, .ok)
        XCTAssertNil(registrationResponse.inboxRegistration)

        let capability = routeCapability(0x71)
        let scope = Data(repeating: 0x72, count: 32)
        let disabledCreate = try harness.send(
            .createInboxRouteCapability(
                CreateInboxRouteCapabilityRequest(
                    inboxId: inboxId,
                    capability: capability,
                    relayScope: scope,
                    mutationSequence: 1
                )
            )
        )
        XCTAssertEqual(
            disabledCreate.error,
            "Experimental opaque route capabilities are disabled"
        )
        let disabledRevoke = try harness.send(
            .revokeInboxRouteCapability(
                RevokeInboxRouteCapabilityRequest(
                    inboxId: inboxId,
                    capability: capability,
                    relayScope: scope,
                    mutationSequence: 1
                )
            )
        )
        XCTAssertEqual(
            disabledRevoke.error,
            "Experimental opaque route capabilities are disabled"
        )
    }

    func testRouteMutationSequenceExhaustionFailsClosed() {
        XCTAssertEqual(
            CreateInboxRouteCapabilityRequest.nextMutationSequence(after: 0),
            1
        )
        XCTAssertEqual(
            CreateInboxRouteCapabilityRequest.nextMutationSequence(
                after: CreateInboxRouteCapabilityRequest.maximumMutationSequence - 1
            ),
            CreateInboxRouteCapabilityRequest.maximumMutationSequence
        )
        XCTAssertEqual(
            CreateInboxRouteCapabilityRequest.nextMutationSequence(
                after: CreateInboxRouteCapabilityRequest.maximumMutationSequence
            ),
            0
        )
        XCTAssertEqual(
            CreateInboxRouteCapabilityRequest.nextMutationSequence(after: UInt64.max),
            0
        )
    }

    func testRegistrationCursorDecoderMigratesOnlyTrueLegacyState() throws {
        let scope = Data(repeating: 0xA5, count: 32)
        let digest = Data(repeating: 0xB6, count: 32)
        let current = InboxRegistrationRecord(
            accessPublicKey: Data([0x01]),
            registeredAt: Date(timeIntervalSince1970: 1_000),
            routeMutationScope: scope,
            lastRouteMutationSequence: 1,
            lastRouteMutationDigest: digest
        )
        var missingScope = try XCTUnwrap(
            JSONSerialization.jsonObject(with: RelayCodec.encoder().encode(current))
                as? [String: Any]
        )
        missingScope.removeValue(forKey: "routeMutationScope")
        XCTAssertThrowsError(
            try RelayCodec.decoder().decode(
                InboxRegistrationRecord.self,
                from: JSONSerialization.data(withJSONObject: missingScope)
            )
        )

        var invalidScope = missingScope
        invalidScope["routeMutationScope"] = Data(repeating: 0, count: 32)
            .base64EncodedString()
        XCTAssertThrowsError(
            try RelayCodec.decoder().decode(
                InboxRegistrationRecord.self,
                from: JSONSerialization.data(withJSONObject: invalidScope)
            )
        )

        var exhausted = missingScope
        exhausted["routeMutationScope"] = scope.base64EncodedString()
        exhausted["lastRouteMutationSequence"] = NSNumber(
            value: CreateInboxRouteCapabilityRequest.maximumMutationSequence + 1
        )
        XCTAssertThrowsError(
            try RelayCodec.decoder().decode(
                InboxRegistrationRecord.self,
                from: JSONSerialization.data(withJSONObject: exhausted)
            )
        )

        let legacy = InboxRegistrationRecord(
            accessPublicKey: Data([0x02]),
            registeredAt: Date(timeIntervalSince1970: 1_001)
        )
        var legacyObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: RelayCodec.encoder().encode(legacy))
                as? [String: Any]
        )
        var explicitNullScope = legacyObject
        explicitNullScope["routeMutationScope"] = NSNull()
        XCTAssertThrowsError(
            try RelayCodec.decoder().decode(
                InboxRegistrationRecord.self,
                from: JSONSerialization.data(withJSONObject: explicitNullScope)
            )
        )
        legacyObject.removeValue(forKey: "routeMutationScope")
        legacyObject.removeValue(forKey: "lastRouteMutationSequence")
        legacyObject.removeValue(forKey: "lastRouteMutationDigest")
        let migrated = try RelayCodec.decoder().decode(
            InboxRegistrationRecord.self,
            from: JSONSerialization.data(withJSONObject: legacyObject)
        )
        XCTAssertTrue(migrated.routeMutationScope.isValidRouteMutationScope)
        XCTAssertEqual(migrated.lastRouteMutationSequence, 0)
        XCTAssertNil(migrated.lastRouteMutationDigest)
    }

    func testFederationPreservesCapabilityOnlyDeliveryShape() throws {
        let federation = FederationDescriptor(mode: .open, name: "opaque-route-test")
        let source = try RelayTCPHarness(
            kind: .bridge,
            federation: federation,
            compatibilityProfiles: [],
            experimentalRouteCapabilitiesEnabled: true
        )
        let destination = try RelayTCPHarness(
            kind: .standard,
            federation: federation,
            compatibilityProfiles: [],
            experimentalRouteCapabilitiesEnabled: true
        )
        defer {
            try? source.shutdown()
            try? destination.shutdown()
        }
        let signer = try makeSignerOrSkip()
        let inboxId = InboxAddress.derived(from: signer.publicKey)
        let unsignedRegistration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey
        )
        let registrationResponse = try destination.send(
            .registerInbox(
                RegisterInboxRequest.privacyMinimizedV2(
                    inboxId: inboxId,
                    accessPublicKey: signer.publicKey,
                    accessProof: try signer.proof {
                        try unsignedRegistration.signableData(for: $0)
                    }
                )
            )
        )
        XCTAssertEqual(registrationResponse.type, .ok)
        let registrationReceipt = try XCTUnwrap(registrationResponse.inboxRegistration)
        let capability = routeCapability(0x7A)
        let unsignedCreate = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: registrationReceipt.routeMutationScope,
            mutationSequence: registrationReceipt.nextRouteMutationSequence
        )
        XCTAssertEqual(
            try destination.send(
                .createInboxRouteCapability(
                    CreateInboxRouteCapabilityRequest(
                        inboxId: inboxId,
                        capability: capability,
                        relayScope: registrationReceipt.routeMutationScope,
                        mutationSequence: registrationReceipt.nextRouteMutationSequence,
                        authorityProof: try signer.proof {
                            try unsignedCreate.signableData(for: $0)
                        }
                    )
                )
            ).type,
            .ok
        )
        let response = try source.send(
            .deliver(
                DeliverRequest(
                    inboxCapability: capability,
                    envelope: envelope(80),
                    destinationRelay: destination.endpoint
                )
            )
        )
        XCTAssertEqual(response.type, .delivered)
        XCTAssertEqual(response.delivered?.storedCount, 1)
    }

    func testRelayAuthenticatesCapabilityLifecycleAndFailsClosedAfterRevocation() throws {
        let harness = try RelayTCPHarness(
            compatibilityProfiles: [],
            experimentalRouteCapabilitiesEnabled: true
        )
        defer { try? harness.shutdown() }
        let signer = try makeSignerOrSkip()
        let inboxId = InboxAddress.derived(from: signer.publicKey)
        let unsignedRegistration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey
        )
        let registration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey,
            accessProof: try signer.proof { try unsignedRegistration.signableData(for: $0) }
        )
        let registrationResponse = try harness.send(.registerInbox(registration))
        XCTAssertEqual(registrationResponse.type, .ok)
        let registrationReceipt = try XCTUnwrap(registrationResponse.inboxRegistration)

        let capability = routeCapability(0x71)
        XCTAssertEqual(
            try harness.send(
                .deliver(DeliverRequest(inboxCapability: capability, envelope: envelope(70)))
            ).error,
            "Inbox route capability is unavailable"
        )

        let unsignedCreate = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: registrationReceipt.routeMutationScope,
            mutationSequence: registrationReceipt.nextRouteMutationSequence
        )
        XCTAssertEqual(
            try harness.send(.createInboxRouteCapability(unsignedCreate)).error,
            "Missing actor proof."
        )
        let create = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: registrationReceipt.routeMutationScope,
            mutationSequence: registrationReceipt.nextRouteMutationSequence,
            authorityProof: try signer.proof { try unsignedCreate.signableData(for: $0) }
        )
        XCTAssertEqual(try harness.send(.createInboxRouteCapability(create)).type, .ok)
        XCTAssertEqual(try harness.send(.createInboxRouteCapability(create)).type, .ok)
        let freshlySignedCreate = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: registrationReceipt.routeMutationScope,
            mutationSequence: registrationReceipt.nextRouteMutationSequence,
            authorityProof: try signer.proof { try unsignedCreate.signableData(for: $0) }
        )
        XCTAssertEqual(
            try harness.send(.createInboxRouteCapability(freshlySignedCreate)).type,
            .ok
        )
        let expiredCurrentReplay = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: registrationReceipt.routeMutationScope,
            mutationSequence: registrationReceipt.nextRouteMutationSequence,
            authorityProof: try signer.proof(
                signedAt: Date().addingTimeInterval(-RelayActorProof.maximumAgeSeconds - 30)
            ) {
                try unsignedCreate.signableData(for: $0)
            }
        )
        XCTAssertEqual(
            try harness.send(.createInboxRouteCapability(expiredCurrentReplay)).type,
            .ok
        )

        let neverAppliedCapability = routeCapability(0x73)
        let unsignedExpiredFirstApplication = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: neverAppliedCapability,
            relayScope: registrationReceipt.routeMutationScope,
            mutationSequence: registrationReceipt.nextRouteMutationSequence + 1
        )
        let expiredFirstApplication = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: neverAppliedCapability,
            relayScope: registrationReceipt.routeMutationScope,
            mutationSequence: registrationReceipt.nextRouteMutationSequence + 1,
            authorityProof: try signer.proof(
                signedAt: Date().addingTimeInterval(-RelayActorProof.maximumAgeSeconds - 30)
            ) {
                try unsignedExpiredFirstApplication.signableData(for: $0)
            }
        )
        XCTAssertEqual(
            try harness.send(.createInboxRouteCapability(expiredFirstApplication)).error,
            "Actor proof expired."
        )
        XCTAssertEqual(
            try harness.send(
                .deliver(DeliverRequest(inboxCapability: capability, envelope: envelope(71)))
            ).type,
            .delivered
        )

        let unsignedRevoke = RevokeInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: registrationReceipt.routeMutationScope,
            mutationSequence: registrationReceipt.nextRouteMutationSequence + 1
        )
        let revoke = RevokeInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: registrationReceipt.routeMutationScope,
            mutationSequence: registrationReceipt.nextRouteMutationSequence + 1,
            authorityProof: try signer.proof { try unsignedRevoke.signableData(for: $0) }
        )
        XCTAssertEqual(try harness.send(.revokeInboxRouteCapability(revoke)).type, .ok)
        XCTAssertEqual(
            try harness.send(
                .deliver(DeliverRequest(inboxCapability: capability, envelope: envelope(72)))
            ).error,
            "Inbox route capability is unavailable"
        )
    }

    func testRouteMutationStorageFailureIsRetryableOverWire() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-linux-route-wire-failure-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let harness = try RelayTCPHarness(
            compatibilityProfiles: [],
            storeFileURL: directory.appendingPathComponent("relay.sqlite"),
            experimentalRouteCapabilitiesEnabled: true
        )
        defer { try? harness.shutdown() }
        let signer = try makeSignerOrSkip()
        let inboxId = InboxAddress.derived(from: signer.publicKey)
        let unsignedRegistration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey
        )
        let registration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey,
            accessProof: try signer.proof {
                try unsignedRegistration.signableData(for: $0)
            }
        )
        let registrationResponse = try harness.send(.registerInbox(registration))
        let receipt = try XCTUnwrap(registrationResponse.inboxRegistration)
        let capability = routeCapability(0x74)
        let unsignedCreate = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: receipt.routeMutationScope,
            mutationSequence: receipt.nextRouteMutationSequence
        )
        let create = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: receipt.routeMutationScope,
            mutationSequence: receipt.nextRouteMutationSequence,
            authorityProof: try signer.proof {
                try unsignedCreate.signableData(for: $0)
            }
        )

        harness.failNextPersistenceForTesting()
        XCTAssertEqual(
            try harness.send(.createInboxRouteCapability(create)).error,
            "Relay storage is unavailable"
        )
        XCTAssertEqual(
            try harness.send(.createInboxRouteCapability(create)).type,
            .ok
        )
        XCTAssertEqual(
            try harness.send(
                .deliver(DeliverRequest(inboxCapability: capability, envelope: envelope(74)))
            ).type,
            .delivered
        )
    }

    func testCapabilityMutationProofAndCapabilityOnlyDeliveryWireMatchCore() throws {
        let capability = routeCapability(0xAB)
        let relayScope = Data(repeating: 0xCD, count: 32)
        let request = CreateInboxRouteCapabilityRequest(
            inboxId: "inbox",
            capability: capability,
            relayScope: relayScope,
            mutationSequence: 7
        )
        let proof = RelayActorProof(
            fingerprint: "",
            publicSigningKey: Data(),
            signedAt: try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-07-16T12:34:56Z")),
            nonce: try XCTUnwrap(UUID(uuidString: "11111111-1111-4111-8111-111111111111")),
            signature: Data()
        )
        XCTAssertEqual(
            String(decoding: try request.signableData(for: proof), as: UTF8.self),
            #"{"capabilityDigest":"IkvMkZBanyd6iiDOZ3EZYnGhrcwmV+X6MhLMUiFpYQY=","domain":"org.noctweave.relay.inbox-route-capability-mutation","inboxId":"inbox","mutationSequence":7,"nonce":"11111111-1111-4111-8111-111111111111","operation":"create","relayScope":"zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0=","signedAt":"2026-07-16T12:34:56Z","version":3}"#
        )
        XCTAssertEqual(
            try request.mutationDigest().base64EncodedString(),
            "XyEdBJ/tHu/mmgaLIXY0D4JSQ9dLnn5+V9/t3Bh8lWw="
        )

        let wire = try RelayCodec.encoder().encode(
            RelayRequest.deliver(
                DeliverRequest(
                    inboxCapability: capability,
                    envelope: envelope(1)
                )
            )
        )
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: wire) as? [String: Any])
        let deliver = try XCTUnwrap(object["deliver"] as? [String: Any])
        XCTAssertEqual(Set(deliver.keys), ["envelope", "inboxCapability"])
        XCTAssertNil(deliver["inboxId"])
        XCTAssertNil(deliver["routingToken"])
        XCTAssertEqual(object["type"] as? String, "deliver")
    }

    func testBoundedMakeBeforeBreakRevocationAndRetirementPurge() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA1]))

        let old = routeCapability(0x01)
        let replacement = routeCapability(0x02)
        try store.seedInboxRouteCapabilityForTesting(inboxId: inboxId, capability: old)
        try store.seedInboxRouteCapabilityForTesting(inboxId: inboxId, capability: replacement)
        XCTAssertEqual(store.resolveInboxRouteCapability(old), inboxId)
        XCTAssertEqual(store.resolveInboxRouteCapability(replacement), inboxId)

        try store.seedInboxRouteCapabilityRevocationForTesting(inboxId: inboxId, capability: old)
        try store.seedInboxRouteCapabilityRevocationForTesting(inboxId: inboxId, capability: old)
        XCTAssertNil(store.resolveInboxRouteCapability(old))
        XCTAssertEqual(store.resolveInboxRouteCapability(replacement), inboxId)
        XCTAssertThrowsError(
            try store.seedInboxRouteCapabilityForTesting(inboxId: inboxId, capability: old)
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .inboxRouteCapabilityRevoked)
        }

        for marker in UInt8(3)...UInt8(17) {
            try store.seedInboxRouteCapabilityForTesting(
                inboxId: inboxId,
                capability: routeCapability(marker)
            )
        }
        XCTAssertThrowsError(
            try store.seedInboxRouteCapabilityForTesting(
                inboxId: inboxId,
                capability: routeCapability(0x40)
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .inboxRouteCapabilityLimitReached)
        }

        try store.retireInbox(
            inboxId: inboxId,
            requestDigest: Data(repeating: 0x77, count: 32)
        )
        XCTAssertNil(store.resolveInboxRouteCapability(replacement))
        XCTAssertEqual(store.inboxRouteCapabilityRecordCount(), 0)
    }

    func testRevokingActiveCapabilityKeepsTombstonesBounded() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA2]))

        let active = routeCapability(0xF0)
        try store.seedInboxRouteCapabilityForTesting(inboxId: inboxId, capability: active)
        for marker in UInt8(1)...UInt8(64) {
            try store.seedInboxRouteCapabilityRevocationForTesting(
                inboxId: inboxId,
                capability: routeCapability(marker)
            )
        }
        XCTAssertEqual(store.inboxRouteCapabilityRecordCount(), 65)

        try store.seedInboxRouteCapabilityRevocationForTesting(inboxId: inboxId, capability: active)
        XCTAssertEqual(store.inboxRouteCapabilityRecordCount(), 64)
    }

    func testCapabilityRegistryPersistsDigestOnlyAndRollsBackAtomically() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-linux-route-capability-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("relay.sqlite")
        let inboxId = InboxAddress.generate()
        let persisted = routeCapability(0x51)
        let rolledBack = routeCapability(0x52)

        let store = RelayStore(fileURL: storeURL, maxInboxMessages: nil, temporalBucketSeconds: 0)
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xB1]))
        try store.seedInboxRouteCapabilityForTesting(inboxId: inboxId, capability: persisted)
        store.failNextPersistenceForTesting()
        XCTAssertThrowsError(
            try store.seedInboxRouteCapabilityForTesting(inboxId: inboxId, capability: rolledBack)
        )
        XCTAssertNil(store.resolveInboxRouteCapability(rolledBack))
        XCTAssertEqual(store.resolveInboxRouteCapability(persisted), inboxId)

        let reloaded = RelayStore(fileURL: storeURL, maxInboxMessages: nil, temporalBucketSeconds: 0)
        try reloaded.load()
        XCTAssertEqual(reloaded.resolveInboxRouteCapability(persisted), inboxId)
        XCTAssertNil(reloaded.resolveInboxRouteCapability(rolledBack))

        let bytes = try Data(contentsOf: storeURL)
        XCTAssertNil(bytes.range(of: persisted.rawValue))
        XCTAssertNotNil(
            bytes.range(of: Data(persisted.relayRegistryDigest.base64EncodedString().utf8))
        )
    }

    func testSequencedMutationsAreScopedOrderedReplaySafeAndAtomic() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-linux-route-sequence-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("relay.sqlite")
        let inboxId = InboxAddress.generate()
        let store = RelayStore(fileURL: storeURL, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let receipt = try store.registerInbox(
            inboxId: inboxId,
            accessPublicKey: Data([0xC1])
        )
        let capability = routeCapability(0x81)
        let create = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: receipt.routeMutationScope,
            mutationSequence: 1
        )

        store.failNextPersistenceForTesting()
        XCTAssertThrowsError(
            try store.applyInboxRouteCapabilityMutation(
                operation: .create,
                inboxId: inboxId,
                capability: capability,
                relayScope: receipt.routeMutationScope,
                mutationSequence: 1,
                mutationDigest: create.mutationDigest()
            )
        )
        XCTAssertNil(store.resolveInboxRouteCapability(capability))

        XCTAssertEqual(
            try store.applyInboxRouteCapabilityMutation(
                operation: .create,
                inboxId: inboxId,
                capability: capability,
                relayScope: receipt.routeMutationScope,
                mutationSequence: 1,
                mutationDigest: create.mutationDigest()
            ),
            .applied
        )
        XCTAssertEqual(
            try store.applyInboxRouteCapabilityMutation(
                operation: .create,
                inboxId: inboxId,
                capability: capability,
                relayScope: receipt.routeMutationScope,
                mutationSequence: 1,
                mutationDigest: create.mutationDigest()
            ),
            .replayed
        )

        let conflicting = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: routeCapability(0x82),
            relayScope: receipt.routeMutationScope,
            mutationSequence: 1
        )
        XCTAssertThrowsError(
            try store.applyInboxRouteCapabilityMutation(
                operation: .create,
                inboxId: inboxId,
                capability: conflicting.capability,
                relayScope: receipt.routeMutationScope,
                mutationSequence: 1,
                mutationDigest: conflicting.mutationDigest()
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .inboxRouteCapabilityMutationConflict)
        }
        XCTAssertThrowsError(
            try store.applyInboxRouteCapabilityMutation(
                operation: .create,
                inboxId: inboxId,
                capability: routeCapability(0x83),
                relayScope: receipt.routeMutationScope,
                mutationSequence: 3,
                mutationDigest: Data(repeating: 0x33, count: 32)
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .inboxRouteCapabilityMutationOutOfOrder)
        }

        let revoke = RevokeInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: receipt.routeMutationScope,
            mutationSequence: 2
        )
        _ = try store.applyInboxRouteCapabilityMutation(
            operation: .revoke,
            inboxId: inboxId,
            capability: capability,
            relayScope: receipt.routeMutationScope,
            mutationSequence: 2,
            mutationDigest: revoke.mutationDigest()
        )
        for marker in UInt8(1)...UInt8(64) {
            try store.seedInboxRouteCapabilityRevocationForTesting(
                inboxId: inboxId,
                capability: routeCapability(marker)
            )
        }
        XCTAssertThrowsError(
            try store.applyInboxRouteCapabilityMutation(
                operation: .create,
                inboxId: inboxId,
                capability: capability,
                relayScope: receipt.routeMutationScope,
                mutationSequence: 1,
                mutationDigest: create.mutationDigest()
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .inboxRouteCapabilityMutationOutOfOrder)
        }

        let reloaded = RelayStore(fileURL: storeURL, maxInboxMessages: nil, temporalBucketSeconds: 0)
        try reloaded.load()
        XCTAssertEqual(
            try reloaded.applyInboxRouteCapabilityMutation(
                operation: .revoke,
                inboxId: inboxId,
                capability: capability,
                relayScope: receipt.routeMutationScope,
                mutationSequence: 2,
                mutationDigest: revoke.mutationDigest()
            ),
            .replayed
        )

        let otherRelay = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let otherReceipt = try otherRelay.registerInbox(
            inboxId: inboxId,
            accessPublicKey: Data([0xC1])
        )
        XCTAssertNotEqual(otherReceipt.routeMutationScope, receipt.routeMutationScope)
        XCTAssertThrowsError(
            try otherRelay.applyInboxRouteCapabilityMutation(
                operation: .create,
                inboxId: inboxId,
                capability: capability,
                relayScope: receipt.routeMutationScope,
                mutationSequence: 1,
                mutationDigest: create.mutationDigest()
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .invalidInboxRouteCapabilityMutation)
        }
    }

    private func routeCapability(_ marker: UInt8) -> InboxRouteCapabilityV2 {
        InboxRouteCapabilityV2(rawValue: Data(repeating: marker, count: 32))
    }

    private func envelope(_ counter: UInt64) -> Envelope {
        Envelope(
            conversationId: "opaque-route-test",
            sessionId: "session-v2",
            senderFingerprint: Data(repeating: 0x33, count: 32).base64EncodedString(),
            sentAt: Date(timeIntervalSince1970: TimeInterval(10_000 + counter)),
            messageCounter: counter,
            kemCiphertext: nil,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: 12),
                ciphertext: Data(repeating: UInt8(truncatingIfNeeded: counter), count: 512),
                tag: Data(repeating: 0x22, count: 16)
            ),
            signature: Data(
                repeating: 0x44,
                count: OQSSignatureVerifier.mlDSA65SignatureBytes
            )
        )
    }

    private func makeSignerOrSkip() throws -> RouteCapabilitySigner {
        guard let pair = OQSSignatureVerifier.shared.generateKeyPair() else {
            throw XCTSkip("ML-DSA runtime is unavailable")
        }
        return RouteCapabilitySigner(privateKey: pair.privateKey, publicKey: pair.publicKey)
    }
}

private struct RouteCapabilitySigner {
    let privateKey: Data
    let publicKey: Data

    func proof(
        signedAt: Date = Date(),
        signableData: (RelayActorProof) throws -> Data
    ) throws -> RelayActorProof {
        let draft = RelayActorProof(
            fingerprint: Data(SHA256.hash(data: publicKey)).base64EncodedString(),
            publicSigningKey: publicKey,
            signedAt: signedAt,
            nonce: UUID(),
            signature: Data()
        )
        guard let signature = OQSSignatureVerifier.shared.sign(
            data: try signableData(draft),
            privateKey: privateKey,
            publicKey: publicKey
        ) else {
            throw XCTSkip("ML-DSA signing is unavailable")
        }
        return RelayActorProof(
            fingerprint: draft.fingerprint,
            publicSigningKey: draft.publicSigningKey,
            signedAt: draft.signedAt,
            nonce: draft.nonce,
            signature: signature
        )
    }
}
