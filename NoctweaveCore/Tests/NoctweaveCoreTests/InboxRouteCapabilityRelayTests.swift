import Foundation
import XCTest
@testable import NoctweaveCore

final class InboxRouteCapabilityRelayTests: XCTestCase {
    func testRouteCapabilityProtocolIsDisabledByDefault() async throws {
        let store = RelayStore()
        let server = RelayServer(store: store)
        let port = UInt16.random(in: 46_000...48_000)
        let started = expectation(description: "default route-disabled relay started")
        server.onEvent = { if case .started = $0 { started.fulfill() } }
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2)

        let client = RelayClient(endpoint: RelayEndpoint(host: "127.0.0.1", port: port))
        let response = try await client.send(
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

        let accessKey = try SigningKeyPair.generate()
        let inboxId = InboxAddress.derived(from: accessKey.publicKeyData)
        let unsignedRegistration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData
        )
        let registration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            accessProof: try proof(signingKey: accessKey) {
                try unsignedRegistration.signableData(for: $0)
            }
        )
        let registrationResponse = try await client.send(.registerInbox(registration))
        XCTAssertEqual(registrationResponse.type, .ok)
        XCTAssertNil(registrationResponse.inboxRegistration)

        let capability = routeCapability(0x71)
        let scope = Data(repeating: 0x72, count: 32)
        let create = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: scope,
            mutationSequence: 1
        )
        let revoke = RevokeInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: scope,
            mutationSequence: 1
        )
        let disabledCreate = try await client.send(.createInboxRouteCapability(create))
        XCTAssertEqual(
            disabledCreate.error,
            "Experimental opaque route capabilities are disabled"
        )
        let disabledRevoke = try await client.send(.revokeInboxRouteCapability(revoke))
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
            JSONSerialization.jsonObject(
                with: NoctweaveCoder.encode(current, sortedKeys: true)
            ) as? [String: Any]
        )
        missingScope.removeValue(forKey: "routeMutationScope")
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                InboxRegistrationRecord.self,
                from: JSONSerialization.data(withJSONObject: missingScope)
            )
        )

        var invalidScope = missingScope
        invalidScope["routeMutationScope"] = Data(repeating: 0, count: 32)
            .base64EncodedString()
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
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
            try NoctweaveCoder.decode(
                InboxRegistrationRecord.self,
                from: JSONSerialization.data(withJSONObject: exhausted)
            )
        )

        let legacy = InboxRegistrationRecord(
            accessPublicKey: Data([0x02]),
            registeredAt: Date(timeIntervalSince1970: 1_001)
        )
        var legacyObject = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: NoctweaveCoder.encode(legacy, sortedKeys: true)
            ) as? [String: Any]
        )
        var explicitNullScope = legacyObject
        explicitNullScope["routeMutationScope"] = NSNull()
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                InboxRegistrationRecord.self,
                from: JSONSerialization.data(withJSONObject: explicitNullScope)
            )
        )
        legacyObject.removeValue(forKey: "routeMutationScope")
        legacyObject.removeValue(forKey: "lastRouteMutationSequence")
        legacyObject.removeValue(forKey: "lastRouteMutationDigest")
        let migrated = try NoctweaveCoder.decode(
            InboxRegistrationRecord.self,
            from: JSONSerialization.data(withJSONObject: legacyObject)
        )
        XCTAssertTrue(migrated.routeMutationScope.isValidRouteMutationScope)
        XCTAssertEqual(migrated.lastRouteMutationSequence, 0)
        XCTAssertNil(migrated.lastRouteMutationDigest)
    }

    func testFederationForwardsCapabilityWithoutInboxIdentifier() async throws {
        let sourceStore = RelayStore()
        let destinationStore = RelayStore()
        let sourceEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: UInt16.random(in: 54_100...54_900)
        )
        var destinationPort = UInt16.random(in: 55_100...55_900)
        while destinationPort == sourceEndpoint.port {
            destinationPort = UInt16.random(in: 55_100...55_900)
        }
        let destinationEndpoint = RelayEndpoint(host: "127.0.0.1", port: destinationPort)
        let federation = FederationDescriptor(mode: .manual, name: "opaque-route-test")
        let source = RelayServer(
            store: sourceStore,
            configuration: RelayConfiguration(
                federation: federation,
                federationAllowList: [destinationEndpoint],
                experimentalRouteCapabilitiesEnabled: true
            )
        )
        let destination = RelayServer(
            store: destinationStore,
            configuration: RelayConfiguration(
                federation: federation,
                federationAllowList: [sourceEndpoint],
                experimentalRouteCapabilitiesEnabled: true
            )
        )
        let sourceStarted = expectation(description: "source relay started")
        let destinationStarted = expectation(description: "destination relay started")
        source.onEvent = { if case .started = $0 { sourceStarted.fulfill() } }
        destination.onEvent = { if case .started = $0 { destinationStarted.fulfill() } }
        try source.start(host: "127.0.0.1", port: sourceEndpoint.port)
        try destination.start(host: "127.0.0.1", port: destinationEndpoint.port)
        defer {
            source.stop()
            destination.stop()
        }
        await fulfillment(of: [sourceStarted, destinationStarted], timeout: 2)

        let inboxId = InboxAddress.generate()
        let capability = routeCapability(0x7A)
        try await destinationStore.registerInbox(
            inboxId: inboxId,
            accessPublicKey: Data([0xA2])
        )
        try await destinationStore.seedInboxRouteCapabilityForTesting(
            inboxId: inboxId,
            capability: capability
        )
        let response = try await RelayClient(endpoint: sourceEndpoint).send(
            .deliver(
                DeliverRequest(
                    inboxCapability: capability,
                    envelope: envelope(80),
                    destinationRelay: destinationEndpoint
                )
            )
        )
        XCTAssertEqual(response.type, .delivered)
        let sourceStats = await sourceStore.stats()
        let destinationStats = await destinationStore.stats()
        XCTAssertEqual(sourceStats.messages, 0)
        XCTAssertEqual(destinationStats.messages, 1)
    }

    func testRelayAuthenticatesCapabilityLifecycleAndRejectsUnavailableRoutesWithoutAllocation() async throws {
        let store = RelayStore()
        let server = RelayServer(
            store: store,
            configuration: RelayConfiguration(experimentalRouteCapabilitiesEnabled: true)
        )
        let port = UInt16.random(in: 52_000...54_000)
        let started = expectation(description: "opaque route relay started")
        server.onEvent = { event in
            if case .started = event { started.fulfill() }
        }
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2)
        let client = RelayClient(endpoint: RelayEndpoint(host: "127.0.0.1", port: port))

        let accessKey = try SigningKeyPair.generate()
        let inboxId = InboxAddress.derived(from: accessKey.publicKeyData)
        let unsignedRegistration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData
        )
        let registration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            accessProof: try proof(signingKey: accessKey) {
                try unsignedRegistration.signableData(for: $0)
            }
        )
        let registrationResponse = try await client.send(.registerInbox(registration))
        XCTAssertEqual(registrationResponse.type, .ok)
        let registrationReceipt = try XCTUnwrap(registrationResponse.inboxRegistration)

        let capability = routeCapability(0x71)
        let unavailable = try await client.send(
            .deliver(DeliverRequest(inboxCapability: capability, envelope: envelope(70)))
        )
        XCTAssertEqual(unavailable.error, "Inbox route capability is unavailable")
        var stats = await store.stats()
        XCTAssertEqual(stats.messages, 0)

        let unsignedCreate = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: registrationReceipt.routeMutationScope,
            mutationSequence: registrationReceipt.nextRouteMutationSequence
        )
        let unauthorizedCreate = try await client.send(
            .createInboxRouteCapability(unsignedCreate)
        )
        XCTAssertEqual(unauthorizedCreate.error, "Missing actor proof.")
        var resolved = await store.resolveInboxRouteCapability(capability)
        XCTAssertNil(resolved)
        let create = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: registrationReceipt.routeMutationScope,
            mutationSequence: registrationReceipt.nextRouteMutationSequence,
            authorityProof: try proof(signingKey: accessKey) {
                try unsignedCreate.signableData(for: $0)
            }
        )
        let createResponse = try await client.send(.createInboxRouteCapability(create))
        XCTAssertEqual(createResponse.type, .ok)
        let exactCreateRetry = try await client.send(.createInboxRouteCapability(create))
        XCTAssertEqual(exactCreateRetry.type, .ok)
        let freshlySignedCreate = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: registrationReceipt.routeMutationScope,
            mutationSequence: registrationReceipt.nextRouteMutationSequence,
            authorityProof: try proof(signingKey: accessKey) {
                try unsignedCreate.signableData(for: $0)
            }
        )
        let freshCreateRetry = try await client.send(
            .createInboxRouteCapability(freshlySignedCreate)
        )
        XCTAssertEqual(freshCreateRetry.type, .ok)
        let expiredCurrentReplay = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: registrationReceipt.routeMutationScope,
            mutationSequence: registrationReceipt.nextRouteMutationSequence,
            authorityProof: try proof(
                signingKey: accessKey,
                signedAt: Date().addingTimeInterval(-RelayActorProof.maximumAgeSeconds - 30)
            ) {
                try unsignedCreate.signableData(for: $0)
            }
        )
        let expiredReplayResponse = try await client.send(
            .createInboxRouteCapability(expiredCurrentReplay)
        )
        XCTAssertEqual(expiredReplayResponse.type, .ok)

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
            authorityProof: try proof(
                signingKey: accessKey,
                signedAt: Date().addingTimeInterval(-RelayActorProof.maximumAgeSeconds - 30)
            ) {
                try unsignedExpiredFirstApplication.signableData(for: $0)
            }
        )
        let expiredFirstResponse = try await client.send(
            .createInboxRouteCapability(expiredFirstApplication)
        )
        XCTAssertEqual(expiredFirstResponse.error, "Actor proof expired.")
        let delivered = try await client.send(
            .deliver(DeliverRequest(inboxCapability: capability, envelope: envelope(71)))
        )
        XCTAssertEqual(delivered.type, .delivered)
        stats = await store.stats()
        XCTAssertEqual(stats.messages, 1)

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
            authorityProof: try proof(signingKey: accessKey) {
                try unsignedRevoke.signableData(for: $0)
            }
        )
        let revokeResponse = try await client.send(.revokeInboxRouteCapability(revoke))
        XCTAssertEqual(revokeResponse.type, .ok)
        let revoked = try await client.send(
            .deliver(DeliverRequest(inboxCapability: capability, envelope: envelope(72)))
        )
        XCTAssertEqual(revoked.error, "Inbox route capability is unavailable")
        stats = await store.stats()
        XCTAssertEqual(stats.messages, 1)

        XCTAssertThrowsError(
            try InboxRouteCapabilityV2.importAuthenticatedBearer(
                Data(repeating: 0x72, count: 31)
            )
        )
        XCTAssertThrowsError(
            try InboxRouteCapabilityV2.importAuthenticatedBearer(
                Data(repeating: 0, count: 32)
            )
        )
        let generated = InboxRouteCapabilityV2.generate()
        XCTAssertTrue(generated.isStructurallyValid)
        XCTAssertEqual(generated.description, "InboxRouteCapabilityV2(<redacted>)")
        stats = await store.stats()
        XCTAssertEqual(stats.messages, 1)
    }

    func testRouteMutationStorageFailureIsRetryableOverWire() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-route-wire-failure-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let store = RelayStore(
            storeURL: directory.appendingPathComponent("relay.sqlite"),
            temporalBucketSeconds: 0
        )
        let server = RelayServer(
            store: store,
            configuration: RelayConfiguration(experimentalRouteCapabilitiesEnabled: true)
        )
        let port = UInt16.random(in: 49_000...51_000)
        let started = expectation(description: "route failure relay started")
        server.onEvent = { if case .started = $0 { started.fulfill() } }
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2)

        let client = RelayClient(endpoint: RelayEndpoint(host: "127.0.0.1", port: port))
        let accessKey = try SigningKeyPair.generate()
        let inboxId = InboxAddress.derived(from: accessKey.publicKeyData)
        let unsignedRegistration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData
        )
        let registration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            accessProof: try proof(signingKey: accessKey) {
                try unsignedRegistration.signableData(for: $0)
            }
        )
        let registrationResponse = try await client.send(.registerInbox(registration))
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
            authorityProof: try proof(signingKey: accessKey) {
                try unsignedCreate.signableData(for: $0)
            }
        )

        await store.failNextPersistenceForTesting()
        let failed = try await client.send(.createInboxRouteCapability(create))
        XCTAssertEqual(failed.error, "Relay storage is unavailable")
        let resolvedAfterFailure = await store.resolveInboxRouteCapability(capability)
        XCTAssertNil(resolvedAfterFailure)

        let retried = try await client.send(.createInboxRouteCapability(create))
        XCTAssertEqual(retried.type, .ok)
        let resolvedAfterRetry = await store.resolveInboxRouteCapability(capability)
        XCTAssertEqual(resolvedAfterRetry, inboxId)
    }

    func testCapabilityMutationProofAndCapabilityOnlyDeliveryWireAreCanonical() throws {
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
            "cOCi7pyjuNc1mcAcU8WGHEcy2zQPlm8bg3/t+K6gXvY="
        )

        let wire = try NoctweaveCoder.encode(
            RelayRequest.deliver(
                DeliverRequest(
                    inboxCapability: capability,
                    envelope: envelope(1)
                )
            ),
            sortedKeys: true
        )
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: wire) as? [String: Any])
        let deliver = try XCTUnwrap(object["deliver"] as? [String: Any])
        XCTAssertEqual(Set(deliver.keys), ["envelope", "inboxCapability"])
        XCTAssertNil(deliver["inboxId"])
        XCTAssertNil(deliver["routingToken"])
        XCTAssertEqual(object["type"] as? String, "deliver")
    }

    func testBoundedMakeBeforeBreakRevocationAndRetirementPurge() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA1]))

        let old = routeCapability(0x01)
        let replacement = routeCapability(0x02)
        try await store.seedInboxRouteCapabilityForTesting(inboxId: inboxId, capability: old)
        try await store.seedInboxRouteCapabilityForTesting(inboxId: inboxId, capability: replacement)
        var resolvedOld = await store.resolveInboxRouteCapability(old)
        var resolvedReplacement = await store.resolveInboxRouteCapability(replacement)
        XCTAssertEqual(resolvedOld, inboxId)
        XCTAssertEqual(resolvedReplacement, inboxId)

        try await store.seedInboxRouteCapabilityRevocationForTesting(inboxId: inboxId, capability: old)
        try await store.seedInboxRouteCapabilityRevocationForTesting(inboxId: inboxId, capability: old)
        resolvedOld = await store.resolveInboxRouteCapability(old)
        resolvedReplacement = await store.resolveInboxRouteCapability(replacement)
        XCTAssertNil(resolvedOld)
        XCTAssertEqual(resolvedReplacement, inboxId)
        await XCTAssertThrowsRouteCapabilityError(
            try await store.seedInboxRouteCapabilityForTesting(inboxId: inboxId, capability: old),
            expected: .inboxRouteCapabilityRevoked
        )

        for marker in UInt8(3)...UInt8(17) {
            try await store.seedInboxRouteCapabilityForTesting(
                inboxId: inboxId,
                capability: routeCapability(marker)
            )
        }
        await XCTAssertThrowsRouteCapabilityError(
            try await store.seedInboxRouteCapabilityForTesting(
                inboxId: inboxId,
                capability: routeCapability(0x40)
            ),
            expected: .inboxRouteCapabilityLimitReached
        )

        try await store.retireInbox(
            inboxId: inboxId,
            requestDigest: Data(repeating: 0x77, count: 32)
        )
        resolvedReplacement = await store.resolveInboxRouteCapability(replacement)
        let recordCount = await store.inboxRouteCapabilityRecordCount()
        XCTAssertNil(resolvedReplacement)
        XCTAssertEqual(recordCount, 0)
    }

    func testRevokingActiveCapabilityKeepsTombstonesBounded() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA2]))

        let active = routeCapability(0xF0)
        try await store.seedInboxRouteCapabilityForTesting(inboxId: inboxId, capability: active)
        for marker in UInt8(1)...UInt8(64) {
            try await store.seedInboxRouteCapabilityRevocationForTesting(
                inboxId: inboxId,
                capability: routeCapability(marker)
            )
        }
        let beforeActiveRevocation = await store.inboxRouteCapabilityRecordCount()
        XCTAssertEqual(beforeActiveRevocation, 65)

        try await store.seedInboxRouteCapabilityRevocationForTesting(inboxId: inboxId, capability: active)
        let afterActiveRevocation = await store.inboxRouteCapabilityRecordCount()
        XCTAssertEqual(afterActiveRevocation, 64)
    }

    func testCapabilityRegistryPersistsDigestOnlyAndRollsBackAtomically() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-route-capability-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("relay.sqlite")
        let inboxId = InboxAddress.generate()
        let persisted = routeCapability(0x51)
        let rolledBack = routeCapability(0x52)

        let store = RelayStore(storeURL: storeURL, temporalBucketSeconds: 0)
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xB1]))
        try await store.seedInboxRouteCapabilityForTesting(inboxId: inboxId, capability: persisted)
        await store.failNextPersistenceForTesting()
        do {
            try await store.seedInboxRouteCapabilityForTesting(inboxId: inboxId, capability: rolledBack)
            XCTFail("Expected injected persistence failure")
        } catch {
            let resolvedRolledBack = await store.resolveInboxRouteCapability(rolledBack)
            XCTAssertNil(resolvedRolledBack)
        }
        let resolvedPersisted = await store.resolveInboxRouteCapability(persisted)
        XCTAssertEqual(resolvedPersisted, inboxId)

        let reloaded = RelayStore(storeURL: storeURL, temporalBucketSeconds: 0)
        try await reloaded.loadFromDisk()
        let reloadedPersisted = await reloaded.resolveInboxRouteCapability(persisted)
        let reloadedRolledBack = await reloaded.resolveInboxRouteCapability(rolledBack)
        XCTAssertEqual(reloadedPersisted, inboxId)
        XCTAssertNil(reloadedRolledBack)

        let bytes = try Data(contentsOf: storeURL)
        XCTAssertNil(bytes.range(of: persisted.rawValue))
        XCTAssertNotNil(
            bytes.range(of: Data(persisted.relayRegistryDigest.base64EncodedString().utf8))
        )
    }

    func testSequencedMutationsAreScopedOrderedReplaySafeAndAtomic() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-route-sequence-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("relay.sqlite")
        let inboxId = InboxAddress.generate()
        let store = RelayStore(storeURL: storeURL, temporalBucketSeconds: 0)
        let receipt = try await store.registerInbox(
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

        await store.failNextPersistenceForTesting()
        do {
            _ = try await store.applyInboxRouteCapabilityMutation(
                operation: .create,
                inboxId: inboxId,
                capability: capability,
                relayScope: receipt.routeMutationScope,
                mutationSequence: 1,
                mutationDigest: create.mutationDigest()
            )
            XCTFail("Expected injected persistence failure")
        } catch {
            let resolvedAfterFailure = await store.resolveInboxRouteCapability(capability)
            XCTAssertNil(resolvedAfterFailure)
        }

        let applied = try await store.applyInboxRouteCapabilityMutation(
            operation: .create,
            inboxId: inboxId,
            capability: capability,
            relayScope: receipt.routeMutationScope,
            mutationSequence: 1,
            mutationDigest: create.mutationDigest()
        )
        XCTAssertEqual(applied, .applied)
        let replayed = try await store.applyInboxRouteCapabilityMutation(
            operation: .create,
            inboxId: inboxId,
            capability: capability,
            relayScope: receipt.routeMutationScope,
            mutationSequence: 1,
            mutationDigest: create.mutationDigest()
        )
        XCTAssertEqual(replayed, .replayed)

        let conflicting = CreateInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: routeCapability(0x82),
            relayScope: receipt.routeMutationScope,
            mutationSequence: 1
        )
        await XCTAssertThrowsRouteCapabilityError(
            try await store.applyInboxRouteCapabilityMutation(
                operation: .create,
                inboxId: inboxId,
                capability: conflicting.capability,
                relayScope: receipt.routeMutationScope,
                mutationSequence: 1,
                mutationDigest: conflicting.mutationDigest()
            ),
            expected: .inboxRouteCapabilityMutationConflict
        )
        await XCTAssertThrowsRouteCapabilityError(
            try await store.applyInboxRouteCapabilityMutation(
                operation: .create,
                inboxId: inboxId,
                capability: routeCapability(0x83),
                relayScope: receipt.routeMutationScope,
                mutationSequence: 3,
                mutationDigest: Data(repeating: 0x33, count: 32)
            ),
            expected: .inboxRouteCapabilityMutationOutOfOrder
        )

        let revoke = RevokeInboxRouteCapabilityRequest(
            inboxId: inboxId,
            capability: capability,
            relayScope: receipt.routeMutationScope,
            mutationSequence: 2
        )
        _ = try await store.applyInboxRouteCapabilityMutation(
            operation: .revoke,
            inboxId: inboxId,
            capability: capability,
            relayScope: receipt.routeMutationScope,
            mutationSequence: 2,
            mutationDigest: revoke.mutationDigest()
        )
        for marker in UInt8(1)...UInt8(64) {
            try await store.seedInboxRouteCapabilityRevocationForTesting(
                inboxId: inboxId,
                capability: routeCapability(marker)
            )
        }
        await XCTAssertThrowsRouteCapabilityError(
            try await store.applyInboxRouteCapabilityMutation(
                operation: .create,
                inboxId: inboxId,
                capability: capability,
                relayScope: receipt.routeMutationScope,
                mutationSequence: 1,
                mutationDigest: create.mutationDigest()
            ),
            expected: .inboxRouteCapabilityMutationOutOfOrder
        )

        let reloaded = RelayStore(storeURL: storeURL, temporalBucketSeconds: 0)
        try await reloaded.loadFromDisk()
        let replayAfterReload = try await reloaded.applyInboxRouteCapabilityMutation(
            operation: .revoke,
            inboxId: inboxId,
            capability: capability,
            relayScope: receipt.routeMutationScope,
            mutationSequence: 2,
            mutationDigest: revoke.mutationDigest()
        )
        XCTAssertEqual(replayAfterReload, .replayed)

        let otherRelay = RelayStore()
        let otherReceipt = try await otherRelay.registerInbox(
            inboxId: inboxId,
            accessPublicKey: Data([0xC1])
        )
        XCTAssertNotEqual(otherReceipt.routeMutationScope, receipt.routeMutationScope)
        await XCTAssertThrowsRouteCapabilityError(
            try await otherRelay.applyInboxRouteCapabilityMutation(
                operation: .create,
                inboxId: inboxId,
                capability: capability,
                relayScope: receipt.routeMutationScope,
                mutationSequence: 1,
                mutationDigest: create.mutationDigest()
            ),
            expected: .invalidInboxRouteCapabilityMutation
        )
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
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: 12),
                ciphertext: Data(repeating: UInt8(truncatingIfNeeded: counter), count: 512),
                tag: Data(repeating: 0x22, count: 16)
            ),
            signature: Data(repeating: 0x44, count: 3_309)
        )
    }

    private func proof(
        signingKey: SigningKeyPair,
        signedAt: Date = Date(),
        signableData: (RelayActorProof) throws -> Data
    ) throws -> RelayActorProof {
        let draft = RelayActorProof(
            fingerprint: CryptoBox.fingerprint(for: signingKey.publicKeyData),
            publicSigningKey: signingKey.publicKeyData,
            signedAt: signedAt,
            nonce: UUID(),
            signature: Data()
        )
        return RelayActorProof(
            fingerprint: draft.fingerprint,
            publicSigningKey: draft.publicSigningKey,
            signedAt: draft.signedAt,
            nonce: draft.nonce,
            signature: try signingKey.sign(signableData(draft))
        )
    }
}

private func XCTAssertThrowsRouteCapabilityError<T>(
    _ expression: @autoclosure () async throws -> T,
    expected: RelayStoreError,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected route capability error", file: file, line: line)
    } catch {
        XCTAssertEqual(error as? RelayStoreError, expected, file: file, line: line)
    }
}
