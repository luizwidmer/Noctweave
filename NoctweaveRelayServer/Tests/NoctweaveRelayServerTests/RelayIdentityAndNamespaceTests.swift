import Foundation
import NIOCore
import NIOEmbedded
import XCTest
@testable import NoctweaveRelayServer

final class RelayIdentityAndNamespaceTests: XCTestCase {
    private let federation = FederationDescriptor(
        mode: .manual,
        name: "namespace-tests"
    )
    private let endpoint = RelayEndpoint(
        host: "relay.example",
        port: 443,
        useTLS: true,
        transport: .http
    )

    func testNamespacePolicyGateSerializesLedgerMutationAndOperatorUpdate() {
        let initial = RelayConfiguration(federation: federation)
        var updated = initial
        updated.federationAllowList = [endpoint]
        let replacement = updated
        let configurationStore = RelayConfigurationStore(initial)
        let enteredMutation = DispatchSemaphore(value: 0)
        let finishMutation = DispatchSemaphore(value: 0)
        let replacementStarted = DispatchSemaphore(value: 0)
        let replacementFinished = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            _ = configurationStore.withUnchanged(initial) {
                enteredMutation.signal()
                _ = finishMutation.wait(timeout: .now() + .seconds(5))
            }
        }
        XCTAssertEqual(enteredMutation.wait(timeout: .now() + .seconds(5)), .success)
        DispatchQueue.global().async {
            replacementStarted.signal()
            configurationStore.replace(with: replacement)
            replacementFinished.signal()
        }
        XCTAssertEqual(replacementStarted.wait(timeout: .now() + .seconds(5)), .success)
        defer { finishMutation.signal() }
        XCTAssertEqual(replacementFinished.wait(timeout: .now() + .milliseconds(50)), .timedOut)
        finishMutation.signal()
        XCTAssertEqual(replacementFinished.wait(timeout: .now() + .seconds(5)), .success)
        XCTAssertEqual(configurationStore.snapshot(), replacement)
        XCTAssertNil(configurationStore.withUnchanged(initial) { 1 })
    }

    func testSignedRelayIdentityBindsCapabilitiesEndpointAndSuffix() throws {
        let key = try RelayIdentityKeyMaterialV1.generate()
        let configuration = RelayConfiguration(
            federation: federation,
            advertisedEndpoint: endpoint,
            noctwebRelaySuffix: NoctwebRelaySuffixV1(rawValue: ".signed")
        )
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let info = try configuration.makeInfo(now: now).authenticated(
            by: key,
            sequence: 1,
            advertisedEndpoints: [endpoint],
            noctwebSuffix: configuration.noctwebRelaySuffix
        )

        XCTAssertEqual(info.authenticatedRelayID, key.relayID)
        XCTAssertEqual(
            info.authenticatedNoctwebSuffix,
            NoctwebRelaySuffixV1(rawValue: ".signed")
        )
        XCTAssertEqual(info.relayIdentity?.claim.advertisedEndpoints, [endpoint])
        XCTAssertEqual(
            try RelayCodec.decoder().decode(
                RelayInfo.self,
                from: RelayCodec.encoder(sortedKeys: true).encode(info)
            ),
            info
        )
    }

    func testRelayIdentityRuntimeRejectsUnrepresentableTimestamp() throws {
        let runtime = RelayIdentityRuntime(
            keyMaterial: try RelayIdentityKeyMaterialV1.generate()
        )
        let configuration = RelayConfiguration(
            federation: federation,
            advertisedEndpoint: endpoint
        )

        XCTAssertThrowsError(try runtime.signedIdentity(
            configuration: configuration,
            advertisedEndpoints: [endpoint],
            hostSigningPublicKey: nil,
            at: Date(timeIntervalSince1970: .greatestFiniteMagnitude)
        )) {
            XCTAssertEqual($0 as? RelayIdentityError, .invalidPayload)
        }
    }

    func testDuplicateAndExpiredClaimsNeverReleaseOwnership() throws {
        let owner = try RelayIdentityKeyMaterialV1.generate()
        let attacker = try RelayIdentityKeyMaterialV1.generate()
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        var ledger = NoctwebNamespaceLedgerV1()
        try ledger.claim(
            try identity(owner, suffix: ".durable", sequence: 1, now: now, lifetime: 60),
            now: now
        )

        let later = now.addingTimeInterval(120)
        XCTAssertNil(ledger.snapshotRecords(at: later).first?.activeIdentityClaim)
        XCTAssertThrowsError(
            try ledger.claim(
                try identity(attacker, suffix: ".durable", sequence: 2, now: later),
                now: later
            )
        ) {
            XCTAssertEqual(
                $0 as? NoctwebNamespaceLedgerErrorV1,
                .suffixAlreadyOwned
            )
        }
    }

    func testRotationAndReleaseRequireCryptographicContinuity() throws {
        let oldKey = try RelayIdentityKeyMaterialV1.generate()
        let newKey = try RelayIdentityKeyMaterialV1.generate()
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let suffix = NoctwebRelaySuffixV1(rawValue: ".rotate")!
        var ledger = NoctwebNamespaceLedgerV1()
        try ledger.claim(
            try identity(oldKey, suffix: suffix.rawValue, sequence: 1, now: now),
            now: now
        )
        let rotation = try RelayIdentityRotationV1.signed(
            from: oldKey,
            to: newKey,
            sequence: 2,
            issuedAt: now.addingTimeInterval(1)
        )
        try ledger.rotate(
            rotation,
            to: try identity(
                newKey,
                suffix: suffix.rawValue,
                sequence: 2,
                now: now.addingTimeInterval(1)
            ),
            now: now.addingTimeInterval(1)
        )
        XCTAssertEqual(ledger.record(for: suffix)?.ownerRelayID, newKey.relayID)

        let release = try NoctwebNamespaceReleaseV1.signed(
            suffix: suffix,
            owner: newKey,
            sequence: 3,
            issuedAt: now.addingTimeInterval(2)
        )
        try ledger.release(release, now: now.addingTimeInterval(2))
        XCTAssertEqual(ledger.record(for: suffix)?.status, .tombstoned)
        XCTAssertThrowsError(
            try ledger.claim(
                try identity(
                    newKey,
                    suffix: suffix.rawValue,
                    sequence: 4,
                    now: now.addingTimeInterval(3)
                ),
                now: now.addingTimeInterval(3)
            )
        ) {
            XCTAssertEqual(
                $0 as? NoctwebNamespaceLedgerErrorV1,
                .suffixTombstoned
            )
        }
    }

    func testNamespaceOwnershipPersistsBesideExistingRelayDatabase() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweb-namespace-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let database = root.appendingPathComponent("relay.sqlite")
        let now = Date()
        let owner = try RelayIdentityKeyMaterialV1.generate()
        let claim = try identity(
            owner,
            suffix: ".persistent",
            sequence: 1,
            now: now
        )

        let first = RelayStore(fileURL: database, temporalBucketSeconds: 0)
        try first.load()
        try first.claimNoctwebNamespace(claim, now: now)

        let reopened = RelayStore(fileURL: database, temporalBucketSeconds: 0)
        try reopened.load()
        let record = try XCTUnwrap(
            reopened.noctwebNamespaceRecords(at: now).first
        )
        XCTAssertEqual(record.suffix.rawValue, ".persistent")
        XCTAssertEqual(record.ownerRelayID, owner.relayID)
    }

    func testFailedFederationRosterSaveRetainsConservativeNamespaceOwnership() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctweb-registration-fault-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let database = root.appendingPathComponent("relay.sqlite")
        let now = Date()
        let owner = try RelayIdentityKeyMaterialV1.generate()
        let suffix = NoctwebRelaySuffixV1(rawValue: ".rosterfault")!
        let configuration = RelayConfiguration(
            federation: federation,
            advertisedEndpoint: endpoint,
            noctwebRelaySuffix: suffix
        )
        let info = try configuration.makeInfo(now: now).authenticated(
            by: owner,
            sequence: 1,
            advertisedEndpoints: [endpoint],
            noctwebSuffix: suffix
        )
        let registration = FederationNodeRegistrationRequest(
            endpoint: endpoint,
            relayInfo: info,
            ttlSeconds: 300
        )

        let store = RelayStore(fileURL: database, temporalBucketSeconds: 0)
        try store.load()
        store.failNextPersistenceForTesting()
        XCTAssertThrowsError(try store.registerFederationNode(registration))
        XCTAssertTrue(store.listFederationNodes(nil).isEmpty)

        let reopened = RelayStore(fileURL: database, temporalBucketSeconds: 0)
        try reopened.load()
        XCTAssertTrue(reopened.listFederationNodes(nil).isEmpty)
        XCTAssertEqual(
            reopened.noctwebNamespaceRecord(for: suffix)?.ownerRelayID,
            owner.relayID
        )
    }

    func testManualNamespaceRotationRejectsUnlistedSuccessor() throws {
        let now = Date()
        let owner = try RelayIdentityKeyMaterialV1.generate()
        let successor = try RelayIdentityKeyMaterialV1.generate()
        let suffix = ".unlistedrotation"
        let oldIdentity = try identity(owner, suffix: suffix, sequence: 1, now: now)
        let unlistedEndpoint = RelayEndpoint(
            host: "unlisted.example",
            port: 443,
            useTLS: true,
            transport: .http
        )
        let newIdentity = try identity(
            successor,
            suffix: suffix,
            sequence: 2,
            now: now,
            endpoint: unlistedEndpoint
        )
        let store = RelayStore(fileURL: nil, temporalBucketSeconds: 0)
        // Ownership survives an operator removing a manual peer. A stale
        // owner must not use rotation to assign it to an unlisted successor.
        try store.claimNoctwebNamespace(oldIdentity, now: now)
        let handler = RelayHandler(
            store: store,
            maxMessageBytes: nil,
            maxLineBytes: nil,
            localEndpoint: nil,
            relayConfiguration: RelayConfiguration(
                kind: .standard,
                federation: federation
            ),
            relayIdentityRuntime: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            ),
            forwardingRequestTimeoutSeconds: 2
        )
        let channel = EmbeddedChannel(handler: handler)
        defer { _ = try? channel.finish() }
        let rotation = try RelayIdentityRotationV1.signed(
            from: owner,
            to: successor,
            sequence: 2,
            issuedAt: now
        )
        let request = RelayRequest.rotateNoctwebNamespaceV1(
            NoctwebNamespaceRotationRequestV1(
                rotation: rotation,
                newIdentity: newIdentity
            )
        )
        let data = try RelayCodec.encoder().encode(request)
        var input = channel.allocator.buffer(capacity: data.count)
        input.writeBytes(data)
        try channel.writeInbound(input)
        var output: ByteBuffer = try XCTUnwrap(channel.readOutbound())
        let encoded = try XCTUnwrap(output.readData(length: output.readableBytes))
        XCTAssertEqual(encoded.last, 0x0a)
        let response = try RelayCodec.decodeWire(
            RelayResponse.self,
            from: Data(encoded.dropLast())
        )
        XCTAssertEqual(response.error?.code, .authenticationRequired)
        XCTAssertEqual(
            store.noctwebNamespaceRecord(for: NoctwebRelaySuffixV1(rawValue: suffix)!)?.ownerRelayID,
            owner.relayID
        )
    }

    private func identity(
        _ key: RelayIdentityKeyMaterialV1,
        suffix: String,
        sequence: Int,
        now: Date,
        lifetime: TimeInterval = 24 * 60 * 60,
        endpoint: RelayEndpoint? = nil
    ) throws -> SignedRelayIdentityClaimV1 {
        try key.makeSignedClaim(
            sequence: sequence,
            relayKind: .standard,
            federation: federation,
            advertisedEndpoints: [endpoint ?? self.endpoint],
            noctwebSuffix: NoctwebRelaySuffixV1(rawValue: suffix),
            capabilities: RelayCapabilityManifestV2.advertised(
                attachmentsEnabled: true,
                hiddenRetrievalEnabled: false,
                onionEnabled: false,
                mixnetEnabled: false
            ),
            issuedAt: now,
            lifetime: lifetime
        )
    }
}
