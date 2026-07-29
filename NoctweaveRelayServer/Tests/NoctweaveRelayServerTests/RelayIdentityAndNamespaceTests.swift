import Foundation
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

    private func identity(
        _ key: RelayIdentityKeyMaterialV1,
        suffix: String,
        sequence: Int,
        now: Date,
        lifetime: TimeInterval = 24 * 60 * 60
    ) throws -> SignedRelayIdentityClaimV1 {
        try key.makeSignedClaim(
            sequence: sequence,
            relayKind: .standard,
            federation: federation,
            advertisedEndpoints: [endpoint],
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
