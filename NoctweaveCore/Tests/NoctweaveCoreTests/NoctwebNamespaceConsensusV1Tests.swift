import XCTest
@testable import NoctweaveCore

final class NoctwebNamespaceConsensusV1Tests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let federation = FederationDescriptor(mode: .manual, name: "test-federation")
    private let endpoint = RelayEndpoint(
        host: "relay.example",
        port: 443,
        useTLS: true,
        transport: .http
    )

    func testDuplicateSuffixCannotBeClaimedByAnotherRelay() throws {
        let first = try RelayIdentityKeyMaterialV1.generate()
        let second = try RelayIdentityKeyMaterialV1.generate()
        var ledger = NoctwebNamespaceLedgerV1()

        try ledger.claim(try identityClaim(first, suffix: ".unique", sequence: 1), now: now)
        XCTAssertThrowsError(
            try ledger.claim(
                try identityClaim(second, suffix: ".unique", sequence: 1),
                now: now
            )
        ) { error in
            XCTAssertEqual(
                error as? NoctwebNamespaceLedgerErrorV1,
                .suffixAlreadyOwned
            )
        }
        XCTAssertEqual(
            ledger.record(for: NoctwebRelaySuffixV1(rawValue: ".unique")!)?.ownerRelayID,
            first.relayID
        )
    }

    func testExpiredRouteClaimDoesNotReleaseSuffixOwnership() throws {
        let owner = try RelayIdentityKeyMaterialV1.generate()
        let attacker = try RelayIdentityKeyMaterialV1.generate()
        var ledger = NoctwebNamespaceLedgerV1()
        try ledger.claim(
            try identityClaim(
                owner,
                suffix: ".durable",
                sequence: 1,
                issuedAt: now,
                lifetime: 60
            ),
            now: now
        )

        let later = now.addingTimeInterval(120)
        let records = ledger.snapshotRecords(at: later)
        XCTAssertEqual(records.first?.status, .active)
        XCTAssertNil(records.first?.activeIdentityClaim)
        XCTAssertThrowsError(
            try ledger.claim(
                try identityClaim(
                    attacker,
                    suffix: ".durable",
                    sequence: 2,
                    issuedAt: later
                ),
                now: later
            )
        ) { error in
            XCTAssertEqual(
                error as? NoctwebNamespaceLedgerErrorV1,
                .suffixAlreadyOwned
            )
        }
    }

    func testRelayKeyRotationPreservesSuffixWithTwoSignatures() throws {
        let oldKey = try RelayIdentityKeyMaterialV1.generate()
        let newKey = try RelayIdentityKeyMaterialV1.generate()
        var ledger = NoctwebNamespaceLedgerV1()
        try ledger.claim(try identityClaim(oldKey, suffix: ".rotate", sequence: 1), now: now)
        let rotation = try RelayIdentityRotationV1.signed(
            from: oldKey,
            to: newKey,
            sequence: 2,
            issuedAt: now.addingTimeInterval(1)
        )
        let newClaim = try identityClaim(
            newKey,
            suffix: ".rotate",
            sequence: 2,
            issuedAt: now.addingTimeInterval(1)
        )

        try ledger.rotate(
            rotation,
            to: newClaim,
            now: now.addingTimeInterval(1)
        )

        let record = try XCTUnwrap(
            ledger.record(for: NoctwebRelaySuffixV1(rawValue: ".rotate")!)
        )
        XCTAssertEqual(record.ownerRelayID, newKey.relayID)
        XCTAssertEqual(record.status, .active)
    }

    func testReleaseCreatesNonReclaimableTombstone() throws {
        let owner = try RelayIdentityKeyMaterialV1.generate()
        var ledger = NoctwebNamespaceLedgerV1()
        let suffix = NoctwebRelaySuffixV1(rawValue: ".retired")!
        try ledger.claim(try identityClaim(owner, suffix: suffix.rawValue, sequence: 1), now: now)
        let release = try NoctwebNamespaceReleaseV1.signed(
            suffix: suffix,
            owner: owner,
            sequence: 2,
            issuedAt: now.addingTimeInterval(1)
        )

        try ledger.release(release, now: now.addingTimeInterval(1))

        XCTAssertEqual(ledger.record(for: suffix)?.status, .tombstoned)
        XCTAssertThrowsError(
            try ledger.claim(
                try identityClaim(owner, suffix: suffix.rawValue, sequence: 3),
                now: now
            )
        ) { error in
            XCTAssertEqual(
                error as? NoctwebNamespaceLedgerErrorV1,
                .suffixTombstoned
            )
        }
    }

    func testSnapshotRequiresConfiguredQuorumAndRejectsTampering() throws {
        let owner = try RelayIdentityKeyMaterialV1.generate()
        let signerA = try RelayIdentityKeyMaterialV1.generate()
        let signerB = try RelayIdentityKeyMaterialV1.generate()
        let signerC = try RelayIdentityKeyMaterialV1.generate()
        var ledger = NoctwebNamespaceLedgerV1()
        try ledger.claim(try identityClaim(owner, suffix: ".site", sequence: 1), now: now)
        let payload = try NoctwebNamespaceSnapshotPayloadV1(
            federationMode: federation.mode,
            federationName: federation.name,
            epoch: 1,
            previousSnapshotDigest: nil,
            records: ledger.snapshotRecords(at: now),
            issuedAt: now
        )
        let policy = NoctwebNamespaceConsensusPolicyV1(
            federationMode: federation.mode,
            federationName: federation.name,
            signers: [signerA, signerB, signerC].map {
                NoctwebNamespaceConsensusSignerV1(
                    relayID: $0.relayID,
                    signingPublicKey: $0.signingPublicKey
                )
            },
            threshold: 2
        )
        let quorumSnapshot = try NoctwebNamespaceSnapshotV1.signed(
            payload: payload,
            by: [signerA, signerB]
        )
        XCTAssertTrue(try quorumSnapshot.verifyThrowing(policy: policy, at: now))

        let minoritySnapshot = try NoctwebNamespaceSnapshotV1.signed(
            payload: payload,
            by: [signerA]
        )
        XCTAssertFalse(try minoritySnapshot.verifyThrowing(policy: policy, at: now))

        let tamperedPayload = try NoctwebNamespaceSnapshotPayloadV1(
            federationMode: federation.mode,
            federationName: federation.name,
            epoch: 1,
            previousSnapshotDigest: nil,
            records: [],
            issuedAt: now
        )
        let tampered = NoctwebNamespaceSnapshotV1(
            payload: tamperedPayload,
            signatures: quorumSnapshot.signatures
        )
        XCTAssertFalse(try tampered.verifyThrowing(policy: policy, at: now))
    }

    func testIndependentLedgersConvergeRegardlessOfReceiptTime() throws {
        let owner = try RelayIdentityKeyMaterialV1.generate()
        let claim = try identityClaim(
            owner,
            suffix: ".convergent",
            sequence: 1,
            issuedAt: now
        )
        var first = NoctwebNamespaceLedgerV1()
        var second = NoctwebNamespaceLedgerV1()

        try first.claim(claim, now: now)
        try second.claim(claim, now: now.addingTimeInterval(600))

        XCTAssertEqual(first.records, second.records)
        XCTAssertEqual(
            try NoctweaveCanonicalJSON.encode(first.records),
            try NoctweaveCanonicalJSON.encode(second.records)
        )
    }

    func testNamespaceLifecycleRequestsRoundTripOnStrictWire() throws {
        let oldKey = try RelayIdentityKeyMaterialV1.generate()
        let newKey = try RelayIdentityKeyMaterialV1.generate()
        let oldClaim = try identityClaim(
            oldKey,
            suffix: ".wire",
            sequence: 1
        )
        let rotation = try RelayIdentityRotationV1.signed(
            from: oldKey,
            to: newKey,
            sequence: 2,
            issuedAt: now.addingTimeInterval(1)
        )
        let newClaim = try identityClaim(
            newKey,
            suffix: ".wire",
            sequence: 2,
            issuedAt: now.addingTimeInterval(1)
        )
        let release = try NoctwebNamespaceReleaseV1.signed(
            suffix: NoctwebRelaySuffixV1(rawValue: ".wire")!,
            owner: newKey,
            sequence: 3,
            issuedAt: now.addingTimeInterval(2)
        )
        let requests: [RelayRequest] = [
            .claimNoctwebNamespaceV1(
                NoctwebNamespaceClaimRequestV1(identity: oldClaim)
            ),
            .rotateNoctwebNamespaceV1(
                NoctwebNamespaceRotationRequestV1(
                    rotation: rotation,
                    newIdentity: newClaim
                )
            ),
            .releaseNoctwebNamespaceV1(release)
        ]

        for request in requests {
            XCTAssertEqual(
                try NoctweaveCoder.decode(
                    RelayRequest.self,
                    from: NoctweaveCoder.encode(request)
                ),
                request
            )
        }
    }

    func testSignedNameResolutionIsBoundToExpectedRelayIdentity() throws {
        let relay = try RelayIdentityKeyMaterialV1.generate()
        let impostor = try RelayIdentityKeyMaterialV1.generate()
        let claim = try identityClaim(
            relay,
            suffix: ".names",
            sequence: 1
        )
        let binding = NoctweaveNetHostNameBindingRequestV1(
            relaySuffix: NoctwebRelaySuffixV1(rawValue: ".names")!,
            siteLabel: "journal",
            objectID: String(repeating: "a", count: 64),
            publisherID: "nwpub1_\(String(repeating: "b", count: 64))",
            headID: "sha256:\(String(repeating: "c", count: 64))",
            revision: 1,
            previousObjectID: nil,
            idempotencyKey: Data(repeating: 0x42, count: 32)
        )
        let resolution = try NoctweaveNetHostNameResolutionV1.signed(
            binding: binding,
            updatedAt: now,
            signer: relay,
            at: now
        )

        XCTAssertTrue(
            try resolution.verifyThrowing(
                expectedRelayIdentity: claim,
                at: now
            )
        )
        let impostorClaim = try identityClaim(
            impostor,
            suffix: ".names",
            sequence: 1
        )
        XCTAssertFalse(
            try resolution.verifyThrowing(
                expectedRelayIdentity: impostorClaim,
                at: now
            )
        )
    }

    private func identityClaim(
        _ key: RelayIdentityKeyMaterialV1,
        suffix: String,
        sequence: Int,
        issuedAt: Date? = nil,
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
                wakeEnabled: false,
                hiddenRetrievalEnabled: false,
                onionEnabled: false,
                mixnetEnabled: false
            ),
            issuedAt: issuedAt ?? now,
            lifetime: lifetime
        )
    }
}
