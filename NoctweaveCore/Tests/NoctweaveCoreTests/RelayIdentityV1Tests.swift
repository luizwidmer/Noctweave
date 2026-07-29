import XCTest
@testable import NoctweaveCore

final class RelayIdentityV1Tests: XCTestCase {
    func testSignedClaimBindsRelayEndpointCapabilitiesAndSuffix() throws {
        let key = try RelayIdentityKeyMaterialV1.generate()
        let endpoint = RelayEndpoint(
            host: "relay.example",
            port: 443,
            useTLS: true,
            transport: .http
        )
        let suffix = try XCTUnwrap(NoctwebRelaySuffixV1(rawValue: ".example"))
        let capabilities = RelayCapabilityManifestV2.advertised(
            attachmentsEnabled: true,
            wakeEnabled: false,
            hiddenRetrievalEnabled: false,
            onionEnabled: false,
            mixnetEnabled: false
        )
        let issuedAt = Date(timeIntervalSince1970: 1_800_000_000)
        let signed = try key.makeSignedClaim(
            sequence: 7,
            relayKind: .standard,
            federation: FederationDescriptor(mode: .manual, name: "friends"),
            advertisedEndpoints: [endpoint],
            noctwebSuffix: suffix,
            capabilities: capabilities,
            issuedAt: issuedAt
        )

        XCTAssertTrue(try signed.verifyThrowing(at: issuedAt))
        XCTAssertEqual(signed.claim.relayID, key.relayID)
        XCTAssertEqual(signed.claim.noctwebSuffix, suffix)
        XCTAssertEqual(signed.claim.advertisedEndpoints, [endpoint])
        XCTAssertEqual(
            signed.claim.capabilityDigest,
            try RelayIdentityClaimV1.capabilityDigest(for: capabilities)
        )
    }

    func testSignedClaimRejectsSuffixSubstitution() throws {
        let key = try RelayIdentityKeyMaterialV1.generate()
        let endpoint = RelayEndpoint(host: "relay.example", port: 443, useTLS: true, transport: .http)
        let capabilities = RelayCapabilityManifestV2.advertised(
            attachmentsEnabled: true,
            wakeEnabled: false,
            hiddenRetrievalEnabled: false,
            onionEnabled: false,
            mixnetEnabled: false
        )
        let original = try key.makeSignedClaim(
            sequence: 1,
            relayKind: .standard,
            federation: FederationDescriptor(mode: .manual, name: "friends"),
            advertisedEndpoints: [endpoint],
            noctwebSuffix: NoctwebRelaySuffixV1(rawValue: ".alpha"),
            capabilities: capabilities,
            issuedAt: Date(timeIntervalSince1970: 1_800_000_000)
        )
        let substitutedClaim = RelayIdentityClaimV1(
            relayID: original.claim.relayID,
            signingPublicKey: original.claim.signingPublicKey,
            sequence: original.claim.sequence,
            relayKind: original.claim.relayKind,
            federationMode: original.claim.federationMode,
            federationName: original.claim.federationName,
            advertisedEndpoints: original.claim.advertisedEndpoints,
            noctwebSuffix: NoctwebRelaySuffixV1(rawValue: ".beta"),
            capabilityDigest: original.claim.capabilityDigest,
            issuedAt: original.claim.issuedAt,
            expiresAt: original.claim.expiresAt
        )
        let substituted = SignedRelayIdentityClaimV1(
            claim: substitutedClaim,
            signature: original.signature
        )

        XCTAssertFalse(try substituted.verifyThrowing())
    }

    func testRelayInfoAuthenticatesClaimAgainstAdvertisedCapabilities() throws {
        let key = try RelayIdentityKeyMaterialV1.generate()
        let endpoint = RelayEndpoint(host: "relay.example", port: 443, useTLS: true, transport: .http)
        let configuration = RelayConfiguration(
            federation: FederationDescriptor(mode: .manual, name: "friends"),
            advertisedEndpoint: endpoint,
            noctwebRelaySuffix: NoctwebRelaySuffixV1(rawValue: ".example")
        )
        let info = try configuration.makeInfo(
            now: Date(timeIntervalSince1970: 1_800_000_000)
        ).authenticated(
            by: key,
            sequence: 1,
            advertisedEndpoints: [endpoint],
            noctwebSuffix: configuration.noctwebRelaySuffix
        )

        XCTAssertEqual(info.authenticatedRelayID, key.relayID)
        XCTAssertEqual(
            info.authenticatedNoctwebSuffix,
            NoctwebRelaySuffixV1(rawValue: ".example")
        )
        let encoded = try NoctweaveCoder.encode(info)
        XCTAssertEqual(try NoctweaveCoder.decode(RelayInfo.self, from: encoded), info)
    }

    func testRelayIdentityRotationRequiresBothKeys() throws {
        let oldKey = try RelayIdentityKeyMaterialV1.generate()
        let newKey = try RelayIdentityKeyMaterialV1.generate()
        let rotation = try RelayIdentityRotationV1.signed(
            from: oldKey,
            to: newKey,
            sequence: 2,
            issuedAt: Date(timeIntervalSince1970: 1_800_000_000)
        )

        XCTAssertTrue(try rotation.verifyThrowing())

        var damagedSignature = rotation.newKeySignature
        damagedSignature[damagedSignature.startIndex] ^= 0x01
        let damaged = RelayIdentityRotationV1(
            version: rotation.version,
            oldRelayID: rotation.oldRelayID,
            newRelayID: rotation.newRelayID,
            oldSigningPublicKey: rotation.oldSigningPublicKey,
            newSigningPublicKey: rotation.newSigningPublicKey,
            sequence: rotation.sequence,
            issuedAt: rotation.issuedAt,
            oldKeySignature: rotation.oldKeySignature,
            newKeySignature: damagedSignature
        )
        XCTAssertFalse(try damaged.verifyThrowing())
    }

    func testNoctwebSuffixCanonicalFormRejectsAliases() {
        XCTAssertNotNil(NoctwebRelaySuffixV1(rawValue: ".alpha-1"))
        XCTAssertNil(NoctwebRelaySuffixV1(rawValue: ".Alpha"))
        XCTAssertNil(NoctwebRelaySuffixV1(rawValue: ".álpha"))
        XCTAssertNil(NoctwebRelaySuffixV1(rawValue: ".-alpha"))
        XCTAssertNil(NoctwebRelaySuffixV1(rawValue: ".alpha-"))
        XCTAssertNil(NoctwebRelaySuffixV1(rawValue: "alpha"))
    }
}
