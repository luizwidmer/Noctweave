import XCTest
@testable import NoctweaveCore

final class EndpointPrekeyRotationTests: XCTestCase {
    func testPersistedPrekeyValidationAndConsumptionUseThrowingPath() throws {
        let authority = try RelationshipAuthorityV2.generate(
            relationshipPseudonym: "Scoped relationship"
        )
        var state = try PrekeyState.generate(
            authority: authority,
            oneTimeCount: 1,
            issuedAt: Date(timeIntervalSince1970: 1_800_000_000)
        )
        let oneTimeID = try XCTUnwrap(state.oneTimePrekeys.first?.id)

        XCTAssertTrue(try state.isStructurallyValidThrowing)
        XCTAssertNotNil(try state.signedPrekeyKeyPairThrowing(
            id: state.signedPrekeyId,
            now: state.signedPrekeyIssuedAt
        ))
        XCTAssertNotNil(try state.consumeOneTimePrekeyThrowing(id: oneTimeID))
        XCTAssertTrue(state.oneTimePrekeys.isEmpty)
    }

    func testSignedPrekeyThrowingVerificationRejectsInvalidPeerMaterial() throws {
        let signingKey = try SigningKeyPair.generate()
        let otherSigningKey = try SigningKeyPair.generate()
        let agreementKey = try AgreementKeyPair.generate()
        let prekey = try SignedPrekey.create(
            agreementPublicKey: agreementKey.publicKeyData,
            signingKey: signingKey,
            issuedAt: Date(timeIntervalSince1970: 1_800_000_000)
        )

        XCTAssertTrue(try prekey.verifyThrowing(using: signingKey.publicKeyData))
        XCTAssertFalse(try prekey.verifyThrowing(using: otherSigningKey.publicKeyData))
        XCTAssertFalse(try prekey.verifyThrowing(using: Data([0x01])))
        XCTAssertTrue(try AgreementKeyPair.isValidPublicKeyThrowing(prekey.publicKey))
    }

    func testPairwiseRenewalAtomicallyRefreshesTheOnlyEndpointBinding() throws {
        let now = Date()
        let createdAt = now.addingTimeInterval(
            -PrekeyBundle.maximumAge + PrekeyState.signedPrekeyRenewalLeadTime
        )
        var identity = try LocalPairwiseIdentityV2.generate(
            relationshipPseudonym: "One relationship",
            createdAt: createdAt
        )
        let authorization = identity.endpointBinding.authorizationDigest

        XCTAssertTrue(try identity.renewEndpointPrekeyIfNeeded(at: now))
        XCTAssertEqual(identity.endpointBinding.authorizationDigest, authorization)
        XCTAssertTrue(identity.isStructurallyValid)
        XCTAssertEqual(identity.localEndpoint.prekeys.retiredSignedPrekeys.count, 1)
    }

    func testRenewalKeepsStableRelationshipAuthorizationAndSessionBinding() throws {
        let now = Date()
        let issuedAt = now.addingTimeInterval(
            -PrekeyBundle.maximumAge + PrekeyState.signedPrekeyRenewalLeadTime
        )
        var local = try endpointFixture(pseudonym: "Alice-for-Bob", prekeyIssuedAt: issuedAt)
        let peer = try endpointFixture(pseudonym: "Bob-for-Alice", prekeyIssuedAt: now)
        let original = local.binding
        let originalPrekey = original.prekeyBundle.signedPrekey
        let originalAuthorizationDigest = try XCTUnwrap(original.authorizationDigest)
        let relationshipID = UUID()
        let localHandle = RelationshipEndpointHandle.generate(relationshipId: relationshipID)
        let peerHandle = RelationshipEndpointHandle.generate(relationshipId: relationshipID)
        let originalTranscript = try PairwiseEndpointBindingV4.create(
            relationshipId: relationshipID,
            localEndpointHandle: localHandle,
            peerEndpointHandle: peerHandle,
            localEndpoint: original,
            peerEndpoint: peer.binding
        )

        XCTAssertTrue(try local.localEndpoint.renewSignedPrekeyIfNeeded(at: now))
        XCTAssertEqual(local.localEndpoint.prekeys.retiredSignedPrekeys.count, 1)
        XCTAssertNotEqual(local.localEndpoint.prekeys.signedPrekeyId, originalPrekey.id)
        XCTAssertNotNil(try local.localEndpoint.prekeys.signedPrekeyKeyPairThrowing(
            id: originalPrekey.id,
            now: now
        ))
        let persistedPrekeys = try NoctweaveCoder.decode(
            PrekeyState.self,
            from: NoctweaveCoder.encode(local.localEndpoint.prekeys)
        )
        XCTAssertNotNil(try persistedPrekeys.signedPrekeyKeyPairThrowing(
            id: originalPrekey.id,
            now: now
        ))

        let refreshed = try original.refreshingPrekeyPackage(
            using: local.localEndpoint,
            at: now
        )
        XCTAssertEqual(refreshed.authorizationDigest, originalAuthorizationDigest)
        XCTAssertEqual(refreshed.authoritySignature, original.authoritySignature)
        XCTAssertNotEqual(refreshed.prekeyBundle.signedPrekey.id, originalPrekey.id)
        XCTAssertNoThrow(try refreshed.verified(
            authoritySigningPublicKey: local.authority.signingKey.publicKeyData,
            now: now
        ))

        let refreshedTranscript = try PairwiseEndpointBindingV4.create(
            relationshipId: relationshipID,
            localEndpointHandle: localHandle,
            peerEndpointHandle: peerHandle,
            localEndpoint: refreshed,
            peerEndpoint: peer.binding
        )
        XCTAssertEqual(refreshedTranscript, originalTranscript)

        XCTAssertNil(try local.localEndpoint.prekeys.signedPrekeyKeyPairThrowing(
            id: originalPrekey.id,
            now: originalPrekey.expiresAt
        ))
        local.localEndpoint.prekeys.pruneExpiredSignedPrekeys(now: originalPrekey.expiresAt)
        XCTAssertTrue(local.localEndpoint.prekeys.retiredSignedPrekeys.isEmpty)
    }

    func testFreshPrekeyDoesNotRotateAndTamperedOrExpiredPackageFailsClosed() throws {
        let now = Date()
        var fixture = try endpointFixture(pseudonym: "Alice-for-Bob", prekeyIssuedAt: now)
        let binding = fixture.binding

        XCTAssertFalse(try fixture.localEndpoint.renewSignedPrekeyIfNeeded(at: now))
        XCTAssertTrue(fixture.localEndpoint.prekeys.retiredSignedPrekeys.isEmpty)
        XCTAssertTrue(try binding.isStructurallyValidThrowing(now: now))

        let tampered = RelationshipEndpointBindingV4(
            signingPublicKey: binding.signingPublicKey,
            agreementPublicKey: binding.agreementPublicKey,
            capabilities: binding.capabilities,
            prekeyBundle: binding.prekeyBundle,
            prekeyPackageSignature: Data(repeating: 0, count: 3_309),
            issuedAt: binding.issuedAt,
            authoritySignature: binding.authoritySignature
        )
        XCTAssertThrowsError(try tampered.verified(
            authoritySigningPublicKey: fixture.authority.signingKey.publicKeyData,
            now: now
        )) { error in
            XCTAssertEqual(
                error as? RelationshipEndpointBindingError,
                .invalidPrekeyPackageSignature
            )
        }

        let tamperedAuthority = RelationshipEndpointBindingV4(
            signingPublicKey: binding.signingPublicKey,
            agreementPublicKey: binding.agreementPublicKey,
            capabilities: binding.capabilities,
            prekeyBundle: binding.prekeyBundle,
            prekeyPackageSignature: binding.prekeyPackageSignature,
            issuedAt: binding.issuedAt,
            authoritySignature: Data(repeating: 0, count: 3_309)
        )
        XCTAssertThrowsError(try tamperedAuthority.verified(
            authoritySigningPublicKey: fixture.authority.signingKey.publicKeyData,
            now: now
        )) { error in
            XCTAssertEqual(
                error as? RelationshipEndpointBindingError,
                .invalidAuthoritySignature
            )
        }

        let signedPrekey = binding.prekeyBundle.signedPrekey
        let invalidSignedPrekey = SignedPrekey(
            id: signedPrekey.id,
            publicKey: signedPrekey.publicKey,
            issuedAt: signedPrekey.issuedAt,
            expiresAt: signedPrekey.expiresAt,
            signature: Data(repeating: 0, count: 3_309)
        )
        let invalidBundle = PrekeyBundle(
            version: binding.prekeyBundle.version,
            relationshipSigningKeyDigest: binding.prekeyBundle.relationshipSigningKeyDigest,
            signedPrekey: invalidSignedPrekey,
            oneTimePrekeys: binding.prekeyBundle.oneTimePrekeys,
            createdAt: binding.prekeyBundle.createdAt
        )
        let invalidPrekeyBinding = RelationshipEndpointBindingV4(
            signingPublicKey: binding.signingPublicKey,
            agreementPublicKey: binding.agreementPublicKey,
            capabilities: binding.capabilities,
            prekeyBundle: invalidBundle,
            prekeyPackageSignature: binding.prekeyPackageSignature,
            issuedAt: binding.issuedAt,
            authoritySignature: binding.authoritySignature
        )
        XCTAssertThrowsError(try invalidPrekeyBinding.verified(
            authoritySigningPublicKey: fixture.authority.signingKey.publicKeyData,
            now: now
        )) { error in
            XCTAssertEqual(error as? RelationshipEndpointBindingError, .invalidStructure)
        }
        XCTAssertFalse(binding.isStructurallyValid(
            now: binding.prekeyBundle.signedPrekey.expiresAt
        ))
    }

    func testBindingSchemaContainsNoEndpointSetOrDeviceLifecycleState() throws {
        let fixture = try endpointFixture(pseudonym: "Relationship-only", prekeyIssuedAt: Date())
        let text = try XCTUnwrap(String(
            data: NoctweaveCoder.encode(fixture.binding, sortedKeys: true),
            encoding: .utf8
        ))
        for forbidden in ["manifest", "checkpoint", "epoch", "device", "installation", "revok"] {
            XCTAssertFalse(text.lowercased().contains(forbidden))
        }
    }
}

private struct EndpointPrekeyRotationFixture {
    let authority: RelationshipAuthorityV2
    var localEndpoint: LocalRelationshipEndpointV2
    let binding: RelationshipEndpointBindingV4
}

private func endpointFixture(
    pseudonym: String,
    prekeyIssuedAt: Date
) throws -> EndpointPrekeyRotationFixture {
    let authority = try RelationshipAuthorityV2.generate(
        relationshipPseudonym: pseudonym
    )
    let endpointSigning = try SigningKeyPair.generate()
    let endpointAgreement = try AgreementKeyPair.generate()
    let signedPrekeyPair = try AgreementKeyPair.generate()
    let signedPrekey = try SignedPrekey.create(
        agreementPublicKey: signedPrekeyPair.publicKeyData,
        signingKey: endpointSigning,
        issuedAt: prekeyIssuedAt
    )
    let localEndpoint = LocalRelationshipEndpointV2(
        signingKey: endpointSigning,
        agreementKey: endpointAgreement,
        prekeys: PrekeyState(
            signedPrekeyId: signedPrekey.id,
            signedPrekeyPublicKey: signedPrekeyPair.publicKeyData,
            signedPrekeyPrivateKey: signedPrekeyPair.privateKeyData,
            signedPrekeySignature: signedPrekey.signature,
            signedPrekeyIssuedAt: signedPrekey.issuedAt,
            signedPrekeyExpiresAt: signedPrekey.expiresAt,
            oneTimePrekeys: []
        ),
        createdAt: prekeyIssuedAt
    )
    return EndpointPrekeyRotationFixture(
        authority: authority,
        localEndpoint: localEndpoint,
        binding: try RelationshipEndpointBindingV4.create(
            authority: authority,
            endpoint: localEndpoint,
            issuedAt: prekeyIssuedAt
        )
    )
}
