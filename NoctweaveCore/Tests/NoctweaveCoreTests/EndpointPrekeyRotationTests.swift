import XCTest
@testable import NoctweaveCore

final class EndpointPrekeyRotationTests: XCTestCase {
    func testRenewalKeepsStableAuthorizationAndRetainsOldPrivateKeyUntilExpiry() throws {
        let now = Date()
        let issuedAt = now.addingTimeInterval(
            -PrekeyBundle.maximumAge + PrekeyState.signedPrekeyRenewalLeadTime
        )
        var local = try endpointFixture(name: "Alice", prekeyIssuedAt: issuedAt)
        let peer = try endpointFixture(name: "Bob", prekeyIssuedAt: now)
        let original = local.endpoint
        let originalPrekey = original.prekeyBundle.signedPrekey
        let originalAuthorizationDigest = try XCTUnwrap(original.authorizationDigest)
        let originalBinding = try PairwiseInstallationBindingV4.derive(
            localIdentityGenerationId: local.generationId,
            localIdentitySigningPublicKey: local.identity.signingKey.publicKeyData,
            localEndpoint: original,
            peerIdentityGenerationId: peer.generationId,
            peerIdentitySigningPublicKey: peer.identity.signingKey.publicKeyData,
            peerEndpoint: peer.endpoint
        )

        XCTAssertTrue(try local.installation.renewSignedPrekeyIfNeeded(at: now))
        XCTAssertEqual(local.installation.prekeys.retiredSignedPrekeys.count, 1)
        XCTAssertNotEqual(local.installation.prekeys.signedPrekeyId, originalPrekey.id)
        XCTAssertNotNil(local.installation.prekeys.signedPrekeyKeyPair(
            id: originalPrekey.id,
            now: now
        ))
        let persistedPrekeys = try NoctweaveCoder.decode(
            PrekeyState.self,
            from: NoctweaveCoder.encode(local.installation.prekeys)
        )
        XCTAssertNotNil(persistedPrekeys.signedPrekeyKeyPair(
            id: originalPrekey.id,
            now: now
        ))

        let refreshed = try original.refreshingPrekeyPackage(
            using: local.installation,
            at: now
        )
        XCTAssertEqual(refreshed.authorizationDigest, originalAuthorizationDigest)
        XCTAssertEqual(refreshed.authoritySignature, original.authoritySignature)
        XCTAssertEqual(refreshed.possessionSignature, original.possessionSignature)
        XCTAssertNotEqual(refreshed.prekeyBundle.signedPrekey.id, originalPrekey.id)
        XCTAssertNoThrow(try refreshed.verified(
            identityPublicKey: local.identity.signingKey.publicKeyData,
            manifest: local.manifest,
            now: now
        ))

        let refreshedBinding = try PairwiseInstallationBindingV4.derive(
            localIdentityGenerationId: local.generationId,
            localIdentitySigningPublicKey: local.identity.signingKey.publicKeyData,
            localEndpoint: refreshed,
            peerIdentityGenerationId: peer.generationId,
            peerIdentitySigningPublicKey: peer.identity.signingKey.publicKeyData,
            peerEndpoint: peer.endpoint
        )
        XCTAssertEqual(refreshedBinding, originalBinding)

        XCTAssertNil(local.installation.prekeys.signedPrekeyKeyPair(
            id: originalPrekey.id,
            now: originalPrekey.expiresAt
        ))
        local.installation.prekeys.pruneExpiredSignedPrekeys(now: originalPrekey.expiresAt)
        XCTAssertTrue(local.installation.prekeys.retiredSignedPrekeys.isEmpty)
    }

    func testFreshPrekeyDoesNotRotateAndTamperedOrExpiredPackageFailsClosed() throws {
        let now = Date()
        var fixture = try endpointFixture(name: "Alice", prekeyIssuedAt: now)
        let endpoint = fixture.endpoint

        XCTAssertFalse(try fixture.installation.renewSignedPrekeyIfNeeded(at: now))
        XCTAssertTrue(fixture.installation.prekeys.retiredSignedPrekeys.isEmpty)

        let tampered = CertifiedInstallationEndpoint(
            identityGenerationId: endpoint.identityGenerationId,
            identityAuthorityPublicKey: endpoint.identityAuthorityPublicKey,
            manifestEpoch: endpoint.manifestEpoch,
            manifestDigest: endpoint.manifestDigest,
            installationId: endpoint.installationId,
            signingPublicKey: endpoint.signingPublicKey,
            agreementPublicKey: endpoint.agreementPublicKey,
            capabilities: endpoint.capabilities,
            prekeyBundle: endpoint.prekeyBundle,
            prekeyPackageSignature: Data(repeating: 0, count: 3_309),
            issuedAt: endpoint.issuedAt,
            authoritySignature: endpoint.authoritySignature,
            possessionSignature: endpoint.possessionSignature
        )
        XCTAssertThrowsError(try tampered.verified(
            identityPublicKey: fixture.identity.signingKey.publicKeyData,
            manifest: fixture.manifest,
            now: now
        ))
        XCTAssertFalse(endpoint.isStructurallyValid(
            now: endpoint.prekeyBundle.signedPrekey.expiresAt
        ))
    }
}

private struct EndpointPrekeyRotationFixture {
    let identity: Identity
    let generationId: UUID
    var installation: LocalInstallationState
    let manifest: InstallationManifest
    let endpoint: CertifiedInstallationEndpoint
}

private func endpointFixture(
    name: String,
    prekeyIssuedAt: Date
) throws -> EndpointPrekeyRotationFixture {
    let identity = try Identity.generate(displayName: name)
    let generationId = UUID()
    let endpointSigning = try SigningKeyPair.generate()
    let endpointAgreement = try AgreementKeyPair.generate()
    let signedPrekeyPair = try AgreementKeyPair.generate()
    let signedPrekey = try SignedPrekey.create(
        agreementPublicKey: signedPrekeyPair.publicKeyData,
        signingKey: endpointSigning,
        issuedAt: prekeyIssuedAt
    )
    let installation = LocalInstallationState(
        id: UUID(),
        identityGenerationId: generationId,
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
    let manifest = try InstallationManifest.create(
        identityGenerationId: generationId,
        epoch: 0,
        installations: [installation.publicRecord(addedEpoch: 0)],
        identity: identity,
        issuedAt: prekeyIssuedAt
    )
    return EndpointPrekeyRotationFixture(
        identity: identity,
        generationId: generationId,
        installation: installation,
        manifest: manifest,
        endpoint: try CertifiedInstallationEndpoint.create(
            identity: identity,
            installation: installation,
            manifest: manifest,
            issuedAt: Date()
        )
    )
}
