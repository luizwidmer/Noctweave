import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2SelfSyncTransportTests: XCTestCase {
    func testSignedSourceChainRejectsImpersonationGapsForksAndConflictingReplays() throws {
        let fixture = try makeFixture()
        let first = try SignedSelfSyncRecordV2.create(
            identityGenerationId: fixture.generationId,
            sourceEndpointId: fixture.source.id,
            manifestEpoch: fixture.manifest.epoch,
            sourceSequence: 1,
            previousSourceDigest: nil,
            createdAt: fixture.createdAt.addingTimeInterval(1),
            payload: preferencePayload(revision: 1),
            sourceSigningKey: fixture.source.signingKey
        )
        XCTAssertTrue(
            first.verify(
                manifest: fixture.manifest,
                identityPublicKey: fixture.identity.signingKey.publicKeyData
            )
        )

        var chain = SelfSyncSourceChainV2(
            identityGenerationId: fixture.generationId,
            sourceEndpointId: fixture.source.id
        )
        XCTAssertEqual(
            try chain.apply(
                first,
                manifest: fixture.manifest,
                identityPublicKey: fixture.identity.signingKey.publicKeyData
            ),
            .applied
        )
        XCTAssertEqual(
            try chain.apply(
                first,
                manifest: fixture.manifest,
                identityPublicKey: fixture.identity.signingKey.publicKeyData
            ),
            .exactDuplicate
        )

        let gap = try SignedSelfSyncRecordV2.create(
            identityGenerationId: fixture.generationId,
            sourceEndpointId: fixture.source.id,
            manifestEpoch: fixture.manifest.epoch,
            sourceSequence: 3,
            previousSourceDigest: try XCTUnwrap(first.digest),
            createdAt: fixture.createdAt.addingTimeInterval(3),
            payload: preferencePayload(revision: 3),
            sourceSigningKey: fixture.source.signingKey
        )
        XCTAssertThrowsError(
            try chain.apply(
                gap,
                manifest: fixture.manifest,
                identityPublicKey: fixture.identity.signingKey.publicKeyData
            )
        ) { error in
            XCTAssertEqual(error as? SignedSelfSyncV2Error, .sequenceGap)
        }

        let impersonated = try SignedSelfSyncRecordV2.create(
            identityGenerationId: fixture.generationId,
            sourceEndpointId: fixture.source.id,
            manifestEpoch: fixture.manifest.epoch,
            sourceSequence: 2,
            previousSourceDigest: try XCTUnwrap(first.digest),
            createdAt: fixture.createdAt.addingTimeInterval(2),
            payload: preferencePayload(revision: 2),
            sourceSigningKey: fixture.recipient.signingKey
        )
        XCTAssertFalse(
            impersonated.verify(
                manifest: fixture.manifest,
                identityPublicKey: fixture.identity.signingKey.publicKeyData
            )
        )
        XCTAssertThrowsError(
            try chain.apply(
                impersonated,
                manifest: fixture.manifest,
                identityPublicKey: fixture.identity.signingKey.publicKeyData
            )
        ) { error in
            XCTAssertEqual(error as? SignedSelfSyncV2Error, .invalidSignature)
        }

        let second = try SignedSelfSyncRecordV2.create(
            identityGenerationId: fixture.generationId,
            sourceEndpointId: fixture.source.id,
            manifestEpoch: fixture.manifest.epoch,
            sourceSequence: 2,
            previousSourceDigest: try XCTUnwrap(first.digest),
            createdAt: fixture.createdAt.addingTimeInterval(2),
            payload: preferencePayload(revision: 2),
            sourceSigningKey: fixture.source.signingKey
        )
        XCTAssertEqual(
            try chain.apply(
                second,
                manifest: fixture.manifest,
                identityPublicKey: fixture.identity.signingKey.publicKeyData
            ),
            .applied
        )

        let fork = try SignedSelfSyncRecordV2.create(
            identityGenerationId: fixture.generationId,
            sourceEndpointId: fixture.source.id,
            manifestEpoch: fixture.manifest.epoch,
            sourceSequence: 3,
            previousSourceDigest: Data(repeating: 0xA5, count: 32),
            createdAt: fixture.createdAt.addingTimeInterval(3),
            payload: preferencePayload(revision: 3),
            sourceSigningKey: fixture.source.signingKey
        )
        XCTAssertThrowsError(
            try chain.apply(
                fork,
                manifest: fixture.manifest,
                identityPublicKey: fixture.identity.signingKey.publicKeyData
            )
        ) { error in
            XCTAssertEqual(error as? SignedSelfSyncV2Error, .sourceFork)
        }

        let conflictingReplay = try SignedSelfSyncRecordV2.create(
            identityGenerationId: fixture.generationId,
            sourceEndpointId: fixture.source.id,
            manifestEpoch: fixture.manifest.epoch,
            sourceSequence: 2,
            previousSourceDigest: try XCTUnwrap(first.digest),
            createdAt: fixture.createdAt.addingTimeInterval(2),
            payload: preferencePayload(revision: 99),
            sourceSigningKey: fixture.source.signingKey
        )
        XCTAssertThrowsError(
            try chain.apply(
                conflictingReplay,
                manifest: fixture.manifest,
                identityPublicKey: fixture.identity.signingKey.publicKeyData
            )
        ) { error in
            XCTAssertEqual(error as? SignedSelfSyncV2Error, .replayConflict)
        }
    }

    func testSealedRecordHidesGenerationAndEndpointMetadataAndBindsCiphertextContext() throws {
        let fixture = try makeFixture()
        let record = try SignedSelfSyncRecordV2.create(
            identityGenerationId: fixture.generationId,
            sourceEndpointId: fixture.source.id,
            manifestEpoch: fixture.manifest.epoch,
            sourceSequence: 1,
            previousSourceDigest: nil,
            createdAt: fixture.createdAt.addingTimeInterval(1),
            payload: preferencePayload(revision: 1),
            sourceSigningKey: fixture.source.signingKey
        )
        let epochKey = SymmetricKey(size: .bits256).dataRepresentation
        let sealed = try SealedSelfSyncRecordV2.seal(
            record,
            epochKeyData: epochKey,
            storedAt: fixture.createdAt.addingTimeInterval(59)
        )

        XCTAssertTrue(sealed.isStructurallyValid)
        XCTAssertTrue(
            NoctweaveSignedSelfSyncV2.recordPaddingBuckets.contains(
                sealed.payload.ciphertext.count
            )
        )
        XCTAssertEqual(try sealed.open(epochKeyData: epochKey), record)

        let relayVisible = try NoctweaveCoder.encode(sealed, sortedKeys: true)
        let relayVisibleText = String(decoding: relayVisible, as: UTF8.self)
        XCTAssertFalse(relayVisibleText.contains(fixture.generationId.uuidString))
        XCTAssertFalse(relayVisibleText.contains(fixture.source.id.uuidString))
        XCTAssertFalse(relayVisibleText.contains(fixture.recipient.id.uuidString))

        XCTAssertThrowsError(
            try sealed.open(
                epochKeyData: SymmetricKey(size: .bits256).dataRepresentation
            )
        ) { error in
            XCTAssertEqual(error as? SignedSelfSyncV2Error, .decryptionFailed)
        }
    }

    func testWelcomeIsIndependentlyKEMSealedRecipientBoundExpiringAndReplaySafe() throws {
        let fixture = try makeFixture()
        let welcome = try SelfSyncEpochWelcomeV2.create(
            identityGenerationId: fixture.generationId,
            manifestEpoch: fixture.manifest.epoch,
            selfSyncEpoch: 1,
            previousEpochDigest: nil,
            recipientEndpointId: fixture.recipient.id,
            epochKeyData: SymmetricKey(size: .bits256).dataRepresentation,
            issuedAt: fixture.createdAt.addingTimeInterval(1),
            expiresAt: fixture.createdAt.addingTimeInterval(301),
            identitySigningKey: fixture.identity.signingKey
        )
        let sealed = try SealedSelfSyncEpochWelcomeV2.seal(
            welcome,
            recipientAgreementPublicKey: fixture.recipient.agreementKey.publicKeyData
        )
        let opened = try sealed.open(
            recipientAgreementKey: fixture.recipient.agreementKey,
            manifest: fixture.manifest,
            identityPublicKey: fixture.identity.signingKey.publicKeyData,
            expectedRecipientEndpointId: fixture.recipient.id,
            now: fixture.createdAt.addingTimeInterval(2)
        )
        XCTAssertEqual(opened, welcome)

        let relayVisible = String(
            decoding: try NoctweaveCoder.encode(sealed, sortedKeys: true),
            as: UTF8.self
        )
        XCTAssertFalse(relayVisible.contains(fixture.generationId.uuidString))
        XCTAssertFalse(relayVisible.contains(fixture.recipient.id.uuidString))

        XCTAssertThrowsError(
            try sealed.open(
                recipientAgreementKey: fixture.recipient.agreementKey,
                manifest: fixture.manifest,
                identityPublicKey: fixture.identity.signingKey.publicKeyData,
                expectedRecipientEndpointId: fixture.source.id,
                now: fixture.createdAt.addingTimeInterval(2)
            )
        ) { error in
            XCTAssertEqual(error as? SignedSelfSyncV2Error, .wrongRecipient)
        }
        XCTAssertThrowsError(
            try sealed.open(
                recipientAgreementKey: fixture.source.agreementKey,
                manifest: fixture.manifest,
                identityPublicKey: fixture.identity.signingKey.publicKeyData,
                expectedRecipientEndpointId: fixture.recipient.id,
                now: fixture.createdAt.addingTimeInterval(2)
            )
        ) { error in
            XCTAssertEqual(error as? SignedSelfSyncV2Error, .decryptionFailed)
        }
        XCTAssertThrowsError(
            try sealed.open(
                recipientAgreementKey: fixture.recipient.agreementKey,
                manifest: fixture.manifest,
                identityPublicKey: fixture.identity.signingKey.publicKeyData,
                expectedRecipientEndpointId: fixture.recipient.id,
                now: fixture.createdAt.addingTimeInterval(301)
            )
        ) { error in
            XCTAssertEqual(error as? SignedSelfSyncV2Error, .expired)
        }

        var ledger = SelfSyncWelcomeReplayLedgerV2()
        try ledger.consume(
            welcome,
            manifest: fixture.manifest,
            identityPublicKey: fixture.identity.signingKey.publicKeyData,
            expectedRecipientEndpointId: fixture.recipient.id,
            now: fixture.createdAt.addingTimeInterval(2)
        )
        XCTAssertThrowsError(
            try ledger.consume(
                welcome,
                manifest: fixture.manifest,
                identityPublicKey: fixture.identity.signingKey.publicKeyData,
                expectedRecipientEndpointId: fixture.recipient.id,
                now: fixture.createdAt.addingTimeInterval(2)
            )
        ) { error in
            XCTAssertEqual(error as? SignedSelfSyncV2Error, .welcomeReplay)
        }
    }

    private func preferencePayload(revision: UInt64) -> TypedSelfSyncPayloadV2 {
        .preference(
            SelfSyncPreferenceUpdateV2(
                key: "notifications.enabled",
                revision: revision,
                value: .boolean(true),
                updatedAt: Date(timeIntervalSince1970: 1_001 + TimeInterval(revision))
            )
        )
    }

    private func makeFixture() throws -> (
        identity: Identity,
        generationId: UUID,
        source: LocalEndpointState,
        recipient: LocalEndpointState,
        manifest: EndpointSetManifest,
        createdAt: Date
    ) {
        let createdAt = Date(timeIntervalSince1970: 1_000)
        let identity = try Identity.generate(displayName: "Signed self-sync")
        let generationId = UUID()
        let source = try LocalEndpointState.generate(
            identityGenerationId: generationId,
            createdAt: createdAt
        )
        let recipient = try LocalEndpointState.generate(
            identityGenerationId: generationId,
            createdAt: createdAt
        )
        let manifest = try EndpointSetManifest.create(
            identityGenerationId: generationId,
            epoch: 0,
            endpoints: [
                source.publicRecord(addedEpoch: 0),
                recipient.publicRecord(addedEpoch: 0)
            ],
            identity: identity,
            issuedAt: createdAt
        )
        return (identity, generationId, source, recipient, manifest, createdAt)
    }
}
