import Foundation
import XCTest
@testable import NoctweaveCore

final class HistoryTransferV2Tests: XCTestCase {
    func testRoundTripReturnsOnlyAnInertReadOnlyProjectionAndSchemaExcludesSecrets() throws {
        let fixture = try Fixture()
        var ledger = HistoryArchiveImportLedgerV2()

        let result = try HistoryTransferV2.importArchive(
            encodedPackage: fixture.transportPackage.encodedForTransport(),
            trust: fixture.trust,
            recipientAgreementKey: fixture.recipientAgreementKey,
            ledger: &ledger,
            at: fixture.createdAt.addingTimeInterval(1)
        )

        XCTAssertEqual(result.disposition, .imported)
        XCTAssertEqual(result.projection, fixture.projection)
        XCTAssertFalse(result.projection.authorizesMailboxSync)
        XCTAssertFalse(result.projection.authorizesSending)
        XCTAssertFalse(result.projection.authorizesGroupParticipation)
        XCTAssertFalse(result.projection.authorizesFutureEpochs)
        XCTAssertFalse(result.projection.authorizesFutureParticipation)
        XCTAssertFalse(try XCTUnwrap(result.projection.attachmentReferences.first).canFetchAttachment)
        XCTAssertEqual(ledger.receipts.count, 1)

        let projectionKeys = try allJSONKeys(in: NoctweaveCoder.encode(result.projection, sortedKeys: true))
        let packageKeys = try allJSONKeys(in: fixture.transportPackage.encodedForTransport())
        let forbiddenKeys: Set<String> = [
            "privateKeyData",
            "inboxAccessKey",
            "inboxAuthority",
            "ratchetState",
            "rootKey",
            "chainKey",
            "prekeyState",
            "selfSyncKey",
            "appLockMaterial",
            "mailboxCredential",
            "groupLeaf",
            "participationAuthorization"
        ]
        XCTAssertTrue(projectionKeys.isDisjoint(with: forbiddenKeys))
        XCTAssertTrue(packageKeys.isDisjoint(with: forbiddenKeys))

        let control = ConversationEvent(
            conversationId: "conversation-1",
            authorInstallationHandle: fixture.authorHandle,
            createdAt: fixture.createdAt,
            kind: .control,
            content: try XCTUnwrap(EncodedContent.text("rotate"))
        )
        XCTAssertThrowsError(try HistoryEventProjectionV2(projecting: control)) { error in
            XCTAssertEqual(error as? HistoryTransferV2Error, .controlEventExcluded)
        }
    }

    func testOuterTransportSealExposesOnlyMinimalFieldsAndBucketedSize() throws {
        let fixture = try Fixture()
        let encoded = try fixture.transportPackage.encodedForTransport()
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertEqual(
            Set(object.keys),
            Set(["version", "kemCiphertext", "nonce", "ciphertext", "tag"])
        )
        XCTAssertEqual(
            try allJSONKeys(in: encoded),
            Set(["version", "kemCiphertext", "nonce", "ciphertext", "tag"])
        )

        let visibleJSON = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        let forbiddenVisibleValues = [
            fixture.identityGenerationId.uuidString,
            fixture.senderInstallationId.uuidString,
            fixture.recipientInstallationId.uuidString,
            fixture.authorityKey.publicKeyData.base64EncodedString(),
            fixture.senderInstallationKey.publicKeyData.base64EncodedString(),
            fixture.recipientAgreementKey.publicKeyData.base64EncodedString(),
            String(fixture.createdAt.timeIntervalSinceReferenceDate),
            String(fixture.expiresAt.timeIntervalSinceReferenceDate)
        ]
        for value in forbiddenVisibleValues {
            XCTAssertFalse(visibleJSON.localizedCaseInsensitiveContains(value), value)
        }

        XCTAssertTrue(
            NoctweaveHistoryTransferV2.sealedArchivePaddingBuckets.contains(
                fixture.transportPackage.ciphertext.count
            )
        )
        XCTAssertGreaterThan(
            fixture.transportPackage.ciphertext.count,
            try fixture.package.encodedForOuterSeal().count + MemoryLayout<UInt64>.size
        )

        let longerProjection = fixture.projectionReplacingText(String(repeating: "x", count: 1_024))
        let secondTransport = try HistoryTransferV2.exportArchive(
            longerProjection,
            senderIdentityAuthorityKey: fixture.authorityKey,
            senderInstallationId: fixture.senderInstallationId,
            senderInstallationSigningKey: fixture.senderInstallationKey,
            recipientInstallationId: fixture.recipientInstallationId,
            recipientAgreementPublicKey: fixture.recipientAgreementKey.publicKeyData,
            createdAt: fixture.createdAt,
            expiresAt: fixture.expiresAt
        )
        XCTAssertEqual(secondTransport.ciphertext.count, fixture.transportPackage.ciphertext.count)
    }

    func testOuterSealTamperingAndWrongRecipientFailBeforeInnerImport() throws {
        let fixture = try Fixture()
        var ledger = HistoryArchiveImportLedgerV2()
        var ciphertext = fixture.transportPackage.ciphertext
        ciphertext[ciphertext.startIndex] ^= 0x01
        let tampered = SealedHistoryArchiveTransportV2(
            kemCiphertext: fixture.transportPackage.kemCiphertext,
            nonce: fixture.transportPackage.nonce,
            ciphertext: ciphertext,
            tag: fixture.transportPackage.tag
        )
        XCTAssertThrowsError(
            try HistoryTransferV2.importArchive(
                tampered,
                trust: fixture.trust,
                recipientAgreementKey: fixture.recipientAgreementKey,
                ledger: &ledger,
                at: fixture.createdAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? HistoryTransferV2Error, .decryptionFailed)
        }
        XCTAssertTrue(ledger.receipts.isEmpty)

        let wrongRecipientKey = try AgreementKeyPair.generate()
        XCTAssertThrowsError(
            try HistoryTransferV2.importArchive(
                fixture.transportPackage,
                trust: fixture.trust,
                recipientAgreementKey: wrongRecipientKey,
                ledger: &ledger,
                at: fixture.createdAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? HistoryTransferV2Error, .decryptionFailed)
        }
        XCTAssertTrue(ledger.receipts.isEmpty)
    }

    func testOuterSealRejectsNonBucketCiphertextAndMalformedBounds() throws {
        let fixture = try Fixture()
        var ledger = HistoryArchiveImportLedgerV2()
        let malformed = SealedHistoryArchiveTransportV2(
            kemCiphertext: fixture.transportPackage.kemCiphertext,
            nonce: fixture.transportPackage.nonce,
            ciphertext: Data(repeating: 0, count: 65 * 1_024),
            tag: fixture.transportPackage.tag
        )
        XCTAssertFalse(malformed.isStructurallyValid)
        XCTAssertThrowsError(
            try HistoryTransferV2.importArchive(
                malformed,
                trust: fixture.trust,
                recipientAgreementKey: fixture.recipientAgreementKey,
                ledger: &ledger,
                at: fixture.createdAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? HistoryTransferV2Error, .invalidPackage)
        }

        let malformedTag = SealedHistoryArchiveTransportV2(
            kemCiphertext: fixture.transportPackage.kemCiphertext,
            nonce: fixture.transportPackage.nonce,
            ciphertext: fixture.transportPackage.ciphertext,
            tag: Data(repeating: 0, count: 15)
        )
        XCTAssertFalse(malformedTag.isStructurallyValid)
        XCTAssertTrue(ledger.receipts.isEmpty)
    }

    func testTamperingAndWrongRecipientFailWithoutCommittingImport() throws {
        let fixture = try Fixture()
        var ledger = HistoryArchiveImportLedgerV2()
        var ciphertext = fixture.package.encryptedProjection.ciphertext
        ciphertext[ciphertext.startIndex] ^= 0x01
        let tamperedCiphertext = EncryptedPayload(
            nonce: fixture.package.encryptedProjection.nonce,
            ciphertext: ciphertext,
            tag: fixture.package.encryptedProjection.tag
        )
        let tampered = EncryptedHistoryArchiveV2(
            manifest: fixture.package.manifest,
            manifestDigest: fixture.package.manifestDigest,
            encryptedProjection: tamperedCiphertext,
            keyWrap: fixture.package.keyWrap,
            keyWrapDigest: fixture.package.keyWrapDigest,
            senderIdentityAuthorityPublicKey: fixture.package.senderIdentityAuthorityPublicKey,
            senderInstallationSigningPublicKey: fixture.package.senderInstallationSigningPublicKey,
            authoritySignature: fixture.package.authoritySignature,
            installationPossessionSignature: fixture.package.installationPossessionSignature
        )

        XCTAssertThrowsError(
            try HistoryTransferV2.importInnerArchive(
                tampered,
                trust: fixture.trust,
                recipientAgreementKey: fixture.recipientAgreementKey,
                ledger: &ledger,
                at: fixture.createdAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? HistoryTransferV2Error, .ciphertextDigestMismatch)
        }
        XCTAssertTrue(ledger.receipts.isEmpty)

        let wrongRecipientKey = try AgreementKeyPair.generate()
        XCTAssertThrowsError(
            try HistoryTransferV2.importInnerArchive(
                fixture.package,
                trust: fixture.trust,
                recipientAgreementKey: wrongRecipientKey,
                ledger: &ledger,
                at: fixture.createdAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? HistoryTransferV2Error, .wrongRecipient)
        }
        XCTAssertTrue(ledger.receipts.isEmpty)

        var possessionSignature = fixture.package.installationPossessionSignature
        possessionSignature[possessionSignature.startIndex] ^= 0x01
        let forgedPossession = EncryptedHistoryArchiveV2(
            manifest: fixture.package.manifest,
            manifestDigest: fixture.package.manifestDigest,
            encryptedProjection: fixture.package.encryptedProjection,
            keyWrap: fixture.package.keyWrap,
            keyWrapDigest: fixture.package.keyWrapDigest,
            senderIdentityAuthorityPublicKey: fixture.package.senderIdentityAuthorityPublicKey,
            senderInstallationSigningPublicKey: fixture.package.senderInstallationSigningPublicKey,
            authoritySignature: fixture.package.authoritySignature,
            installationPossessionSignature: possessionSignature
        )
        XCTAssertThrowsError(
            try HistoryTransferV2.importInnerArchive(
                forgedPossession,
                trust: fixture.trust,
                recipientAgreementKey: fixture.recipientAgreementKey,
                ledger: &ledger,
                at: fixture.createdAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? HistoryTransferV2Error, .invalidInstallationSignature)
        }
        XCTAssertTrue(ledger.receipts.isEmpty)
    }

    func testExpiryAndReplayRulesAreExactAndIdempotent() throws {
        let fixture = try Fixture()
        var expiredLedger = HistoryArchiveImportLedgerV2()
        XCTAssertThrowsError(
            try HistoryTransferV2.importInnerArchive(
                fixture.package,
                trust: fixture.trust,
                recipientAgreementKey: fixture.recipientAgreementKey,
                ledger: &expiredLedger,
                at: fixture.expiresAt
            )
        ) { error in
            XCTAssertEqual(error as? HistoryTransferV2Error, .expired)
        }
        XCTAssertTrue(expiredLedger.receipts.isEmpty)

        var ledger = HistoryArchiveImportLedgerV2()
        let first = try HistoryTransferV2.importInnerArchive(
            fixture.package,
            trust: fixture.trust,
            recipientAgreementKey: fixture.recipientAgreementKey,
            ledger: &ledger,
            at: fixture.createdAt.addingTimeInterval(1)
        )
        let replay = try HistoryTransferV2.importInnerArchive(
            fixture.package,
            trust: fixture.trust,
            recipientAgreementKey: fixture.recipientAgreementKey,
            ledger: &ledger,
            at: fixture.createdAt.addingTimeInterval(2)
        )
        XCTAssertEqual(first.disposition, .imported)
        XCTAssertEqual(replay.disposition, .alreadyImported)
        XCTAssertEqual(replay.projection, first.projection)
        XCTAssertEqual(ledger.receipts.count, 1)

        let changedProjection = fixture.projectionReplacingText("different history")
        let conflictingPackage = try HistoryTransferV2.exportInnerArchive(
            changedProjection,
            archiveId: fixture.package.id,
            senderIdentityAuthorityKey: fixture.authorityKey,
            senderInstallationId: fixture.senderInstallationId,
            senderInstallationSigningKey: fixture.senderInstallationKey,
            recipientInstallationId: fixture.recipientInstallationId,
            recipientAgreementPublicKey: fixture.recipientAgreementKey.publicKeyData,
            createdAt: fixture.createdAt,
            expiresAt: fixture.expiresAt
        )
        XCTAssertThrowsError(
            try HistoryTransferV2.importInnerArchive(
                conflictingPackage,
                trust: fixture.trust,
                recipientAgreementKey: fixture.recipientAgreementKey,
                ledger: &ledger,
                at: fixture.createdAt.addingTimeInterval(3)
            )
        ) { error in
            XCTAssertEqual(error as? HistoryTransferV2Error, .replayConflict)
        }
        XCTAssertEqual(ledger.receipts.count, 1)
    }

    func testDefaultArchiveIsBoundToTheSameIdentityGeneration() throws {
        let fixture = try Fixture()

        XCTAssertEqual(
            fixture.package.manifest.recipientIdentityGenerationId,
            fixture.identityGenerationId
        )
        XCTAssertNil(fixture.package.manifest.crossGenerationApprovalDigest)
    }

    func testCrossGenerationHistoryRequiresExplicitApprovalAndRemainsInert() throws {
        let fixture = try Fixture()
        let recipientGenerationId = UUID(
            uuidString: "90000000-0000-0000-0000-000000000009"
        )!
        XCTAssertThrowsError(try CrossGenerationHistoryBridgeApprovalV2.create(
            sourceIdentityGenerationId: fixture.identityGenerationId,
            recipientIdentityGenerationId: fixture.identityGenerationId,
            senderEndpointId: fixture.senderInstallationId,
            recipientEndpointId: fixture.recipientInstallationId,
            senderIdentityAuthorityKey: fixture.authorityKey,
            senderEndpointSigningKey: fixture.senderInstallationKey,
            recipientAgreementPublicKey: fixture.recipientAgreementKey.publicKeyData,
            issuedAt: fixture.createdAt,
            expiresAt: fixture.expiresAt
        )) { error in
            XCTAssertEqual(error as? HistoryTransferV2Error, .invalidCrossGenerationApproval)
        }
        let approval = try CrossGenerationHistoryBridgeApprovalV2.create(
            sourceIdentityGenerationId: fixture.identityGenerationId,
            recipientIdentityGenerationId: recipientGenerationId,
            senderEndpointId: fixture.senderInstallationId,
            recipientEndpointId: fixture.recipientInstallationId,
            senderIdentityAuthorityKey: fixture.authorityKey,
            senderEndpointSigningKey: fixture.senderInstallationKey,
            recipientAgreementPublicKey: fixture.recipientAgreementKey.publicKeyData,
            nonce: Data(repeating: 0x7a, count: 32),
            issuedAt: fixture.createdAt,
            expiresAt: fixture.expiresAt
        )
        let transport = try HistoryTransferV2.exportCrossGenerationArchive(
            fixture.projection,
            senderIdentityAuthorityKey: fixture.authorityKey,
            senderEndpointId: fixture.senderInstallationId,
            senderEndpointSigningKey: fixture.senderInstallationKey,
            recipientEndpointId: fixture.recipientInstallationId,
            recipientAgreementPublicKey: fixture.recipientAgreementKey.publicKeyData,
            approval: approval,
            createdAt: fixture.createdAt,
            expiresAt: fixture.expiresAt.addingTimeInterval(-1)
        )

        var ordinaryLedger = HistoryArchiveImportLedgerV2()
        XCTAssertThrowsError(
            try HistoryTransferV2.importArchive(
                transport,
                trust: fixture.trust,
                recipientAgreementKey: fixture.recipientAgreementKey,
                ledger: &ordinaryLedger,
                at: fixture.createdAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? HistoryTransferV2Error, .crossGenerationApprovalRequired)
        }
        XCTAssertTrue(ordinaryLedger.receipts.isEmpty)

        var bridgeLedger = HistoryArchiveImportLedgerV2()
        let result = try HistoryTransferV2.importCrossGenerationArchive(
            transport,
            approval: approval,
            recipientAgreementKey: fixture.recipientAgreementKey,
            ledger: &bridgeLedger,
            at: fixture.createdAt.addingTimeInterval(1)
        )
        XCTAssertEqual(result.projection, fixture.projection)
        XCTAssertFalse(approval.authorizesMailboxSync)
        XCTAssertFalse(approval.authorizesSending)
        XCTAssertFalse(approval.authorizesGroupParticipation)
        XCTAssertFalse(approval.authorizesFutureEpochs)
        XCTAssertFalse(approval.authorizesFutureParticipation)
        XCTAssertTrue(approval.containsPrivateGenerationLink)
        XCTAssertFalse(approval.authorizesIdentityContinuity)
        XCTAssertFalse(result.projection.authorizesFutureParticipation)

        var forgedSignature = approval.endpointPossessionSignature
        forgedSignature[forgedSignature.startIndex] ^= 0x01
        let forged = CrossGenerationHistoryBridgeApprovalV2(
            id: approval.id,
            version: approval.version,
            purpose: approval.purpose,
            sourceIdentityGenerationId: approval.sourceIdentityGenerationId,
            recipientIdentityGenerationId: approval.recipientIdentityGenerationId,
            senderEndpointId: approval.senderEndpointId,
            recipientEndpointId: approval.recipientEndpointId,
            senderIdentityAuthorityPublicKey: approval.senderIdentityAuthorityPublicKey,
            senderEndpointSigningPublicKey: approval.senderEndpointSigningPublicKey,
            recipientAgreementPublicKeyDigest: approval.recipientAgreementPublicKeyDigest,
            nonce: approval.nonce,
            issuedAt: approval.issuedAt,
            expiresAt: approval.expiresAt,
            authoritySignature: approval.authoritySignature,
            endpointPossessionSignature: forgedSignature
        )
        var forgedLedger = HistoryArchiveImportLedgerV2()
        XCTAssertThrowsError(
            try HistoryTransferV2.importCrossGenerationArchive(
                transport,
                approval: forged,
                recipientAgreementKey: fixture.recipientAgreementKey,
                ledger: &forgedLedger,
                at: fixture.createdAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? HistoryTransferV2Error, .invalidCrossGenerationApproval)
        }
        XCTAssertTrue(forgedLedger.receipts.isEmpty)

        var expiredLedger = HistoryArchiveImportLedgerV2()
        XCTAssertThrowsError(
            try HistoryTransferV2.importCrossGenerationArchive(
                transport,
                approval: approval,
                recipientAgreementKey: fixture.recipientAgreementKey,
                ledger: &expiredLedger,
                at: approval.expiresAt
            )
        ) { error in
            XCTAssertEqual(error as? HistoryTransferV2Error, .invalidCrossGenerationApproval)
        }
        XCTAssertTrue(expiredLedger.receipts.isEmpty)
    }

    func testOversizeManifestIsRejectedBeforeAuthenticationOrDecryption() throws {
        let fixture = try Fixture()
        let original = fixture.package.manifest
        let oversizePlaintext = UInt64(NoctweaveHistoryTransferV2.maximumArchivePlaintextBytes) + 1
        let oversizeManifest = HistoryArchiveManifestV2(
            id: original.id,
            projectionId: original.projectionId,
            identityGenerationId: original.identityGenerationId,
            createdByInstallationId: original.createdByInstallationId,
            recipientInstallationId: original.recipientInstallationId,
            recipientAgreementPublicKeyDigest: original.recipientAgreementPublicKeyDigest,
            createdAt: original.createdAt,
            expiresAt: original.expiresAt,
            plaintextByteCount: oversizePlaintext,
            encryptedByteCount: oversizePlaintext + 28,
            projectionDigest: original.projectionDigest,
            ciphertextDigest: original.ciphertextDigest,
            conversationCount: original.conversationCount,
            eventCount: original.eventCount,
            attachmentReferenceCount: original.attachmentReferenceCount,
            contactAliasCount: original.contactAliasCount
        )
        let oversize = EncryptedHistoryArchiveV2(
            manifest: oversizeManifest,
            manifestDigest: fixture.package.manifestDigest,
            encryptedProjection: fixture.package.encryptedProjection,
            keyWrap: fixture.package.keyWrap,
            keyWrapDigest: fixture.package.keyWrapDigest,
            senderIdentityAuthorityPublicKey: fixture.package.senderIdentityAuthorityPublicKey,
            senderInstallationSigningPublicKey: fixture.package.senderInstallationSigningPublicKey,
            authoritySignature: fixture.package.authoritySignature,
            installationPossessionSignature: fixture.package.installationPossessionSignature
        )
        var ledger = HistoryArchiveImportLedgerV2()

        XCTAssertThrowsError(
            try HistoryTransferV2.importInnerArchive(
                oversize,
                trust: fixture.trust,
                recipientAgreementKey: fixture.recipientAgreementKey,
                ledger: &ledger,
                at: fixture.createdAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? HistoryTransferV2Error, .archiveTooLarge)
        }
        XCTAssertTrue(ledger.receipts.isEmpty)
    }

    private func allJSONKeys(in encoded: Data) throws -> Set<String> {
        let object = try JSONSerialization.jsonObject(with: encoded)
        var result = Set<String>()
        func visit(_ value: Any) {
            if let dictionary = value as? [String: Any] {
                result.formUnion(dictionary.keys)
                dictionary.values.forEach(visit)
            } else if let array = value as? [Any] {
                array.forEach(visit)
            }
        }
        visit(object)
        return result
    }
}

private struct Fixture {
    let createdAt = Date(timeIntervalSince1970: 10_000)
    let expiresAt = Date(timeIntervalSince1970: 10_600)
    let identityGenerationId = UUID(uuidString: "10000000-0000-0000-0000-000000000001")!
    let senderInstallationId = UUID(uuidString: "20000000-0000-0000-0000-000000000002")!
    let recipientInstallationId = UUID(uuidString: "30000000-0000-0000-0000-000000000003")!
    let authorHandle = RelationshipInstallationHandle(
        rawValue: Data(repeating: 0x41, count: 32).base64EncodedString()
    )
    let authorityKey: SigningKeyPair
    let senderInstallationKey: SigningKeyPair
    let recipientAgreementKey: AgreementKeyPair
    let projection: ReadOnlyHistoryProjectionV2
    let package: EncryptedHistoryArchiveV2
    let transportPackage: SealedHistoryArchiveTransportV2
    let trust: HistoryArchiveImportTrustV2

    init() throws {
        authorityKey = try SigningKeyPair.generate()
        senderInstallationKey = try SigningKeyPair.generate()
        recipientAgreementKey = try AgreementKeyPair.generate()
        let event = HistoryEventProjectionV2(
            id: UUID(uuidString: "40000000-0000-0000-0000-000000000004")!,
            clientTransactionId: UUID(uuidString: "50000000-0000-0000-0000-000000000005")!,
            conversationId: "conversation-1",
            authorInstallationHandle: authorHandle,
            createdAt: createdAt,
            kind: .application,
            content: try XCTUnwrap(EncodedContent.text("historical hello"))
        )
        projection = ReadOnlyHistoryProjectionV2(
            id: UUID(uuidString: "60000000-0000-0000-0000-000000000006")!,
            identityGenerationId: identityGenerationId,
            exportedAt: createdAt,
            conversations: [
                HistoryConversationProjectionV2(conversationId: "conversation-1", events: [event])
            ],
            attachmentReferences: [
                HistoryAttachmentReferenceV2(
                    id: UUID(uuidString: "70000000-0000-0000-0000-000000000007")!,
                    sourceEventId: event.id,
                    mimeType: "application/octet-stream",
                    byteCount: 42,
                    sha256: Data(repeating: 0x42, count: 32)
                )
            ],
            contactAliases: [
                HistoryContactAliasV2(relationshipId: "relationship-1", alias: "Alice")
            ]
        )
        package = try HistoryTransferV2.exportInnerArchive(
            projection,
            archiveId: UUID(uuidString: "80000000-0000-0000-0000-000000000008")!,
            senderIdentityAuthorityKey: authorityKey,
            senderInstallationId: senderInstallationId,
            senderInstallationSigningKey: senderInstallationKey,
            recipientInstallationId: recipientInstallationId,
            recipientAgreementPublicKey: recipientAgreementKey.publicKeyData,
            createdAt: createdAt,
            expiresAt: expiresAt
        )
        transportPackage = try HistoryTransferV2.exportArchive(
            projection,
            archiveId: UUID(uuidString: "80000000-0000-0000-0000-000000000008")!,
            senderIdentityAuthorityKey: authorityKey,
            senderInstallationId: senderInstallationId,
            senderInstallationSigningKey: senderInstallationKey,
            recipientInstallationId: recipientInstallationId,
            recipientAgreementPublicKey: recipientAgreementKey.publicKeyData,
            createdAt: createdAt,
            expiresAt: expiresAt
        )
        trust = HistoryArchiveImportTrustV2(
            identityGenerationId: identityGenerationId,
            senderInstallationId: senderInstallationId,
            recipientInstallationId: recipientInstallationId,
            senderIdentityAuthorityPublicKey: authorityKey.publicKeyData,
            senderInstallationSigningPublicKey: senderInstallationKey.publicKeyData
        )
    }

    func projectionReplacingText(_ text: String) -> ReadOnlyHistoryProjectionV2 {
        let original = projection.conversations[0].events[0]
        let replacement = HistoryEventProjectionV2(
            id: original.id,
            clientTransactionId: original.clientTransactionId,
            conversationId: original.conversationId,
            authorInstallationHandle: original.authorInstallationHandle,
            createdAt: original.createdAt,
            kind: original.kind,
            content: EncodedContent.text(text)!,
            relation: original.relation
        )
        return ReadOnlyHistoryProjectionV2(
            id: projection.id,
            identityGenerationId: projection.identityGenerationId,
            exportedAt: projection.exportedAt,
            conversations: [HistoryConversationProjectionV2(conversationId: original.conversationId, events: [replacement])],
            attachmentReferences: projection.attachmentReferences,
            contactAliases: projection.contactAliases
        )
    }
}
