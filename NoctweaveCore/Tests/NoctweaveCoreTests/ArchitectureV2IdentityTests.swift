import XCTest
import CryptoKit
@testable import NoctweaveCore

final class ArchitectureV2IdentityTests: XCTestCase {
    func testLegacyProfileMigratesToIndependentInstallationAndSignedManifest() throws {
        let identity = try Identity.generate(displayName: "Architecture migration")
        let prekeys = try PrekeyState.generate(identity: identity)
        var profile = IdentityProfile(
            identity: identity,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: prekeys,
            createdAt: Date(timeIntervalSince1970: 1_000)
        )

        XCTAssertTrue(try profile.migrateToArchitectureV2())
        XCTAssertTrue(profile.isArchitectureV2Ready)
        XCTAssertEqual(profile.architectureVersion, 2)
        let accessKey = try XCTUnwrap(profile.inboxAccessKey)
        XCTAssertTrue(InboxAddress.isBound(profile.inboxId, to: accessKey.publicKeyData))
        XCTAssertNotEqual(
            profile.localInstallation?.signingKey.publicKeyData,
            identity.signingKey.publicKeyData
        )
        XCTAssertNotEqual(
            profile.localInstallation?.agreementKey.publicKeyData,
            identity.agreementKey.publicKeyData
        )
        XCTAssertEqual(profile.installationManifest?.activeInstallations.count, 1)
        XCTAssertFalse(try profile.migrateToArchitectureV2())
    }

    func testClientStateStoreMigratesLegacyStateOnceAndPersistsGeneration() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let stateURL = directory.appendingPathComponent("state.json")
        defer { try? FileManager.default.removeItem(at: directory) }
        let identity = try Identity.generate(displayName: "Persisted migration")
        let legacy = ClientState(
            identity: identity,
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            inboxId: InboxAddress.generate()
        )
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try NoctweaveCoder.encode(legacy).write(to: stateURL, options: .atomic)

        let store = ClientStateStore(fileURL: stateURL, useEncryption: false)
        let loadedFirst = try await store.load()
        let first = try XCTUnwrap(loadedFirst)
        let firstProfile = try XCTUnwrap(first.identityProfiles.first { $0.id == first.activeIdentityId })
        let firstGeneration = try XCTUnwrap(firstProfile.identityGenerationId)
        XCTAssertEqual(first.schemaVersion, 2)
        XCTAssertTrue(firstProfile.isArchitectureV2Ready)

        let loadedSecond = try await store.load()
        let second = try XCTUnwrap(loadedSecond)
        let secondProfile = try XCTUnwrap(second.identityProfiles.first { $0.id == second.activeIdentityId })
        XCTAssertEqual(secondProfile.identityGenerationId, firstGeneration)
        XCTAssertEqual(secondProfile.localInstallation?.id, firstProfile.localInstallation?.id)
    }

    func testRelationshipInstallationHandleMatchesJavaScriptVector() throws {
        let handle = RelationshipInstallationHandle.generate(
            identityGenerationId: try XCTUnwrap(UUID(uuidString: "25D6B258-9C3D-43B9-A6AB-F654B3089B4B")),
            installationId: try XCTUnwrap(UUID(uuidString: "A12AA310-613D-4F86-8F45-28DC0D410F9F")),
            relationshipId: try XCTUnwrap(UUID(uuidString: "4A2D4951-C0CA-4B9D-94A4-2DC80B4AE8E0")),
            nonce: try XCTUnwrap(UUID(uuidString: "E141680A-06A0-4E36-B2D7-5AE72B6013CD"))
        )
        XCTAssertEqual(handle.rawValue, "DwJGzuzXU2cCN2GRkyDQbpsIX3FSSpgu/rH1/BrTskg=")
        XCTAssertTrue(handle.isStructurallyValid)
    }

    func testCapabilityNegotiationUsesHighestSharedVersionAndLowestLimit() throws {
        let local = ProtocolCapabilityManifest(modules: [
            ProtocolModuleCapability(module: "nw.core", versions: [1, 2], status: .provisional),
            ProtocolModuleCapability(
                module: "nw.mailbox",
                versions: [1, 2],
                status: .provisional,
                limits: ["maxPage": 256]
            )
        ])
        let peer = ProtocolCapabilityManifest(modules: [
            ProtocolModuleCapability(module: "nw.core", versions: [2], status: .stable),
            ProtocolModuleCapability(
                module: "nw.mailbox",
                versions: [2, 3],
                status: .stable,
                limits: ["maxPage": 64]
            )
        ])
        let negotiated = try XCTUnwrap(local.negotiated(with: peer))
        XCTAssertTrue(negotiated.supports(module: "nw.core", version: 2))
        let mailbox = try XCTUnwrap(negotiated.modules.first { $0.module == "nw.mailbox" })
        XCTAssertEqual(mailbox.versions, [2])
        XCTAssertEqual(mailbox.limits["maxPage"], 64)
    }

    func testDefaultEndpointCapabilitiesAdvertiseOnlyTheWiredDirectPath() throws {
        let manifest = ProtocolCapabilityManifest()
        XCTAssertEqual(
            manifest.modules.map(\.module),
            ["nw.core", "nw.endpoints", "nw.events", "nw.prekeys"]
        )
        XCTAssertEqual(
            manifest.modules.first { $0.module == "nw.endpoints" }?.limits["maxActiveEndpoints"],
            1
        )
        XCTAssertEqual(ProtocolCapabilityManifest.knownModuleCatalog.count, 13)

        for inactive in [
            "nw.mailbox",
            "nw.routes",
            "nw.blobs",
            "nw.groups",
            "nw.wake",
            "nw.federation",
            "nw.privacy.hidden-retrieval",
            "nw.privacy.onion",
            "nw.privacy.mixnet"
        ] {
            XCTAssertFalse(manifest.modules.contains { $0.module == inactive })
            XCTAssertTrue(
                ProtocolCapabilityManifest.knownModuleCatalog.contains { $0.module == inactive }
            )
        }
    }

    func testInstallationManifestRejectsInvalidHistoryAndFutureInstallationEpochs() throws {
        let issuedAt = Date(timeIntervalSince1970: 2_000)
        let identity = try Identity.generate(displayName: "Manifest invariants")
        let generationId = UUID()
        let installation = try LocalInstallationState.generate(
            identityGenerationId: generationId,
            createdAt: issuedAt
        )
        let record = installation.publicRecord(addedEpoch: 0)

        let rootWithParent = try InstallationManifest.create(
            identityGenerationId: generationId,
            epoch: 0,
            previousManifestDigest: Data(repeating: 1, count: 32),
            installations: [record],
            identity: identity,
            issuedAt: issuedAt
        )
        XCTAssertFalse(rootWithParent.isStructurallyValid)
        XCTAssertFalse(rootWithParent.verify(identityPublicKey: identity.signingKey.publicKeyData))

        let updateWithoutParent = try InstallationManifest.create(
            identityGenerationId: generationId,
            epoch: 1,
            installations: [record],
            identity: identity,
            issuedAt: issuedAt
        )
        XCTAssertFalse(updateWithoutParent.isStructurallyValid)

        let futureRecord = InstallationRecord(
            id: record.id,
            identityGenerationId: generationId,
            signingPublicKey: record.signingPublicKey,
            agreementPublicKey: record.agreementPublicKey,
            capabilities: record.capabilities,
            addedEpoch: 2,
            addedAt: issuedAt
        )
        let futureAdd = try InstallationManifest.create(
            identityGenerationId: generationId,
            epoch: 1,
            previousManifestDigest: Data(repeating: 2, count: 32),
            installations: [futureRecord],
            identity: identity,
            issuedAt: issuedAt
        )
        XCTAssertFalse(futureAdd.isStructurallyValid)

        let futureRevocation = try XCTUnwrap(record.revoked(epoch: 2, at: issuedAt))
        let futureRevoke = try InstallationManifest.create(
            identityGenerationId: generationId,
            epoch: 1,
            previousManifestDigest: Data(repeating: 3, count: 32),
            installations: [futureRevocation],
            identity: identity,
            issuedAt: issuedAt
        )
        XCTAssertFalse(futureRevoke.isStructurallyValid)
    }

    func testArchitectureReadinessBindsLocalInstallationKeysToManifestRecord() throws {
        let identity = try Identity.generate(displayName: "Installation binding")
        var profile = IdentityProfile(
            identity: identity,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity)
        )
        XCTAssertTrue(try profile.migrateToArchitectureV2())
        XCTAssertTrue(profile.isArchitectureV2Ready)

        let original = try XCTUnwrap(profile.localInstallation)
        profile.localInstallation = try LocalInstallationState.generate(
            identityGenerationId: original.identityGenerationId,
            id: original.id,
            createdAt: original.createdAt
        )
        XCTAssertFalse(profile.isArchitectureV2Ready)
        XCTAssertThrowsError(try profile.migrateToArchitectureV2()) { error in
            XCTAssertEqual(error as? IdentityProfileMigrationError, .invalidV2State)
        }
    }

    func testArchitectureReadinessRejectsReusedOrUnscopedInboxReachability() throws {
        let identity = try Identity.generate(displayName: "Reachability binding")
        let relay = RelayEndpoint(host: "127.0.0.1", port: 9340)
        var profile = IdentityProfile(
            identity: identity,
            inboxId: InboxAddress.generate(),
            relay: relay,
            prekeys: try PrekeyState.generate(identity: identity)
        )
        XCTAssertTrue(try profile.migrateToArchitectureV2())
        XCTAssertTrue(profile.isArchitectureV2Ready)

        let originalInboxId = profile.inboxId
        let originalAccessKey = try XCTUnwrap(profile.inboxAccessKey)
        profile.inboxAccessKey = try SigningKeyPair.generate()
        XCTAssertFalse(profile.isArchitectureV2Ready)

        profile.inboxAccessKey = originalAccessKey
        profile.inboxId = InboxAddress.generate()
        XCTAssertFalse(profile.isArchitectureV2Ready)

        profile.inboxId = originalInboxId
        var endpoint = try XCTUnwrap(profile.localInstallation)
        let routeKey = MailboxRouteCredentialV2.routeIdentifier(
            relay: relay,
            inboxId: originalInboxId
        )
        let unscoped = try MailboxRouteCredentialV2.generate()
        endpoint.mailboxCredentialsByRoute[routeKey] = unscoped
        endpoint.mailboxConsumerIdsByRoute[routeKey] = unscoped.consumerId
        profile.localInstallation = endpoint
        XCTAssertFalse(profile.isArchitectureV2Ready)

        let wrongInboxKey = try SigningKeyPair.generate()
        let wrongInbox = InboxAddress.derived(from: wrongInboxKey.publicKeyData)
        let scopedWrong = try MailboxRouteCredentialV2.generate(
            relay: relay,
            inboxId: wrongInbox
        )
        endpoint.mailboxCredentialsByRoute = [
            MailboxRouteCredentialV2.routeIdentifier(relay: relay, inboxId: wrongInbox): scopedWrong
        ]
        endpoint.mailboxConsumerIdsByRoute = [
            MailboxRouteCredentialV2.routeIdentifier(relay: relay, inboxId: wrongInbox): scopedWrong.consumerId
        ]
        profile.localInstallation = endpoint
        XCTAssertFalse(profile.isArchitectureV2Ready)
    }

    func testMailboxCredentialsUseFreshKeysPerRouteAndPreserveLegacySponsor() throws {
        let createdAt = Date(timeIntervalSince1970: 1_500)
        var installation = try LocalInstallationState.generate(
            identityGenerationId: UUID(),
            createdAt: createdAt
        )
        let legacyId = MailboxConsumerId.generate()
        installation.mailboxConsumerIdsByRoute["legacy-route"] = legacyId

        let legacyMigration = try installation.ensureMailboxCredential(
            for: "legacy-route",
            at: createdAt.addingTimeInterval(1)
        )
        let secondRoute = try installation.ensureMailboxCredential(
            for: "second-route",
            at: createdAt.addingTimeInterval(2)
        )

        XCTAssertEqual(legacyMigration.legacySponsorConsumerId, legacyId)
        XCTAssertNotEqual(legacyMigration.consumerId, legacyId)
        XCTAssertNotEqual(
            legacyMigration.signingKey.publicKeyData,
            installation.signingKey.publicKeyData
        )
        XCTAssertNotEqual(
            legacyMigration.signingKey.publicKeyData,
            secondRoute.signingKey.publicKeyData
        )
        XCTAssertTrue(installation.mailboxStateIsStructurallyValid)

        try installation.completeMailboxCredentialMigration(for: "legacy-route")
        XCTAssertNil(
            installation.mailboxCredentialsByRoute["legacy-route"]?.legacySponsorConsumerId
        )
        XCTAssertEqual(
            installation.mailboxConsumerIdsByRoute["legacy-route"],
            legacyMigration.consumerId
        )
        let decoded = try NoctweaveCoder.decode(
            LocalInstallationState.self,
            from: NoctweaveCoder.encode(installation, sortedKeys: true)
        )
        XCTAssertEqual(
            decoded.mailboxCredentialsByRoute,
            installation.mailboxCredentialsByRoute
        )
        XCTAssertEqual(
            decoded.mailboxConsumerIdsByRoute,
            installation.mailboxConsumerIdsByRoute
        )
    }

    func testProfileAdmitsAndRemovesIndependentEndpointWithProofsAndHashChain() throws {
        let createdAt = Date(timeIntervalSince1970: 3_000)
        let identity = try Identity.generate(displayName: "Installation lifecycle")
        var profile = IdentityProfile(
            identity: identity,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: createdAt
        )
        XCTAssertTrue(try profile.migrateToArchitectureV2())
        let root = try XCTUnwrap(profile.installationManifest)
        let rootDigest = try XCTUnwrap(root.digest)
        let remote = try LocalInstallationState.generate(
            identityGenerationId: try XCTUnwrap(profile.identityGenerationId),
            createdAt: createdAt.addingTimeInterval(1)
        )
        try admitEndpoint(
            remote,
            to: &profile,
            at: createdAt.addingTimeInterval(2)
        )
        let authorized = try XCTUnwrap(profile.installationManifest)
        XCTAssertEqual(authorized.epoch, 1)
        XCTAssertEqual(authorized.previousManifestDigest, rootDigest)
        XCTAssertEqual(profile.activeEndpoints.count, 2)
        XCTAssertTrue(authorized.verify(identityPublicKey: identity.signingKey.publicKeyData))
        XCTAssertTrue(profile.isArchitectureV2Ready)
        XCTAssertThrowsError(try profile.prepareEndpointAdmission(
            candidate: EndpointAdmissionCandidateV2(endpoint: remote),
            issuedAt: createdAt.addingTimeInterval(3),
            expiresAt: createdAt.addingTimeInterval(63)
        )) { error in
            XCTAssertEqual(error as? EndpointAdmissionV2Error, .replayed)
        }

        let localInstallationId = try XCTUnwrap(profile.localInstallation?.id)
        XCTAssertNil(try profile.removeEndpoint(
            localInstallationId,
            at: createdAt.addingTimeInterval(3)
        ))
        let removal = try XCTUnwrap(profile.removeEndpoint(
            remote.id,
            at: createdAt.addingTimeInterval(3)
        ))
        XCTAssertTrue(removal.isStructurallyValid)
        XCTAssertTrue(removal.requiresExternalCleanup)
        XCTAssertFalse(removal.authorizesFutureParticipation)
        let revoked = try XCTUnwrap(profile.installationManifest)
        XCTAssertEqual(revoked.epoch, 2)
        XCTAssertEqual(revoked.previousManifestDigest, authorized.digest)
        XCTAssertEqual(profile.activeEndpoints.map(\.id), [localInstallationId])
        XCTAssertTrue(profile.isArchitectureV2Ready)
        XCTAssertNil(try profile.removeEndpoint(
            remote.id,
            at: createdAt.addingTimeInterval(4)
        ))
    }

    func testRevokedInstallationsAreCheckpointedSoDeviceChurnDoesNotExhaustManifest() throws {
        let createdAt = Date(timeIntervalSince1970: 4_000)
        let identity = try Identity.generate(displayName: "Installation churn")
        var profile = IdentityProfile(
            identity: identity,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: createdAt
        )
        XCTAssertTrue(try profile.migrateToArchitectureV2())

        for replacement in 0..<(NoctweaveArchitectureV2.maximumInstallations * 2) {
            let manifest = try XCTUnwrap(profile.installationManifest)
            let installation = try LocalInstallationState.generate(
                identityGenerationId: try XCTUnwrap(profile.identityGenerationId),
                createdAt: createdAt.addingTimeInterval(Double(replacement * 2 + 1))
            )
            let additionDate = createdAt.addingTimeInterval(Double(replacement * 2 + 1))
            let revocationDate = createdAt.addingTimeInterval(Double(replacement * 2 + 2))

            XCTAssertEqual(manifest.epoch, UInt64(replacement * 2))
            try admitEndpoint(installation, to: &profile, at: additionDate)
            XCTAssertEqual(profile.installationManifest?.installations.count, 2)
            XCTAssertNotNil(try profile.removeEndpoint(installation.id, at: revocationDate))
            XCTAssertEqual(profile.activeEndpoints.count, 1)
            XCTAssertTrue(profile.isArchitectureV2Ready)
        }

        XCTAssertEqual(profile.installationManifest?.installations.count, 2)
        XCTAssertEqual(
            profile.installationManifest?.epoch,
            UInt64(NoctweaveArchitectureV2.maximumInstallations * 4)
        )
    }

    func testExpiredInstallationsAreCheckpointedSoTheyCannotExhaustManifest() throws {
        let createdAt = Date(timeIntervalSince1970: 4_500)
        let identity = try Identity.generate(displayName: "Expiring installation churn")
        var profile = IdentityProfile(
            identity: identity,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: createdAt
        )
        XCTAssertTrue(try profile.migrateToArchitectureV2())
        let expiresAt = createdAt.addingTimeInterval(100)

        for index in 1..<NoctweaveArchitectureV2.maximumInstallations {
            let manifest = try XCTUnwrap(profile.installationManifest)
            let installation = try LocalInstallationState.generate(
                identityGenerationId: try XCTUnwrap(profile.identityGenerationId),
                createdAt: createdAt.addingTimeInterval(Double(index))
            )
            XCTAssertEqual(manifest.epoch, UInt64(index - 1))
            try admitEndpoint(
                installation,
                to: &profile,
                at: createdAt.addingTimeInterval(Double(index)),
                endpointExpiresAt: expiresAt
            )
        }
        XCTAssertEqual(
            profile.installationManifest?.installations.count,
            NoctweaveArchitectureV2.maximumInstallations
        )

        let fullManifestDigest = try XCTUnwrap(profile.installationManifest?.digest)
        let replacement = try LocalInstallationState.generate(
            identityGenerationId: try XCTUnwrap(profile.identityGenerationId),
            createdAt: expiresAt.addingTimeInterval(1)
        )
        try admitEndpoint(
            replacement,
            to: &profile,
            at: expiresAt.addingTimeInterval(1)
        )

        let checkpoint = try XCTUnwrap(profile.installationManifest)
        XCTAssertEqual(checkpoint.previousManifestDigest, fullManifestDigest)
        XCTAssertEqual(checkpoint.installations.count, 2)
        XCTAssertTrue(checkpoint.installations.contains(where: { $0.id == replacement.id }))
        XCTAssertTrue(profile.isArchitectureV2Ready)
    }

    func testEndpointAdmissionRejectsExpiryReplayWrongGenerationAndForgedProofs() throws {
        let createdAt = Date(timeIntervalSince1970: 5_000)
        let identity = try Identity.generate(displayName: "Endpoint admission proofs")
        var profile = IdentityProfile(
            identity: identity,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: createdAt
        )
        XCTAssertTrue(try profile.migrateToArchitectureV2())
        let endpoint = try LocalInstallationState.generate(
            identityGenerationId: try XCTUnwrap(profile.identityGenerationId),
            createdAt: createdAt.addingTimeInterval(1)
        )
        let wrongGenerationCandidate = EndpointAdmissionCandidateV2(
            identityGenerationId: UUID(),
            endpointId: endpoint.id,
            signingPublicKey: endpoint.signingKey.publicKeyData,
            agreementPublicKey: endpoint.agreementKey.publicKeyData
        )
        XCTAssertThrowsError(try profile.prepareEndpointAdmission(
            candidate: wrongGenerationCandidate,
            issuedAt: createdAt.addingTimeInterval(2),
            expiresAt: createdAt.addingTimeInterval(62)
        )) { error in
            XCTAssertEqual(error as? EndpointAdmissionV2Error, .wrongIdentityGeneration)
        }
        let pending = try profile.prepareEndpointAdmission(
            candidate: EndpointAdmissionCandidateV2(endpoint: endpoint),
            issuedAt: createdAt.addingTimeInterval(2),
            expiresAt: createdAt.addingTimeInterval(62),
            nonce: Data(repeating: 0x41, count: 32)
        )
        let response = try EndpointAdmissionResponseV2.create(
            challenge: pending.challenge,
            endpoint: endpoint,
            identityAuthorityPublicKey: identity.signingKey.publicKeyData,
            respondedAt: createdAt.addingTimeInterval(3)
        )

        let wrongGeneration = EndpointAdmissionResponseV2(
            identityGenerationId: UUID(),
            endpointId: response.endpointId,
            challengeDigest: response.challengeDigest,
            nonce: response.nonce,
            respondedAt: response.respondedAt,
            kemKeyConfirmation: response.kemKeyConfirmation,
            endpointSignature: response.endpointSignature
        )
        XCTAssertThrowsError(try profile.completeEndpointAdmission(
            wrongGeneration,
            pending: pending,
            at: createdAt.addingTimeInterval(4)
        )) { error in
            XCTAssertEqual(error as? EndpointAdmissionV2Error, .wrongIdentityGeneration)
        }

        var wrongConfirmation = response.kemKeyConfirmation
        wrongConfirmation[0] ^= 0xff
        let wrongKEMSecret = EndpointAdmissionResponseV2(
            identityGenerationId: response.identityGenerationId,
            endpointId: response.endpointId,
            challengeDigest: response.challengeDigest,
            nonce: response.nonce,
            respondedAt: response.respondedAt,
            kemKeyConfirmation: wrongConfirmation,
            endpointSignature: response.endpointSignature
        )
        XCTAssertThrowsError(try profile.completeEndpointAdmission(
            wrongKEMSecret,
            pending: pending,
            at: createdAt.addingTimeInterval(4)
        )) { error in
            XCTAssertEqual(error as? EndpointAdmissionV2Error, .invalidKEMKeyConfirmation)
        }

        var forgedSignature = response.endpointSignature
        forgedSignature[0] ^= 0xff
        let forgedSigningProof = EndpointAdmissionResponseV2(
            identityGenerationId: response.identityGenerationId,
            endpointId: response.endpointId,
            challengeDigest: response.challengeDigest,
            nonce: response.nonce,
            respondedAt: response.respondedAt,
            kemKeyConfirmation: response.kemKeyConfirmation,
            endpointSignature: forgedSignature
        )
        XCTAssertThrowsError(try profile.completeEndpointAdmission(
            forgedSigningProof,
            pending: pending,
            at: createdAt.addingTimeInterval(4)
        )) { error in
            XCTAssertEqual(error as? EndpointAdmissionV2Error, .invalidEndpointSigningProof)
        }
        XCTAssertThrowsError(try profile.completeEndpointAdmission(
            response,
            pending: pending,
            at: pending.challenge.expiresAt
        )) { error in
            XCTAssertEqual(error as? EndpointAdmissionV2Error, .expired)
        }

        try profile.completeEndpointAdmission(
            response,
            pending: pending,
            at: createdAt.addingTimeInterval(4)
        )
        XCTAssertThrowsError(try profile.completeEndpointAdmission(
            response,
            pending: pending,
            at: createdAt.addingTimeInterval(5)
        )) { error in
            XCTAssertEqual(error as? EndpointAdmissionV2Error, .replayed)
        }
        XCTAssertEqual(profile.activeEndpoints.count, 2)
    }

    func testEndpointRemovalRekeysSelfSyncAndReturnsCompleteCleanupPlan() throws {
        let createdAt = Date(timeIntervalSince1970: 5_500)
        let identity = try Identity.generate(displayName: "Endpoint removal rekey")
        var profile = IdentityProfile(
            identity: identity,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: createdAt
        )
        XCTAssertTrue(try profile.migrateToArchitectureV2())
        let endpoint = try LocalInstallationState.generate(
            identityGenerationId: try XCTUnwrap(profile.identityGenerationId),
            createdAt: createdAt.addingTimeInterval(1)
        )
        try admitEndpoint(endpoint, to: &profile, at: createdAt.addingTimeInterval(2))
        let oldSelfSync = try XCTUnwrap(profile.selfSyncV2)

        let result = try XCTUnwrap(profile.removeEndpoint(
            endpoint.id,
            at: createdAt.addingTimeInterval(4)
        ))
        let replacement = try XCTUnwrap(profile.selfSyncV2)
        XCTAssertEqual(replacement.selfSyncEpoch, oldSelfSync.selfSyncEpoch + 1)
        XCTAssertEqual(replacement.previousEpochDigest, oldSelfSync.epochCommitmentDigest)
        XCTAssertNotEqual(replacement.epochKeyData, oldSelfSync.epochKeyData)
        XCTAssertEqual(
            Set(result.cleanupObligations.map(\.kind)),
            Set(EndpointRemovalCleanupKindV2.allCases)
        )
        let journal = try XCTUnwrap(profile.endpointRemovalJournalsV2.first)
        XCTAssertEqual(profile.endpointRemovalJournalsV2.count, 1)
        XCTAssertEqual(journal.result, result)
        XCTAssertEqual(journal.pendingObligations.count, result.cleanupObligations.count)

        let encodedProfile = try NoctweaveCoder.encode(profile, sortedKeys: true)
        var reloaded = try NoctweaveCoder.decode(IdentityProfile.self, from: encodedProfile)
        XCTAssertTrue(reloaded.isArchitectureV2Ready)
        XCTAssertEqual(reloaded.endpointRemovalJournalsV2, profile.endpointRemovalJournalsV2)
        XCTAssertFalse(reloaded.completeEndpointRemovalObligation(
            journalId: UUID(),
            obligationId: result.cleanupObligations[0].id,
            at: createdAt.addingTimeInterval(6)
        ))
        for (offset, obligation) in result.cleanupObligations.enumerated() {
            XCTAssertTrue(reloaded.completeEndpointRemovalObligation(
                journalId: journal.id,
                obligationId: obligation.id,
                at: createdAt.addingTimeInterval(Double(6 + offset))
            ))
        }
        XCTAssertTrue(reloaded.endpointRemovalJournalsV2.isEmpty)
        XCTAssertTrue(reloaded.pendingEndpointRemovalObligationsV2.isEmpty)
        XCTAssertTrue(reloaded.isArchitectureV2Ready)

        var mutableReplacement = replacement
        let localEndpoint = try XCTUnwrap(profile.localInstallation)
        let manifest = try XCTUnwrap(profile.installationManifest)
        let record = try mutableReplacement.sealEvent(
            sourceEndpointId: localEndpoint.id,
            manifestEpoch: manifest.epoch,
            payload: .endpointManifest(manifest),
            sourceSigningKey: localEndpoint.signingKey,
            createdAt: createdAt.addingTimeInterval(5)
        )
        XCTAssertThrowsError(try record.open(epochKeyData: oldSelfSync.epochKeyData))
    }

    func testArchitectureReadinessVerifiesIssuedEndpointAuthorityAndPossession() throws {
        let createdAt = Date(timeIntervalSince1970: 5_800)
        let identity = try Identity.generate(displayName: "Issued endpoint readiness")
        var profile = IdentityProfile(
            identity: identity,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: createdAt
        )
        XCTAssertTrue(try profile.migrateToArchitectureV2())
        let endpoint = try CertifiedInstallationEndpoint.create(
            identity: identity,
            installation: try XCTUnwrap(profile.localInstallation),
            manifest: try XCTUnwrap(profile.installationManifest),
            issuedAt: Date()
        )
        profile.issuedContactEndpointsV2 = [endpoint]
        XCTAssertTrue(profile.isArchitectureV2Ready)

        var forgedAuthority = endpoint.authoritySignature
        forgedAuthority[0] ^= 0xff
        profile.issuedContactEndpointsV2 = [copyEndpoint(
            endpoint,
            authoritySignature: forgedAuthority
        )]
        XCTAssertFalse(profile.isArchitectureV2Ready)

        var forgedPossession = endpoint.possessionSignature
        forgedPossession[0] ^= 0xff
        profile.issuedContactEndpointsV2 = [copyEndpoint(
            endpoint,
            possessionSignature: forgedPossession
        )]
        XCTAssertFalse(profile.isArchitectureV2Ready)
    }

    func testRotationChainsManifestWithoutChangingGeneration() throws {
        let relay = RelayEndpoint(host: "127.0.0.1", port: 9340)
        let originalIdentity = try Identity.generate(displayName: "Generation lifecycle")
        var state = ClientState(
            identity: originalIdentity,
            relay: relay,
            inboxId: InboxAddress.generate()
        )
        XCTAssertTrue(try state.migrateToArchitectureV2())

        let originalGeneration = try XCTUnwrap(state.identityGenerationId)
        let originalInstallation = try XCTUnwrap(state.localInstallation)
        let originalManifest = try XCTUnwrap(state.installationManifest)
        let originalDigest = try XCTUnwrap(originalManifest.digest)

        _ = try state.identity.rotateKeys()
        state.prekeys = try PrekeyState.generate(identity: state.identity)
        try state.resignInstallationManifestAfterIdentityRotation(
            at: originalManifest.issuedAt.addingTimeInterval(1)
        )

        let rotatedManifest = try XCTUnwrap(state.installationManifest)
        XCTAssertEqual(state.identityGenerationId, originalGeneration)
        XCTAssertEqual(state.localInstallation?.id, originalInstallation.id)
        XCTAssertEqual(rotatedManifest.epoch, originalManifest.epoch + 1)
        XCTAssertEqual(rotatedManifest.previousManifestDigest, originalDigest)
        XCTAssertTrue(rotatedManifest.verify(identityPublicKey: state.identity.signingKey.publicKeyData))
        XCTAssertTrue(state.identityProfiles.first?.isArchitectureV2Ready == true)
        XCTAssertThrowsError(try state.resignInstallationManifestAfterIdentityRotation(
            at: originalManifest.issuedAt
        )) { error in
            XCTAssertEqual(error as? IdentityProfileMigrationError, .invalidV2State)
        }

        XCTAssertEqual(state.identityGenerationId, originalGeneration)
        XCTAssertEqual(state.localInstallation?.id, originalInstallation.id)
    }

    private func admitEndpoint(
        _ endpoint: LocalInstallationState,
        to profile: inout IdentityProfile,
        at date: Date,
        endpointExpiresAt: Date? = nil
    ) throws {
        let candidate = EndpointAdmissionCandidateV2(
            endpoint: endpoint,
            expiresAt: endpointExpiresAt
        )
        let nonceByte = UInt8(truncatingIfNeeded: Int(date.timeIntervalSince1970))
        let pending = try profile.prepareEndpointAdmission(
            candidate: candidate,
            issuedAt: date,
            expiresAt: date.addingTimeInterval(30),
            nonce: Data(repeating: nonceByte, count: 32)
        )
        let responseDate = date.addingTimeInterval(0.25)
        let response = try EndpointAdmissionResponseV2.create(
            challenge: pending.challenge,
            endpoint: endpoint,
            identityAuthorityPublicKey: profile.identity.signingKey.publicKeyData,
            respondedAt: responseDate
        )
        try profile.completeEndpointAdmission(
            response,
            pending: pending,
            at: responseDate
        )
    }

    private func copyEndpoint(
        _ endpoint: CertifiedInstallationEndpoint,
        authoritySignature: Data? = nil,
        possessionSignature: Data? = nil
    ) -> CertifiedInstallationEndpoint {
        CertifiedInstallationEndpoint(
            identityGenerationId: endpoint.identityGenerationId,
            identityAuthorityPublicKey: endpoint.identityAuthorityPublicKey,
            manifestEpoch: endpoint.manifestEpoch,
            manifestDigest: endpoint.manifestDigest,
            installationId: endpoint.installationId,
            signingPublicKey: endpoint.signingPublicKey,
            agreementPublicKey: endpoint.agreementPublicKey,
            capabilities: endpoint.capabilities,
            prekeyBundle: endpoint.prekeyBundle,
            prekeyPackageSignature: endpoint.prekeyPackageSignature,
            issuedAt: endpoint.issuedAt,
            authoritySignature: authoritySignature ?? endpoint.authoritySignature,
            possessionSignature: possessionSignature ?? endpoint.possessionSignature
        )
    }
}
