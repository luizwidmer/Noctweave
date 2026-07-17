import XCTest
import CryptoKit
@testable import NoctweaveCore

final class ArchitectureV2IdentityTests: XCTestCase {
    func testFreshProfileIsCreatedCompleteWithoutMigration() throws {
        let identity = try Identity.generate(displayName: "Current baseline")
        let profile = try makeCurrentIdentityProfile(
            identity: identity,
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: Date(timeIntervalSince1970: 1_000)
        )

        XCTAssertTrue(profile.isArchitectureV2Ready)
        XCTAssertEqual(profile.architectureVersion, 2)
        let accessKey = try XCTUnwrap(profile.inboxAccessKey)
        XCTAssertTrue(InboxAddress.isBound(profile.inboxId, to: accessKey.publicKeyData))
        XCTAssertNotEqual(
            profile.localEndpoint?.signingKey.publicKeyData,
            identity.signingKey.publicKeyData
        )
        XCTAssertNotEqual(
            profile.localEndpoint?.agreementKey.publicKeyData,
            identity.agreementKey.publicKeyData
        )
        XCTAssertEqual(profile.endpointSetManifest?.activeEndpoints.count, 1)
    }

    func testClientStateDecoderRejectsOldOrMissingBaselineFields() throws {
        let identity = try Identity.generate(displayName: "Strict state")
        let state = try makeCurrentClientState(
            identity: identity,
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340)
        )
        let encoded = try NoctweaveCoder.encode(state)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])

        object["schemaVersion"] = 1
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                ClientState.self,
                from: JSONSerialization.data(withJSONObject: object)
            )
        )

        object["schemaVersion"] = NoctweaveArchitectureV2.version
        var profiles = try XCTUnwrap(object["identityProfiles"] as? [[String: Any]])
        profiles[0].removeValue(forKey: "selfSyncV2")
        object["identityProfiles"] = profiles
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                ClientState.self,
                from: JSONSerialization.data(withJSONObject: object)
            )
        )
    }

    func testRelationshipEndpointHandleMatchesJavaScriptVector() throws {
        let handle = RelationshipEndpointHandle.generate(
            identityGenerationId: try XCTUnwrap(UUID(uuidString: "25D6B258-9C3D-43B9-A6AB-F654B3089B4B")),
            endpointId: try XCTUnwrap(UUID(uuidString: "A12AA310-613D-4F86-8F45-28DC0D410F9F")),
            relationshipId: try XCTUnwrap(UUID(uuidString: "4A2D4951-C0CA-4B9D-94A4-2DC80B4AE8E0")),
            nonce: try XCTUnwrap(UUID(uuidString: "E141680A-06A0-4E36-B2D7-5AE72B6013CD"))
        )
        XCTAssertEqual(handle.rawValue, "03kx4/LQ+FBjGnQG/B/NTnX7Sj13lp5+O9NUKj2/ZBk=")
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

    func testEndpointSetManifestRejectsInvalidHistoryAndFutureEndpointEpochs() throws {
        let issuedAt = Date(timeIntervalSince1970: 2_000)
        let identity = try Identity.generate(displayName: "Manifest invariants")
        let generationId = UUID()
        let endpoint = try LocalEndpointState.generate(
            identityGenerationId: generationId,
            createdAt: issuedAt
        )
        let record = endpoint.publicRecord(addedEpoch: 0)

        let rootWithParent = try EndpointSetManifest.create(
            identityGenerationId: generationId,
            epoch: 0,
            previousManifestDigest: Data(repeating: 1, count: 32),
            endpoints: [record],
            identity: identity,
            issuedAt: issuedAt
        )
        XCTAssertFalse(rootWithParent.isStructurallyValid)
        XCTAssertFalse(rootWithParent.verify(identityPublicKey: identity.signingKey.publicKeyData))

        let updateWithoutParent = try EndpointSetManifest.create(
            identityGenerationId: generationId,
            epoch: 1,
            endpoints: [record],
            identity: identity,
            issuedAt: issuedAt
        )
        XCTAssertFalse(updateWithoutParent.isStructurallyValid)

        let futureRecord = EndpointRecord(
            id: record.id,
            identityGenerationId: generationId,
            signingPublicKey: record.signingPublicKey,
            agreementPublicKey: record.agreementPublicKey,
            capabilities: record.capabilities,
            addedEpoch: 2,
            addedAt: issuedAt
        )
        let futureAdd = try EndpointSetManifest.create(
            identityGenerationId: generationId,
            epoch: 1,
            previousManifestDigest: Data(repeating: 2, count: 32),
            endpoints: [futureRecord],
            identity: identity,
            issuedAt: issuedAt
        )
        XCTAssertFalse(futureAdd.isStructurallyValid)

        let futureRevocation = try XCTUnwrap(record.revoked(epoch: 2, at: issuedAt))
        let futureRevoke = try EndpointSetManifest.create(
            identityGenerationId: generationId,
            epoch: 1,
            previousManifestDigest: Data(repeating: 3, count: 32),
            endpoints: [futureRevocation],
            identity: identity,
            issuedAt: issuedAt
        )
        XCTAssertFalse(futureRevoke.isStructurallyValid)
    }

    func testArchitectureReadinessBindsLocalEndpointKeysToManifestRecord() throws {
        let identity = try Identity.generate(displayName: "Endpoint binding")
        var profile = try makeCurrentIdentityProfile(
            identity: identity,
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity)
        )
        XCTAssertTrue(profile.isArchitectureV2Ready)

        let original = try XCTUnwrap(profile.localEndpoint)
        profile.localEndpoint = try LocalEndpointState.generate(
            identityGenerationId: original.identityGenerationId,
            id: original.id,
            createdAt: original.createdAt
        )
        XCTAssertFalse(profile.isArchitectureV2Ready)
    }

    func testArchitectureReadinessRejectsReusedOrUnscopedInboxReachability() throws {
        let identity = try Identity.generate(displayName: "Reachability binding")
        let relay = RelayEndpoint(host: "127.0.0.1", port: 9340)
        var profile = try makeCurrentIdentityProfile(
            identity: identity,
            relay: relay,
            prekeys: try PrekeyState.generate(identity: identity)
        )
        XCTAssertTrue(profile.isArchitectureV2Ready)

        let originalInboxId = profile.inboxId
        let originalAccessKey = try XCTUnwrap(profile.inboxAccessKey)
        profile.inboxAccessKey = try SigningKeyPair.generate()
        XCTAssertFalse(profile.isArchitectureV2Ready)

        profile.inboxAccessKey = originalAccessKey
        profile.inboxId = InboxAddress.generate()
        XCTAssertFalse(profile.isArchitectureV2Ready)

        profile.inboxId = originalInboxId
        var endpoint = try XCTUnwrap(profile.localEndpoint)
        let routeKey = MailboxRouteCredentialV2.routeIdentifier(
            relay: relay,
            inboxId: originalInboxId
        )
        let unscoped = try MailboxRouteCredentialV2.generate()
        endpoint.mailboxCredentialsByRoute[routeKey] = unscoped
        profile.localEndpoint = endpoint
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
        profile.localEndpoint = endpoint
        XCTAssertFalse(profile.isArchitectureV2Ready)
    }

    func testMailboxCredentialsUseFreshKeysPerRoute() throws {
        let createdAt = Date(timeIntervalSince1970: 1_500)
        var endpoint = try LocalEndpointState.generate(
            identityGenerationId: UUID(),
            createdAt: createdAt
        )
        let firstRoute = try endpoint.ensureMailboxCredential(
            for: "first-route",
            at: createdAt.addingTimeInterval(1)
        )
        let secondRoute = try endpoint.ensureMailboxCredential(
            for: "second-route",
            at: createdAt.addingTimeInterval(2)
        )

        XCTAssertNotEqual(
            firstRoute.signingKey.publicKeyData,
            endpoint.signingKey.publicKeyData
        )
        XCTAssertNotEqual(
            firstRoute.signingKey.publicKeyData,
            secondRoute.signingKey.publicKeyData
        )
        XCTAssertTrue(endpoint.mailboxStateIsStructurallyValid)

        let decoded = try NoctweaveCoder.decode(
            LocalEndpointState.self,
            from: NoctweaveCoder.encode(endpoint, sortedKeys: true)
        )
        XCTAssertEqual(
            decoded.mailboxCredentialsByRoute,
            endpoint.mailboxCredentialsByRoute
        )
    }

    func testProfileAdmitsAndRemovesIndependentEndpointWithProofsAndHashChain() throws {
        let createdAt = Date(timeIntervalSince1970: 3_000)
        let identity = try Identity.generate(displayName: "Endpoint lifecycle")
        var profile = try makeCurrentIdentityProfile(
            identity: identity,
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: createdAt
        )
        let root = try XCTUnwrap(profile.endpointSetManifest)
        let rootDigest = try XCTUnwrap(root.digest)
        let remote = try LocalEndpointState.generate(
            identityGenerationId: try XCTUnwrap(profile.identityGenerationId),
            createdAt: createdAt.addingTimeInterval(1)
        )
        try admitEndpoint(
            remote,
            to: &profile,
            at: createdAt.addingTimeInterval(2)
        )
        let authorized = try XCTUnwrap(profile.endpointSetManifest)
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

        let localEndpointId = try XCTUnwrap(profile.localEndpoint?.id)
        XCTAssertNil(try profile.removeEndpoint(
            localEndpointId,
            at: createdAt.addingTimeInterval(3)
        ))
        let removal = try XCTUnwrap(profile.removeEndpoint(
            remote.id,
            at: createdAt.addingTimeInterval(3)
        ))
        XCTAssertTrue(removal.isStructurallyValid)
        XCTAssertTrue(removal.requiresExternalCleanup)
        XCTAssertFalse(removal.authorizesFutureParticipation)
        let revoked = try XCTUnwrap(profile.endpointSetManifest)
        XCTAssertEqual(revoked.epoch, 2)
        XCTAssertEqual(revoked.previousManifestDigest, authorized.digest)
        XCTAssertEqual(profile.activeEndpoints.map(\.id), [localEndpointId])
        XCTAssertTrue(profile.isArchitectureV2Ready)
        XCTAssertNil(try profile.removeEndpoint(
            remote.id,
            at: createdAt.addingTimeInterval(4)
        ))
    }

    func testRevokedEndpointsAreCheckpointedSoDeviceChurnDoesNotExhaustManifest() throws {
        let createdAt = Date(timeIntervalSince1970: 4_000)
        let identity = try Identity.generate(displayName: "Endpoint churn")
        var profile = try makeCurrentIdentityProfile(
            identity: identity,
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: createdAt
        )

        for replacement in 0..<(NoctweaveArchitectureV2.maximumEndpoints * 2) {
            let manifest = try XCTUnwrap(profile.endpointSetManifest)
            let endpoint = try LocalEndpointState.generate(
                identityGenerationId: try XCTUnwrap(profile.identityGenerationId),
                createdAt: createdAt.addingTimeInterval(Double(replacement * 2 + 1))
            )
            let additionDate = createdAt.addingTimeInterval(Double(replacement * 2 + 1))
            let revocationDate = createdAt.addingTimeInterval(Double(replacement * 2 + 2))

            XCTAssertEqual(manifest.epoch, UInt64(replacement * 2))
            try admitEndpoint(endpoint, to: &profile, at: additionDate)
            XCTAssertEqual(profile.endpointSetManifest?.endpoints.count, 2)
            XCTAssertNotNil(try profile.removeEndpoint(endpoint.id, at: revocationDate))
            XCTAssertEqual(profile.activeEndpoints.count, 1)
            XCTAssertTrue(profile.isArchitectureV2Ready)
        }

        XCTAssertEqual(profile.endpointSetManifest?.endpoints.count, 2)
        XCTAssertEqual(
            profile.endpointSetManifest?.epoch,
            UInt64(NoctweaveArchitectureV2.maximumEndpoints * 4)
        )
    }

    func testExpiredEndpointsAreCheckpointedSoTheyCannotExhaustManifest() throws {
        let createdAt = Date(timeIntervalSince1970: 4_500)
        let identity = try Identity.generate(displayName: "Expiring endpoint churn")
        var profile = try makeCurrentIdentityProfile(
            identity: identity,
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: createdAt
        )
        let expiresAt = createdAt.addingTimeInterval(100)

        for index in 1..<NoctweaveArchitectureV2.maximumEndpoints {
            let manifest = try XCTUnwrap(profile.endpointSetManifest)
            let endpoint = try LocalEndpointState.generate(
                identityGenerationId: try XCTUnwrap(profile.identityGenerationId),
                createdAt: createdAt.addingTimeInterval(Double(index))
            )
            XCTAssertEqual(manifest.epoch, UInt64(index - 1))
            try admitEndpoint(
                endpoint,
                to: &profile,
                at: createdAt.addingTimeInterval(Double(index)),
                endpointExpiresAt: expiresAt
            )
        }
        XCTAssertEqual(
            profile.endpointSetManifest?.endpoints.count,
            NoctweaveArchitectureV2.maximumEndpoints
        )

        let fullManifestDigest = try XCTUnwrap(profile.endpointSetManifest?.digest)
        let replacement = try LocalEndpointState.generate(
            identityGenerationId: try XCTUnwrap(profile.identityGenerationId),
            createdAt: expiresAt.addingTimeInterval(1)
        )
        try admitEndpoint(
            replacement,
            to: &profile,
            at: expiresAt.addingTimeInterval(1)
        )

        let checkpoint = try XCTUnwrap(profile.endpointSetManifest)
        XCTAssertEqual(checkpoint.previousManifestDigest, fullManifestDigest)
        XCTAssertEqual(checkpoint.endpoints.count, 2)
        XCTAssertTrue(checkpoint.endpoints.contains(where: { $0.id == replacement.id }))
        XCTAssertTrue(profile.isArchitectureV2Ready)
    }

    func testEndpointAdmissionRejectsExpiryReplayWrongGenerationAndForgedProofs() throws {
        let createdAt = Date(timeIntervalSince1970: 5_000)
        let identity = try Identity.generate(displayName: "Endpoint admission proofs")
        var profile = try makeCurrentIdentityProfile(
            identity: identity,
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: createdAt
        )
        let endpoint = try LocalEndpointState.generate(
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
        var profile = try makeCurrentIdentityProfile(
            identity: identity,
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: createdAt
        )
        let endpoint = try LocalEndpointState.generate(
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
        let localEndpoint = try XCTUnwrap(profile.localEndpoint)
        let manifest = try XCTUnwrap(profile.endpointSetManifest)
        let record = try mutableReplacement.sealEvent(
            sourceEndpointId: localEndpoint.id,
            manifestEpoch: manifest.epoch,
            payload: .endpointSetManifest(manifest),
            sourceSigningKey: localEndpoint.signingKey,
            createdAt: createdAt.addingTimeInterval(5)
        )
        XCTAssertThrowsError(try record.open(epochKeyData: oldSelfSync.epochKeyData))
    }

    func testArchitectureReadinessVerifiesIssuedEndpointAuthorityAndPossession() throws {
        let createdAt = Date(timeIntervalSince1970: 5_800)
        let identity = try Identity.generate(displayName: "Issued endpoint readiness")
        var profile = try makeCurrentIdentityProfile(
            identity: identity,
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: createdAt
        )
        let endpoint = try CertifiedGenerationEndpoint.create(
            identity: identity,
            endpoint: try XCTUnwrap(profile.localEndpoint),
            manifest: try XCTUnwrap(profile.endpointSetManifest),
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
        var state = try makeCurrentClientState(identity: originalIdentity, relay: relay)

        let originalGeneration = try XCTUnwrap(state.identityGenerationId)
        let originalEndpoint = try XCTUnwrap(state.localEndpoint)
        let originalManifest = try XCTUnwrap(state.endpointSetManifest)
        let originalDigest = try XCTUnwrap(originalManifest.digest)

        _ = try state.identity.rotateKeys()
        state.prekeys = try PrekeyState.generate(identity: state.identity)
        try state.resignEndpointSetManifestAfterIdentityRotation(
            at: originalManifest.issuedAt.addingTimeInterval(1)
        )

        let rotatedManifest = try XCTUnwrap(state.endpointSetManifest)
        XCTAssertEqual(state.identityGenerationId, originalGeneration)
        XCTAssertEqual(state.localEndpoint?.id, originalEndpoint.id)
        XCTAssertEqual(rotatedManifest.epoch, originalManifest.epoch + 1)
        XCTAssertEqual(rotatedManifest.previousManifestDigest, originalDigest)
        XCTAssertTrue(rotatedManifest.verify(identityPublicKey: state.identity.signingKey.publicKeyData))
        XCTAssertTrue(state.identityProfiles.first?.isArchitectureV2Ready == true)
        XCTAssertThrowsError(try state.resignEndpointSetManifestAfterIdentityRotation(
            at: originalManifest.issuedAt
        )) { error in
            XCTAssertEqual(error as? IdentityProfileStateError, .invalidCurrentState)
        }

        XCTAssertEqual(state.identityGenerationId, originalGeneration)
        XCTAssertEqual(state.localEndpoint?.id, originalEndpoint.id)
    }

    private func admitEndpoint(
        _ endpoint: LocalEndpointState,
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
        _ endpoint: CertifiedGenerationEndpoint,
        authoritySignature: Data? = nil,
        possessionSignature: Data? = nil
    ) -> CertifiedGenerationEndpoint {
        CertifiedGenerationEndpoint(
            identityGenerationId: endpoint.identityGenerationId,
            identityAuthorityPublicKey: endpoint.identityAuthorityPublicKey,
            manifestEpoch: endpoint.manifestEpoch,
            manifestDigest: endpoint.manifestDigest,
            endpointId: endpoint.endpointId,
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
