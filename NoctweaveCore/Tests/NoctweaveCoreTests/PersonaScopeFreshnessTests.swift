import Foundation
import XCTest
@testable import NoctweaveCore

final class PersonaScopeFreshnessTests: XCTestCase {
    private let origin = Date(timeIntervalSince1970: 1_910_000_000)

    func testPersonaRejectsCredentialReuseAcrossGroupsTransactionally() throws {
        let signingKey = try SigningKeyPair.generate()
        let agreementKey = try AgreementKeyPair.generate()
        let memberHandle = GroupScopedMemberHandleV2.generate()
        let credentialHandle = GroupScopedCredentialHandleV2.generate()
        let first = try makeGroupRuntime(
            memberHandle: memberHandle,
            credentialHandle: credentialHandle,
            signingKey: signingKey,
            agreementKey: agreementKey
        )
        let second = try makeGroupRuntime(
            memberHandle: memberHandle,
            credentialHandle: credentialHandle,
            signingKey: signingKey,
            agreementKey: agreementKey
        )
        XCTAssertTrue(first.isStructurallyValid)
        XCTAssertTrue(second.isStructurallyValid)

        var persona = try PersonaProfileV1(displayName: "Local", createdAt: origin)
        try persona.upsert(groupRuntime: first)
        XCTAssertThrowsError(try persona.upsert(groupRuntime: second)) { error in
            XCTAssertEqual(error as? PersonaProfileV1Error, .invalidState)
        }
        XCTAssertEqual(persona.groupRuntimes, [first])
        XCTAssertTrue(persona.isStructurallyValid)
    }

    func testPersonaRejectsGroupKeysReusedFromRelationshipAuthority() throws {
        let relationship = try makeRelationship()
        let authority = relationship.localIdentity.relationshipAuthority
        let runtime = try makeGroupRuntime(
            signingKey: authority.signingKey,
            agreementKey: authority.agreementKey
        )
        XCTAssertTrue(relationship.isStructurallyValid)
        XCTAssertTrue(runtime.isStructurallyValid)

        var persona = try PersonaProfileV1(displayName: "Local", createdAt: origin)
        try persona.upsert(relationship: relationship)
        XCTAssertThrowsError(try persona.upsert(groupRuntime: runtime)) { error in
            XCTAssertEqual(error as? PersonaProfileV1Error, .invalidState)
        }
        XCTAssertTrue(persona.groupRuntimes.isEmpty)
    }

    func testPersonaRejectsGroupHandleReusedFromRelationshipEndpoint() throws {
        let relationship = try makeRelationship()
        let runtime = try makeGroupRuntime(
            memberHandle: GroupScopedMemberHandleV2(
                rawValue: relationship.localEndpointHandle.rawValue
            )
        )
        XCTAssertTrue(runtime.isStructurallyValid)

        var persona = try PersonaProfileV1(displayName: "Local", createdAt: origin)
        try persona.upsert(relationship: relationship)
        XCTAssertThrowsError(try persona.upsert(groupRuntime: runtime)) { error in
            XCTAssertEqual(error as? PersonaProfileV1Error, .invalidState)
        }
        XCTAssertTrue(persona.groupRuntimes.isEmpty)
    }

    func testPersonaRejectsGroupIDReusedFromRelationshipScope() throws {
        let relationship = try makeRelationship()
        let runtime = try makeGroupRuntime(groupId: relationship.id)
        XCTAssertTrue(runtime.isStructurallyValid)

        var persona = try PersonaProfileV1(displayName: "Local", createdAt: origin)
        try persona.upsert(relationship: relationship)
        XCTAssertThrowsError(try persona.upsert(groupRuntime: runtime)) { error in
            XCTAssertEqual(error as? PersonaProfileV1Error, .invalidState)
        }
        XCTAssertTrue(persona.groupRuntimes.isEmpty)
    }

    func testClientStateRejectsRelationshipGroupReuseAcrossPersonas() throws {
        let relationship = try makeRelationship()
        let authority = relationship.localIdentity.relationshipAuthority
        let runtime = try makeGroupRuntime(
            signingKey: authority.signingKey,
            agreementKey: authority.agreementKey
        )

        var state = try ClientState(displayName: "First", createdAt: origin)
        try state.updateActivePersona {
            try $0.upsert(relationship: relationship)
        }
        _ = try state.addPersona(displayName: "Second", createdAt: origin)
        XCTAssertThrowsError(try state.updateActivePersona {
            try $0.upsert(groupRuntime: runtime)
        }) { error in
            XCTAssertEqual(error as? ClientStateError, .invalidState)
        }
        XCTAssertTrue(state.activePersona.groupRuntimes.isEmpty)
        XCTAssertTrue(state.isStructurallyValid)
    }

    func testDistinctRelationshipAndGroupScopesRemainValid() throws {
        let relationship = try makeRelationship()
        let first = try makeGroupRuntime()
        let second = try makeGroupRuntime()
        var persona = try PersonaProfileV1(displayName: "Local", createdAt: origin)

        try persona.upsert(relationship: relationship)
        try persona.upsert(groupRuntime: first)
        try persona.upsert(groupRuntime: second)

        XCTAssertEqual(persona.groupRuntimes.count, 2)
        XCTAssertTrue(persona.isStructurallyValid)
    }

    private func makeGroupRuntime(
        groupId: UUID = UUID(),
        memberHandle: GroupScopedMemberHandleV2 = .generate(),
        credentialHandle: GroupScopedCredentialHandleV2 = .generate(),
        signingKey suppliedSigningKey: SigningKeyPair? = nil,
        agreementKey suppliedAgreementKey: AgreementKeyPair? = nil
    ) throws -> GroupRuntimeRecord {
        let signingKey = try suppliedSigningKey ?? SigningKeyPair.generate()
        let agreementKey = try suppliedAgreementKey ?? AgreementKeyPair.generate()
        let admission = try GroupCredentialAdmissionV2.create(
            groupId: groupId,
            memberHandle: memberHandle,
            credentialHandle: credentialHandle,
            groupSigningKey: signingKey,
            groupAgreementKey: agreementKey,
            issuedAt: origin,
            expiresAt: origin.addingTimeInterval(3_600)
        )
        let leaf = try GroupMemberCredentialV2.fromVerifiedProjection(
            admission,
            addedEpoch: 1
        )
        let credential = LocalGroupCredentialV2(
            groupId: groupId,
            memberHandle: memberHandle,
            credentialHandle: credentialHandle,
            admissionDigest: leaf.admissionDigest,
            signingKey: signingKey,
            agreementKey: agreementKey
        )
        let creator = GroupMemberV2(
            id: memberHandle,
            role: .owner,
            addedEpoch: 1
        )
        let provider = NoctweavePQGroupExperimentalProviderV2()
        let membership = try provider.membership(
            groupId: groupId,
            epoch: 1,
            members: [creator],
            leaves: [leaf]
        )
        let prepared = try provider.prepareGenesis(
            membership: membership,
            localCredential: credential
        )
        let providerDigest = try XCTUnwrap(prepared.providerCommitDigest)
        let signedState = try SignedGroupStateV2.initial(
            groupId: groupId,
            creator: creator,
            creatorAdmission: admission,
            providerGenesisDigest: providerDigest,
            signingKey: signingKey,
            signedAt: origin
        )
        let cryptoState = try provider.finalizePreparedEpoch(
            prepared,
            acceptance: GroupCryptoAcceptedEpochV2(
                proposal: prepared.proposal,
                providerCommitDigest: providerDigest,
                signedCommitDigest: signedState.commitDigest,
                acceptedTranscriptHash: signedState.confirmedTranscriptHash
            )
        )
        return GroupRuntimeRecord(
            groupId: groupId,
            localCredential: credential,
            signedState: signedState,
            cryptoState: cryptoState
        )
    }

    private func makeRelationship() throws -> PairwiseRelationshipV2 {
        let offer = try ContactPairingHandshakeV2.makeOffer(
            createdAt: origin,
            expiresAt: origin.addingTimeInterval(300)
        )
        var pending = offer.pending
        var ledger = RendezvousRedemptionLedgerV2()
        let result = try ContactPairingHandshakeV2.establish(
            pendingOffer: &pending,
            invitation: offer.invitation,
            offerer: try makeParticipant(host: "scope-a.example"),
            responder: try makeParticipant(host: "scope-b.example"),
            ledger: &ledger,
            at: origin.addingTimeInterval(1)
        )
        return result.offererRelationship
    }

    private func makeParticipant(host: String) throws -> PreparedContactParticipantV2 {
        let pending = try PendingContactParticipantV2.prepare(
            relationshipPseudonym: host,
            relay: RelayEndpoint(
                host: host,
                port: 443,
                useTLS: true,
                transport: .websocket
            ),
            createdAt: origin
        )
        let route = try OpaqueReceiveRouteV2.creating(
            from: pending.routeCreateRequest,
            presentedRenewCapability: pending.clientCapabilities.renewCapability,
            existing: nil,
            confidentialTransport: true,
            receivedAt: origin
        )
        return try pending.activate(createdRoute: route)
    }
}
