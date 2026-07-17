import Foundation
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2SelfSyncConvergenceTests: XCTestCase {
    func testConsentAndPreferenceConvergeIndependentOfArrivalOrder() throws {
        let fixture = try makeFixture()
        var sourceA = fixture.localState
        var sourceB = fixture.localState
        var receiver = fixture.localState
        let relationshipId = UUID()

        let consentA = try emit(
            .consent(
                SelfSyncConsentUpdateV2(
                    relationshipId: relationshipId,
                    revision: 7,
                    state: .allowed,
                    updatedAt: fixture.createdAt.addingTimeInterval(10)
                )
            ),
            source: fixture.sourceA,
            sender: &sourceA,
            receiver: &receiver,
            fixture: fixture,
            at: fixture.createdAt.addingTimeInterval(10)
        ).result
        let preferenceA = try emit(
            .preference(
                SelfSyncPreferenceUpdateV2(
                    key: "notifications.enabled",
                    revision: 4,
                    value: .boolean(true),
                    updatedAt: fixture.createdAt.addingTimeInterval(11)
                )
            ),
            source: fixture.sourceA,
            sender: &sourceA,
            receiver: &receiver,
            fixture: fixture,
            at: fixture.createdAt.addingTimeInterval(11)
        ).result
        let consentB = try emit(
            .consent(
                SelfSyncConsentUpdateV2(
                    relationshipId: relationshipId,
                    revision: 7,
                    state: .blocked,
                    updatedAt: fixture.createdAt.addingTimeInterval(100)
                )
            ),
            source: fixture.sourceB,
            sender: &sourceB,
            receiver: &receiver,
            fixture: fixture,
            at: fixture.createdAt.addingTimeInterval(12)
        ).result
        let preferenceB = try emit(
            .preference(
                SelfSyncPreferenceUpdateV2(
                    key: "notifications.enabled",
                    revision: 4,
                    value: .boolean(false),
                    updatedAt: fixture.createdAt.addingTimeInterval(101)
                )
            ),
            source: fixture.sourceB,
            sender: &sourceB,
            receiver: &receiver,
            fixture: fixture,
            at: fixture.createdAt.addingTimeInterval(13)
        ).result

        var forward = SelfSyncConvergenceProjectionV2(
            identityGenerationId: fixture.generationId
        )
        for result in [consentA, consentB, preferenceA, preferenceB] {
            try forward.apply(result)
        }
        var reverse = SelfSyncConvergenceProjectionV2(
            identityGenerationId: fixture.generationId
        )
        for result in [preferenceB, preferenceA, consentB, consentA] {
            try reverse.apply(result)
        }

        XCTAssertEqual(forward, reverse)
        XCTAssertEqual(forward.consentStates.count, 1)
        XCTAssertEqual(forward.preferences.count, 1)

        let higherRevision = try emit(
            .preference(
                SelfSyncPreferenceUpdateV2(
                    key: "notifications.enabled",
                    revision: 5,
                    value: .string("revision-wins"),
                    updatedAt: fixture.createdAt.addingTimeInterval(1)
                )
            ),
            source: fixture.sourceA,
            sender: &sourceA,
            receiver: &receiver,
            fixture: fixture,
            at: fixture.createdAt.addingTimeInterval(14)
        ).result
        XCTAssertEqual(try forward.apply(higherRevision), .projectionChanged)
        XCTAssertEqual(forward.preferences[0].update.revision, 5)
        XCTAssertEqual(forward.preferences[0].update.value, .string("revision-wins"))
    }

    func testReadMarkersUseMaximumLogicalPositionAndStableTieBreak() throws {
        let fixture = try makeFixture()
        var sourceA = fixture.localState
        var sourceB = fixture.localState
        var receiver = fixture.localState
        let relationshipId = UUID()

        let tiedA = try emit(
            .readMarker(
                SelfSyncReadMarkerV2(
                    relationshipId: relationshipId,
                    logicalPosition: 20,
                    throughEventId: UUID(),
                    updatedAt: fixture.createdAt.addingTimeInterval(20)
                )
            ),
            source: fixture.sourceA,
            sender: &sourceA,
            receiver: &receiver,
            fixture: fixture,
            at: fixture.createdAt.addingTimeInterval(20)
        ).result
        let tiedB = try emit(
            .readMarker(
                SelfSyncReadMarkerV2(
                    relationshipId: relationshipId,
                    logicalPosition: 20,
                    throughEventId: UUID(),
                    updatedAt: fixture.createdAt.addingTimeInterval(200)
                )
            ),
            source: fixture.sourceB,
            sender: &sourceB,
            receiver: &receiver,
            fixture: fixture,
            at: fixture.createdAt.addingTimeInterval(21)
        ).result
        let advanced = try emit(
            .readMarker(
                SelfSyncReadMarkerV2(
                    relationshipId: relationshipId,
                    logicalPosition: 21,
                    throughEventId: UUID(),
                    updatedAt: fixture.createdAt.addingTimeInterval(2)
                )
            ),
            source: fixture.sourceA,
            sender: &sourceA,
            receiver: &receiver,
            fixture: fixture,
            at: fixture.createdAt.addingTimeInterval(22)
        ).result

        var first = SelfSyncConvergenceProjectionV2(
            identityGenerationId: fixture.generationId
        )
        try first.apply(tiedA)
        try first.apply(tiedB)
        var second = SelfSyncConvergenceProjectionV2(
            identityGenerationId: fixture.generationId
        )
        try second.apply(tiedB)
        try second.apply(tiedA)
        XCTAssertEqual(first, second)

        XCTAssertEqual(try first.apply(advanced), .projectionChanged)
        XCTAssertEqual(try first.apply(tiedB), .projectionUnchanged)
        XCTAssertEqual(first.readMarkers[0].marker.logicalPosition, 21)
    }

    func testReplayIsIdempotentAndSecurityStateRequiresExternalHandling() throws {
        let fixture = try makeFixture()
        var sender = fixture.localState
        var receiver = fixture.localState
        var projection = SelfSyncConvergenceProjectionV2(
            identityGenerationId: fixture.generationId
        )
        let emitted = try emit(
            .consent(
                SelfSyncConsentUpdateV2(
                    relationshipId: UUID(),
                    revision: 1,
                    state: .requests,
                    updatedAt: fixture.createdAt.addingTimeInterval(1)
                )
            ),
            source: fixture.sourceA,
            sender: &sender,
            receiver: &receiver,
            fixture: fixture,
            at: fixture.createdAt.addingTimeInterval(1)
        )
        XCTAssertEqual(try projection.apply(emitted.result), .projectionChanged)
        let beforeReplay = projection
        let duplicate = try receiver.openAndAdvance(
            emitted.sealed,
            manifest: fixture.manifest,
            identityPublicKey: fixture.identity.signingKey.publicKeyData
        )
        XCTAssertEqual(duplicate.sourceResult, .exactDuplicate)
        XCTAssertEqual(try projection.apply(duplicate), .exactDuplicate)
        XCTAssertEqual(projection, beforeReplay)

        let external = try emit(
            .endpointSetManifest(fixture.manifest),
            source: fixture.sourceA,
            sender: &sender,
            receiver: &receiver,
            fixture: fixture,
            at: fixture.createdAt.addingTimeInterval(2)
        ).result
        XCTAssertEqual(
            try projection.apply(external),
            .requiresExternalHandling(.endpointSetManifest(fixture.manifest))
        )
        XCTAssertEqual(projection, beforeReplay)

        var wrongGeneration = SelfSyncConvergenceProjectionV2(
            identityGenerationId: UUID()
        )
        XCTAssertThrowsError(try wrongGeneration.apply(emitted.result)) { error in
            XCTAssertEqual(error as? SelfSyncConvergenceV2Error, .wrongGeneration)
        }
    }

    func testCapacityRejectsWithoutEvictionAndProjectionRoundTrips() throws {
        let generationId = UUID()
        let stamp = SelfSyncConvergenceStampV2(
            sourceOrderKey: Data(repeating: 0x11, count: 32),
            recordDigest: Data(repeating: 0x22, count: 32)
        )
        let preferences = (0..<NoctweaveSelfSyncConvergenceV2.maximumPreferences).map {
            SelfSyncConvergedPreferenceV2(
                update: SelfSyncPreferenceUpdateV2(
                    key: String(format: "preference.%04d", $0),
                    revision: 1,
                    value: .integer(Int64($0)),
                    updatedAt: Date(timeIntervalSince1970: 1_000)
                ),
                stamp: stamp
            )
        }
        var projection = try SelfSyncConvergenceProjectionV2(
            identityGenerationId: generationId,
            consentStates: [],
            readMarkers: [],
            preferences: preferences
        )
        let roundTrip = try NoctweaveCoder.decode(
            SelfSyncConvergenceProjectionV2.self,
            from: NoctweaveCoder.encode(projection, sortedKeys: true)
        )
        XCTAssertEqual(roundTrip, projection)

        let fixture = try makeFixture(generationId: generationId)
        var sender = fixture.localState
        var receiver = fixture.localState
        let overflow = try emit(
            .preference(
                SelfSyncPreferenceUpdateV2(
                    key: "preference.overflow",
                    revision: 1,
                    value: .boolean(true),
                    updatedAt: fixture.createdAt.addingTimeInterval(1)
                )
            ),
            source: fixture.sourceA,
            sender: &sender,
            receiver: &receiver,
            fixture: fixture,
            at: fixture.createdAt.addingTimeInterval(1)
        ).result
        let beforeOverflow = projection
        XCTAssertThrowsError(try projection.apply(overflow)) { error in
            XCTAssertEqual(error as? SelfSyncConvergenceV2Error, .capacityReached)
        }
        XCTAssertEqual(projection, beforeOverflow)
    }

    private typealias Fixture = (
        identity: Identity,
        generationId: UUID,
        sourceA: LocalEndpointState,
        sourceB: LocalEndpointState,
        manifest: EndpointSetManifest,
        localState: SelfSyncLocalStateV2,
        createdAt: Date
    )

    private func makeFixture(generationId: UUID = UUID()) throws -> Fixture {
        let createdAt = Date(timeIntervalSince1970: 10_000)
        let identity = try Identity.generate(displayName: "Self-sync convergence")
        let sourceA = try LocalEndpointState.generate(
            identityGenerationId: generationId,
            createdAt: createdAt
        )
        let sourceB = try LocalEndpointState.generate(
            identityGenerationId: generationId,
            createdAt: createdAt
        )
        let manifest = try EndpointSetManifest.create(
            identityGenerationId: generationId,
            epoch: 0,
            endpoints: [
                sourceA.publicRecord(addedEpoch: 0),
                sourceB.publicRecord(addedEpoch: 0)
            ],
            identity: identity,
            issuedAt: createdAt
        )
        let localState = SelfSyncLocalStateV2(
            identityGenerationId: generationId,
            epochKeyData: Data(repeating: 0xA5, count: 32)
        )
        return (
            identity,
            generationId,
            sourceA,
            sourceB,
            manifest,
            localState,
            createdAt
        )
    }

    private func emit(
        _ payload: TypedSelfSyncPayloadV2,
        source: LocalEndpointState,
        sender: inout SelfSyncLocalStateV2,
        receiver: inout SelfSyncLocalStateV2,
        fixture: Fixture,
        at: Date
    ) throws -> (sealed: SealedSelfSyncRecordV2, result: SelfSyncReceiveResultV2) {
        let sealed = try sender.sealEvent(
            sourceEndpointId: source.id,
            manifestEpoch: fixture.manifest.epoch,
            payload: payload,
            sourceSigningKey: source.signingKey,
            createdAt: at
        )
        return (
            sealed,
            try receiver.openAndAdvance(
                sealed,
                manifest: fixture.manifest,
                identityPublicKey: fixture.identity.signingKey.publicKeyData
            )
        )
    }
}
