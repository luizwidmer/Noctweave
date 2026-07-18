import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class PairwiseRelationshipQuarantineV2Tests: XCTestCase {
    private let origin = Date(timeIntervalSince1970: 1_725_000_000)

    func testTransportQuarantineUsesStrictPredecodeCoordinates() throws {
        let quarantine = transportQuarantine(
            sequence: 7,
            observedAt: origin,
            innerEnvelopeID: UUID()
        )
        let encoded = try NoctweaveCoder.encode(quarantine, sortedKeys: true)
        XCTAssertEqual(
            try NoctweaveCoder.decode(
                QuarantinedTransportEnvelopeV2.self,
                from: encoded
            ),
            quarantine
        )

        var object = try jsonObject(quarantine)
        object["envelopeCiphertext"] = "forbidden"
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            QuarantinedTransportEnvelopeV2.self,
            from: JSONSerialization.data(withJSONObject: object)
        ))

        object = try jsonObject(quarantine)
        object["recordDigest"] = Data(repeating: 1, count: 31).base64EncodedString()
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            QuarantinedTransportEnvelopeV2.self,
            from: JSONSerialization.data(withJSONObject: object)
        ))
    }

    func testTransportQuarantineIsIdempotentAndEvictsOldestWithoutCapacityFailure() throws {
        var relationship = try makeRelationship()
        for sequence in 1...PairwiseRelationshipV2.maximumTransportQuarantine {
            XCTAssertTrue(try relationship.recordTransportQuarantine(
                transportQuarantine(
                    sequence: UInt64(sequence),
                    observedAt: origin.addingTimeInterval(TimeInterval(sequence))
                )
            ))
        }
        let originalOldest = try XCTUnwrap(relationship.transportQuarantine.first)
        let newest = transportQuarantine(
            sequence: UInt64(PairwiseRelationshipV2.maximumTransportQuarantine + 1),
            observedAt: origin.addingTimeInterval(
                TimeInterval(PairwiseRelationshipV2.maximumTransportQuarantine + 1)
            )
        )
        XCTAssertTrue(try relationship.recordTransportQuarantine(newest))
        XCTAssertEqual(
            relationship.transportQuarantine.count,
            PairwiseRelationshipV2.maximumTransportQuarantine
        )
        XCTAssertFalse(relationship.transportQuarantine.contains {
            $0.packetID == originalOldest.packetID
        })
        XCTAssertEqual(relationship.transportQuarantine.last, newest)

        let retry = transportQuarantine(
            sequence: newest.relaySequence,
            observedAt: newest.observedAt.addingTimeInterval(100)
        )
        XCTAssertFalse(try relationship.recordTransportQuarantine(retry))

        let tooOld = transportQuarantine(
            sequence: UInt64(PairwiseRelationshipV2.maximumTransportQuarantine + 2),
            observedAt: origin.addingTimeInterval(-1)
        )
        XCTAssertFalse(try relationship.recordTransportQuarantine(tooOld))
        XCTAssertEqual(
            relationship.transportQuarantine.count,
            PairwiseRelationshipV2.maximumTransportQuarantine
        )

        let conflicting = QuarantinedTransportEnvelopeV2(
            streamDigest: newest.streamDigest,
            relaySequence: newest.relaySequence,
            packetID: OpaqueRoutePacketIDV2.generate(),
            recordDigest: newest.recordDigest,
            reason: newest.reason,
            observedAt: newest.observedAt
        )
        XCTAssertThrowsError(try relationship.recordTransportQuarantine(conflicting)) {
            XCTAssertEqual($0 as? PairwiseRelationshipV2Error, .conflictingEvent)
        }
        XCTAssertTrue(relationship.isStructurallyValid)
    }

    func testControlQuarantineIsRelationshipScopedBoundedAndPersisted() throws {
        var relationship = try makeRelationship()
        let peer = relationship.peerIdentity.sendRoutes.ownerEndpointHandle
        var firstID: UUID?
        for offset in 0..<PairwiseRelationshipV2.maximumControlQuarantine {
            let quarantine = try controlQuarantine(
                relationship: relationship,
                author: peer,
                createdAt: origin.addingTimeInterval(TimeInterval(offset))
            )
            firstID = firstID ?? quarantine.event.id
            XCTAssertTrue(try relationship.recordControlQuarantine(quarantine))
        }

        let newest = try controlQuarantine(
            relationship: relationship,
            author: peer,
            createdAt: origin.addingTimeInterval(
                TimeInterval(PairwiseRelationshipV2.maximumControlQuarantine)
            )
        )
        XCTAssertTrue(try relationship.recordControlQuarantine(newest))
        XCTAssertEqual(
            relationship.controlQuarantine.count,
            PairwiseRelationshipV2.maximumControlQuarantine
        )
        XCTAssertFalse(relationship.controlQuarantine.contains { $0.event.id == firstID })
        XCTAssertEqual(relationship.controlQuarantine.last, newest)

        let retry = QuarantinedControlEvent(
            event: newest.event,
            receivedAt: newest.receivedAt.addingTimeInterval(10),
            reason: newest.reason
        )
        XCTAssertFalse(try relationship.recordControlQuarantine(retry))

        let wrongAuthor = try controlQuarantine(
            relationship: relationship,
            author: RelationshipEndpointHandle.generate(relationshipId: UUID()),
            createdAt: newest.receivedAt.addingTimeInterval(20)
        )
        XCTAssertThrowsError(try relationship.recordControlQuarantine(wrongAuthor)) {
            XCTAssertEqual($0 as? PairwiseRelationshipV2Error, .wrongRelationship)
        }

        let encoded = try NoctweaveCoder.encode(relationship, sortedKeys: true)
        XCTAssertEqual(
            try NoctweaveCoder.decode(PairwiseRelationshipV2.self, from: encoded),
            relationship
        )
    }

    func testExplicitQuarantineCompactionUsesCanonicalOldestEviction() throws {
        var relationship = try makeRelationship()
        relationship.transportQuarantine = (0...PairwiseRelationshipV2.maximumTransportQuarantine)
            .reversed()
            .map { offset in
                transportQuarantine(
                    sequence: UInt64(offset + 1),
                    observedAt: origin.addingTimeInterval(TimeInterval(offset))
                )
            }
        XCTAssertFalse(relationship.isStructurallyValid)
        try relationship.compactQuarantineState()
        XCTAssertTrue(relationship.isStructurallyValid)
        XCTAssertEqual(
            relationship.transportQuarantine.first?.relaySequence,
            2
        )
        XCTAssertEqual(
            relationship.transportQuarantine.last?.relaySequence,
            UInt64(PairwiseRelationshipV2.maximumTransportQuarantine + 1)
        )
    }

    private func transportQuarantine(
        sequence: UInt64,
        observedAt: Date,
        innerEnvelopeID: UUID? = nil
    ) -> QuarantinedTransportEnvelopeV2 {
        let packetDigest = Data(SHA256.hash(data: Data("packet-\(sequence)".utf8)))
        let recordDigest = Data(SHA256.hash(data: Data("record-\(sequence)".utf8)))
        return QuarantinedTransportEnvelopeV2(
            streamDigest: Data(SHA256.hash(data: Data("relationship-stream".utf8))),
            relaySequence: sequence,
            packetID: OpaqueRoutePacketIDV2(rawValue: packetDigest),
            recordDigest: recordDigest,
            reason: .invalidCiphertext,
            observedAt: observedAt,
            innerEnvelopeID: innerEnvelopeID
        )
    }

    private func controlQuarantine(
        relationship: PairwiseRelationshipV2,
        author: RelationshipEndpointHandle,
        createdAt: Date
    ) throws -> QuarantinedControlEvent {
        QuarantinedControlEvent(
            event: ConversationEvent(
                id: UUID(),
                clientTransactionId: UUID(),
                conversationId: relationship.conversationID,
                authorEndpointHandle: author,
                createdAt: createdAt,
                kind: .control,
                content: EncodedContent(
                    type: ContentTypeId(
                        authority: "org.noctweave.control",
                        name: "future-control",
                        major: 1,
                        minor: 0
                    ),
                    parameters: [:],
                    payload: Data("unsupported control".utf8),
                    fallbackText: nil,
                    disposition: .silent
                )
            ),
            receivedAt: createdAt.addingTimeInterval(1),
            reason: "Unsupported authenticated relationship control"
        )
    }

    private func makeRelationship() throws -> PairwiseRelationshipV2 {
        var offer = try ContactPairingHandshakeV2.makeOffer(
            createdAt: origin,
            expiresAt: origin.addingTimeInterval(300)
        )
        let first = try activateParticipant(name: "A", host: "a.example")
        let second = try activateParticipant(name: "B", host: "b.example")
        var ledger = RendezvousRedemptionLedgerV2()
        return try ContactPairingHandshakeV2.establish(
            pendingOffer: &offer.pending,
            invitation: offer.invitation,
            offerer: first,
            responder: second,
            ledger: &ledger,
            at: origin.addingTimeInterval(1)
        ).offererRelationship
    }

    private func activateParticipant(
        name: String,
        host: String
    ) throws -> PreparedContactParticipantV2 {
        let pending = try PendingContactParticipantV2.prepare(
            relationshipPseudonym: name,
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

    private func jsonObject<T: Encodable>(_ value: T) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: NoctweaveCoder.encode(value, sortedKeys: true)
            ) as? [String: Any]
        )
    }
}
