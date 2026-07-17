import Foundation
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2RendezvousTests: XCTestCase {
    func testPublicOfferIsPrivacyBoundedAndOnlyContactPairingIsEnabled() throws {
        let createdAt = Date(timeIntervalSince1970: 10_000)
        let capability = try RendezvousTransportCapabilityV2.generate(
            expiresAt: createdAt.addingTimeInterval(300)
        )
        let pending = try PendingRendezvousOfferV2.create(
            transportCapability: capability,
            createdAt: createdAt
        )
        let secret = try pending.redemptionSecret()

        XCTAssertTrue(pending.offer.isStructurallyValid)
        XCTAssertTrue(
            pending.offer.isUsable(
                at: createdAt.addingTimeInterval(299),
                for: .contactPairing
            )
        )
        XCTAssertFalse(
            pending.offer.isUsable(
                at: createdAt.addingTimeInterval(299),
                for: .endpointAdmission
            )
        )

        let encoded = try NoctweaveCoder.encode(pending.offer, sortedKeys: true)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertEqual(
            Set(object.keys),
            Set([
                "version",
                "purpose",
                "transportCapability",
                "oneTimeTokenDigest",
                "ephemeralAgreementPublicKey",
                "createdAt",
                "expiresAt",
                "limits"
            ])
        )
        let encodedCapability = try XCTUnwrap(object["transportCapability"] as? [String: Any])
        XCTAssertEqual(Set(encodedCapability.keys), Set(["opaqueValue", "expiresAt"]))
        XCTAssertNil(object["oneTimeToken"])
        XCTAssertFalse(
            try XCTUnwrap(String(data: encoded, encoding: .utf8))
                .contains(secret.oneTimeToken.base64EncodedString())
        )

        for disabledPurpose in [
            RendezvousPurposeV2.endpointAdmission,
            .routeRollover,
            .groupInvitation,
            .historyTransfer
        ] {
            XCTAssertThrowsError(
                try PendingRendezvousOfferV2.create(
                    purpose: disabledPurpose,
                    transportCapability: capability,
                    createdAt: createdAt
                )
            ) { error in
                XCTAssertEqual(error as? RendezvousV2Error, .purposeDisabled)
            }
        }
    }

    func testRealMLKEMHandshakeDerivesMatchingTranscriptBoundSessions() throws {
        let createdAt = Date(timeIntervalSince1970: 20_000)
        var pending = try makePending(createdAt: createdAt)
        let secret = try pending.redemptionSecret()
        let responder = try RendezvousResponderV2.createOpen(
            for: pending.offer,
            redemptionSecret: secret,
            at: createdAt.addingTimeInterval(1)
        )
        var ledger = RendezvousRedemptionLedgerV2()
        var offererSession = try pending.accept(
            responder.request,
            ledger: &ledger,
            at: createdAt.addingTimeInterval(1)
        )
        var responderSession = responder.session

        XCTAssertEqual(offererSession.sessionId, responderSession.sessionId)
        XCTAssertEqual(offererSession.transcriptDigest, responderSession.transcriptDigest)
        XCTAssertEqual(ledger.redemptionCount, 1)

        let contactPayload = Data("one-time contact material".utf8)
        let offerFrame = try responderSession.seal(
            contactPayload,
            kind: .contactOffer,
            at: createdAt.addingTimeInterval(2)
        )
        XCTAssertTrue(offerFrame.isStructurallyValid)
        XCTAssertTrue(
            NoctweaveRendezvousV2.paddingBuckets.contains(offerFrame.payload.ciphertext.count)
        )
        XCTAssertEqual(
            try offererSession.open(offerFrame, at: createdAt.addingTimeInterval(2)),
            contactPayload
        )

        let acknowledgement = Data("accepted".utf8)
        let acknowledgementFrame = try offererSession.seal(
            acknowledgement,
            kind: .contactAcceptance,
            at: createdAt.addingTimeInterval(3)
        )
        XCTAssertEqual(
            try responderSession.open(
                acknowledgementFrame,
                at: createdAt.addingTimeInterval(3)
            ),
            acknowledgement
        )
    }

    func testWrongPurposeAndOfferTranscriptTamperFailClosed() throws {
        let createdAt = Date(timeIntervalSince1970: 30_000)
        var pending = try makePending(createdAt: createdAt)
        let secret = try pending.redemptionSecret()

        XCTAssertThrowsError(
            try RendezvousResponderV2.createOpen(
                for: pending.offer,
                redemptionSecret: secret,
                expectedPurpose: .endpointAdmission,
                at: createdAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? RendezvousV2Error, .wrongPurpose)
        }

        let tamperedLimits = try RendezvousLimitsV2(
            maximumFrames: pending.offer.limits.maximumFrames - 1,
            maximumFramePlaintextBytes: pending.offer.limits.maximumFramePlaintextBytes
        )
        let tamperedOffer = try RendezvousOfferV2(
            purpose: pending.offer.purpose,
            transportCapability: pending.offer.transportCapability,
            oneTimeTokenDigest: pending.offer.oneTimeTokenDigest,
            ephemeralAgreementPublicKey: pending.offer.ephemeralAgreementPublicKey,
            createdAt: pending.offer.createdAt,
            expiresAt: pending.offer.expiresAt,
            limits: tamperedLimits
        )
        let tamperedResponder = try RendezvousResponderV2.createOpen(
            for: tamperedOffer,
            redemptionSecret: secret,
            at: createdAt.addingTimeInterval(1)
        )
        var ledger = RendezvousRedemptionLedgerV2()
        XCTAssertThrowsError(
            try pending.accept(
                tamperedResponder.request,
                ledger: &ledger,
                at: createdAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? RendezvousV2Error, .invalidOpen)
        }
        XCTAssertEqual(ledger.redemptionCount, 0)
        XCTAssertFalse(pending.isRedeemed)
    }

    func testExpiryIsExclusiveAtTheDeadline() throws {
        let createdAt = Date(timeIntervalSince1970: 40_000)
        var pending = try makePending(createdAt: createdAt, lifetime: 60)
        let secret = try pending.redemptionSecret()

        XCTAssertFalse(
            pending.offer.isUsable(
                at: pending.offer.expiresAt,
                for: .contactPairing
            )
        )
        XCTAssertThrowsError(
            try RendezvousResponderV2.createOpen(
                for: pending.offer,
                redemptionSecret: secret,
                at: pending.offer.expiresAt
            )
        ) { error in
            XCTAssertEqual(error as? RendezvousV2Error, .expired)
        }

        let responder = try RendezvousResponderV2.createOpen(
            for: pending.offer,
            redemptionSecret: secret,
            at: createdAt.addingTimeInterval(1)
        )
        var ledger = RendezvousRedemptionLedgerV2()
        var session = try pending.accept(
            responder.request,
            ledger: &ledger,
            at: createdAt.addingTimeInterval(1)
        )
        XCTAssertThrowsError(
            try session.seal(
                Data("late".utf8),
                kind: .confirmation,
                at: pending.offer.expiresAt
            )
        ) { error in
            XCTAssertEqual(error as? RendezvousV2Error, .expired)
        }
    }

    func testTokenProofTamperDoesNotConsumeTheOffer() throws {
        let createdAt = Date(timeIntervalSince1970: 50_000)
        var pending = try makePending(createdAt: createdAt)
        let secret = try pending.redemptionSecret()
        let responder = try RendezvousResponderV2.createOpen(
            for: pending.offer,
            redemptionSecret: secret,
            at: createdAt.addingTimeInterval(1)
        )

        var wrongToken = secret.oneTimeToken
        wrongToken[wrongToken.startIndex] ^= 0xff
        let wrongSecret = try RendezvousRedemptionSecretV2(oneTimeToken: wrongToken)
        XCTAssertThrowsError(
            try RendezvousResponderV2.createOpen(
                for: pending.offer,
                redemptionSecret: wrongSecret,
                at: createdAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? RendezvousV2Error, .invalidRedemptionSecret)
        }

        var tamperedProof = responder.request.tokenProof
        tamperedProof[tamperedProof.startIndex] ^= 0xff
        let tamperedRequest = RendezvousOpenV2(
            purpose: responder.request.purpose,
            offerDigest: responder.request.offerDigest,
            kemCiphertext: responder.request.kemCiphertext,
            tokenProof: tamperedProof,
            openedAt: responder.request.openedAt
        )
        var ledger = RendezvousRedemptionLedgerV2()
        XCTAssertThrowsError(
            try pending.accept(
                tamperedRequest,
                ledger: &ledger,
                at: createdAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? RendezvousV2Error, .invalidOpen)
        }
        XCTAssertFalse(pending.isRedeemed)
        XCTAssertEqual(ledger.redemptionCount, 0)

        _ = try pending.accept(
            responder.request,
            ledger: &ledger,
            at: createdAt.addingTimeInterval(1)
        )
        XCTAssertTrue(pending.isRedeemed)
        XCTAssertEqual(ledger.redemptionCount, 1)
    }

    func testSingleRedemptionAndFrameReplayAreRejected() throws {
        let createdAt = Date(timeIntervalSince1970: 60_000)
        let originalPending = try makePending(createdAt: createdAt)
        let secret = try originalPending.redemptionSecret()
        let responder = try RendezvousResponderV2.createOpen(
            for: originalPending.offer,
            redemptionSecret: secret,
            at: createdAt.addingTimeInterval(1)
        )
        var firstPending = originalPending
        var clonedPending = originalPending
        var ledger = RendezvousRedemptionLedgerV2()
        var receivingSession = try firstPending.accept(
            responder.request,
            ledger: &ledger,
            at: createdAt.addingTimeInterval(1)
        )
        var sendingSession = responder.session

        XCTAssertThrowsError(
            try clonedPending.accept(
                responder.request,
                ledger: &ledger,
                at: createdAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? RendezvousV2Error, .alreadyRedeemed)
        }

        let frame = try sendingSession.seal(
            Data("hello".utf8),
            kind: .contactOffer,
            at: createdAt.addingTimeInterval(2)
        )
        let kindTamper = RendezvousFrameV2(
            sessionId: frame.sessionId,
            purpose: frame.purpose,
            senderRole: frame.senderRole,
            sequence: frame.sequence,
            messageKind: .confirmation,
            payload: frame.payload
        )
        XCTAssertThrowsError(
            try receivingSession.open(kindTamper, at: createdAt.addingTimeInterval(2))
        ) { error in
            XCTAssertEqual(error as? RendezvousV2Error, .decryptionFailed)
        }
        XCTAssertEqual(receivingSession.nextInboundSequence, 1)

        let sequenceTamper = RendezvousFrameV2(
            sessionId: frame.sessionId,
            purpose: frame.purpose,
            senderRole: frame.senderRole,
            sequence: 2,
            messageKind: frame.messageKind,
            payload: frame.payload
        )
        XCTAssertThrowsError(
            try receivingSession.open(sequenceTamper, at: createdAt.addingTimeInterval(2))
        ) { error in
            XCTAssertEqual(
                error as? RendezvousV2Error,
                .unexpectedSequence(expected: 1, actual: 2)
            )
        }

        XCTAssertEqual(
            try receivingSession.open(frame, at: createdAt.addingTimeInterval(2)),
            Data("hello".utf8)
        )
        XCTAssertThrowsError(
            try receivingSession.open(frame, at: createdAt.addingTimeInterval(2))
        ) { error in
            XCTAssertEqual(
                error as? RendezvousV2Error,
                .unexpectedSequence(expected: 2, actual: 1)
            )
        }
    }

    func testFrameLimitsAreEnforcedBeforeEncryption() throws {
        let createdAt = Date(timeIntervalSince1970: 70_000)
        let limits = try RendezvousLimitsV2(
            maximumFrames: 1,
            maximumFramePlaintextBytes: 8
        )
        let pending = try makePending(
            createdAt: createdAt,
            limits: limits
        )
        let responder = try RendezvousResponderV2.createOpen(
            for: pending.offer,
            redemptionSecret: pending.redemptionSecret(),
            at: createdAt.addingTimeInterval(1)
        )
        var sendingSession = responder.session

        XCTAssertThrowsError(
            try sendingSession.seal(
                Data(repeating: 1, count: 9),
                kind: .contactOffer,
                at: createdAt.addingTimeInterval(2)
            )
        ) { error in
            XCTAssertEqual(error as? RendezvousV2Error, .payloadTooLarge)
        }
        XCTAssertEqual(sendingSession.nextOutboundSequence, 1)

        let frame = try sendingSession.seal(
            Data(repeating: 1, count: 8),
            kind: .contactOffer,
            at: createdAt.addingTimeInterval(2)
        )
        XCTAssertEqual(frame.payload.ciphertext.count, 4_096)
        XCTAssertThrowsError(
            try sendingSession.seal(
                Data(),
                kind: .confirmation,
                at: createdAt.addingTimeInterval(3)
            )
        ) { error in
            XCTAssertEqual(error as? RendezvousV2Error, .frameLimitExceeded)
        }
    }

    private func makePending(
        createdAt: Date,
        lifetime: TimeInterval = 300,
        limits: RendezvousLimitsV2 = .contactPairing
    ) throws -> PendingRendezvousOfferV2 {
        let capability = try RendezvousTransportCapabilityV2.generate(
            expiresAt: createdAt.addingTimeInterval(lifetime)
        )
        return try PendingRendezvousOfferV2.create(
            transportCapability: capability,
            createdAt: createdAt,
            limits: limits
        )
    }
}
