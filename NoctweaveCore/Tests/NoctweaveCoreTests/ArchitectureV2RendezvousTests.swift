import Foundation
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2RendezvousTests: XCTestCase {
    func testPublicOfferIsPrivacyBoundedAndContactPairingOnly() throws {
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

    func testOfferTranscriptTamperFailsClosed() throws {
        let createdAt = Date(timeIntervalSince1970: 30_000)
        var pending = try makePending(createdAt: createdAt)
        let secret = try pending.redemptionSecret()

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

    func testCurrentRendezvousCodecsRequireExactFieldSets() throws {
        let fixture = try makeCodecFixture()

        try assertStrictObject(
            fixture.capability,
            fields: ["opaqueValue", "expiresAt"]
        )
        try assertStrictObject(
            fixture.pending.offer.limits,
            fields: ["maximumFrames", "maximumFramePlaintextBytes"]
        )
        try assertStrictObject(
            fixture.pending.offer,
            fields: [
                "version",
                "purpose",
                "transportCapability",
                "oneTimeTokenDigest",
                "ephemeralAgreementPublicKey",
                "createdAt",
                "expiresAt",
                "limits"
            ]
        )
        try assertStrictObject(
            fixture.secret,
            fields: ["oneTimeToken"]
        )
        try assertStrictObject(
            fixture.pending,
            fields: ["offer", "ephemeralAgreementKey", "oneTimeToken", "redeemedAt"]
        )
        try assertStrictObject(
            fixture.open,
            fields: [
                "version",
                "purpose",
                "offerDigest",
                "kemCiphertext",
                "tokenProof",
                "openedAt"
            ]
        )
        try assertStrictObject(fixture.ledger, fields: ["records"])
        try assertStrictObject(fixture.frame.sessionId, fields: ["rawValue"])
        try assertStrictObject(
            fixture.frame,
            fields: [
                "version",
                "sessionId",
                "purpose",
                "senderRole",
                "sequence",
                "messageKind",
                "payload"
            ]
        )
    }

    func testPendingOfferUsesExplicitNullAndRequiresItOnDecode() throws {
        let pending = try makeCodecFixture().pending
        let encoded = try NoctweaveCoder.encode(pending, sortedKeys: true)
        let object = try jsonObject(encoded)

        XCTAssertTrue(object.keys.contains("redeemedAt"))
        XCTAssertTrue(object["redeemedAt"] is NSNull)

        var missingNull = object
        missingNull.removeValue(forKey: "redeemedAt")
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                PendingRendezvousOfferV2.self,
                from: try jsonData(missingNull)
            )
        )
    }

    func testLedgerRecordsAreExactAndStructurallyValidated() throws {
        let ledger = try makeCodecFixture().ledger
        let encoded = try NoctweaveCoder.encode(ledger, sortedKeys: true)
        let object = try jsonObject(encoded)
        var records = try XCTUnwrap(object["records"] as? [[String: Any]])
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(
            Set(records[0].keys),
            Set(["offerDigest", "openDigest", "redeemedAt", "expiresAt"])
        )

        var unknownRecord = records[0]
        unknownRecord["legacy"] = true
        var unknownLedger = object
        unknownLedger["records"] = [unknownRecord]
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                RendezvousRedemptionLedgerV2.self,
                from: try jsonData(unknownLedger)
            )
        )

        var incompleteRecord = records[0]
        incompleteRecord.removeValue(forKey: "openDigest")
        var incompleteLedger = object
        incompleteLedger["records"] = [incompleteRecord]
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                RendezvousRedemptionLedgerV2.self,
                from: try jsonData(incompleteLedger)
            )
        )

        records.append(records[0])
        var duplicateLedger = object
        duplicateLedger["records"] = records
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                RendezvousRedemptionLedgerV2.self,
                from: try jsonData(duplicateLedger)
            )
        )
    }

    func testRendezvousCodecsRejectInvalidStateOnDecodeAndEncode() throws {
        let fixture = try makeCodecFixture()

        try assertDecodeRejectsMutation(
            fixture.capability,
            as: RendezvousTransportCapabilityV2.self,
            key: "opaqueValue",
            value: Data([1]).base64EncodedString()
        )
        try assertDecodeRejectsMutation(
            fixture.pending.offer.limits,
            as: RendezvousLimitsV2.self,
            key: "maximumFrames",
            value: 0
        )
        try assertDecodeRejectsMutation(
            fixture.pending.offer,
            as: RendezvousOfferV2.self,
            key: "version",
            value: 1
        )
        try assertDecodeRejectsMutation(
            fixture.secret,
            as: RendezvousRedemptionSecretV2.self,
            key: "oneTimeToken",
            value: Data([1]).base64EncodedString()
        )
        try assertDecodeRejectsMutation(
            fixture.open,
            as: RendezvousOpenV2.self,
            key: "offerDigest",
            value: Data([1]).base64EncodedString()
        )
        try assertDecodeRejectsMutation(
            fixture.frame.sessionId,
            as: RendezvousSessionIDV2.self,
            key: "rawValue",
            value: Data([1]).base64EncodedString()
        )
        try assertDecodeRejectsMutation(
            fixture.frame,
            as: RendezvousFrameV2.self,
            key: "sequence",
            value: 0
        )

        let invalidOpen = RendezvousOpenV2(
            version: 1,
            purpose: fixture.open.purpose,
            offerDigest: fixture.open.offerDigest,
            kemCiphertext: fixture.open.kemCiphertext,
            tokenProof: fixture.open.tokenProof,
            openedAt: fixture.open.openedAt
        )
        XCTAssertThrowsError(try NoctweaveCoder.encode(invalidOpen))

        let invalidSessionId = RendezvousSessionIDV2(rawValue: Data([1]))
        XCTAssertThrowsError(try NoctweaveCoder.encode(invalidSessionId))

        let invalidFrame = RendezvousFrameV2(
            sessionId: fixture.frame.sessionId,
            purpose: fixture.frame.purpose,
            senderRole: fixture.frame.senderRole,
            sequence: 0,
            messageKind: fixture.frame.messageKind,
            payload: fixture.frame.payload
        )
        XCTAssertThrowsError(try NoctweaveCoder.encode(invalidFrame))
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

    private func makeCodecFixture() throws -> (
        capability: RendezvousTransportCapabilityV2,
        pending: PendingRendezvousOfferV2,
        secret: RendezvousRedemptionSecretV2,
        open: RendezvousOpenV2,
        ledger: RendezvousRedemptionLedgerV2,
        frame: RendezvousFrameV2
    ) {
        let createdAt = Date(timeIntervalSince1970: 80_000)
        let capability = try RendezvousTransportCapabilityV2.generate(
            expiresAt: createdAt.addingTimeInterval(300)
        )
        let pending = try PendingRendezvousOfferV2.create(
            transportCapability: capability,
            createdAt: createdAt
        )
        let secret = try pending.redemptionSecret()
        let responder = try RendezvousResponderV2.createOpen(
            for: pending.offer,
            redemptionSecret: secret,
            at: createdAt.addingTimeInterval(1)
        )
        var acceptedPending = pending
        var ledger = RendezvousRedemptionLedgerV2()
        _ = try acceptedPending.accept(
            responder.request,
            ledger: &ledger,
            at: createdAt.addingTimeInterval(1)
        )
        var session = responder.session
        let frame = try session.seal(
            Data("strict codec".utf8),
            kind: .contactOffer,
            at: createdAt.addingTimeInterval(2)
        )
        return (capability, pending, secret, responder.request, ledger, frame)
    }

    private func assertStrictObject<Value: Codable>(
        _ value: Value,
        fields: Set<String>,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let encoded = try NoctweaveCoder.encode(value, sortedKeys: true)
        let object = try jsonObject(encoded)
        XCTAssertEqual(Set(object.keys), fields, file: file, line: line)
        XCTAssertNoThrow(
            try NoctweaveCoder.decode(Value.self, from: encoded),
            file: file,
            line: line
        )

        var unknown = object
        unknown["legacy"] = true
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(Value.self, from: jsonData(unknown)),
            file: file,
            line: line
        )

        var incomplete = object
        incomplete.removeValue(forKey: try XCTUnwrap(fields.first))
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(Value.self, from: jsonData(incomplete)),
            file: file,
            line: line
        )
    }

    private func assertDecodeRejectsMutation<Value: Codable>(
        _ value: Value,
        as type: Value.Type,
        key: String,
        value replacement: Any,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        var object = try jsonObject(NoctweaveCoder.encode(value, sortedKeys: true))
        object[key] = replacement
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(type, from: jsonData(object)),
            file: file,
            line: line
        )
    }

    private func jsonObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func jsonData(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
}
