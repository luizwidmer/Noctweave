import Foundation
import XCTest
@testable import NoctweaveCore

final class CallProtocolV1Tests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_930_000_000)
    private let callID = UUID(uuidString: "7D5A399D-D3B1-487A-9BDD-2D2F04B93476")!
    private let candidateID = UUID(uuidString: "2566A7F0-E735-4E4A-B0EB-2AF080EAA024")!

    func testRealMLKEMHandshakeDerivesMatchingMediaKeys() throws {
        var pending = try makePending()
        let responder = try CallResponderHandshakeV1.answer(
            pending.offerSignal,
            tracks: [CallTrackSelectionV1(trackID: 1, codecIdentifier: "opus")],
            selectedCandidateID: candidateID,
            at: now.addingTimeInterval(1)
        )
        let initiatorMaterial = try pending.accept(
            responder.answerSignal,
            at: now.addingTimeInterval(1)
        )

        XCTAssertEqual(initiatorMaterial, responder.keyMaterial)
        XCTAssertEqual(initiatorMaterial.rootKey.count, 32)

        let frame = CallMediaFrameV1(
            trackID: 1,
            timestamp: 960,
            payload: Data("authenticated audio".utf8)
        )
        var sender = try CallMediaSenderV1(material: initiatorMaterial, role: .initiator)
        var receiver = try CallMediaReceiverV1(
            material: responder.keyMaterial,
            remoteRole: .initiator
        )
        let sealed = try sender.seal(frame, targetByteCount: 512)

        XCTAssertEqual(sealed.ciphertext.count, 512)
        XCTAssertEqual(try receiver.open(sealed), frame)
        XCTAssertThrowsError(try receiver.open(sealed)) { error in
            XCTAssertEqual(error as? CallProtocolV1Error, .replay)
        }
    }

    func testSharedJavaScriptVectorMatchesCanonicalKDFAndMediaCiphertext() throws {
        let vector = try loadSharedVector()
        let callID = try XCTUnwrap(UUID(uuidString: vector.callID))
        let candidateID = try XCTUnwrap(UUID(uuidString: vector.candidateID))
        let createdAt = try parseDate(vector.createdAt)
        let expiresAt = try parseDate(vector.expiresAt)
        let answerAt = try parseDate(vector.answerAt)
        let offer = CallOfferV1(
            initiatorAgreementPublicKey: Data(
                repeating: vector.offerPublicKeyRepeatedByte,
                count: vector.offerPublicKeyBytes
            ),
            tracks: [
                CallTrackOfferV1(
                    trackID: 1,
                    mediaKind: .audio,
                    codecs: [.opus]
                )
            ],
            candidates: [
                CallTransportCandidateV1(
                    candidateID: candidateID,
                    kind: .relayWebSocket,
                    privacy: .relayMediated,
                    priority: 100,
                    descriptor: Data(vector.descriptor.utf8)
                )
            ]
        )
        let offerSignal = CallSignalV1(
            callID: callID,
            senderRole: .initiator,
            sequence: 1,
            kind: .offer,
            createdAt: createdAt,
            expiresAt: expiresAt,
            offer: offer
        )
        XCTAssertEqual(offer.canonicalDigest?.base64EncodedString(), vector.expectedOfferDigestBase64)
        let answer = CallAnswerV1(
            offerDigest: try XCTUnwrap(offer.canonicalDigest),
            kemCiphertext: Data(
                repeating: vector.kemCiphertextRepeatedByte,
                count: vector.kemCiphertextBytes
            ),
            tracks: [CallTrackSelectionV1(trackID: 1, codecIdentifier: "opus")],
            selectedCandidateID: candidateID
        )
        let answerSignal = CallSignalV1(
            callID: callID,
            senderRole: .responder,
            sequence: 1,
            kind: .answer,
            createdAt: answerAt,
            expiresAt: expiresAt,
            answer: answer
        )
        let material = try CallKeyScheduleV1.derive(
            offerSignal: offerSignal,
            answerSignal: answerSignal,
            sharedSecret: Data(
                repeating: vector.sharedSecretRepeatedByte,
                count: vector.sharedSecretBytes
            )
        )
        XCTAssertEqual(
            material.transcriptDigest.base64EncodedString(),
            vector.expectedTranscriptDigestBase64
        )
        XCTAssertEqual(material.rootKey.base64EncodedString(), vector.expectedRootKeyBase64)
        XCTAssertEqual(
            try CallKeyScheduleV1.mediaKey(
                material: material,
                senderRole: .initiator,
                epoch: 0
            ).dataRepresentation.base64EncodedString(),
            vector.expectedInitiatorMediaKeyEpoch0Base64
        )
        let payload = try XCTUnwrap(Data(base64Encoded: vector.mediaFrame.payloadBase64))
        let sealed = try CallMediaCipherV1.seal(
            CallMediaFrameV1(
                trackID: vector.mediaFrame.trackID,
                timestamp: vector.mediaFrame.timestamp,
                flags: CallMediaFlagsV1(rawValue: vector.mediaFrame.flags),
                payload: payload
            ),
            material: material,
            senderRole: .initiator,
            epoch: 0,
            sequence: 1,
            targetByteCount: vector.mediaFrame.targetByteCount,
            deterministicPadding: Data(
                repeating: vector.mediaFrame.paddingRepeatedByte,
                count: vector.mediaFrame.targetByteCount - 16 - 14 - payload.count
            )
        )
        XCTAssertEqual(
            sealed.ciphertext.base64EncodedString(),
            vector.mediaFrame.expectedCiphertextBase64
        )
    }

    func testPendingOfferRoundTripPreservesEncryptedStoreState() throws {
        let pending = try makePending()
        let encoded = try NoctweaveCoder.encode(pending, sortedKeys: true)
        var restored = try NoctweaveCoder.decode(PendingCallOfferV1.self, from: encoded)
        let responder = try CallResponderHandshakeV1.answer(
            restored.offerSignal,
            tracks: [CallTrackSelectionV1(trackID: 1, codecIdentifier: "opus")],
            selectedCandidateID: candidateID,
            at: now.addingTimeInterval(1)
        )

        XCTAssertEqual(
            try restored.accept(responder.answerSignal, at: now.addingTimeInterval(1)),
            responder.keyMaterial
        )
    }

    func testTamperingAndWrongDirectionFailAuthentication() throws {
        let material = fixedMaterial()
        let frame = CallMediaFrameV1(trackID: 1, timestamp: 20, payload: Data([1, 2, 3]))
        let sealed = try CallMediaCipherV1.seal(
            frame,
            material: material,
            senderRole: .initiator,
            epoch: 0,
            sequence: 1,
            targetByteCount: 512,
            deterministicPadding: Data(repeating: 0xA5, count: 479)
        )
        var tamperedBytes = sealed.ciphertext
        tamperedBytes[tamperedBytes.startIndex] ^= 0x80
        let tampered = SealedCallMediaFrameV1(
            epoch: sealed.epoch,
            sequence: sealed.sequence,
            ciphertext: tamperedBytes
        )

        XCTAssertThrowsError(
            try CallMediaCipherV1.open(tampered, material: material, senderRole: .initiator)
        ) { error in
            XCTAssertEqual(error as? CallProtocolV1Error, .authenticationFailed)
        }
        XCTAssertThrowsError(
            try CallMediaCipherV1.open(sealed, material: material, senderRole: .responder)
        ) { error in
            XCTAssertEqual(error as? CallProtocolV1Error, .authenticationFailed)
        }
    }

    func testReplayWindowAllowsReorderingAndOnlyAdjacentEpochs() throws {
        let material = fixedMaterial()
        let frame = CallMediaFrameV1(trackID: 1, timestamp: 1, payload: Data([9]))
        var receiver = try CallMediaReceiverV1(material: material, remoteRole: .initiator)

        let first = try seal(frame, material: material, epoch: 0, sequence: 2)
        let reordered = try seal(frame, material: material, epoch: 0, sequence: 1)
        XCTAssertEqual(try receiver.open(first), frame)
        XCTAssertEqual(try receiver.open(reordered), frame)

        let skippedEpoch = try seal(frame, material: material, epoch: 2, sequence: 1)
        XCTAssertThrowsError(try receiver.open(skippedEpoch)) { error in
            XCTAssertEqual(error as? CallProtocolV1Error, .invalidEpoch)
        }

        let epochOne = try seal(frame, material: material, epoch: 1, sequence: 1)
        let epochTwo = try seal(frame, material: material, epoch: 2, sequence: 1)
        XCTAssertEqual(try receiver.open(epochOne), frame)
        XCTAssertEqual(try receiver.open(epochTwo), frame)

        let retiredEpoch = try seal(frame, material: material, epoch: 0, sequence: 3)
        XCTAssertThrowsError(try receiver.open(retiredEpoch)) { error in
            XCTAssertEqual(error as? CallProtocolV1Error, .invalidEpoch)
        }
    }

    func testCallCapabilityRequiresExplicitModuleAndContentOptIn() throws {
        let baseline = ProtocolCapabilityManifest()
        XCTAssertFalse(baseline.supportsCallV1)
        XCTAssertFalse(baseline.supports(module: NoctweaveCallV1.module, version: 1))
        XCTAssertFalse(baseline.supports(contentType: .callSignal))

        let enabled = baseline.enablingCallV1()
        XCTAssertTrue(enabled.isStructurallyValid)
        XCTAssertTrue(enabled.supportsCallV1)
        XCTAssertEqual(
            enabled.modules.first { $0.module == NoctweaveCallV1.module }?.status,
            .experimental
        )

        XCTAssertFalse(try XCTUnwrap(enabled.negotiated(with: baseline)).supportsCallV1)
        XCTAssertTrue(try XCTUnwrap(enabled.negotiated(with: enabled)).supportsCallV1)
    }

    func testSignalEncodingIsStrictCanonicalAndSilent() throws {
        let signal = try makePending().offerSignal
        let content = try EncodedContent.callSignal(signal)

        XCTAssertEqual(content.type, .callSignal)
        XCTAssertEqual(content.disposition, .silent)
        XCTAssertEqual(try content.decodeCallSignalV1(), signal)

        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: content.payload) as? [String: Any]
        )
        object["futureField"] = true
        let withUnknownField = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(CallSignalV1.self, from: withUnknownField)
        )

        let prettyPrinted = try JSONSerialization.data(
            withJSONObject: object.filter { $0.key != "futureField" },
            options: [.prettyPrinted, .sortedKeys]
        )
        let nonCanonicalContent = EncodedContent(
            type: .callSignal,
            payload: prettyPrinted,
            fallbackText: nil,
            disposition: .silent
        )
        XCTAssertThrowsError(try nonCanonicalContent.decodeCallSignalV1()) { error in
            XCTAssertEqual(error as? CallProtocolV1Error, .nonCanonicalSignal)
        }
    }

    func testAnswerMustSelectAnOfferedCandidateAndCodec() throws {
        let pending = try makePending()
        XCTAssertThrowsError(try CallResponderHandshakeV1.answer(
            pending.offerSignal,
            tracks: [CallTrackSelectionV1(trackID: 1, codecIdentifier: "not-offered")],
            selectedCandidateID: candidateID,
            at: now.addingTimeInterval(1)
        )) { error in
            XCTAssertEqual(error as? CallProtocolV1Error, .invalidAnswer)
        }
        XCTAssertThrowsError(try CallResponderHandshakeV1.answer(
            pending.offerSignal,
            tracks: [CallTrackSelectionV1(trackID: 1, codecIdentifier: "opus")],
            selectedCandidateID: UUID(),
            at: now.addingTimeInterval(1)
        )) { error in
            XCTAssertEqual(error as? CallProtocolV1Error, .invalidAnswer)
        }
    }

    func testStateMachineHandlesReplayForkAndTwoConnectedSignals() throws {
        let pending = try makePending()
        var state = try CallStateMachineV1(offerSignal: pending.offerSignal, now: now)
        let ringing = signal(
            callID: callID,
            role: .responder,
            sequence: 1,
            kind: .ringing,
            at: now.addingTimeInterval(1)
        )
        XCTAssertEqual(try state.apply(ringing, now: now.addingTimeInterval(1)), .applied)
        XCTAssertEqual(try state.apply(ringing, now: now.addingTimeInterval(1)), .exactReplay)

        let fork = signal(
            callID: callID,
            role: .responder,
            sequence: 1,
            kind: .candidate,
            at: now.addingTimeInterval(1),
            candidate: candidate()
        )
        XCTAssertThrowsError(try state.apply(fork, now: now.addingTimeInterval(1))) { error in
            XCTAssertEqual(error as? CallProtocolV1Error, .signalFork)
        }

        let answer = try CallResponderHandshakeV1.answer(
            pending.offerSignal,
            tracks: [CallTrackSelectionV1(trackID: 1, codecIdentifier: "opus")],
            selectedCandidateID: candidateID,
            sequence: 2,
            at: now.addingTimeInterval(2)
        ).answerSignal
        XCTAssertEqual(try state.apply(answer, now: now.addingTimeInterval(2)), .applied)
        XCTAssertEqual(state.phase, .connecting)

        let initiatorConnected = signal(
            callID: callID,
            role: .initiator,
            sequence: 2,
            kind: .connected,
            at: now.addingTimeInterval(3)
        )
        let responderConnected = signal(
            callID: callID,
            role: .responder,
            sequence: 3,
            kind: .connected,
            at: now.addingTimeInterval(3)
        )
        XCTAssertEqual(try state.apply(initiatorConnected, now: now.addingTimeInterval(3)), .applied)
        XCTAssertEqual(try state.apply(responderConnected, now: now.addingTimeInterval(3)), .applied)
        XCTAssertEqual(state.phase, .active)

        let ended = signal(
            callID: callID,
            role: .initiator,
            sequence: 3,
            kind: .ended,
            at: now.addingTimeInterval(4),
            terminationReason: .completed
        )
        XCTAssertEqual(try state.apply(ended, now: now.addingTimeInterval(4)), .applied)
        XCTAssertEqual(state.phase, .ended)
        XCTAssertEqual(state.terminationReason, .completed)
    }

    func testMediaBoundsAreEnforcedBeforeEncryption() throws {
        let oversized = CallMediaFrameV1(
            trackID: 1,
            timestamp: 0,
            payload: Data(repeating: 0, count: NoctweaveCallV1.maximumMediaPayloadBytes + 1)
        )
        XCTAssertFalse(oversized.isStructurallyValid)
        XCTAssertThrowsError(try CallMediaCipherV1.seal(
            oversized,
            material: fixedMaterial(),
            senderRole: .initiator,
            epoch: 0,
            sequence: 1
        )) { error in
            XCTAssertEqual(error as? CallProtocolV1Error, .invalidMediaFrame)
        }
    }

    private func makePending() throws -> PendingCallOfferV1 {
        try PendingCallOfferV1.create(
            callID: callID,
            tracks: [
                CallTrackOfferV1(
                    trackID: 1,
                    mediaKind: .audio,
                    codecs: [.opus]
                )
            ],
            candidates: [candidate()],
            createdAt: now
        )
    }

    private func loadSharedVector() throws -> SharedCallVector {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return try JSONDecoder().decode(
            SharedCallVector.self,
            from: Data(contentsOf: repositoryRoot.appendingPathComponent(
                "NoctweaveDocumentation/test_vectors/call_v1.json"
            ))
        )
    }

    private func parseDate(_ value: String) throws -> Date {
        try XCTUnwrap(ISO8601DateFormatter().date(from: value))
    }

    private func candidate() -> CallTransportCandidateV1 {
        CallTransportCandidateV1(
            candidateID: candidateID,
            kind: .relayWebSocket,
            privacy: .relayMediated,
            priority: 100,
            descriptor: Data("wss://relay.example/call/opaque-route".utf8)
        )
    }

    private func fixedMaterial() -> CallKeyMaterialV1 {
        CallKeyMaterialV1(
            callID: callID,
            transcriptDigest: Data(repeating: 0x11, count: 32),
            rootKey: Data(repeating: 0x22, count: 32)
        )
    }

    private func seal(
        _ frame: CallMediaFrameV1,
        material: CallKeyMaterialV1,
        epoch: UInt32,
        sequence: UInt64
    ) throws -> SealedCallMediaFrameV1 {
        try CallMediaCipherV1.seal(
            frame,
            material: material,
            senderRole: .initiator,
            epoch: epoch,
            sequence: sequence,
            targetByteCount: 512,
            deterministicPadding: Data(repeating: 0, count: 481)
        )
    }

    private func signal(
        callID: UUID,
        role: CallRoleV1,
        sequence: UInt64,
        kind: CallSignalKindV1,
        at date: Date,
        candidate: CallTransportCandidateV1? = nil,
        terminationReason: CallTerminationReasonV1? = nil
    ) -> CallSignalV1 {
        CallSignalV1(
            callID: callID,
            senderRole: role,
            sequence: sequence,
            kind: kind,
            createdAt: date,
            expiresAt: date.addingTimeInterval(300),
            candidate: candidate,
            terminationReason: terminationReason
        )
    }
}

private struct SharedCallVector: Decodable {
    let callID: String
    let candidateID: String
    let createdAt: String
    let expiresAt: String
    let answerAt: String
    let descriptor: String
    let offerPublicKeyBytes: Int
    let offerPublicKeyRepeatedByte: UInt8
    let kemCiphertextBytes: Int
    let kemCiphertextRepeatedByte: UInt8
    let sharedSecretBytes: Int
    let sharedSecretRepeatedByte: UInt8
    let expectedOfferDigestBase64: String
    let expectedTranscriptDigestBase64: String
    let expectedRootKeyBase64: String
    let expectedInitiatorMediaKeyEpoch0Base64: String
    let mediaFrame: SharedCallMediaVector
}

private struct SharedCallMediaVector: Decodable {
    let trackID: UInt16
    let timestamp: UInt64
    let flags: UInt8
    let payloadBase64: String
    let targetByteCount: Int
    let paddingRepeatedByte: UInt8
    let expectedCiphertextBase64: String
}
