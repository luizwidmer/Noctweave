import Foundation
@testable import NoctweaveCore

func makeTestDirectEnvelope(
    id: UUID = UUID(),
    eventId: UUID = UUID(),
    conversationId: String = "test-conversation",
    sessionId: String = "test-session",
    counter: UInt64 = 0,
    sentAt: Date = Date(timeIntervalSince1970: 1_700_000_000),
    payload: EncryptedPayload = EncryptedPayload(
        nonce: Data(repeating: 0x11, count: 12),
        ciphertext: Data(repeating: 0x22, count: PaddedMessagePlaintext.minimumPaddedBytes),
        tag: Data(repeating: 0x33, count: 16)
    ),
    signature: Data = Data(repeating: 0x44, count: 3_309)
) -> DirectEnvelopeV4 {
    DirectEnvelopeV4(
        id: id,
        conversationId: conversationId,
        sessionId: sessionId,
        eventId: eventId,
        senderEndpointHandle: RelationshipEndpointHandle(
            rawValue: Data(repeating: 0x51, count: 32).base64EncodedString()
        ),
        senderCertificateDigest: Data(repeating: 0x52, count: 32),
        senderEndpointSetEpoch: 1,
        recipientEndpointHandle: RelationshipEndpointHandle(
            rawValue: Data(repeating: 0x53, count: 32).base64EncodedString()
        ),
        recipientCertificateDigest: Data(repeating: 0x54, count: 32),
        recipientEndpointSetEpoch: 1,
        cipherSuite: DirectV4CipherSuite.identifier,
        negotiatedCapabilitiesDigest: Data(repeating: 0x55, count: 32),
        bootstrap: .none,
        sentAt: sentAt,
        messageCounter: counter,
        payload: payload,
        signature: signature
    )
}

func makeTestProtocolEnvelope(
    id: UUID = UUID(),
    eventId: UUID = UUID(),
    conversationId: String = "test-conversation",
    sessionId: String = "test-session",
    counter: UInt64 = 0,
    sentAt: Date = Date(timeIntervalSince1970: 1_700_000_000),
    payload: EncryptedPayload = EncryptedPayload(
        nonce: Data(repeating: 0x11, count: 12),
        ciphertext: Data(repeating: 0x22, count: PaddedMessagePlaintext.minimumPaddedBytes),
        tag: Data(repeating: 0x33, count: 16)
    ),
    signature: Data = Data(repeating: 0x44, count: 3_309)
) -> ProtocolEnvelopeV1 {
    .directV4(
        makeTestDirectEnvelope(
            id: id,
            eventId: eventId,
            conversationId: conversationId,
            sessionId: sessionId,
            counter: counter,
            sentAt: sentAt,
            payload: payload,
            signature: signature
        )
    )
}
