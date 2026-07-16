import Foundation
import XCTest
@testable import NoctweaveCore

final class EnvelopeWireVectorTests: XCTestCase {
    func testEnvelopeSecurityContextWireVectorRoundTrips() throws {
        let vector = Data(
            """
            {
              "id":"11111111-1111-1111-1111-111111111111",
              "conversationId":"core-envelope-vector",
              "sessionId":"session-v2",
              "senderFingerprint":"REREREREREREREREREREREREREREREREREREREREREQ=",
              "sentAt":"2027-01-15T08:00:00Z",
              "messageCounter":42,
              "kemCiphertext":"AQID",
              "prekey":{"kind":"oneTime","id":"22222222-2222-2222-2222-222222222222"},
              "rootRatchet":{
                "counter":7,
                "kemCiphertext":"BAUG",
                "sentAt":"2027-01-15T08:01:00Z"
              },
              "authenticatedContext":{
                "purpose":"group",
                "group":{
                  "protocolVersion":"noctweave-pq-group-experimental-2",
                  "cipherSuite":"Noctweave-PQ-Group-Experimental-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-2",
                  "groupId":"33333333-3333-3333-3333-333333333333",
                  "epoch":9,
                  "senderFingerprint":"REREREREREREREREREREREREREREREREREREREREREQ=",
                  "transcriptHash":"VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU="
                }
              },
              "payload":{"nonce":"ERERERERERERERER","ciphertext":"ISIjJA==","tag":"MzMzMzMzMzMzMzMzMzMzMw=="},
              "signature":"QkNERQ=="
            }
            """.utf8
        )
        let envelope = try NoctweaveCoder.decode(Envelope.self, from: vector)
        XCTAssertEqual(envelope.prekey?.kind, .oneTime)
        XCTAssertEqual(envelope.rootRatchet?.counter, 7)
        XCTAssertEqual(envelope.authenticatedContext?.purpose, .group)
        XCTAssertEqual(
            envelope.authenticatedContext?.group?.protocolVersion,
            MLSGroupEpochState.currentProtocolVersion
        )
        XCTAssertEqual(
            envelope.authenticatedContext?.group?.cipherSuite,
            MLSGroupEpochState.currentCipherSuite
        )
        XCTAssertEqual(envelope.authenticatedContext?.group?.epoch, 9)
        let reencoded = try NoctweaveCoder.encode(envelope, sortedKeys: true)
        XCTAssertEqual(try jsonObject(reencoded), try jsonObject(vector))
    }

    private func jsonObject(_ data: Data) throws -> NSDictionary {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: data, options: []) as? NSDictionary
        )
    }
}
