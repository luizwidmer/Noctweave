import Foundation
import XCTest
@testable import NoctweaveCore

final class StrictCryptographicStateTests: XCTestCase {
    func testPairwiseAuthorityRejectsRemovedRotationState() throws {
        let authority = try RelationshipAuthorityV2.generate(
            relationshipPseudonym: "relationship-pseudonym"
        )
        let encoded = try NoctweaveCoder.encode(authority)
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertEqual(
            Set(object.keys),
            ["relationshipPseudonym", "signingKey", "agreementKey", "createdAt"]
        )
        object["rotationCounter"] = 1
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                RelationshipAuthorityV2.self,
                from: JSONSerialization.data(withJSONObject: object)
            )
        )
    }

    func testRatchetChainRequiresEveryCurrentFieldAndRejectsUnknownFields() throws {
        let state = ChainKeyState(
            keyData: Data(repeating: 0x41, count: 32),
            counter: 0,
            skippedMessageKeys: [:]
        )
        let encoded = try NoctweaveCoder.encode(state)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertEqual(
            Set(object.keys),
            ["keyData", "counter", "skippedMessageKeys"]
        )

        for requiredKey in object.keys {
            var missing = object
            missing.removeValue(forKey: requiredKey)
            XCTAssertThrowsError(
                try NoctweaveCoder.decode(
                    ChainKeyState.self,
                    from: JSONSerialization.data(withJSONObject: missing)
                )
            )
        }

        var extended = object
        extended["legacyCounter"] = 0
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                ChainKeyState.self,
                from: JSONSerialization.data(withJSONObject: extended)
            )
        )
        XCTAssertEqual(try NoctweaveCoder.decode(ChainKeyState.self, from: encoded), state)
    }

    func testPrekeyStateRequiresTheCompleteCurrentSchema() throws {
        let authority = try RelationshipAuthorityV2.generate(
            relationshipPseudonym: "strict-prekeys"
        )
        let state = try PrekeyState.generate(authority: authority, oneTimeCount: 1)
        let encoded = try NoctweaveCoder.encode(state)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertEqual(
            Set(object.keys),
            [
                "signedPrekeyId",
                "signedPrekeyPublicKey",
                "signedPrekeyPrivateKey",
                "signedPrekeySignature",
                "signedPrekeyIssuedAt",
                "signedPrekeyExpiresAt",
                "retiredSignedPrekeys",
                "oneTimePrekeys"
            ]
        )

        for requiredKey in ["signedPrekeyExpiresAt", "retiredSignedPrekeys"] {
            var missing = object
            missing.removeValue(forKey: requiredKey)
            XCTAssertThrowsError(
                try NoctweaveCoder.decode(
                    PrekeyState.self,
                    from: JSONSerialization.data(withJSONObject: missing)
                )
            )
        }

        var extended = object
        extended["migrationVersion"] = 1
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                PrekeyState.self,
                from: JSONSerialization.data(withJSONObject: extended)
            )
        )
        XCTAssertEqual(try NoctweaveCoder.decode(PrekeyState.self, from: encoded), state)
    }
}
