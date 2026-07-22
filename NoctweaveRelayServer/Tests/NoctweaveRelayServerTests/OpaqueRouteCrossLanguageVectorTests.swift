import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class OpaqueRouteCrossLanguageVectorTests: XCTestCase {
    func testJavaScriptCreateTransitionDecodesAndValidatesInRelay() throws {
        let json = #"{"request":{"version":2,"routeID":{"rawValue":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="},"sendCapabilityDigest":"gU04/oQMI4qppdMqlT0fp3CngXy4+SrfEfirybI+lHI=","readCredentialDigest":"hj4vqN+9BOMTsOqFuCG3THVdGRTVz1f9rygjUC5isNs=","renewCapabilityDigest":"YAF7Ftz6nmCX7IGs+umVlwjwFlZHfVfgdkhO7RpFCwg=","teardownCapabilityDigest":"IaBYgz9z0PGaA66HZQMzRmhS7cluYK/K8biXeWF1bPw=","lease":{"issuedAt":"2026-07-16T12:00:00Z","lastRenewedAt":"2026-07-16T12:00:00Z","expiresAt":"2026-07-16T13:00:00Z","renewalSequence":0,"policy":{"paddingBucket":16384,"retentionBucket":86400,"quotaBucket":256,"transportRequirement":"confidentialAuthenticated"}},"idempotencyKey":{"rawValue":"BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY="},"authorization":{"authority":"renew","nonce":{"rawValue":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="},"operationDigest":"zmMoEEgrx3LS7S6cyRvPn+InD9953hy9Y5ReEUZ3woo=","authorizedAt":"2026-07-16T12:00:00Z","mac":"5FrSK38Drfme1OqI42Rlib2ab1N2s/qgOA1Kn6d7E6Q="}},"renewCapability":{"rawValue":"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="}}"#
        let submission = try RelayCodec.decoder().decode(
            OpaqueRouteCreateSubmissionV2.self,
            from: Data(json.utf8)
        )

        XCTAssertTrue(submission.isStructurallyValid)
        XCTAssertEqual(
            submission.request.transitionDigest?.base64EncodedString(),
            "zmMoEEgrx3LS7S6cyRvPn+InD9953hy9Y5ReEUZ3woo="
        )
        XCTAssertEqual(
            submission.request.authorization.mac.base64EncodedString(),
            "5FrSK38Drfme1OqI42Rlib2ab1N2s/qgOA1Kn6d7E6Q="
        )
    }
}
