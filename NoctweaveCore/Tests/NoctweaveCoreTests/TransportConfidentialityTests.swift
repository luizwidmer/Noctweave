import XCTest
@testable import NoctweaveCore

final class TransportConfidentialityTests: XCTestCase {
    func testTrustedReverseProxyDoesNotEnableCoreListenerTLS() {
        let configuration = RelayConfiguration(
            tlsEnabled: false,
            trustedReverseProxyTLS: true
        )
        XCTAssertFalse(configuration.tlsEnabled)
        XCTAssertEqual(
            configuration.effectiveTransportConfidentiality(isLiteralLoopbackSource: false),
            .trustedReverseProxyTLS
        )
        XCTAssertTrue(
            configuration.effectiveTransportConfidentiality(isLiteralLoopbackSource: false)
                .permitsCapabilityTransport
        )
    }
}
