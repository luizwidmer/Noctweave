import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class NoctweaveOriginNamespaceTests: XCTestCase {
    func testFederationDirectoryKeyProbeUsesNoctweaveOriginDomain() {
        XCTAssertEqual(
            String(decoding: FederationDirectorySignature.keyProbeDomain, as: UTF8.self),
            "org.noctweave.federation.directory-key-probe/v1"
        )
    }
}
