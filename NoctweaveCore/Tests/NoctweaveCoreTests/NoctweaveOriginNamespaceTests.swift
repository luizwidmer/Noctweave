import Foundation
import XCTest
@testable import NoctweaveCore

final class NoctweaveOriginNamespaceTests: XCTestCase {
    func testCryptographicDomainsUseNoctweaveOriginNamespace() {
        XCTAssertEqual(
            String(decoding: HiddenRetrievalPlanner.rankingDomain, as: UTF8.self),
            "org.noctweave.hidden-retrieval.rank/v1"
        )
        XCTAssertEqual(
            String(decoding: HiddenRetrievalPlanner.xorPIRMaskDomain, as: UTF8.self),
            "org.noctweave.hidden-retrieval.xor-pir-mask/v1"
        )
        XCTAssertEqual(
            String(decoding: OnionTransport.layerKeyDerivationSalt, as: UTF8.self),
            "org.noctweave.onion-transport.layer-key/v1"
        )
    }

    func testLocalSecureStorageAndKeyboardStateUseNoctweaveOriginIdentifiers() throws {
        XCTAssertEqual(ClientStateStore.secureStorageService, "org.noctweave.securestorage")
        XCTAssertEqual(SecureTypingKeyboard.noctweave.rawValue, "noctweave")
        XCTAssertEqual(PrivacySettings().secureTypingKeyboard, .noctweave)
        XCTAssertEqual(SecureTypingKeyboard.noctweave.displayName, "Noctweave keyboard")
        XCTAssertEqual(SecureTypingKeyboard.noctweave.shortName, "Noctweave")
        XCTAssertEqual(
            String(decoding: try NoctweaveCoder.encode(SecureTypingKeyboard.noctweave), as: UTF8.self),
            #""noctweave""#
        )
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(
                SecureTypingKeyboard.self,
                from: Data(#""noctyra""#.utf8)
            )
        )
    }
}
