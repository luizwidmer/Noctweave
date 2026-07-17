import XCTest
@testable import NoctweaveCore

final class ArchitectureV2GroupSelfSyncTests: XCTestCase {
    func testGroupPermissionPolicyMakesRoleDecisionsExplicit() {
        let policy = GroupPermissionPolicy.default

        XCTAssertTrue(policy.isStructurallyValid)
        XCTAssertTrue(policy.allows(.addClient, for: .admin))
        XCTAssertTrue(policy.allows(.removeClient, for: .owner))
        XCTAssertFalse(policy.allows(.removeClient, for: .member))
        XCTAssertFalse(policy.allows(.updatePolicy, for: .admin))
        XCTAssertTrue(policy.allows(.updatePolicy, for: .owner))
    }
}
