import XCTest
@testable import NoctweaveCore

final class GroupPolicyTests: XCTestCase {
    func testGroupPermissionPolicyMakesRoleDecisionsExplicit() {
        let policy = GroupPermissionPolicy.default

        XCTAssertTrue(policy.isStructurallyValid)
        XCTAssertTrue(policy.allows(.addMember, for: .admin))
        XCTAssertTrue(policy.allows(.removeMember, for: .owner))
        XCTAssertFalse(policy.allows(.removeMember, for: .member))
        XCTAssertFalse(policy.allows(.updatePolicy, for: .admin))
        XCTAssertTrue(policy.allows(.updatePolicy, for: .owner))
    }
}
