import Foundation
import XCTest
@testable import NoctweaveCore

final class RelayServerRetirementTests: XCTestCase {
    func testRetirementIncludesSuspendedWorkAndRejectsNewWork() async throws {
        let registry = RelayServerWorkRegistry()
        let gate = Gate()
        let active = registry.launch(connection: nil) { await gate.wait() }
        for _ in 0..<200 {
            if await gate.entered { break }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        let entered = await gate.entered
        XCTAssertTrue(entered)
        let pending = registry.retire()
        XCTAssertEqual(pending.count, 1)
        XCTAssertTrue(registry.isRetired)
        let rejected = registry.launch(connection: nil) { await gate.markUnexpectedWork() }
        await rejected.value
        await gate.release()
        for task in pending { await task.value }
        await active.value
        let unexpected = await gate.unexpected
        XCTAssertFalse(unexpected)
    }

    func testRetiredServerCannotRestart() async throws {
        let server = RelayServer(store: RelayStore())
        await server.retireAndDrain()
        XCTAssertThrowsError(try server.start(host: "127.0.0.1", port: 19339))
        await server.retireAndDrain()
    }

    private actor Gate {
        var entered = false
        var unexpected = false
        private var continuation: CheckedContinuation<Void, Never>?
        func wait() async {
            entered = true
            await withCheckedContinuation { continuation = $0 }
        }
        func release() { continuation?.resume(); continuation = nil }
        func markUnexpectedWork() { unexpected = true }
    }
}
