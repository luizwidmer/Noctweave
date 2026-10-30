import Foundation
import Logging
import XCTest
@testable import YubiKit

private final class CapturedLog: @unchecked Sendable {
    private let lock = NSLock()
    private var messages: [String] = []

    func append(_ message: String) {
        lock.lock()
        defer { lock.unlock() }
        messages.append(message)
    }

    var text: String {
        lock.lock()
        defer { lock.unlock() }
        return messages.joined(separator: "\n")
    }
}

private struct CaptureLogHandler: LogHandler {
    var logLevel: Logger.Level = .trace
    var metadata: Logger.Metadata = [:]
    let captured: CapturedLog

    subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    func log(event: LogEvent) {
        captured.append(event.message.description)
    }
}

final class YubiKitLogRedactionTests: XCTestCase {
    func testTraceLoggingNeverEmitsSyntheticAPDUBytes() {
        let captured = CapturedLog()
        var logger = Logger(label: "yubikit-redaction-test") { _ in
            CaptureLogHandler(captured: captured)
        }
        logger.logLevel = .trace
        let marker = Data("SYNTHETIC-SECRET-PIN".utf8)
        logger.traceRequest(marker)
        logger.traceResponse(marker)

        XCTAssertTrue(captured.text.contains("SEND"))
        XCTAssertTrue(captured.text.contains("RECV"))
        XCTAssertFalse(captured.text.contains("SYNTHETIC-SECRET-PIN"))
        XCTAssertFalse(captured.text.contains(marker.map { String(format: "%02x", $0) }.joined()))
    }

    func testAPDUDebugDescriptionNeverEmitsCommandBytes() {
        let marker = Data("SYNTHETIC-SECRET-PIN".utf8)
        let apdu = APDU(cla: 0, ins: 0, p1: 0, p2: 0, command: marker)
        XCTAssertTrue(apdu.description.contains("commandBytes: \(marker.count)"))
        XCTAssertFalse(apdu.description.contains("SYNTHETIC-SECRET-PIN"))
        XCTAssertFalse(apdu.description.contains(marker.map { String(format: "%02x", $0) }.joined()))
    }
}
