import XCTest
@testable import ClipboardGuardian
import AppKit

final class MockPasteboard: PasteboardProviding {
    var changeCount: Int = 0
    private var content: String?

    func setString(_ s: String?) {
        content = s
        changeCount += 1
    }

    func string(forType type: NSPasteboard.PasteboardType) -> String? {
        return content
    }
}

struct TestRule: DetectionRule {
    func detect(in content: String) -> [Finding] {
        if content.contains("trigger") {
            return [Finding(severity: .high, category: "test", message: "found")]
        }
        return []
    }
}

final class ClipboardMonitorTests: XCTestCase {
    func testCheckOnce_callsAnalyzerOnChange() {
        let mock = MockPasteboard()
        mock.changeCount = 0

        let analyzer = Analyzer(rules: [TestRule()])
        var received: [[Finding]] = []

        let monitor = ClipboardMonitor(provider: mock, analyzer: analyzer) { findings in
            received.append(findings)
        }

        mock.setString("this will trigger")
        monitor.checkOnce()

        XCTAssertEqual(received.count, 1)
        XCTAssertEqual(received.first?.first?.category, "test")

        // No further change -> no callback
        monitor.checkOnce()
        XCTAssertEqual(received.count, 1)
    }

    func testCheckOnce_notifiesSafeClipboardAfterDangerousContent() {
        let mock = MockPasteboard()
        mock.changeCount = 0

        let analyzer = Analyzer(rules: [TestRule()])
        var received: [[Finding]] = []

        let monitor = ClipboardMonitor(provider: mock, analyzer: analyzer) { findings in
            received.append(findings)
        }

        mock.setString("this will trigger")
        monitor.checkOnce()
        XCTAssertEqual(received.count, 1)
        XCTAssertFalse(received[0].isEmpty)

        mock.setString("safe clipboard text")
        monitor.checkOnce()
        XCTAssertEqual(received.count, 2)
        XCTAssertTrue(received[1].isEmpty)
    }
}
