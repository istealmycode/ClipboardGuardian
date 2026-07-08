import Testing
@testable import ClipboardGuardian

final class MockTextProvider: ClipboardTextProviding {
    var changeCount: Int = 0
    private var content: String?

    func setText(_ s: String?) {
        content = s
        changeCount += 1
    }

    func currentText() -> String? {
        content
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

@Suite("Clipboard Monitor")
struct ClipboardMonitorTests {
    @Test("emits findings only when clipboard change count advances")
    func testCheckOnce_callsAnalyzerOnChange() {
        let mock = MockTextProvider()
        mock.changeCount = 0

        let analyzer = Analyzer(rules: [TestRule()])
        var received: [[Finding]] = []

        let monitor = ClipboardMonitor(provider: mock, analyzer: analyzer) { findings in
            received.append(findings)
        }

        mock.setText("this will trigger")
        monitor.checkOnce()

        #expect(received.count == 1)
        #expect(received.first?.first?.category == "test")

        // No further change -> no callback
        monitor.checkOnce()
        #expect(received.count == 1)
    }

    @Test("notifies safe state after previously dangerous clipboard content")
    func testCheckOnce_notifiesSafeClipboardAfterDangerousContent() {
        let mock = MockTextProvider()
        mock.changeCount = 0

        let analyzer = Analyzer(rules: [TestRule()])
        var received: [[Finding]] = []

        let monitor = ClipboardMonitor(provider: mock, analyzer: analyzer) { findings in
            received.append(findings)
        }

        mock.setText("this will trigger")
        monitor.checkOnce()
        #expect(received.count == 1)
        #expect(!received[0].isEmpty)

        mock.setText("safe clipboard text")
        monitor.checkOnce()
        #expect(received.count == 2)
        #expect(received[1].isEmpty)
    }
}
