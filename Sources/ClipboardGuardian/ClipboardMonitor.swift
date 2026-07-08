import Foundation

public protocol ClipboardTextProviding: AnyObject {
    var changeCount: Int { get }
    func currentText() -> String?
}

public final class ClipboardMonitor {
    private let provider: ClipboardTextProviding
    private let analyzer: Analyzer
    private let callback: ([Finding]) -> Void
    private var lastChangeCount: Int

    public init(provider: ClipboardTextProviding,
                analyzer: Analyzer,
                callback: @escaping ([Finding]) -> Void) {
        self.provider = provider
        self.analyzer = analyzer
        self.callback = callback
        self.lastChangeCount = provider.changeCount
    }

    public func checkOnce() {
        let current = provider.changeCount
        guard current != lastChangeCount else { return }
        lastChangeCount = current

        let findings: [Finding]
        if let text = provider.currentText() {
            findings = analyzer.analyze(text)
        } else {
            findings = []
        }

        callback(findings)
    }

    public func start(interval: TimeInterval = 1.0) {
        // Polling via a repeating timer is intentionally left out in this
        // minimal implementation to avoid Sendable/actor capture warnings in
        // environments where the main runloop timer closure is @Sendable.
        // Call `checkOnce()` directly in tests or wire a timer at the app layer.
    }

    public func stop() {}
}
