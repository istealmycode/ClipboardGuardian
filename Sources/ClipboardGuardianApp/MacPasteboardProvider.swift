import AppKit
import ClipboardGuardian

final class MacPasteboardProvider: ClipboardTextProviding {
    private let pasteboard: NSPasteboard

    init(pasteboard: NSPasteboard = .general) {
        self.pasteboard = pasteboard
    }

    var changeCount: Int {
        pasteboard.changeCount
    }

    func currentText() -> String? {
        pasteboard.string(forType: .string)
    }
}
