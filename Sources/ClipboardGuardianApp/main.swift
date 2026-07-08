import SwiftUI
import AppKit
import ClipboardGuardian

@MainActor
final class StatusBarController: NSObject {
    private let statusItem: NSStatusItem
    private let menu: NSMenu
    private var monitor: ClipboardMonitor!
    private var timer: Timer?
    private var latestFindings: [Finding] = []

    init(analyzer: Analyzer) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        menu = NSMenu()
        super.init()
        monitor = ClipboardMonitor(analyzer: analyzer) { [weak self] findings in
            self?.handleFindings(findings)
        }
        statusItem.button?.title = "🟢"
        statusItem.menu = menu
        rebuildMenu()
    }

    private func handleFindings(_ findings: [Finding]) {
        latestFindings = findings
        updateStatusIcon()
        rebuildMenu()
    }

    private func updateStatusIcon() {
        statusItem.button?.title = latestFindings.isEmpty ? "🟢" : "🔴"
    }

    private func rebuildMenu() {
        menu.removeAllItems()

        let statusItem = NSMenuItem(title: latestFindings.isEmpty ? "Clipboard is safe" : "Potentially dangerous clipboard content detected", action: nil, keyEquivalent: "")
        statusItem.isEnabled = false
        menu.addItem(statusItem)
        menu.addItem(NSMenuItem.separator())

        let quit = NSMenuItem(title: "Quit ClipboardGuardian", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
    }

    func startPolling(interval: TimeInterval = 1.0) {
        timer = Timer.scheduledTimer(timeInterval: interval, target: self, selector: #selector(timerFired(_:)), userInfo: nil, repeats: true)
        RunLoop.main.add(timer!, forMode: .common)
    }

    @objc private func timerFired(_ sender: Timer) {
        monitor.checkOnce()
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusBarController: StatusBarController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Ensure the app behaves as a menu-bar accessory and does not show a
        // Dock icon or regular app window when launched directly.
        NSApp.setActivationPolicy(.accessory)

        let analyzer = Analyzer(rules: [PrivateKeyDetectionRule(), AWSCredentialDetectionRule()])
        statusBarController = StatusBarController(analyzer: analyzer)
        statusBarController?.startPolling()
        // Ensure any windows are hidden immediately and prevent activation.
        for win in NSApp.windows {
            win.orderOut(nil)
        }
        NSApp.hide(nil)
    }
}

@main
struct ClipboardGuardianApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        Settings {
            EmptyView()
        }
    }
}
