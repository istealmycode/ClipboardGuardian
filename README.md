# ClipboardGuardian

⚠️ **This entire codebase was AI-generated** (using GitHub Copilot)

A macOS menu-bar clipboard safety monitor that turns red for dangerous clipboard contents and green for safe text.

## Features

- Monitors macOS clipboard changes via `NSPasteboard`
- Detects private key material and AWS credential leaks
- Displays status using a menu-bar-only app icon
- Includes a CLI-friendly analyzer and test coverage

## Build & Run

```bash
swift build --product ClipboardGuardianApp
.open .build/ClipboardGuardianApp.app
```

## Test

```bash
swift test
```

## Project Structure

- `Sources/ClipboardGuardian` — core analyzer logic and detection rules
- `Sources/ClipboardGuardianApp` — menu-bar app entry point
- `Sources/clipboardguardian-cli` — optional CLI binary
- `Tests/ClipboardGuardianTests` — unit and integration tests

