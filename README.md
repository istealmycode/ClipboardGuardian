# ClipboardGuardian

⚠️ **This entire codebase was AI-generated** (using GitHub Copilot)

A macOS menu-bar clipboard safety monitor that turns red for dangerous clipboard contents and green for safe text.

## Features

- Monitors macOS clipboard changes via `NSPasteboard`
- Detects private key material and AWS credential leaks
- Displays status using a menu-bar-only app icon
- Includes analyzer logic with test coverage

## Build & Run

```bash
swift build --product ClipboardGuardianApp
./.build/arm64-apple-macosx/debug/ClipboardGuardianApp
```

## Desktop Launcher

The repo includes a launcher app at `ClipboardGuardianLauncher.app`.

Copy it to your Desktop:

```bash
cp -R ClipboardGuardianLauncher.app ~/Desktop/ClipboardGuardianLauncher.app
```

Launch it (or double-click it in Finder):

```bash
open -g ~/Desktop/ClipboardGuardianLauncher.app
```

Notes:

- The launcher starts `ClipboardGuardianApp` in the background.
- Repeated launches do not spawn multiple app instances.

## Test

```bash
swift test
```

## Project Structure

- `Sources/ClipboardGuardian` — core analyzer logic and detection rules
- `Sources/ClipboardGuardianApp` — menu-bar app entry point
- `Tests/ClipboardGuardianTests` — unit and integration tests

