# ClipboardGuardian Development Guidelines

ClipboardGuardian is a native macOS security application. The core analysis engine is the primary product. The UI is an adapter over that engine.

## Philosophy

- Build the analysis engine before building the UI.
- Follow Test-Driven Development whenever practical.
- Prefer small, focused pull requests.
- Explain design decisions in code comments only when they add value.
- Favor readability over cleverness.

## Architecture

- Keep the analysis engine platform-independent.
- Avoid importing AppKit or SwiftUI into the Core module.
- Detection rules should be independent and composable.
- The Analyzer should orchestrate rules, not contain detection logic.
- Prefer protocols for extensibility where appropriate, but don't introduce abstraction without a clear need.

## Testing

- Every new detection rule must have positive and negative tests.
- False positives are considered bugs.
- Use fake credentials and fake secrets in tests.
- Never include real API keys, tokens, or private keys in the repository.

## Security

- Clipboard contents must never leave the local machine.
- Do not introduce telemetry or analytics unless explicitly requested.
- Never persist clipboard history unless the feature is intentionally implemented.
- Security findings should explain why they were generated.

## Code Style

- Keep functions small and focused.
- Prefer value types (`struct`) unless reference semantics are required.
- Avoid force unwrapping.
- Use descriptive names instead of abbreviations.
- Keep dependencies to a minimum.

## Workflow

Before implementing:
1. Write or update tests.
2. Make the tests pass.
3. Refactor if needed.
4. Ensure all tests pass before considering the task complete.

When making changes:
- Summarize the files changed.
- Explain the design decisions.
- Note any tradeoffs.
