import Foundation

public struct PrivateKeyDetectionRule: DetectionRule {
    public init() {}

    public func detect(in content: String) -> [Finding] {
        let normalized = content.replacingOccurrences(of: "\r\n", with: "\n").lowercased()

        guard hasPrivateKeyBoundary(in: normalized, prefix: "begin"),
              hasPrivateKeyBoundary(in: normalized, prefix: "end") else {
            return []
        }

        return [
            Finding(
                severity: .critical,
                category: "private key",
                message: "A private key block was detected in clipboard content."
            )
        ]
    }

    private func hasPrivateKeyBoundary(in content: String, prefix: String) -> Bool {
        let prefixPattern = NSRegularExpression.escapedPattern(for: prefix)
        let pattern = "(?m)^[ \\t-]*\\b" + prefixPattern + "\\b[ \\t]+(?:[a-z0-9 ]+\\s+)?private key[ \\t-]*$"
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            return false
        }
        let range = NSRange(content.startIndex..<content.endIndex, in: content)
        return regex.firstMatch(in: content, options: [], range: range) != nil
    }
}
