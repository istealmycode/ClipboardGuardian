import Foundation

public struct MaliciousJavaScriptDetectionRule: DetectionRule {
    public init() {}

    public func detect(in content: String) -> [Finding] {
        let executionPattern = #"(?i)\b(?:eval\s*\(|new\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*['\"])"#
        let obfuscationPattern = #"(?i)\b(?:atob\s*\(|unescape\s*\(|fromCharCode\s*\()"#

        let hasExecution = content.range(of: executionPattern, options: [.regularExpression]) != nil
        let hasObfuscation = content.range(of: obfuscationPattern, options: [.regularExpression]) != nil

        let exfilSourcePattern = #"(?i)\b(?:document\.cookie|localStorage|sessionStorage)\b"#
        let exfilSinkPattern = #"(?i)\b(?:fetch\s*\(|XMLHttpRequest|sendBeacon\s*\()"#
        let hasExfilSource = content.range(of: exfilSourcePattern, options: [.regularExpression]) != nil
        let hasExfilSink = content.range(of: exfilSinkPattern, options: [.regularExpression]) != nil

        if (hasExecution && hasObfuscation) || (hasExfilSource && hasExfilSink) {
            return [
                Finding(
                    severity: .high,
                    category: "malicious script",
                    message: "Potentially malicious JavaScript behavior was detected."
                )
            ]
        }

        return []
    }
}
