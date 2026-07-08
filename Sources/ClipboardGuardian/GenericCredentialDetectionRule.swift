import Foundation

public struct GenericCredentialDetectionRule: DetectionRule {
    public init() {}

    public func detect(in content: String) -> [Finding] {
        let patterns: [(pattern: String, message: String)] = [
            (#"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"#, "A Slack token was detected."),
            (#"\bsk_live_[A-Za-z0-9]{16,}\b"#, "A Stripe live secret key was detected."),
            (#"\bAIza[0-9A-Za-z_-]{35}\b"#, "A Google API key was detected.")
        ]

        for item in patterns {
            if content.range(of: item.pattern, options: [.regularExpression]) != nil {
                return [
                    Finding(
                        severity: .critical,
                        category: "credential",
                        message: item.message
                    )
                ]
            }
        }

        return []
    }
}
