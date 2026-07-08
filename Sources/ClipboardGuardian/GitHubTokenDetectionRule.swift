import Foundation

public struct GitHubTokenDetectionRule: DetectionRule {
    public init() {}

    public func detect(in content: String) -> [Finding] {
        let patterns = [
            #"\bgh[pousr]_[A-Za-z0-9]{30,255}\b"#,
            #"\bgithub_pat_[A-Za-z0-9_]{50,255}\b"#
        ]

        for pattern in patterns {
            if content.range(of: pattern, options: [.regularExpression]) != nil {
                return [
                    Finding(
                        severity: .critical,
                        category: "credential",
                        message: "A GitHub token was detected."
                    )
                ]
            }
        }

        return []
    }
}
